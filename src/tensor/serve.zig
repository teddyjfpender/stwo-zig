//! Per-request proofs that share one weight opening (FlashProve-style serving).
//!
//! A batch of R requests is proved as R independent request proofs plus one
//! shared weight opening:
//!
//! * request j runs the full per-batch protocol (`proto.proveCore`: witness
//!   commitment, LogUp-GKR, op sumchecks, claim batching, witness opening) on
//!   its own transcript `T_j = H("stwo-tensor-req-v1", salt_j, statement_j, ...)`.
//!   It yields weight claims (w, local point, value) and the final digest d_j.
//! * the batch transcript absorbs the weight root, R, and for every request
//!   its digest d_j and its weight claims (ids, points, values), in order;
//!   only then are the weight-opening challenges drawn, and one opening of the
//!   committed weight table covers every request's claims.
//!
//! The proof a client receives for request i is `RequestProof_i` plus the
//! `SharedOpening` (identical for all requests of the batch). `verifyRequest`
//! replays T_i, checks d_i and that slot i of the shared opening holds exactly
//! the weight claims T_i derived, then replays the batch transcript and checks
//! the weight opening for all slots. Soundness and leakage:
//! design/tensor-frontend/serving.md.
const std = @import("std");
const f = @import("field.zig");
const proto = @import("protocol.zig");
const pcs = @import("pcs.zig");
const sc = @import("sumcheck.zig");
const batch_sc = @import("batch.zig");
const Transcript = @import("transcript.zig").Transcript;

const QM31 = f.QM31;

pub const REQ_DOMAIN = "stwo-tensor-req-v1";
pub const BATCH_DOMAIN = "stwo-tensor-batch-v1";

pub const Request = struct {
    st: proto.Statement,
    witness: []const []const i32,
    /// forward-pass accumulators (as for `proto.proveWithAccumulators`); null: recomputed
    acc: ?[]const ?[]i64 = null,
    /// requant ext-einsum accumulators (as for `proto.proveWithAllAccumulators`;
    /// used only together with `acc`); null: recomputed
    ext_acc: ?[]const ?[]const i64 = null,
    /// Per-request salt, mixed first into the request transcript and sent only
    /// in this request's own proof. It hides the request from the other
    /// clients of the batch (they see its digest and claim points; with a
    /// known salt those are a deterministic function of the prompt, so a
    /// client could confirm a guess of another client's prompt). It must be
    /// 256-bit uniform, SECRET (known only to the server and this request's
    /// client) and never reused. null (the default): `BatchProver.add` draws
    /// it from `std.crypto.random`. Pass a value only in tests / reproducible
    /// benches (`testSalt`), never in production.
    salt: ?[32]u8 = null,
};

/// Claims per slot are capped at `max_claims_per_weight * key.infos.len`
/// (checked before any per-claim allocation). An honest request makes at most
/// one claim per weight per matmul shape class; 4 leaves room for a weight
/// read by several ops. Bounds verifier memory/work per downloaded slot.
pub const max_claims_per_weight = 4;
/// Upper bound on the slots of one batch accepted by a verifier.
pub const max_slots = 1 << 16;

pub const RequestProof = struct {
    salt: [32]u8,
    /// per-request part; `weight_opening` is null (the weight claims are in
    /// the shared opening's slot; their values are the op finals)
    core: proto.Proof,

    pub fn deinit(self: *RequestProof, a: std.mem.Allocator) void {
        self.core.deinit(a);
    }

    pub fn byteSize(self: RequestProof) usize {
        return 32 + self.core.sizes().total;
    }
};

/// One request's slot in the shared opening. Claims reference distinct local
/// points by index (matmuls of one shape class share their point).
pub const ClaimSet = struct {
    digest: [32]u8,
    /// distinct local points (in the weight matrices' own index space)
    points: [][]QM31,
    /// per claim: weight id, index into `points`, value
    w: []u32,
    point_of: []u32,
    values: []QM31,

    pub fn deinit(self: *ClaimSet, a: std.mem.Allocator) void {
        for (self.points) |p| a.free(p);
        a.free(self.points);
        a.free(self.w);
        a.free(self.point_of);
        a.free(self.values);
    }

    pub fn byteSize(self: ClaimSet) usize {
        var s: usize = 32 + 8;
        for (self.points) |p| s += 4 + p.len * f.FELT_BYTES;
        return s + self.w.len * (4 + 4 + 16);
    }
};

pub const SharedOpening = struct {
    requests: []ClaimSet,
    /// cross-request claim reduction: one sumcheck over the weight table
    /// reduces every slot's claims to W~(r) (absent when there are no claims)
    reduction: ?sc.Proof = null,
    reduced_value: QM31 = QM31.zero(),
    /// opening of the committed weight table at the single point r
    opening: ?proto.Opening,

    pub fn deinit(self: *SharedOpening, a: std.mem.Allocator) void {
        for (self.requests) |*r| r.deinit(a);
        a.free(self.requests);
        if (self.reduction) |*p| p.deinit(a);
        if (self.opening) |*o| o.deinit(a);
    }

    pub fn claimBytes(self: SharedOpening) usize {
        var s: usize = 4;
        for (self.requests) |r| s += r.byteSize();
        return s;
    }

    pub fn openingBytes(self: SharedOpening) usize {
        const red = if (self.reduction) |p| p.byteSize() + 16 else 0;
        return red + if (self.opening) |o| o.byteSize() else 0;
    }

    pub fn byteSize(self: SharedOpening) usize {
        return self.claimBytes() + self.openingBytes();
    }
};

pub const Batch = struct {
    requests: []RequestProof,
    shared: SharedOpening,

    pub fn deinit(self: *Batch, a: std.mem.Allocator) void {
        for (self.requests) |*r| r.deinit(a);
        a.free(self.requests);
        self.shared.deinit(a);
    }

    /// Bytes a client downloads for request i: its own part + the shared opening.
    pub fn requestBytes(self: Batch, i: usize) usize {
        return self.requests[i].byteSize() + self.shared.byteSize();
    }
};

pub const BatchTimings = struct {
    /// per request: the core prover's stage timings
    requests: []proto.Timings,
    request_ns: []u64,
    shared_open_ns: u64 = 0,

    pub fn deinit(self: *BatchTimings, a: std.mem.Allocator) void {
        a.free(self.requests);
        a.free(self.request_ns);
    }
};

fn requestTranscript(salt: [32]u8) Transcript {
    var tr = Transcript.initDomain(REQ_DOMAIN);
    tr.mixDigest(salt);
    return tr;
}

/// Batch transcript: weight root, R, then per request its digest and claims.
fn batchTranscript(key_root: [32]u8, reqs: []const ClaimSet) Transcript {
    var tr = Transcript.initDomain(BATCH_DOMAIN);
    tr.mixDigest(key_root);
    tr.mixU64(reqs.len);
    for (reqs) |r| {
        tr.mixDigest(r.digest);
        tr.mixU64(r.points.len);
        for (r.points) |p| {
            tr.mixU64(p.len);
            tr.mixFelts(p);
        }
        tr.mixU64(r.w.len);
        for (r.w, r.point_of, r.values) |w, pi, v| {
            tr.mixU32s(&.{ w, pi });
            tr.mixFelt(v);
        }
    }
    return tr;
}

fn nowNs(t0: std.time.Instant) u64 {
    const t1 = std.time.Instant.now() catch return 0;
    return t1.since(t0);
}

/// Proves every request of a batch (in order) with one shared weight opening.
pub fn proveRequests(a: std.mem.Allocator, pool: *f.Pool, cfg: proto.Config, ws: *const proto.WeightStore, reqs: []const Request, timings: ?*BatchTimings) !Batch {
    var bp = BatchProver.init(a, pool, cfg, ws);
    defer bp.deinit();
    for (reqs, 0..) |rq, j| {
        const t0 = try std.time.Instant.now();
        var tm: proto.Timings = .{};
        try bp.add(rq, &tm);
        if (timings) |bt| {
            bt.requests[j] = tm;
            bt.request_ns[j] = nowNs(t0);
        }
    }
    const t0 = try std.time.Instant.now();
    const batch = try bp.finish();
    if (timings) |bt| bt.shared_open_ns = nowNs(t0);
    return batch;
}

/// Streaming batch prover: `add` proves one request's own part right away (the
/// caller may then free its witness); `finish` produces the shared opening.
pub const BatchProver = struct {
    a: std.mem.Allocator,
    pool: *f.Pool,
    cfg: proto.Config,
    ws: *const proto.WeightStore,
    rproofs: std.ArrayList(RequestProof) = .empty,
    sets: std.ArrayList(ClaimSet) = .empty,

    pub fn init(a: std.mem.Allocator, pool: *f.Pool, cfg: proto.Config, ws: *const proto.WeightStore) BatchProver {
        return .{ .a = a, .pool = pool, .cfg = cfg, .ws = ws };
    }

    /// Frees whatever `finish` did not hand out.
    pub fn deinit(self: *BatchProver) void {
        for (self.rproofs.items) |*p| p.deinit(self.a);
        self.rproofs.deinit(self.a);
        for (self.sets.items) |*s| s.deinit(self.a);
        self.sets.deinit(self.a);
    }

    pub fn add(self: *BatchProver, rq: Request, tm: *proto.Timings) !void {
        const a = self.a;
        try self.rproofs.ensureUnusedCapacity(a, 1);
        try self.sets.ensureUnusedCapacity(a, 1);
        const salt = rq.salt orelse blk: {
            var s: [32]u8 = undefined;
            std.crypto.random.bytes(&s);
            break :blk s;
        };
        var tr = requestTranscript(salt);
        var wc: std.ArrayList(proto.WeightClaimP) = .empty;
        defer proto.freeWeightClaims(a, &wc);
        var core = if (rq.acc) |acc|
            try proto.proveCore(a, self.pool, self.cfg, rq.st, self.ws, rq.witness, acc, rq.ext_acc, tm, &tr, &wc)
        else blk: {
            const acc = try proto.computeAccumulators(a, self.pool, rq.st, self.ws, rq.witness, self.cfg.accel);
            defer {
                for (acc) |x| if (x) |v| a.free(v);
                a.free(acc);
            }
            break :blk try proto.proveCore(a, self.pool, self.cfg, rq.st, self.ws, rq.witness, acc, null, tm, &tr, &wc);
        };
        errdefer core.deinit(a);
        var cs = try claimSet(a, tr.ch.digestBytes(), wc.items);
        errdefer cs.deinit(a);
        self.rproofs.appendAssumeCapacity(.{ .salt = salt, .core = core });
        self.sets.appendAssumeCapacity(cs);
    }

    pub fn finish(self: *BatchProver) !Batch {
        const a = self.a;
        var tr = batchTranscript(self.ws.com.root(), self.sets.items);
        var red = try reduceAndOpen(a, self.pool, self.cfg, &tr, self.ws, self.sets.items);
        errdefer red.deinit(a);
        const rp = try self.rproofs.toOwnedSlice(a);
        const sets = self.sets.toOwnedSlice(a) catch |e| {
            self.rproofs = .fromOwnedSlice(rp);
            return e;
        };
        return .{ .requests = rp, .shared = .{ .requests = sets, .reduction = red.reduction, .reduced_value = red.value, .opening = red.opening } };
    }
};

const Reduced = struct {
    reduction: ?sc.Proof = null,
    value: QM31 = QM31.zero(),
    opening: ?proto.Opening = null,

    fn deinit(self: *Reduced, a: std.mem.Allocator) void {
        if (self.reduction) |*p| p.deinit(a);
        if (self.opening) |*o| o.deinit(a);
    }
};

/// Cross-request weight-claim reduction (prover). With gamma_c drawn after
/// every slot is absorbed:
///   sum_c gamma_c v_c = sum_x W(x) E(x),  E(x) = sum_c gamma_c eq(z_c, x)
/// over the whole weight table (z_c the claim's full table point); one
/// degree-2 sumcheck reduces it to W~(r) E~(r), and W~(r) is opened once.
/// E is materialised (16 B per table entry) block by block from each claim's
/// local point, as the witness claim batching does.
fn reduceAndOpen(a: std.mem.Allocator, pool: *f.Pool, cfg: proto.Config, tr: *Transcript, ws: *const proto.WeightStore, sets: []const ClaimSet) !Reduced {
    var n_all: usize = 0;
    for (sets) |cs| n_all += cs.w.len;
    if (n_all == 0) return .{};
    const gammas = try a.alloc(QM31, n_all);
    defer a.free(gammas);
    tr.drawN(gammas);
    const total = @as(usize, 1) << @intCast(ws.log_rows + ws.log_cols);
    const E = try a.alloc(QM31, total);
    defer a.free(E);
    @memset(E, QM31.zero());
    var claim = QM31.zero();
    var rc: std.ArrayList(batch_sc.RegionClaim) = .empty;
    defer rc.deinit(a);
    for (0..ws.infos.len) |w| {
        rc.clearRetainingCapacity();
        var gi: usize = 0;
        for (sets) |cs| for (cs.w, cs.point_of, cs.values) |cw, pi, v| {
            if (cw == w) {
                try rc.append(a, .{ .point = cs.points[pi], .gamma = gammas[gi] });
                claim = claim.add(gammas[gi].mul(v));
            }
            gi += 1;
        };
        if (rc.items.len > 0) try batch_sc.fillRegion(a, pool, E[ws.offsets[w]..][0..ws.infos[w].size()], rc.items);
    }
    // the committed i8 table is the base operand directly (no widened copy)
    std.debug.assert(ws.table.len == total);
    const used = @min(total, ws.rows_used << @intCast(ws.log_cols));
    var res = try batch_sc.proveBaseTimesExtT(i8, a, pool, tr, claim, ws.table, E, used);
    defer a.free(res.point);
    errdefer res.proof.deinit(a);
    const value = res.finals[0];
    a.free(res.finals);
    tr.mixFelt(value);
    const cl = [_]pcs.Claim{.{ .point = res.point, .value = value }};
    const opening = try proto.openWeightFull(a, pool, cfg, tr, ws, &cl);
    return .{ .reduction = res.proof, .value = value, .opening = opening };
}

pub fn initTimings(a: std.mem.Allocator, n: usize) !BatchTimings {
    const t = BatchTimings{ .requests = try a.alloc(proto.Timings, n), .request_ns = try a.alloc(u64, n) };
    @memset(t.requests, .{});
    @memset(t.request_ns, 0);
    return t;
}

/// Builds a slot from a request's weight claims (copies distinct points).
fn claimSet(a: std.mem.Allocator, digest: [32]u8, claims: []const proto.WeightClaimP) !ClaimSet {
    const n = claims.len;
    var pts: std.ArrayList([]QM31) = .empty;
    errdefer {
        for (pts.items) |p| a.free(p);
        pts.deinit(a);
    }
    const w = try a.alloc(u32, n);
    errdefer a.free(w);
    const point_of = try a.alloc(u32, n);
    errdefer a.free(point_of);
    const values = try a.alloc(QM31, n);
    errdefer a.free(values);
    for (claims, 0..) |c, k| {
        w[k] = @intCast(c.w);
        values[k] = c.value;
        const idx = for (pts.items, 0..) |p, i| {
            if (eqlPoint(p, c.point)) break i;
        } else blk: {
            try pts.append(a, try a.dupe(QM31, c.point));
            break :blk pts.items.len - 1;
        };
        point_of[k] = @intCast(idx);
    }
    return .{ .digest = digest, .points = try pts.toOwnedSlice(a), .w = w, .point_of = point_of, .values = values };
}

/// Verifies request `index` of a batch: its own part, that the shared
/// opening's slot `index` holds exactly the weight claims its transcript
/// derived, and the shared weight opening of every slot.
pub fn verifyRequest(a: std.mem.Allocator, cfg: proto.Config, st: proto.Statement, key: proto.WeightKey, rp: *const RequestProof, shared: *const SharedOpening, index: usize) !void {
    return verifyRequestInfo(a, cfg, st, key, rp, shared, index, null);
}

/// As `verifyRequest`, and fills `info` (when given) as `proto.verifyInfo`
/// does: the request's witness/LogUp shapes, and the shared opening's weight
/// shape with its single claim group (the reduced point r).
pub fn verifyRequestInfo(a: std.mem.Allocator, cfg: proto.Config, st: proto.Statement, key: proto.WeightKey, rp: *const RequestProof, shared: *const SharedOpening, index: usize, info: ?*proto.VerifyInfo) !void {
    if (index >= shared.requests.len) return error.ProofShape;
    if (rp.core.weight_opening != null) return error.ProofShape;
    var tr = requestTranscript(rp.salt);
    var wc = proto.VerifierWeightClaims{};
    defer wc.deinit(a);
    try proto.verifyCore(a, cfg, st, key, &rp.core, &tr, &wc, info);
    const mine = shared.requests[index];
    if (!std.mem.eql(u8, &mine.digest, &tr.ch.digestBytes())) return error.RequestDigest;
    // the verifier rebuilds its own slot from its own claims (as the prover
    // does) and requires the slot to be that exact byte string (SERVE-1)
    if (wc.points.items.len > max_claims_per_weight * key.infos.len) return error.ProofShape;
    var own = try ownSlot(a, key, tr.ch.digestBytes(), wc.points.items, wc.values.items);
    defer own.deinit(a);
    if (!eqlSlot(own, mine)) return error.WeightClaimMismatch;
    try verifySharedOpening(a, cfg, key, shared, info);
}

/// The verifier's own slot: each claim's full table point is split into its
/// weight (the block prefix selects the weight's offset and size) and its
/// local point; then `claimSet` as on the prover side.
fn ownSlot(a: std.mem.Allocator, key: proto.WeightKey, digest: [32]u8, full: []const []QM31, values: []const QM31) !ClaimSet {
    const log_total = key.log_rows + key.log_cols;
    const claims = try a.alloc(proto.WeightClaimP, full.len);
    defer a.free(claims);
    for (full, values, claims) |p, v, *c| {
        if (p.len != log_total) return error.WeightClaimMismatch;
        const w = for (key.infos, 0..) |info, w| {
            const ls = info.logSize();
            if (ls > log_total) continue;
            const nb = log_total - ls;
            const block = key.offsets[w] >> @intCast(ls);
            const ok = for (0..nb) |k| {
                const bit = (block >> @intCast(nb - 1 - k)) & 1 == 1;
                if (!p[k].eql(if (bit) QM31.one() else QM31.zero())) break false;
            } else true;
            if (ok) break w;
        } else return error.WeightClaimMismatch;
        c.* = .{ .w = w, .point = p[log_total - key.infos[w].logSize() ..], .value = v };
    }
    return claimSet(a, digest, claims);
}

fn eqlSlot(x: ClaimSet, y: ClaimSet) bool {
    if (!std.mem.eql(u8, &x.digest, &y.digest) or x.points.len != y.points.len) return false;
    for (x.points, y.points) |p, q| if (!eqlPoint(p, q)) return false;
    if (!std.mem.eql(u32, x.w, y.w) or !std.mem.eql(u32, x.point_of, y.point_of) or x.values.len != y.values.len) return false;
    for (x.values, y.values) |p, q| if (!p.eql(q)) return false;
    return true;
}

/// Canonical slot form (SERVE-1, SERVE-3), checked for every slot before any
/// per-claim allocation: at most `max_claims_per_weight * |weights|` claims;
/// every claim's weight id in range and its point of the weight's size; the
/// points in first-use order, every point referenced, all points distinct.
/// So a slot is the unique `claimSet` encoding of its claim list, and
/// nothing unreferenced reaches the batch transcript.
fn checkCanonical(key: proto.WeightKey, r: ClaimSet) !void {
    if (r.point_of.len != r.w.len or r.values.len != r.w.len) return error.ProofShape;
    if (r.w.len > max_claims_per_weight * key.infos.len or r.points.len > r.w.len) return error.ProofShape;
    var next: usize = 0; // points first used so far
    for (r.w, r.point_of) |w, pi| {
        if (w >= key.infos.len or pi > next or pi >= r.points.len or r.points[pi].len != key.infos[w].logSize()) return error.ProofShape;
        if (pi == next) next += 1;
    }
    if (next != r.points.len) return error.ProofShape;
    for (r.points, 0..) |p, i| for (r.points[0..i]) |q| if (eqlPoint(p, q)) return error.ProofShape;
}

/// Checks every slot's canonical shape, then the cross-request reduction and
/// the weight opening, which cover all slots.
fn verifySharedOpening(a: std.mem.Allocator, cfg: proto.Config, key: proto.WeightKey, shared: *const SharedOpening, info: ?*proto.VerifyInfo) !void {
    const log_total = key.log_rows + key.log_cols;
    if (shared.requests.len > max_slots) return error.ProofShape;
    var n_all: usize = 0;
    for (shared.requests) |r| {
        try checkCanonical(key, r);
        n_all += r.w.len;
    }
    const full = try a.alloc([]QM31, n_all);
    var n_full: usize = 0;
    defer {
        for (full[0..n_full]) |p| a.free(p);
        a.free(full);
    }
    const wcl = try a.alloc(pcs.Claim, n_all);
    defer a.free(wcl);
    for (shared.requests) |r| {
        for (r.w, r.point_of, r.values) |w, pi, v| {
            full[n_full] = try fullPointOf(a, log_total, key.offsets[w], key.infos[w].logSize(), r.points[pi]);
            wcl[n_full] = .{ .point = full[n_full], .value = v };
            n_full += 1;
        }
    }
    if ((n_all == 0) != (shared.opening == null) or (n_all == 0) != (shared.reduction == null)) return error.ProofShape;
    if (n_all == 0) return;
    var tr = batchTranscript(key.root, shared.requests);
    // cross-request reduction: sum_c gamma_c v_c = sum_x W(x) E(x)
    const gammas = try a.alloc(QM31, n_all);
    defer a.free(gammas);
    tr.drawN(gammas);
    var claim = QM31.zero();
    for (wcl, gammas) |c, g| claim = claim.add(g.mul(c.value));
    const vr = try sc.verify(a, &tr, claim, log_total, 2, shared.reduction.?);
    defer a.free(vr.point);
    var e_at = QM31.zero();
    for (wcl, gammas) |c, g| e_at = e_at.add(g.mul(f.eqEval(c.point, vr.point)));
    if (!vr.final_claim.eql(shared.reduced_value.mul(e_at))) return error.WeightReduction;
    tr.mixFelt(shared.reduced_value);
    const one = [_]pcs.Claim{.{ .point = vr.point, .value = shared.reduced_value }};
    try proto.verifyWeightOpening(a, &tr, cfg, key, &one, shared.opening.?, info);
}

fn eqlPoint(x: []const QM31, y: []const QM31) bool {
    if (x.len != y.len) return false;
    for (x, y) |p, q| if (!p.eql(q)) return false;
    return true;
}

fn fullPointOf(a: std.mem.Allocator, log_total: u32, offset: usize, log_size: u32, local: []const QM31) ![]QM31 {
    const out = try a.alloc(QM31, log_total);
    const nb = log_total - log_size;
    const block = offset >> @intCast(log_size);
    for (0..nb) |k| out[k] = if ((block >> @intCast(nb - 1 - k)) & 1 == 1) QM31.one() else QM31.zero();
    @memcpy(out[nb..], local);
    return out;
}

/// Deterministic salts for benches and tests (production: std.crypto.random).
pub fn testSalt(i: usize) [32]u8 {
    var s: [32]u8 = undefined;
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    h.update("stwo-tensor-test-salt");
    h.update(std.mem.asBytes(&@as(u64, i)));
    h.final(&s);
    return s;
}

// ---------------------------------------------------------------------------
// Tests.

const testing = std.testing;
const model = @import("model.zig");
const pcs2 = @import("pcs2.zig");

fn tlConfig() proto.Config {
    return .{
        .two_level = .{
            .outer = .{ .log_blowup = 2, .n_queries = 16, .pow_bits = 2 },
            .inner = .{ .log_blowup = 3, .n_queries = 12, .pow_bits = 1 },
            .depth = 1,
        },
        .gkr_threads = 2,
        .batch_matmuls = true,
    };
}

const Fixture = struct {
    pool: f.Pool,
    ws: proto.WeightStore,
    wdata: [3][]i8,
    winfos: [3]proto.TensorInfo,
    built: []model.Built,
    views: [][]const []const i32,
    reqs: []Request,

    fn init(fx: *Fixture, a: std.mem.Allocator, pc: *proto.Config, R: usize) !void {
        try fx.pool.init(a, 4);
        const cfg = model.Mlp{ .log_t = 3, .log_d = 5, .log_f = 6 };
        fx.winfos = model.mlpWeightInfos(cfg);
        pc.weight_log_cols = try proto.chooseWeightLogCols(pc.*, a, &fx.winfos, 2);
        for (&fx.wdata, 0..) |*w, i| w.* = try model.randomWeights(a, fx.winfos[i].size(), 100 + i, -8, 7);
        const wv = [_][]const i8{ fx.wdata[0], fx.wdata[1], fx.wdata[2] };
        fx.ws = try proto.commitWeights(a, &fx.pool, pc.*, &fx.winfos, &wv);
        fx.built = try a.alloc(model.Built, R);
        fx.views = try a.alloc([]const []const i32, R);
        fx.reqs = try a.alloc(Request, R);
        for (0..R) |j| {
            const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 9 + j);
            defer a.free(x);
            fx.built[j] = try model.buildMlp(a, &fx.pool, &fx.ws, cfg, x);
            const v = try a.alloc([]const i32, fx.built[j].witness.len);
            for (fx.built[j].witness, 0..) |w, i| v[i] = w;
            fx.views[j] = v;
            fx.reqs[j] = .{ .st = fx.built[j].statement(), .witness = v, .acc = fx.built[j].accs, .salt = testSalt(j) };
        }
    }

    fn deinit(fx: *Fixture, a: std.mem.Allocator) void {
        for (fx.built, fx.views) |*b, v| {
            b.deinit(a);
            a.free(v);
        }
        a.free(fx.built);
        a.free(fx.views);
        a.free(fx.reqs);
        fx.ws.deinit(a);
        for (fx.wdata) |w| a.free(w);
        fx.pool.deinit();
    }
};

fn expectReject(r: anyerror!void) !void {
    if (r) |_| return error.TamperAccepted else |_| {}
}

test "per-request path under the security params (witness OOD, weight_outer) and VerifyInfo accounting" {
    const a = testing.allocator;
    var pc = tlConfig();
    pc.two_level.?.ood = true;
    pc.weight_outer = .{ .log_blowup = 2, .n_queries = 20, .pow_bits = 1 };
    var fx: Fixture = undefined;
    try fx.init(a, &pc, 2);
    defer fx.deinit(a);
    const key = proto.weightKey(&fx.ws);
    var batch = try proveRequests(a, &fx.pool, pc, &fx.ws, fx.reqs, null);
    defer batch.deinit(a);
    for (0..2) |i| try testing.expect(batch.requests[i].core.witness_ood != null);
    // the same request as a single proof: the core accounting must agree
    var stm: proto.Timings = .{};
    var single = try proto.proveWithAccumulators(a, &fx.pool, pc, fx.reqs[0].st, &fx.ws, fx.reqs[0].witness, fx.reqs[0].acc.?, &stm);
    defer single.deinit(a);
    var si: proto.VerifyInfo = .{};
    try proto.verifyInfo(a, pc, fx.reqs[0].st, key, &single, &si);
    for (0..2) |i| {
        var ri: proto.VerifyInfo = .{};
        try verifyRequestInfo(a, pc, fx.reqs[i].st, key, &batch.requests[i], &batch.shared, i, &ri);
        try testing.expect(std.meta.eql(ri.witness_shape, si.witness_shape));
        try testing.expectEqual(si.witness_groups, ri.witness_groups);
        try testing.expectEqual(@as(usize, 2), ri.witness_groups); // claim + OOD
        try testing.expectEqual(si.logup_fractions, ri.logup_fractions);
        try testing.expectEqual(si.logup_degree_fractions, ri.logup_degree_fractions);
        try testing.expect(std.meta.eql(ri.weight_shape, si.weight_shape));
        // one reduced point plus the key OOD claim (PCS-1), grouped by column point
        try testing.expect(ri.weight_groups >= 1 and ri.weight_groups <= 2);
        try testing.expect(si.weight_groups >= 1);
    }
    // the shared opening is bound to the per-batch weight parameters
    var pc2 = pc;
    pc2.weight_outer = null;
    try expectReject(verifyRequest(a, pc2, fx.reqs[0].st, key, &batch.requests[0], &batch.shared, 0));
    var pc3 = pc;
    pc3.two_level.?.ood = false;
    try expectReject(verifyRequest(a, pc3, fx.reqs[0].st, key, &batch.requests[0], &batch.shared, 0));
}

test "per-request proofs with one shared weight opening: every request verifies; tampering rejected" {
    const a = testing.allocator;
    var pc = tlConfig();
    var fx: Fixture = undefined;
    try fx.init(a, &pc, 3);
    defer fx.deinit(a);
    const key = proto.weightKey(&fx.ws);
    var bt = try initTimings(a, 3);
    defer bt.deinit(a);
    var batch = try proveRequests(a, &fx.pool, pc, &fx.ws, fx.reqs, &bt);
    defer batch.deinit(a);
    for (0..3) |i| try verifyRequest(a, pc, fx.reqs[i].st, key, &batch.requests[i], &batch.shared, i);
    // a request's proof only verifies in its own slot, with its own salt and statement
    try expectReject(verifyRequest(a, pc, fx.reqs[0].st, key, &batch.requests[0], &batch.shared, 1));
    try expectReject(verifyRequest(a, pc, fx.reqs[0].st, key, &batch.requests[0], &batch.shared, 3));
    {
        const sv = batch.requests[1].salt;
        batch.requests[1].salt[0] ^= 1;
        try expectReject(verifyRequest(a, pc, fx.reqs[1].st, key, &batch.requests[1], &batch.shared, 1));
        batch.requests[1].salt = sv;
    }
    // own part tampered
    {
        const sv = batch.requests[2].core.witness_value;
        batch.requests[2].core.witness_value = sv.add(QM31.one());
        try expectReject(verifyRequest(a, pc, fx.reqs[2].st, key, &batch.requests[2], &batch.shared, 2));
        batch.requests[2].core.witness_value = sv;
    }
    // own slot: value, point, digest tampered
    {
        const s = &batch.shared.requests[1];
        const sv = s.values[0];
        s.values[0] = sv.add(QM31.one());
        try expectReject(verifyRequest(a, pc, fx.reqs[1].st, key, &batch.requests[1], &batch.shared, 1));
        s.values[0] = sv;
        const sp = s.points[0][0];
        s.points[0][0] = sp.add(QM31.one());
        try expectReject(verifyRequest(a, pc, fx.reqs[1].st, key, &batch.requests[1], &batch.shared, 1));
        s.points[0][0] = sp;
        // point index redirected (classes share points; a claim may not move)
        if (s.points.len > 1) {
            const pi = s.point_of[0];
            s.point_of[0] = if (pi == 0) 1 else 0;
            try expectReject(verifyRequest(a, pc, fx.reqs[1].st, key, &batch.requests[1], &batch.shared, 1));
            s.point_of[0] = pi;
        }
        const spi = s.point_of[0];
        s.point_of[0] = @intCast(s.points.len); // out of range: error, no crash
        try expectReject(verifyRequest(a, pc, fx.reqs[1].st, key, &batch.requests[1], &batch.shared, 1));
        s.point_of[0] = spi;
        s.digest[3] ^= 1;
        try expectReject(verifyRequest(a, pc, fx.reqs[1].st, key, &batch.requests[1], &batch.shared, 1));
        s.digest[3] ^= 1;
    }
    // ANOTHER request's slot tampered (false claim there): the shared opening
    // must fail for every verifier, since it proves all slots at once
    {
        const s = &batch.shared.requests[0];
        const sv = s.values[1];
        s.values[1] = sv.add(QM31.one());
        for (1..3) |i| try expectReject(verifyRequest(a, pc, fx.reqs[i].st, key, &batch.requests[i], &batch.shared, i));
        s.values[1] = sv;
        s.digest[0] ^= 1; // other slot's digest is bound by the batch transcript
        try expectReject(verifyRequest(a, pc, fx.reqs[2].st, key, &batch.requests[2], &batch.shared, 2));
        s.digest[0] ^= 1;
        // malformed slot: weight id out of range / wrong point length -> error, no crash
        const sw = s.w[0];
        s.w[0] = 99;
        try expectReject(verifyRequest(a, pc, fx.reqs[2].st, key, &batch.requests[2], &batch.shared, 2));
        s.w[0] = sw;
    }
    // cross-request reduction tampered: a round, the reduced value
    {
        const p = &batch.shared.reduction.?;
        const sv = p.rounds[1].evals[0];
        p.rounds[1].evals[0] = sv.add(QM31.one());
        try expectReject(verifyRequest(a, pc, fx.reqs[0].st, key, &batch.requests[0], &batch.shared, 0));
        p.rounds[1].evals[0] = sv;
        const rv = batch.shared.reduced_value;
        batch.shared.reduced_value = rv.add(QM31.one());
        try expectReject(verifyRequest(a, pc, fx.reqs[2].st, key, &batch.requests[2], &batch.shared, 2));
        batch.shared.reduced_value = rv;
    }
    // opening tampered
    {
        const lv = &batch.shared.opening.?.two.levels[0];
        lv.col_values[0] = lv.col_values[0].add(f.M31.one());
        try expectReject(verifyRequest(a, pc, fx.reqs[0].st, key, &batch.requests[0], &batch.shared, 0));
        lv.col_values[0] = lv.col_values[0].sub(f.M31.one());
    }
    // a request proved with the single-batch protocol transcript does not verify here
    var key2 = key;
    key2.root[0] ^= 1;
    try expectReject(verifyRequest(a, pc, fx.reqs[0].st, key2, &batch.requests[0], &batch.shared, 0));
    for (0..3) |i| try verifyRequest(a, pc, fx.reqs[i].st, key, &batch.requests[i], &batch.shared, i);
}

test "per-request proofs: dropping or reordering slots is rejected; R = 1 and flat PCS work" {
    const a = testing.allocator;
    {
        var pc = tlConfig();
        var fx: Fixture = undefined;
        try fx.init(a, &pc, 2);
        defer fx.deinit(a);
        const key = proto.weightKey(&fx.ws);
        var batch = try proveRequests(a, &fx.pool, pc, &fx.ws, fx.reqs, null);
        defer batch.deinit(a);
        // swap the two slots: request 0 now finds request 1's claims in slot 0
        std.mem.swap(ClaimSet, &batch.shared.requests[0], &batch.shared.requests[1]);
        try expectReject(verifyRequest(a, pc, fx.reqs[0].st, key, &batch.requests[0], &batch.shared, 0));
        try expectReject(verifyRequest(a, pc, fx.reqs[0].st, key, &batch.requests[0], &batch.shared, 1)); // transcript order changed
        std.mem.swap(ClaimSet, &batch.shared.requests[0], &batch.shared.requests[1]);
        // drop the other slot: the opening no longer matches its transcript
        const full = batch.shared.requests;
        batch.shared.requests = full[0..1];
        try expectReject(verifyRequest(a, pc, fx.reqs[0].st, key, &batch.requests[0], &batch.shared, 0));
        batch.shared.requests = full;
        try verifyRequest(a, pc, fx.reqs[0].st, key, &batch.requests[0], &batch.shared, 0);
    }
    {
        var pc = tlConfig();
        pc.two_level = null;
        pc.pcs = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 };
        pc.weight_log_cols = 4;
        var fx: Fixture = undefined;
        try fx.init(a, &pc, 1);
        defer fx.deinit(a);
        const key = proto.weightKey(&fx.ws);
        var batch = try proveRequests(a, &fx.pool, pc, &fx.ws, fx.reqs, null);
        defer batch.deinit(a);
        try verifyRequest(a, pc, fx.reqs[0].st, key, &batch.requests[0], &batch.shared, 0);
        // a request proof does not verify as a standalone batch proof (different transcript)
        try expectReject(proto.verify(a, pc, fx.reqs[0].st, key, &batch.requests[0].core));
    }
}
