//! Structured prover for the witness batch sumcheck  sum_x F(x) E(x)  with
//!   E(x) = sum_c gamma_c [x in block_c] eq(z_c, x - offset_c),
//! where every block is an aligned subcube (offset_c a multiple of 2^n_c,
//! protocol.layout). It never materialises or folds E.
//!
//! Over the whole table (N variables, MSB first) claim c's weight is a full
//! eq: E(x) = sum_c gamma_c eq(P_c, x) with P_c = (bits of offset_c >> n_c,
//! z_c). Its first N - n_c coordinates are Boolean ("prefix rounds"), the
//! rest are z_c ("local rounds"). With the split eq of eqsum.zig:
//!
//!  * prefix round, bit beta: e(t) = beta ? t : 1 - t, and
//!    q_c(t) = <eq(z_c), F_k(t, rest_c, .)> is linear with q_c(beta) = the
//!    claim's running value (tracked exactly). Only the sibling value
//!    q_c(1 - beta) is new, and it is usually free: it is another claim's
//!    running value (same point, sibling block) or zero (block past the
//!    active part). Otherwise it is one inner product over 2^n_c entries.
//!  * local rounds: claims with the same (n, z) form a group; their weights
//!    coincide up to a scalar, so a group costs one split-eq pass
//!    sum_x' T(x') F_k(0, x') per round (q(1) follows from the group value).
//!
//! F is folded every round exactly as in sumcheck.proveActive. The round
//! values s(0), s(2) are the same field elements the generic prover computes
//! (sumcheck.proveActive(2, {F, E}) after batch.fillRegion), so proofs and
//! transcripts are byte-identical; this is prover algebra only.
const std = @import("std");
const f = @import("field.zig");
const sc = @import("sumcheck.zig");
const Transcript = @import("transcript.zig").Transcript;

const QM31 = f.QM31;
const M31 = f.M31;
const PQ = f.PackedQM31;
const PM = f.PackedM31;
const LANES = f.PACK_WIDTH;

pub const Claim = struct {
    offset: usize,
    point: []const QM31,
    gamma: QM31,
    /// <eq(point), F[offset ..][0 .. 2^point.len]> (the claimed value)
    value: QM31,
};

const CState = struct {
    group: usize,
    n: u32,
    /// remaining prefix (block index among the 2^(N-k-n) blocks of F_k)
    pre: usize,
    gamma: QM31,
    c: QM31,
    val: QM31,
};

const Group = struct {
    n: u32,
    point: []const QM31,
    /// full eq table (sibling inner products), built on first use
    eq_full: ?[]QM31 = null,
    /// local-round suffix table eq(z[j+1..]), built when local rounds start
    t: ?[]QM31 = null,
    gam: QM31 = QM31.zero(),
    val: QM31 = QM31.zero(),
};

fn samePoint(x: []const QM31, y: []const QM31) bool {
    if (x.len != y.len) return false;
    for (x, y) |p, q| if (!p.eql(q)) return false;
    return true;
}

inline fn packedFromI32(src: []const i32, at: usize) PM {
    const v: @Vector(LANES, i32) = src[at..][0..LANES].*;
    const u: PM = @bitCast(v);
    const p: PM = @splat(f.P);
    return @select(u32, v < @as(@Vector(LANES, i32), @splat(0)), u +% p, u);
}

inline fn loadP(src: []const QM31, at: usize) PQ {
    return PQ.fromLanes(src[at..][0..LANES].*);
}

inline fn sumLanes(v: PQ) QM31 {
    var s = QM31.zero();
    inline for (0..LANES) |l| s = s.add(v.lane(l));
    return s;
}

/// Source of F_k: the base table (round 0) or the folded ext buffer.
const Src = union(enum) { base: []const i32, ext: []const QM31 };

const DotCtx = struct { w: []const QM31, src: Src, off: usize, partial: []QM31, chunk: usize };

fn dotChunk(c: *const DotCtx, s: usize, e: usize) void {
    var acc = QM31.zero();
    var x = s;
    switch (c.src) {
        .base => |b| {
            if (LANES > 1) {
                var p = PQ.zero();
                while (x + LANES <= e) : (x += LANES) p = p.add(loadP(c.w, x).mulBase(packedFromI32(b, c.off + x)));
                acc = sumLanes(p);
            }
            while (x < e) : (x += 1) acc = acc.add(c.w[x].mulM31(f.fromI32(b[c.off + x])));
        },
        .ext => |v| {
            if (LANES > 1) {
                var p = PQ.zero();
                while (x + LANES <= e) : (x += LANES) p = p.add(loadP(c.w, x).mul(loadP(v, c.off + x)));
                acc = sumLanes(p);
            }
            while (x < e) : (x += 1) acc = acc.add(c.w[x].mul(v[c.off + x]));
        },
    }
    c.partial[s / c.chunk] = acc;
}

/// sum_{x < len} w[x] * F_k[off + x]
fn dot(pool: *f.Pool, partial: []QM31, w: []const QM31, src: Src, off: usize, len: usize) QM31 {
    if (len == 0) return QM31.zero();
    const target = pool.n_threads * 4;
    var chunk = (len + target - 1) / target;
    if (chunk < 4096) chunk = 4096;
    chunk = (chunk + LANES - 1) / LANES * LANES;
    if (chunk > len) chunk = len;
    const n_chunks = (len + chunk - 1) / chunk;
    var ctx = DotCtx{ .w = w, .src = src, .off = off, .partial = partial[0..n_chunks], .chunk = chunk };
    if (n_chunks <= 1) {
        dotChunk(&ctx, 0, len);
    } else {
        var wg: std.Thread.WaitGroup = .{};
        var s: usize = 0;
        while (s < len) : (s += chunk) pool.pool.spawnWg(&wg, dotChunk, .{ &ctx, s, @min(len, s + chunk) });
        pool.pool.waitAndWork(&wg);
    }
    var out = QM31.zero();
    for (ctx.partial) |p| out = out.add(p);
    return out;
}

const FoldCtx = struct { src: Src, dst: []QM31, half: usize, active: usize, r: QM31 };

/// dst[x] = F[x] + r (F[x + half] - F[x]) for x < min(half, active), the high
/// partner being zero past `active` (sumcheck.proveActive's fold).
fn foldChunk(c: *const FoldCtx, s: usize, e: usize) void {
    const hi_end = if (c.active > c.half) @max(s, @min(e, c.active - c.half)) else s;
    var x = s;
    const rp = PQ.splat(c.r);
    const omr = QM31.one().sub(c.r);
    switch (c.src) {
        .base => |b| {
            if (LANES > 1) {
                while (x + LANES <= hi_end) : (x += LANES) {
                    const lo = packedFromI32(b, x);
                    const hi = packedFromI32(b, x + c.half);
                    const v = rp.mulBase(f.subPackedM31(hi, lo)).add(PQ.fromBase(lo));
                    inline for (0..LANES) |l| c.dst[x + l] = v.lane(l);
                }
            }
            while (x < hi_end) : (x += 1) c.dst[x] = c.r.mulM31(f.fromI32(b[x + c.half]).sub(f.fromI32(b[x]))).add(QM31.fromBase(f.fromI32(b[x])));
            while (x < e) : (x += 1) c.dst[x] = omr.mulM31(f.fromI32(b[x]));
        },
        .ext => |v| {
            // in place (dst may alias v): x reads v[x], v[x + half] and writes dst[x] only
            if (LANES > 1) {
                while (x + LANES <= hi_end) : (x += LANES) {
                    const lo = loadP(v, x);
                    const hi = loadP(v, x + c.half);
                    const o = lo.add(rp.mul(hi.sub(lo)));
                    inline for (0..LANES) |l| c.dst[x + l] = o.lane(l);
                }
            }
            while (x < hi_end) : (x += 1) c.dst[x] = v[x].add(c.r.mul(v[x + c.half].sub(v[x])));
            while (x < e) : (x += 1) c.dst[x] = omr.mul(v[x]);
        },
    }
}

const HalveCtx = struct { t: []QM31, q: usize };
fn halveChunk(c: *const HalveCtx, s: usize, e: usize) void {
    for (s..e) |i| c.t[i] = c.t[i].add(c.t[i + c.q]);
}

/// Merged claims (same offset and point: gammas added; the values agree).
fn merge(a: std.mem.Allocator, claims: []const Claim) ![]Claim {
    var out: std.ArrayList(Claim) = .empty;
    errdefer out.deinit(a);
    outer: for (claims) |c| {
        for (out.items) |*m| if (m.offset == c.offset and samePoint(m.point, c.point)) {
            m.gamma = m.gamma.add(c.gamma);
            continue :outer;
        };
        try out.append(a, c);
    }
    return out.toOwnedSlice(a);
}

/// Prefix-round sibling lookup: the running value of a claim of the same
/// group at block `sib`, zero for a block past the active part, else null.
fn knownSibling(st: []const CState, g: usize, sib: usize, n: u32, active: usize) ?QM31 {
    for (st) |s| if (s.group == g and s.pre == sib) return s.val;
    if ((sib << @intCast(n)) >= active) return QM31.zero();
    return null;
}

/// Cost estimate (QM31-op units) of this prover vs. the materialised-E one
/// (batch.fillRegion + batch.proveBaseTimesExt), from the claim structure
/// alone (simulates which prefix-round siblings are free). Returns true when
/// the structured prover is expected to be cheaper.
pub fn worthIt(a: std.mem.Allocator, len: usize, active: usize, claims_in: []const Claim) !bool {
    if (len < 2 or claims_in.len == 0) return false;
    const N = f.log2Exact(len);
    const claims = try merge(a, claims_in);
    defer a.free(claims);
    var groups: std.ArrayList(Group) = .empty;
    defer groups.deinit(a);
    const st = try a.alloc(CState, claims.len);
    defer a.free(st);
    try initState(a, claims, &groups, st);
    var cost: f64 = @floatFromInt(len); // F folds
    var mat: f64 = 3.0 * @as(f64, @floatFromInt(len));
    for (claims) |c| mat += @floatFromInt(@as(usize, 1) << @intCast(c.point.len));
    const has_unknown = try a.alloc(bool, groups.items.len);
    defer a.free(has_unknown);
    @memset(has_unknown, false);
    for (groups.items) |g| cost += 1.5 * @as(f64, @floatFromInt(@as(usize, 1) << @intCast(g.n)));
    var act = @min(active, len);
    var half = len / 2;
    for (0..N) |k| {
        for (st) |s| {
            if (k + s.n >= N) continue;
            const rem: u6 = @intCast(N - s.n - k);
            const beta = (s.pre >> (rem - 1)) & 1;
            const sib = s.pre ^ (@as(usize, 1) << (rem - 1));
            _ = beta;
            if (knownSibling(st, s.group, sib, s.n, act) == null) {
                cost += @floatFromInt(@as(usize, 1) << @intCast(s.n));
                has_unknown[s.group] = true;
            }
        }
        // advance prefixes (values are not needed for the plan)
        for (st) |*s| if (k + s.n < N) {
            const rem: u6 = @intCast(N - s.n - k);
            s.pre &= (@as(usize, 1) << (rem - 1)) - 1;
        };
        act = @min(half, act);
        half /= 2;
    }
    for (groups.items, has_unknown) |g, u| if (u) {
        cost += @floatFromInt(@as(usize, 1) << @intCast(g.n));
    };
    // margin: many small per-group passes parallelise worse than the
    // materialised prover's few large ones (MLP 1024 tok, 9 groups: 0.94 of
    // mat estimated, measured slower)
    return cost < 0.6 * mat;
}

fn initState(a: std.mem.Allocator, claims: []const Claim, groups: *std.ArrayList(Group), st: []CState) !void {
    for (claims, st) |c, *s| {
        const n: u32 = @intCast(c.point.len);
        var gi: usize = groups.items.len;
        for (groups.items, 0..) |g, i| if (g.n == n and samePoint(g.point, c.point)) {
            gi = i;
            break;
        };
        if (gi == groups.items.len) try groups.append(a, .{ .n = n, .point = c.point });
        s.* = .{ .group = gi, .n = n, .pre = c.offset >> @intCast(n), .gamma = c.gamma, .c = QM31.one(), .val = c.value };
    }
}

/// Same transcript and result as
///   E = 0; batch.fillRegion(E[offset_c ..], claims of each block);
///   sc.proveActive(2, {F*E}, claim, {F as QM31, E}, active)
/// (proveBaseTimesExt). `buf` (>= len / 2 entries) holds the folded F.
/// Every claim's block must be aligned (offset multiple of 2^point.len) and
/// inside [0, len).
pub fn prove(
    a: std.mem.Allocator,
    pool: *f.Pool,
    tr: *Transcript,
    claim: QM31,
    F: []const i32,
    active_in: usize,
    claims_in: []const Claim,
    buf: []QM31,
) !sc.ProveResult {
    const len = F.len;
    const N = f.log2Exact(len);
    std.debug.assert(N >= 1 and buf.len >= len / 2);
    for (claims_in) |c| {
        const sz = @as(usize, 1) << @intCast(c.point.len);
        if (c.offset % sz != 0 or c.offset + sz > len) return error.ClaimShape;
    }
    const claims = try merge(a, claims_in);
    defer a.free(claims);
    var groups: std.ArrayList(Group) = .empty;
    defer {
        for (groups.items) |g| {
            if (g.eq_full) |t| a.free(t);
            if (g.t) |t| a.free(t);
        }
        groups.deinit(a);
    }
    const st = try a.alloc(CState, claims.len);
    defer a.free(st);
    try initState(a, claims, &groups, st);
    // per-claim sibling values of the current round (computed or free)
    const sibv = try a.alloc(QM31, claims.len);
    defer a.free(sibv);
    const partial = try a.alloc(QM31, pool.n_threads * 4 + 2);
    defer a.free(partial);

    const rounds = try a.alloc(sc.RoundPoly, N);
    errdefer a.free(rounds);
    const point = try a.alloc(QM31, N);
    errdefer a.free(point);

    const two = QM31.fromBase(M31.fromCanonical(2));
    var active = @min(active_in, len);
    var half = len / 2;
    var src: Src = .{ .base = F };
    _ = claim;
    for (0..N) |k| {
        var s0 = QM31.zero();
        var s2 = QM31.zero();
        // --- prefix rounds: sibling values (before any state changes)
        for (st, 0..) |s, i| {
            if (k + s.n >= N) continue;
            const rem: u6 = @intCast(N - s.n - k);
            const sib = s.pre ^ (@as(usize, 1) << (rem - 1));
            sibv[i] = knownSibling(st, s.group, sib, s.n, active) orelse blk: {
                // computed earlier this round for the same (group, block)?
                for (st[0..i], 0..) |o, j| if (o.group == s.group and k + o.n < N and (o.pre ^ (@as(usize, 1) << (rem - 1))) == sib) break :blk sibv[j];
                const g = &groups.items[s.group];
                if (g.eq_full == null) g.eq_full = try f.eqTablePar(a, pool, g.point, QM31.one());
                const off = sib << @intCast(s.n);
                const sz = @as(usize, 1) << @intCast(s.n);
                break :blk dot(pool, partial, g.eq_full.?, src, off, @min(sz, active - off));
            };
        }
        for (st, 0..) |s, i| {
            if (k + s.n >= N) continue;
            const rem: u6 = @intCast(N - s.n - k);
            const beta = (s.pre >> (rem - 1)) & 1;
            const q0 = if (beta == 1) sibv[i] else s.val;
            const q1 = if (beta == 1) s.val else sibv[i];
            const gc = s.gamma.mul(s.c);
            // e(0) = 1 - beta, e(2) = beta ? 2 : -1
            if (beta == 0) {
                s0 = s0.add(gc.mul(q0));
                s2 = s2.sub(gc.mul(q1.add(q1).sub(q0)));
            } else {
                s2 = s2.add(gc.mul(two).mul(q1.add(q1).sub(q0)));
            }
        }
        // --- local rounds (one pass per group)
        const gq = try a.alloc([2]QM31, groups.items.len);
        defer a.free(gq);
        for (groups.items, 0..) |*g, gi| {
            if (k + g.n < N) continue;
            const j = k + g.n - N;
            if (j == 0) {
                // enter local rounds: group scalar and common value
                g.gam = QM31.zero();
                for (st) |s| if (s.group == gi) {
                    g.gam = g.gam.add(s.gamma.mul(s.c));
                    g.val = s.val;
                };
                if (g.eq_full) |t| {
                    a.free(t);
                    g.eq_full = null;
                }
                g.t = try f.eqTablePar(a, pool, g.point[1..], QM31.one());
            }
            const zeta = g.point[j];
            const t = g.t.?[0..half];
            const work = @min(half, active);
            const q0 = dot(pool, partial, t, src, 0, work);
            const q1 = if (!zeta.isZero())
                g.val.sub(QM31.one().sub(zeta).mul(q0)).mul(zeta.inv() catch unreachable)
            else
                dot(pool, partial, t, src, half, if (active > half) active - half else 0);
            gq[gi] = .{ q0, q1 };
            const e0 = QM31.one().sub(zeta);
            const e2 = zeta.mul(QM31.fromBase(M31.fromCanonical(3))).sub(QM31.one());
            s0 = s0.add(g.gam.mul(e0).mul(q0));
            s2 = s2.add(g.gam.mul(e2).mul(q1.add(q1).sub(q0)));
        }
        var rp = sc.RoundPoly{ .evals = [_]QM31{QM31.zero()} ** sc.MAX_DEG };
        rp.evals[0] = s0;
        rp.evals[1] = s2;
        tr.mixFelts(rp.evals[0..2]);
        rounds[k] = rp;
        const r = tr.draw();
        point[k] = r;
        // --- update claim / group state
        for (st, 0..) |*s, i| {
            if (k + s.n >= N) continue;
            const rem: u6 = @intCast(N - s.n - k);
            const beta = (s.pre >> (rem - 1)) & 1;
            const q0 = if (beta == 1) sibv[i] else s.val;
            const q1 = if (beta == 1) s.val else sibv[i];
            s.val = q0.add(r.mul(q1.sub(q0)));
            s.c = s.c.mul(if (beta == 1) r else QM31.one().sub(r));
            s.pre &= (@as(usize, 1) << (rem - 1)) - 1;
        }
        for (groups.items, 0..) |*g, gi| {
            if (k + g.n < N) continue;
            const j = k + g.n - N;
            const zeta = g.point[j];
            const q0 = gq[gi][0];
            const q1 = gq[gi][1];
            g.val = q0.add(r.mul(q1.sub(q0)));
            g.gam = g.gam.mul(QM31.one().sub(zeta).mul(QM31.one().sub(r)).add(zeta.mul(r)));
            if (half >= 2) {
                const hc = HalveCtx{ .t = g.t.?, .q = half / 2 };
                pool.parallelFor(half / 2, 8192, &hc, halveChunk);
            }
        }
        // --- fold F
        const work = @min(half, active);
        const fc = FoldCtx{ .src = src, .dst = buf, .half = half, .active = active, .r = r };
        pool.parallelFor(work, 4096, &fc, foldChunk);
        src = .{ .ext = buf[0..half] };
        active = work;
        half /= 2;
    }
    // finals = [F(point), E(point)]; E(point) = sum_c gamma_c eq(P_c, point)
    // (claims on one-entry blocks never reach a local round: gamma C)
    var e_fin = QM31.zero();
    for (groups.items) |g| if (g.n > 0) {
        e_fin = e_fin.add(g.gam);
    };
    for (st) |s| if (s.n == 0) {
        e_fin = e_fin.add(s.gamma.mul(s.c));
    };
    const finals = try a.alloc(QM31, 2);
    finals[0] = if (active > 0) buf[0] else QM31.zero();
    finals[1] = if (active > 0) e_fin else QM31.zero();
    return .{ .proof = .{ .rounds = rounds, .deg = 2 }, .point = point, .finals = finals };
}

// ---------------------------------------------------------------------------

const batch = @import("batch.zig");

fn randFelt(rnd: std.Random) QM31 {
    var l: f.Limbs = undefined;
    for (&l) |*x| x.* = rnd.uintLessThan(u32, f.P);
    return f.fromLimbs(l);
}

/// Random aligned layout (sizes desc, as protocol.layout), random claims (some
/// sharing points, some sharing blocks, some blocks without claims), checked
/// against fillRegion + proveBaseTimesExt: rounds, point, finals, transcript.
fn checkRandom(seed: u64, threads: usize, zero_coord: bool) !void {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, threads);
    defer pool.deinit();
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    const n_t = rnd.intRangeAtMost(usize, 1, 6);
    var logs: [6]u32 = undefined;
    for (logs[0..n_t]) |*l| l.* = rnd.intRangeAtMost(u32, 0, 9);
    std.mem.sort(u32, logs[0..n_t], {}, std.sort.desc(u32));
    var offs: [6]usize = undefined;
    var cur: usize = 0;
    for (logs[0..n_t], 0..) |l, i| {
        offs[i] = cur;
        cur += @as(usize, 1) << @intCast(l);
    }
    var len: usize = 2;
    while (len < cur) len *= 2;
    const used = cur;
    const F = try a.alloc(i32, len);
    defer a.free(F);
    for (F, 0..) |*v, i| v.* = if (i < used) rnd.intRangeAtMost(i32, -300, 300) else 0;
    // shared point pool per size
    var pts: [3][9]QM31 = undefined;
    for (&pts) |*p| for (p) |*x| {
        x.* = randFelt(rnd);
    };
    if (zero_coord) pts[0][1] = QM31.zero();
    var claims: std.ArrayList(Claim) = .empty;
    defer claims.deinit(a);
    const n_c = rnd.intRangeAtMost(usize, 1, 8);
    for (0..n_c) |_| {
        const t = rnd.uintLessThan(usize, n_t);
        const pi = rnd.uintLessThan(usize, 3);
        try claims.append(a, .{ .offset = offs[t], .point = pts[pi][0..logs[t]], .gamma = randFelt(rnd), .value = QM31.zero() });
    }
    // values and the reference E
    const E = try a.alloc(QM31, len);
    defer a.free(E);
    @memset(E, QM31.zero());
    var total = QM31.zero();
    for (claims.items) |*c| {
        const eq = try f.eqTable(a, c.point, QM31.one());
        defer a.free(eq);
        var v = QM31.zero();
        for (eq, 0..) |e, i| {
            v = v.add(e.mulM31(f.fromI32(F[c.offset + i])));
            E[c.offset + i] = E[c.offset + i].add(e.mul(c.gamma));
        }
        c.value = v;
        total = total.add(c.gamma.mul(v));
    }
    var t1 = Transcript.initDomain("beq");
    var t2 = Transcript.initDomain("beq");
    var r1 = try batch.proveBaseTimesExt(a, &pool, &t1, total, F, E, used);
    defer r1.deinit(a);
    const buf = try a.alloc(QM31, len / 2);
    defer a.free(buf);
    var r2 = try prove(a, &pool, &t2, total, F, used, claims.items, buf);
    defer r2.deinit(a);
    try std.testing.expectEqual(r1.proof.rounds.len, r2.proof.rounds.len);
    for (r1.proof.rounds, r2.proof.rounds) |x, y| {
        try std.testing.expect(x.evals[0].eql(y.evals[0]));
        try std.testing.expect(x.evals[1].eql(y.evals[1]));
    }
    for (r1.point, r2.point) |x, y| try std.testing.expect(x.eql(y));
    for (r1.finals, r2.finals) |x, y| try std.testing.expect(x.eql(y));
    try std.testing.expect(t1.draw().eql(t2.draw()));
    _ = try worthIt(a, len, used, claims.items);
}

test "batch_eq.prove matches the materialised-E batch prover exactly" {
    for (0..60) |seed| try checkRandom(seed, 1 + seed % 3, seed % 5 == 0);
}

test "batch_eq.prove: toy shape (three blocks, one point, padded fourth block)" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const n = 12;
    const len = @as(usize, 4) << n;
    const used = @as(usize, 3) << n;
    const F = try a.alloc(i32, len);
    defer a.free(F);
    var prng = std.Random.DefaultPrng.init(5);
    const rnd = prng.random();
    for (F, 0..) |*v, i| v.* = if (i < used) rnd.intRangeAtMost(i32, -128, 127) else 0;
    var pt: [n]QM31 = undefined;
    for (&pt) |*x| x.* = randFelt(rnd);
    var claims: [3]Claim = undefined;
    const E = try a.alloc(QM31, len);
    defer a.free(E);
    @memset(E, QM31.zero());
    const eq = try f.eqTable(a, &pt, QM31.one());
    defer a.free(eq);
    var total = QM31.zero();
    for (&claims, 0..) |*c, t| {
        c.* = .{ .offset = t << n, .point = &pt, .gamma = randFelt(rnd), .value = QM31.zero() };
        for (eq, 0..) |e, i| {
            c.value = c.value.add(e.mulM31(f.fromI32(F[c.offset + i])));
            E[c.offset + i] = e.mul(c.gamma);
        }
        total = total.add(c.gamma.mul(c.value));
    }
    try std.testing.expect(try worthIt(a, len, used, &claims));
    var t1 = Transcript.initDomain("toy");
    var t2 = Transcript.initDomain("toy");
    var r1 = try batch.proveBaseTimesExt(a, &pool, &t1, total, F, E, used);
    defer r1.deinit(a);
    const buf = try a.alloc(QM31, len / 2);
    defer a.free(buf);
    var r2 = try prove(a, &pool, &t2, total, F, used, &claims, buf);
    defer r2.deinit(a);
    for (r1.proof.rounds, r2.proof.rounds) |x, y| {
        try std.testing.expect(x.evals[0].eql(y.evals[0]));
        try std.testing.expect(x.evals[1].eql(y.evals[1]));
    }
    for (r1.finals, r2.finals) |x, y| try std.testing.expect(x.eql(y));
    try std.testing.expect(t1.draw().eql(t2.draw()));
}
