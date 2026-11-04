//! Tensor proof protocol (v1, non-hiding).
//!
//! Statement: a list of integer tensor ops over committed weights (int8,
//! committed once) and a per-batch witness (activations, multiplicities).
//!
//!   matmul    Y = requant_s(X . W)        X witness [T,K], W weight [K,N] (or witness [N,K]^T)
//!   hadamard  Y = requant_s(A (.) B)      A, B, Y witness, same shape
//!   lookup    Out = table(In)             elementwise int8 -> int8 public table
//!   range8    In in [-128, 128)
//!
//! requant_s(acc) = floor((acc + 2^(s-1)) / 2^s), defined only when the result
//! is in [-128, 128) (the model is undefined otherwise, as in FlashProve).
//! The remainder r = acc + 2^(s-1) - 2^s Y is a *virtual* column: never
//! committed. Range checks r in [0, 2^s) and Y + 128 in [0, 256) are LogUp
//! relations proved by one batched LogUp-GKR (stwo's fast prover). GKR's
//! terminal claims on r are turned into claims on acc, which matmul/hadamard
//! sumchecks reduce to claims on committed X and W. All witness claims are
//! batched by one sumcheck into a single opening of the witness table; all
//! weight claims share their column point (GKR's common ood suffix) and are
//! opened with one combined row.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const f = @import("field.zig");
const canonical = @import("canonical.zig");
const sc = @import("sumcheck.zig");
const pcs = @import("pcs.zig");
const pcs2 = @import("pcs2.zig");
const bsc = @import("batch_sumcheck.zig");
const linalg = @import("linalg.zig");
const batch = @import("batch.zig");
const batch_eq = @import("batch_eq.zig");

fn batchEqEnabled() bool {
    return if (std.posix.getenv("TENSOR_BATCH_EQ")) |v| !std.mem.eql(u8, v, "0") else true;
}
const eqsum = @import("eqsum.zig");
const prep = @import("prep.zig");
const accel = @import("accel.zig");
const Transcript = @import("transcript.zig").Transcript;
pub const xt = @import("ext.zig");

const M31 = f.M31;
const QM31 = f.QM31;
const lookups = engine.lookups;
const Fast = lookups.gkr_prover_fast.ForField(QM31);
const GkrVerifier = lookups.gkr_verifier.ForField(QM31);

// ---------------------------------------------------------------------------
// Statement.

pub const MAX_DIMS = 3;

pub const TensorInfo = struct {
    /// log2 of each dimension, MSB-first (outermost first)
    log_dims: [MAX_DIMS]u32 = .{ 0, 0, 0 },
    n_dims: u8,

    pub fn logSize(self: TensorInfo) u32 {
        var s: u32 = 0;
        for (self.log_dims[0..self.n_dims]) |d| s += d;
        return s;
    }
    pub fn size(self: TensorInfo) usize {
        return @as(usize, 1) << @intCast(self.logSize());
    }
    pub fn mat(lt: u32, ln: u32) TensorInfo {
        return .{ .log_dims = .{ lt, ln, 0 }, .n_dims = 2 };
    }
    pub fn vec(l: u32) TensorInfo {
        return .{ .log_dims = .{ l, 0, 0 }, .n_dims = 1 };
    }
};

pub const Table = struct {
    /// out[v + 128] for v in [-128, 128)
    values: [256]i8,
};

pub const Op = union(enum) {
    matmul: struct { x: u32, w: u32, y: u32, shift: u5 },
    hadamard: struct { a: u32, b: u32, y: u32, shift: u5 },
    lookup: struct { in: u32, out: u32, table: u32 },
    range8: struct { in: u32 },
    /// c = a (.) b over the field (arbitrary M31 values, canonical in [0, p))
    product: struct { a: u32, b: u32, c: u32 },
    /// fused gated activation: h = clamp8(requant_s(table[g] * u)); one lookup
    /// of the triple (g, u, h) into a public 2^16-entry table. Proves g, u in
    /// int8 (table domain) and h, without committing table[g] or a remainder.
    glu: struct { g: u32, u: u32, h: u32, table: u32, shift: u5 },
};

pub const Statement = struct {
    witness: []const TensorInfo,
    weights: []const TensorInfo, // matrices [K, N]
    tables: []const Table,
    ops: []const Op,
    /// transformer-coverage ops (einsum / key / lineq), see ext.zig
    ext: xt.Ext = .{},
    /// digest of the public model definition the statement was built from
    /// (model.MlpConfig / transformer.ModelConfig: shapes, requant shifts,
    /// tables, norm parameters); mixed into the transcript when set (P2)
    model_digest: ?[32]u8 = null,
};

/// Committed weights (prover side): concatenated int8 table + commitment.
pub const WeightStore = struct {
    infos: []const TensorInfo,
    offsets: []usize,
    table: []i8,
    log_rows: u32,
    log_cols: u32,
    rows_used: usize,
    com: pcs.Committed,
    /// MLE of the table at the key's OOD point (`weightOodPoint`), computed at
    /// commit time and published in the WeightKey (security.md 4.2).
    ood_value: QM31 = QM31.zero(),

    pub fn deinit(self: *WeightStore, a: std.mem.Allocator) void {
        a.free(self.offsets);
        a.free(self.table);
        self.com.deinit(a);
    }

    pub fn matrix(self: *const WeightStore, id: usize) pcs.Matrix(i8) {
        const info = self.infos[id];
        // rows = all but the last dimension ([K, N], or [E, K, N] stacked as [E K, N])
        const lc = info.log_dims[info.n_dims - 1];
        return .{ .data = self.table[self.offsets[id]..][0..info.size()], .log_rows = info.logSize() - lc, .log_cols = lc };
    }

    pub fn tableMatrix(self: *const WeightStore) pcs.Matrix(i8) {
        return .{ .data = self.table, .log_rows = self.log_rows, .log_cols = self.log_cols, .rows_used = self.rows_used };
    }
};

/// Aligned layout: tensors sorted by size (desc), each at an offset that is a
/// multiple of its size. Returns offsets and total log size.
pub fn layout(a: std.mem.Allocator, infos: []const TensorInfo, extra_sizes: []const usize) !struct { offsets: []usize, log_total: u32, used: usize } {
    const n = infos.len + extra_sizes.len;
    const sizes = try a.alloc(usize, n);
    defer a.free(sizes);
    for (infos, 0..) |t, i| sizes[i] = t.size();
    for (extra_sizes, 0..) |s, i| sizes[infos.len + i] = s;
    const order = try a.alloc(usize, n);
    defer a.free(order);
    for (order, 0..) |*o, i| o.* = i;
    std.mem.sort(usize, order, sizes, struct {
        fn lt(s: []usize, x: usize, y: usize) bool {
            return s[x] > s[y] or (s[x] == s[y] and x < y);
        }
    }.lt);
    const offsets = try a.alloc(usize, n);
    var cur: usize = 0;
    for (order) |i| {
        offsets[i] = cur;
        cur += sizes[i];
    }
    var total: usize = 1;
    while (total < cur) total *= 2;
    return .{ .offsets = offsets, .log_total = f.log2Exact(total), .used = cur };
}

fn splitTable(log_total: u32, log_cols_max: u32) struct { lr: u32, lc: u32 } {
    // balance: columns ~ sqrt(total) * 4, capped
    var lc: u32 = (log_total + 3) / 2;
    if (lc > log_cols_max) lc = log_cols_max;
    if (lc > log_total) lc = log_total;
    return .{ .lr = log_total - lc, .lc = lc };
}

pub const Config = struct {
    pcs: pcs.Params = .{},
    /// When set, all openings use the recursive tensor PCS (pcs2): combined
    /// rows are committed instead of sent, claims are grouped by column point,
    /// and the witness table split is chosen by the pcs2 size model. `pcs` is
    /// then ignored (two_level.outer holds the outer parameters).
    two_level: ?pcs2.Params = null,
    /// Batch all matmuls of one shape class (same T, K, N) into one sumcheck
    /// with shared challenges, so their weight claims share the local point
    /// (one PCS claim group per class instead of per matmul).
    batch_matmuls: bool = false,
    /// Per-batch weight openings: query/PoW parameters of the outer level
    /// (the weight table itself; null = the witness outer parameters). The
    /// weight table's proximity is proven once in the weight key at a small
    /// distance, so per-batch consistency queries each fail a cheating
    /// prover with probability ~1 - (rho + delta_key) instead of
    /// (1 - rho)/2 (security.md, section 4). The blowup must equal the outer
    /// blowup (same commitment).
    weight_outer: ?pcs.Params = null,
    /// Weight-key proximity proof (one-time): outer-level query/PoW
    /// parameters (null = the witness outer parameters). Same blowup rule.
    key_outer: ?pcs.Params = null,
    /// Weight-key LogUp: number of independent alpha (1 or 2). Both are drawn
    /// in one round (no prover message between them) and run as one batched
    /// LogUp-GKR, so the LogUp error is squared also round by round
    /// (security.md 4.1). 1 keeps the key proof unchanged.
    key_alphas: u32 = 1,
    /// Per-batch weight openings run their own proximity test (k = prox_rows
    /// random rows), next to the matmul claims and the key's OOD claim
    /// (z_ood, v_ood). Then each batch opening binds the claims to the one
    /// list member that matches v_ood, in any decoding regime (Johnson with
    /// OOD, or the capacity conjecture), as FlashProve's online proof does.
    /// false: consistency queries only; the binding then rests on the weight
    /// key's proximity at distance delta_key, and each query costs
    /// -log2(rho + delta_key) bits (security.md 4, 4.2). Conjectured bits are
    /// not meaningful in that mode (bench prints null).
    weight_proximity: bool = true,
    /// max log columns of the weight table (claims are grouped by column
    /// point, so any value <= the table's log size is complete)
    weight_log_cols: u32 = 10,
    witness_log_cols_max: u32 = 14,
    gkr_threads: usize = 8,
    /// smallest GKR loop split across the GKR pool (stwo's default is 2^13;
    /// 2^10 measured best for the MLP: the many small late-round loops of
    /// every layer otherwise run serially)
    gkr_min_parallel: usize = 1 << 10,
    /// Allocate the LogUp-GKR key inputs before the witness commitment and
    /// fault their pages in on a helper thread meanwhile (prover memory
    /// scheduling only; proofs are identical either way).
    prefault_gkr_inputs: bool = true,
    /// Also allocate, fault in and free the CPU GKR prover's layer blocks
    /// during the witness commitment. Only useful when the allocator caches
    /// freed blocks (recycle.Recycler); ignored with an accelerator. Proofs
    /// are identical either way.
    warm_gkr_layers: bool = false,
    /// Optional device accelerator (e.g. Metal); proofs are identical either way.
    accel: ?*const accel.Accel = null,
    /// zero-knowledge mode (zk.zig): hiding commitments, masked sumchecks, no GKR
    hiding: bool = false,
    /// hiding weight commitment: random coefficient slots per row; opening budget = slots/2 columns
    weight_mask_slots: u32 = 1024,
    /// hiding mode: PCS parameters of the weight table (null = same as `pcs`)
    weight_pcs: ?pcs.Params = null,
    /// hiding mode LogUp: masked GKR (true) or committed inverses (false)
    zk_logup_gkr: bool = true,
    /// hiding mode (masked GKR only): requant remainders stay virtual; each
    /// remainder leaf claim is routed through a matmul / hadamard sumcheck at the
    /// GKR leaf point with a pad-masked accumulator hat (zk.md §4.7)
    zk_virtual_remainders: bool = false,
    /// Security level (security.md section 10). `.custom` (default): the
    /// parameters above, whatever they are - every existing proof. Any other
    /// level fixes every soundness parameter (securityConfig) and needs the
    /// degree-8 challenge field (an -Dchallenge=om31 build); prover and
    /// verifier both refuse a config that does not match its level.
    security: SecurityLevel = .custom,
};

/// Selectable security levels. The number is the calculator's "all rounds
/// added, without work" reading (FlashProve's 92.42-bit row): -log2 of the
/// sum of every round's error with no proof-of-work credit, over proven
/// (Johnson-regime, BCHKS25) proximity bounds. PoW is still run (20 bits
/// before every query phase) and shows up only in the with-work reading.
pub const SecurityLevel = enum(u8) {
    custom = 0,
    /// >= 128 bits all rounds added without work: measured 132-134 on the
    /// toy, MLP and layer benches (security.md 10), asserted for product
    /// and MLP proofs in sec128_test.zig
    bits128 = 1,
    /// >= 160 bits all rounds added without work (the compiled N/2^L reading
    /// stays capped near 126 bits by the 256-bit Merkle/Fiat-Shamir hash)
    bits160 = 2,

    /// challenge-field degree the level needs
    pub fn challengeDegree(self: SecurityLevel) u32 {
        return if (self == .custom) 4 else 8;
    }

    pub fn name(self: SecurityLevel) []const u8 {
        return @tagName(self);
    }
};

/// The PCS parameters of a level: Johnson regime with OOD samples on every
/// table (pcs2 depth 2, 1 proximity row), outer level at rate 1/4 (~1 bit
/// per query: agreement sqrt(1/4)(1 + 1/m) with m large, which the degree-8
/// field allows), committed-row levels at rate 1/8 (~1.5 bits per query),
/// 20 PoW bits before every query phase. Weight openings run their own
/// proximity test with the outer parameters; key LogUp uses one alpha (the
/// field term is ~2^-220 already). Non-soundness knobs of `base` (threads,
/// accel, prefault, batching, weight_log_cols, ...) are kept.
pub fn securityConfig(base: Config, level: SecurityLevel) Config {
    if (level == .custom) return base;
    const q: [2]usize = switch (level) {
        .custom => unreachable,
        // 9 query terms on an MLP (witness, weights, key x 3 levels): the
        // largest sum is 2^-129.07 at bits128 (security.md 10.1)
        .bits128 => .{ 133, 88 },
        .bits160 => .{ 168, 112 },
    };
    var c = base;
    c.security = level;
    const outer = pcs.Params{ .n_queries = q[0], .log_blowup = 2, .pow_bits = 20 };
    const inner = pcs.Params{ .n_queries = q[1], .log_blowup = 3, .pow_bits = 20 };
    c.pcs = outer;
    // One proximity row: over the degree-8 field its correlated-agreement
    // term is ~2^-159 on the toy (k = 1), so the second row (needed over QM31) only
    // costs bytes and prover time. The work shift (prover-side budget of the
    // inner encodings, not a soundness parameter) is fixed at 1: it gives
    // the smallest proofs at ~15% more toy prove time than shift 2 (security.md 10.1).
    c.two_level = .{ .outer = outer, .inner = inner, .depth = 2, .inner_work_shift = 1, .prox_rows = 1, .deep = inner, .ood = true };
    c.weight_outer = null;
    c.key_outer = null;
    c.key_alphas = 1;
    c.weight_proximity = true;
    c.hiding = false;
    return c;
}

/// Refuses a config whose soundness parameters are not exactly its level's,
/// or whose level needs a larger challenge field than this build's
/// (error.ChallengeFieldTooSmall: rebuild with -Dchallenge=om31). Run by
/// every prover and verifier entry (proveCore, verifyCore, weight key).
pub fn checkSecurity(cfg: Config) !void {
    if (cfg.security == .custom) return;
    if (f.CHALLENGE_DEGREE < cfg.security.challengeDegree()) return error.ChallengeFieldTooSmall;
    const want = securityConfig(cfg, cfg.security);
    const ok = std.meta.eql(cfg.pcs, want.pcs) and cfg.two_level != null and blk: {
        var a = cfg.two_level.?;
        a.inner_work_shift = want.two_level.?.inner_work_shift;
        break :blk std.meta.eql(a, want.two_level.?);
    } and cfg.weight_outer == null and cfg.key_outer == null and cfg.key_alphas == 1 and cfg.weight_proximity and !cfg.hiding;
    if (!ok) return error.SecurityParams;
}

/// Binds the level into the transcript (degree-8 builds only: QM31
/// transcripts are unchanged), so a proof made at one level never verifies
/// at another even if the parameters were made to coincide.
pub fn mixSecurity(tr: *Transcript, cfg: Config) void {
    if (f.IS_OM31) tr.mixU32s(&.{ 0x5345434c, @intFromEnum(cfg.security) });
}

/// Recommended configuration (stream `speed`): the recursive committed-row
/// PCS (pcs2, depth 2) and shape-class batched matmul sumchecks. `outer` is
/// the big table's opening, `inner` every committed-row level's. The flat
/// Ligero mode stays available (two_level = null, batch_matmuls = false) for
/// comparison; Config's field defaults are unchanged so explicit `.pcs`
/// settings keep their meaning.
pub fn recommendedConfig(outer: pcs.Params, inner: pcs.Params) Config {
    return .{ .pcs = outer, .two_level = .{ .outer = outer, .depth = 2, .inner = inner }, .batch_matmuls = true };
}

pub fn commitWeights(a: std.mem.Allocator, pool: *f.Pool, cfg: Config, infos: []const TensorInfo, data: []const []const i8) !WeightStore {
    const lay = try layout(a, infos, &.{});
    const total = @as(usize, 1) << @intCast(lay.log_total);
    const table = try a.alloc(i8, total);
    @memset(table, 0);
    for (infos, 0..) |t, i| @memcpy(table[lay.offsets[i]..][0..t.size()], data[i]);
    var lc = cfg.weight_log_cols;
    if (lc > lay.log_total) lc = lay.log_total;
    const lr = lay.log_total - lc;
    const lb = outerParams(cfg).log_blowup;
    var tw = try pcs.Twiddles.init(a, lc + lb);
    defer tw.deinit(a);
    const ru = (lay.used + (@as(usize, 1) << @intCast(lc)) - 1) >> @intCast(lc);
    const m = pcs.Matrix(i8){ .data = table, .log_rows = lr, .log_cols = lc, .rows_used = ru };
    const com = try accel.commit(cfg.accel, i8, a, pool, &tw, m, lb);
    var ws = WeightStore{ .infos = infos, .offsets = lay.offsets, .table = table, .log_rows = lr, .log_cols = lc, .rows_used = ru, .com = com };
    // OOD answer at the point derived from the root and layout
    const z = try weightOodPoint(a, weightKey(&ws));
    defer a.free(z);
    ws.ood_value = try tableMleI8(a, pool, ws.tableMatrix(), z);
    return ws;
}

/// MLE of a committed i8 table (rows >= rows_used zero) at a point.
pub fn tableMleI8(a: std.mem.Allocator, pool: *f.Pool, m: pcs.Matrix(i8), point: []const QM31) !QM31 {
    std.debug.assert(point.len == m.log_rows + m.log_cols);
    const eq_r = try f.eqTable(a, point[0..m.log_rows], QM31.one());
    defer a.free(eq_r);
    const cv = [_][]const QM31{eq_r};
    const rows = try pcs.combineRows(i8, a, pool, m, &cv, 7);
    defer {
        for (rows) |r| a.free(r);
        a.free(rows);
    }
    const eq_c = try f.eqTablePar(a, pool, point[m.log_rows..], QM31.one());
    defer a.free(eq_c);
    var v = QM31.zero();
    for (rows[0], eq_c) |u, e| v = v.add(u.mul(e));
    return v;
}

/// Mixes the whole weight layout (root, tensor shapes, offsets, table split),
/// so the key proof and every batch proof commit to one layout (PCS-2).
pub fn mixWeightLayout(tr: *Transcript, key: WeightKey) void {
    tr.mixDigest(key.root);
    tr.mixU64(key.infos.len);
    for (key.infos, 0..) |t, i| {
        tr.mixU64(t.n_dims);
        for (t.log_dims) |d| tr.mixU64(d);
        tr.mixU64(if (i < key.offsets.len) key.offsets[i] else std.math.maxInt(u64));
    }
    tr.mixU32s(&.{ key.log_rows, key.log_cols });
    tr.mixU64(key.rows_used);
}

/// The weight-key transcript up to the OOD point: domain, root, layout.
/// The key proof continues from here (weight_key.zig).
pub fn keyTranscript(key: WeightKey) Transcript {
    var tr = Transcript.initDomain("stwo-tensor-weight-key-v2");
    mixWeightLayout(&tr, key);
    return tr;
}

/// The weight table's OOD point: drawn in the key transcript right after the
/// root and layout, before any prover message (security.md 4.2).
pub fn weightOodPoint(a: std.mem.Allocator, key: WeightKey) ![]QM31 {
    var tr = keyTranscript(key);
    const z = try a.alloc(QM31, key.log_rows + key.log_cols);
    tr.drawN(z);
    return z;
}

/// The verifier-held key must describe the layout `infos` determines: same
/// tensors, canonical offsets, and a table split of exactly that size. Errors
/// instead of panics on any mismatch (PCS-2 / PROTO-5).
pub fn checkKeyLayout(a: std.mem.Allocator, infos: []const TensorInfo, key: WeightKey) !void {
    if (key.infos.len != infos.len or key.offsets.len != infos.len) return error.WeightKeyShape;
    for (key.infos, infos) |x, y| if (!std.meta.eql(x, y)) return error.WeightKeyShape;
    if (infos.len == 0) return;
    const lay = try layout(a, infos, &.{});
    defer a.free(lay.offsets);
    if (!std.mem.eql(usize, lay.offsets, key.offsets)) return error.WeightKeyShape;
    if (key.log_cols > lay.log_total or key.log_rows + key.log_cols != lay.log_total) return error.WeightKeyShape;
    const C = @as(usize, 1) << @intCast(key.log_cols);
    if (key.rows_used != (lay.used + C - 1) / C) return error.WeightKeyShape;
}

// ---------------------------------------------------------------------------
// Relations derived from the statement (shared by prover and verifier).

const KeyKind = enum { remainder, y_range, lookup_pair, plain_range, glu_triple, ext };

const KeyInst = struct {
    kind: KeyKind,
    op: usize, // for .ext: index into Relations.ext_keys
    log_size: u32,
    table: usize, // index into `tables` list below
};

const TableKind = union(enum) { range: u5, act: u32, glu: struct { table: u32, shift: u5 }, ext_lookup: u32 };

const RelTable = struct {
    kind: TableKind,
    log_size: u32,
    mult_tensor: usize, // index of multiplicity tensor in the extended witness list
};

const Relations = struct {
    keys: []KeyInst,
    tables: []RelTable,
    ext_keys: []xt.Key = &.{},
    /// index of the first ext key in `keys`
    ext_base: usize = 0,

    fn deinit(self: *Relations, a: std.mem.Allocator) void {
        a.free(self.keys);
        a.free(self.tables);
        a.free(self.ext_keys);
    }
};

/// LogUp over M31 needs every relation's fraction count (keys + table rows)
/// below p: a key value outside the table then has a nonzero net
/// multiplicity mod p (P7 / PROTO-6). Relations are summed per table, as the
/// verifier checks them (`LogUpSumNonZero`).
fn checkLogUpCounts(rel: Relations) !void {
    for (rel.tables, 0..) |t, ti| {
        if (t.log_size >= 31) return error.LogUpCountAboveP;
        var d: u64 = @as(u64, 1) << @intCast(t.log_size);
        for (rel.keys) |k| if (k.table == ti) {
            if (k.log_size >= 31) return error.LogUpCountAboveP;
            d += @as(u64, 1) << @intCast(k.log_size);
        };
        if (d >= f.P) return error.LogUpCountAboveP;
    }
}

/// `checkLogUpCounts` of a statement's relations.
pub fn checkStatementLogUp(a: std.mem.Allocator, st: Statement) !void {
    var rel = try deriveRelations(a, st);
    defer rel.deinit(a);
    try checkLogUpCounts(rel);
}

fn tableIndex(list: *std.ArrayList(RelTable), a: std.mem.Allocator, kind: TableKind, n_witness: usize) !usize {
    return tableIndexX(list, a, kind, n_witness, .{});
}

fn tableIndexX(list: *std.ArrayList(RelTable), a: std.mem.Allocator, kind: TableKind, n_witness: usize, x: xt.Ext) !usize {
    for (list.items, 0..) |t, i| {
        if (std.meta.eql(t.kind, kind)) return i;
    }
    const log_size: u32 = switch (kind) {
        .range => |s| @max(@as(u32, s), 1),
        .act => 8,
        .glu => 16,
        .ext_lookup => |id| x.tables[id].log_size,
    };
    try list.append(a, .{ .kind = kind, .log_size = log_size, .mult_tensor = n_witness + list.items.len });
    return list.items.len - 1;
}

/// Tensors whose int8 range is implied by a lookup (inputs of lookup/glu).
fn rangeImplied(st: Statement, id: u32) bool {
    for (st.ops) |op| switch (op) {
        .lookup => |l| if (l.in == id) return true,
        .glu => |g| if (g.g == id or g.u == id) return true,
        else => {},
    };
    return false;
}

pub fn gluValue(st: Statement, table: u32, shift: u5, vg: i64, vu: i64) i64 {
    const act: i64 = st.tables[table].values[@intCast(vg + 128)];
    const q = @divFloor(act * vu + shiftHalf(shift), @as(i64, 1) << shift);
    return std.math.clamp(q, -128, 127);
}

fn deriveRelations(a: std.mem.Allocator, st: Statement) !Relations {
    var keys: std.ArrayList(KeyInst) = .empty;
    var tabs: std.ArrayList(RelTable) = .empty;
    const nw = st.witness.len;
    for (st.ops, 0..) |op, i| {
        switch (op) {
            .matmul => |m| {
                const ls = st.witness[m.y].logSize();
                try keys.append(a, .{ .kind = .remainder, .op = i, .log_size = ls, .table = try tableIndex(&tabs, a, .{ .range = m.shift }, nw) });
                if (!rangeImplied(st, m.y)) try keys.append(a, .{ .kind = .y_range, .op = i, .log_size = ls, .table = try tableIndex(&tabs, a, .{ .range = 8 }, nw) });
            },
            .hadamard => |h| {
                const ls = st.witness[h.y].logSize();
                try keys.append(a, .{ .kind = .remainder, .op = i, .log_size = ls, .table = try tableIndex(&tabs, a, .{ .range = h.shift }, nw) });
                if (!rangeImplied(st, h.y)) try keys.append(a, .{ .kind = .y_range, .op = i, .log_size = ls, .table = try tableIndex(&tabs, a, .{ .range = 8 }, nw) });
            },
            .lookup => |l| {
                try keys.append(a, .{ .kind = .lookup_pair, .op = i, .log_size = st.witness[l.in].logSize(), .table = try tableIndex(&tabs, a, .{ .act = l.table }, nw) });
            },
            .range8 => |r| {
                try keys.append(a, .{ .kind = .plain_range, .op = i, .log_size = st.witness[r.in].logSize(), .table = try tableIndex(&tabs, a, .{ .range = 8 }, nw) });
            },
            .product => {},
            .glu => |g| {
                try keys.append(a, .{ .kind = .glu_triple, .op = i, .log_size = st.witness[g.h].logSize(), .table = try tableIndex(&tabs, a, .{ .glu = .{ .table = g.table, .shift = g.shift } }, nw) });
            },
        }
    }
    const ext_base = keys.items.len;
    const ext_keys = try xt.deriveKeys(a, st.ext);
    for (ext_keys, 0..) |k, i| {
        const kind: TableKind = switch (k.table) {
            .range => |b| .{ .range = b },
            .lookup => |id| .{ .ext_lookup = id },
        };
        try keys.append(a, .{ .kind = .ext, .op = i, .log_size = k.log_size, .table = try tableIndexX(&tabs, a, kind, nw, st.ext) });
    }
    return .{ .keys = try keys.toOwnedSlice(a), .tables = try tabs.toOwnedSlice(a), .ext_keys = ext_keys, .ext_base = ext_base };
}

fn extendedInfos(a: std.mem.Allocator, st: Statement, rel: Relations) ![]TensorInfo {
    const out = try a.alloc(TensorInfo, st.witness.len + rel.tables.len);
    @memcpy(out[0..st.witness.len], st.witness);
    for (rel.tables, 0..) |t, i| out[st.witness.len + i] = TensorInfo.vec(t.log_size);
    return out;
}

fn shiftHalf(s: u5) i64 {
    return @as(i64, 1) << (s - 1);
}

fn tableValue(st: Statement, kind: TableKind, idx: usize) struct { key: i64, out: i64, out2: i64 = 0 } {
    return switch (kind) {
        .range => .{ .key = @intCast(idx), .out = 0 },
        .act => |t| .{ .key = @as(i64, @intCast(idx)) - 128, .out = st.tables[t].values[idx] },
        .glu => |g| blk: {
            const vg = @as(i64, @intCast(idx >> 8)) - 128;
            const vu = @as(i64, @intCast(idx & 255)) - 128;
            break :blk .{ .key = vg, .out = vu, .out2 = gluValue(st, g.table, g.shift, vg, vu) };
        },
        .ext_lookup => |t| .{ .key = @intCast(idx), .out = st.ext.tables[t].values[idx] },
    };
}

/// MLE of a public table's key at point (n = log_size vars).
fn tableKeyMle(st: Statement, a: std.mem.Allocator, t: RelTable, point: []const QM31, beta: QM31) !QM31 {
    switch (t.kind) {
        .range => return f.identityMle(point),
        .act => |ti| {
            var outv: [256]i32 = undefined;
            for (0..256) |i| outv[i] = st.tables[ti].values[i];
            const out_mle = try f.mleEvalI32(a, &outv, point);
            return f.identityMle(point).sub(f.qFromI64(128)).add(beta.mul(out_mle));
        },
        .glu => |g| {
            const fv = try a.alloc(i32, 1 << 16);
            defer a.free(fv);
            for (0..1 << 16) |idx| fv[idx] = @intCast(tableValue(st, .{ .glu = g }, idx).out2);
            const f_mle = try f.mleEvalI32(a, fv, point);
            const vg = f.identityMle(point[0..8]).sub(f.qFromI64(128));
            const vu = f.identityMle(point[8..16]).sub(f.qFromI64(128));
            return vg.add(beta.mul(vu)).add(beta.mul(beta).mul(f_mle));
        },
        .ext_lookup => |ti| {
            const out_mle = try f.mleEvalI32(a, st.ext.tables[ti].values, point);
            return f.identityMle(point).add(beta.mul(out_mle));
        },
    }
}

// ---------------------------------------------------------------------------
// Proof.

/// An opening proof of either PCS flavour.
pub const Opening = union(enum) {
    flat: pcs.OpeningProof,
    two: pcs2.Proof,

    pub fn deinit(self: *Opening, a: std.mem.Allocator) void {
        switch (self.*) {
            .flat => |*p| p.deinit(a),
            .two => |*p| p.deinit(a),
        }
    }

    pub fn byteSize(self: Opening) usize {
        return switch (self) {
            .flat => |p| p.byteSize(),
            .two => |p| p.byteSize(),
        };
    }
};

/// Max log columns of the witness table under pcs2 (bounds twiddle memory).
const PCS2_MAX_LOG_COLS: u32 = 22;

fn witnessSplit(cfg: Config, log_total: u32, used: usize) struct { lr: u32, lc: u32 } {
    if (cfg.two_level) |tl| {
        const b = pcs2.bestOuter(tl, log_total, used, 1 + @as(usize, @intFromBool(tl.ood)), true, @min(log_total, PCS2_MAX_LOG_COLS));
        return .{ .lr = log_total - b.log_cols, .lc = b.log_cols };
    }
    const s = splitTable(log_total, cfg.witness_log_cols_max);
    return .{ .lr = s.lr, .lc = s.lc };
}

pub fn outerParams(cfg: Config) pcs.Params {
    return if (cfg.two_level) |tl| tl.outer else cfg.pcs;
}

/// Config whose outer-level parameters are `over` (same blowup required).
fn withOuter(cfg: Config, over: ?pcs.Params) !Config {
    const o = over orelse return cfg;
    if (o.log_blowup != outerParams(cfg).log_blowup) return error.ConfigBlowup;
    var c = cfg;
    if (c.two_level) |*tl| tl.outer = o else c.pcs = o;
    return c;
}

/// Config used for per-batch weight openings.
pub fn weightOpenConfig(cfg: Config) !Config {
    return withOuter(cfg, cfg.weight_outer);
}

/// Config used for the one-time weight-key proximity opening.
pub fn keyConfig(cfg: Config) !Config {
    return withOuter(cfg, cfg.key_outer);
}

/// The witness table carries an OOD sample when the PCS runs beyond unique
/// decoding (pcs2 with ood): one extra claim group in the witness opening.
pub fn witnessOod(cfg: Config) bool {
    return if (cfg.two_level) |tl| tl.ood else false;
}

/// MLE of a committed i32 table (row-major, rows >= rows_used zero) at a point
/// (row coordinates first): one row combination and a dot product.
pub fn tableMle(a: std.mem.Allocator, pool: *f.Pool, m: pcs.Matrix(i32), point: []const QM31) !QM31 {
    std.debug.assert(point.len == m.log_rows + m.log_cols);
    const eq_r = try f.eqTable(a, point[0..m.log_rows], QM31.one());
    defer a.free(eq_r);
    const cv = [_][]const QM31{eq_r};
    const rows = try pcs.combineRows(i32, a, pool, m, &cv, 30);
    defer {
        for (rows) |r| a.free(r);
        a.free(rows);
    }
    const eq_c = try f.eqTablePar(a, pool, point[m.log_rows..], QM31.one());
    defer a.free(eq_c);
    var v = QM31.zero();
    for (rows[0], eq_c) |u, e| v = v.add(u.mul(e));
    return v;
}

/// Weight-table column count for a weight set under the configured PCS: with
/// pcs2 the size model picks it (assuming `n_groups` distinct column points per
/// batch); otherwise `cfg.weight_log_cols`.
pub fn chooseWeightLogCols(cfg: Config, a: std.mem.Allocator, infos: []const TensorInfo, n_groups: usize) !u32 {
    const tl = (try weightOpenConfig(cfg)).two_level orelse return cfg.weight_log_cols;
    const lay = try layout(a, infos, &.{});
    defer a.free(lay.offsets);
    // + 1 group for the key's OOD claim; proximity rows per Config.weight_proximity
    return pcs2.bestOuter(tl, lay.log_total, lay.used, n_groups + 1, cfg.weight_proximity, @min(lay.log_total, PCS2_MAX_LOG_COLS)).log_cols;
}

pub const WitnessClaim = struct { tensor: usize, point: []QM31, value: QM31 };

pub const Proof = struct {
    witness_root: [32]u8,
    gkr: ?GkrVerifier.GkrBatchProof,
    /// per lookup key instance: claimed In(rho)
    lookup_in_values: []QM31,
    /// per matmul/hadamard op (in op order): sumcheck proof and final factor values
    op_sumchecks: []sc.Proof,
    op_finals: [][]QM31,
    batch_sumcheck: sc.Proof,
    witness_value: QM31,
    /// MLE of the witness table at the OOD point drawn right after its root
    /// (only when the PCS runs beyond unique decoding, `witnessOod`)
    witness_ood: ?QM31 = null,
    witness_opening: Opening,
    /// The weight claims' values are not sent: they are the op finals
    /// (W(r, rho_n)) already in the proof; the verifier rebuilds them.
    weight_opening: ?Opening,
    ext: xt.ProofPart = .{},
    /// the level the proof was made at (Config.security); carried in the
    /// wire header of degree-8 proofs, not hashed
    security: SecurityLevel = .custom,

    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        if (self.gkr) |*g| g.deinit(a);
        a.free(self.lookup_in_values);
        for (self.op_sumchecks) |*p| p.deinit(a);
        a.free(self.op_sumchecks);
        for (self.op_finals) |x| a.free(x);
        a.free(self.op_finals);
        self.batch_sumcheck.deinit(a);
        self.witness_opening.deinit(a);
        if (self.weight_opening) |*w| w.deinit(a);
        self.ext.deinit(a);
    }

    pub const Sizes = struct { gkr: usize, sumchecks: usize, witness_opening: usize, weight_opening: usize, total: usize };

    pub fn sizes(self: Proof) Sizes {
        var gk: usize = 0;
        if (self.gkr) |g| {
            for (g.sumcheck_proofs) |p| for (p.round_polys) |rp| {
                gk += rp.coeffsSlice().len * f.FELT_BYTES;
            };
            for (g.layer_masks_by_instance) |ms| for (ms) |m| {
                gk += m.columnsSlice().len * 32;
            };
            for (g.output_claims_by_instance) |c| gk += c.len * f.FELT_BYTES;
        }
        var s: usize = self.lookup_in_values.len * f.FELT_BYTES + self.batch_sumcheck.byteSize() + f.FELT_BYTES + @as(usize, if (self.witness_ood != null) f.FELT_BYTES else 0);
        for (self.op_sumchecks) |p| s += p.byteSize();
        for (self.op_finals) |x| s += x.len * f.FELT_BYTES;
        s += self.ext.byteSize();
        const wo = self.witness_opening.byteSize();
        const wto = if (self.weight_opening) |w| w.byteSize() else 0;
        return .{ .gkr = gk, .sumchecks = s, .witness_opening = wo, .weight_opening = wto, .total = 32 + gk + s + wo + wto };
    }
};

pub const Timings = struct {
    /// matmul/hadamard accumulators, multiplicities (before the commitment)
    prep_ns: u64 = 0,
    witness_commit_ns: u64 = 0,
    /// GKR terminal claims -> witness claims (MLE evaluations)
    terminal_ns: u64 = 0,
    gkr_ns: u64 = 0,
    op_sumcheck_ns: u64 = 0,
    weight_fold_ns: u64 = 0,
    batch_ns: u64 = 0,
    witness_open_ns: u64 = 0,
    weight_open_ns: u64 = 0,
    /// prover-side recomputation of matmul/hadamard accumulators (0 with proveWithAccumulators)
    accumulators_ns: u64 = 0,
    multiplicities_ns: u64 = 0,
    /// parts of gkr_ns: LogUp input construction, layer build, layer sumchecks
    gkr_input_ns: u64 = 0,
    gkr_build_ns: u64 = 0,
    gkr_sumcheck_ns: u64 = 0,
    witness_elems: usize = 0,
    witness_table_elems: usize = 0,
    /// ext ops: accumulators, key columns, multiplicities (before commit)
    ext_init_ns: u64 = 0,
    /// ext terminal claims (MLE evaluations after GKR)
    ext_terminal_ns: u64 = 0,
    /// ext op sumchecks (part of op_sumcheck_ns)
    ext_ops_ns: u64 = 0,
};

fn mixStatement(tr: *Transcript, st: Statement, key: WeightKey) void {
    mixWeightLayout(tr, key);
    tr.mixFelt(key.ood_value);
    tr.mixU64(st.witness.len);
    for (st.witness) |t| {
        tr.mixU64(t.n_dims);
        for (t.log_dims) |d| tr.mixU64(d);
    }
    tr.mixU64(st.weights.len);
    for (st.weights) |t| for (t.log_dims) |d| tr.mixU64(d);
    for (st.tables) |t| {
        var w: [64]u32 = undefined;
        for (0..64) |i| {
            w[i] = 0;
            for (0..4) |j| w[i] |= @as(u32, @as(u8, @bitCast(t.values[i * 4 + j]))) << @intCast(8 * j);
        }
        tr.mixU32s(&w);
    }
    for (st.ops) |op| switch (op) {
        .matmul => |m| tr.mixU32s(&.{ 1, m.x, m.w, m.y, m.shift }),
        .hadamard => |h| tr.mixU32s(&.{ 2, h.a, h.b, h.y, h.shift }),
        .lookup => |l| tr.mixU32s(&.{ 3, l.in, l.out, l.table }),
        .range8 => |r| tr.mixU32s(&.{ 4, r.in }),
        .product => |q| tr.mixU32s(&.{ 5, q.a, q.b, q.c }),
        .glu => |g| tr.mixU32s(&.{ 6, g.g, g.u, g.h, g.table, g.shift }),
    };
    xt.mixStatement(tr, st.ext);
    if (st.model_digest) |d| {
        tr.mixU32s(&.{0x4d4f444c}); // "MODL"
        tr.mixDigest(d);
    }
}

fn fullPoint(a: std.mem.Allocator, log_total: u32, offset: usize, log_size: u32, local: []const QM31) ![]QM31 {
    if (log_size > log_total or local.len != log_size) return error.ClaimShape;
    if (log_size < 64 and offset & ((@as(usize, 1) << @intCast(log_size)) - 1) != 0) return error.ClaimShape;
    if (log_total < 64 and (offset >> @intCast(log_total)) != 0) return error.ClaimShape;
    const out = try a.alloc(QM31, log_total);
    const nb = log_total - log_size;
    const block = offset >> @intCast(log_size);
    for (0..nb) |k| {
        const bit = (block >> @intCast(nb - 1 - k)) & 1;
        out[k] = if (bit == 1) QM31.one() else QM31.zero();
    }
    @memcpy(out[nb..], local);
    return out;
}

fn keySrc(st: Statement, w: []const []const i32, acc: []const ?[]i64, k: KeyInst) prep.KeySrc {
    return switch (k.kind) {
        .remainder => blk: {
            const y_id: u32, const sh: u5 = switch (st.ops[k.op]) {
                .matmul => |m| .{ m.y, m.shift },
                .hadamard => |h| .{ h.y, h.shift },
                else => unreachable,
            };
            break :blk .{ .remainder = .{ .acc = acc[k.op].?, .y = w[y_id], .sh = sh } };
        },
        .y_range => .{ .range8 = .{ .v = w[
            switch (st.ops[k.op]) {
                .matmul => |m| m.y,
                .hadamard => |h| h.y,
                else => unreachable,
            }
        ] } },
        .plain_range => .{ .range8 = .{ .v = w[st.ops[k.op].range8.in] } },
        .lookup_pair => blk: {
            const l = st.ops[k.op].lookup;
            break :blk .{ .lookup = .{ .in = w[l.in], .out = w[l.out], .table = &st.tables[l.table].values } };
        },
        .glu_triple, .ext => unreachable, // handled by the generic paths
    };
}

/// Denominators alpha - key(i) for a key instance (prover side). Must run
/// after `multiplicities` accepted the witness (keys in range).
/// Denominators `alpha - key` of core key instance `k` into `out`
/// (length 2^k.log_size).
fn keyValuesInto(out: []QM31, pool: *f.Pool, st: Statement, w: []const []const i32, acc: []const ?[]i64, k: KeyInst, alpha: QM31, beta: QM31) void {
    const n = @as(usize, 1) << @intCast(k.log_size);
    std.debug.assert(out.len == n);
    switch (k.kind) {
        .glu_triple, .ext => {
    const Ctx = struct { out: []QM31, st: Statement, w: []const []const i32, acc: []const ?[]i64, k: KeyInst, alpha: QM31, beta: QM31 };
    const ctx = Ctx{ .out = out, .st = st, .w = w, .acc = acc, .k = k, .alpha = alpha, .beta = beta };
    pool.parallelFor(n, 4096, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            for (s..e) |i| {
                const key: QM31 = switch (c.k.kind) {
                    .remainder => blk: {
                        const op = c.st.ops[c.k.op];
                        const y_id: u32, const sh: u5 = switch (op) {
                            .matmul => |m| .{ m.y, m.shift },
                            .hadamard => |h| .{ h.y, h.shift },
                            else => unreachable,
                        };
                        const r = c.acc[c.k.op].?[i] + shiftHalf(sh) - (@as(i64, c.w[y_id][i]) << sh);
                        break :blk f.qFromI64(r);
                    },
                    .y_range => blk: {
                        const y_id: u32 = switch (c.st.ops[c.k.op]) {
                            .matmul => |m| m.y,
                            .hadamard => |h| h.y,
                            else => unreachable,
                        };
                        break :blk f.qFromI64(@as(i64, c.w[y_id][i]) + 128);
                    },
                    .plain_range => f.qFromI64(@as(i64, c.w[c.st.ops[c.k.op].range8.in][i]) + 128),
                    .lookup_pair => blk: {
                        const l = c.st.ops[c.k.op].lookup;
                        break :blk f.qFromI64(c.w[l.in][i]).add(c.beta.mul(f.qFromI64(c.w[l.out][i])));
                    },
                    .glu_triple => blk: {
                        const g = c.st.ops[c.k.op].glu;
                        break :blk f.qFromI64(c.w[g.g][i]).add(c.beta.mul(f.qFromI64(c.w[g.u][i]))).add(c.beta.mul(c.beta).mul(f.qFromI64(c.w[g.h][i])));
                    },
                    .ext => unreachable, // xt.keyDen
                };
                c.out[i] = c.alpha.sub(key);
            }
        }
    }.run);
        },
        else => prep.denominators(pool, out, keySrc(st, w, acc, k), alpha, beta),
    }
}

/// One buffer whose first `touch_len` entries a helper thread faults in.
const PrefaultBuf = struct {
    buf: ?[]QM31 = null,
    thread: ?std.Thread = null,

    fn start(self: *PrefaultBuf, a: std.mem.Allocator, len: usize, touch_len: usize) !void {
        const b = try a.alloc(QM31, len);
        self.buf = b;
        // the slice is copied into the thread's arguments (no stack temporaries)
        self.thread = std.Thread.spawn(.{}, touchOne, .{b[0..touch_len]}) catch null;
    }

    fn touchOne(b: []QM31) void {
        KeyBufs.touch(&.{b});
    }

    /// The buffer (ownership passes to the caller), or a fresh one.
    fn take(self: *PrefaultBuf, a: std.mem.Allocator, len: usize) ![]QM31 {
        self.join();
        if (self.buf) |b| {
            std.debug.assert(b.len == len);
            self.buf = null;
            return b;
        }
        return a.alloc(QM31, len);
    }

    fn join(self: *PrefaultBuf) void {
        if (self.thread) |t| t.join();
        self.thread = null;
    }

    fn deinit(self: *PrefaultBuf, a: std.mem.Allocator) void {
        self.join();
        if (self.buf) |b| a.free(b);
        self.buf = null;
    }
};

/// GKR key-input buffers allocated before the witness commitment, with their
/// pages touched by a helper thread while the commitment runs. Fresh pages
/// cost a serialized zero-fill fault each (≈9 GB/s for the 0.9 GB of key
/// denominators at 512 tokens); the overlap moves that cost off the critical
/// path. Values are written later, after alpha and beta are drawn, so the
/// proof is unchanged.
///
/// With `warm_layers`, a second helper also allocates, touches and frees
/// blocks of the sizes the CPU GKR prover allocates for its layers (num and
/// den, 2^(k-1) QM31 each, k = n..1 per instance). With a caching allocator
/// (`recycle.Recycler`) those blocks are then handed back, already faulted
/// in, to the GKR build; with a plain allocator the warm-up is wasted work on
/// the helper thread, which is why it is opt-in.
const KeyBufs = struct {
    bufs: [][]QM31,
    handed: usize = 0,
    thread: ?std.Thread = null,
    warm_thread: ?std.Thread = null,
    warm_logs: []u32 = &.{},

    fn init(a: std.mem.Allocator, rel: Relations, eps: *const xt.ProverState, prefault: bool, warm_layers: bool) !KeyBufs {
        const bufs = try a.alloc([]QM31, rel.keys.len);
        var n: usize = 0;
        errdefer {
            for (bufs[0..n]) |b| a.free(b);
            a.free(bufs);
        }
        for (rel.keys) |k| {
            const len = if (k.kind == .ext) xt.keyLen(eps, k.op) else @as(usize, 1) << @intCast(k.log_size);
            bufs[n] = try a.alloc(QM31, len);
            n += 1;
        }
        var self = KeyBufs{ .bufs = bufs };
        // best effort: without the thread the pages fault when written
        if (prefault) self.thread = std.Thread.spawn(.{}, touch, .{bufs}) catch null;
        if (warm_layers) warm: {
            const logs = a.alloc(u32, rel.keys.len + rel.tables.len) catch break :warm;
            for (bufs, 0..) |b, i| logs[i] = std.math.log2_int(usize, b.len);
            for (rel.tables, 0..) |t, i| logs[rel.keys.len + i] = t.log_size;
            self.warm_logs = logs;
            self.warm_thread = std.Thread.spawn(.{}, warm, .{ a, logs }) catch null;
        }
        return self;
    }

    /// Allocate and touch the GKR layer blocks in gkr_prover_fast's build
    /// order and sizes, holding them all (freeing each at once would cache a
    /// single block per size), then free them. Allocation failure stops early.
    fn warm(a: std.mem.Allocator, logs: []const u32) void {
        var held: std.ArrayList([]QM31) = .empty;
        defer {
            for (held.items) |b| a.free(b);
            held.deinit(a);
        }
        for (logs) |n| {
            var k = n;
            while (k > 0) : (k -= 1) {
                const size = @as(usize, 1) << @intCast(k - 1);
                for (0..2) |_| {
                    held.ensureUnusedCapacity(a, 1) catch return;
                    const b = a.alloc(QM31, size) catch return;
                    held.appendAssumeCapacity(b);
                    touch(&.{b});
                }
            }
        }
    }

    fn joinWarm(self: *KeyBufs) void {
        if (self.warm_thread) |t| t.join();
        self.warm_thread = null;
    }

    fn touch(bufs: []const []QM31) void {
        const page = 16 * 1024;
        for (bufs) |b| {
            const bytes = std.mem.sliceAsBytes(b);
            var i: usize = 0;
            while (i < bytes.len) : (i += page) @as(*volatile u8, &bytes[i]).* = 0;
        }
    }

    fn join(self: *KeyBufs) void {
        if (self.thread) |t| t.join();
        self.thread = null;
    }

    /// Joins the helper and frees every buffer not yet handed to the GKR
    /// prover (which consumes owned inputs).
    fn deinit(self: *KeyBufs, a: std.mem.Allocator) void {
        self.join();
        self.joinWarm();
        if (self.warm_logs.len > 0) a.free(self.warm_logs);
        for (self.bufs[self.handed..]) |b| a.free(b);
        a.free(self.bufs);
    }
};

fn tableDen(a: std.mem.Allocator, st: Statement, t: RelTable, alpha: QM31, beta: QM31) ![]QM31 {
    const n = @as(usize, 1) << @intCast(t.log_size);
    const out = try a.alloc(QM31, n);
    for (0..n) |i| {
        const v = tableValue(st, t.kind, i);
        out[i] = alpha.sub(f.qFromI64(v.key).add(beta.mul(f.qFromI64(v.out))).add(beta.mul(beta).mul(f.qFromI64(v.out2))));
    }
    return out;
}

/// Compute multiplicities for all tables from witness values (validating every key).
fn multiplicities(a: std.mem.Allocator, pool: *f.Pool, st: Statement, rel: Relations, w: []const []const i32, acc: []const ?[]i64, eps: *const xt.ProverState) ![][]i32 {
    const out = try a.alloc([]i32, rel.tables.len);
    var n_alloc: usize = 0;
    errdefer {
        for (out[0..n_alloc]) |m| a.free(m);
        a.free(out);
    }
    for (rel.tables, 0..) |t, i| {
        out[i] = try a.alloc(i32, @as(usize, 1) << @intCast(t.log_size));
        @memset(out[i], 0);
        n_alloc += 1;
    }
    for (rel.keys) |k| {
        const n = @as(usize, 1) << @intCast(k.log_size);
        const mult = out[k.table];
        switch (k.kind) {
            .remainder, .y_range, .plain_range, .lookup_pair => {
                try prep.countInto(a, pool, mult, keySrc(st, w, acc, k));
                continue;
            },
            else => {},
        }
        switch (k.kind) {
            .remainder => {
                const op = st.ops[k.op];
                const y_id: u32, const sh: u5 = switch (op) {
                    .matmul => |m| .{ m.y, m.shift },
                    .hadamard => |h| .{ h.y, h.shift },
                    else => unreachable,
                };
                for (0..n) |i| {
                    const r = acc[k.op].?[i] + shiftHalf(sh) - (@as(i64, w[y_id][i]) << sh);
                    if (r < 0 or r >= mult.len) return error.RemainderOutOfRange;
                    mult[@intCast(r)] += 1;
                }
            },
            .y_range, .plain_range => {
                const y_id: u32 = switch (st.ops[k.op]) {
                    .matmul => |m| m.y,
                    .hadamard => |h| h.y,
                    .range8 => |r| r.in,
                    else => unreachable,
                };
                for (0..n) |i| {
                    const v = @as(i64, w[y_id][i]) + 128;
                    if (v < 0 or v >= 256) return error.ValueOutOfRange;
                    mult[@intCast(v)] += 1;
                }
            },
            .glu_triple => {
                const g = st.ops[k.op].glu;
                for (0..n) |i| {
                    const vg = @as(i64, w[g.g][i]);
                    const vu = @as(i64, w[g.u][i]);
                    if (vg < -128 or vg > 127 or vu < -128 or vu > 127) return error.ValueOutOfRange;
                    if (gluValue(st, g.table, g.shift, vg, vu) != w[g.h][i]) return error.LookupMismatch;
                    mult[@intCast((vg + 128) * 256 + (vu + 128))] += 1;
                }
            },
            .lookup_pair => {
                const l = st.ops[k.op].lookup;
                for (0..n) |i| {
                    const v = @as(i64, w[l.in][i]) + 128;
                    if (v < 0 or v >= 256) return error.ValueOutOfRange;
                    if (st.tables[l.table].values[@intCast(v)] != w[l.out][i]) return error.LookupMismatch;
                    mult[@intCast(v)] += 1;
                }
            },
            .ext => try xt.addMultiplicitiesPar(a, pool, st, eps, k.op, mult),
        }
    }
    return out;
}

/// Integer accumulators for matmul/hadamard ops (prover side).
pub fn computeAccumulators(a: std.mem.Allocator, pool: *f.Pool, st: Statement, ws: *const WeightStore, w: []const []const i32, hook: ?*const accel.Accel) ![]?[]i64 {
    const out = try a.alloc(?[]i64, st.ops.len);
    for (st.ops, 0..) |op, i| {
        out[i] = null;
        switch (op) {
            .matmul => |m| out[i] = if (st.weights[m.w].n_dims == 3)
                try batchedMatmulAcc(a, pool, st.witness[m.x], w[m.x], ws.matrix(m.w), hook)
            else
                try accel.matmulAcc(hook, a, st.witness[m.x].log_dims[0], w[m.x], ws.matrix(m.w)) orelse
                    try matmulAcc(a, pool, st.witness[m.x], w[m.x], ws.matrix(m.w)),
            .hadamard => |h| {
                const n = st.witness[h.y].size();
                const acc = try a.alloc(i64, n);
                for (0..n) |j| acc[j] = @as(i64, w[h.a][j]) * @as(i64, w[h.b][j]);
                out[i] = acc;
            },
            else => {},
        }
    }
    return out;
}

pub fn matmulAcc(a: std.mem.Allocator, pool: *f.Pool, xi: TensorInfo, x: []const i32, wm: pcs.Matrix(i8)) ![]i64 {
    const T = @as(usize, 1) << @intCast(xi.log_dims[0]);
    const K = wm.nRows();
    const N = wm.nCols();
    const acc = try a.alloc(i64, T * N);
    // i32 row sums are exact while max|x| * 128 * K < 2^31 (validateStatement
    // guarantees |acc| < 2^30 for numerically bounded operands); otherwise
    // (exact-einsum operands, or an out-of-contract witness) sum in i64 so the
    // prover never wraps (review finding KERN-3).
    var max_abs: u64 = 0;
    for (x[0 .. T * K]) |v| max_abs = @max(max_abs, @abs(v));
    if (max_abs * 128 * K >= (1 << 31)) {
        matmulAccWide(pool, x, wm, acc, T, K, N);
        return acc;
    }
    const Ctx = struct { x: []const i32, wm: pcs.Matrix(i8), acc: []i64, K: usize, N: usize };
    const ctx = Ctx{ .x = x, .wm = wm, .acc = acc, .K = K, .N = N };
    pool.parallelFor(T, 1, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            const tmp = std.heap.page_allocator.alloc(i32, c.N) catch @panic("oom");
            defer std.heap.page_allocator.free(tmp);
            for (s..e) |t| {
                @memset(tmp, 0);
                for (0..c.K) |k| {
                    const xv = c.x[t * c.K + k];
                    if (xv == 0) continue;
                    const row = c.wm.row(k);
                    for (tmp, row) |*o, wv| o.* += xv * @as(i32, wv);
                }
                for (0..c.N) |n| c.acc[t * c.N + n] = tmp[n];
            }
        }
    }.run);
    return acc;
}

/// Batched matmul accumulators: X [E, T, K], W [E, K, N] (as the [E K, N]
/// matrix of `WeightStore.matrix`) -> acc [E, T, N], acc[e] = X[e] . W[e].
pub fn batchedMatmulAcc(a: std.mem.Allocator, pool: *f.Pool, xi: TensorInfo, x: []const i32, wm: pcs.Matrix(i8), hook: ?*const accel.Accel) ![]i64 {
    const le = xi.log_dims[0];
    const lt = xi.log_dims[1];
    const lk = xi.log_dims[2];
    const E = @as(usize, 1) << @intCast(le);
    const T = @as(usize, 1) << @intCast(lt);
    const K = @as(usize, 1) << @intCast(lk);
    const N = wm.nCols();
    std.debug.assert(wm.data.len == E * K * N and x.len == E * T * K);
    const out = try a.alloc(i64, E * T * N);
    errdefer a.free(out);
    for (0..E) |e| {
        const we = pcs.Matrix(i8){ .data = wm.data[e * K * N ..][0 .. K * N], .log_rows = lk, .log_cols = wm.log_cols };
        const xe = x[e * T * K ..][0 .. T * K];
        const acc = try accel.matmulAcc(hook, a, lt, xe, we) orelse try matmulAcc(a, pool, TensorInfo.mat(lt, lk), xe, we);
        defer a.free(acc);
        @memcpy(out[e * T * N ..][0 .. T * N], acc);
    }
    return out;
}

/// A matmul whose weight is a stacked [E, K, N] tensor (batched over e).
fn isBatchedMatmul(st: Statement, op: Op) bool {
    return switch (op) {
        .matmul => |m| m.w < st.weights.len and st.weights[m.w].n_dims == 3,
        else => false,
    };
}

fn matmulAccWide(pool: *f.Pool, x: []const i32, wm: pcs.Matrix(i8), acc: []i64, T: usize, K: usize, N: usize) void {
    const Ctx = struct { x: []const i32, wm: pcs.Matrix(i8), acc: []i64, K: usize, N: usize };
    const ctx = Ctx{ .x = x, .wm = wm, .acc = acc, .K = K, .N = N };
    pool.parallelFor(T, 1, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            for (s..e) |t| {
                const o = c.acc[t * c.N ..][0..c.N];
                @memset(o, 0);
                for (0..c.K) |k| {
                    const xv: i64 = c.x[t * c.K + k];
                    if (xv == 0) continue;
                    for (o, c.wm.row(k)) |*d, wv| d.* += xv * wv;
                }
            }
        }
    }.run);
}

/// requant (prover helper)
pub fn requant(acc: i64, s: u5) i32 {
    return @intCast(@divFloor(acc + shiftHalf(s), @as(i64, 1) << s));
}

fn toQM31Vec(a: std.mem.Allocator, pool: *f.Pool, v: []const i32) ![]QM31 {
    const out = try a.alloc(QM31, v.len);
    const Ctx = struct { v: []const i32, out: []QM31 };
    const ctx = Ctx{ .v = v, .out = out };
    pool.parallelFor(v.len, 8192, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            for (s..e) |i| c.out[i] = QM31.fromBase(f.fromI32(c.v[i]));
        }
    }.run);
    return out;
}

const ClaimList = std.ArrayList(WitnessClaim);

const T_PROD2 = [_]sc.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1 } }};
const T_EQ3 = [_]sc.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }};
const T_PRODUCT = [_]sc.Term{ .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }, .{ .coeff = QM31.fromU32Unchecked(f.P - 1, 0, 0, 0), .factors = &[_]u8{ 0, 3 } } };

fn nowNs(t0: std.time.Instant) u64 {
    const t1 = std.time.Instant.now() catch return 0;
    return t1.since(t0);
}

// ---------------------------------------------------------------------------
// Prover.

pub fn prove(
    a: std.mem.Allocator,
    pool: *f.Pool,
    cfg: Config,
    st: Statement,
    ws: *const WeightStore,
    witness: []const []const i32,
    timings: *Timings,
) !Proof {
    // hiding proofs come from zk.prove; never silently produce a non-hiding one
    if (cfg.hiding) return error.HidingRequiresZkProve;
    const tp = try std.time.Instant.now();
    const acc = try computeAccumulators(a, pool, st, ws, witness, cfg.accel);
    defer {
        for (acc) |x| if (x) |v| a.free(v);
        a.free(acc);
    }
    timings.accumulators_ns = nowNs(tp);
    return proveWithAccumulators(a, pool, cfg, st, ws, witness, acc, timings);
}

/// As `prove`, with the integer accumulators of the matmul/hadamard ops
/// supplied by the caller (e.g. kept from the forward pass). `acc` must equal
/// `computeAccumulators(st, ws, witness)`; anything else only yields a proof
/// the verifier rejects (the prover is untrusted), and out-of-range
/// remainders are still refused here.
pub fn proveWithAccumulators(
    a: std.mem.Allocator,
    pool: *f.Pool,
    cfg: Config,
    st: Statement,
    ws: *const WeightStore,
    witness: []const []const i32,
    acc: []const ?[]i64,
    timings: *Timings,
) !Proof {
    return proveWithAllAccumulators(a, pool, cfg, st, ws, witness, acc, null, timings);
}

/// As `proveWithAccumulators`, plus (optionally) the accumulators of the
/// requant ext einsums (`ext_acc[i]` for st.ext.ops[i], null = recompute).
/// Same trust model: wrong values are refused or rejected, never accepted.
pub fn proveWithAllAccumulators(
    a: std.mem.Allocator,
    pool: *f.Pool,
    cfg: Config,
    st: Statement,
    ws: *const WeightStore,
    witness: []const []const i32,
    acc: []const ?[]i64,
    ext_acc: ?[]const ?[]const i64,
    timings: *Timings,
) !Proof {
    var tr = Transcript.initDomain("stwo-tensor-v1");
    var wc: std.ArrayList(WeightClaimP) = .empty;
    defer freeWeightClaims(a, &wc);
    var proof = try proveCore(a, pool, cfg, st, ws, witness, acc, ext_acc, timings, &tr, &wc);
    errdefer proof.deinit(a);
    const t0 = try std.time.Instant.now();
    proof.weight_opening = try openWeightClaims(a, pool, cfg, &tr, ws, wc.items);
    timings.weight_open_ns = nowNs(t0);
    return proof;
}

pub fn freeWeightClaims(a: std.mem.Allocator, wc: *std.ArrayList(WeightClaimP)) void {
    for (wc.items) |c| a.free(c.point);
    wc.deinit(a);
}

/// Opens the committed weights at a list of claims (local points; any number
/// of distinct column points) on transcript `tr`, with the per-batch weight
/// parameters (`weightOpenConfig`). The claim values are not part of the
/// proof: the verifier takes them from the op finals. Null when there are no
/// claims.
pub fn openWeightClaims(a: std.mem.Allocator, pool: *f.Pool, cfg: Config, tr: *Transcript, ws: *const WeightStore, claims: []const WeightClaimP) !?Opening {
    const wcl = try a.alloc(pcs.Claim, claims.len);
    defer a.free(wcl);
    const full_pts = try a.alloc([]QM31, claims.len);
    var n_pts: usize = 0;
    defer {
        for (full_pts[0..n_pts]) |p| a.free(p);
        a.free(full_pts);
    }
    const wlog_total = ws.log_rows + ws.log_cols;
    for (claims, 0..) |c, i| {
        full_pts[i] = try fullPoint(a, wlog_total, ws.offsets[c.w], ws.infos[c.w].logSize(), c.point);
        n_pts += 1;
        wcl[i] = .{ .point = full_pts[i], .value = c.value };
    }
    return openWeightFull(a, pool, cfg, tr, ws, wcl);
}

/// Opens the committed weight table at claims with full table points, with
/// the per-batch weight parameters (`weightOpenConfig`): pcs2 takes one claim
/// group per distinct column point, the flat PCS one group for all claims.
/// Null when there are no claims.
pub fn openWeightFull(a: std.mem.Allocator, pool: *f.Pool, cfg: Config, tr: *Transcript, ws: *const WeightStore, wcl_in: []const pcs.Claim) !?Opening {
    if (wcl_in.len == 0) return null;
    // PCS-1: append the key's OOD claim (z_ood, v_ood), which pins the decoding
    // certified by the key proof; with Config.weight_proximity the opening also
    // runs its own proximity test. Claims are grouped by column point.
    const wcl = try a.alloc(pcs.Claim, wcl_in.len + 1);
    defer a.free(wcl);
    @memcpy(wcl[0..wcl_in.len], wcl_in);
    const wood_z = try weightOodPoint(a, weightKey(ws));
    defer a.free(wood_z);
    wcl[wcl_in.len] = .{ .point = wood_z, .value = ws.ood_value };
    const wcfg = try weightOpenConfig(cfg);
    const gs = try pcs2.groupByColumn(a, wcl, ws.log_rows);
    defer pcs2.freeGroups(a, gs);
    if (wcfg.two_level) |tl| return .{ .two = try pcs2.open(i8, a, pool, tr, tl, &ws.com, ws.tableMatrix(), gs, cfg.weight_proximity) };
    return .{ .flat = try pcs.open(i8, a, pool, tr, wcfg.pcs, &ws.com, ws.tableMatrix(), gs, cfg.weight_proximity) };
}

/// The per-batch (or per-request) part of the prover: witness commitment
/// (with its OOD sample under pcs2+ood), LogUp-GKR, op sumchecks, claim
/// batching and the witness opening, on the caller's transcript `tr_io`
/// (initialised by the caller, updated in place). The weight claims it
/// produces are moved to `weight_claims_out` (local points, in protocol
/// order); the returned proof has no weight opening.
/// `proveWithAllAccumulators` opens them on the same transcript;
/// `serve.proveRequests` opens all requests' claims at once.
pub fn proveCore(
    a: std.mem.Allocator,
    pool: *f.Pool,
    cfg: Config,
    st: Statement,
    ws: *const WeightStore,
    witness: []const []const i32,
    acc: []const ?[]i64,
    ext_acc: ?[]const ?[]const i64,
    timings: *Timings,
    tr_io: *Transcript,
    weight_claims_out: *std.ArrayList(WeightClaimP),
) !Proof {
    try checkSecurity(cfg);
    if (acc.len != st.ops.len) return error.AccumulatorShape;
    for (st.ops, acc) |op, x| switch (op) {
        .matmul => |m| if (x == null or x.?.len != st.witness[m.y].size()) return error.AccumulatorShape,
        .hadamard => |h| if (x == null or x.?.len != st.witness[h.y].size()) return error.AccumulatorShape,
        else => {},
    };
    try checkKeyLayout(a, st.weights, weightKey(ws));
    var rel = try deriveRelations(a, st);
    defer rel.deinit(a);
    try checkLogUpCounts(rel);
    const t_init = try std.time.Instant.now();
    var eps = try xt.proverInitWith(a, pool, st, witness, ext_acc);
    defer eps.deinit(a);
    timings.ext_init_ns = nowNs(t_init);
    const tm0 = try std.time.Instant.now();
    const mults = try multiplicities(a, pool, st, rel, witness, acc, &eps);
    timings.multiplicities_ns = nowNs(tm0);
    defer {
        for (mults) |m| a.free(m);
        a.free(mults);
    }
    const ext = try extendedInfos(a, st, rel);
    defer a.free(ext);
    const all = try a.alloc([]const i32, ext.len);
    defer a.free(all);
    for (witness, 0..) |w, i| all[i] = w;
    for (mults, 0..) |m, i| all[witness.len + i] = m;

    var key_bufs = try KeyBufs.init(a, rel, &eps, cfg.prefault_gkr_inputs, cfg.warm_gkr_layers and cfg.accel == null);
    defer key_bufs.deinit(a);

    // --- witness table + commitment
    var t0 = try std.time.Instant.now();
    const lay = try layout(a, ext, &.{});
    defer a.free(lay.offsets);
    const total = @as(usize, 1) << @intCast(lay.log_total);
    const wtab = try a.alloc(i32, total);
    defer a.free(wtab);
    @memset(wtab, 0);
    for (all, 0..) |v, i| @memcpy(wtab[lay.offsets[i]..][0..v.len], v);
    const split = witnessSplit(cfg, lay.log_total, lay.used);
    const olb = outerParams(cfg).log_blowup;
    var wtw = try pcs.Twiddles.init(a, split.lc + olb);
    defer wtw.deinit(a);
    const w_ru = (lay.used + (@as(usize, 1) << @intCast(split.lc)) - 1) >> @intCast(split.lc);
    const wm = pcs.Matrix(i32){ .data = wtab, .log_rows = split.lr, .log_cols = split.lc, .rows_used = w_ru };
    var wcom = try accel.commit(cfg.accel, i32, a, pool, &wtw, wm, olb);
    defer wcom.deinit(a);
    timings.witness_commit_ns = nowNs(t0);
    timings.witness_table_elems = w_ru << @intCast(split.lc);
    for (all) |v| timings.witness_elems += v.len;

    var tr = tr_io.*;
    mixStatement(&tr, st, weightKey(ws));
    mixSecurity(&tr, cfg);
    tr.mixDigest(wcom.root());
    // OOD sample of the witness table: fixes the decoded witness before any
    // challenge (security.md, section 3)
    const wood_pt = try a.alloc(QM31, if (witnessOod(cfg)) lay.log_total else 0);
    defer a.free(wood_pt);
    var wood: ?QM31 = null;
    if (witnessOod(cfg)) {
        tr.drawN(wood_pt);
        wood = try tableMle(a, pool, wm, wood_pt);
        tr.mixFelt(wood.?);
    }
    const alpha = tr.draw();
    const beta = tr.draw();

    // --- LogUp-GKR over all key and table instances
    t0 = try std.time.Instant.now();
    const n_inst = rel.keys.len + rel.tables.len;
    const inputs = try a.alloc(Fast.Input, n_inst);
    defer a.free(inputs);
    key_bufs.join();
    for (rel.keys, key_bufs.bufs, 0..) |k, buf, i| {
        if (k.kind == .ext) xt.keyDenInto(buf, pool, &eps, k.op, alpha, beta) else keyValuesInto(buf, pool, st, all, acc, k, alpha, beta);
        inputs[i] = .{ .num = .ones, .den = buf, .owned = true };
    }
    const mult_m31 = try a.alloc([]M31, rel.tables.len);
    defer {
        for (mult_m31) |m| a.free(m);
        a.free(mult_m31);
    }
    for (rel.tables, 0..) |t, i| {
        mult_m31[i] = try a.alloc(M31, mults[i].len);
        for (mults[i], mult_m31[i]) |m, *o| o.* = f.fromI32(m);
        inputs[rel.keys.len + i] = .{ .num = .{ .base = mult_m31[i] }, .den = try tableDen(a, st, t, alpha, beta), .owned = false };
    }
    var gkr_proof: ?GkrVerifier.GkrBatchProof = null;
    var art: lookups.verifier_kernel.Artifact(QM31) = .{ .ood_point = &.{}, .claims_to_verify_by_instance = &.{}, .n_variables_by_instance = &.{} };
    var gkr_stats: Fast.Stats = .{};
    timings.gkr_input_ns = nowNs(t0);
    key_bufs.joinWarm();
    // the GKR prover consumes (frees) the owned key inputs on every exit
    key_bufs.handed = key_bufs.bufs.len;
    if (n_inst > 0) {
        const gkr_res = if (cfg.accel != null) try accel.gkrProveBatch(cfg.accel, a, &tr.ch, inputs, cfg.gkr_threads) else try Fast.proveBatch(a, &tr.ch, inputs, .{ .threads = cfg.gkr_threads, .min_parallel = cfg.gkr_min_parallel }, &gkr_stats);
        gkr_proof = gkr_res.proof;
        art = gkr_res.artifact;
    }
    // table dens were borrowed (owned=false): free them now
    for (rel.tables, 0..) |_, i| a.free(inputs[rel.keys.len + i].den);
    defer if (n_inst > 0) art.deinit(a);
    timings.gkr_ns = nowNs(t0);
    // CPU batch stage: allocate its E table now (the GKR layers are gone) and
    // fault in the pages it will write while the terminal and op sumchecks run.
    var e_pre = PrefaultBuf{};
    defer e_pre.deinit(a);
    if (cfg.accel == null and cfg.prefault_gkr_inputs) try e_pre.start(a, total, lay.used);
    timings.gkr_build_ns = gkr_stats.build_ns;
    timings.gkr_sumcheck_ns = gkr_stats.sumcheck_ns;
    const L = art.ood_point.len;

    var claims: ClaimList = .empty;
    defer {
        for (claims.items) |c| a.free(c.point);
        claims.deinit(a);
    }
    var weight_claims: std.ArrayList(WeightClaimP) = .empty;
    defer {
        for (weight_claims.items) |c| a.free(c.point);
        weight_claims.deinit(a);
    }

    const t_term = try std.time.Instant.now();
    // terminal claims -> witness claims
    var lookup_vals: std.ArrayList(QM31) = .empty;
    const y_vals = try a.alloc(QM31, rel.keys.len);
    defer a.free(y_vals);
    for (rel.keys, 0..) |k, i| {
        const pt = art.ood_point[L - k.log_size ..];
        switch (k.kind) {
            .glu_triple => {
                const g = st.ops[k.op].glu;
                const vg = try accel.mleEvalI32Pool(cfg.accel, a, pool, all[g.g], pt);
                const vu = try accel.mleEvalI32Pool(cfg.accel, a, pool, all[g.u], pt);
                try lookup_vals.append(a, vg);
                try lookup_vals.append(a, vu);
                tr.mixFelts(&.{ vg, vu });
                const den = art.claims_to_verify_by_instance[i][1];
                const b2 = beta.mul(beta);
                const vh = alpha.sub(den).sub(vg).sub(beta.mul(vu)).mul(b2.inv() catch unreachable);
                try claims.append(a, .{ .tensor = g.g, .point = try a.dupe(QM31, pt), .value = vg });
                try claims.append(a, .{ .tensor = g.u, .point = try a.dupe(QM31, pt), .value = vu });
                try claims.append(a, .{ .tensor = g.h, .point = try a.dupe(QM31, pt), .value = vh });
            },
            .remainder, .y_range => {
                if (k.kind == .remainder) {
                    const has_range = i + 1 < rel.keys.len and rel.keys[i + 1].kind == .y_range and rel.keys[i + 1].op == k.op;
                    if (has_range) {
                        y_vals[i] = alpha.sub(art.claims_to_verify_by_instance[i + 1][1]).sub(f.qFromI64(128));
                    } else {
                        const y_id: u32 = switch (st.ops[k.op]) {
                            .matmul => |m| m.y,
                            .hadamard => |h| h.y,
                            else => unreachable,
                        };
                        const yv = try accel.mleEvalI32Pool(cfg.accel, a, pool, all[y_id], pt);
                        try lookup_vals.append(a, yv);
                        tr.mixFelt(yv);
                        y_vals[i] = yv;
                        try claims.append(a, .{ .tensor = y_id, .point = try a.dupe(QM31, pt), .value = yv });
                    }
                }
                if (k.kind == .y_range) {
                    const y_id: u32 = switch (st.ops[k.op]) {
                        .matmul => |m| m.y,
                        .hadamard => |h| h.y,
                        else => unreachable,
                    };
                    const den = art.claims_to_verify_by_instance[i][1];
                    try claims.append(a, .{ .tensor = y_id, .point = try a.dupe(QM31, pt), .value = alpha.sub(den).sub(f.qFromI64(128)) });
                }
            },
            .plain_range => {
                const den = art.claims_to_verify_by_instance[i][1];
                try claims.append(a, .{ .tensor = st.ops[k.op].range8.in, .point = try a.dupe(QM31, pt), .value = alpha.sub(den).sub(f.qFromI64(128)) });
            },
            .lookup_pair => {
                const l = st.ops[k.op].lookup;
                const vin = try accel.mleEvalI32Pool(cfg.accel, a, pool, all[l.in], pt);
                try lookup_vals.append(a, vin);
                tr.mixFelt(vin);
                const den = art.claims_to_verify_by_instance[i][1];
                const vout = alpha.sub(den).sub(vin).mul(beta.inv() catch unreachable);
                try claims.append(a, .{ .tensor = l.in, .point = try a.dupe(QM31, pt), .value = vin });
                try claims.append(a, .{ .tensor = l.out, .point = try a.dupe(QM31, pt), .value = vout });
            },
            .ext => {},
        }
    }
    for (rel.tables, 0..) |t, ti| {
        const pt = art.ood_point[L - t.log_size ..];
        const num = art.claims_to_verify_by_instance[rel.keys.len + ti][0];
        try claims.append(a, .{ .tensor = t.mult_tensor, .point = try a.dupe(QM31, pt), .value = num });
    }
    var ext_values: std.ArrayList(QM31) = .empty;
    errdefer ext_values.deinit(a);
    var ext_sumchecks: std.ArrayList(sc.Proof) = .empty;
    errdefer ext_sumchecks.deinit(a);
    var ext_finals: std.ArrayList([2]QM31) = .empty;
    errdefer ext_finals.deinit(a);
    const gview = xt.GkrView{ .ood = art.ood_point, .cv = @ptrCast(art.claims_to_verify_by_instance), .key_base = rel.ext_base };
    const t_ext_term = try std.time.Instant.now();
    try xt.proveTerminal(a, pool, st, all, &eps, gview, alpha, beta, &tr, &claims, &ext_values);
    timings.ext_terminal_ns = nowNs(t_ext_term);

    // --- op sumchecks (matmul / hadamard), in key order (one per remainder key)
    timings.terminal_ns = nowNs(t_term);
    t0 = try std.time.Instant.now();
    var op_proofs: std.ArrayList(sc.Proof) = .empty;
    var op_finals: std.ArrayList([]QM31) = .empty;
    const class_done = try a.alloc(bool, rel.keys.len);
    defer a.free(class_done);
    @memset(class_done, false);
    for (rel.keys, 0..) |k, i| {
        if (k.kind != .remainder) continue;
        if (isBatchedMatmul(st, st.ops[k.op])) {
            const m = st.ops[k.op].matmul;
            const pt = art.ood_point[L - k.log_size ..];
            try proveMatmul3(a, pool, cfg, &tr, st, ws, all, m, pt, accValue(art, i, m.shift, alpha, y_vals), timings, &op_proofs, &op_finals, &claims, &weight_claims);
            continue;
        }
        if (cfg.batch_matmuls and st.ops[k.op] == .matmul) {
            if (class_done[i]) continue;
            const members = try classMembers(a, st, rel, i);
            defer a.free(members);
            for (members) |mi| class_done[mi] = true;
            try proveMatmulClass(a, pool, &tr, st, ws, all, art, rel, members, alpha, y_vals, timings, &op_proofs, &op_finals, &claims, &weight_claims);
            continue;
        }
        const pt = art.ood_point[L - k.log_size ..];
        // acc(rho) = r(rho) - 2^(s-1) + 2^s y(rho), with r = alpha - den_r, y = alpha - den_y - 128
        const r_val = alpha.sub(art.claims_to_verify_by_instance[i][1]);
        const y_val = y_vals[i];
        switch (st.ops[k.op]) {
            .matmul => |m| {
                const sh = m.shift;
                const acc_val = r_val.sub(f.qFromI64(shiftHalf(sh))).add(y_val.mulM31(M31.fromCanonical(@as(u32, 1) << sh)));
                const xi = st.witness[m.x];
                const lt = xi.log_dims[0];
                const lk = xi.log_dims[1];
                const rho_t = pt[0..lt];
                const rho_n = pt[lt..];
                // f(k) = X(rho_t, k)
                const eq_t = try f.eqTablePar(a, pool, rho_t, QM31.one());
                defer a.free(eq_t);
                const xm = pcs.Matrix(i32){ .data = all[m.x], .log_rows = lt, .log_cols = lk };
                const fx = try accel.colCombine(cfg.accel, i32, a, pool, xm, eq_t, operandBoundLog2(st, m.x));
                defer a.free(fx);
                // g(k) = W(k, rho_n): the weight pass
                const tw0 = try std.time.Instant.now();
                const eq_n = try f.eqTablePar(a, pool, rho_n, QM31.one());
                defer a.free(eq_n);
                const gw = try accel.rowDots(cfg.accel, a, pool, ws.matrix(m.w), eq_n, 7);
                defer a.free(gw);
                timings.weight_fold_ns += nowNs(tw0);
                const res = try accel.proveActive(cfg.accel, 2, &T_PROD2, a, pool, &tr, acc_val, .{ fx, gw }, fx.len);
                defer a.free(res.point);
                try op_proofs.append(a, res.proof);
                tr.mixFelts(res.finals);
                try op_finals.append(a, res.finals);
                const px = try a.alloc(QM31, lt + lk);
                @memcpy(px[0..lt], rho_t);
                @memcpy(px[lt..], res.point);
                try claims.append(a, .{ .tensor = m.x, .point = px, .value = res.finals[0] });
                const pw = try a.alloc(QM31, lk + rho_n.len);
                @memcpy(pw[0..lk], res.point);
                @memcpy(pw[lk..], rho_n);
                try weight_claims.append(a, .{ .w = m.w, .point = pw, .value = res.finals[1] });
            },
            .hadamard => |h| {
                const sh = h.shift;
                const acc_val = r_val.sub(f.qFromI64(shiftHalf(sh))).add(y_val.mulM31(M31.fromCanonical(@as(u32, 1) << sh)));
                // identical transcripts: device path (accel) or split-eq CPU prover
                var res = if (cfg.accel != null) blk: {
                    const eq = try f.eqTablePar(a, pool, pt, QM31.one());
                    const fa = try toQM31Vec(a, pool, all[h.a]);
                    const fb = try toQM31Vec(a, pool, all[h.b]);
                    defer a.free(eq);
                    defer a.free(fa);
                    defer a.free(fb);
                    break :blk try accel.proveActive(cfg.accel, 3, &T_EQ3, a, pool, &tr, acc_val, .{ eq, fa, fb }, eq.len);
                } else try eqsum.prove(.hadamard, a, pool, &tr, acc_val, pt, .{ all[h.a], all[h.b] });
                defer a.free(res.point);
                try op_proofs.append(a, res.proof);
                tr.mixFelts(res.finals[1..]);
                const fin = try a.dupe(QM31, res.finals[1..]);
                a.free(res.finals);
                try op_finals.append(a, fin);
                try claims.append(a, .{ .tensor = h.a, .point = try a.dupe(QM31, res.point), .value = fin[0] });
                try claims.append(a, .{ .tensor = h.b, .point = try a.dupe(QM31, res.point), .value = fin[1] });
            },
            else => unreachable,
        }
    }
    for (st.ops) |op| switch (op) {
        .product => |q| {
            const ls = st.witness[q.c].logSize();
            const rho = try a.alloc(QM31, ls);
            defer a.free(rho);
            tr.drawN(rho);
            // identical transcripts: device path (accel) or split-eq CPU prover
            var res = if (cfg.accel != null) blk: {
                const eqc = [_]accel.BatchClaim{.{ .offset = 0, .point = rho, .gamma = QM31.one() }};
                const n_prod = @as(usize, 1) << @intCast(ls);
                break :blk try accel.proveFactors(cfg.accel, 4, &T_PRODUCT, a, pool, &tr, QM31.zero(), .{ .{ .eq = &eqc }, .{ .int = all[q.a] }, .{ .int = all[q.b] }, .{ .int = all[q.c] } }, n_prod, n_prod);
            } else try eqsum.prove(.product, a, pool, &tr, QM31.zero(), rho, .{ all[q.a], all[q.b], all[q.c] });
            defer a.free(res.point);
            try op_proofs.append(a, res.proof);
            const fin = try a.dupe(QM31, res.finals[1..]);
            a.free(res.finals);
            res.finals = &.{};
            tr.mixFelts(fin);
            try op_finals.append(a, fin);
            try claims.append(a, .{ .tensor = q.a, .point = try a.dupe(QM31, res.point), .value = fin[0] });
            try claims.append(a, .{ .tensor = q.b, .point = try a.dupe(QM31, res.point), .value = fin[1] });
            try claims.append(a, .{ .tensor = q.c, .point = try a.dupe(QM31, res.point), .value = fin[2] });
        },
        else => {},
    };
    const t_ext_ops = try std.time.Instant.now();
    try xt.proveOps(a, pool, cfg.accel, st, all, &eps, gview, alpha, &tr, &claims, &ext_values, &ext_sumchecks, &ext_finals);
    timings.ext_ops_ns = nowNs(t_ext_ops);
    timings.op_sumcheck_ns = nowNs(t0);

    // --- batch witness claims into one point
    t0 = try std.time.Instant.now();
    for (claims.items) |c| tr.mixFelt(c.value);
    const gammas = try a.alloc(QM31, claims.items.len);
    defer a.free(gammas);
    tr.drawN(gammas);
    var batch_claim = QM31.zero();
    for (claims.items, gammas) |c, g| batch_claim = batch_claim.add(g.mul(c.value));
    const bres = if (cfg.accel != null) blk: {
        const bclaims = try a.alloc(accel.BatchClaim, claims.items.len);
        defer a.free(bclaims);
        for (claims.items, gammas, bclaims) |c, g, *bc| bc.* = .{ .offset = lay.offsets[c.tensor], .point = c.point, .gamma = g };
        break :blk try accel.batchProve(cfg.accel, a, pool, &tr, wtab, lay.used, bclaims, batch_claim);
    } else blk: {
        // E = sum_c gamma_c eq(z_c, .) on tensor c's block; entries >= lay.used are never read.
        const E = try e_pre.take(a, total);
        defer a.free(E);
        // Structured prover (batch_eq.zig: split eq per claim, E never
        // materialised) when its cost model wins; identical transcript.
        // TENSOR_BATCH_EQ=0 forces the materialised-E prover.
        if (total >= 2 and batchEqEnabled()) {
            const sclaims = try a.alloc(batch_eq.Claim, claims.items.len);
            defer a.free(sclaims);
            for (claims.items, gammas, sclaims) |c, g, *sc_| {
                if (c.point.len != ext[c.tensor].logSize()) return error.ClaimShape;
                sc_.* = .{ .offset = lay.offsets[c.tensor], .point = c.point, .gamma = g, .value = c.value };
            }
            if (try batch_eq.worthIt(a, total, lay.used, sclaims))
                break :blk try batch_eq.prove(a, pool, &tr, batch_claim, wtab, lay.used, sclaims, E[0 .. total / 2]);
        }
        var rc: std.ArrayList(batch.RegionClaim) = .empty;
        defer rc.deinit(a);
        for (ext, 0..) |info, t| {
            rc.clearRetainingCapacity();
            for (claims.items, gammas) |c, g| if (c.tensor == t) {
                if (c.point.len != info.logSize()) return error.ClaimShape;
                try rc.append(a, .{ .point = c.point, .gamma = g });
            };
            try batch.fillRegion(a, pool, E[lay.offsets[t]..][0..info.size()], rc.items);
        }
        break :blk try batch.proveBaseTimesExt(a, pool, &tr, batch_claim, wtab, E, lay.used);
    };
    defer a.free(bres.point);
    const wval = bres.finals[0];
    a.free(bres.finals);
    timings.batch_ns = nowNs(t0);

    // --- witness opening (with proximity)
    t0 = try std.time.Instant.now();
    const wclaim = [_]pcs.Claim{.{ .point = bres.point, .value = wval }};
    const woclaim = [_]pcs.Claim{.{ .point = wood_pt, .value = wood orelse QM31.zero() }};
    const wgroups_all = [_]pcs.Group{ .{ .claims = &wclaim }, .{ .claims = &woclaim } };
    const wgroups = wgroups_all[0 .. 1 + @as(usize, @intFromBool(witnessOod(cfg)))];
    const wopen: Opening = if (cfg.two_level) |tl|
        .{ .two = try pcs2.open(i32, a, pool, &tr, tl, &wcom, wm, wgroups, true) }
    else
        .{ .flat = try pcs.open(i32, a, pool, &tr, cfg.pcs, &wcom, wm, wgroups, true) };
    timings.witness_open_ns = nowNs(t0);

    tr_io.* = tr;
    weight_claims_out.* = weight_claims;
    weight_claims = .empty;

    return .{
        .security = cfg.security,
        .witness_root = wcom.root(),
        .gkr = gkr_proof,
        .lookup_in_values = try lookup_vals.toOwnedSlice(a),
        .op_sumchecks = try op_proofs.toOwnedSlice(a),
        .op_finals = try op_finals.toOwnedSlice(a),
        .batch_sumcheck = bres.proof,
        .witness_value = wval,
        .witness_ood = wood,
        .witness_opening = wopen,
        .weight_opening = null,
        .ext = .{ .values = try ext_values.toOwnedSlice(a), .sumchecks = try ext_sumchecks.toOwnedSlice(a), .finals = try ext_finals.toOwnedSlice(a) },
    };
}

// ---------------------------------------------------------------------------
// Verifier.

pub const WeightKey = struct {
    root: [32]u8,
    infos: []const TensorInfo,
    offsets: []const usize,
    log_rows: u32,
    log_cols: u32,
    rows_used: usize,
    /// the table's MLE at `weightOodPoint(key)`, certified by the key proof;
    /// every batch's weight opening includes the claim (z_ood, ood_value)
    ood_value: QM31,
};

pub fn weightKey(ws: *const WeightStore) WeightKey {
    return .{ .root = ws.com.root(), .infos = ws.infos, .offsets = ws.offsets, .log_rows = ws.log_rows, .log_cols = ws.log_cols, .rows_used = ws.rows_used, .ood_value = ws.ood_value };
}

/// Max witness tensors per statement (validateStatement's bound table).
pub const MAX_STATEMENT_TENSORS = 4096;

/// The bound_log2 to pass to colCombine / combineRows for witness tensor `t`:
/// the relation-proved bound from bounds.zig (|t[i]| <= 2^b, full-coverage
/// relations only), or 31 (any i32; combineRows then reduces every 2 rows)
/// when the tensor has no numeric bound (KERN-3 and its recheck variant).
pub fn operandBoundLog2(st: Statement, t: u32) u32 {
    var buf: [MAX_STATEMENT_TENSORS]u8 = undefined;
    if (st.witness.len > buf.len or t >= st.witness.len) return 31;
    const bound = buf[0..st.witness.len];
    @import("bounds.zig").validateStatementBounds(st, bound) catch return 31;
    return if (bound[t] > 30) 31 else bound[t];
}

/// Public well-formedness checks the soundness argument relies on (see
/// bounds.zig): shapes and ids are checked before any indexing; every
/// multiplication operand (core matmul / hadamard, ext einsum) and every term
/// of a range / lookup / linear relation has a magnitude bound derived from
/// proved relations; no accumulator, exact product, or relation can wrap mod
/// p; 1 <= shift <= 22 on core ops. Run by verify() before anything else.
pub fn validateStatement(st: Statement) !void {
    return @import("bounds.zig").validateStatement(st);
}

/// Statement-derived proof shape that the wire decoder (wire.zig) bounds its
/// lengths by: the witness table's opening shape and the LogUp-GKR instance
/// sizes (relation keys first, then tables, as in the verifier).
pub const WireShape = struct {
    witness: pcs.Shape,
    witness_groups: usize,
    log_total: u32,
    n_keys: usize,
    inst_log_sizes: []u32,

    pub fn deinit(self: *WireShape, a: std.mem.Allocator) void {
        a.free(self.inst_log_sizes);
    }
};

pub fn wireShape(a: std.mem.Allocator, cfg: Config, st: Statement) !WireShape {
    try validateStatement(st);
    try xt.validate(st);
    var rel = try deriveRelations(a, st);
    defer rel.deinit(a);
    const ext = try extendedInfos(a, st, rel);
    defer a.free(ext);
    const lay = try layout(a, ext, &.{});
    defer a.free(lay.offsets);
    const split = witnessSplit(cfg, lay.log_total, lay.used);
    const sizes = try a.alloc(u32, rel.keys.len + rel.tables.len);
    for (rel.keys, 0..) |k, i| sizes[i] = k.log_size;
    for (rel.tables, 0..) |t, i| sizes[rel.keys.len + i] = t.log_size;
    const w_ru = (lay.used + (@as(usize, 1) << @intCast(split.lc)) - 1) >> @intCast(split.lc);
    return .{
        .witness = .{ .log_rows = split.lr, .log_cols = split.lc, .log_blowup = outerParams(cfg).log_blowup, .rows_used = w_ru },
        .witness_groups = 1 + @as(usize, @intFromBool(witnessOod(cfg))),
        .log_total = lay.log_total,
        .n_keys = rel.keys.len,
        .inst_log_sizes = sizes,
    };
}

/// What the verifier checked, for the soundness calculator (security.zig).
pub const VerifyInfo = struct {
    witness_shape: pcs.Shape = .{ .log_rows = 0, .log_cols = 0, .log_blowup = 0 },
    witness_groups: usize = 0,
    weight_shape: ?pcs.Shape = null,
    /// weight groups include the key's OOD claim group
    weight_groups: usize = 0,
    weight_proximity: bool = false,
    /// LogUp: number of fractions (keys + table rows) summed over all
    /// relations, and of the largest relation (must stay below p)
    logup_fractions: f64 = 0,
    logup_max_relation: f64 = 0,
    /// largest key arity (1 = single values, 3 = glu triples)
    logup_max_arity: u32 = 1,
    /// sum over relations of g_rel * fractions_rel, with g_rel = max(arity - 1,
    /// 1) the total degree of the relation's denominators in (alpha, beta)
    logup_degree_fractions: f64 = 0,
};

pub fn verify(a: std.mem.Allocator, cfg: Config, st: Statement, key: WeightKey, proof: *const Proof) !void {
    return verifyInfo(a, cfg, st, key, proof, null);
}

/// As `verify`, and fills `info` (when given) for the soundness calculator.
pub fn verifyInfo(a: std.mem.Allocator, cfg: Config, st: Statement, key: WeightKey, proof: *const Proof, info: ?*VerifyInfo) !void {
    var tr = Transcript.initDomain("stwo-tensor-v1");
    var wc = VerifierWeightClaims{};
    defer wc.deinit(a);
    try verifyCore(a, cfg, st, key, proof, &tr, &wc, info);
    // weight claims: the values are the matmul finals for W (not resent)
    if (wc.values.items.len != wc.points.items.len) return error.ProofShape;
    const wcl = try a.alloc(pcs.Claim, wc.points.items.len);
    defer a.free(wcl);
    for (wc.points.items, wc.values.items, 0..) |p, v, i| wcl[i] = .{ .point = p, .value = v };
    if ((wcl.len == 0) != (proof.weight_opening == null)) return error.ProofShape;
    if (proof.weight_opening) |wop| try verifyWeightOpening(a, &tr, cfg, key, wcl, wop, info);
}

/// Weight claims derived by the verifier's core pass: full points in the
/// weight table and the values the op sumchecks require there (the op
/// finals for W; the proof does not resend them).
pub const VerifierWeightClaims = struct {
    points: std.ArrayList([]QM31) = .empty,
    values: std.ArrayList(QM31) = .empty,

    pub fn deinit(self: *VerifierWeightClaims, a: std.mem.Allocator) void {
        for (self.points.items) |p| a.free(p);
        self.points.deinit(a);
        self.values.deinit(a);
    }
};

/// Verifies a weight opening of `wcl` (full points, verifier-derived values)
/// against the key with the per-batch weight parameters (`weightOpenConfig`);
/// groups are re-derived from the verifier's own points, as the prover does.
/// Records the weight shape and group count in `info` when given.
pub fn verifyWeightOpening(a: std.mem.Allocator, tr: *Transcript, cfg: Config, key: WeightKey, wcl_in: []const pcs.Claim, wop: Opening, info: ?*VerifyInfo) !void {
    const wcfg = try weightOpenConfig(cfg);
    const kshape = pcs.Shape{ .log_rows = key.log_rows, .log_cols = key.log_cols, .log_blowup = outerParams(cfg).log_blowup, .rows_used = key.rows_used };
    // PCS-1: the key's OOD claim joins the weight claims (see openWeightFull)
    const wcl = try a.alloc(pcs.Claim, wcl_in.len + 1);
    defer a.free(wcl);
    @memcpy(wcl[0..wcl_in.len], wcl_in);
    const wood_z = try weightOodPoint(a, key);
    defer a.free(wood_z);
    wcl[wcl_in.len] = .{ .point = wood_z, .value = key.ood_value };
    const gs = try pcs2.groupByColumn(a, wcl, key.log_rows);
    defer pcs2.freeGroups(a, gs);
    try verifyOpeningAny(a, tr, wcfg, kshape, key.root, gs, cfg.weight_proximity, wop);
    if (info) |inf| {
        inf.weight_groups = gs.len;
        inf.weight_shape = kshape;
        inf.weight_proximity = cfg.weight_proximity;
    }
}

/// The verifier of `proveCore`: everything but the weight opening, on the
/// caller's transcript. Appends the weight claims to `out` (protocol order)
/// and fills the witness/LogUp part of `info` when given.
pub fn verifyCore(a: std.mem.Allocator, cfg: Config, st: Statement, key: WeightKey, proof: *const Proof, tr_io: *Transcript, out: *VerifierWeightClaims, info: ?*VerifyInfo) !void {
    try checkSecurity(cfg);
    if (proof.security != cfg.security) return error.SecurityLevelMismatch;
    // every transmitted limb in [0, P) before any arithmetic (KERN-1)
    try canonical.check(proof);
    try validateStatement(st);
    // the key must carry exactly the canonical layout of the statement's
    // weights (dims, offsets, split, rows_used); checkKeyLayout subsumes the
    // earlier per-tensor shape comparison and reports error.WeightKeyShape
    try checkKeyLayout(a, st.weights, key);
    try xt.validate(st);
    var rel = try deriveRelations(a, st);
    defer rel.deinit(a);
    try checkLogUpCounts(rel);
    const ext = try extendedInfos(a, st, rel);
    defer a.free(ext);
    const lay = try layout(a, ext, &.{});
    defer a.free(lay.offsets);
    const split = witnessSplit(cfg, lay.log_total, lay.used);
    const olb = outerParams(cfg).log_blowup;

    var tr = tr_io.*;
    mixStatement(&tr, st, key);
    mixSecurity(&tr, cfg);
    tr.mixDigest(proof.witness_root);
    if ((proof.witness_ood != null) != witnessOod(cfg)) return error.ProofShape;
    const wood_pt = try a.alloc(QM31, if (witnessOod(cfg)) lay.log_total else 0);
    defer a.free(wood_pt);
    if (proof.witness_ood) |v| {
        tr.drawN(wood_pt);
        tr.mixFelt(v);
    }
    const alpha = tr.draw();
    const beta = tr.draw();

    const n_inst = rel.keys.len + rel.tables.len;
    if ((n_inst > 0) != (proof.gkr != null)) return error.GkrShape;
    var art: lookups.verifier_kernel.Artifact(QM31) = .{ .ood_point = &.{}, .claims_to_verify_by_instance = &.{}, .n_variables_by_instance = &.{} };
    if (proof.gkr) |*gp| {
        if (gp.output_claims_by_instance.len != n_inst) return error.GkrShape;
        const gates = try a.alloc(GkrVerifier.Gate, n_inst);
        defer a.free(gates);
        @memset(gates, .LogUp);
        art = try GkrVerifier.partiallyVerifyBatch(a, gates, gp, &tr.ch);
    }
    defer if (n_inst > 0) art.deinit(a);
    const L = art.ood_point.len;
    for (rel.keys, 0..) |k, i| if (art.n_variables_by_instance[i] != k.log_size) return error.GkrShape;
    for (rel.tables, 0..) |t, i| if (art.n_variables_by_instance[rel.keys.len + i] != t.log_size) return error.GkrShape;

    // LogUp sums per table relation must vanish.
    for (rel.tables, 0..) |_, ti| {
        var num = QM31.zero();
        var den = QM31.one();
        const add = struct {
            fn f(n: *QM31, d: *QM31, n2: QM31, d2: QM31) void {
                n.* = n.*.mul(d2).add(n2.mul(d.*));
                d.* = d.*.mul(d2);
            }
        }.f;
        for (rel.keys, 0..) |k, i| if (k.table == ti) {
            const oc = proof.gkr.?.output_claims_by_instance[i];
            if (oc.len != 2 or oc[1].isZero()) return error.GkrShape;
            add(&num, &den, oc[0], oc[1]);
        };
        const oc = proof.gkr.?.output_claims_by_instance[rel.keys.len + ti];
        if (oc.len != 2 or oc[1].isZero()) return error.GkrShape;
        // table side is subtracted
        add(&num, &den, oc[0].neg(), oc[1]);
        if (!num.isZero()) return error.LogUpSumNonZero;
    }

    var claims: ClaimList = .empty;
    defer {
        for (claims.items) |c| a.free(c.point);
        claims.deinit(a);
    }
    var lk_i: usize = 0;
    const y_vals = try a.alloc(QM31, rel.keys.len);
    defer a.free(y_vals);
    for (rel.keys, 0..) |k, i| {
        const pt = art.ood_point[L - k.log_size ..];
        const cv = art.claims_to_verify_by_instance[i];
        if (cv.len != 2) return error.GkrShape;
        if (!cv[0].eql(QM31.one())) return error.GkrTerminal; // singles: numerator MLE is 1
        switch (k.kind) {
            .remainder => {
                const has_range = i + 1 < rel.keys.len and rel.keys[i + 1].kind == .y_range and rel.keys[i + 1].op == k.op;
                if (has_range) {
                    y_vals[i] = alpha.sub(art.claims_to_verify_by_instance[i + 1][1]).sub(f.qFromI64(128));
                } else {
                    const y_id: u32 = switch (st.ops[k.op]) {
                        .matmul => |m| m.y,
                        .hadamard => |h| h.y,
                        else => unreachable,
                    };
                    if (lk_i >= proof.lookup_in_values.len) return error.ProofShape;
                    const yv = proof.lookup_in_values[lk_i];
                    lk_i += 1;
                    tr.mixFelt(yv);
                    y_vals[i] = yv;
                    try claims.append(a, .{ .tensor = y_id, .point = try a.dupe(QM31, pt), .value = yv });
                }
            },
            .glu_triple => {
                const g = st.ops[k.op].glu;
                if (lk_i + 2 > proof.lookup_in_values.len) return error.ProofShape;
                const vg = proof.lookup_in_values[lk_i];
                const vu = proof.lookup_in_values[lk_i + 1];
                lk_i += 2;
                tr.mixFelts(&.{ vg, vu });
                const b2 = beta.mul(beta);
                const vh = alpha.sub(cv[1]).sub(vg).sub(beta.mul(vu)).mul(b2.inv() catch return error.ProofShape);
                try claims.append(a, .{ .tensor = g.g, .point = try a.dupe(QM31, pt), .value = vg });
                try claims.append(a, .{ .tensor = g.u, .point = try a.dupe(QM31, pt), .value = vu });
                try claims.append(a, .{ .tensor = g.h, .point = try a.dupe(QM31, pt), .value = vh });
            },
            .y_range => {
                const y_id: u32 = switch (st.ops[k.op]) {
                    .matmul => |m| m.y,
                    .hadamard => |h| h.y,
                    else => unreachable,
                };
                try claims.append(a, .{ .tensor = y_id, .point = try a.dupe(QM31, pt), .value = alpha.sub(cv[1]).sub(f.qFromI64(128)) });
            },
            .plain_range => try claims.append(a, .{ .tensor = st.ops[k.op].range8.in, .point = try a.dupe(QM31, pt), .value = alpha.sub(cv[1]).sub(f.qFromI64(128)) }),
            .lookup_pair => {
                const l = st.ops[k.op].lookup;
                if (lk_i >= proof.lookup_in_values.len) return error.ProofShape;
                const vin = proof.lookup_in_values[lk_i];
                lk_i += 1;
                tr.mixFelt(vin);
                const vout = alpha.sub(cv[1]).sub(vin).mul(beta.inv() catch return error.ProofShape);
                try claims.append(a, .{ .tensor = l.in, .point = try a.dupe(QM31, pt), .value = vin });
                try claims.append(a, .{ .tensor = l.out, .point = try a.dupe(QM31, pt), .value = vout });
            },
            .ext => {},
        }
    }
    if (lk_i != proof.lookup_in_values.len) return error.ProofShape;
    for (rel.tables, 0..) |t, ti| {
        const pt = art.ood_point[L - t.log_size ..];
        const cv = art.claims_to_verify_by_instance[rel.keys.len + ti];
        if (cv.len != 2) return error.GkrShape;
        const expect_den = alpha.sub(try tableKeyMle(st, a, t, pt, beta));
        if (!cv[1].eql(expect_den)) return error.GkrTerminal;
        try claims.append(a, .{ .tensor = t.mult_tensor, .point = try a.dupe(QM31, pt), .value = cv[0] });
    }
    const gview = xt.GkrView{ .ood = art.ood_point, .cv = @ptrCast(art.claims_to_verify_by_instance), .key_base = rel.ext_base };
    var ext_cur: usize = 0;
    try xt.verifyTerminal(a, st, rel.ext_keys, gview, alpha, beta, &tr, &claims, &proof.ext, &ext_cur);

    var weight_pts: std.ArrayList([]QM31) = .empty;
    defer {
        for (weight_pts.items) |p| a.free(p);
        weight_pts.deinit(a);
    }
    if (proof.op_finals.len != proof.op_sumchecks.len) return error.ProofShape;
    var expected_w: std.ArrayList(QM31) = .empty;
    defer expected_w.deinit(a);
    const vclass_done = try a.alloc(bool, rel.keys.len);
    defer a.free(vclass_done);
    @memset(vclass_done, false);
    var op_i: usize = 0;
    for (rel.keys, 0..) |k, i| {
        if (k.kind != .remainder) continue;
        // members of an already verified matmul class consume no sumcheck;
        // skip them before the bounds check (a statement whose last
        // remainder keys belong to an earlier class was rejected otherwise)
        if (cfg.batch_matmuls and st.ops[k.op] == .matmul and vclass_done[i]) continue;
        if (op_i >= proof.op_sumchecks.len) return error.ProofShape;
        if (isBatchedMatmul(st, st.ops[k.op])) {
            const m = st.ops[k.op].matmul;
            const pt = art.ood_point[L - k.log_size ..];
            try verifyMatmul3(a, &tr, st, key, m, pt, accValue(art, i, m.shift, alpha, y_vals), proof.op_sumchecks[op_i], proof.op_finals[op_i], &claims, &weight_pts, &expected_w);
            op_i += 1;
            continue;
        }
        if (cfg.batch_matmuls and st.ops[k.op] == .matmul) {
            const members = try classMembers(a, st, rel, i);
            defer a.free(members);
            for (members) |mi| vclass_done[mi] = true;
            try verifyMatmulClass(a, &tr, st, key, art, rel, members, alpha, y_vals, proof.op_sumchecks[op_i], proof.op_finals[op_i], &claims, &weight_pts, &expected_w);
            op_i += 1;
            continue;
        }
        const pt = art.ood_point[L - k.log_size ..];
        const r_val = alpha.sub(art.claims_to_verify_by_instance[i][1]);
        const y_val = y_vals[i];
        const sh: u5 = switch (st.ops[k.op]) {
            .matmul => |m| m.shift,
            .hadamard => |h| h.shift,
            else => unreachable,
        };
        const acc_val = r_val.sub(f.qFromI64(shiftHalf(sh))).add(y_val.mulM31(M31.fromCanonical(@as(u32, 1) << sh)));
        const fin = proof.op_finals[op_i];
        switch (st.ops[k.op]) {
            .matmul => |m| {
                const xi = st.witness[m.x];
                const lt = xi.log_dims[0];
                const lkk = xi.log_dims[1];
                if (st.weights[m.w].log_dims[0] != lkk or st.weights[m.w].log_dims[1] != k.log_size - lt) return error.StatementShape;
                const vr = try sc.verify(a, &tr, acc_val, lkk, 2, proof.op_sumchecks[op_i]);
                defer a.free(vr.point);
                if (fin.len != 2) return error.ProofShape;
                if (!vr.final_claim.eql(fin[0].mul(fin[1]))) return error.OpSumcheck;
                tr.mixFelts(fin);
                const px = try a.alloc(QM31, lt + lkk);
                @memcpy(px[0..lt], pt[0..lt]);
                @memcpy(px[lt..], vr.point);
                try claims.append(a, .{ .tensor = m.x, .point = px, .value = fin[0] });
                const pw = try a.alloc(QM31, lkk + (k.log_size - lt));
                @memcpy(pw[0..lkk], vr.point);
                @memcpy(pw[lkk..], pt[lt..]);
                try weight_pts.append(a, try fullPoint(a, key.log_rows + key.log_cols, key.offsets[m.w], key.infos[m.w].logSize(), pw));
                try expected_w.append(a, fin[1]);
                a.free(pw);
            },
            .hadamard => |h| {
                const vr = try sc.verify(a, &tr, acc_val, k.log_size, 3, proof.op_sumchecks[op_i]);
                defer a.free(vr.point);
                if (fin.len != 2) return error.ProofShape;
                if (!vr.final_claim.eql(f.eqEval(pt, vr.point).mul(fin[0]).mul(fin[1]))) return error.OpSumcheck;
                tr.mixFelts(fin);
                try claims.append(a, .{ .tensor = h.a, .point = try a.dupe(QM31, vr.point), .value = fin[0] });
                try claims.append(a, .{ .tensor = h.b, .point = try a.dupe(QM31, vr.point), .value = fin[1] });
            },
            else => unreachable,
        }
        op_i += 1;
    }
    for (st.ops) |op| switch (op) {
        .product => |q| {
            if (op_i >= proof.op_sumchecks.len) return error.ProofShape;
            const ls = st.witness[q.c].logSize();
            if (st.witness[q.a].logSize() != ls or st.witness[q.b].logSize() != ls) return error.StatementShape;
            const rho = try a.alloc(QM31, ls);
            defer a.free(rho);
            tr.drawN(rho);
            const vr = try sc.verify(a, &tr, QM31.zero(), ls, 3, proof.op_sumchecks[op_i]);
            defer a.free(vr.point);
            const fin = proof.op_finals[op_i];
            if (fin.len != 3) return error.ProofShape;
            const e = f.eqEval(rho, vr.point);
            if (!vr.final_claim.eql(e.mul(fin[0].mul(fin[1]).sub(fin[2])))) return error.OpSumcheck;
            tr.mixFelts(fin);
            try claims.append(a, .{ .tensor = q.a, .point = try a.dupe(QM31, vr.point), .value = fin[0] });
            try claims.append(a, .{ .tensor = q.b, .point = try a.dupe(QM31, vr.point), .value = fin[1] });
            try claims.append(a, .{ .tensor = q.c, .point = try a.dupe(QM31, vr.point), .value = fin[2] });
            op_i += 1;
        },
        else => {},
    };
    if (op_i != proof.op_sumchecks.len) return error.ProofShape;
    try xt.verifyOps(a, st, rel.ext_keys, gview, alpha, &tr, &claims, &proof.ext, &ext_cur);

    // batch reduction
    for (claims.items) |c| tr.mixFelt(c.value);
    const gammas = try a.alloc(QM31, claims.items.len);
    defer a.free(gammas);
    tr.drawN(gammas);
    var batch_claim = QM31.zero();
    for (claims.items, gammas) |c, g| batch_claim = batch_claim.add(g.mul(c.value));
    const bv = try sc.verify(a, &tr, batch_claim, lay.log_total, 2, proof.batch_sumcheck);
    defer a.free(bv.point);
    var e_at = QM31.zero();
    for (claims.items, gammas) |c, g| {
        const fp = try fullPoint(a, lay.log_total, lay.offsets[c.tensor], ext[c.tensor].logSize(), c.point);
        defer a.free(fp);
        e_at = e_at.add(g.mul(f.eqEval(fp, bv.point)));
    }
    if (!bv.final_claim.eql(proof.witness_value.mul(e_at))) return error.BatchSumcheck;

    const wclaim = [_]pcs.Claim{.{ .point = bv.point, .value = proof.witness_value }};
    const woclaim = [_]pcs.Claim{.{ .point = wood_pt, .value = proof.witness_ood orelse QM31.zero() }};
    const wgroups_all = [_]pcs.Group{ .{ .claims = &wclaim }, .{ .claims = &woclaim } };
    const wgroups = wgroups_all[0 .. 1 + @as(usize, @intFromBool(witnessOod(cfg)))];
    const w_ru = (lay.used + (@as(usize, 1) << @intCast(split.lc)) - 1) >> @intCast(split.lc);
    const wshape = pcs.Shape{ .log_rows = split.lr, .log_cols = split.lc, .log_blowup = olb, .rows_used = w_ru };
    try verifyOpeningAny(a, &tr, cfg, wshape, proof.witness_root, wgroups, true, proof.witness_opening);
    if (info) |inf| {
        inf.witness_shape = wshape;
        inf.witness_groups = wgroups.len;
        for (rel.tables, 0..) |t, ti| {
            var d: f64 = @floatFromInt(@as(u64, 1) << @intCast(t.log_size));
            // the table's own entries: range values, (key, out) pairs, glu
            // triples; ext tables counted as triples (conservative)
            var ar_rel: u32 = switch (t.kind) {
                .range => 1,
                .act => 2,
                .glu, .ext_lookup => 3,
            };
            for (rel.keys) |k| if (k.table == ti) {
                d += @floatFromInt(@as(u64, 1) << @intCast(k.log_size));
                const ar: u32 = switch (k.kind) {
                    .lookup_pair => 2,
                    .glu_triple, .ext => 3,
                    else => 1,
                };
                ar_rel = @max(ar_rel, ar);
            };
            inf.logup_max_arity = @max(inf.logup_max_arity, ar_rel);
            inf.logup_degree_fractions += @as(f64, @floatFromInt(@max(ar_rel, 2) - 1)) * d;
            inf.logup_fractions += d;
            inf.logup_max_relation = @max(inf.logup_max_relation, d);
        }
    }

    tr_io.* = tr;
    out.points = weight_pts;
    weight_pts = .empty;
    out.values = expected_w;
    expected_w = .empty;
}

/// Verifies an opening of the PCS flavour selected by `cfg`; a proof of the
/// other flavour is rejected.
pub fn verifyOpeningAny(a: std.mem.Allocator, tr: *Transcript, cfg: Config, shape: pcs.Shape, root: [32]u8, groups: []const pcs.Group, with_proximity: bool, op: Opening) !void {
    if (cfg.two_level) |tl| {
        if (op != .two) return error.ProofShape;
        try pcs2.verify(a, tr, tl, shape, root, groups, with_proximity, op.two);
    } else {
        if (op != .flat) return error.ProofShape;
        var tw = try pcs.Twiddles.init(a, shape.log_cols + shape.log_blowup);
        defer tw.deinit(a);
        try pcs.verifyOpening(a, tr, cfg.pcs, &tw, shape, root, groups, with_proximity, op.flat);
    }
}

/// Offline: proximity test of the committed weight table (run once per commitment).
pub fn proveWeightProximity(a: std.mem.Allocator, pool: *f.Pool, cfg0: Config, ws: *const WeightStore) !Opening {
    const cfg = try keyConfig(cfg0);
    var tr = Transcript.initDomain("stwo-tensor-weights-v1");
    tr.mixDigest(ws.com.root());
    if (cfg.two_level) |tl| return .{ .two = try pcs2.open(i8, a, pool, &tr, tl, &ws.com, ws.tableMatrix(), &.{}, true) };
    return .{ .flat = try pcs.open(i8, a, pool, &tr, cfg.pcs, &ws.com, ws.tableMatrix(), &.{}, true) };
}

pub fn verifyWeightProximity(a: std.mem.Allocator, cfg0: Config, key: WeightKey, proof: Opening) !void {
    try canonical.check(proof);
    const cfg = try keyConfig(cfg0);
    var tr = Transcript.initDomain("stwo-tensor-weights-v1");
    tr.mixDigest(key.root);
    const shape = pcs.Shape{ .log_rows = key.log_rows, .log_cols = key.log_cols, .log_blowup = outerParams(cfg).log_blowup, .rows_used = key.rows_used };
    try verifyOpeningAny(a, &tr, cfg, shape, key.root, &.{}, true, proof);
}

// ---------------------------------------------------------------------------
// Shape-class batching of matmuls (Config.batch_matmuls).

pub const WeightClaimP = struct { w: usize, point: []QM31, value: QM31 };

fn sameMatmulClass(st: Statement, x: anytype, y: anytype) bool {
    const a = st.witness[x.x];
    const b = st.witness[y.x];
    return a.log_dims[0] == b.log_dims[0] and a.log_dims[1] == b.log_dims[1] and
        st.weights[x.w].log_dims[0] == st.weights[y.w].log_dims[0] and st.weights[x.w].log_dims[1] == st.weights[y.w].log_dims[1];
}

/// Remainder-key indices of all matmuls in the shape class of key i, in key order.
fn classMembers(a: std.mem.Allocator, st: Statement, rel: Relations, i: usize) ![]usize {
    const m0 = st.ops[rel.keys[i].op].matmul;
    var out: std.ArrayList(usize) = .empty;
    for (rel.keys, 0..) |k, j| {
        if (k.kind != .remainder) continue;
        switch (st.ops[k.op]) {
            .matmul => |m| if (st.weights[m.w].n_dims == 2 and sameMatmulClass(st, m0, m)) try out.append(a, j),
            else => {},
        }
    }
    return out.toOwnedSlice(a);
}

/// acc(rho) of a remainder key from the GKR terminal claims (r and y keys).
/// acc(rho) of a remainder key: r from its GKR terminal claim, y from the
/// terminal loop (y_range instance or a prover-sent value when elided).
fn accValue(art: lookups.verifier_kernel.Artifact(QM31), i: usize, sh: u5, alpha: QM31, y_vals: []const QM31) QM31 {
    const r_val = alpha.sub(art.claims_to_verify_by_instance[i][1]);
    const y_val = y_vals[i];
    return r_val.sub(f.qFromI64(shiftHalf(sh))).add(y_val.mulM31(M31.fromCanonical(@as(u32, 1) << sh)));
}

fn proveMatmulClass(
    a: std.mem.Allocator,
    pool: *f.Pool,
    tr: *Transcript,
    st: Statement,
    ws: *const WeightStore,
    all: []const []const i32,
    art: lookups.verifier_kernel.Artifact(QM31),
    rel: Relations,
    members: []const usize,
    alpha: QM31,
    y_vals: []const QM31,
    timings: *Timings,
    op_proofs: *std.ArrayList(sc.Proof),
    op_finals: *std.ArrayList([]QM31),
    claims: *ClaimList,
    weight_claims: *std.ArrayList(WeightClaimP),
) !void {
    const E = members.len;
    const L = art.ood_point.len;
    const m0 = st.ops[rel.keys[members[0]].op].matmul;
    const lt = st.witness[m0.x].log_dims[0];
    const lk = st.witness[m0.x].log_dims[1];
    const pt = art.ood_point[L - rel.keys[members[0]].log_size ..];
    const rho_t = pt[0..lt];
    const rho_n = pt[lt..];
    const xi = try a.alloc(QM31, E);
    defer a.free(xi);
    tr.drawN(xi);
    var claim = QM31.zero();
    for (members, xi) |mi, x| claim = claim.add(x.mul(accValue(art, mi, st.ops[rel.keys[mi].op].matmul.shift, alpha, y_vals)));
    const eq_t = try f.eqTablePar(a, pool, rho_t, QM31.one());
    defer a.free(eq_t);
    const eq_n = try f.eqTablePar(a, pool, rho_n, QM31.one());
    defer a.free(eq_n);
    const fs = try a.alloc([]QM31, E);
    const gs = try a.alloc([]QM31, E);
    defer {
        for (fs) |v| a.free(v);
        for (gs) |v| a.free(v);
        a.free(fs);
        a.free(gs);
    }
    for (members, 0..) |mi, e| {
        const m = st.ops[rel.keys[mi].op].matmul;
        const xm = pcs.Matrix(i32){ .data = all[m.x], .log_rows = lt, .log_cols = lk };
        fs[e] = try linalg.colCombine(i32, a, pool, xm, eq_t, operandBoundLog2(st, m.x));
        const tw0 = try std.time.Instant.now();
        gs[e] = try linalg.rowDots(i8, a, pool, ws.matrix(m.w), eq_n, 7);
        timings.weight_fold_ns += nowNs(tw0);
    }
    var res = try bsc.prove(a, tr, claim, fs, gs, xi);
    defer res.deinitExceptProof(a);
    try op_proofs.append(a, res.proof);
    const fin = try a.alloc(QM31, 2 * E);
    for (0..E) |e| {
        fin[2 * e] = res.f_finals[e];
        fin[2 * e + 1] = res.g_finals[e];
    }
    tr.mixFelts(fin);
    try op_finals.append(a, fin);
    for (members, 0..) |mi, e| {
        const m = st.ops[rel.keys[mi].op].matmul;
        const px = try a.alloc(QM31, lt + lk);
        @memcpy(px[0..lt], rho_t);
        @memcpy(px[lt..], res.point);
        try claims.append(a, .{ .tensor = m.x, .point = px, .value = fin[2 * e] });
        const pw = try a.alloc(QM31, lk + rho_n.len);
        @memcpy(pw[0..lk], res.point);
        @memcpy(pw[lk..], rho_n);
        try weight_claims.append(a, .{ .w = m.w, .point = pw, .value = fin[2 * e + 1] });
    }
}

fn verifyMatmulClass(
    a: std.mem.Allocator,
    tr: *Transcript,
    st: Statement,
    key: WeightKey,
    art: lookups.verifier_kernel.Artifact(QM31),
    rel: Relations,
    members: []const usize,
    alpha: QM31,
    y_vals: []const QM31,
    sproof: sc.Proof,
    fin: []const QM31,
    claims: *ClaimList,
    weight_pts: *std.ArrayList([]QM31),
    expected_w: *std.ArrayList(QM31),
) !void {
    const E = members.len;
    const L = art.ood_point.len;
    const k0 = rel.keys[members[0]];
    const m0 = st.ops[k0.op].matmul;
    const lt = st.witness[m0.x].log_dims[0];
    const lk = st.witness[m0.x].log_dims[1];
    for (members) |mi| {
        const m = st.ops[rel.keys[mi].op].matmul;
        if (st.weights[m.w].log_dims[0] != lk or st.weights[m.w].log_dims[1] != rel.keys[mi].log_size - lt) return error.StatementShape;
        if (rel.keys[mi].log_size != k0.log_size) return error.StatementShape;
    }
    const pt = art.ood_point[L - k0.log_size ..];
    const rho_t = pt[0..lt];
    const rho_n = pt[lt..];
    const xi = try a.alloc(QM31, E);
    defer a.free(xi);
    tr.drawN(xi);
    var claim = QM31.zero();
    for (members, xi) |mi, x| claim = claim.add(x.mul(accValue(art, mi, st.ops[rel.keys[mi].op].matmul.shift, alpha, y_vals)));
    const vr = try sc.verify(a, tr, claim, lk, 2, sproof);
    defer a.free(vr.point);
    if (fin.len != 2 * E) return error.ProofShape;
    var expect = QM31.zero();
    for (0..E) |e| expect = expect.add(xi[e].mul(fin[2 * e].mul(fin[2 * e + 1])));
    if (!vr.final_claim.eql(expect)) return error.OpSumcheck;
    tr.mixFelts(fin);
    for (members, 0..) |mi, e| {
        const m = st.ops[rel.keys[mi].op].matmul;
        const px = try a.alloc(QM31, lt + lk);
        @memcpy(px[0..lt], rho_t);
        @memcpy(px[lt..], vr.point);
        try claims.append(a, .{ .tensor = m.x, .point = px, .value = fin[2 * e] });
        const pw = try a.alloc(QM31, lk + rho_n.len);
        defer a.free(pw);
        @memcpy(pw[0..lk], vr.point);
        @memcpy(pw[lk..], rho_n);
        try weight_pts.append(a, try fullPoint(a, key.log_rows + key.log_cols, key.offsets[m.w], key.infos[m.w].logSize(), pw));
        try expected_w.append(a, fin[2 * e + 1]);
    }
}

// ---------------------------------------------------------------------------
// Batched matmul: Y[e] = requant(X[e] . W[e]), X [E, T, K], W [E, K, N] (one
// stacked weight tensor, e.g. all experts' gate projections of an MoE layer).
//
// acc~(rho_e, rho_t, rho_n) = sum_{e, k} eq(rho_e, e) X~(e, rho_t, k) W~(e, k, rho_n)
// (e is a batch variable of both operands, so it stays in the sumcheck, which
// has degree 3 over e and 2 over k). The finals are X~(r_e, rho_t, r_k) and
// one weight claim W~(r_e, r_k, rho_n) for the whole stack.

fn proveMatmul3(
    a: std.mem.Allocator,
    pool: *f.Pool,
    cfg: Config,
    tr: *Transcript,
    st: Statement,
    ws: *const WeightStore,
    all: []const []const i32,
    m: std.meta.TagPayload(Op, .matmul),
    pt: []const QM31,
    acc_val: QM31,
    timings: *Timings,
    op_proofs: *std.ArrayList(sc.Proof),
    op_finals: *std.ArrayList([]QM31),
    claims: *ClaimList,
    weight_claims: *std.ArrayList(WeightClaimP),
) !void {
    const xi = st.witness[m.x];
    const le = xi.log_dims[0];
    const lt = xi.log_dims[1];
    const lk = xi.log_dims[2];
    const E = @as(usize, 1) << @intCast(le);
    const T = @as(usize, 1) << @intCast(lt);
    const K = @as(usize, 1) << @intCast(lk);
    const rho_e = pt[0..le];
    const rho_t = pt[le..][0..lt];
    const rho_n = pt[le + lt ..];
    // fx(e, k) = X~(e, rho_t, k)
    const eq_t = try f.eqTablePar(a, pool, rho_t, QM31.one());
    defer a.free(eq_t);
    const fx = try a.alloc(QM31, E * K);
    defer a.free(fx);
    for (0..E) |e| {
        const xm = pcs.Matrix(i32){ .data = all[m.x][e * T * K ..][0 .. T * K], .log_rows = lt, .log_cols = lk };
        const v = try accel.colCombine(cfg.accel, i32, a, pool, xm, eq_t, 8);
        defer a.free(v);
        @memcpy(fx[e * K ..][0..K], v);
    }
    // gw(e, k) = W~(e, k, rho_n): the weight pass over the [E K, N] stack
    const tw0 = try std.time.Instant.now();
    const eq_n = try f.eqTablePar(a, pool, rho_n, QM31.one());
    defer a.free(eq_n);
    const gw = try accel.rowDots(cfg.accel, a, pool, ws.matrix(m.w), eq_n, 7);
    defer a.free(gw);
    timings.weight_fold_ns += nowNs(tw0);
    // eq(rho_e, e) broadcast over k
    const eq_e = try f.eqTablePar(a, pool, rho_e, QM31.one());
    defer a.free(eq_e);
    const eqk = try a.alloc(QM31, E * K);
    defer a.free(eqk);
    for (0..E) |e| @memset(eqk[e * K ..][0..K], eq_e[e]);
    var res = try accel.proveActive(cfg.accel, 3, &T_EQ3, a, pool, tr, acc_val, .{ eqk, fx, gw }, E * K);
    defer a.free(res.point);
    try op_proofs.append(a, res.proof);
    const fin = try a.dupe(QM31, res.finals[1..]);
    a.free(res.finals);
    res.finals = &.{};
    tr.mixFelts(fin);
    try op_finals.append(a, fin);
    const r_e = res.point[0..le];
    const r_k = res.point[le..];
    const px = try a.alloc(QM31, le + lt + lk);
    @memcpy(px[0..le], r_e);
    @memcpy(px[le..][0..lt], rho_t);
    @memcpy(px[le + lt ..], r_k);
    try claims.append(a, .{ .tensor = m.x, .point = px, .value = fin[0] });
    const pw = try a.alloc(QM31, le + lk + rho_n.len);
    @memcpy(pw[0..le], r_e);
    @memcpy(pw[le..][0..lk], r_k);
    @memcpy(pw[le + lk ..], rho_n);
    try weight_claims.append(a, .{ .w = m.w, .point = pw, .value = fin[1] });
}

fn verifyMatmul3(
    a: std.mem.Allocator,
    tr: *Transcript,
    st: Statement,
    key: WeightKey,
    m: std.meta.TagPayload(Op, .matmul),
    pt: []const QM31,
    acc_val: QM31,
    sproof: sc.Proof,
    fin: []const QM31,
    claims: *ClaimList,
    weight_pts: *std.ArrayList([]QM31),
    expected_w: *std.ArrayList(QM31),
) !void {
    const xi = st.witness[m.x];
    const le = xi.log_dims[0];
    const lt = xi.log_dims[1];
    const lk = xi.log_dims[2];
    // shapes were checked by validateStatement; the key must agree with the statement
    if (m.w >= key.infos.len or key.infos[m.w].n_dims != 3 or !std.meta.eql(key.infos[m.w].log_dims, st.weights[m.w].log_dims)) return error.StatementShape;
    if (pt.len != le + lt + st.weights[m.w].log_dims[2]) return error.StatementShape;
    const rho_e = pt[0..le];
    const rho_t = pt[le..][0..lt];
    const rho_n = pt[le + lt ..];
    const vr = try sc.verify(a, tr, acc_val, le + lk, 3, sproof);
    defer a.free(vr.point);
    if (fin.len != 2) return error.ProofShape;
    if (!vr.final_claim.eql(f.eqEval(rho_e, vr.point[0..le]).mul(fin[0]).mul(fin[1]))) return error.OpSumcheck;
    tr.mixFelts(fin);
    const px = try a.alloc(QM31, le + lt + lk);
    @memcpy(px[0..le], vr.point[0..le]);
    @memcpy(px[le..][0..lt], rho_t);
    @memcpy(px[le + lt ..], vr.point[le..]);
    try claims.append(a, .{ .tensor = m.x, .point = px, .value = fin[0] });
    const pw = try a.alloc(QM31, le + lk + rho_n.len);
    defer a.free(pw);
    @memcpy(pw[0..le], vr.point[0..le]);
    @memcpy(pw[le..][0..lk], vr.point[le..]);
    @memcpy(pw[le + lk ..], rho_n);
    try weight_pts.append(a, try fullPoint(a, key.log_rows + key.log_cols, key.offsets[m.w], key.infos[m.w].logSize(), pw));
    try expected_w.append(a, fin[1]);
}
