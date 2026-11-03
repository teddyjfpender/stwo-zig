//! Integer Llama-style decoder layers as tensor-protocol statements.
//!
//! Exact semantics, ranges and soundness notes: design/tensor-frontend/transformer.md.
//! Every function here computes the witness with plain integer arithmetic and
//! emits the ops that constrain it; the prover additionally re-checks every
//! constraint (ext.proverInit / multiplicities) before proving.
const std = @import("std");
const f = @import("field.zig");
const proto = @import("protocol.zig");
const xt = @import("ext.zig");
const model = @import("model.zig");

const TensorInfo = proto.TensorInfo;
const Ref = xt.Ref;

const IOTA = blk: {
    var x: [64]u8 = undefined;
    for (&x, 0..) |*v, i| v.* = i;
    break :blk x;
};
const SUMS = [_]u8{xt.SUM} ** xt.MAXB;

/// Labels start, start+1, ..., start+n-1.
pub fn ids(start: u32, n: u32) []const u8 {
    return IOTA[start..][0..n];
}

pub fn sums(n: u32) []const u8 {
    return SUMS[0..n];
}

pub fn cat(parts: []const []const u8) xt.Labels {
    var buf: [xt.MAXB]u8 = undefined;
    var n: usize = 0;
    for (parts) |p| {
        @memcpy(buf[n..][0..p.len], p);
        n += p.len;
    }
    return xt.labels(buf[0..n]);
}

pub fn term(c: i64, r: Ref, parts: []const []const u8) xt.Term {
    return .{ .coeff = c, .t = r, .labels = cat(parts) };
}

/// Smallest s >= 1 with requant(acc, s) in [-2^(ob-1), 2^(ob-1)) for all entries.
pub fn chooseShiftBits(acc: []const i64, ob: u5) !u5 {
    var mx: i64 = 0;
    var mn: i64 = 0;
    for (acc) |v| {
        mx = @max(mx, v);
        mn = @min(mn, v);
    }
    const lim = @as(i64, 1) << (ob - 1);
    var s: u5 = 1;
    while (s <= xt.MAX_TABLE_BITS) : (s += 1) {
        if (proto.requant(mx, s) < lim and proto.requant(mn, s) >= -lim) return s;
    }
    return error.RequantOverflow;
}

/// requant with s = 0 meaning identity.
pub fn rq(v: i64, s: u5) i64 {
    return if (s == 0) v else proto.requant(v, s);
}

pub fn expTable() [1024]i32 {
    var t: [1024]i32 = undefined;
    for (&t, 0..) |*v, d| {
        v.* = if (d < 256) @intFromFloat(@round(256.0 * @exp(-@as(f64, @floatFromInt(d)) / 16.0))) else 0;
    }
    return t;
}

pub const Builder = struct {
    a: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    pool: *f.Pool,
    infos: std.ArrayList(TensorInfo) = .empty,
    wit: std.ArrayList([]i32) = .empty,
    ops: std.ArrayList(proto.Op) = .empty,
    xops: std.ArrayList(xt.Op) = .empty,
    publics: std.ArrayList(xt.Public) = .empty,
    xtables: std.ArrayList(xt.LookupTable) = .empty,
    tables: std.ArrayList(proto.Table) = .empty,
    weight_infos: std.ArrayList(TensorInfo) = .empty,

    pub fn init(a: std.mem.Allocator, pool: *f.Pool) Builder {
        return .{ .a = a, .arena = std.heap.ArenaAllocator.init(a), .pool = pool };
    }

    pub fn deinit(self: *Builder) void {
        const a = self.a;
        for (self.wit.items) |w| a.free(w);
        self.wit.deinit(a);
        self.infos.deinit(a);
        self.ops.deinit(a);
        self.xops.deinit(a);
        self.publics.deinit(a);
        self.xtables.deinit(a);
        self.tables.deinit(a);
        self.weight_infos.deinit(a);
        self.arena.deinit();
    }

    pub fn statement(self: *const Builder) proto.Statement {
        return .{
            .witness = self.infos.items,
            .weights = self.weight_infos.items,
            .tables = self.tables.items,
            .ops = self.ops.items,
            .ext = .{ .ops = self.xops.items, .publics = self.publics.items, .tables = self.xtables.items },
        };
    }

    pub fn witnessView(self: *const Builder, a: std.mem.Allocator) ![]const []const i32 {
        const v = try a.alloc([]const i32, self.wit.items.len);
        for (self.wit.items, 0..) |w, i| v[i] = w;
        return v;
    }

    fn view(self: *const Builder) []const []const i32 {
        return @ptrCast(self.wit.items);
    }

    pub fn vals(self: *const Builder, r: Ref) []const i32 {
        return if (r.public) self.publics.items[r.id].values else self.wit.items[r.id];
    }

    /// Takes ownership of `data` (allocated with self.a).
    pub fn add(self: *Builder, info_in: TensorInfo, data: []i32) !u32 {
        const info = info_in; // by-value copy before the list may reallocate
        std.debug.assert(data.len == info.size());
        try self.infos.ensureUnusedCapacity(self.a, 1);
        try self.wit.ensureUnusedCapacity(self.a, 1);
        self.infos.appendAssumeCapacity(info);
        try self.wit.append(self.a, data);
        return @intCast(self.wit.items.len - 1);
    }

    pub fn addVec(self: *Builder, log: u32, data: []i32) !u32 {
        return self.add(TensorInfo.vec(log), data);
    }

    pub fn public(self: *Builder, log: u32, values: []const i32) !u32 {
        try self.publics.append(self.a, .{ .log_size = log, .values = try self.arena.allocator().dupe(i32, values) });
        return @intCast(self.publics.items.len - 1);
    }

    pub fn xtable(self: *Builder, log: u5, values: []const i32) !u32 {
        try self.xtables.append(self.a, .{ .log_size = log, .values = try self.arena.allocator().dupe(i32, values) });
        return @intCast(self.xtables.items.len - 1);
    }

    pub fn expr(self: *Builder, terms: []const xt.Term, c: i64) !xt.Expr {
        return .{ .terms = try self.arena.allocator().dupe(xt.Term, terms), .constant = c };
    }

    fn einsumSpec(a_: Ref, b_: Ref, n_out: u32, n_k: u32, la: []const []const u8, lb: []const []const u8) xt.Einsum {
        return .{ .a = a_, .b = b_, .y = null, .n_out = @intCast(n_out), .n_k = @intCast(n_k), .a_labels = cat(la), .b_labels = cat(lb) };
    }

    /// Y = requant_s(einsum(A, B)), s chosen (if null) so Y fits out_bits.
    pub fn einsumRequant(self: *Builder, info: TensorInfo, a_: Ref, b_: Ref, n_k: u32, la: []const []const u8, lb: []const []const u8, shift: ?u5, out_bits: u5) !u32 {
        var e = einsumSpec(a_, b_, info.logSize(), n_k, la, lb);
        const acc = try xt.einsumAcc(self.a, self.pool, e, self.vals(a_), self.vals(b_));
        defer self.a.free(acc);
        const s = shift orelse try chooseShiftBits(acc, out_bits);
        const y = try self.a.alloc(i32, acc.len);
        const lim = @as(i64, 1) << (out_bits - 1);
        for (acc, y) |v, *o| {
            const q = proto.requant(v, s);
            if (q < -lim or q >= lim) {
                self.a.free(y);
                return error.RequantOverflow;
            }
            o.* = q;
        }
        const id = try self.add(info, y);
        e.y = id;
        e.shift = s;
        e.out_bits = out_bits;
        try self.xops.append(self.a, .{ .einsum = e });
        return id;
    }

    /// Y = einsum(A, B) exactly (info == null: asserts the einsum is zero).
    pub fn einsumExact(self: *Builder, info: ?TensorInfo, n_out: u32, a_: Ref, b_: Ref, n_k: u32, la: []const []const u8, lb: []const []const u8) !?u32 {
        var e = einsumSpec(a_, b_, n_out, n_k, la, lb);
        const acc = try xt.einsumAcc(self.a, self.pool, e, self.vals(a_), self.vals(b_));
        defer self.a.free(acc);
        var id: ?u32 = null;
        if (info) |inf| {
            std.debug.assert(inf.logSize() == n_out);
            const y = try self.a.alloc(i32, acc.len);
            for (acc, y) |v, *o| {
                if (v < std.math.minInt(i32) or v > std.math.maxInt(i32)) {
                    self.a.free(y);
                    return error.EinsumOverflow;
                }
                o.* = @intCast(v);
            }
            id = try self.add(inf, y);
        }
        e.y = id;
        try self.xops.append(self.a, .{ .einsum = e });
        return id;
    }

    /// Asserts einsum(A, B) == existing witness y exactly.
    pub fn einsumInto(self: *Builder, y: u32, a_: Ref, b_: Ref, n_k: u32, la: []const []const u8, lb: []const []const u8) !void {
        var e = einsumSpec(a_, b_, self.infos.items[y].logSize(), n_k, la, lb);
        const acc = try xt.einsumAcc(self.a, self.pool, e, self.vals(a_), self.vals(b_));
        defer self.a.free(acc);
        for (acc, self.wit.items[y]) |v, w| if (v != w) return error.EinsumMismatch;
        e.y = y;
        try self.xops.append(self.a, .{ .einsum = e });
    }

    pub fn key(self: *Builder, n: u32, input: xt.Expr, output: ?xt.Expr, table: xt.TableRef) !void {
        try self.xops.append(self.a, .{ .key = .{ .n = @intCast(n), .input = input, .output = output, .table = table } });
    }

    pub fn lineq(self: *Builder, n: u32, e: xt.Expr) !void {
        try self.xops.append(self.a, .{ .lineq = .{ .n = @intCast(n), .expr = e } });
    }

    pub fn materialize(self: *Builder, e: xt.Expr, n: u32) ![]i64 {
        return xt.materialize(self.a, self.statement(), self.view(), e, n);
    }

    /// expr in [0, 2^bits) over {0,1}^n. Above 16 bits: committed 16-bit limbs
    /// lo, hi with expr == lo + 2^16 hi (lineq) and range keys on both.
    pub fn rangeWide(self: *Builder, n: u32, e: xt.Expr, bits: u32) !void {
        if (bits <= 16) return self.key(n, e, null, .{ .range = @intCast(bits) });
        std.debug.assert(bits <= 32);
        const v = try self.materialize(e, n);
        defer self.a.free(v);
        const lo = try self.a.alloc(i32, v.len);
        const hi = try self.a.alloc(i32, v.len);
        for (v, lo, hi) |x, *l, *h| {
            if (x < 0 or x >= (@as(i64, 1) << @intCast(bits))) {
                self.a.free(lo);
                self.a.free(hi);
                return error.ValueOutOfRange;
            }
            l.* = @intCast(x & 0xffff);
            h.* = @intCast(x >> 16);
        }
        const lo_id = try self.addVec(n, lo);
        const hi_id = try self.addVec(n, hi);
        try self.key(n, try self.expr(&.{term(1, Ref.w(lo_id), &.{ids(0, n)})}, 0), null, .{ .range = 16 });
        try self.key(n, try self.expr(&.{term(1, Ref.w(hi_id), &.{ids(0, n)})}, 0), null, .{ .range = @intCast(bits - 16) });
        const terms = try self.arena.allocator().alloc(xt.Term, e.terms.len + 2);
        @memcpy(terms[0..e.terms.len], e.terms);
        terms[e.terms.len] = term(-1, Ref.w(lo_id), &.{ids(0, n)});
        terms[e.terms.len + 1] = term(-65536, Ref.w(hi_id), &.{ids(0, n)});
        try self.lineq(n, .{ .terms = terms, .constant = e.constant });
    }

    /// Signed range: x + 2^(bits-1) in [0, 2^bits) (elementwise, all bits of x).
    pub fn rangeSigned(self: *Builder, x: u32, bits: u32) !void {
        const n = self.infos.items[x].logSize();
        try self.rangeWide(n, try self.expr(&.{term(1, Ref.w(x), &.{ids(0, n)})}, @as(i64, 1) << @intCast(bits - 1)), bits);
    }

    /// xs = round(x / 2^s) = floor((x + 2^(s-1)) / 2^s) as a committed int8
    /// tensor: remainder key x + 2^(s-1) - 2^s xs in [0, 2^s) and xs range.
    pub fn requantLinear(self: *Builder, x: u32, s: u5) !u32 {
        const info = self.infos.items[x];
        const n = info.logSize();
        const xs = try self.a.alloc(i32, info.size());
        for (self.wit.items[x], xs) |v, *o| o.* = proto.requant(v, s);
        const id = try self.add(info, xs);
        try self.key(n, try self.expr(&.{ term(1, Ref.w(x), &.{ids(0, n)}), term(-(@as(i64, 1) << s), Ref.w(id), &.{ids(0, n)}) }, @as(i64, 1) << (s - 1)), null, .{ .range = s });
        try self.rangeSigned(id, 8);
        return id;
    }

    // --- core ops (weights) -------------------------------------------------

    pub fn matmul(self: *Builder, ws: *const proto.WeightStore, x: u32, w: u32) !u32 {
        const xi = self.infos.items[x];
        const acc = try proto.matmulAcc(self.a, self.pool, xi, self.wit.items[x], ws.matrix(w));
        defer self.a.free(acc);
        const s = model.chooseShift(acc);
        const y = try self.a.alloc(i32, acc.len);
        for (acc, y) |v, *o| o.* = proto.requant(v, s);
        const id = try self.add(TensorInfo.mat(xi.log_dims[0], ws.infos[w].log_dims[1]), y);
        try self.ops.append(self.a, .{ .matmul = .{ .x = x, .w = w, .y = id, .shift = s } });
        return id;
    }

    pub fn coreTable(self: *Builder, t: proto.Table) !u32 {
        try self.tables.append(self.a, t);
        return @intCast(self.tables.items.len - 1);
    }

    pub fn lookup(self: *Builder, x: u32, table: u32) !u32 {
        const out = try self.a.alloc(i32, self.wit.items[x].len);
        for (self.wit.items[x], out) |v, *o| o.* = self.tables.items[table].values[@intCast(v + 128)];
        const info = self.infos.items[x]; // copy: add() may reallocate infos
        const id = try self.add(info, out);
        try self.ops.append(self.a, .{ .lookup = .{ .in = x, .out = id, .table = table } });
        return id;
    }

    pub fn hadamard(self: *Builder, x: u32, y: u32) !u32 {
        const n = self.wit.items[x].len;
        const acc = try self.a.alloc(i64, n);
        defer self.a.free(acc);
        for (self.wit.items[x], self.wit.items[y], acc) |p, q, *o| o.* = @as(i64, p) * q;
        const s = model.chooseShift(acc);
        const out = try self.a.alloc(i32, n);
        for (acc, out) |v, *o| o.* = proto.requant(v, s);
        const info = self.infos.items[x]; // copy: add() may reallocate infos
        const id = try self.add(info, out);
        try self.ops.append(self.a, .{ .hadamard = .{ .a = x, .b = y, .y = id, .shift = s } });
        return id;
    }
};

// ---------------------------------------------------------------------------
// Layer configuration.

pub const LayerCfg = struct {
    log_t: u32,
    log_d: u32,
    log_f: u32,
    log_heads: u32,
    /// log2 of KV heads (GQA): log_kv_heads <= log_heads
    log_kv_heads: u32,
    n_layers: u32 = 1,
    /// RMSNorm reciprocal precision: inv = floor(2^INV_BITS / rt)
    pub const INV_BITS = 15;

    pub fn logDh(self: LayerCfg) u32 {
        return self.log_d - self.log_heads;
    }
    pub fn logDkv(self: LayerCfg) u32 {
        return self.log_kv_heads + self.logDh();
    }
    pub fn validate(self: LayerCfg) !void {
        if (self.log_heads > self.log_d or self.logDh() < 1) return error.BadConfig;
        if (self.log_kv_heads > self.log_heads) return error.BadConfig;
        // no-wrap bounds (transformer.md, "Field-size bounds")
        if (self.log_d > 14 or self.log_f > 15 or self.logDh() > 13) return error.BadConfig;
        if (self.log_heads + 2 * self.log_t > 26 or self.log_t > 12) return error.BadConfig;
    }
};

pub const WEIGHTS_PER_LAYER = 7;
pub const W = struct {
    pub const q = 0;
    pub const k = 1;
    pub const v = 2;
    pub const o = 3;
    pub const gate = 4;
    pub const up = 5;
    pub const down = 6;
};

pub fn layerWeightInfos(a: std.mem.Allocator, cfg: LayerCfg) ![]TensorInfo {
    const out = try a.alloc(TensorInfo, WEIGHTS_PER_LAYER * cfg.n_layers);
    for (0..cfg.n_layers) |l| {
        const b = out[l * WEIGHTS_PER_LAYER ..];
        b[W.q] = TensorInfo.mat(cfg.log_d, cfg.log_d);
        b[W.k] = TensorInfo.mat(cfg.log_d, cfg.logDkv());
        b[W.v] = TensorInfo.mat(cfg.log_d, cfg.logDkv());
        b[W.o] = TensorInfo.mat(cfg.log_d, cfg.log_d);
        b[W.gate] = TensorInfo.mat(cfg.log_d, cfg.log_f);
        b[W.up] = TensorInfo.mat(cfg.log_d, cfg.log_f);
        b[W.down] = TensorInfo.mat(cfg.log_f, cfg.log_d);
    }
    return out;
}

/// RoPE rotation table R[t, i, b_out, b_in] (2^7 fixed point).
pub fn ropeTable(a: std.mem.Allocator, log_t: u32, log_dh: u32) ![]i32 {
    const T = @as(usize, 1) << @intCast(log_t);
    const half = @as(usize, 1) << @intCast(log_dh - 1);
    const dh: f64 = @floatFromInt(@as(usize, 1) << @intCast(log_dh));
    const out = try a.alloc(i32, T * half * 4);
    for (0..T) |t| for (0..half) |i| {
        const theta = @as(f64, @floatFromInt(t)) * std.math.pow(f64, 10000.0, -2.0 * @as(f64, @floatFromInt(i)) / dh);
        const c: i32 = @intFromFloat(@round(128.0 * @cos(theta)));
        const s: i32 = @intFromFloat(@round(128.0 * @sin(theta)));
        const base = (t * half + i) * 4;
        out[base + 0] = c; // (b_out 0, b_in 0)
        out[base + 1] = -s; // (0, 1)
        out[base + 2] = s; // (1, 0)
        out[base + 3] = c; // (1, 1)
    };
    return out;
}

/// Causal additive mask Bias[t, j] = 0 (j <= t) or -512 (j > t).
pub fn causalBias(a: std.mem.Allocator, log_t: u32) ![]i32 {
    const T = @as(usize, 1) << @intCast(log_t);
    const out = try a.alloc(i32, T * T);
    for (0..T) |t| for (0..T) |j| {
        out[t * T + j] = if (j <= t) 0 else -512;
    };
    return out;
}

pub const MASK_BIAS = 512;

/// Shared public tensors / tables of a stack.
pub const Ctx = struct {
    cfg: LayerCfg,
    ws: *const proto.WeightStore,
    rope: u32,
    bias: u32,
    exp_table: u32,
    silu: u32,
    gammas: []u32, // 2 per layer
};

pub fn initCtx(b: *Builder, cfg: LayerCfg, ws: *const proto.WeightStore, seed: u64) !Ctx {
    try cfg.validate();
    const rt = try ropeTable(b.a, cfg.log_t, cfg.logDh());
    defer b.a.free(rt);
    const rope_id = try b.public(cfg.log_t + cfg.logDh() + 1, rt);
    const cb = try causalBias(b.a, cfg.log_t);
    defer b.a.free(cb);
    const bias = try b.public(2 * cfg.log_t, cb);
    const et = expTable();
    const exp_table = try b.xtable(10, &et);
    const silu = try b.coreTable(model.siluTable());
    const gammas = try b.arena.allocator().alloc(u32, 2 * cfg.n_layers);
    var prng = std.Random.DefaultPrng.init(seed);
    const D = @as(usize, 1) << @intCast(cfg.log_d);
    const g = try b.a.alloc(i32, D);
    defer b.a.free(g);
    for (gammas) |*gid| {
        for (g) |*v| v.* = prng.random().intRangeAtMost(i32, 48, 80);
        gid.* = try b.public(cfg.log_d, g);
    }
    for (0..cfg.n_layers) |_| {
        const wi = try layerWeightInfos(b.a, .{ .log_t = cfg.log_t, .log_d = cfg.log_d, .log_f = cfg.log_f, .log_heads = cfg.log_heads, .log_kv_heads = cfg.log_kv_heads });
        defer b.a.free(wi);
        try b.weight_infos.appendSlice(b.a, wi);
    }
    return .{ .cfg = cfg, .ws = ws, .rope = rope_id, .bias = bias, .exp_table = exp_table, .silu = silu, .gammas = gammas };
}

// ---------------------------------------------------------------------------
// Blocks.

/// RMSNorm over the last dim of x [T, D] with public gamma; returns int8 y [T, D].
/// If `x_int8` the input is range-checked as int8, otherwise it is first
/// requantized to int8 (xs = round(x / 2^s0)).
pub const RmsOut = struct { y: u32, xs: u32, ss: u32, rt: u32, inv: u32, u: u32 };

pub fn rmsnorm(b: *Builder, c: Ctx, x: u32, gamma: u32, x_int8: bool) !RmsOut {
    const lt = c.cfg.log_t;
    const ld = c.cfg.log_d;
    const n = lt + ld;
    // xs: int8 view of x
    var xs = x;
    if (x_int8) {
        try b.rangeSigned(x, 8);
    } else {
        var s0: u5 = 0;
        for (b.wit.items[x]) |v| {
            while (rq(v, s0) < -128 or rq(v, s0) > 127) s0 += 1;
        }
        if (s0 == 0) try b.rangeSigned(x, 8) else xs = try b.requantLinear(x, s0);
    }
    const xr = Ref.w(xs);
    // ss[t] = sum_d xs^2
    const ss = (try b.einsumExact(TensorInfo.vec(lt), lt, xr, xr, ld, &.{ids(0, n)}, &.{ids(0, n)})).?;
    // rt = max{r >= 0 : r^2 2^s1 <= (ss + c) 2^m1}
    const s1: u5 = if (ld >= 8) @intCast(ld - 8) else 0;
    const m1: u5 = if (ld < 8) @intCast(8 - ld) else 0;
    const ceps: i64 = @as(i64, 1) << s1;
    const T = @as(usize, 1) << @intCast(lt);
    const rt = try b.a.alloc(i32, T);
    for (b.wit.items[ss], rt) |v, *o| {
        const N: u64 = @intCast((@as(i64, v) + ceps) << m1);
        o.* = @intCast(std.math.sqrt(N >> s1));
    }
    const rt_id = try b.addVec(lt, rt);
    const nmax: u64 = @intCast(((@as(i64, 1) << @intCast(ld + 14)) + ceps) << m1);
    const rtmax = std.math.sqrt(nmax >> s1);
    // rt in [0, 2^rt_bits) with 2^s1 * rt^2 < 2^30: rt2 = rt * rt cannot wrap mod p
    const rt_bits: u32 = std.math.log2_int_ceil(u64, rtmax + 1);
    if (2 * rt_bits + s1 > 30) return error.BadConfig;
    try b.rangeWide(lt, try b.expr(&.{term(1, Ref.w(rt_id), &.{ids(0, lt)})}, 0), rt_bits);
    const rt2 = (try b.einsumExact(TensorInfo.vec(lt), lt, Ref.w(rt_id), Ref.w(rt_id), 0, &.{ids(0, lt)}, &.{ids(0, lt)})).?;
    const gap_bits: u32 = s1 + std.math.log2_int_ceil(u64, 2 * rtmax + 2);
    const tl = ids(0, lt);
    const p_m1 = @as(i64, 1) << m1;
    const p_s1 = @as(i64, 1) << s1;
    // lower: (ss + c) 2^m1 - 2^s1 rt2 >= 0
    try b.rangeWide(lt, try b.expr(&.{ term(p_m1, Ref.w(ss), &.{tl}), term(-p_s1, Ref.w(rt2), &.{tl}) }, ceps * p_m1), gap_bits);
    // upper: 2^s1 (rt2 + 2 rt + 1) - 1 - (ss + c) 2^m1 >= 0
    try b.rangeWide(lt, try b.expr(&.{ term(p_s1, Ref.w(rt2), &.{tl}), term(2 * p_s1, Ref.w(rt_id), &.{tl}), term(-p_m1, Ref.w(ss), &.{tl}) }, p_s1 - 1 - ceps * p_m1), gap_bits);
    // inv = floor(2^K / rt)
    const K = LayerCfg.INV_BITS;
    const inv = try b.a.alloc(i32, T);
    for (rt, inv) |r, *o| o.* = @divFloor(@as(i32, 1) << K, r);
    const inv_id = try b.addVec(lt, inv);
    try b.rangeWide(lt, try b.expr(&.{term(1, Ref.w(inv_id), &.{tl})}, 0), 16);
    const pr = (try b.einsumExact(TensorInfo.vec(lt), lt, Ref.w(inv_id), Ref.w(rt_id), 0, &.{tl}, &.{tl})).?;
    // 2^K - pr in [0, rt): 2^K - pr >= 0 and rt - 1 - 2^K + pr >= 0
    try b.rangeWide(lt, try b.expr(&.{term(-1, Ref.w(pr), &.{tl})}, @as(i64, 1) << K), 16);
    try b.rangeWide(lt, try b.expr(&.{ term(1, Ref.w(rt_id), &.{tl}), term(1, Ref.w(pr), &.{tl}) }, -1 - (@as(i64, 1) << K)), 16);
    // u = requant_6(xs * inv) (16-bit), y = requant(u * gamma) (int8)
    const u = try b.einsumRequant(TensorInfo.mat(lt, ld), xr, Ref.w(inv_id), 0, &.{ids(0, n)}, &.{tl}, 6, 16);
    const y = try b.einsumRequant(TensorInfo.mat(lt, ld), Ref.w(u), Ref.p(gamma), 0, &.{ids(0, n)}, &.{ids(lt, ld)}, null, 8);
    return .{ .y = y, .xs = xs, .ss = ss, .rt = rt_id, .inv = inv_id, .u = u };
}

/// RoPE on x [T, heads * dh] (layout t, head, i, b): out[.., i, b'] =
/// requant_7(sum_b x[.., i, b] R[t, i, b', b]), 9-bit output.
pub fn rope(b: *Builder, c: Ctx, x: u32, log_heads: u32) !u32 {
    const lt = c.cfg.log_t;
    const ldh = c.cfg.logDh();
    const n_out = lt + log_heads + ldh;
    const i_vars = ids(lt + log_heads, ldh - 1);
    return b.einsumRequant(
        TensorInfo.mat(lt, log_heads + ldh),
        Ref.w(x),
        Ref.p(c.rope),
        1,
        &.{ ids(0, lt), ids(lt, log_heads), i_vars, ids(n_out, 1) },
        &.{ ids(0, lt), i_vars, ids(n_out - 1, 1), ids(n_out, 1) },
        7,
        9,
    );
}

pub const AttnOut = struct { o: u32, scores: u32, probs: u32, rden: u32, m: u32, sel: u32, d: u32, e: u32, den: u32 };

/// Causal GQA attention core: qr [T, H dh], kr / v [T, Hkv dh] -> O [T, H dh].
pub fn attention(b: *Builder, c: Ctx, qr: u32, kr: u32, v: u32) !AttnOut {
    const cfg = c.cfg;
    const lt = cfg.log_t;
    const lh = cfg.log_heads;
    const lkv = cfg.log_kv_heads;
    const lg = lh - lkv;
    const ldh = cfg.logDh();
    const n3 = lh + 2 * lt; // (h, t, j)
    const n2 = lh + lt; // (h, t)
    // scores S[hk, g, t, j] = requant(sum_e Qr[t, hk, g, e] Kr[j, hk, e])
    const S = try b.einsumRequant(
        TensorInfo.vec(n3),
        Ref.w(qr),
        Ref.w(kr),
        ldh,
        &.{ ids(lh, lt), ids(0, lkv), ids(lkv, lg), ids(n3, ldh) },
        &.{ ids(lh + lt, lt), ids(0, lkv), ids(n3, ldh) },
        null,
        8,
    );
    const T = @as(usize, 1) << @intCast(lt);
    const H = @as(usize, 1) << @intCast(lh);
    const bias = b.vals(Ref.p(c.bias));
    const sv = b.wit.items[S];
    // rowmax over masked scores + first-argmax selector
    const m = try b.a.alloc(i32, H * T);
    const sel = try b.a.alloc(i32, H * T * T);
    @memset(sel, 0);
    for (0..H * T) |row| {
        const t = row % T;
        var best: i32 = std.math.minInt(i32);
        var arg: usize = 0;
        for (0..T) |j| {
            const val = sv[row * T + j] + bias[t * T + j];
            if (val > best) {
                best = val;
                arg = j;
            }
        }
        m[row] = best;
        sel[row * T + arg] = 1;
    }
    const m_id = try b.addVec(n2, m);
    const sel_id = try b.addVec(n3, sel);
    const dd = try b.a.alloc(i32, H * T * T);
    for (dd, 0..) |*o, i| {
        const row = i / T;
        const t = row % T;
        const j = i % T;
        o.* = m[row] - sv[i] - bias[t * T + j];
    }
    const dd_id = try b.addVec(n3, dd);
    const all3 = ids(0, n3);
    // D - m + S + Bias = 0
    try b.lineq(n3, try b.expr(&.{
        term(1, Ref.w(dd_id), &.{all3}),
        term(-1, Ref.w(m_id), &.{ids(0, n2)}),
        term(1, Ref.w(S), &.{all3}),
        term(1, Ref.p(c.bias), &.{ids(lh, 2 * lt)}),
    }, 0));
    // sel in {0,1} (sel * sel == sel: one degree-3 zero-check, cheaper than a
    // 1-bit LogUp key over H T^2), sum_j sel = 1, sum_j sel * D = 0
    try b.einsumInto(sel_id, Ref.w(sel_id), Ref.w(sel_id), 0, &.{all3}, &.{all3});
    try b.lineq(n2, try b.expr(&.{term(1, Ref.w(sel_id), &.{ ids(0, n2), sums(lt) })}, -1));
    _ = try b.einsumExact(null, n2, Ref.w(sel_id), Ref.w(dd_id), lt, &.{all3}, &.{all3});
    // e = exp_table(D) (domain [0, 1024) also range-checks D)
    const et = b.xtables.items[c.exp_table].values;
    const e = try b.a.alloc(i32, H * T * T);
    for (dd, e) |d, *o| o.* = et[@intCast(d)];
    const e_id = try b.addVec(n3, e);
    try b.key(n3, try b.expr(&.{term(1, Ref.w(dd_id), &.{all3})}, 0), try b.expr(&.{term(1, Ref.w(e_id), &.{all3})}, 0), .{ .lookup = c.exp_table });
    // den = sum_j e
    const den = try b.a.alloc(i32, H * T);
    for (den, 0..) |*o, row| {
        var s: i32 = 0;
        for (e[row * T ..][0..T]) |x| s += x;
        o.* = s;
    }
    const den_id = try b.addVec(n2, den);
    try b.lineq(n2, try b.expr(&.{ term(1, Ref.w(den_id), &.{ids(0, n2)}), term(-1, Ref.w(e_id), &.{ ids(0, n2), sums(lt) }) }, 0));
    // per-row reciprocal rden = floor(2^K / den), K = lt + 15, proved on the
    // [H, T] vector: rden in [0, 2^(lt+8)), pr = rden * den,
    // 0 <= 2^K - pr < den.
    const K: u5 = @intCast(lt + 15);
    const rden = try b.a.alloc(i32, H * T);
    for (den, rden) |d, *o| o.* = @divFloor(@as(i32, 1) << K, d);
    const rden_id = try b.addVec(n2, rden);
    const all2 = ids(0, n2);
    try b.rangeWide(n2, try b.expr(&.{term(1, Ref.w(rden_id), &.{all2})}, 0), lt + 8);
    const pr = (try b.einsumExact(TensorInfo.vec(n2), n2, Ref.w(rden_id), Ref.w(den_id), 0, &.{all2}, &.{all2})).?;
    try b.rangeWide(n2, try b.expr(&.{term(-1, Ref.w(pr), &.{all2})}, @as(i64, 1) << K), lt + 8);
    try b.rangeWide(n2, try b.expr(&.{ term(1, Ref.w(den_id), &.{all2}), term(1, Ref.w(pr), &.{all2}) }, -1 - (@as(i64, 1) << K)), lt + 8);
    // P = rq_{lt+8}(e * rden) ~ 128 e / den, in [0, 128] (9-bit signed range)
    const p_id = try b.einsumRequant(TensorInfo.vec(n3), Ref.w(e_id), Ref.w(rden_id), 0, &.{all3}, &.{all2}, @intCast(lt + 8), 9);
    // O[t, hk, g, e] = requant(sum_j P[hk, g, t, j] V[j, hk, e])
    const n_o = lt + lh + ldh;
    const O = try b.einsumRequant(
        TensorInfo.mat(lt, lh + ldh),
        Ref.w(p_id),
        Ref.w(v),
        lt,
        &.{ ids(lt, lkv), ids(lt + lkv, lg), ids(0, lt), ids(n_o, lt) },
        &.{ ids(n_o, lt), ids(lt, lkv), ids(lt + lh, ldh) },
        null,
        8,
    );
    return .{ .o = O, .scores = S, .probs = p_id, .rden = rden_id, .m = m_id, .sel = sel_id, .d = dd_id, .e = e_id, .den = den_id };
}

/// z = x + y (committed, lineq).
pub fn residual(b: *Builder, x: u32, y: u32) !u32 {
    const info = b.infos.items[x];
    const n = info.logSize();
    const z = try b.a.alloc(i32, info.size());
    for (z, b.wit.items[x], b.wit.items[y]) |*o, p, q| o.* = p + q;
    const id = try b.add(info, z);
    try b.lineq(n, try b.expr(&.{ term(1, Ref.w(id), &.{ids(0, n)}), term(-1, Ref.w(x), &.{ids(0, n)}), term(-1, Ref.w(y), &.{ids(0, n)}) }, 0));
    return id;
}

pub const LayerOut = struct { out: u32, h: u32, attn: AttnOut, rms1: RmsOut, rms2: RmsOut, q: u32, qr: u32 };

/// One Llama-style decoder layer: x -> x + Attn(RMSNorm(x)) -> h + MLP(RMSNorm(h)).
pub fn decoderLayer(b: *Builder, c: Ctx, layer: u32, x: u32, x_int8: bool) !LayerOut {
    const cfg = c.cfg;
    const wb = layer * WEIGHTS_PER_LAYER;
    const r1 = try rmsnorm(b, c, x, c.gammas[2 * layer], x_int8);
    const y1 = r1.y;
    const q = try b.matmul(c.ws, y1, wb + W.q);
    const k = try b.matmul(c.ws, y1, wb + W.k);
    const v = try b.matmul(c.ws, y1, wb + W.v);
    const qr = try rope(b, c, q, cfg.log_heads);
    const kr = try rope(b, c, k, cfg.log_kv_heads);
    const at = try attention(b, c, qr, kr, v);
    const ao = try b.matmul(c.ws, at.o, wb + W.o);
    const h = try residual(b, x, ao);
    const r2 = try rmsnorm(b, c, h, c.gammas[2 * layer + 1], false);
    const g = try b.matmul(c.ws, r2.y, wb + W.gate);
    const u = try b.matmul(c.ws, r2.y, wb + W.up);
    const act = try b.lookup(g, c.silu);
    const hm = try b.hadamard(act, u);
    const mo = try b.matmul(c.ws, hm, wb + W.down);
    return .{ .out = try residual(b, h, mo), .h = h, .attn = at, .rms1 = r1, .rms2 = r2, .q = q, .qr = qr };
}

/// Stack of cfg.n_layers decoder layers on int8 input x [T, D].
pub fn buildStack(b: *Builder, c: Ctx, x_in: []const i32) !LayerOut {
    var x = try b.add(TensorInfo.mat(c.cfg.log_t, c.cfg.log_d), try b.a.dupe(i32, x_in));
    var o: LayerOut = undefined;
    for (0..c.cfg.n_layers) |l| {
        o = try decoderLayer(b, c, @intCast(l), x, l == 0);
        x = o.out;
    }
    return o;
}

// ---------------------------------------------------------------------------
// Tests.

const testing = std.testing;

pub const TestSetup = struct {
    pool: f.Pool,
    ws: proto.WeightStore,
    wdata: [][]i8,
    winfos: []TensorInfo,
    pc: proto.Config,

    pub fn deinit(self: *TestSetup, a: std.mem.Allocator) void {
        self.ws.deinit(a);
        for (self.wdata) |w| a.free(w);
        a.free(self.wdata);
        a.free(self.winfos);
        self.pool.deinit();
    }
};

pub fn setupWeights(a: std.mem.Allocator, pool: *f.Pool, cfg: LayerCfg, pc: proto.Config, seed: u64) !struct { ws: proto.WeightStore, wdata: [][]i8, winfos: []TensorInfo } {
    const winfos = try layerWeightInfos(a, cfg);
    const wdata = try a.alloc([]i8, winfos.len);
    const wv = try a.alloc([]const i8, winfos.len);
    defer a.free(wv);
    for (wdata, 0..) |*w, i| {
        w.* = try model.randomWeights(a, winfos[i].size(), seed + i, -8, 7);
        wv[i] = w.*;
    }
    const ws = try proto.commitWeights(a, pool, pc, winfos, wv);
    return .{ .ws = ws, .wdata = wdata, .winfos = winfos };
}

fn testCfg() proto.Config {
    return .{ .pcs = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 }, .weight_log_cols = 4, .witness_log_cols_max = 8, .gkr_threads = 2 };
}

fn proveVerify(a: std.mem.Allocator, pool: *f.Pool, pc: proto.Config, b: *const Builder, ws: *const proto.WeightStore) !proto.Proof {
    const st = b.statement();
    const wv = try b.witnessView(a);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    var proof = try proto.prove(a, pool, pc, st, ws, wv, &tm);
    errdefer proof.deinit(a);
    try proto.verify(a, pc, st, proto.weightKey(ws), &proof);
    return proof;
}

fn expectReject(a: std.mem.Allocator, pc: proto.Config, st: proto.Statement, ws: *const proto.WeightStore, proof: *const proto.Proof) !void {
    if (proto.verify(a, pc, st, proto.weightKey(ws), proof)) |_| {
        return error.TamperAccepted;
    } else |_| {}
}

test "decoder layer (GQA attention, RoPE, softmax, RMSNorm, SwiGLU) proves and verifies; tampering rejected" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const cfg = LayerCfg{ .log_t = 3, .log_d = 5, .log_f = 6, .log_heads = 2, .log_kv_heads = 1 };
    const pc = testCfg();
    var sw = try setupWeights(a, &pool, cfg, pc, 300);
    defer {
        sw.ws.deinit(a);
        for (sw.wdata) |w| a.free(w);
        a.free(sw.wdata);
        a.free(sw.winfos);
    }
    var b = Builder.init(a, &pool);
    defer b.deinit();
    const c = try initCtx(&b, cfg, &sw.ws, 1);
    const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 17);
    defer a.free(x);
    _ = try buildStack(&b, c, x);

    var proof = try proveVerify(a, &pool, pc, &b, &sw.ws);
    defer proof.deinit(a);
    const st = b.statement();
    // tamper each ext proof component
    {
        const sv = proof.ext.values[3];
        proof.ext.values[3] = sv.add(f.QM31.one());
        try expectReject(a, pc, st, &sw.ws, &proof);
        proof.ext.values[3] = sv;
    }
    {
        const last = proof.ext.values.len - 1;
        const sv = proof.ext.values[last];
        proof.ext.values[last] = sv.add(f.QM31.one());
        try expectReject(a, pc, st, &sw.ws, &proof);
        proof.ext.values[last] = sv;
    }
    for (0..proof.ext.finals.len) |i| {
        if (i % 3 != 0) continue;
        const sv = proof.ext.finals[i];
        proof.ext.finals[i][0] = sv[0].add(f.QM31.one());
        try expectReject(a, pc, st, &sw.ws, &proof);
        proof.ext.finals[i] = sv;
        proof.ext.finals[i][1] = sv[1].add(f.QM31.one());
        try expectReject(a, pc, st, &sw.ws, &proof);
        proof.ext.finals[i] = sv;
    }
    for (proof.ext.sumchecks) |*p| {
        if (p.rounds.len == 0) continue;
        const sv = p.rounds[0].evals[0];
        p.rounds[0].evals[0] = sv.add(f.QM31.one());
        try expectReject(a, pc, st, &sw.ws, &proof);
        p.rounds[0].evals[0] = sv;
    }
    // statement tamper: different mask bias / gamma / shift must be rejected
    {
        const pubs = try a.dupe(xt.Public, st.ext.publics);
        defer a.free(pubs);
        const nb = try a.dupe(i32, pubs[c.bias].values);
        defer a.free(nb);
        nb[1] = 0; // unmask (t=0, j=1)
        pubs[c.bias].values = nb;
        var st2 = st;
        st2.ext.publics = pubs;
        try expectReject(a, pc, st2, &sw.ws, &proof);
    }
    {
        const xops = try a.dupe(xt.Op, st.ext.ops);
        defer a.free(xops);
        for (xops) |*op| if (op.* == .einsum and op.einsum.shift > 0) {
            op.einsum.shift += 1;
            break;
        };
        var st2 = st;
        st2.ext.ops = xops;
        try expectReject(a, pc, st2, &sw.ws, &proof);
    }
    // malformed statement is rejected, not a crash
    {
        const xops = try a.dupe(xt.Op, st.ext.ops);
        defer a.free(xops);
        for (xops) |*op| if (op.* == .einsum) {
            op.einsum.a_labels[0] = 31;
            break;
        };
        var st2 = st;
        st2.ext.ops = xops;
        try expectReject(a, pc, st2, &sw.ws, &proof);
    }
    try proto.verify(a, pc, st, proto.weightKey(&sw.ws), &proof);
}

test "two-layer stack proves and verifies" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const cfg = LayerCfg{ .log_t = 2, .log_d = 4, .log_f = 5, .log_heads = 1, .log_kv_heads = 0, .n_layers = 2 };
    var pc = testCfg();
    pc.weight_log_cols = 3;
    var sw = try setupWeights(a, &pool, cfg, pc, 500);
    defer {
        sw.ws.deinit(a);
        for (sw.wdata) |w| a.free(w);
        a.free(sw.wdata);
        a.free(sw.winfos);
    }
    var b = Builder.init(a, &pool);
    defer b.deinit();
    const c = try initCtx(&b, cfg, &sw.ws, 2);
    const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 23);
    defer a.free(x);
    _ = try buildStack(&b, c, x);
    var proof = try proveVerify(a, &pool, pc, &b, &sw.ws);
    defer proof.deinit(a);
}

const SmallCfg = LayerCfg{ .log_t = 2, .log_d = 4, .log_f = 5, .log_heads = 2, .log_kv_heads = 1 };

const Fixture = struct {
    sw: @typeInfo(@typeInfo(@TypeOf(setupWeights)).@"fn".return_type.?).error_union.payload,
    b: Builder,
    c: Ctx,
    out: LayerOut,

    fn init(a: std.mem.Allocator, pool: *f.Pool, cfg: LayerCfg, pc: proto.Config, seed: u64) !*Fixture {
        const fx = try a.create(Fixture);
        errdefer a.destroy(fx);
        fx.sw = try setupWeights(a, pool, cfg, pc, seed);
        fx.b = Builder.init(a, pool);
        fx.c = try initCtx(&fx.b, cfg, &fx.sw.ws, seed + 1);
        const x = try model.randomInput(a, @as(usize, 1) << @intCast(cfg.log_t + cfg.log_d), seed + 2);
        defer a.free(x);
        fx.out = try buildStack(&fx.b, fx.c, x);
        return fx;
    }

    fn deinit(fx: *Fixture, a: std.mem.Allocator) void {
        fx.b.deinit();
        fx.sw.ws.deinit(a);
        for (fx.sw.wdata) |w| a.free(w);
        a.free(fx.sw.wdata);
        a.free(fx.sw.winfos);
        a.destroy(fx);
    }
};

test "decoder layer witness matches a direct integer reference (RoPE, GQA scores, causal softmax, PV, RMSNorm)" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const cfg = LayerCfg{ .log_t = 3, .log_d = 5, .log_f = 6, .log_heads = 2, .log_kv_heads = 1 };
    var pc = testCfg();
    pc.weight_log_cols = 4;
    const fx = try Fixture.init(a, &pool, cfg, pc, 40);
    defer fx.deinit(a);
    const b = &fx.b;
    const at = fx.out.attn;
    const T = @as(usize, 1) << @intCast(cfg.log_t);
    const H = @as(usize, 1) << @intCast(cfg.log_heads);
    const G = @as(usize, 1) << @intCast(cfg.log_heads - cfg.log_kv_heads);
    const dh = @as(usize, 1) << @intCast(cfg.logDh());
    const D = H * dh;
    const Dkv = D / G;
    const rt = try ropeTable(a, cfg.log_t, cfg.logDh());
    defer a.free(rt);
    // RoPE on q: qr[t, h, 2i + bo] = rq(sum_bi q[t, h, 2i + bi] R[t, i, bo, bi], 7)
    const q = b.wit.items[fx.out.q];
    const qr = b.wit.items[fx.out.qr];
    for (0..T) |t| for (0..H) |h| for (0..dh / 2) |i| for (0..2) |bo| {
        var s: i64 = 0;
        for (0..2) |bi| s += @as(i64, q[t * D + h * dh + 2 * i + bi]) * rt[((t * dh / 2 + i) * 2 + bo) * 2 + bi];
        try testing.expectEqual(rq(s, 7), qr[t * D + h * dh + 2 * i + bo]);
    };
    // scores with GQA: kv head = h / G (MSB part of the head index)
    var sops: ?xt.Einsum = null;
    for (b.xops.items) |op| if (op == .einsum and op.einsum.y != null and op.einsum.y.? == at.scores) {
        sops = op.einsum;
    };
    const kr_id = sops.?.b.id;
    const kr = b.wit.items[kr_id];
    const S = b.wit.items[at.scores];
    for (0..H) |h| for (0..T) |t| for (0..T) |j| {
        var s: i64 = 0;
        for (0..dh) |e| s += @as(i64, qr[t * D + h * dh + e]) * kr[j * Dkv + (h / G) * dh + e];
        try testing.expectEqual(rq(s, sops.?.shift), S[(h * T + t) * T + j]);
    };
    // causal softmax
    const P = b.wit.items[at.probs];
    const et = expTable();
    for (0..H) |h| for (0..T) |t| {
        var mx: i64 = std.math.minInt(i64);
        for (0..t + 1) |j| mx = @max(mx, S[(h * T + t) * T + j]);
        var den: i64 = 0;
        for (0..t + 1) |j| den += et[@intCast(mx - S[(h * T + t) * T + j])];
        var psum: i64 = 0;
        const K: u6 = @intCast(cfg.log_t + 15);
        const rden = @divFloor(@as(i64, 1) << K, den);
        for (0..T) |j| {
            const pv = P[(h * T + t) * T + j];
            if (j > t) {
                try testing.expectEqual(@as(i32, 0), pv);
            } else {
                const ev: i64 = et[@intCast(mx - S[(h * T + t) * T + j])];
                try testing.expectEqual(rq(ev * rden, @intCast(cfg.log_t + 8)), pv);
                // within 1 of the exact 128 e / den
                try testing.expect(@abs(pv * den - 128 * ev) <= den);
            }
            psum += pv;
        }
        try testing.expect(@abs(psum - 128) <= @as(i64, @intCast(T)));
    };
    // PV: O[t, h, e] = rq(sum_j P[h, t, j] V[j, kvh, e])
    var oops: ?xt.Einsum = null;
    for (b.xops.items) |op| if (op == .einsum and op.einsum.y != null and op.einsum.y.? == at.o) {
        oops = op.einsum;
    };
    const V = b.wit.items[oops.?.b.id];
    const O = b.wit.items[at.o];
    for (0..T) |t| for (0..H) |h| for (0..dh) |e| {
        var s: i64 = 0;
        for (0..T) |j| s += @as(i64, P[(h * T + t) * T + j]) * V[j * Dkv + (h / G) * dh + e];
        try testing.expectEqual(rq(s, oops.?.shift), O[t * D + h * dh + e]);
    };
    // RMSNorm: rt = isqrt((ss + 2^s1) 2^m1 / 2^s1), inv = 2^15 / rt
    const r1 = fx.out.rms1;
    const xs = b.wit.items[r1.xs];
    for (0..T) |t| {
        var ss: i64 = 0;
        for (0..D) |d| ss += @as(i64, xs[t * D + d]) * xs[t * D + d];
        try testing.expectEqual(ss, b.wit.items[r1.ss][t]);
        const rtv: i64 = b.wit.items[r1.rt][t];
        const N = (ss + 1) * 8; // ld = 5: s1 = 0, m1 = 3
        try testing.expect(rtv * rtv <= N and (rtv + 1) * (rtv + 1) > N);
        try testing.expectEqual(@divFloor(@as(i64, 1 << 15), rtv), b.wit.items[r1.inv][t]);
    }
}

const Cheat = enum { sel_nonbinary, rden_plus_one, sel_moved, max_lowered, prob_plus_one, rt_plus_one, residual, exp_value, masked_exp, score, ss_value };

fn cheatCase(a: std.mem.Allocator, cheat: Cheat) !void {
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var pc = testCfg();
    pc.weight_log_cols = 3;
    const fx = try Fixture.init(a, &pool, SmallCfg, pc, 77);
    defer fx.deinit(a);
    const b = &fx.b;
    const at = fx.out.attn;
    const T = @as(usize, 1) << @intCast(SmallCfg.log_t);
    const bias = b.vals(Ref.p(fx.c.bias));
    const S = b.wit.items[at.scores];
    const sel = b.wit.items[at.sel];
    const m = b.wit.items[at.m];
    const Dd = b.wit.items[at.d];
    const row = T - 1; // head 0, last token: all positions unmasked
    var jstar: usize = 0;
    for (0..T) |j| if (sel[row * T + j] == 1) {
        jstar = j;
    };
    // a position whose masked score is strictly below the max
    var jlow: ?usize = null;
    for (0..T) |j| if (S[row * T + j] + bias[(T - 1) * T + j] < m[row]) {
        jlow = j;
    };
    switch (cheat) {
        .sel_moved => {
            sel[row * T + jstar] = 0;
            sel[row * T + jlow.?] = 1;
        },
        .max_lowered => {
            // claim the max is a smaller score; D recomputed consistently
            const j2 = jlow.?;
            const nm = S[row * T + j2] + bias[(T - 1) * T + j2];
            m[row] = nm;
            sel[row * T + jstar] = 0;
            sel[row * T + j2] = 1;
            for (0..T) |j| Dd[row * T + j] = nm - S[row * T + j] - bias[(T - 1) * T + j];
        },
        .prob_plus_one => b.wit.items[at.probs][row * T] += 1,
        .rden_plus_one => b.wit.items[at.rden][row] += 1,
        .sel_nonbinary => {
            // non-binary selector that keeps sum_j sel = 1
            sel[row * T + jstar] = 2;
            sel[row * T + jlow.?] = -1;
        },
        .rt_plus_one => {
            const r = fx.out.rms1;
            b.wit.items[r.rt][0] += 1;
        },
        .residual => b.wit.items[fx.out.h][0] += 1,
        .exp_value => b.wit.items[at.e][row * T + jstar] -= 1,
        .masked_exp => b.wit.items[at.e][1] = 3, // (t = 0, j = 1) is masked
        .score => S[row * T] += 1,
        .ss_value => b.wit.items[fx.out.rms2.ss][0] += 1,
    }
    xt.test_unchecked_prover = true;
    defer xt.test_unchecked_prover = false;
    const st = b.statement();
    const wv = try b.witnessView(a);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    var proof = try proto.prove(a, &pool, pc, st, &fx.sw.ws, wv, &tm);
    defer proof.deinit(a);
    try expectReject(a, pc, st, &fx.sw.ws, &proof);
}

test "verifier rejects invalid attention / softmax / RMSNorm / residual witnesses (unchecked prover)" {
    inline for (@typeInfo(Cheat).@"enum".fields) |fld| {
        cheatCase(testing.allocator, @enumFromInt(fld.value)) catch |err| {
            std.debug.print("cheat case {s} failed: {}\n", .{ fld.name, err });
            return err;
        };
    }
}

test "honest prover refuses invalid witnesses" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var pc = testCfg();
    pc.weight_log_cols = 3;
    const fx = try Fixture.init(a, &pool, SmallCfg, pc, 91);
    defer fx.deinit(a);
    fx.b.wit.items[fx.out.h][0] += 1;
    const wv = try fx.b.witnessView(a);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    try testing.expectError(error.LinEqViolated, proto.prove(a, &pool, pc, fx.b.statement(), &fx.sw.ws, wv, &tm));
}
