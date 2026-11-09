//! Field helpers for the tensor frontend: M31 base field, QM31 secure field.
//!
//! Multilinear convention (matches stwo's GKR/MLE code): variable 0 is the
//! most significant bit of the hypercube index, so `fold(r)` combines the low
//! half with the high half: f'(x) = f(0,x) + r (f(1,x) - f(0,x)).
const std = @import("std");
const core = @import("stwo_core");

pub const M31 = core.fields.m31.M31;
/// QM31 = p^4 extension (stwo's secure field).
pub const Q4 = core.fields.qm31.QM31;
/// Degree of the challenge field over M31 (build option -Dchallenge):
/// 4 = QM31 (default), 8 = OM31 = QM31[v]/(v^2 - u) (core/fields/om31.zig).
pub const CHALLENGE_DEGREE: u32 = @import("tensor_options").challenge_degree;
pub const IS_OM31 = CHALLENGE_DEGREE == 8;
/// The challenge / secure field of every tensor proof. Historically named
/// QM31 (every module uses `f.QM31`); in an -Dchallenge=om31 build it is the
/// degree-8 field Ext8 below. Commitments stay over M31 either way.
pub const QM31 = if (IS_OM31) Ext8 else Q4;
/// log2 |challenge field|
pub const LOG2_CHALLENGE: f64 = @as(f64, @floatFromInt(CHALLENGE_DEGREE)) * 30.99999999932819;

/// OM31 = QM31[v]/(v^2 - u) (core/fields/om31.zig; irreducible since
/// Norm(u) = 5 is a non-square mod p). QM31 is its subfield c1 = 0, and
/// OM31.fromU32Unchecked(a,b,c,d) builds that subfield element, so every
/// QM31 constant in the frontend keeps its meaning.
pub const Ext8 = core.fields.om31.OM31;
pub const P: u32 = core.fields.m31.Modulus;
pub const PackedQ4 = core.fields.packed_qm31.PackedQM31;
/// PACK_WIDTH lanes of the challenge field (PackedQM31, or PackedExt8).
pub const PackedQM31 = if (IS_OM31) PackedExt8 else PackedQ4;

/// PACK_WIDTH lanes of OM31 as a pair of packed QM31 (core/fields/packed_om31.zig
/// arithmetic), with PackedQM31's method surface.
pub const PackedExt8 = struct {
    c0: PackedQ4,
    c1: PackedQ4,
    const PO = core.fields.packed_om31;
    const Self = @This();
    inline fn o(x: Self) PO.PackedOM31 {
        return .{ .c0 = x.c0, .c1 = x.c1 };
    }
    pub inline fn zero() Self {
        return .{ .c0 = PackedQ4.zero(), .c1 = PackedQ4.zero() };
    }
    pub inline fn fromBase(v: PackedM31) Self {
        return .{ .c0 = PackedQ4.fromBase(v), .c1 = PackedQ4.zero() };
    }
    pub inline fn splat(v: Ext8) Self {
        return .{ .c0 = PackedQ4.splat(v.c0), .c1 = PackedQ4.splat(v.c1) };
    }
    pub inline fn fromLanes(v: [PACK_WIDTH]Ext8) Self {
        var a: [PACK_WIDTH]Q4 = undefined;
        var b: [PACK_WIDTH]Q4 = undefined;
        inline for (0..PACK_WIDTH) |i| {
            a[i] = v[i].c0;
            b[i] = v[i].c1;
        }
        return .{ .c0 = PackedQ4.fromLanes(a), .c1 = PackedQ4.fromLanes(b) };
    }
    pub inline fn lane(x: Self, i: usize) Ext8 {
        return .{ .c0 = x.c0.lane(i), .c1 = x.c1.lane(i) };
    }
    pub inline fn add(x: Self, y: Self) Self {
        return .{ .c0 = x.c0.add(y.c0), .c1 = x.c1.add(y.c1) };
    }
    pub inline fn sub(x: Self, y: Self) Self {
        return .{ .c0 = x.c0.sub(y.c0), .c1 = x.c1.sub(y.c1) };
    }
    pub inline fn mul(x: Self, y: Self) Self {
        const r = PO.mul(o(x), o(y));
        return .{ .c0 = r.c0, .c1 = r.c1 };
    }
    pub inline fn mulBase(x: Self, b: PackedM31) Self {
        return .{ .c0 = x.c0.mulBase(b), .c1 = x.c1.mulBase(b) };
    }
};
pub const PackedM31 = core.fields.m31.PackedM31;
pub const PACK_WIDTH = core.fields.m31.PACK_WIDTH;
pub const addPackedM31 = core.fields.m31.addPacked;
pub const subPackedM31 = core.fields.m31.subPacked;
pub const mulPackedM31 = core.fields.m31.mulPacked;

/// Signed integer to M31 (|x| < p).
pub inline fn fromI64(x: i64) M31 {
    const p: i64 = P;
    var r = @mod(x, p);
    if (r < 0) r += p;
    return M31.fromCanonical(@intCast(r));
}

/// Any i32 to its canonical M31 residue. Total on the whole i32 range:
/// maxInt(i32) = p maps to 0 and minInt(i32) = -2^31 maps to p - 1 (EXT-5 /
/// KERN-5: the old branch asserted on p and wrapped on -2^31).
pub inline fn fromI32(x: i32) M31 {
    var r: i64 = x;
    if (r < 0) r += P;
    if (r < 0) r += P; // x = -2^31
    if (r >= P) r -= P; // x = 2^31 - 1 = p
    return M31.fromCanonical(@intCast(r));
}

test "fromI32 is total and canonical on the whole i32 range" {
    try std.testing.expectEqual(@as(u32, 0), fromI32(std.math.maxInt(i32)).v);
    try std.testing.expectEqual(@as(u32, P - 1), fromI32(std.math.minInt(i32)).v);
    try std.testing.expectEqual(@as(u32, P - 1), fromI32(-1).v);
    try std.testing.expectEqual(@as(u32, 5), fromI32(5).v);
    for ([_]i32{ std.math.minInt(i32), std.math.minInt(i32) + 1, -@as(i32, P) + 3, -1, 0, 1, std.math.maxInt(i32) - 1, std.math.maxInt(i32) }) |x|
        try std.testing.expectEqual(fromI64(x).v, fromI32(x).v);
}

pub inline fn qFromI64(x: i64) QM31 {
    return QM31.fromBase(fromI64(x));
}

/// limbs of one challenge-field element (4 for QM31, 8 for OM31)
pub const N_LIMBS: usize = CHALLENGE_DEGREE;
pub const Limbs = [N_LIMBS]u32;
/// bytes of one challenge-field element on the wire
pub const FELT_BYTES: usize = 4 * N_LIMBS;

pub inline fn limbs(x: QM31) Limbs {
    if (!IS_OM31) return .{ x.c0.a.v, x.c0.b.v, x.c1.a.v, x.c1.b.v };
    var out: Limbs = undefined;
    for (x.toM31Array(), 0..) |v, i| out[i] = v.v;
    return out;
}

/// Canonical-input contract (KERN-4): the field kernels (M31.sub's
/// (a + P) - b, QM31.mul's base-field shortcut mulM31 -> mulVec4, ...) are
/// only correct for limbs in [0, P). Values built here from trusted limbs use
/// `fromLimbs`; anything decoded from untrusted bytes must use
/// `fromLimbsChecked`, and verifiers run canonical.check on whole proofs.
pub inline fn fromLimbs(l: Limbs) QM31 {
    if (!IS_OM31) return QM31.fromU32Unchecked(l[0], l[1], l[2], l[3]);
    var m: [N_LIMBS]M31 = undefined;
    for (l, 0..) |v, i| m[i] = M31.fromCanonical(v);
    return QM31.fromM31Array(m);
}

/// `fromLimbs` for untrusted input: error.NonCanonical if a limb is >= P.
pub fn fromLimbsChecked(l: Limbs) error{NonCanonical}!QM31 {
    for (l) |v| if (v >= P) return error.NonCanonical;
    return fromLimbs(l);
}

/// Reduce a signed 64-bit accumulator (|acc| < 2^62) into M31.
pub inline fn reduceI64(acc: i64) u32 {
    const p: i64 = P;
    var r = @rem(acc, p);
    if (r < 0) r += p;
    return @intCast(r);
}

pub fn log2Exact(n: usize) u32 {
    std.debug.assert(n != 0 and std.math.isPowerOfTwo(n));
    return @intCast(std.math.log2_int(usize, n));
}

// ---------------------------------------------------------------------------
// Thread pool helper.

/// upper bound on per-call task fan-out used by fixed-size scratch arrays
pub const MAX_POOL_TASKS: usize = 256;

pub const Pool = struct {
    pool: std.Thread.Pool,
    n_threads: usize,

    pub fn init(self: *Pool, allocator: std.mem.Allocator, n_threads: usize) !void {
        self.n_threads = n_threads;
        try self.pool.init(.{ .allocator = allocator, .n_jobs = n_threads });
    }

    pub fn deinit(self: *Pool) void {
        self.pool.deinit();
    }

    /// Calls `func(ctx, chunk_start, chunk_end)` over [0, n) split into roughly
    /// `n_threads * 4` chunks (at least `min_chunk` items each).
    pub fn parallelFor(self: *Pool, n: usize, min_chunk: usize, ctx: anytype, comptime func: anytype) void {
        if (n == 0) return;
        const target_chunks = self.n_threads * 4;
        var chunk = (n + target_chunks - 1) / target_chunks;
        if (chunk < min_chunk) chunk = min_chunk;
        if (chunk >= n or self.n_threads <= 1) {
            func(ctx, 0, n);
            return;
        }
        var wg: std.Thread.WaitGroup = .{};
        var start: usize = 0;
        while (start < n) : (start += chunk) {
            const end = @min(n, start + chunk);
            self.pool.spawnWg(&wg, func, .{ ctx, start, end });
        }
        self.pool.waitAndWork(&wg);
    }
};

// ---------------------------------------------------------------------------
// eq tables.

/// eq(point, x) for all x in {0,1}^n, MSB-first (point[0] <-> index MSB).
pub fn eqTable(allocator: std.mem.Allocator, point: []const QM31, scale: QM31) ![]QM31 {
    const n = point.len;
    const out = try allocator.alloc(QM31, @as(usize, 1) << @intCast(n));
    out[0] = scale;
    var len: usize = 1;
    // Process variables from the last (LSB) to the first (MSB) so that each
    // doubling places the new variable at the current MSB: out[i + len] uses x_k = 1.
    var k: usize = n;
    while (k > 0) {
        k -= 1;
        const r = point[k];
        const one_minus = QM31.one().sub(r);
        var i: usize = len;
        while (i > 0) {
            i -= 1;
            const v = out[i];
            out[i + len] = v.mul(r);
            out[i] = v.mul(one_minus);
        }
        len *= 2;
    }
    return out;
}

/// Parallel eq table for large n: builds the top bits serially, then expands
/// each block independently.
pub fn eqTablePar(allocator: std.mem.Allocator, pool: *Pool, point: []const QM31, scale: QM31) ![]QM31 {
    const n = point.len;
    if (n <= 14) return eqTable(allocator, point, scale);
    const top: usize = 8;
    const prefix = try eqTable(allocator, point[0..top], scale);
    defer allocator.free(prefix);
    const suffix = try eqTable(allocator, point[top..], QM31.one());
    defer allocator.free(suffix);
    const out = try allocator.alloc(QM31, @as(usize, 1) << @intCast(n));
    const Ctx = struct { out: []QM31, prefix: []const QM31, suffix: []const QM31 };
    const ctx = Ctx{ .out = out, .prefix = prefix, .suffix = suffix };
    pool.parallelFor(prefix.len, 1, ctx, struct {
        fn run(c: Ctx, s: usize, e: usize) void {
            for (s..e) |hi| {
                const base = hi * c.suffix.len;
                const p = c.prefix[hi];
                for (c.suffix, 0..) |v, lo| c.out[base + lo] = p.mul(v);
            }
        }
    }.run);
    return out;
}

/// eq(a, b) for two points of equal length.
pub fn eqEval(a: []const QM31, b: []const QM31) QM31 {
    std.debug.assert(a.len == b.len);
    var acc = QM31.one();
    for (a, b) |x, y| {
        // x*y + (1-x)(1-y) = 1 - x - y + 2xy
        const xy = x.mul(y);
        acc = acc.mul(QM31.one().sub(x).sub(y).add(xy).add(xy));
    }
    return acc;
}

/// MLE of the identity table v -> v (n variables, MSB first) at `point`.
pub fn identityMle(point: []const QM31) QM31 {
    var acc = QM31.zero();
    const n = point.len;
    for (point, 0..) |r, k| {
        const w: u32 = @as(u32, 1) << @intCast(n - 1 - k);
        acc = acc.add(r.mulM31(M31.fromCanonical(w)));
    }
    return acc;
}

/// Evaluate the MLE of a QM31 vector at a point by repeated folding (test/verifier helper).
pub fn mleEval(allocator: std.mem.Allocator, values: []const QM31, point: []const QM31) !QM31 {
    std.debug.assert(values.len == (@as(usize, 1) << @intCast(point.len)));
    const buf = try allocator.dupe(QM31, values);
    defer allocator.free(buf);
    var len = buf.len;
    for (point) |r| {
        const half = len / 2;
        for (0..half) |i| buf[i] = buf[i].add(r.mul(buf[i + half].sub(buf[i])));
        len = half;
    }
    return buf[0];
}

/// MLE of an integer vector at a point by folding (MSB first); the first fold
/// multiplies QM31 by M31 differences only (verifier-side public tensors:
/// half the memory and about a third of the work of the eq-table form).
pub fn mleFoldI32(a: std.mem.Allocator, v: []const i32, z: []const QM31) !QM31 {
    std.debug.assert(v.len == @as(usize, 1) << @intCast(z.len));
    if (z.len == 0) return QM31.fromBase(fromI32(v[0]));
    const half = v.len / 2;
    const buf = try a.alloc(QM31, half);
    defer a.free(buf);
    for (buf, v[0..half], v[half..]) |*o, lo, hi| {
        const l = fromI32(lo);
        o.* = QM31.fromBase(l).add(z[0].mulM31(fromI32(hi).sub(l)));
    }
    var len = half;
    for (z[1..]) |r| {
        const h = len / 2;
        for (0..h) |i| buf[i] = buf[i].add(r.mul(buf[i + h].sub(buf[i])));
        len = h;
    }
    return buf[0];
}

test "mleFoldI32 matches mleEvalI32 (field)" {
    const a = std.testing.allocator;
    var v: [64]i32 = undefined;
    for (&v, 0..) |*x, i| x.* = @as(i32, @intCast(i * 37 % 101)) - 50;
    v[3] = std.math.minInt(i32);
    v[9] = std.math.maxInt(i32);
    var z: [6]QM31 = undefined;
    for (&z, 0..) |*x, i| x.* = QM31.fromU32Unchecked(@intCast(i * 7 + 3), 11, @intCast(i), 5);
    try std.testing.expect((try mleFoldI32(a, &v, &z)).eql(try mleEvalI32(a, &v, &z)));
}

pub fn mleEvalI32(allocator: std.mem.Allocator, values: []const i32, point: []const QM31) !QM31 {
    const eq = try eqTable(allocator, point, QM31.one());
    defer allocator.free(eq);
    var acc = QM31.zero();
    for (values, eq) |v, e| acc = acc.add(e.mulM31(fromI32(v)));
    return acc;
}

/// MLE of an integer vector at pt, with eq split into a high table (one entry
/// per chunk) and a low table (shared, in cache): no full-size eq table.
pub fn mleEvalI32Par(a: std.mem.Allocator, pool: *Pool, vals: []const i32, pt: []const QM31) !QM31 {
    const n = pt.len;
    std.debug.assert(vals.len == @as(usize, 1) << @intCast(n));
    const lo_bits = @min(n, 12);
    const eq_hi = try eqTable(a, pt[0 .. n - lo_bits], QM31.one());
    defer a.free(eq_hi);
    const eq_lo = try eqTable(a, pt[n - lo_bits ..], QM31.one());
    defer a.free(eq_lo);
    const parts = try a.alloc(QM31, eq_hi.len);
    defer a.free(parts);
    const Ctx = struct { vals: []const i32, hi: []const QM31, lo: []const QM31, parts: []QM31 };
    const ctx = Ctx{ .vals = vals, .hi = eq_hi, .lo = eq_lo, .parts = parts };
    pool.parallelFor(eq_hi.len, @max(1, @as(usize, 1 << 14) >> @intCast(lo_bits)), &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            const L = c.lo.len;
            for (s..e) |h| {
                var acc = QM31.zero();
                for (c.vals[h * L ..][0..L], c.lo) |v, wv| {
                    if (v != 0) acc = acc.add(wv.mulM31(fromI32(v)));
                }
                c.parts[h] = acc.mul(c.hi[h]);
            }
        }
    }.run);
    var acc = QM31.zero();
    for (parts) |x| acc = acc.add(x);
    return acc;
}

test "eq table matches eqEval and mle folding" {
    const a = std.testing.allocator;
    var pts: [5]QM31 = undefined;
    for (&pts, 0..) |*p, i| p.* = QM31.fromU32Unchecked(@intCast(3 + i * 7), @intCast(11 + i), 5, @intCast(2 * i + 1));
    const eq = try eqTable(a, &pts, QM31.one());
    defer a.free(eq);
    for (0..32) |x| {
        var bits: [5]QM31 = undefined;
        for (0..5) |k| bits[k] = if ((x >> @intCast(4 - k)) & 1 == 1) QM31.one() else QM31.zero();
        try std.testing.expect(eq[x].eql(eqEval(&pts, &bits)));
    }
    var vals: [32]QM31 = undefined;
    for (&vals, 0..) |*v, i| v.* = QM31.fromBase(M31.fromCanonical(@intCast(i * i + 1)));
    var direct = QM31.zero();
    for (vals, eq) |v, e| direct = direct.add(v.mul(e));
    try std.testing.expect(direct.eql(try mleEval(a, &vals, &pts)));
    var idv: [32]QM31 = undefined;
    for (&idv, 0..) |*v, i| v.* = QM31.fromBase(M31.fromCanonical(@intCast(i)));
    try std.testing.expect(identityMle(&pts).eql(try mleEval(a, &idv, &pts)));
}

test "parallel split-eq mleEvalI32Par equals mleEvalI32" {
    const a = std.testing.allocator;
    var pool: Pool = undefined;
    try pool.init(a, 3);
    defer pool.deinit();
    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();
    for ([_]usize{ 0, 1, 5, 12, 13, 17 }) |n| {
        const vals = try a.alloc(i32, @as(usize, 1) << @intCast(n));
        defer a.free(vals);
        for (vals) |*v| v.* = rnd.intRangeAtMost(i32, std.math.minInt(i32), std.math.maxInt(i32));
        const pt = try a.alloc(QM31, n);
        defer a.free(pt);
        for (pt) |*p| p.* = QM31.fromU32Unchecked(rnd.uintLessThan(u32, P), rnd.uintLessThan(u32, P), rnd.uintLessThan(u32, P), rnd.uintLessThan(u32, P));
        try std.testing.expect((try mleEvalI32(a, vals, pt)).eql(try mleEvalI32Par(a, &pool, vals, pt)));
    }
}
