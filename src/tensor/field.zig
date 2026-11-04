//! Field helpers for the tensor frontend: M31 base field, QM31 secure field.
//!
//! Multilinear convention (matches stwo's GKR/MLE code): variable 0 is the
//! most significant bit of the hypercube index, so `fold(r)` combines the low
//! half with the high half: f'(x) = f(0,x) + r (f(1,x) - f(0,x)).
const std = @import("std");
const core = @import("stwo_core");

pub const M31 = core.fields.m31.M31;
pub const QM31 = core.fields.qm31.QM31;
pub const P: u32 = core.fields.m31.Modulus;
pub const PackedQM31 = core.fields.packed_qm31.PackedQM31;
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

pub inline fn fromI32(x: i32) M31 {
    return if (x >= 0) M31.fromCanonical(@intCast(x)) else M31.fromCanonical(@intCast(@as(i64, P) + x));
}

pub inline fn qFromI64(x: i64) QM31 {
    return QM31.fromBase(fromI64(x));
}

pub inline fn limbs(x: QM31) [4]u32 {
    return .{ x.c0.a.v, x.c0.b.v, x.c1.a.v, x.c1.b.v };
}

/// Canonical-input contract (KERN-4): the field kernels (M31.sub's
/// (a + P) - b, QM31.mul's base-field shortcut mulM31 -> mulVec4, ...) are
/// only correct for limbs in [0, P). Values built here from trusted limbs use
/// `fromLimbs`; anything decoded from untrusted bytes must use
/// `fromLimbsChecked`, and verifiers run canonical.check on whole proofs.
pub inline fn fromLimbs(l: [4]u32) QM31 {
    return QM31.fromU32Unchecked(l[0], l[1], l[2], l[3]);
}

/// `fromLimbs` for untrusted input: error.NonCanonical if a limb is >= P.
pub fn fromLimbsChecked(l: [4]u32) error{NonCanonical}!QM31 {
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
