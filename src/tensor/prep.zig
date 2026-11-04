//! Prover-side LogUp input preparation: multiplicities (parallel histograms)
//! and key denominators alpha - key(i), specialised per key kind.
//!
//! Values are exactly the ones protocol.zig computed before (field arithmetic
//! is exact); range/lookup validity is checked while counting, which happens
//! before any denominator is built, so the denominator kernels can use
//! table lookups / plain M31 subtraction without re-checking.
const std = @import("std");
const f = @import("field.zig");

const QM31 = f.QM31;
const M31 = f.M31;

pub const KeySrc = union(enum) {
    /// r = acc + 2^(sh-1) - (y << sh), must lie in [0, mult.len)
    remainder: struct { acc: []const i64, y: []const i32, sh: u5 },
    /// v + 128 in [0, 256)
    range8: struct { v: []const i32 },
    /// in + 128 in [0, 256) and out == table[in + 128]
    lookup: struct { in: []const i32, out: []const i32, table: *const [256]i8 },
    /// v + off in [0, mult.len) (wide core-matmul outputs: off = 2^(ob-1),
    /// mult.len = 2^ob)
    range_off: struct { v: []const i32, off: i64 },

    fn len(self: KeySrc) usize {
        return switch (self) {
            .remainder => |r| r.y.len,
            .range8 => |r| r.v.len,
            .lookup => |l| l.in.len,
            .range_off => |r| r.v.len,
        };
    }
};

pub const CountError = error{ RemainderOutOfRange, ValueOutOfRange, LookupMismatch };

inline fn remIndex(r: anytype, i: usize) i64 {
    return r.acc[i] + (@as(i64, 1) << (r.sh - 1)) - (@as(i64, r.y[i]) << r.sh);
}

/// Test-only (test builds): count requant remainders by their value mod p,
/// as the GKR keys see them, instead of refusing out-of-range integers. A
/// cheating prover that wraps a requant output mod p (so the field remainder
/// stays in range) then reaches the verifier.
pub var test_field_remainders: bool = false;

fn countRange(src: KeySrc, hist: []i32, s: usize, e: usize) CountError!void {
    switch (src) {
        .remainder => |r| {
            const m: i64 = @intCast(hist.len);
            const wrap = @import("builtin").is_test and test_field_remainders;
            for (s..e) |i| {
                const v = if (wrap) @mod(remIndex(r, i), @as(i64, f.P)) else remIndex(r, i);
                if (v < 0 or v >= m) return error.RemainderOutOfRange;
                hist[@intCast(v)] += 1;
            }
        },
        .range8 => |r| for (r.v[s..e]) |x| {
            const v = @as(i64, x) + 128;
            if (v < 0 or v >= 256) return error.ValueOutOfRange;
            hist[@intCast(v)] += 1;
        },
        .lookup => |l| for (s..e) |i| {
            const v = @as(i64, l.in[i]) + 128;
            if (v < 0 or v >= 256) return error.ValueOutOfRange;
            if (l.table[@intCast(v)] != l.out[i]) return error.LookupMismatch;
            hist[@intCast(v)] += 1;
        },
        .range_off => |r| {
            const m: i64 = @intCast(hist.len);
            for (r.v[s..e]) |x| {
                const v = @as(i64, x) + r.off;
                if (v < 0 or v >= m) return error.ValueOutOfRange;
                hist[@intCast(v)] += 1;
            }
        },
    }
}

/// mult[key(i)] += 1 for all i, validating every key. Parallel with
/// per-task histograms when the table is small relative to the key count.
pub fn countInto(a: std.mem.Allocator, pool: *f.Pool, mult: []i32, src: KeySrc) !void {
    const n = src.len();
    if (src == .range8 or src == .lookup) std.debug.assert(mult.len == 256);
    const tasks = @min(@min(pool.n_threads, f.MAX_POOL_TASKS), n / 65536);
    if (tasks <= 1 or mult.len * tasks > n) return countRange(src, mult, 0, n);
    const hists = try a.alloc(i32, tasks * mult.len);
    defer a.free(hists);
    @memset(hists, 0);
    var errs = [_]?CountError{null} ** f.MAX_POOL_TASKS;
    const Ctx = struct { src: KeySrc, hists: []i32, m: usize, n: usize, tasks: usize, errs: []?CountError };
    const ctx = Ctx{ .src = src, .hists = hists, .m = mult.len, .n = n, .tasks = tasks, .errs = errs[0..tasks] };
    var wg: std.Thread.WaitGroup = .{};
    for (0..tasks) |t| pool.pool.spawnWg(&wg, struct {
        fn run(c: *const Ctx, ti: usize) void {
            const s = c.n * ti / c.tasks;
            const e = c.n * (ti + 1) / c.tasks;
            countRange(c.src, c.hists[ti * c.m ..][0..c.m], s, e) catch |err| {
                c.errs[ti] = err;
            };
        }
    }.run, .{ &ctx, t });
    pool.pool.waitAndWork(&wg);
    // report the error of the lowest failing index range (same error the serial scan reports)
    for (errs[0..tasks]) |e| if (e) |err| return err;
    for (0..tasks) |t| {
        const h = hists[t * mult.len ..][0..mult.len];
        for (mult, h) |*o, v| o.* += v;
    }
}

/// out[i] = alpha - key(i)  (key(i) = r, v + 128, or in + beta*out).
/// Requires that `countInto` accepted `src` (keys in range).
pub fn denominators(pool: *f.Pool, out: []QM31, src: KeySrc, alpha: QM31, beta: QM31) void {
    std.debug.assert(out.len == src.len());
    var lut: [256]QM31 = undefined;
    switch (src) {
        .range8 => for (&lut, 0..) |*l, j| {
            l.* = alpha.sub(QM31.fromBase(M31.fromCanonical(@intCast(j))));
        },
        .lookup => |lk| for (&lut, 0..) |*l, j| {
            const key = f.qFromI64(@as(i64, @intCast(j)) - 128).add(beta.mul(f.qFromI64(lk.table[j])));
            l.* = alpha.sub(key);
        },
        .remainder, .range_off => {},
    }
    const Ctx = struct { out: []QM31, src: KeySrc, alpha: QM31, lut: *const [256]QM31 };
    const ctx = Ctx{ .out = out, .src = src, .alpha = alpha, .lut = &lut };
    pool.parallelFor(out.len, 8192, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            switch (c.src) {
                .remainder => |r| {
                    // alpha - v: only the base coordinate changes
                    const a0 = if (f.IS_OM31) c.alpha.c0.c0.a else c.alpha.c0.a;
                    for (s..e) |i| {
                        const v: u32 = if (@import("builtin").is_test and test_field_remainders)
                            @intCast(@mod(remIndex(r, i), @as(i64, f.P)))
                        else
                            @intCast(remIndex(r, i));
                        var q = c.alpha;
                        if (f.IS_OM31) {
                            q.c0.c0.a = a0.sub(M31.fromCanonical(v));
                        } else {
                            q.c0.a = a0.sub(M31.fromCanonical(v));
                        }
                        c.out[i] = q;
                    }
                },
                .range8 => |r| for (s..e) |i| {
                    c.out[i] = c.lut[@intCast(r.v[i] + 128)];
                },
                .lookup => |l| for (s..e) |i| {
                    c.out[i] = c.lut[@intCast(l.in[i] + 128)];
                },
                .range_off => |r| {
                    const a0 = if (f.IS_OM31) c.alpha.c0.c0.a else c.alpha.c0.a;
                    for (s..e) |i| {
                        const v: u32 = @intCast(@as(i64, r.v[i]) + r.off);
                        var q = c.alpha;
                        if (f.IS_OM31) {
                            q.c0.c0.a = a0.sub(M31.fromCanonical(v));
                        } else {
                            q.c0.a = a0.sub(M31.fromCanonical(v));
                        }
                        c.out[i] = q;
                    }
                },
            }
        }
    }.run);
}

test "countInto parallel equals serial and reports errors" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const n = 1 << 19;
    const v = try a.alloc(i32, n);
    defer a.free(v);
    var prng = std.Random.DefaultPrng.init(1);
    for (v) |*x| x.* = prng.random().intRangeAtMost(i32, -128, 127);
    var m1 = [_]i32{0} ** 256;
    var m2 = [_]i32{0} ** 256;
    try countInto(a, &pool, &m1, .{ .range8 = .{ .v = v } });
    try countRange(.{ .range8 = .{ .v = v } }, &m2, 0, n);
    try std.testing.expectEqualSlices(i32, &m2, &m1);
    v[n - 3] = 128;
    var m3 = [_]i32{0} ** 256;
    try std.testing.expectError(error.ValueOutOfRange, countInto(a, &pool, &m3, .{ .range8 = .{ .v = v } }));
}
