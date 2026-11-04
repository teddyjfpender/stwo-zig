//! Adversarial review (review-kern): Metal vs CPU identity at the exactness
//! boundaries the host dispatch logic claims.
const std = @import("std");
const t = @import("stwo_tensor");
const metal = @import("stwo_tensor_metal");
const f = t.field;
const pcs = t.pcs;
const proto = t.protocol;
const QM31 = f.QM31;

var gpu_singleton: ?*metal.Gpu = null;
fn gpu() !*metal.Gpu {
    if (gpu_singleton) |g| return g;
    gpu_singleton = try metal.Gpu.init(std.heap.c_allocator);
    return gpu_singleton.?;
}

fn checkMatmul(a: std.mem.Allocator, pool: *f.Pool, g: *metal.Gpu, lt: u32, lk: u32, ln: u32, x: []const i32, w: []const i8) !void {
    const wm = pcs.Matrix(i8){ .data = w, .log_rows = lk, .log_cols = ln };
    const cpu = try proto.matmulAcc(a, pool, proto.TensorInfo.mat(lt, lk), x, wm);
    defer a.free(cpu);
    const dev = (try t.accel.matmulAcc(g.accel(), a, lt, x, wm)) orelse return error.Declined;
    defer a.free(dev);
    var bad: usize = 0;
    for (cpu, dev, 0..) |c, d, i| if (c != d) {
        if (bad < 3) std.debug.print("\n[review-kern] metal matmul mismatch at {d}: cpu {d} gpu {d}\n", .{ i, c, d });
        bad += 1;
    };
    try std.testing.expectEqual(@as(usize, 0), bad);
}

test "review-kern metal: matmul with activation +128 (max |x| == 128, fp32 path) matches CPU" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const g = try gpu();
    const lt = 6;
    const lk = 7;
    const ln = 6;
    const x = try a.alloc(i32, 1 << (lt + lk));
    defer a.free(x);
    var prng = std.Random.DefaultPrng.init(4);
    const r = prng.random();
    // e.g. softmax probabilities quantised to [0, 128] (transformer.zig: P in [0, 128])
    for (x) |*v| v.* = r.intRangeAtMost(i32, 0, 128);
    x[0] = 128;
    const w = try a.alloc(i8, 1 << (lk + ln));
    defer a.free(w);
    for (w) |*v| v.* = r.int(i8);
    try checkMatmul(a, &pool, g, lt, lk, ln, x, w);
}

test "review-kern metal: matmul int32 path at |x| = 2^15 - 1 and worst-case weights matches CPU" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const g = try gpu();
    const lt = 6;
    const lk = 8;
    const ln = 6;
    const x = try a.alloc(i32, 1 << (lt + lk));
    defer a.free(x);
    @memset(x, -(1 << 15) + 1);
    const w = try a.alloc(i8, 1 << (lk + ln));
    defer a.free(w);
    @memset(w, -128);
    try checkMatmul(a, &pool, g, lt, lk, ln, x, w);
}

test "review-kern metal: fp32 matmul at the 2^23 partial-sum bound (K = 2^12, x = w = -128) matches CPU" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const g = try gpu();
    const lt = 6;
    const lk = 12;
    const ln = 6;
    const x = try a.alloc(i32, 1 << (lt + lk));
    defer a.free(x);
    @memset(x, -128);
    const w = try a.alloc(i8, 1 << (lk + ln));
    defer a.free(w);
    @memset(w, -128);
    // odd perturbations so partial sums are not all powers of two
    for (0..(@as(usize, 1) << lk)) |k| w[k << ln] = -127;
    try checkMatmul(a, &pool, g, lt, lk, ln, x, w);
}

// --- independent re-check variants (not committed) ---
fn variant(lt: u32, lk: u32, ln: u32, seed: u64, lo: i32, hi: i32, force: []const i32) !void {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const g = try gpu();
    const x = try a.alloc(i32, @as(usize, 1) << @intCast(lt + lk));
    defer a.free(x);
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    for (x) |*v| v.* = r.intRangeAtMost(i32, lo, hi);
    for (force, 0..) |v, i| x[i * 37 % x.len] = v;
    const w = try a.alloc(i8, @as(usize, 1) << @intCast(lk + ln));
    defer a.free(w);
    for (w) |*v| v.* = r.int(i8);
    try checkMatmul(a, &pool, g, lt, lk, ln, x, w);
}
test "recheck metal: full int8 range [-128,127] incl both ends (fp32 path), K=2^10" {
    try variant(6, 10, 6, 11, -128, 127, &.{ -128, 127 });
}
test "recheck metal: single +128 among negatives, K=2^12 (int32 path)" {
    try variant(6, 12, 6, 12, -128, 0, &.{128});
}
test "recheck metal: single -129 among int8 (int32 path)" {
    try variant(6, 9, 6, 13, -128, 127, &.{-129});
}
test "recheck metal: |x| = 2^15-1 both signs, K=2^12 (int32 path, multi-chunk)" {
    try variant(6, 12, 6, 14, -(1 << 15) + 1, (1 << 15) - 1, &.{ (1 << 15) - 1, -(1 << 15) + 1 });
}
test "recheck metal: x = 2^15 (declined -> CPU)" {
    const a = std.testing.allocator;
    const g = try gpu();
    var x = [_]i32{1 << 15} ** (64 * 64);
    var w = [_]i8{1} ** (64 * 64);
    const wm = pcs.Matrix(i8){ .data = &w, .log_rows = 6, .log_cols = 6 };
    const dev = try t.accel.matmulAcc(g.accel(), a, 6, &x, wm);
    try std.testing.expect(dev == null);
}
