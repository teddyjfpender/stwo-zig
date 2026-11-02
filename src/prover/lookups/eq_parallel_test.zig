const std = @import("std");
const core = @import("stwo_core");
const C = @import("gkr_circuit_field.zig");
const Pools = @import("../work_pool.zig");
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn dense(comptime S: type, i: usize) S {
    var coordinates: [S.zero().toM31Array().len]M = undefined;
    for (&coordinates, 0..) |*v, j| v.* = M.fromCanonical(@intCast((i * 7919 + j * 977 + 3) % 1048573));
    return S.fromM31Array(coordinates);
}
fn check(comptime S: type) !void {
    const Eq = C.ForField(S).EqEvals;
    var pool: Pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var binding = try Pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    for ([_]usize{ 0, 1, 5, 17 }) |variables| {
        const y = try a.alloc(S, variables);
        defer a.free(y);
        for (y, 0..) |*v, i| v.* = dense(S, i);
        var eq = try Eq.generate(a, y);
        defer eq.deinit(a);
        for (eq.evals.evalsSlice(), 0..) |value, index| {
            var expected = if (y.len == 0) S.one() else S.one().sub(y[0]);
            // The first tail coordinate is the high index bit, just as the
            // existing Eq generator and circuit sumcheck binding require.
            for (y[@min(1, y.len)..], 0..) |yi, bit| {
                const high = y.len - 2 - bit;
                expected = expected.mul(if (index & (@as(usize, 1) << @intCast(high)) == 0) S.one().sub(yi) else yi);
            }
            try std.testing.expectEqualDeep(expected, value);
        }
    }
}
test "pooled Q Eq levels preserve direct tensor basis ordering" {
    try check(core.fields.qm31.QM31);
}
test "pooled OM Eq levels preserve direct tensor basis ordering" {
    try check(core.fields.om31.OM31);
}
fn benchmark(comptime S: type) !void {
    const Eq = C.ForField(S).EqEvals;
    var y: [20]S = undefined;
    for (&y, 0..) |*v, i| v.* = dense(S, i);
    var times: [2]u64 = undefined;
    for ([_]usize{ 1, 4 }, 0..) |workers, index| {
        var pool: Pools.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers });
        defer pool.deinit();
        var binding = try Pools.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var timer = try std.time.Timer.start();
        var sum = S.zero();
        for (0..3) |_| {
            var eq = try Eq.generate(a, &y);
            sum = sum.add(eq.evals.evalsSlice()[1337]);
            eq.deinit(a);
        }
        times[index] = timer.read();
        std.mem.doNotOptimizeAway(sum);
    }
    std.debug.print("GKR_EQ_LEVELS field={s} variables=20 rounds=3 serial_ns={d} pool4_ns={d} ratio={d:.3}\n", .{ @typeName(S), times[0], times[1], @as(f64, @floatFromInt(times[0])) / @as(f64, @floatFromInt(times[1])) });
}
test "optional bounded Eq levels microbenchmark" {
    if (!std.process.hasEnvVarConstant("STWO_ZIG_BENCH_GKR_EQ")) return;
    try benchmark(core.fields.qm31.QM31);
    try benchmark(core.fields.om31.OM31);
}
