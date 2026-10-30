const std = @import("std");
const engine = @import("stwo_prover_engine");
const Jobs = @import("block_v7_preparation_jobs_v1.zig");
const Context = struct {
    slots: [9]usize = @splat(0),
    fail: bool = false,
    fn prepare(self: *@This(), index: usize) !void {
        self.slots[index] = index + 1;
        if (self.fail and index == 1) return error.FirstFailure;
        if (self.fail and index == 2) return error.SecondFailure;
    }
};
test "parallel preparation canonical slots deterministic failure and nested fallback" {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    for ([_]usize{ 1, 2, 4 }) |width| {
        var context = Context{};
        try Jobs.run(a, 9, width, &context, Context.prepare);
        for (context.slots, 0..) |value, index| try std.testing.expectEqual(index + 1, value);
    }
    var failing = Context{ .fail = true };
    try std.testing.expectError(error.FirstFailure, Jobs.run(a, 9, 4, &failing, Context.prepare));
    // Every submitted job joins; no later cohort starts after an error.
    try std.testing.expectEqualSlices(usize, &.{ 1, 2, 3, 4, 0, 0, 0, 0, 0 }, &failing.slots);
    var lease = try pool.acquire(try engine.work_pool.WorkerBudget.init(4));
    {
        defer lease.deinit();
        var nested = Context{};
        try Jobs.run(a, 9, 4, &nested, Context.prepare);
        for (nested.slots, 0..) |value, index| try std.testing.expectEqual(index + 1, value);
    }
    var context = Context{};
    try std.testing.expectError(error.InvalidParallelPreparation, Jobs.run(a, 9, 0, &context, Context.prepare));
}
fn allocFailure(a: std.mem.Allocator) !void {
    var context = Context{};
    try Jobs.run(a, 9, 4, &context, Context.prepare);
}
test "parallel preparation submission metadata allocation cleanup" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocFailure, .{});
}
