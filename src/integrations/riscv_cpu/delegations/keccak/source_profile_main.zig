const std = @import("std");
const engine = @import("stwo_prover_engine");
pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 4) return error.ExpectedOutputCallsWorkers;
    const calls = try std.fmt.parseUnsigned(usize, args[2], 10);
    const workers = try std.fmt.parseUnsigned(usize, args[3], 10);
    if (calls > 18078) return error.InvalidFixtureCallCount;
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try @import("source_profile.zig").write(a, args[1], calls, workers);
}
