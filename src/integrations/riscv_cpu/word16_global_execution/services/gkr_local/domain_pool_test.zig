const std = @import("std");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const Fixture = @import("cpu_worker_test.zig");
const Domain = @import("role_domain.zig");
const Role = @import("role.zig");
const a = std.testing.allocator;
test "pooled packed CPU domain FFT and rows preserve complete physical artifacts" {
    inline for (.{ 0, 1 }) |shard| {
        const scalar = try Fixture.exercise(shard, .normal, .resident);
        var pool: engine.work_pool.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = 4 });
        defer pool.deinit();
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        const pooled = try Fixture.exercise(shard, .normal, .resident);
        try std.testing.expectEqualSlices(u8, &scalar, &pooled);
    }
}
test "domain scratch plan is finite alignment-aware and allocated before work" {
    const plan = try Domain.rowScratchPlan(Role.Component, 1 << 22, 32);
    try std.testing.expect(plan.jobs <= engine.lookups.row_work.MAX_SHARDS);
    try std.testing.expect(plan.total_bytes <= Domain.MAX_ROW_SCRATCH_BYTES);
    try std.testing.expectEqual(plan.total_bytes, plan.jobs * plan.bytes_per_job);
    try std.testing.expectError(error.InvalidLocalGkrTrace, Domain.rowScratchPlan(Role.Component, A.evaluation.LANES + 1, 4));
    const serial = try Domain.rowScratchPlan(Role.Component, 32, 1);
    try std.testing.expectEqual(@as(usize, 1), serial.jobs);
    try std.testing.checkAllAllocationFailures(a, scratchLifecycle, .{});
}
fn scratchLifecycle(allocator: std.mem.Allocator) !void {
    var owned = try Domain.ScratchOwner(Role.Component).init(allocator, 1 << 22, 8);
    defer owned.deinit();
    try std.testing.expectEqual(owned.plan.jobs, owned.data.len);
    try std.testing.expectEqual(owned.plan.total_bytes, std.mem.sliceAsBytes(owned.data).len);
}
