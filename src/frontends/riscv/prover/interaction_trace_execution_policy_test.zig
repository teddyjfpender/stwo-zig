//! Execution-policy regression for receipt-bearing guest Tree 2.

const std = @import("std");
const work_pool = @import("stwo_prover_engine").work_pool;
const interaction_trace = @import("interaction_trace.zig");

test "profiled guest Tree2 ignores an active global proof pool" {
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = 256 * 1024,
    });
    defer pool.deinit();
    var binding = try work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();

    try std.testing.expectEqual(&pool, work_pool.getGlobalPool().?);
    try std.testing.expectEqual(
        interaction_trace.BaseExecutionPolicy.sequential,
        interaction_trace.GUEST_PROFILED_TREE2_EXECUTION_POLICY,
    );
    try std.testing.expect(
        interaction_trace.GUEST_PROFILED_TREE2_EXECUTION_POLICY.selectedPool() == null,
    );
    try interaction_trace.GUEST_PROFILED_TREE2_EXECUTION_POLICY.requireSequentialReceipt();
    try std.testing.expectError(
        error.UnsupportedProfiledInteractionExecution,
        interaction_trace.BaseExecutionPolicy.ambient.requireSequentialReceipt(),
    );
    try std.testing.expectEqual(
        &pool,
        interaction_trace.BaseExecutionPolicy.ambient.selectedPool().?,
    );
}
