//! Operational CPU tree policy, frozen before admission; never transcript input.
const std = @import("std");
const Child = @import("child.zig");
const Retention = @import("retention_plan.zig");
const R = @import("../roster.zig");
const P = @import("../protocol.zig");
const W = @import("worker_protocol.zig");
pub fn validate(base: Child.TreePolicy, threshold: usize) !void {
    if (threshold != 0 and (!base.stream_bottom or base.checkpointed or !base.tight_admission)) return error.InvalidHybridGkrTreePolicy;
}
pub fn resolve(base: Child.TreePolicy, threshold: usize, source_dense_peak: usize) !Child.TreePolicy {
    try validate(base, threshold);
    var result = base;
    if (threshold != 0 and source_dense_peak > threshold) result.checkpointed = true;
    return result;
}
pub const CpuPlan = struct { plan: Retention.RetentionPlan, policy: Child.TreePolicy };
pub fn forCpu(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, config: W.PcsConfig, gkr_limit: usize, global_limit: usize, base: Child.TreePolicy, threshold: usize) !CpuPlan {
    try validate(base, threshold);
    if (threshold == 0) return .{ .policy = base, .plan = if (base.stream_bottom) try Retention.forCpuWithSourceStorage(a, setup, request, config, gkr_limit, global_limit, base.checkpointed) else try Retention.forCpuWithTightAdmission(a, setup, request, config, gkr_limit, global_limit, base.checkpointed, base.tight_admission) };
    // Derive source80 geometry once without applying its GKR cap yet. Selection
    // depends solely on shape+threshold; no failed allocation or budget retry.
    const dense = try Retention.forCpuWithSourceStorage(a, setup, request, config, std.math.maxInt(usize), global_limit, false);
    const selected = try resolve(base, threshold, dense.gkr_peak_bytes);
    if (selected.checkpointed) return .{ .policy = selected, .plan = try Retention.forCpuWithSourceStorage(a, setup, request, config, gkr_limit, global_limit, true) };
    if (gkr_limit == 0) return error.MissingLocalGkrBudget;
    if (dense.gkr_peak_bytes > gkr_limit) return error.LocalGkrBudgetExceeded;
    return .{ .policy = selected, .plan = dense };
}
test "hybrid GKR selector is strict deterministic and rejects conflicting bases" {
    const source = Child.TreePolicy{ .stream_bottom = true, .tight_admission = true };
    try std.testing.expectEqualDeep(source, try resolve(source, 100, 99));
    try std.testing.expectEqualDeep(source, try resolve(source, 100, 100));
    var expected = source;
    expected.checkpointed = true;
    try std.testing.expectEqualDeep(expected, try resolve(source, 100, 101));
    try std.testing.expectEqualDeep(source, try resolve(source, 0, std.math.maxInt(usize)));
    try std.testing.expectError(error.InvalidHybridGkrTreePolicy, resolve(.{}, 1, 2));
    try std.testing.expectError(error.InvalidHybridGkrTreePolicy, resolve(.{ .stream_bottom = true, .tight_admission = true, .checkpointed = true }, 1, 2));
    try std.testing.expectError(error.InvalidHybridGkrTreePolicy, resolve(.{ .stream_bottom = true }, 1, 2));
    try std.testing.expectEqualDeep(Child.TreePolicy{}, try resolve(.{}, 0, 0));
}
