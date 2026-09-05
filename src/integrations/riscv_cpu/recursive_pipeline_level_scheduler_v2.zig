//! Parent-first level admission for runtime-shaped recursive campaigns.
//!
//! The durable campaign DAG remains independent of machine size.  This
//! process-local planner receives an authenticated campaign shape and an
//! execution-key-bound CPU/RSS policy, chooses the highest ready tree level,
//! and returns the number of independent nodes that may run concurrently.
//! It neither owns nor serializes proof leases; the persistent worker keeps
//! lease ownership and completion ordering.

const std = @import("std");

const shape_mod = @import("recursive_pipeline_campaign_shape_v2.zig");
const policy_mod = @import("recursive_pipeline_worker_execution_policy_v2.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_LEASE = false;

pub const Error = shape_mod.Error || policy_mod.Error || error{
    InvalidRecursiveLevelScheduler,
};

pub const LevelAdmissionV2 = struct {
    height: u8,
    node_count: u32,
    ready_count: u32,
    admitted_count: u16,
    proof_worker_count_per_node: u16,
    reserved_cpu_tokens: u64,
    reserved_rss_bytes: u64,

    pub fn validate(
        self: LevelAdmissionV2,
        shape: *const shape_mod.CampaignShapeAuthorityV2,
        policy: *const policy_mod.PolicyV2,
    ) !void {
        try shape.validate();
        try policy.validate();
        const expected_nodes = try shape.nodeCount(self.height);
        const expected_admitted = try policy.readyNodeAdmission(
            self.ready_count,
        );
        const cpu = std.math.mul(
            u64,
            expected_admitted,
            policy.cpu_tokens_per_node,
        ) catch return error.InvalidRecursiveLevelScheduler;
        const rss = std.math.mul(
            u64,
            expected_admitted,
            policy.rss_bytes_per_node,
        ) catch return error.InvalidRecursiveLevelScheduler;
        if (self.node_count != expected_nodes or self.ready_count == 0 or
            self.ready_count > expected_nodes or
            self.admitted_count != expected_admitted or
            self.proof_worker_count_per_node != policy.proof_worker_count or
            self.reserved_cpu_tokens != cpu or
            self.reserved_rss_bytes != rss or
            self.reserved_cpu_tokens > policy.total_cpu_tokens or
            self.reserved_rss_bytes > policy.total_rss_bytes)
        {
            return error.InvalidRecursiveLevelScheduler;
        }
    }
};

/// `ready_by_height[0]` contains leaf-wrapper work and each later entry the
/// ready fold nodes at that height. Parents outrank lower-level work once both
/// children are committed, keeping the live lease frontier bounded.
pub fn selectHighestReadyLevel(
    shape: *const shape_mod.CampaignShapeAuthorityV2,
    policy: *const policy_mod.PolicyV2,
    ready_by_height: []const u32,
) !?LevelAdmissionV2 {
    try shape.validate();
    try policy.validate();
    const level_count = std.math.add(
        usize,
        shape.root_height,
        1,
    ) catch return error.InvalidRecursiveLevelScheduler;
    if (ready_by_height.len != level_count)
        return error.InvalidRecursiveLevelScheduler;
    for (ready_by_height, 0..) |ready, height| {
        const node_count = try shape.nodeCount(@intCast(height));
        if (ready > node_count)
            return error.InvalidRecursiveLevelScheduler;
    }
    var cursor = ready_by_height.len;
    while (cursor > 0) {
        cursor -= 1;
        const ready = ready_by_height[cursor];
        if (ready == 0) continue;
        const admitted = try policy.readyNodeAdmission(ready);
        if (admitted == 0) return error.InvalidRecursiveLevelScheduler;
        var result = LevelAdmissionV2{
            .height = @intCast(cursor),
            .node_count = try shape.nodeCount(@intCast(cursor)),
            .ready_count = ready,
            .admitted_count = admitted,
            .proof_worker_count_per_node = policy.proof_worker_count,
            .reserved_cpu_tokens = try std.math.mul(
                u64,
                admitted,
                policy.cpu_tokens_per_node,
            ),
            .reserved_rss_bytes = try std.math.mul(
                u64,
                admitted,
                policy.rss_bytes_per_node,
            ),
        };
        try result.validate(shape, policy);
        return result;
    }
    return null;
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or SERIALIZABLE_LEASE)
    {
        @compileError("recursive level scheduler contract drifted");
    }
}
