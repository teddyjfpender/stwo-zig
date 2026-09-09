const std = @import("std");

const subject = @import("recursive_pipeline_level_scheduler_v2.zig");
const policy_mod = @import("recursive_pipeline_worker_execution_policy_v2.zig");
const shape_mod = @import("recursive_pipeline_campaign_shape_v2.zig");

test "runtime campaign scheduler prefers ready parents and respects dual tokens" {
    const shape = try shape_mod.CampaignShapeAuthorityV2.init(
        sha(1),
        sha(2),
        13,
    );
    const host = try policy_mod.HostExecutionAuthorityV2.init(7, 70_000);
    const policy = try policy_mod.PolicyV2.init(host, .{
        .total_cpu_tokens = 7,
        .cpu_tokens_per_node = 2,
        .proof_worker_count = 2,
        .maximum_parallel_nodes = 3,
        .total_rss_bytes = 60_000,
        .rss_bytes_per_node = 20_000,
    });
    var ready = [_]u32{0} ** 5;
    ready[0] = 11;
    ready[1] = 2;
    const admission = (try subject.selectHighestReadyLevel(
        &shape,
        &policy,
        &ready,
    )).?;
    try admission.validate(&shape, &policy);
    try std.testing.expectEqual(@as(u8, 1), admission.height);
    try std.testing.expectEqual(@as(u16, 2), admission.admitted_count);
    try std.testing.expectEqual(@as(u64, 4), admission.reserved_cpu_tokens);
    try std.testing.expectEqual(@as(u64, 40_000), admission.reserved_rss_bytes);

    ready[1] = 0;
    const leaf_wave = (try subject.selectHighestReadyLevel(
        &shape,
        &policy,
        &ready,
    )).?;
    try std.testing.expectEqual(@as(u8, 0), leaf_wave.height);
    try std.testing.expectEqual(@as(u16, 3), leaf_wave.admitted_count);
    try std.testing.expectEqual(@as(u16, 2), leaf_wave.proof_worker_count_per_node);
}

test "scheduler topology is runtime-derived across depths and host capacities" {
    const shape = try shape_mod.CampaignShapeAuthorityV2.init(
        sha(11),
        sha(12),
        37,
    );
    try std.testing.expectEqual(@as(u8, 6), shape.root_height);
    const host = try policy_mod.HostExecutionAuthorityV2.init(12, 48_000);
    const policy = try policy_mod.PolicyV2.init(host, .{
        .total_cpu_tokens = 12,
        .cpu_tokens_per_node = 3,
        .proof_worker_count = 3,
        .maximum_parallel_nodes = 4,
        .total_rss_bytes = 48_000,
        .rss_bytes_per_node = 12_000,
    });
    var ready = [_]u32{0} ** 7;
    var height: usize = 0;
    var fold_nodes: u32 = 0;
    while (height <= @as(usize, shape.root_height)) : (height += 1) {
        const nodes = try shape.nodeCount(@intCast(height));
        ready[height] = nodes;
        if (height != 0) fold_nodes += nodes;
    }
    try std.testing.expectEqual(shape.fold_count, fold_nodes);
    const root = (try subject.selectHighestReadyLevel(
        &shape,
        &policy,
        &ready,
    )).?;
    try std.testing.expectEqual(shape.root_height, root.height);
    try std.testing.expectEqual(@as(u32, 1), root.node_count);

    ready[shape.root_height] = 0;
    ready[shape.root_height - 1] = 2;
    const parents = (try subject.selectHighestReadyLevel(
        &shape,
        &policy,
        &ready,
    )).?;
    try std.testing.expectEqual(shape.root_height - 1, parents.height);
    try std.testing.expectEqual(@as(u16, 2), parents.admitted_count);

    ready[0] = shape.padded_leaf_count + 1;
    try std.testing.expectError(
        error.InvalidRecursiveLevelScheduler,
        subject.selectHighestReadyLevel(&shape, &policy, &ready),
    );
}

test "scheduler authority and leases have no durable codec" {
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(!subject.SERIALIZABLE_LEASE);
    try std.testing.expect(!@hasDecl(subject.LevelAdmissionV2, "encode"));
    try std.testing.expect(!@hasDecl(policy_mod.PolicyV2, "encode"));
}

fn sha(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index| byte.* = seed +% @as(u8, @intCast(index));
    return result;
}
