const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const subject = @import("recursive_pipeline_worker_execution_policy_v2.zig");

test "execution policy saturates configurable cores under both token caps" {
    const host = try subject.HostExecutionAuthorityV2.init(
        18,
        32 * 1024 * 1024 * 1024,
    );
    const eighteen = try subject.PolicyV2.init(host, .{
        .total_cpu_tokens = 18,
        .cpu_tokens_per_node = 9,
        .proof_worker_count = 9,
        .maximum_parallel_nodes = 2,
        .total_rss_bytes = 32 * 1024 * 1024 * 1024,
        .rss_bytes_per_node = 16 * 1024 * 1024 * 1024,
    });
    try std.testing.expectEqual(@as(usize, 9), eighteen.engineWorkerCount());
    try std.testing.expectEqual(@as(u16, 2), eighteen.tokenCapacity());
    try std.testing.expectEqual(@as(u16, 2), eighteen.readyNodeAdmission(64));

    const one_node = try subject.PolicyV2.init(host, .{
        .total_cpu_tokens = 18,
        .cpu_tokens_per_node = 18,
        .proof_worker_count = 18,
        .maximum_parallel_nodes = 1,
        .total_rss_bytes = 32 * 1024 * 1024 * 1024,
        .rss_bytes_per_node = 16 * 1024 * 1024 * 1024,
    });
    try std.testing.expectEqual(@as(usize, 18), one_node.engineWorkerCount());
    try std.testing.expectEqual(@as(u16, 1), one_node.readyNodeAdmission(64));
}

test "execution policy is execution-key-bound and rejects oversubscription" {
    const host = try subject.HostExecutionAuthorityV2.init(7, 30_000);
    const policy = try subject.PolicyV2.init(host, .{
        .total_cpu_tokens = 7,
        .cpu_tokens_per_node = 2,
        .proof_worker_count = 2,
        .maximum_parallel_nodes = 3,
        .total_rss_bytes = 30_000,
        .rss_bytes_per_node = 10_000,
    });
    const execution = try artifact_store.ExecutionKeyV1.create(.{
        .semantic_key_identity = digest(1),
        .producer_identity = digest(2),
        .verifier_identity = digest(3),
        .source_identity = digest(4),
        .build_identity = digest(5),
        .executable_identity = digest(6),
        .toolchain_identity = digest(7),
        .backend_identity = digest(8),
        .optimization_identity = digest(9),
        .worker_policy_identity = policy.worker_policy_identity,
        .memory_policy_identity = policy.memory_policy_identity,
        .retention_policy_identity = digest(10),
        .timeout_policy_identity = digest(11),
    });
    try policy.validateAgainstExecution(execution);
    var wrong = execution;
    wrong.fields.worker_policy_identity[0] ^= 1;
    wrong = try artifact_store.ExecutionKeyV1.create(wrong.fields);
    try std.testing.expectError(
        error.RecursiveExecutionPolicyMismatch,
        policy.validateAgainstExecution(wrong),
    );
    try std.testing.expectError(
        error.InvalidRecursiveExecutionPolicy,
        subject.PolicyV2.init(host, .{
            .total_cpu_tokens = 7,
            .cpu_tokens_per_node = 3,
            .proof_worker_count = 4,
            .maximum_parallel_nodes = 2,
            .total_rss_bytes = 30_000,
            .rss_bytes_per_node = 10_000,
        }),
    );
    const large_host = try subject.HostExecutionAuthorityV2.init(
        subject.MAX_PROOF_WORKERS + 1,
        100_000,
    );
    try std.testing.expectError(
        error.InvalidRecursiveExecutionPolicy,
        subject.PolicyV2.init(large_host, .{
            .total_cpu_tokens = @intCast(subject.MAX_PROOF_WORKERS + 1),
            .cpu_tokens_per_node = @intCast(subject.MAX_PROOF_WORKERS + 1),
            .proof_worker_count = @intCast(subject.MAX_PROOF_WORKERS + 1),
            .maximum_parallel_nodes = 1,
            .total_rss_bytes = 100_000,
            .rss_bytes_per_node = 100_000,
        }),
    );
}

fn digest(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index| byte.* = seed +% @as(u8, @intCast(index));
    return result;
}
