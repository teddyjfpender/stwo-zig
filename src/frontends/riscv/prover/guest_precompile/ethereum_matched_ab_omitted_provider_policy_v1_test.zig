const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const policy = @import("ethereum_matched_ab_omitted_provider_policy_v1.zig");
const matched_execution = @import("ethereum_leaf_matched_ab_execution_profile_v1.zig");
const d5_authority = @import("../memory_provider_shards/degree5_ethereum_omit_provider_authority_v1.zig");
const omit_protocol = @import("../memory_provider_shards/ethereum_omit_protocol_v1.zig");
const joint_proof_authority = @import("../memory_provider_shards/joint_proof_authority.zig");

fn testSnapshot() policy.GeometrySnapshot {
    const Holder = struct {
        var tree0 = [_]u32{ 6, 5 };
        var tree1 = [_]u32{ 7, 6, 5 };
        var tree2 = [_]u32{ 7, 5 };
    };
    return .{
        .allocator = undefined,
        .tree0_log_sizes = Holder.tree0[0..],
        .tree1_non_candidate_log_sizes = Holder.tree1[0..],
        .tree2_log_sizes = Holder.tree2[0..],
        .legacy_poseidon = .{
            .infra_index = 3,
            .main_column_offset = 900,
            .main_column_count = 445,
            .log_size = 24,
            .n_rows = 8_572_350,
        },
        .degree5 = undefined,
        .degree6 = undefined,
    };
}

fn testCallAuthority(
    calls: []poseidon2_air.Call,
) policy.ProviderCallAuthorityV1 {
    return .{
        .allocator = std.testing.allocator,
        .calls = calls,
        .public_data_wire_id = [_]u32{0x51515151} ** 8,
    };
}

test "omitted core estimate excludes the exact log24 legacy provider" {
    const snapshot = testSnapshot();
    const execution = matched_execution.Authority.canonical();
    const estimate = try policy.estimateOmittedCoreV1(&snapshot, execution);
    try estimate.validateAgainst(&snapshot, execution);
    try estimate.requireWithinMatchedBudget();
    try std.testing.expectEqual(
        @as(u64, 3),
        estimate.tree1_non_provider.column_count,
    );
    try std.testing.expectEqual(@as(u64, 8), estimate.composition.column_count);
    try std.testing.expectEqual(@as(u32, 24), estimate.legacy_provider_log_size);
    try std.testing.expect(
        estimate.staged_peak_lower_bound_bytes < policy.host_byte_budget,
    );

    var mutated_snapshot = snapshot;
    mutated_snapshot.legacy_poseidon.main_column_count = 444;
    try std.testing.expectError(
        error.InvalidMatchedAbOmittedCoreGeometry,
        policy.estimateOmittedCoreV1(&mutated_snapshot, execution),
    );

    const original_tree1 = snapshot.tree1_non_candidate_log_sizes[0];
    snapshot.tree1_non_candidate_log_sizes[0] += 1;
    defer snapshot.tree1_non_candidate_log_sizes[0] = original_tree1;
    try std.testing.expectError(
        error.MatchedAbOmittedCoreEstimateMismatch,
        estimate.validateAgainst(&snapshot, execution),
    );
}

test "call authority and max-log20 provider plan are reconstructed" {
    var calls: [17]poseidon2_air.Call = undefined;
    for (&calls, 0..) |*call, index| call.* =
        poseidon2_air.Call.narrowWithOutput(
            @intCast(index + 1),
            @intCast(index + 2),
            @intCast(index + 3),
        );
    var source = testCallAuthority(calls[0..]);
    const call_identity = try policy.CallAuthorityIdentityV1.canonical(&source);
    try call_identity.validateAgainst(&source);
    const execution = matched_execution.Authority.canonical();
    var owned = try policy.OwnedProviderPlanAdmissionV1.create(
        std.testing.allocator,
        [_]u8{0xa5} ** 32,
        &source,
        execution,
    );
    defer owned.deinit();
    try owned.validateAgainst(&source, execution);
    try std.testing.expectEqual(
        policy.provider_shard_log_size,
        owned.plan.residency.result.shard_log_size,
    );
    try std.testing.expectEqual(@as(u32, 1), owned.plan.shard_count);
    try std.testing.expectEqual(
        policy.provider_retention_policy,
        owned.plan.residency.request.retention_policy,
    );
    try std.testing.expect(
        owned.admission.resource.admitted_peak_bytes < policy.host_byte_budget,
    );

    var mutated_worker = owned.admission;
    mutated_worker.provider_execution.engine_workers_per_owner = 2;
    try std.testing.expectError(
        error.InvalidMatchedAbProviderPlanAdmission,
        mutated_worker.validate(),
    );
    var mutated_resource = owned.admission;
    mutated_resource.resource.admitted_peak_bytes += 1;
    try std.testing.expectError(
        error.InvalidMatchedAbProviderResourceEstimate,
        mutated_resource.validate(),
    );

    source.calls[0].narrow_output.? += 1;
    defer source.calls[0].narrow_output.? -= 1;
    try std.testing.expectError(
        error.MatchedAbProviderCallAuthorityMismatch,
        call_identity.validateAgainst(&source),
    );
    try std.testing.expectError(
        error.GlobalCallCommitmentMismatch,
        owned.validateAgainst(&source, execution),
    );
}

test "fresh closure admission requires genuine plan strategy and zero closure" {
    var calls = [_]poseidon2_air.Call{
        poseidon2_air.Call.narrowWithOutput(1, 2, 3),
    };
    const source = testCallAuthority(calls[0..]);
    const execution = matched_execution.Authority.canonical();
    var owned = try policy.OwnedProviderPlanAdmissionV1.create(
        std.testing.allocator,
        [_]u8{0xb4} ** 32,
        &source,
        execution,
    );
    defer owned.deinit();
    const snapshot = testSnapshot();
    const core = try policy.estimateOmittedCoreV1(&snapshot, execution);

    var closure = omit_protocol.VerifiedJointClosureV1{
        .format = joint_proof_authority.provider_format_version_v2,
        .plan_identity = owned.plan.identity,
        .manifest_identity = [_]u8{0x61} ** 32,
        .relation_context_identity = [_]u8{0x62} ** 32,
        .core_claim_identity = [_]u8{0x63} ** 32,
        .ordered_provider_claims_identity = [_]u8{0x64} ** 32,
        .shard_count = owned.plan.shard_count,
        .core_claim = QM31.zero(),
        .provider_claim = QM31.zero(),
        .closed_sum = QM31.zero(),
        .core_freshly_verified = true,
        .every_provider_freshly_verified = true,
        .every_ordered_call_air_verified = true,
        .complete_ordered_coverage = true,
        .one_shared_relation_context = true,
        .omit_recompute_owner_verified = true,
        .production_eligible = false,
        .recursive_admissible = false,
        .identity = undefined,
    };
    closure.identity = omit_protocol.closureIdentity(closure);
    var strategy = d5_authority.FreshStrategyV1{
        .format = d5_authority.format_version,
        .air_program_identity = [_]u8{0x71} ** 32,
        .execution_profile_identity = [_]u8{0x72} ** 32,
        .plan_identity = owned.plan.identity,
        .manifest_identity = closure.manifest_identity,
        .preprocessed_commitment_identity = [_]u8{0x73} ** 32,
        .relation_context_identity = closure.relation_context_identity,
        .closure_identity = closure.identity,
        .ordered_provider_claims_identity = closure.ordered_provider_claims_identity,
        .shard_count = closure.shard_count,
        .every_provider_degree5_fresh_verified = true,
        .shared_core_zero_sum_verified = true,
        .production_eligible = false,
        .identity = undefined,
    };
    strategy.identity = d5_authority.strategyIdentity(strategy);
    const admission = try policy.FreshClosureAdmissionV1.canonical(
        &core,
        &owned.admission,
        strategy,
        closure,
    );
    try admission.validateAgainst(&core, &owned.admission);

    var mismatched_strategy = strategy;
    mismatched_strategy.manifest_identity[0] ^= 1;
    mismatched_strategy.identity = d5_authority.strategyIdentity(
        mismatched_strategy,
    );
    try std.testing.expectError(
        error.InvalidMatchedAbFreshClosureAdmission,
        policy.FreshClosureAdmissionV1.canonical(
            &core,
            &owned.admission,
            mismatched_strategy,
            closure,
        ),
    );

    var nonzero_closure = closure;
    nonzero_closure.closed_sum = QM31.one();
    nonzero_closure.identity = omit_protocol.closureIdentity(nonzero_closure);
    try std.testing.expectError(
        error.InvalidEthereumProviderJointClosure,
        policy.FreshClosureAdmissionV1.canonical(
            &core,
            &owned.admission,
            strategy,
            nonzero_closure,
        ),
    );
}
