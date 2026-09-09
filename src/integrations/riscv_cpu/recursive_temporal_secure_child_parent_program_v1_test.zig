const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const program =
    @import("recursive_temporal_secure_child_parent_program_v1.zig");

const composition_v3 = frontend.recursion.recursion_air_composition_circuit_v3;
const recorder = composition_v3.segment_recorder_v3.graph_recorder;
const QM31 = stwo_core.fields.qm31.QM31;

test "temporal parent descriptor family and policy are append-only" {
    try std.testing.expectEqual(
        @as(u8, 4),
        @intFromEnum(program.MANIFEST_FAMILY),
    );
    try std.testing.expectEqual(
        @as(u8, 6),
        @intFromEnum(program.CLAIM_POLICY),
    );
    const shape = composition_v3.temporalParentDescriptorShape();
    try std.testing.expectEqual(program.MANIFEST_FAMILY, shape.manifest_family);
    try std.testing.expectEqual(program.CLAIM_POLICY, shape.claim_policy);
    try std.testing.expectEqual(@as(u8, 36), shape.source_claim_count);
    try std.testing.expectEqual(@as(u8, 36), shape.program_roster_count);
    try std.testing.expectEqual(@as(u8, 34), shape.poseidon_roster_row);

    try std.testing.expectEqual(
        @as(u8, 1),
        @intFromEnum(composition_v3.ManifestFamilyV3.universal_v1),
    );
    try std.testing.expectEqual(
        @as(u8, 2),
        @intFromEnum(composition_v3.ManifestFamilyV3.segment_v2),
    );
    try std.testing.expectEqual(
        @as(u8, 3),
        @intFromEnum(composition_v3.ManifestFamilyV3.ethereum_poseidon_h1_v1),
    );
    try std.testing.expectEqual(
        @as(u8, 5),
        @intFromEnum(composition_v3.ClaimPolicyV3.ethereum_poseidon_h1),
    );
    try std.testing.expectEqual(
        @as(u8, 1),
        @intFromEnum(composition_v3.ClaimPolicyV3.complete_segment),
    );
    try std.testing.expectEqual(
        @as(u8, 2),
        @intFromEnum(composition_v3.ClaimPolicyV3.universal_with_zero_tail),
    );
    try std.testing.expectEqual(
        @as(u8, 3),
        @intFromEnum(composition_v3.ClaimPolicyV3.canonical_empty),
    );
    try std.testing.expectEqual(
        @as(u8, 4),
        @intFromEnum(composition_v3.ClaimPolicyV3.canonical_empty_provider),
    );
}

test "temporal parent graph policy is selected explicitly" {
    var builder = recorder.Builder.init(std.testing.allocator);
    defer builder.deinit();
    try builder.reserve(
        composition_v3.PROGRAM_KIND_COUNT +
            composition_v3.COMPOSITION_CLAIM_INPUT_COUNT,
        2 * composition_v3.CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT,
    );
    var selectors: [composition_v3.PROGRAM_KIND_COUNT]recorder.Scalar =
        undefined;
    var claims: [composition_v3.COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar =
        undefined;
    for (&selectors) |*value| value.* = (try builder.input()).value;
    for (&claims) |*value| value.* = (try builder.input()).value;
    try builder.activate();
    try std.testing.expectError(
        error.InvalidProgramRoster,
        composition_v3.recordClaimPolicyConstraintsForManifestPolicy(
            &builder,
            &selectors,
            &claims,
            .temporal_parent_v3,
            .universal_with_zero_tail,
        ),
    );
    const recorded = try composition_v3
        .recordClaimPolicyConstraintsForManifestPolicy(
        &builder,
        &selectors,
        &claims,
        .temporal_parent_v3,
        .temporal_parent,
    );
    try std.testing.expectEqual(
        composition_v3.CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT,
        recorded,
    );
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
}

test "temporal parent claim policy rejects family and closure mutations" {
    var inputs = [_]QM31{QM31.zero()} **
        composition_v3.COMPOSITION_CLAIM_INPUT_COUNT;
    try composition_v3.validateClaimInputsForManifestPolicy(
        .binary_node,
        .temporal_parent_v3,
        .temporal_parent,
        &inputs,
    );
    try std.testing.expectError(
        error.InvalidProgramRoster,
        composition_v3.validateClaimInputsForManifestPolicy(
            .binary_node,
            .temporal_parent_v3,
            .universal_with_zero_tail,
            &inputs,
        ),
    );
    try std.testing.expectError(
        error.InvalidProgramRoster,
        composition_v3.validateClaimInputsForManifestPolicy(
            .empty_leaf,
            .temporal_parent_v3,
            .temporal_parent,
            &inputs,
        ),
    );

    inputs[36] = QM31.one();
    try std.testing.expectError(
        error.InactiveClaimInputMustBeZero,
        composition_v3.validateClaimInputsForManifestPolicy(
            .binary_node,
            .temporal_parent_v3,
            .temporal_parent,
            &inputs,
        ),
    );
    inputs[36] = QM31.zero();
    inputs[composition_v3.POSEIDON_AUX_START] = QM31.one();
    try std.testing.expectError(
        error.PoseidonPartialMismatch,
        composition_v3.validateClaimInputsForManifestPolicy(
            .binary_node,
            .temporal_parent_v3,
            .temporal_parent,
            &inputs,
        ),
    );
}
