const std = @import("std");

const subject =
    @import("recursive_temporal_secure_child_composition_v1.zig");
const h1_graph = @import("recursive_temporal_secure_child_h1_graph_v1.zig");
const h1_session_fixture =
    @import("recursive_temporal_secure_child_h1_session_v1_test.zig");
const stwo_core = @import("stwo_core");
const QM31 = stwo_core.fields.qm31.QM31;

test "secure child H1 graph mint plan has exact nonlegacy claim geometry" {
    std.testing.refAllDeclsRecursive(subject);
    std.testing.refAllDeclsRecursive(h1_session_fixture);
    var plan = subject.testing.graphMintPlan(917);
    try plan.validateShape();

    try std.testing.expectEqual(@as(u8, 12), plan.component_count);
    try std.testing.expectEqual(@as(u8, 11), plan.provider_roster_row);
    try std.testing.expectEqual(@as(u8, 12), plan.provider_partial_start);
    try std.testing.expectEqual(@as(u8, 2), plan.provider_partial_count);
    try std.testing.expectEqual(@as(u8, 14), plan.composition_claim_input_count);
    try std.testing.expect(!plan.production_activation);
    try std.testing.expect(!plan.recorder_support_available);
    try std.testing.expectError(
        error.SecureChildH1CompositionRecorderUnavailable,
        plan.requireRecorderSupport(),
    );
}

test "secure child H1 graph mint plan rejects claim geometry mutations" {
    const canonical = subject.testing.graphMintPlan(1_337);

    var provider_row = canonical;
    provider_row.provider_roster_row = 10;
    subject.testing.resealGraphMintPlan(&provider_row);
    try std.testing.expectError(
        error.InvalidSecureChildGraphMintPlan,
        provider_row.validateShape(),
    );

    var partial_start = canonical;
    partial_start.provider_partial_start = 39;
    subject.testing.resealGraphMintPlan(&partial_start);
    try std.testing.expectError(
        error.InvalidSecureChildGraphMintPlan,
        partial_start.validateShape(),
    );

    var claim_count = canonical;
    claim_count.composition_claim_input_count = 41;
    subject.testing.resealGraphMintPlan(&claim_count);
    try std.testing.expectError(
        error.InvalidSecureChildGraphMintPlan,
        claim_count.validateShape(),
    );

    var recorder = canonical;
    recorder.recorder_support_available = true;
    subject.testing.resealGraphMintPlan(&recorder);
    try std.testing.expectError(
        error.InvalidSecureChildGraphMintPlan,
        recorder.validateShape(),
    );
}

test "secure child H1 graph mint plan rejects custody and sample mutations" {
    const canonical = subject.testing.graphMintPlan(2_049);

    var zero_samples = canonical;
    zero_samples.sampled_value_count = 0;
    subject.testing.resealGraphMintPlan(&zero_samples);
    try std.testing.expectError(
        error.InvalidSecureChildGraphMintPlan,
        zero_samples.validateShape(),
    );

    var zero_reconstruction = canonical;
    zero_reconstruction.reconstruction_identity_sha256 = [_]u8{0} ** 32;
    subject.testing.resealGraphMintPlan(&zero_reconstruction);
    try std.testing.expectError(
        error.InvalidSecureChildGraphMintPlan,
        zero_reconstruction.validateShape(),
    );

    var stale_seal = canonical;
    stale_seal.manifest_seal[0] ^= 1;
    try std.testing.expectError(
        error.InvalidSecureChildGraphMintPlan,
        stale_seal.validateShape(),
    );
}

test "secure child H1 claim policy binds 12 physical and two partial claims" {
    std.testing.refAllDeclsRecursive(h1_graph);
    var physical = [_]QM31{felt(0)} ** h1_graph.PHYSICAL_CLAIM_COUNT;
    for (&physical, 0..) |*claim, index| claim.* = felt(index + 10);
    const partials = [h1_graph.PROVIDER_PARTIAL_COUNT]QM31{
        felt(41),
        felt(59),
    };
    physical[11] = partials[0].add(partials[1]);

    const claims = try h1_graph.ClaimInputsV1.init(&physical, &partials);
    try claims.validate();
    for (physical, claims.values[0..h1_graph.PHYSICAL_CLAIM_COUNT]) |
        expected,
        actual,
    | try std.testing.expect(expected.eql(actual));
    try std.testing.expect(
        partials[0].eql(claims.values[h1_graph.PROVIDER_PARTIAL_START]),
    );
    try std.testing.expect(
        partials[1].eql(claims.values[h1_graph.PROVIDER_PARTIAL_START + 1]),
    );
    for (claims.values[h1_graph.SEMANTIC_CLAIM_INPUT_COUNT..]) |claim|
        try std.testing.expect(claim.eql(QM31.zero()));
    try std.testing.expectError(
        error.SecureChildH1ParentProgramSelectorUnavailable,
        h1_graph.requireParentProgramSelector(),
    );
}

test "secure child H1 claim policy rejects provider and unused-slot mutations" {
    var physical = [_]QM31{felt(7)} ** h1_graph.PHYSICAL_CLAIM_COUNT;
    const partials = [h1_graph.PROVIDER_PARTIAL_COUNT]QM31{
        felt(13),
        felt(17),
    };
    try std.testing.expectError(
        error.SecureChildProviderPartialMismatch,
        h1_graph.ClaimInputsV1.init(&physical, &partials),
    );

    physical[11] = partials[0].add(partials[1]);
    const canonical = try h1_graph.ClaimInputsV1.init(&physical, &partials);
    var unused = canonical;
    unused.values[h1_graph.SEMANTIC_CLAIM_INPUT_COUNT] = felt(1);
    try std.testing.expectError(
        error.InvalidSecureChildH1ClaimInputs,
        unused.validate(),
    );

    var stale_partial = canonical;
    stale_partial.values[h1_graph.PROVIDER_PARTIAL_START] = felt(19);
    try std.testing.expectError(
        error.InvalidSecureChildH1ClaimInputs,
        stale_partial.validate(),
    );
}

fn felt(value: usize) QM31 {
    return QM31.fromU32Unchecked(@intCast(value), 0, 0, 0);
}
