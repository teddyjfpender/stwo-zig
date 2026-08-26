const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const subject = @import("recursive_binary_composition_authority.zig");
const outer = @import("recursive_fri_outer.zig");
const test_support = @import("recursive_binary_composition_authority_test_support.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const CirclePointQM31 = stwo_core.circle.CirclePointQM31;
const Sha256 = std.crypto.hash.sha2.Sha256;
const recursion = frontend.recursion;
const admission = recursion.outer_parent_child_admission;
const binary = recursion.binary_fri_outer_source;
const channel = recursion.poseidon2_channel;
const composition = recursion.air.composition_circuit;
const composition_circuit = recursion.recursion_air_composition_circuit;
const fixed_profile = recursion.fixed_profile;
const manifest_mod = recursion.air.universal_adapter_manifest;
const pair_node = recursion.pair_node;
const protocol = recursion.protocol;
const range_bridge = recursion.air.range_check_8_8_bridge;
const recorder = recursion.air.composition_graph_recorder;
const roster = recursion.air.universal_roster;
const universal_manifest = recursion.air.universal_manifest;

const ProofCapture = outer.OuterProofCapture;
const MerklePathCapture = stwo_core.vcs_lifted.verifier.MerklePathCapture(
    recursion.engine.Hasher,
);
const FriLayerCapture = stwo_core.fri.FriLayerQueryCapture(
    recursion.engine.Hasher,
);

const COLUMN_LOG_DEGREE: u32 = 5;
const QUERY_LOG: u32 = COLUMN_LOG_DEGREE + admission.LOG_BLOWUP_FACTOR;
const POSEIDON_LAYOUT_START: u32 = 2;
const CAPTURE_COLUMN_COUNTS = [admission.TREE_COUNT]usize{ 1, 1, 8, 1 };
const CAPTURE_TREE_HEIGHTS = [admission.TREE_COUNT]u32{ 5, 5, 5, 6 };
const Fixture = test_support.Fixture;
const expectRejectedAtomic = test_support.expectRejectedAtomic;
const expectRejectedAtomicWith = test_support.expectRejectedAtomicWith;
const expectRejectedAtomicAtIndex = test_support.expectRejectedAtomicAtIndex;
const buildCircuit = test_support.buildCircuit;
const circuitIdentity = test_support.circuitIdentity;
const hashInteger = test_support.hashInteger;
const buildCapture = test_support.buildCapture;
const testShape = test_support.testShape;
const testStatementWords = test_support.testStatementWords;
const statementId = test_support.statementId;
const qm31Wire = test_support.qm31Wire;
const uniqueSorted = test_support.uniqueSorted;
const lessThan = test_support.lessThan;
const mapTreeQueryPosition = test_support.mapTreeQueryPosition;
const digest = test_support.digest;
const secure = test_support.secure;

test "binary composition bridge publishes one exact verifier-owned authority and remains role neutral" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    var authority: binary.VerifiedChildCompositionAuthority = undefined;
    try subject.publishInto(
        &authority,
        fixture.input_scratch,
        fixture.node_scratch,
        &fixture.publication,
        fixture.profile,
        0,
        fixture.child,
        fixture.shape,
        &fixture.circuit,
    );
    try authority.validateAgainst(fixture.profile, fixture.child, fixture.shape);
    try std.testing.expect(authority.poseidon2_partials[0].eql(
        fixture.publication.poseidon2_partials[0],
    ));
    try std.testing.expect(authority.poseidon2_partials[1].eql(
        fixture.publication.poseidon2_partials[1],
    ));
    try std.testing.expect(authority.poseidon2_roster_total.eql(
        fixture.publication.poseidon2_partials[0].add(
            fixture.publication.poseidon2_partials[1],
        ),
    ));
    try std.testing.expectEqual(
        fixture.circuit.recorded.nodes.len,
        authority.evaluation.values.len,
    );
    try std.testing.expectEqual(@as(usize, 0), subject.HEAP_ALLOCATIONS_PER_PUBLISH);
    try std.testing.expectEqual(
        @as(usize, 2),
        subject.VERIFIED_CAPTURE_VALIDATION_PASSES_PER_PUBLISH,
    );

    var alternate_child = fixture.child;
    alternate_child.role = .poseidon2_provider;
    var alternate: binary.VerifiedChildCompositionAuthority = undefined;
    try subject.publishInto(
        &alternate,
        fixture.input_scratch,
        fixture.node_scratch,
        &fixture.publication,
        fixture.profile,
        0,
        alternate_child,
        fixture.shape,
        &fixture.circuit,
    );
    try std.testing.expectEqual(
        authority.authority_digest,
        alternate.authority_digest,
    );

    var right_child = fixture.child;
    right_child.position = .right;
    var right: binary.VerifiedChildCompositionAuthority = undefined;
    try subject.publishInto(
        &right,
        fixture.input_scratch,
        fixture.node_scratch,
        &fixture.publication,
        fixture.profile,
        1,
        right_child,
        fixture.shape,
        &fixture.circuit,
    );
    try right.validateAgainst(fixture.profile, right_child, fixture.shape);
    try std.testing.expectEqual(@as(u8, 1), right.child_index);
    try std.testing.expectEqual(binary.RIGHT_RECURSION_VERIFIER_ID, right.verifier_id);
}

test "binary composition bridge rejects every verifier-custody mutation atomically" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const original_statement = fixture.publication.statement_words[0];
    fixture.publication.statement_words[0] = M31.zero();
    try expectRejectedAtomic(&fixture);
    fixture.publication.statement_words[0] = original_statement;

    const original_sample = fixture.publication.capture.sampled_values[0];
    fixture.publication.capture.sampled_values[0] = original_sample.add(QM31.one());
    try expectRejectedAtomic(&fixture);
    fixture.publication.capture.sampled_values[0] = original_sample;

    const original_point = fixture.publication.capture.sampled_points[2][0];
    fixture.publication.capture.sampled_points[2][0] = original_point[0..1];
    try expectRejectedAtomic(&fixture);
    fixture.publication.capture.sampled_points[2][0] = original_point;

    fixture.publication.receipt.claimed_sums[0][0] ^= 1;
    try expectRejectedAtomic(&fixture);
    fixture.publication.receipt.claimed_sums[0][0] ^= 1;

    for (0..outer.POSEIDON2_PARTIAL_COUNT) |partial_index| {
        fixture.publication.poseidon2_partials[partial_index] =
            fixture.publication.poseidon2_partials[partial_index].add(QM31.one());
        try expectRejectedAtomic(&fixture);
        fixture.publication.poseidon2_partials[partial_index] =
            fixture.publication.poseidon2_partials[partial_index].sub(QM31.one());
    }

    fixture.publication.relation_replay.pre_relation_channel.digest[0] ^= 1;
    try expectRejectedAtomic(&fixture);
    fixture.publication.relation_replay.pre_relation_channel.digest[0] ^= 1;

    fixture.publication.relation_replay.identity[0] ^= 1;
    try expectRejectedAtomic(&fixture);
    fixture.publication.relation_replay.identity[0] ^= 1;

    fixture.publication.capture.composition_randomness =
        fixture.publication.capture.composition_randomness.add(QM31.one());
    try expectRejectedAtomic(&fixture);
    fixture.publication.capture.composition_randomness =
        fixture.publication.capture.composition_randomness.sub(QM31.one());

    fixture.publication.capture.oods_seed =
        fixture.publication.capture.oods_seed.add(QM31.one());
    try expectRejectedAtomic(&fixture);
    fixture.publication.capture.oods_seed =
        fixture.publication.capture.oods_seed.sub(QM31.one());

    fixture.publication.capture.commitments[2][0] ^= 1;
    try expectRejectedAtomic(&fixture);
    fixture.publication.capture.commitments[2][0] ^= 1;

    var wrong_child = fixture.child;
    wrong_child.position = .right;
    try expectRejectedAtomicWith(
        &fixture,
        fixture.profile,
        wrong_child,
        fixture.shape,
        fixture.input_scratch,
        fixture.node_scratch,
    );
    wrong_child = fixture.child;
    wrong_child.statement_id[0] ^= 1;
    try expectRejectedAtomicWith(
        &fixture,
        fixture.profile,
        wrong_child,
        fixture.shape,
        fixture.input_scratch,
        fixture.node_scratch,
    );
    wrong_child = fixture.child;
    wrong_child.transcript_id[0] ^= 1;
    try expectRejectedAtomicWith(
        &fixture,
        fixture.profile,
        wrong_child,
        fixture.shape,
        fixture.input_scratch,
        fixture.node_scratch,
    );
    wrong_child = fixture.child;
    wrong_child.parent_vk_id[0] ^= 1;
    try expectRejectedAtomicWith(
        &fixture,
        fixture.profile,
        wrong_child,
        fixture.shape,
        fixture.input_scratch,
        fixture.node_scratch,
    );
    wrong_child = fixture.child;
    wrong_child.proof_id[0] ^= 1;
    try expectRejectedAtomicWith(
        &fixture,
        fixture.profile,
        wrong_child,
        fixture.shape,
        fixture.input_scratch,
        fixture.node_scratch,
    );

    try expectRejectedAtomicAtIndex(&fixture, pair_node.CHILD_COUNT);

    var wrong_shape = fixture.shape;
    wrong_shape.air_program_id[0] ^= 1;
    try expectRejectedAtomicWith(
        &fixture,
        fixture.profile,
        fixture.child,
        wrong_shape,
        fixture.input_scratch,
        fixture.node_scratch,
    );
    wrong_shape = fixture.shape;
    wrong_shape.preprocessing_id[0] ^= 1;
    try expectRejectedAtomicWith(
        &fixture,
        fixture.profile,
        fixture.child,
        wrong_shape,
        fixture.input_scratch,
        fixture.node_scratch,
    );
    wrong_shape = fixture.shape;
    wrong_shape.sampled_value_count += 1;
    try expectRejectedAtomicWith(
        &fixture,
        fixture.profile,
        fixture.child,
        wrong_shape,
        fixture.input_scratch,
        fixture.node_scratch,
    );
    wrong_shape = fixture.shape;
    wrong_shape.claimed_sum_count += 1;
    try expectRejectedAtomicWith(
        &fixture,
        fixture.profile,
        fixture.child,
        wrong_shape,
        fixture.input_scratch,
        fixture.node_scratch,
    );
    wrong_shape = fixture.shape;
    wrong_shape.tree_column_counts[1] = 8;
    wrong_shape.tree_column_counts[2] = 1;
    try expectRejectedAtomicWith(
        &fixture,
        fixture.profile,
        fixture.child,
        wrong_shape,
        fixture.input_scratch,
        fixture.node_scratch,
    );

    var wrong_circuit_identity = fixture.circuit.identity_digest;
    wrong_circuit_identity[0] ^= 1;
    const wrong_profile = try binary.TrustedCompositionProfileV1.sealRecorded(
        fixture.publication.receipt.air_program_id,
        fixture.profile.circuit_id,
        wrong_circuit_identity,
        fixture.circuit.recorded.identity_digest,
        fixture.profile.child_proof_kind,
        fixture.circuit.input_profile,
        fixture.circuit.bindings,
        POSEIDON_LAYOUT_START,
    );
    try expectRejectedAtomicWith(
        &fixture,
        wrong_profile,
        fixture.child,
        fixture.shape,
        fixture.input_scratch,
        fixture.node_scratch,
    );

    var wrong_graph_identity = fixture.circuit.recorded.identity_digest;
    wrong_graph_identity[0] ^= 1;
    const wrong_graph_profile = try binary.TrustedCompositionProfileV1.sealRecorded(
        fixture.publication.receipt.air_program_id,
        fixture.profile.circuit_id,
        fixture.circuit.identity_digest,
        wrong_graph_identity,
        fixture.profile.child_proof_kind,
        fixture.circuit.input_profile,
        fixture.circuit.bindings,
        POSEIDON_LAYOUT_START,
    );
    try expectRejectedAtomicWith(
        &fixture,
        wrong_graph_profile,
        fixture.child,
        fixture.shape,
        fixture.input_scratch,
        fixture.node_scratch,
    );

    const wrong_air_profile = try binary.TrustedCompositionProfileV1.sealRecorded(
        digest(1_901),
        fixture.profile.circuit_id,
        fixture.circuit.identity_digest,
        fixture.circuit.recorded.identity_digest,
        fixture.profile.child_proof_kind,
        fixture.circuit.input_profile,
        fixture.circuit.bindings,
        POSEIDON_LAYOUT_START,
    );
    try expectRejectedAtomicWith(
        &fixture,
        wrong_air_profile,
        fixture.child,
        fixture.shape,
        fixture.input_scratch,
        fixture.node_scratch,
    );

    const wrong_layout_profile = try binary.TrustedCompositionProfileV1.sealRecorded(
        fixture.publication.receipt.air_program_id,
        fixture.profile.circuit_id,
        fixture.circuit.identity_digest,
        fixture.circuit.recorded.identity_digest,
        fixture.profile.child_proof_kind,
        fixture.circuit.input_profile,
        fixture.circuit.bindings,
        POSEIDON_LAYOUT_START + 1,
    );
    try expectRejectedAtomicWith(
        &fixture,
        wrong_layout_profile,
        fixture.child,
        fixture.shape,
        fixture.input_scratch,
        fixture.node_scratch,
    );

    fixture.circuit.manifest_seal[0] ^= 1;
    try expectRejectedAtomic(&fixture);
    fixture.circuit.manifest_seal[0] ^= 1;
}

test "binary composition bridge rejects shape and alias hazards before publication" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    try expectRejectedAtomicWith(
        &fixture,
        fixture.profile,
        fixture.child,
        fixture.shape,
        fixture.input_scratch[0 .. fixture.input_scratch.len - 1],
        fixture.node_scratch,
    );
    try expectRejectedAtomicWith(
        &fixture,
        fixture.profile,
        fixture.child,
        fixture.shape,
        fixture.input_scratch,
        fixture.node_scratch[0 .. fixture.node_scratch.len - 1],
    );

    const alias = try std.testing.allocator.alloc(
        QM31,
        fixture.node_scratch.len,
    );
    defer std.testing.allocator.free(alias);
    try expectRejectedAtomicWith(
        &fixture,
        fixture.profile,
        fixture.child,
        fixture.shape,
        alias[0..fixture.input_scratch.len],
        alias,
    );

    comptime {
        if (@sizeOf(outer.VerifiedOuterProofV1) <
            @sizeOf(binary.VerifiedChildCompositionAuthority) or
            @alignOf(outer.VerifiedOuterProofV1) <
                @alignOf(binary.VerifiedChildCompositionAuthority))
        {
            @compileError("verified publication cannot host alias probe");
        }
    }
    const aliased_destination: *binary.VerifiedChildCompositionAuthority =
        @ptrCast(@alignCast(&fixture.publication));
    var before: [@sizeOf(binary.VerifiedChildCompositionAuthority)]u8 = undefined;
    @memcpy(&before, std.mem.asBytes(aliased_destination));
    try std.testing.expectError(
        error.AliasedWorkspace,
        subject.publishInto(
            aliased_destination,
            fixture.input_scratch,
            fixture.node_scratch,
            &fixture.publication,
            fixture.profile,
            0,
            fixture.child,
            fixture.shape,
            &fixture.circuit,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &before,
        std.mem.asBytes(aliased_destination),
    );
}
