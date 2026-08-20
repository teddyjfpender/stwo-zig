//! Hostile-parity tests for the recursive-parent transcript source.

const std = @import("std");
const stwo_core = @import("stwo_core");

const admission = @import("outer_parent_child_admission.zig");
const channel = @import("poseidon2_channel.zig");
const engine = @import("engine.zig");
const fixed_wire = @import("fixed_wire.zig");
const pair_node = @import("pair_node.zig");
const protocol = @import("protocol.zig");
const span_statement = @import("span_statement.zig");
const roster = @import("air/universal_roster.zig");
const source = @import("outer_parent_transcript_source.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const ProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(engine.Hasher);
const MerklePathCapture = stwo_core.vcs_lifted.verifier.MerklePathCapture(
    engine.Hasher,
);
const FriLayerCapture = stwo_core.fri.FriLayerQueryCapture(engine.Hasher);

const TEST_COLUMN_LOG: u32 = 5;
const TEST_TREE_HEIGHTS = [admission.TREE_COUNT]u32{ 5, 5, 5, 6 };
pub const TEST_DIMENSIONS = fixed_wire.Dimensions{
    .commitment_count = admission.TREE_COUNT,
    .claimed_sum_count = admission.CLAIMED_SUM_COUNT,
    .sampled_value_count = admission.TREE_COUNT,
    .queried_value_count = admission.TREE_COUNT * admission.QUERY_COUNT,
    .trace_path_count = admission.TREE_COUNT * admission.QUERY_COUNT,
    .fri_layer_count = TEST_COLUMN_LOG,
    .query_count = admission.QUERY_COUNT,
    .maximum_fold_width = 2,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = 6,
};
const Wire = admission.FixedOuterProofWireV1(TEST_DIMENSIONS);
const Bundle = source.ChildBundle(TEST_DIMENSIONS);
const Prepared = source.Prepared(TEST_DIMENSIONS);

const test_support = @import("outer_parent_transcript_source_test_support.zig");
pub const AdmittedChild = test_support.AdmittedChild;
const CaptureFixture = test_support.CaptureFixture;
const honestPairInputs = test_support.honestPairInputs;
pub const childBinding = test_support.childBinding;
const defaultStatement = test_support.defaultStatement;
const statementId = test_support.statementId;
const uniqueSorted = test_support.uniqueSorted;
const lessThan = test_support.lessThan;
const mapTreeQueryPosition = test_support.mapTreeQueryPosition;
pub const digest = test_support.digest;
const secure = test_support.secure;
const qm31 = test_support.qm31;
const poison = test_support.poison;
const expectUnchanged = test_support.expectUnchanged;

test "outer parent transcript source exposes a non-production boundary" {
    try std.testing.expectEqual(
        source.ProductionStatus.verifier_subsystem_only,
        source.CURRENT_STATUS,
    );
    try std.testing.expect(!source.COMPLETE_PARENT_PROOF_VERIFIED);
    try std.testing.expectEqual(@as(usize, 0), source.HEAP_ALLOCATIONS_PER_PREPARE);
    try std.testing.expectEqual(@as(usize, 36), source.CLAIM_ROW_COUNT);
}

test "outer parent transcript source prepares two exact ordered 36-row claims" {
    var left = try AdmittedChild.init(std.testing.allocator, 0, digest(11));
    defer left.deinit();
    var right = try AdmittedChild.init(std.testing.allocator, 1, digest(11));
    defer right.deinit();
    const pair_inputs = try honestPairInputs();
    const request_total = pair_node.SecureFelt{ .limbs = .{ 5, 7, 11, 13 } };
    const left_binding = try childBinding(
        &left,
        pair_inputs,
        0,
        request_total,
    );
    const right_binding = try childBinding(
        &right,
        pair_inputs,
        1,
        request_total.neg(),
    );
    const bundles = [source.CHILD_COUNT]Bundle{
        left.bundle(left_binding),
        right.bundle(right_binding),
    };

    const scratch = try std.testing.allocator.alloc(
        u8,
        admission.serializedByteCount(TEST_DIMENSIONS),
    );
    defer std.testing.allocator.free(scratch);
    var prepared: Prepared = undefined;
    try Prepared.prepareInto(&prepared, scratch, pair_inputs, bundles);
    try prepared.validate();
    try prepared.validateAgainst(scratch, pair_inputs, bundles);

    try std.testing.expect(!prepared.productionReady());
    try std.testing.expectEqual(source.CURRENT_STATUS, prepared.status);
    try std.testing.expectEqual(
        try pair_inputs.context.challengeContextId(),
        prepared.context.challenge_context_id,
    );
    try std.testing.expectEqual(
        try pair_inputs.context.contextId(),
        prepared.context.authority_context_id,
    );
    try std.testing.expectEqual(
        pair_inputs.root_pin.expected_aggregator_vk_id,
        prepared.context.parent_vk_id,
    );

    const admitted_children = [source.CHILD_COUNT]*const AdmittedChild{ &left, &right };
    for (&prepared.children, admitted_children, 0..) |*child, admitted, child_index| {
        try std.testing.expectEqual(
            @as(pair_node.ChildPosition, if (child_index == 0) .left else .right),
            child.position,
        );
        try std.testing.expectEqual(
            @as(pair_node.ChildRole, if (child_index == 0) .core_request else .poseidon2_provider),
            child.role,
        );
        try std.testing.expectEqual(admitted.candidate.proof_id, child.proof_id);
        try std.testing.expectEqual(admitted.candidate.transcript_id, child.transcript_id);
        try std.testing.expect(
            child.verifier_input_boundary.eql(
                qm31(admitted.fixture.receipt.verifier_input_boundary),
            ),
        );
        try std.testing.expectEqual(
            admitted.fixture.receipt.component_log_sizes,
            child.universal.component_log_sizes,
        );
        inline for (0..source.CLAIM_ROW_COUNT) |row| {
            const component: roster.Component = @enumFromInt(row);
            try std.testing.expectEqual(
                admitted.fixture.receipt.component_log_sizes[row],
                child.universal.logSize(component),
            );
            try std.testing.expect(
                child.universal.claimedSum(component).eql(
                    qm31(admitted.fixture.receipt.claimed_sums[row]),
                ),
            );
        }
        try std.testing.expect(
            child.replay.composition_randomness.eql(
                admitted.fixture.capture.composition_randomness,
            ),
        );
        try std.testing.expect(
            child.replay.oods_seed.eql(admitted.fixture.capture.oods_seed),
        );
        try std.testing.expect(
            child.replay.deep_randomness.eql(
                admitted.fixture.capture.deep_randomness,
            ),
        );
        try std.testing.expectEqual(
            @as(u32, TEST_COLUMN_LOG),
            child.replay.fri_round_count,
        );
        for (admitted.fixture.capture.queries.raw, child.replay.raw_queries) |
            captured,
            replayed,
        | try std.testing.expectEqual(captured, replayed);
        try std.testing.expectEqual(
            protocol.transcriptId(
                child.replay.final_digest,
                child.replay.final_draw_count,
            ),
            child.transcript_id,
        );
    }

    try std.testing.expectEqual(@as(usize, 72), prepared.performance.roster_rows);
    try std.testing.expectEqual(@as(usize, 72), prepared.performance.claimed_sum_values);
    try std.testing.expectEqual(@as(usize, 32), prepared.performance.sampled_value_words);
    try std.testing.expectEqual(@as(usize, 10), prepared.performance.fri_rounds);
    try std.testing.expectEqual(@as(usize, 36), prepared.performance.transcript_operations);
    try std.testing.expectEqual(@as(usize, 88), prepared.performance.transcript_state_permutations);
    try std.testing.expectEqual(@as(usize, 8), prepared.performance.pow_candidate_permutations);
    try std.testing.expect(prepared.performance.source_identity_permutations > 0);
    try std.testing.expectEqual(
        @sizeOf(Prepared),
        prepared.performance.retained_witness_bytes,
    );
    try std.testing.expectEqual(@as(usize, 0), prepared.performance.heap_allocations);
}

test "outer parent transcript prepared witness revalidates every retained authority field" {
    var left = try AdmittedChild.init(std.testing.allocator, 0, digest(11));
    defer left.deinit();
    var right = try AdmittedChild.init(std.testing.allocator, 1, digest(11));
    defer right.deinit();
    const pair_inputs = try honestPairInputs();
    const total = pair_node.SecureFelt{ .limbs = .{ 83, 89, 97, 101 } };
    const bundles = [source.CHILD_COUNT]Bundle{
        left.bundle(try childBinding(&left, pair_inputs, 0, total)),
        right.bundle(try childBinding(&right, pair_inputs, 1, total.neg())),
    };
    const scratch = try std.testing.allocator.alloc(
        u8,
        admission.serializedByteCount(TEST_DIMENSIONS),
    );
    defer std.testing.allocator.free(scratch);
    var honest: Prepared = undefined;
    try Prepared.prepareInto(&honest, scratch, pair_inputs, bundles);

    var mutated = honest;
    mutated.performance.roster_rows += 1;
    try std.testing.expectError(error.PreparedWitnessMismatch, mutated.validate());

    mutated = honest;
    mutated.context.challenge_context_id[0] ^= 1;
    try std.testing.expectError(error.ChildBindingMismatch, mutated.validate());

    mutated = honest;
    mutated.children[0].leaf_index += 1;
    try std.testing.expectError(error.ChildBindingMismatch, mutated.validate());

    mutated = honest;
    mutated.children[0].profile_id[0] ^= 1;
    try std.testing.expectError(error.ChildBindingMismatch, mutated.validate());

    mutated = honest;
    mutated.children[0].verifier_input_boundary =
        mutated.children[0].verifier_input_boundary.add(QM31.one());
    try std.testing.expectError(error.PreparedWitnessMismatch, mutated.validate());
}

test "outer parent transcript source rejects swaps and duplicate proofs atomically" {
    var left = try AdmittedChild.init(std.testing.allocator, 0, digest(11));
    defer left.deinit();
    var right = try AdmittedChild.init(std.testing.allocator, 1, digest(11));
    defer right.deinit();
    const pair_inputs = try honestPairInputs();
    const total = pair_node.SecureFelt{ .limbs = .{ 17, 19, 23, 29 } };
    const left_binding = try childBinding(&left, pair_inputs, 0, total);
    const right_binding = try childBinding(&right, pair_inputs, 1, total.neg());
    const scratch = try std.testing.allocator.alloc(
        u8,
        admission.serializedByteCount(TEST_DIMENSIONS),
    );
    defer std.testing.allocator.free(scratch);
    var destination: Prepared = undefined;

    var snapshot = poison(Prepared, &destination, 0xa5);
    try std.testing.expectError(
        error.ChildOrderMismatch,
        Prepared.prepareInto(
            &destination,
            scratch,
            pair_inputs,
            .{ right.bundle(right_binding), left.bundle(left_binding) },
        ),
    );
    try expectUnchanged(Prepared, &destination, &snapshot);

    var duplicate_right = right_binding;
    duplicate_right.statement_id = left.candidate.shape.statement_id;
    snapshot = poison(Prepared, &destination, 0x6b);
    try std.testing.expectError(
        error.DuplicateChild,
        Prepared.prepareInto(
            &destination,
            scratch,
            pair_inputs,
            .{ left.bundle(left_binding), left.bundle(duplicate_right) },
        ),
    );
    try expectUnchanged(Prepared, &destination, &snapshot);
}

test "outer parent transcript source rejects cross-profile session and VK substitutions" {
    var left = try AdmittedChild.init(std.testing.allocator, 0, digest(11));
    defer left.deinit();
    var right = try AdmittedChild.init(std.testing.allocator, 1, digest(11));
    defer right.deinit();
    var cross_profile = try AdmittedChild.init(
        std.testing.allocator,
        2,
        digest(12),
    );
    defer cross_profile.deinit();
    const pair_inputs = try honestPairInputs();
    const total = pair_node.SecureFelt{ .limbs = .{ 31, 37, 41, 43 } };
    const left_binding = try childBinding(&left, pair_inputs, 0, total);
    var right_binding = try childBinding(
        &right,
        pair_inputs,
        1,
        total.neg(),
    );
    const cross_binding = try childBinding(
        &cross_profile,
        pair_inputs,
        1,
        total.neg(),
    );
    const scratch = try std.testing.allocator.alloc(
        u8,
        admission.serializedByteCount(TEST_DIMENSIONS),
    );
    defer std.testing.allocator.free(scratch);
    var destination: Prepared = undefined;

    var snapshot = poison(Prepared, &destination, 0xd1);
    try std.testing.expectError(
        error.ChildProfileMismatch,
        Prepared.prepareInto(
            &destination,
            scratch,
            pair_inputs,
            .{ left.bundle(left_binding), cross_profile.bundle(cross_binding) },
        ),
    );
    try expectUnchanged(Prepared, &destination, &snapshot);

    right_binding.session_id[0] ^= 1;
    snapshot = poison(Prepared, &destination, 0xd2);
    try std.testing.expectError(
        error.ChildBindingMismatch,
        Prepared.prepareInto(
            &destination,
            scratch,
            pair_inputs,
            .{ left.bundle(left_binding), right.bundle(right_binding) },
        ),
    );
    try expectUnchanged(Prepared, &destination, &snapshot);
    right_binding.session_id[0] ^= 1;

    right_binding.parent_vk_id[0] ^= 1;
    snapshot = poison(Prepared, &destination, 0xd3);
    try std.testing.expectError(
        error.ChildBindingMismatch,
        Prepared.prepareInto(
            &destination,
            scratch,
            pair_inputs,
            .{ left.bundle(left_binding), right.bundle(right_binding) },
        ),
    );
    try expectUnchanged(Prepared, &destination, &snapshot);
}

test "outer parent transcript source rejects seal capture and transcript-wire mutations atomically" {
    var left = try AdmittedChild.init(std.testing.allocator, 0, digest(11));
    defer left.deinit();
    var right = try AdmittedChild.init(std.testing.allocator, 1, digest(11));
    defer right.deinit();
    const pair_inputs = try honestPairInputs();
    const total = pair_node.SecureFelt{ .limbs = .{ 47, 53, 59, 61 } };
    const left_binding = try childBinding(&left, pair_inputs, 0, total);
    const right_binding = try childBinding(&right, pair_inputs, 1, total.neg());
    const scratch = try std.testing.allocator.alloc(
        u8,
        admission.serializedByteCount(TEST_DIMENSIONS),
    );
    defer std.testing.allocator.free(scratch);
    var destination: Prepared = undefined;

    var hostile_seal = right.seal;
    hostile_seal.receipt_id[0] ^= 1;
    var snapshot = poison(Prepared, &destination, 0xe1);
    try std.testing.expectError(
        error.BundleSealMismatch,
        Prepared.prepareInto(
            &destination,
            scratch,
            pair_inputs,
            .{
                left.bundle(left_binding),
                right.bundleWithSeal(right_binding, hostile_seal),
            },
        ),
    );
    try expectUnchanged(Prepared, &destination, &snapshot);

    const composition = right.fixture.capture.composition_randomness;
    right.fixture.capture.composition_randomness = composition.add(QM31.one());
    snapshot = poison(Prepared, &destination, 0xe2);
    try std.testing.expectError(
        error.TranscriptMismatch,
        Prepared.prepareInto(
            &destination,
            scratch,
            pair_inputs,
            .{ left.bundle(left_binding), right.bundle(right_binding) },
        ),
    );
    try expectUnchanged(Prepared, &destination, &snapshot);
    right.fixture.capture.composition_randomness = composition;

    right.wire.payload.sampled_values[0][0] += 1;
    snapshot = poison(Prepared, &destination, 0xe3);
    try std.testing.expectError(
        error.WireHeaderMismatch,
        Prepared.prepareInto(
            &destination,
            scratch,
            pair_inputs,
            .{ left.bundle(left_binding), right.bundle(right_binding) },
        ),
    );
    try expectUnchanged(Prepared, &destination, &snapshot);
    right.wire.payload.sampled_values[0][0] -= 1;

    const statement_tag = right.statement_words[span_statement.canonical_layout.body_tag];
    right.statement_words[span_statement.canonical_layout.body_tag] = M31.zero();
    snapshot = poison(Prepared, &destination, 0xe4);
    try std.testing.expectError(
        error.CanonicalTagMismatch,
        Prepared.prepareInto(
            &destination,
            scratch,
            pair_inputs,
            .{ left.bundle(left_binding), right.bundle(right_binding) },
        ),
    );
    try expectUnchanged(Prepared, &destination, &snapshot);
    right.statement_words[span_statement.canonical_layout.body_tag] = statement_tag;
}

test "outer parent transcript source rejects an aliased workspace before mutation" {
    var left = try AdmittedChild.init(std.testing.allocator, 0, digest(11));
    defer left.deinit();
    var right = try AdmittedChild.init(std.testing.allocator, 1, digest(11));
    defer right.deinit();
    const pair_inputs = try honestPairInputs();
    const total = pair_node.SecureFelt{ .limbs = .{ 67, 71, 73, 79 } };
    const left_binding = try childBinding(&left, pair_inputs, 0, total);
    const right_binding = try childBinding(&right, pair_inputs, 1, total.neg());
    const scratch_len = admission.serializedByteCount(TEST_DIMENSIONS);
    const allocation_len = @sizeOf(Prepared) + scratch_len;
    const backing = try std.testing.allocator.alignedAlloc(
        u8,
        .of(Prepared),
        allocation_len,
    );
    defer std.testing.allocator.free(backing);
    const destination: *Prepared = @ptrCast(backing.ptr);
    const scratch = backing[1 .. 1 + scratch_len];
    const snapshot = poison(Prepared, destination, 0xf1);

    try std.testing.expectError(
        error.AliasedWorkspace,
        Prepared.prepareInto(
            destination,
            scratch,
            pair_inputs,
            .{ left.bundle(left_binding), right.bundle(right_binding) },
        ),
    );
    try expectUnchanged(Prepared, destination, &snapshot);

    const ordinary_scratch = try std.testing.allocator.alloc(u8, scratch_len);
    defer std.testing.allocator.free(ordinary_scratch);
    var honest: Prepared = undefined;
    const bundles = [source.CHILD_COUNT]Bundle{
        left.bundle(left_binding),
        right.bundle(right_binding),
    };
    try Prepared.prepareInto(
        &honest,
        ordinary_scratch,
        pair_inputs,
        bundles,
    );
    destination.* = honest;
    const validation_snapshot = std.mem.asBytes(destination)[0..@sizeOf(Prepared)].*;
    try std.testing.expectError(
        error.AliasedWorkspace,
        destination.validateAgainst(scratch, pair_inputs, bundles),
    );
    try expectUnchanged(Prepared, destination, &validation_snapshot);
}
