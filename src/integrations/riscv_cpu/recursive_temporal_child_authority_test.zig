const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const subject = @import("recursive_temporal_child_authority.zig");
const outer = @import("recursive_fri_outer.zig");
const test_support = @import("recursive_temporal_child_authority_test_support.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const CirclePointQM31 = stwo_core.circle.CirclePointQM31;
const recursion = frontend.recursion;
const admission = recursion.outer_parent_child_admission;
const channel = recursion.poseidon2_channel;
const protocol = recursion.protocol;
const range_bridge = recursion.air.range_check_8_8_bridge;
const roster = recursion.air.universal_roster;
const temporal = recursion.temporal_pair_node;
const universal_manifest = recursion.air.universal_manifest;
const global_closure = recursion.binary_global_closure_outer_source;
const RelationDomain = @TypeOf(
    @as(global_closure.DomainClaimV1, undefined).domain,
);

const ProofCapture = outer.OuterProofCapture;
const MerklePathCapture = stwo_core.vcs_lifted.verifier.MerklePathCapture(
    recursion.engine.Hasher,
);
const FriLayerCapture = stwo_core.fri.FriLayerQueryCapture(
    recursion.engine.Hasher,
);

const COLUMN_LOG_DEGREE: u32 = 4;
const QUERY_LOG: u32 = COLUMN_LOG_DEGREE + admission.LOG_BLOWUP_FACTOR;
const TREE_HEIGHT: u32 = QUERY_LOG;
const DIMENSIONS = recursion.fixed_wire.Dimensions{
    .commitment_count = admission.TREE_COUNT,
    .claimed_sum_count = admission.CLAIMED_SUM_COUNT,
    .sampled_value_count = admission.TREE_COUNT,
    .queried_value_count = admission.TREE_COUNT * admission.QUERY_COUNT,
    .trace_path_count = admission.TREE_COUNT * admission.QUERY_COUNT,
    .fri_layer_count = COLUMN_LOG_DEGREE,
    .query_count = admission.QUERY_COUNT,
    .maximum_fold_width = 2,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = TREE_HEIGHT,
};
const Wire = admission.FixedOuterProofWireV1(DIMENSIONS);
const ClosureFixtureV2 = test_support.ClosureFixtureV2;
const emptyClosureRow = test_support.emptyClosureRow;
const setClosureDomain = test_support.setClosureDomain;
const recomputeClosureRow = test_support.recomputeClosureRow;
const expectClosurePreflightRejectedAtomic = test_support.expectClosurePreflightRejectedAtomic;
const expectClosurePreflightErrorAtomic = test_support.expectClosurePreflightErrorAtomic;
const testQm31 = test_support.testQm31;
const shaDigest = test_support.shaDigest;
const Fixture = test_support.Fixture;
const expectInspectionRejectedAtomic = test_support.expectInspectionRejectedAtomic;
const buildCapture = test_support.buildCapture;
const testStatementWords = test_support.testStatementWords;
const statementId = test_support.statementId;
const uniqueSorted = test_support.uniqueSorted;
const lessThan = test_support.lessThan;
const mapTreeQueryPosition = test_support.mapTreeQueryPosition;
const digest = test_support.digest;
const digestIsZero = test_support.digestIsZero;
const secure = test_support.secure;

test "temporal child bridge publishes an explicit fail-closed capability ledger" {
    try std.testing.expect(!subject.CURRENT_CAPABILITIES.ready());
    try std.testing.expect(subject.CURRENT_CAPABILITIES.verified_outer_publication);
    try std.testing.expect(subject.CURRENT_CAPABILITIES.canonical_wire_admission);
    try std.testing.expect(subject.CURRENT_CAPABILITIES.statement_binding);
    try std.testing.expect(subject.CURRENT_CAPABILITIES.job_derivation);
    try std.testing.expect(subject.CURRENT_CAPABILITIES.whole_roster_closure);
    try std.testing.expect(
        !subject.CURRENT_CAPABILITIES.complete_parent_prover_and_verifier,
    );
    try std.testing.expect(
        subject.CURRENT_CAPABILITIES.statement_version_transcript_binding,
    );
    try std.testing.expect(
        subject.CURRENT_CAPABILITIES.child_position_context_binding,
    );
    try std.testing.expect(!subject.CURRENT_CAPABILITIES.session_context_binding);
    try std.testing.expect(
        !subject.CURRENT_CAPABILITIES.recursive_parent_vk_context_binding,
    );
    try std.testing.expect(!subject.CURRENT_CAPABILITIES.lineage_context_binding);
    try std.testing.expect(
        subject.CURRENT_CAPABILITIES.closure_receipt_v2_preflight,
    );
    try std.testing.expect(
        !subject.CURRENT_CAPABILITIES.closure_receipt_v2_verifier_custody,
    );
    try std.testing.expect(
        !subject.CURRENT_CAPABILITIES.native_temporal_digest_publication,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        subject.HEAP_ALLOCATIONS_PER_INSPECT,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        subject.HEAP_ALLOCATIONS_PER_PUBLISH,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        subject.CAPTURE_VALIDATION_PASSES_PER_INSPECT,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        subject.HEAP_ALLOCATIONS_PER_CLOSURE_PREFLIGHT,
    );
    try std.testing.expectEqual(
        @as(usize, 32),
        subject.GLOBAL_CLOSURE_DIGEST_BYTE_COUNT,
    );
    try std.testing.expectEqual(
        channel.RATE,
        subject.NATIVE_TEMPORAL_DIGEST_WORD_COUNT,
    );
    const zero_digest: channel.Digest = [_]u32{0} ** channel.RATE;
    const required = subject.RequiredContextV2{
        .statement_version = 1,
        .session_id = zero_digest,
        .recursive_parent_vk_id = zero_digest,
        .lineage_id = zero_digest,
        .statement_id = zero_digest,
        .authenticated_context_id = zero_digest,
    };
    try std.testing.expectEqual(@as(u16, 2), required.format_version);
}

test "closure V2 preflight retains native SHA metadata without temporal custody" {
    const closure_fixture = try ClosureFixtureV2.init();
    var workspace = global_closure.Workspace.init();
    var receipt = global_closure.ClosureReceiptV2.fresh();
    try global_closure.fillIntoV2(
        &workspace,
        &closure_fixture.prepared,
        &closure_fixture.input,
        &receipt,
    );

    var preflight: subject.ClosureReceiptPreflightV2 = undefined;
    try subject.preflightClosureReceiptV2Into(&preflight, &receipt);
    try std.testing.expectEqual(
        subject.CLOSURE_PREFLIGHT_FORMAT_VERSION,
        preflight.format_version,
    );
    try std.testing.expect(!preflight.verifier_custody);
    try std.testing.expect(!preflight.temporal_context_available);
    try std.testing.expect(!preflight.temporalPublicationReady());
    try std.testing.expectEqual(receipt.source_authority_id, preflight.source_authority_id);
    try std.testing.expectEqual(receipt.input_id, preflight.input_id);
    try std.testing.expectEqual(receipt.closure_id, preflight.closure_id);
    try std.testing.expectEqual(
        receipt.context_seam.identity,
        preflight.context_seam_id,
    );
    try std.testing.expectEqual(
        receipt.public_boundaries.wire.snapshot_id,
        preflight.wire_snapshot_id,
    );
    try std.testing.expectEqual(
        receipt.public_boundaries.wire.tuple_provenance_id,
        preflight.wire_tuple_provenance_id,
    );
    try std.testing.expectEqual(
        receipt.public_boundaries.verifier_input.snapshot_id,
        preflight.verifier_input_snapshot_id,
    );
    try std.testing.expectEqual(
        receipt.public_boundaries.verifier_input.tuple_provenance_id,
        preflight.verifier_input_tuple_provenance_id,
    );
}

test "closure V2 preflight rejects context and provenance mutation fleet atomically" {
    const closure_fixture = try ClosureFixtureV2.init();
    var workspace = global_closure.Workspace.init();
    var receipt = global_closure.ClosureReceiptV2.fresh();
    try global_closure.fillIntoV2(
        &workspace,
        &closure_fixture.prepared,
        &closure_fixture.input,
        &receipt,
    );

    var changed = receipt;
    changed.source_authority_id[0] ^= 1;
    try expectClosurePreflightRejectedAtomic(&changed);

    changed = receipt;
    changed.closure_id[0] ^= 1;
    try expectClosurePreflightRejectedAtomic(&changed);

    changed = receipt;
    changed.public_boundaries.wire.source_authority_id[0] ^= 1;
    try expectClosurePreflightRejectedAtomic(&changed);

    changed = receipt;
    changed.public_boundaries.wire.snapshot_id[0] ^= 1;
    try expectClosurePreflightRejectedAtomic(&changed);

    changed = receipt;
    changed.public_boundaries.wire.tuple_provenance_id[0] ^= 1;
    try expectClosurePreflightRejectedAtomic(&changed);

    changed = receipt;
    changed.public_boundaries.verifier_input.source_authority_id[0] ^= 1;
    try expectClosurePreflightRejectedAtomic(&changed);

    changed = receipt;
    changed.public_boundaries.verifier_input.snapshot_id[0] ^= 1;
    try expectClosurePreflightRejectedAtomic(&changed);

    changed = receipt;
    changed.public_boundaries.verifier_input.tuple_provenance_id[0] ^= 1;
    try expectClosurePreflightRejectedAtomic(&changed);

    changed = receipt;
    changed.context_seam.identity[0] ^= 1;
    try expectClosurePreflightRejectedAtomic(&changed);

    changed = receipt;
    changed.context_seam.required.statement_version =
        protocol.LEAF_STATEMENT_VERSION;
    changed.context_seam.identity = changed.context_seam.identityDigest();
    try expectClosurePreflightErrorAtomic(
        error.UnavailableContextNotZero,
        &changed,
    );

    changed = receipt;
    changed.context_seam.required.session_id = shaDigest("mutated-session");
    changed.context_seam.identity = changed.context_seam.identityDigest();
    try expectClosurePreflightErrorAtomic(
        error.UnavailableContextNotZero,
        &changed,
    );

    changed = receipt;
    changed.context_seam.required.parent_vk_id = shaDigest("mutated-parent-vk");
    changed.context_seam.identity = changed.context_seam.identityDigest();
    try expectClosurePreflightErrorAtomic(
        error.UnavailableContextNotZero,
        &changed,
    );

    changed = receipt;
    changed.context_seam.required.statement_id = shaDigest("mutated-statement");
    changed.context_seam.identity = changed.context_seam.identityDigest();
    try expectClosurePreflightErrorAtomic(
        error.UnavailableContextNotZero,
        &changed,
    );

    changed = receipt;
    changed.context_seam.required.lineage_id = shaDigest("mutated-lineage");
    changed.context_seam.identity = changed.context_seam.identityDigest();
    try expectClosurePreflightErrorAtomic(
        error.UnavailableContextNotZero,
        &changed,
    );

    changed = receipt;
    changed.context_seam.required.authenticated_context_id =
        shaDigest("mutated-context-id");
    changed.context_seam.identity = changed.context_seam.identityDigest();
    try expectClosurePreflightErrorAtomic(
        error.UnavailableContextNotZero,
        &changed,
    );
}

test "closure V2 preflight rejects an aliased destination before validation" {
    const closure_fixture = try ClosureFixtureV2.init();
    var workspace = global_closure.Workspace.init();
    var receipt = global_closure.ClosureReceiptV2.fresh();
    try global_closure.fillIntoV2(
        &workspace,
        &closure_fixture.prepared,
        &closure_fixture.input,
        &receipt,
    );
    comptime std.debug.assert(
        @sizeOf(global_closure.ClosureReceiptV2) >=
            @sizeOf(subject.ClosureReceiptPreflightV2),
    );
    comptime std.debug.assert(
        @alignOf(global_closure.ClosureReceiptV2) >=
            @alignOf(subject.ClosureReceiptPreflightV2),
    );
    const before = receipt;
    const destination: *subject.ClosureReceiptPreflightV2 = @ptrCast(
        @alignCast(&receipt),
    );
    try std.testing.expectError(
        error.AliasedWorkspace,
        subject.preflightClosureReceiptV2Into(destination, &receipt),
    );
    try std.testing.expectEqualDeep(before, receipt);
}

test "raw closure V2 can never mint a temporal child" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const closure_fixture = try ClosureFixtureV2.init();
    var workspace = global_closure.Workspace.init();
    var receipt = global_closure.ClosureReceiptV2.fresh();
    try global_closure.fillIntoV2(
        &workspace,
        &closure_fixture.prepared,
        &closure_fixture.input,
        &receipt,
    );

    var destination: temporal.VerifiedChildV2 = undefined;
    @memset(std.mem.asBytes(&destination), 0xb7);
    var before: [@sizeOf(temporal.VerifiedChildV2)]u8 = undefined;
    @memcpy(&before, std.mem.asBytes(&destination));
    try std.testing.expectError(
        error.VerifiedCohortReceiptUnavailable,
        subject.publishFromRawClosureV2Into(
            DIMENSIONS,
            &destination,
            fixture.encoding_scratch,
            &fixture.publication,
            &fixture.wire,
            &fixture.candidate,
            &receipt,
        ),
    );
    try std.testing.expectEqualSlices(u8, &before, std.mem.asBytes(&destination));
}

test "temporal child bridge derives every currently authenticated V2 field" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const canonical = try std.testing.allocator.dupe(u8, fixture.encoding_scratch);
    defer std.testing.allocator.free(canonical);
    @memset(fixture.encoding_scratch, 0xa5);

    var derived: subject.DerivedVerifierFieldsV1 = undefined;
    try subject.inspectInto(
        DIMENSIONS,
        &derived,
        fixture.encoding_scratch,
        &fixture.publication,
        &fixture.wire,
        &fixture.candidate,
    );

    try std.testing.expectEqualSlices(u8, canonical, fixture.encoding_scratch);
    try std.testing.expectEqual(admission.ProofScope.verifier_subsystem, derived.source_scope);
    try std.testing.expectEqual(temporal.ProofKind.segment_leaf, derived.kind);
    try std.testing.expectEqual(temporal.ChildPosition.left, derived.position);
    try std.testing.expectEqual(temporal.COMPLETE_ROSTER_COUNT, derived.roster_count);
    try std.testing.expectEqual(protocol.LEAF_STATEMENT_VERSION, derived.statement_version);
    try std.testing.expectEqual(fixture.publication.receipt.statement_id, derived.statement_id);
    try std.testing.expectEqual(
        try temporal.jobId(&fixture.publication.statement_words),
        derived.job_id,
    );
    try std.testing.expectEqual(
        fixture.publication.receipt.verification_key_id,
        derived.verification_key_id,
    );
    try std.testing.expectEqual(fixture.publication.receipt.air_program_id, derived.air_program_id);
    try std.testing.expectEqual(fixture.publication.receipt.manifest_id, derived.manifest_id);
    try std.testing.expectEqual(fixture.candidate.profile_id, derived.profile_id);
    try std.testing.expectEqual(fixture.candidate.proof_id, derived.proof_id);
    try std.testing.expectEqual(fixture.publication.seal.transcript_id, derived.transcript_id);
    try std.testing.expectEqual(fixture.publication.seal.capture_id, derived.capture_id);
    try std.testing.expectEqual(fixture.publication.seal.receipt_id, derived.verifier_receipt_id);
    try std.testing.expectEqual(fixture.publication.seal.claimed_sums_id, derived.claimed_sums_id);
    try std.testing.expectEqual(
        fixture.publication.relation_replay.identity,
        derived.relation_replay_id,
    );
    try std.testing.expectEqual(
        fixture.publication.auxiliary_claim_seal.digest,
        derived.auxiliary_claim_seal_id,
    );
    try std.testing.expectEqual([4]u32{ 0, 0, 0, 0 }, derived.closure_value);
    try std.testing.expect(!digestIsZero(derived.closure_receipt_id));
}

test "child position and job identity are derived only from canonical span words" {
    var right_fixture = try Fixture.initAtSlot(std.testing.allocator, 1);
    defer right_fixture.deinit();
    var derived: subject.DerivedVerifierFieldsV1 = undefined;
    try subject.inspectInto(
        DIMENSIONS,
        &derived,
        right_fixture.encoding_scratch,
        &right_fixture.publication,
        &right_fixture.wire,
        &right_fixture.candidate,
    );
    try std.testing.expectEqual(temporal.ChildPosition.right, derived.position);
    try std.testing.expectEqual(
        try temporal.jobId(&right_fixture.publication.statement_words),
        derived.job_id,
    );
    try std.testing.expectEqual(
        right_fixture.publication.receipt.statement_id,
        derived.statement_id,
    );
}

test "temporal child publication cannot cross incomplete scope and is fail atomic" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    var destination: temporal.VerifiedChildV2 = undefined;
    @memset(std.mem.asBytes(&destination), 0x6d);
    var before: [@sizeOf(temporal.VerifiedChildV2)]u8 = undefined;
    @memcpy(&before, std.mem.asBytes(&destination));
    var derived_scratch: subject.DerivedVerifierFieldsV1 = undefined;

    try std.testing.expectError(
        error.CompleteParentProofUnavailable,
        subject.publishCurrentInto(
            DIMENSIONS,
            &destination,
            &derived_scratch,
            fixture.encoding_scratch,
            &fixture.publication,
            &fixture.wire,
            &fixture.candidate,
        ),
    );
    try std.testing.expectEqualSlices(u8, &before, std.mem.asBytes(&destination));
}

test "temporal child bridge rejects publication candidate and wire mutations atomically" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const statement_word = fixture.publication.statement_words[0];
    fixture.publication.statement_words[0] = M31.zero();
    try expectInspectionRejectedAtomic(&fixture);
    fixture.publication.statement_words[0] = statement_word;

    fixture.publication.relation_replay.identity[0] ^= 1;
    try expectInspectionRejectedAtomic(&fixture);
    fixture.publication.relation_replay.identity[0] ^= 1;

    fixture.publication.auxiliary_claim_seal.digest[0] ^= 1;
    try expectInspectionRejectedAtomic(&fixture);
    fixture.publication.auxiliary_claim_seal.digest[0] ^= 1;

    fixture.candidate.scope = .complete_parent;
    try expectInspectionRejectedAtomic(&fixture);
    fixture.candidate.scope = .verifier_subsystem;

    fixture.candidate.proof_id[0] ^= 1;
    try expectInspectionRejectedAtomic(&fixture);
    fixture.candidate.proof_id[0] ^= 1;

    fixture.candidate.transcript_id[0] ^= 1;
    try expectInspectionRejectedAtomic(&fixture);
    fixture.candidate.transcript_id[0] ^= 1;

    fixture.candidate.shape.verification_key_id[0] ^= 1;
    try expectInspectionRejectedAtomic(&fixture);
    fixture.candidate.shape.verification_key_id[0] ^= 1;

    fixture.candidate.shape.statement_id[0] ^= 1;
    try expectInspectionRejectedAtomic(&fixture);
    fixture.candidate.shape.statement_id[0] ^= 1;

    fixture.publication.receipt.statement_id[0] ^= 1;
    try expectInspectionRejectedAtomic(&fixture);
    fixture.publication.receipt.statement_id[0] ^= 1;

    const proof_id = fixture.candidate.proof_id;
    fixture.candidate.proof_id[0] = stwo_core.fields.m31.Modulus;
    try expectInspectionRejectedAtomic(&fixture);
    fixture.candidate.proof_id = proof_id;

    fixture.wire.magic ^= 1;
    try expectInspectionRejectedAtomic(&fixture);
    fixture.wire.magic ^= 1;

    fixture.wire.payload.claimed_sums[0][0] ^= 1;
    try expectInspectionRejectedAtomic(&fixture);
    fixture.wire.payload.claimed_sums[0][0] ^= 1;
}

test "temporal child bridge rejects aliases before mutating any output" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const wire_bytes = std.mem.asBytes(&fixture.wire);
    try std.testing.expect(wire_bytes.len >= fixture.encoding_scratch.len);
    var destination: subject.DerivedVerifierFieldsV1 = undefined;
    @memset(std.mem.asBytes(&destination), 0x47);
    var before: [@sizeOf(subject.DerivedVerifierFieldsV1)]u8 = undefined;
    @memcpy(&before, std.mem.asBytes(&destination));
    try std.testing.expectError(
        error.AliasedWorkspace,
        subject.inspectInto(
            DIMENSIONS,
            &destination,
            wire_bytes[0..fixture.encoding_scratch.len],
            &fixture.publication,
            &fixture.wire,
            &fixture.candidate,
        ),
    );
    try std.testing.expectEqualSlices(u8, &before, std.mem.asBytes(&destination));

    try std.testing.expect(
        fixture.encoding_scratch.len >= @sizeOf(subject.DerivedVerifierFieldsV1),
    );
    const aliased_destination: *subject.DerivedVerifierFieldsV1 = @ptrCast(
        @alignCast(fixture.encoding_scratch.ptr),
    );
    @memset(std.mem.asBytes(aliased_destination), 0x9b);
    var aliased_before: [@sizeOf(subject.DerivedVerifierFieldsV1)]u8 = undefined;
    @memcpy(&aliased_before, std.mem.asBytes(aliased_destination));
    try std.testing.expectError(
        error.AliasedWorkspace,
        subject.inspectInto(
            DIMENSIONS,
            aliased_destination,
            fixture.encoding_scratch,
            &fixture.publication,
            &fixture.wire,
            &fixture.candidate,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &aliased_before,
        std.mem.asBytes(aliased_destination),
    );

    comptime std.debug.assert(
        @sizeOf(temporal.VerifiedChildV2) >=
            @sizeOf(subject.DerivedVerifierFieldsV1),
    );
    var child: temporal.VerifiedChildV2 = undefined;
    @memset(std.mem.asBytes(&child), 0x31);
    var child_before: [@sizeOf(temporal.VerifiedChildV2)]u8 = undefined;
    @memcpy(&child_before, std.mem.asBytes(&child));
    const aliased_derived: *subject.DerivedVerifierFieldsV1 = @ptrCast(
        @alignCast(&child),
    );
    try std.testing.expectError(
        error.AliasedWorkspace,
        subject.publishCurrentInto(
            DIMENSIONS,
            &child,
            aliased_derived,
            fixture.encoding_scratch,
            &fixture.publication,
            &fixture.wire,
            &fixture.candidate,
        ),
    );
    try std.testing.expectEqualSlices(u8, &child_before, std.mem.asBytes(&child));
}
