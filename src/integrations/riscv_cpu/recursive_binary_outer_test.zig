//! Focused availability and fail-closed tests for the binary outer driver.

const std = @import("std");

const driver = @import("recursive_binary_outer.zig");

test "binary temporal parent profile APIs type-check as a complete surface" {
    std.testing.refAllDeclsRecursive(driver.TemporalParentArtifactViewV1);
    std.testing.refAllDeclsRecursive(driver.TemporalVerifierSuccessBindingV1);
    try std.testing.expect(@hasDecl(
        driver,
        "openTemporalVerifierSuccessEvidence",
    ));
    try std.testing.expect(!driver.TEMPORAL_VERIFIER_PUBLIC_MINT_AVAILABLE);
    try std.testing.expectEqual(
        @as(usize, 0),
        driver.TEMPORAL_VERIFIER_EVIDENCE_HEAP_ALLOCATIONS,
    );
}

test "binary outer capability ledger reports exact current source frontier" {
    const custody = driver.SourceCustodyCapabilitiesV1.inspect(
        ObservedCurrentFriSurface,
    );
    try std.testing.expect(custody.authenticated_child_custody);
    try std.testing.expect(custody.full_composition_authority);
    try std.testing.expect(custody.retained_relation_rows);
    try std.testing.expect(custody.local_preprocessed_main_writers);
    try std.testing.expect(custody.retained_row34_poseidon_calls);

    const proof = driver.CURRENT_PROOF_CAPABILITIES;
    try std.testing.expect(!proof.ready());
    try std.testing.expect(!proof.global_manifest_geometry);
    try std.testing.expect(!proof.global_tree_writers);
    try std.testing.expect(!proof.authenticated_interaction_receipt);
    try std.testing.expect(!proof.authenticated_domain_audit);
    try std.testing.expect(!proof.complete_claim_binding);
    try std.testing.expect(!proof.component_construction);
    try std.testing.expect(!proof.ordered_rows_0_through_33);
    try std.testing.expect(!proof.authenticated_row34_provider);
    try std.testing.expect(!proof.authenticated_row35_provider);
    try std.testing.expect(!proof.independent_verifier_rebuild);
}

test "binary outer current entrypoint fails before publication mutation" {
    var non_fri_validations: usize = 0;
    var fri_validations: usize = 0;
    var full_authority_checks: usize = 0;
    var non_fri = NonFriAuthorityProbe{ .validations = &non_fri_validations };
    var fri = FriAuthorityProbe{
        .validations = &fri_validations,
        .full_authority_checks = &full_authority_checks,
    };

    var capture: driver.OuterProofCapture = undefined;
    @memset(std.mem.asBytes(&capture), 0xa5);
    const before = std.mem.asBytes(&capture)[0..@sizeOf(driver.OuterProofCapture)].*;
    try std.testing.expectError(
        error.BinaryFriInteractionAuthorityUnavailable,
        driver.proveAndVerifyCurrent(
            std.testing.allocator,
            &non_fri,
            &fri,
            &capture,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), non_fri_validations);
    try std.testing.expectEqual(@as(usize, 1), fri_validations);
    try std.testing.expectEqual(@as(usize, 1), full_authority_checks);
    try std.testing.expectEqualSlices(u8, &before, std.mem.asBytes(&capture));
}

test "binary outer row and PCS authorities remain protocol derived" {
    try std.testing.expectEqual(@as(usize, 36), driver.COMPLETE_ROW_COUNT);
    try std.testing.expectEqual(@as(usize, 18), driver.FRI_FIRST_ROW);
    try std.testing.expectEqual(@as(usize, 34), driver.POSEIDON_PROVIDER_ROW);
    try std.testing.expectEqual(@as(usize, 35), driver.RANGE_PROVIDER_ROW);
    try std.testing.expectEqual(
        @import("stwo_riscv_frontend").recursion.outer_parent_child_admission.PCS_POW_BITS,
        driver.OUTER_CONFIG.pow_bits,
    );
    try std.testing.expect(!driver.WHOLE_FRONTEND_VERIFIED);
    try std.testing.expect(!driver.PRODUCTION_ACTIVATION);
}

test "binary temporal parent frontier exposes the independently verified V3 path" {
    const capabilities = driver.CURRENT_TEMPORAL_PARENT_CAPABILITIES;
    try std.testing.expect(capabilities.verified_segment_child_publications);
    try std.testing.expect(capabilities.verifier_capture_identity_binding);
    try std.testing.expect(capabilities.authenticated_temporal_pair);
    try std.testing.expect(capabilities.role_neutral_rows_18_through_35);
    try std.testing.expect(capabilities.verifier_child_claim_values);
    try std.testing.expect(capabilities.verifier_child_relation_replay);
    try std.testing.expect(capabilities.segment_v2_composition_profile);
    try std.testing.expect(capabilities.temporal_rows_0_through_17);
    try std.testing.expect(capabilities.verified_complete_parent_publication);
    try std.testing.expect(capabilities.complete_parent_prover_and_verifier);
    try std.testing.expect(capabilities.ready());
    try capabilities.requireProduction();
    try std.testing.expectEqual(
        @as(usize, 0),
        driver.HEAP_ALLOCATIONS_PER_TEMPORAL_ARTIFACT_PREFLIGHT,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        driver.PROOF_DECODING_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        driver.SEGMENT_MANIFEST_VALIDATION_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        driver.SEGMENT_WITNESS_PREFLIGHT_PASSES_PER_TEMPORAL_ARTIFACT_PREFLIGHT,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        driver.TEMPORAL_RELATION_RECONSTRUCTIONS_PER_ARTIFACT_PREFLIGHT,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        driver.TEMPORAL_RELATION_DRAW_REHASHES_PER_ARTIFACT_PREFLIGHT,
    );
    try std.testing.expect(@hasField(
        driver.TemporalParentArtifactViewV1,
        "relation_profiles",
    ));
    try std.testing.expect(@hasDecl(
        driver.TemporalParentArtifactViewV1,
        "reconstructChildRelations",
    ));
    try std.testing.expect(driver.TEMPORAL_SEGMENT_CLAIM_ABI_AVAILABLE);
    try std.testing.expectEqual(
        @as(usize, 2),
        driver.TEMPORAL_SEGMENT_CLAIM_INPUT_WRITES_PER_PARENT,
    );
    try std.testing.expect(@hasField(
        driver.TemporalParentArtifactViewV1,
        "segment_composition_profile",
    ));
    try std.testing.expect(@hasDecl(
        driver.TemporalParentArtifactViewV1,
        "writeSegmentCompositionInputs",
    ));
}

test "binary temporal artifact preflight rejects duplicate custody first" {
    var publication: @import("recursive_segment_v2_verified_publication.zig")
        .VerifiedSegmentV2PublicationV1 = undefined;
    @memset(std.mem.asBytes(&publication), 0);
    var capture: driver.OuterProofCapture = undefined;
    @memset(std.mem.asBytes(&capture), 0);
    var recursive_witness: @import("recursive_segment_v2_verified_artifact.zig")
        .RecursiveWitnessV1 = undefined;
    const child = driver.TemporalChildArtifactV1{
        .publication = &publication,
        .capture = &capture,
        .recursive_witness = &recursive_witness,
    };
    var segment_manifest: @import("stwo_riscv_frontend").recursion.air
        .segment_outer_adapter_manifest_v2.Manifest = undefined;
    var pair: @import("recursive_temporal_pair_authority_v2.zig")
        .PreparedTemporalPairAuthorityV1 = undefined;
    @memset(std.mem.asBytes(&pair), 0);
    try std.testing.expectError(
        error.DuplicateTemporalChildArtifact,
        driver.TemporalParentArtifactViewV1.init(
            child,
            child,
            .{ &segment_manifest, &segment_manifest },
            &pair,
        ),
    );
}

const NonFriAuthorityProbe = struct {
    validations: *usize,

    pub fn validate(self: *const NonFriAuthorityProbe) !void {
        self.validations.* += 1;
    }
};

const FriAuthorityProbe = struct {
    validations: *usize,
    full_authority_checks: *usize,

    pub fn validate(self: *const FriAuthorityProbe) !void {
        self.validations.* += 1;
    }

    pub fn requireFullBundleAuthority(self: *const FriAuthorityProbe) !void {
        self.full_authority_checks.* += 1;
    }
};

/// Declaration-only mirror of the public custody surface inspected in the
/// focused binary-FRI source suite. It supplies no rows, claims, or callbacks;
/// this test exercises only the compile-time capability classifier.
const ObservedCurrentFriSurface = struct {
    pub fn validate() void {}
    pub fn wire() void {}
    pub fn requireFullBundleAuthority() void {}
    pub const RelationRows = struct {};
    pub fn merkleRelationRows() void {}
    pub fn fillCompositionPreprocessedInto() void {}
    pub fn fillCompositionMainInto() void {}
    pub fn fillFriPreprocessedInto() void {}
    pub fn fillFriMainInto() void {}
    pub fn fillArithmeticPreprocessedInto() void {}
    pub fn fillArithmeticMainInto() void {}
    pub fn fillMerkleMainInto() void {}
    pub fn merklePoseidonCalls() void {}
};
