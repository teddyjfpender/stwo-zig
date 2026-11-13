//! Proof-kind descriptor geometry and trusted manifest admission.

const Root = @import("recursion_air_composition_circuit_write_inputs_from_validated_profile_and_policy.zig");
const dependency_0 = @import("recursion_air_composition_circuit_canonical_empty_program.zig");
const ProofKind = dependency_0.ProofKind;
const UNIVERSAL_PHYSICAL_CLAIM_COUNT = dependency_0.UNIVERSAL_PHYSICAL_CLAIM_COUNT;
const SEGMENT_PHYSICAL_CLAIM_COUNT = dependency_0.SEGMENT_PHYSICAL_CLAIM_COUNT;
const H1_PHYSICAL_CLAIM_COUNT = dependency_0.H1_PHYSICAL_CLAIM_COUNT;
const EMPTY_PHYSICAL_CLAIM_COUNT = dependency_0.EMPTY_PHYSICAL_CLAIM_COUNT;
const POSEIDON_PARTIAL_COUNT = dependency_0.POSEIDON_PARTIAL_COUNT;
const POSEIDON_ROSTER_ROW = dependency_0.POSEIDON_ROSTER_ROW;
const H1_POSEIDON_ROSTER_ROW = dependency_0.H1_POSEIDON_ROSTER_ROW;
const Error = dependency_0.Error;
const ManifestFamilyV3 = dependency_0.ManifestFamilyV3;
const TrustedManifestsV3 = dependency_0.TrustedManifestsV3;
const DescriptorShape = Root.DescriptorShape;
const INITIAL_PHYSICAL_CLAIM_COUNT = Root.INITIAL_PHYSICAL_CLAIM_COUNT;

pub fn descriptorShape(kind: ProofKind) DescriptorShape {
    return switch (kind) {
        .segment_leaf => .{
            .manifest_family = .segment_v2,
            .claim_policy = .complete_segment,
            .source_claim_count = SEGMENT_PHYSICAL_CLAIM_COUNT,
            .program_roster_count = SEGMENT_PHYSICAL_CLAIM_COUNT,
            .poseidon_partial_count = POSEIDON_PARTIAL_COUNT,
            .poseidon_roster_row = POSEIDON_ROSTER_ROW,
        },
        .binary_node => .{
            .manifest_family = .universal_v1,
            .claim_policy = .universal_with_zero_tail,
            .source_claim_count = UNIVERSAL_PHYSICAL_CLAIM_COUNT,
            .program_roster_count = UNIVERSAL_PHYSICAL_CLAIM_COUNT,
            .poseidon_partial_count = POSEIDON_PARTIAL_COUNT,
            .poseidon_roster_row = POSEIDON_ROSTER_ROW,
        },
        .empty_leaf => .{
            .manifest_family = .universal_v1,
            .claim_policy = .canonical_empty,
            .source_claim_count = EMPTY_PHYSICAL_CLAIM_COUNT,
            .program_roster_count = UNIVERSAL_PHYSICAL_CLAIM_COUNT,
            .poseidon_partial_count = 0,
            .poseidon_roster_row = POSEIDON_ROSTER_ROW,
        },
    };
}

pub fn canonicalEmptyDescriptorShape() DescriptorShape {
    return .{
        .manifest_family = .universal_v1,
        .claim_policy = .canonical_empty_provider,
        .source_claim_count = 1,
        .program_roster_count = UNIVERSAL_PHYSICAL_CLAIM_COUNT,
        .poseidon_partial_count = 0,
        .poseidon_roster_row = POSEIDON_ROSTER_ROW,
    };
}

pub fn h1DescriptorShape() DescriptorShape {
    return .{
        .manifest_family = .ethereum_poseidon_h1_v1,
        .claim_policy = .ethereum_poseidon_h1,
        .source_claim_count = H1_PHYSICAL_CLAIM_COUNT,
        .program_roster_count = H1_PHYSICAL_CLAIM_COUNT,
        .poseidon_partial_count = POSEIDON_PARTIAL_COUNT,
        .poseidon_roster_row = H1_POSEIDON_ROSTER_ROW,
    };
}

pub fn temporalParentDescriptorShape() DescriptorShape {
    return .{
        .manifest_family = .temporal_parent_v3,
        .claim_policy = .temporal_parent,
        .source_claim_count = UNIVERSAL_PHYSICAL_CLAIM_COUNT,
        .program_roster_count = UNIVERSAL_PHYSICAL_CLAIM_COUNT,
        .poseidon_partial_count = POSEIDON_PARTIAL_COUNT,
        .poseidon_roster_row = POSEIDON_ROSTER_ROW,
    };
}

pub fn commonFoldDescriptorShape() DescriptorShape {
    return .{
        .manifest_family = .common_fold_field_v2,
        .claim_policy = .common_fold_field_v2,
        .source_claim_count = UNIVERSAL_PHYSICAL_CLAIM_COUNT,
        .program_roster_count = UNIVERSAL_PHYSICAL_CLAIM_COUNT,
        .poseidon_partial_count = POSEIDON_PARTIAL_COUNT,
        .poseidon_roster_row = POSEIDON_ROSTER_ROW,
    };
}

pub fn initialWrapperDescriptorShape() DescriptorShape {
    return .{
        .manifest_family = .ethereum_initial_wrapper_v1,
        .claim_policy = .ethereum_initial_wrapper_v1,
        .source_claim_count = INITIAL_PHYSICAL_CLAIM_COUNT,
        .program_roster_count = INITIAL_PHYSICAL_CLAIM_COUNT,
        .poseidon_partial_count = POSEIDON_PARTIAL_COUNT,
        .poseidon_roster_row = POSEIDON_ROSTER_ROW,
    };
}

pub fn descriptorShapeForManifest(
    kind: ProofKind,
    family: ManifestFamilyV3,
) DescriptorShape {
    if (kind == .binary_node and family == .ethereum_initial_wrapper_v1)
        return initialWrapperDescriptorShape();
    if (kind == .binary_node and family == .ethereum_poseidon_h1_v1)
        return h1DescriptorShape();
    if (kind == .binary_node and family == .temporal_parent_v3)
        return temporalParentDescriptorShape();
    if (kind == .binary_node and family == .common_fold_field_v2)
        return commonFoldDescriptorShape();
    return descriptorShape(kind);
}

pub fn validateManifests(manifests: TrustedManifestsV3) Error!void {
    try manifests.universal.validate();
    try manifests.segment.validate();
    if (manifests.universal.roster_count != UNIVERSAL_PHYSICAL_CLAIM_COUNT or
        manifests.segment.roster_count != SEGMENT_PHYSICAL_CLAIM_COUNT)
    {
        return error.ManifestAuthorityMismatch;
    }
}
