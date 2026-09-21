//! Fixed component parameters shared by preparation and standalone verification.
const M31 = @import("stwo_core").fields.m31.M31;
const ProofKind = @import("proof_kind.zig").ProofKind;
const query_profile = @import("query_bits_profile.zig");
const tags = @import("verifier_parameter_tags.zig");
const vm_input_air = @import("vm_air_composition_input.zig");
const query_bits_air = @import("query_bits.zig");
const query_mapping_air = @import("query_mapping.zig");
const merkle_root_air = @import("merkle_root.zig");
const trace_merkle_air = @import("trace_merkle.zig");
const pcs_air = @import("pcs_deep_input.zig");
const fri_leaf_air = @import("fri_merkle_leaf.zig");
const fri_anchor_air = @import("fri_merkle_anchor.zig");
const control_air = @import("fri_verifier_control.zig");
const input_air = @import("fri_verifier_input.zig");

pub fn vmInputParameters(
    kind: ProofKind,
) [vm_input_air.PARAMETER_COUNT]M31 {
    const selectors = kind.selectors();
    return .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(tags.vm_input.SAMPLED_VALUE_KIND),
        M31.fromCanonical(tags.vm_input.VM_CLAIMED_SUM_KIND),
        M31.fromCanonical(tags.vm_input.RECURSION_CLAIMED_SUM_KIND),
        M31.fromCanonical(tags.vm_input.CHALLENGE_SCOPE),
        M31.fromCanonical(tags.vm_input.COMPOSITION_RANDOMNESS_KIND),
        M31.fromCanonical(tags.vm_input.OODS_POINT_KIND),
        M31.fromCanonical(tags.vm_input.TRANSCRIPT_CLAIMED_SUM_KIND),
    };
}

pub fn merkleRootParameters(
    kind: ProofKind,
) [merkle_root_air.PARAMETER_COUNT]M31 {
    return kind.selectors()[0..2].*;
}

pub fn traceMerkleParameters(
    kind: ProofKind,
) [trace_merkle_air.PARAMETER_COUNT]M31 {
    const selectors = kind.selectors();
    return .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(tags.trace_merkle.LEAF_TAG),
        M31.fromCanonical(tags.trace_merkle.TRACE_POSITION_KIND),
    };
}

pub fn friLeafParameters(
    kind: ProofKind,
) [fri_leaf_air.PARAMETER_COUNT]M31 {
    const selectors = kind.selectors();
    return .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(tags.fri_leaf.LEAF_TAG),
    };
}

pub fn friAnchorParameters(
    kind: ProofKind,
) [fri_anchor_air.PARAMETER_COUNT]M31 {
    const selectors = kind.selectors();
    return .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(tags.fri_anchor.FRI_MERKLE_KIND),
    };
}

pub fn queryBitsParameters(
    reference: query_profile.Reference,
    kind: ProofKind,
) ![query_bits_air.PARAMETER_COUNT]M31 {
    return query_profile.parameterValues(reference, kind);
}

pub fn queryMappingParameters(
    kind: ProofKind,
) [query_mapping_air.PARAMETER_COUNT]M31 {
    const selectors = kind.selectors();
    return .{ selectors[0], selectors[1] };
}

pub fn controlParameters(
    kind: ProofKind,
) [control_air.PARAMETER_COUNT]M31 {
    const selectors = kind.selectors();
    return .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(tags.control.POSITION_FIELD),
        M31.fromCanonical(tags.control.OFFSET_FIELD),
    };
}

pub fn inputParameters(kind: ProofKind) [input_air.PARAMETER_COUNT]M31 {
    const selectors = kind.selectors();
    return .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(tags.input.FRI_ALPHA_KIND),
        M31.fromCanonical(tags.input.FRI_FOLD_KIND),
        M31.fromCanonical(tags.input.LAST_LAYER_KIND),
        M31.fromCanonical(tags.input.POSITION_FIELD),
        M31.fromCanonical(tags.input.OFFSET_FIELD),
        M31.fromCanonical(tags.input.COEFFICIENT_KIND),
    };
}

pub fn pcsParameters(kind: ProofKind) [pcs_air.PARAMETER_COUNT]M31 {
    const selectors = kind.selectors();
    return .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(tags.pcs.SAMPLED_VALUE_KIND),
        M31.fromCanonical(tags.pcs.OODS_POINT_KIND),
        M31.fromCanonical(tags.pcs.DEEP_RANDOMNESS_KIND),
        M31.fromCanonical(tags.pcs.DEEP_POSITION_KIND),
    };
}
