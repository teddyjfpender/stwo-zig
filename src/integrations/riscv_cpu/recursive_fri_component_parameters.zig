//! Pure component parameters shared by native preparation and detached verification.
const air = @import("stwo_riscv_frontend").recursion.air;
const M31 = @import("stwo_core").fields.m31.M31;
const vm_input_air = air.vm_air_composition_input;
const vm_input_witness = air.vm_air_composition_input_witness;
const query_bits_air = air.query_bits;
const query_bits_witness = air.query_bits_witness;
const query_mapping_air = air.query_mapping;
const query_mapping_witness = air.query_mapping_witness;
const merkle_root_air = air.merkle_root;
const merkle_root_witness = air.merkle_root_witness;
const trace_merkle_air = air.trace_merkle;
const trace_merkle_witness = air.trace_merkle_witness;
const pcs_air = air.pcs_deep_input;
const pcs_witness = air.pcs_deep_input_witness;
const fri_leaf_air = air.fri_merkle_leaf;
const fri_leaf_witness = air.fri_merkle_leaf_witness;
const fri_anchor_air = air.fri_merkle_anchor;
const fri_anchor_witness = air.fri_merkle_anchor_witness;
const control_air = air.fri_verifier_control;
const control_witness = air.fri_verifier_control_witness;
const input_air = air.fri_verifier_input;
const input_witness = air.fri_verifier_input_witness;

pub fn vmInputParameters(
    kind: vm_input_witness.ProofKind,
) [vm_input_air.PARAMETER_COUNT]M31 {
    const selectors = kind.selectors();
    return .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(vm_input_witness.SAMPLED_VALUE_KIND),
        M31.fromCanonical(vm_input_witness.VM_CLAIMED_SUM_KIND),
        M31.fromCanonical(vm_input_witness.RECURSION_CLAIMED_SUM_KIND),
        M31.fromCanonical(vm_input_witness.CHALLENGE_SCOPE),
        M31.fromCanonical(vm_input_witness.COMPOSITION_RANDOMNESS_KIND),
        M31.fromCanonical(vm_input_witness.OODS_POINT_KIND),
        M31.fromCanonical(vm_input_witness.TRANSCRIPT_CLAIMED_SUM_KIND),
    };
}

pub fn merkleRootParameters(
    kind: merkle_root_witness.ProofKind,
) [merkle_root_air.PARAMETER_COUNT]M31 {
    return kind.selectors()[0..2].*;
}

pub fn traceMerkleParameters(
    kind: trace_merkle_witness.ProofKind,
) [trace_merkle_air.PARAMETER_COUNT]M31 {
    const selectors = kind.selectors();
    return .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(trace_merkle_witness.LEAF_TAG),
        M31.fromCanonical(trace_merkle_witness.TRACE_POSITION_KIND),
    };
}

pub fn friLeafParameters(
    kind: fri_leaf_witness.ProofKind,
) [fri_leaf_air.PARAMETER_COUNT]M31 {
    const selectors = kind.selectors();
    return .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(fri_leaf_witness.LEAF_TAG),
    };
}

pub fn friAnchorParameters(
    kind: fri_anchor_witness.ProofKind,
) [fri_anchor_air.PARAMETER_COUNT]M31 {
    const selectors = kind.selectors();
    return .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(fri_anchor_witness.FRI_MERKLE_KIND),
    };
}

pub fn queryBitsParameters(
    reference: query_bits_witness.Reference,
    kind: query_bits_witness.ProofKind,
) ![query_bits_air.PARAMETER_COUNT]M31 {
    return query_bits_witness.parameterValues(reference, kind);
}

pub fn queryMappingParameters(
    kind: query_mapping_witness.ProofKind,
) [query_mapping_air.PARAMETER_COUNT]M31 {
    const selectors = kind.selectors();
    return .{ selectors[0], selectors[1] };
}

pub fn controlParameters(
    kind: control_witness.ProofKind,
) [control_air.PARAMETER_COUNT]M31 {
    const selectors = kind.selectors();
    return .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(control_witness.POSITION_FIELD),
        M31.fromCanonical(control_witness.OFFSET_FIELD),
    };
}

pub fn inputParameters(kind: input_witness.ProofKind) [input_air.PARAMETER_COUNT]M31 {
    const selectors = kind.selectors();
    return .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(input_witness.FRI_ALPHA_KIND),
        M31.fromCanonical(input_witness.FRI_FOLD_KIND),
        M31.fromCanonical(input_witness.LAST_LAYER_KIND),
        M31.fromCanonical(input_witness.POSITION_FIELD),
        M31.fromCanonical(input_witness.OFFSET_FIELD),
        M31.fromCanonical(input_witness.COEFFICIENT_KIND),
    };
}

pub fn pcsParameters(kind: pcs_witness.ProofKind) [pcs_air.PARAMETER_COUNT]M31 {
    const selectors = kind.selectors();
    return .{
        selectors[0],
        selectors[1],
        M31.fromCanonical(pcs_witness.SAMPLED_VALUE_KIND),
        M31.fromCanonical(pcs_witness.OODS_POINT_KIND),
        M31.fromCanonical(pcs_witness.DEEP_RANDOMNESS_KIND),
        M31.fromCanonical(pcs_witness.DEEP_POSITION_KIND),
    };
}
