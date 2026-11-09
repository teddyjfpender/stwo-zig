//! Fixed leaf verifier parameters shared with source preparation.
const M31 = @import("stwo_core").fields.m31.M31;
const geometry = @import("stwo_riscv_air_lang").framework_universal_typed_geometry;
const public_air = @import("stwo_riscv_recursion_air").segment_public_outer_air;
const proof_kind = @import("stwo_riscv_air_lang").framework_proof_kind;
const tags = @import("stwo_riscv_recursion_air").verifier_parameter_tags;
const native_parameters = @import("stwo_riscv_recursion_air").verifier_component_parameters;
const AdmissionParametersV1 = @import("detached_segment_admission.zig").AdmissionParametersV1;

pub const TranscriptParameters = struct {
    control: [geometry.parameterColumnCount(@import("stwo_riscv_air_lang").framework_control)]M31,
    transcript_air: [geometry.parameterColumnCount(@import("stwo_riscv_recursion_air").transcript_air)]M31,
    transcript_binding: [geometry.parameterColumnCount(@import("stwo_riscv_recursion_air").transcript_binding)]M31,
    transcript_state: [geometry.parameterColumnCount(@import("stwo_riscv_recursion_air").transcript_state)]M31,
    transcript_word: [geometry.parameterColumnCount(@import("stwo_riscv_recursion_air").transcript_word)]M31,
    transcript_payload: [geometry.parameterColumnCount(@import("stwo_riscv_recursion_air").transcript_payload)]M31,
    pow_check: [geometry.parameterColumnCount(@import("stwo_riscv_recursion_air").pow_check)]M31,
    pow_frame: [geometry.parameterColumnCount(@import("stwo_riscv_recursion_air").pow_frame)]M31,
    relation_challenge: [geometry.parameterColumnCount(@import("stwo_riscv_recursion_air").relation_challenge)]M31,
    verifier_randomness: [geometry.parameterColumnCount(@import("stwo_riscv_recursion_air").verifier_randomness)]M31,

    pub fn segmentV2() TranscriptParameters {
        const selectors = proof_kind.ProofKind.segment_leaf.selectors();
        return .{
            .control = selectors[0..2].*,
            .transcript_air = .{},
            .transcript_binding = selectors[0..2].*,
            .transcript_state = selectors[0..2].*,
            .transcript_word = selectors[0..2].*,
            .transcript_payload = selectors[0..2].*,
            .pow_check = .{},
            .pow_frame = .{},
            .relation_challenge = selectors[0..2].* ++ .{
                M31.fromCanonical(
                    tags.relation_challenge.AIR_EVALUATION_CHALLENGE_SCOPE,
                ),
                M31.fromCanonical(
                    tags.relation_challenge.VM_PUBLIC_LOGUP_CHALLENGE_SCOPE,
                ),
            },
            .verifier_randomness = selectors[0..2].*,
        };
    }
};

pub const PublicParameters = struct {
    publication_header: [geometry.parameterColumnCount(public_air.PublicationHeader)]M31,
    native_public_sums: [geometry.parameterColumnCount(public_air.NativePublicSums)]M31,
    publication_seal: [geometry.parameterColumnCount(public_air.PublicationSeal)]M31,
    boundary_bridge: [geometry.parameterColumnCount(public_air.StatementBoundary)]M31,
    native_challenges: [geometry.parameterColumnCount(public_air.NativeChallenges)]M31,
    control_relay: [geometry.parameterColumnCount(public_air.ControlRelay)]M31,

    pub fn segmentV2() PublicParameters {
        const zero = [_]M31{M31.zero()};
        return .{
            .publication_header = zero,
            .native_public_sums = zero,
            .publication_seal = zero,
            .boundary_bridge = zero,
            .native_challenges = zero,
            .control_relay = .{},
        };
    }
};

pub fn parametersFor(comptime entry: anytype, admitted: AdmissionParametersV1) ![geometry.parameterColumnCount(entry.Air)]M31 {
    const row = @intFromEnum(entry.row);
    if (comptime row >= 36 or row == 10 or row == 11)
        return @splat(M31.zero());
    if (comptime row < 10)
        return @field(TranscriptParameters.segmentV2(), @tagName(entry.row));
    if (comptime row < 18) {
        const fields = .{ "publication_header", "native_public_sums", "publication_seal", "boundary_bridge", "native_challenges", "control_relay" };
        return @field(PublicParameters.segmentV2(), fields[row - 12]);
    }
    return switch (entry.row) {
        .vm_air_composition_input => native_parameters.vmInputParameters(.segment_leaf),
        .vm_air_composition_control => proof_kind.ProofKind.segment_leaf.selectors()[0..2].*,
        .query_bits => try native_parameters.queryBitsParameters(admitted.query_reference, .segment_leaf),
        .query_mapping => native_parameters.queryMappingParameters(.segment_leaf),
        .merkle_root => native_parameters.merkleRootParameters(.segment_leaf),
        .trace_merkle => native_parameters.traceMerkleParameters(.segment_leaf),
        .pcs_deep_input => native_parameters.pcsParameters(.segment_leaf),
        .fri_merkle_leaf => native_parameters.friLeafParameters(.segment_leaf),
        .fri_merkle_node => proof_kind.ProofKind.segment_leaf.selectors()[0..2].*,
        .fri_merkle_anchor => native_parameters.friAnchorParameters(.segment_leaf),
        .fri_verifier_control => native_parameters.controlParameters(.segment_leaf),
        .fri_verifier_input => native_parameters.inputParameters(.segment_leaf),
        .qm31_mul, .qm31_inv, .linear_ops => proof_kind.ProofKind.segment_leaf.selectors(),
        .merkle_path => .{},
        else => unreachable,
    };
}
