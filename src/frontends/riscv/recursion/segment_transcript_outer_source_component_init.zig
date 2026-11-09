//! Typed component construction for segment transcript rows.

const adapter = @import("stwo_riscv_air_lang").modules.framework_universal_typed_component;
const binding = @import("stwo_riscv_air_lang").modules.framework_universal_relation_binding;
const manifest_mod = @import("stwo_riscv_air_lang").modules.framework_universal_adapter_manifest;
const universal = @import("stwo_riscv_air_lang").modules.framework_universal_challenges;

const ControlRelation = binding.Binding(@import("stwo_riscv_air_lang").modules.framework_control);
const TranscriptAirRelation = binding.Binding(@import("stwo_riscv_recursion_air").modules.transcript_air);
const TranscriptBindingRelation = binding.Binding(@import("stwo_riscv_recursion_air").modules.transcript_binding);
const TranscriptStateRelation = binding.Binding(@import("stwo_riscv_recursion_air").modules.transcript_state);
const TranscriptWordRelation = binding.Binding(@import("stwo_riscv_recursion_air").modules.transcript_word);
const TranscriptPayloadRelation = binding.Binding(@import("stwo_riscv_recursion_air").modules.transcript_payload);
const PowCheckRelation = binding.Binding(@import("stwo_riscv_recursion_air").modules.pow_check);
const PowFrameRelation = binding.Binding(@import("stwo_riscv_recursion_air").modules.pow_frame);
const RelationChallengeRelation = binding.Binding(@import("stwo_riscv_recursion_air").modules.relation_challenge);
const VerifierRandomnessRelation = binding.Binding(@import("stwo_riscv_recursion_air").modules.verifier_randomness);

const ControlAdapter = adapter.Component(@import("stwo_riscv_air_lang").modules.framework_control, ControlRelation);
const TranscriptAirAdapter = adapter.Component(@import("stwo_riscv_recursion_air").modules.transcript_air, TranscriptAirRelation);
const TranscriptBindingAdapter = adapter.Component(@import("stwo_riscv_recursion_air").modules.transcript_binding, TranscriptBindingRelation);
const TranscriptStateAdapter = adapter.Component(@import("stwo_riscv_recursion_air").modules.transcript_state, TranscriptStateRelation);
const TranscriptWordAdapter = adapter.Component(@import("stwo_riscv_recursion_air").modules.transcript_word, TranscriptWordRelation);
const TranscriptPayloadAdapter = adapter.Component(@import("stwo_riscv_recursion_air").modules.transcript_payload, TranscriptPayloadRelation);
const PowCheckAdapter = adapter.Component(@import("stwo_riscv_recursion_air").modules.pow_check, PowCheckRelation);
const PowFrameAdapter = adapter.Component(@import("stwo_riscv_recursion_air").modules.pow_frame, PowFrameRelation);
const RelationChallengeAdapter = adapter.Component(@import("stwo_riscv_recursion_air").modules.relation_challenge, RelationChallengeRelation);
const VerifierRandomnessAdapter = adapter.Component(@import("stwo_riscv_recursion_air").modules.verifier_randomness, VerifierRandomnessRelation);

pub fn init(
    self: anytype,
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
    claims: anytype,
    comptime Components: type,
    comptime rowIndex: anytype,
) !Components {
    try self.validateManifest(manifest);
    try relations.validate();
    return .{
        .control = try ControlAdapter.init(
            &self.owners.control.definition,
            self.owners.control.relation,
            manifest,
            .control,
            self.log_sizes[rowIndex(.control)],
            self.parameters.control,
            relations,
            claims.control,
        ),
        .transcript_air = try TranscriptAirAdapter.init(
            &self.owners.transcript_air.definition,
            self.owners.transcript_air.relation,
            manifest,
            .transcript_air,
            self.log_sizes[rowIndex(.transcript_air)],
            self.parameters.transcript_air,
            relations,
            claims.transcript_air,
        ),
        .transcript_binding = try TranscriptBindingAdapter.init(
            &self.owners.transcript_binding.definition,
            self.owners.transcript_binding.relation,
            manifest,
            .transcript_binding,
            self.log_sizes[rowIndex(.transcript_binding)],
            self.parameters.transcript_binding,
            relations,
            claims.transcript_binding,
        ),
        .transcript_state = try TranscriptStateAdapter.init(
            &self.owners.transcript_state.definition,
            self.owners.transcript_state.relation,
            manifest,
            .transcript_state,
            self.log_sizes[rowIndex(.transcript_state)],
            self.parameters.transcript_state,
            relations,
            claims.transcript_state,
        ),
        .transcript_word = try TranscriptWordAdapter.init(
            &self.owners.transcript_word.definition,
            self.owners.transcript_word.relation,
            manifest,
            .transcript_word,
            self.log_sizes[rowIndex(.transcript_word)],
            self.parameters.transcript_word,
            relations,
            claims.transcript_word,
        ),
        .transcript_payload = try TranscriptPayloadAdapter.init(
            &self.owners.transcript_payload.definition,
            self.owners.transcript_payload.relation,
            manifest,
            .transcript_payload,
            self.log_sizes[rowIndex(.transcript_payload)],
            self.parameters.transcript_payload,
            relations,
            claims.transcript_payload,
        ),
        .pow_check = try PowCheckAdapter.init(
            &self.owners.pow_check.definition,
            self.owners.pow_check.relation,
            manifest,
            .pow_check,
            self.log_sizes[rowIndex(.pow_check)],
            self.parameters.pow_check,
            relations,
            claims.pow_check,
        ),
        .pow_frame = try PowFrameAdapter.init(
            &self.owners.pow_frame.definition,
            self.owners.pow_frame.relation,
            manifest,
            .pow_frame,
            self.log_sizes[rowIndex(.pow_frame)],
            self.parameters.pow_frame,
            relations,
            claims.pow_frame,
        ),
        .relation_challenge = try RelationChallengeAdapter.init(
            &self.owners.relation_challenge.definition,
            self.owners.relation_challenge.relation,
            manifest,
            .relation_challenge,
            self.log_sizes[rowIndex(.relation_challenge)],
            self.parameters.relation_challenge,
            relations,
            claims.relation_challenge,
        ),
        .verifier_randomness = try VerifierRandomnessAdapter.init(
            &self.owners.verifier_randomness.definition,
            self.owners.verifier_randomness.relation,
            manifest,
            .verifier_randomness,
            self.log_sizes[rowIndex(.verifier_randomness)],
            self.parameters.verifier_randomness,
            relations,
            claims.verifier_randomness,
        ),
    };
}
