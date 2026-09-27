//! Typed component construction for binary transcript rows.

const air = @import("air/mod.zig");
const adapter = air.universal_typed_component;
const binding = air.universal_relation_binding;
const manifest_mod = air.universal_adapter_manifest;
const universal = air.universal_challenges;

const ControlRelation = binding.Binding(air.control);
const TranscriptAirRelation = binding.Binding(air.transcript_air);
const TranscriptBindingRelation = binding.Binding(air.transcript_binding);
const TranscriptStateRelation = binding.Binding(air.transcript_state);
const TranscriptWordRelation = binding.Binding(air.transcript_word);
const TranscriptPayloadRelation = binding.Binding(air.transcript_payload);
const PowCheckRelation = binding.Binding(air.pow_check);
const PowFrameRelation = binding.Binding(air.pow_frame);
const RelationChallengeRelation = binding.Binding(air.relation_challenge);
const VerifierRandomnessRelation = binding.Binding(air.verifier_randomness);

const ControlAdapter = adapter.Component(air.control, ControlRelation);
const TranscriptAirAdapter = adapter.Component(air.transcript_air, TranscriptAirRelation);
const TranscriptBindingAdapter = adapter.Component(air.transcript_binding, TranscriptBindingRelation);
const TranscriptStateAdapter = adapter.Component(air.transcript_state, TranscriptStateRelation);
const TranscriptWordAdapter = adapter.Component(air.transcript_word, TranscriptWordRelation);
const TranscriptPayloadAdapter = adapter.Component(air.transcript_payload, TranscriptPayloadRelation);
const PowCheckAdapter = adapter.Component(air.pow_check, PowCheckRelation);
const PowFrameAdapter = adapter.Component(air.pow_frame, PowFrameRelation);
const RelationChallengeAdapter = adapter.Component(air.relation_challenge, RelationChallengeRelation);
const VerifierRandomnessAdapter = adapter.Component(air.verifier_randomness, VerifierRandomnessRelation);

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
