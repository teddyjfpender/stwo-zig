//! Failure-atomic Tree2 generation for role-0 transcript rows 0--9.

const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const components =
    @import("recursive_common_ethereum_incremental_leaf_transcript_components_v4.zig");
const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const support =
    @import("recursive_common_ethereum_incremental_leaf_transcript_cohort_v4_support.zig");

const air = frontend.recursion.air;
const M31 = stwo_core.fields.m31.M31;

/// Every interaction is fully generated and validated into private storage
/// before the first caller-owned Tree2 column is written.
pub const Generated = struct {
    claims: components.ClaimsV4,
    audits: [10]air.relation_interaction.DomainAudit,
};

pub fn generateAll(
    prepared: anytype,
    relations: *const air.universal_challenges.UniversalRelations,
    destination: []const []M31,
) !Generated {
    const owners = &prepared.components.owners;
    const logs = prepared.components.log_sizes;

    var control = try support.generateWithAudit(
        components.ControlFramework,
        prepared.allocator,
        &owners.control.relation,
        prepared.control,
        logs[0],
        relations,
    );
    defer control.deinit(prepared.allocator);
    var transcript_air = try support.generateWithAudit(
        components.TranscriptAirFramework,
        prepared.allocator,
        &owners.transcript_air.relation,
        prepared.transcript_air,
        logs[1],
        relations,
    );
    defer transcript_air.deinit(prepared.allocator);
    var transcript_binding =
        try support.generateWithAudit(
            components.TranscriptBindingFramework,
            prepared.allocator,
            &owners.transcript_binding.relation,
            prepared.transcript_binding,
            logs[2],
            relations,
        );
    defer transcript_binding.deinit(prepared.allocator);
    var transcript_state =
        try support.generateWithAudit(
            components.TranscriptStateFramework,
            prepared.allocator,
            &owners.transcript_state.relation,
            prepared.transcript_state,
            logs[3],
            relations,
        );
    defer transcript_state.deinit(prepared.allocator);
    var transcript_word =
        try support.generateWithAudit(
            components.TranscriptWordFramework,
            prepared.allocator,
            &owners.transcript_word.relation,
            prepared.transcript_word,
            logs[4],
            relations,
        );
    defer transcript_word.deinit(prepared.allocator);
    var transcript_payload =
        try support.generateWithAudit(
            components.TranscriptPayloadFramework,
            prepared.allocator,
            &owners.transcript_payload.relation,
            prepared.transcript_payload,
            logs[5],
            relations,
        );
    defer transcript_payload.deinit(prepared.allocator);
    var pow_check = try support.generateWithAudit(
        components.PowCheckFramework,
        prepared.allocator,
        &owners.pow_check.relation,
        prepared.pow_check,
        logs[6],
        relations,
    );
    defer pow_check.deinit(prepared.allocator);
    var pow_frame = try support.generateWithAudit(
        components.PowFrameFramework,
        prepared.allocator,
        &owners.pow_frame.relation,
        prepared.pow_frame,
        logs[7],
        relations,
    );
    defer pow_frame.deinit(prepared.allocator);
    var relation_challenge =
        try support.generateWithAudit(
            components.RelationChallengeFramework,
            prepared.allocator,
            &owners.relation_challenge.relation,
            prepared.relation_challenge,
            logs[8],
            relations,
        );
    defer relation_challenge.deinit(prepared.allocator);
    var verifier_randomness =
        try support.generateWithAudit(
            components.VerifierRandomnessFramework,
            prepared.allocator,
            &owners.verifier_randomness.relation,
            prepared.verifier_randomness,
            logs[9],
            relations,
        );
    defer verifier_randomness.deinit(prepared.allocator);

    try copy(
        components.ControlFramework,
        &control.interaction.columns,
        prepared.manifest,
        .control,
        destination,
    );
    try copy(
        components.TranscriptAirFramework,
        &transcript_air.interaction.columns,
        prepared.manifest,
        .transcript_air,
        destination,
    );
    try copy(
        components.TranscriptBindingFramework,
        &transcript_binding.interaction.columns,
        prepared.manifest,
        .transcript_binding,
        destination,
    );
    try copy(
        components.TranscriptStateFramework,
        &transcript_state.interaction.columns,
        prepared.manifest,
        .transcript_state,
        destination,
    );
    try copy(
        components.TranscriptWordFramework,
        &transcript_word.interaction.columns,
        prepared.manifest,
        .transcript_word,
        destination,
    );
    try copy(
        components.TranscriptPayloadFramework,
        &transcript_payload.interaction.columns,
        prepared.manifest,
        .transcript_payload,
        destination,
    );
    try copy(
        components.PowCheckFramework,
        &pow_check.interaction.columns,
        prepared.manifest,
        .pow_check,
        destination,
    );
    try copy(
        components.PowFrameFramework,
        &pow_frame.interaction.columns,
        prepared.manifest,
        .pow_frame,
        destination,
    );
    try copy(
        components.RelationChallengeFramework,
        &relation_challenge.interaction.columns,
        prepared.manifest,
        .relation_challenge,
        destination,
    );
    try copy(
        components.VerifierRandomnessFramework,
        &verifier_randomness.interaction.columns,
        prepared.manifest,
        .verifier_randomness,
        destination,
    );

    return .{ .claims = .{ .values = .{
        control.interaction.claimed_sum,
        transcript_air.interaction.claimed_sum,
        transcript_binding.interaction.claimed_sum,
        transcript_state.interaction.claimed_sum,
        transcript_word.interaction.claimed_sum,
        transcript_payload.interaction.claimed_sum,
        pow_check.interaction.claimed_sum,
        pow_frame.interaction.claimed_sum,
        relation_challenge.interaction.claimed_sum,
        verifier_randomness.interaction.claimed_sum,
    } }, .audits = .{
        control.audit,
        transcript_air.audit,
        transcript_binding.audit,
        transcript_state.audit,
        transcript_word.audit,
        transcript_payload.audit,
        pow_check.audit,
        pow_frame.audit,
        relation_challenge.audit,
        verifier_randomness.audit,
    } };
}

fn copy(
    comptime Framework: type,
    columns: *const [Framework.INTERACTION_COLUMN_COUNT][]M31,
    manifest: *const manifest_mod.Manifest,
    key: manifest_mod.ComponentKey,
    destination: []const []M31,
) !void {
    support.copyInteraction(
        Framework,
        columns,
        try manifest.placement(key),
        destination,
    );
}
