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
pub fn generateAll(
    prepared: anytype,
    relations: *const air.universal_challenges.UniversalRelations,
    destination: []const []M31,
) !components.ClaimsV4 {
    const owners = &prepared.components.owners;
    const logs = prepared.components.log_sizes;

    var control = try components.ControlFramework.generatePrepared(
        prepared.allocator,
        &owners.control.relation,
        prepared.control,
        logs[0],
        relations,
    );
    defer control.deinit(prepared.allocator);
    var transcript_air = try components.TranscriptAirFramework.generatePrepared(
        prepared.allocator,
        &owners.transcript_air.relation,
        prepared.transcript_air,
        logs[1],
        relations,
    );
    defer transcript_air.deinit(prepared.allocator);
    var transcript_binding =
        try components.TranscriptBindingFramework.generatePrepared(
            prepared.allocator,
            &owners.transcript_binding.relation,
            prepared.transcript_binding,
            logs[2],
            relations,
        );
    defer transcript_binding.deinit(prepared.allocator);
    var transcript_state =
        try components.TranscriptStateFramework.generatePrepared(
            prepared.allocator,
            &owners.transcript_state.relation,
            prepared.transcript_state,
            logs[3],
            relations,
        );
    defer transcript_state.deinit(prepared.allocator);
    var transcript_word =
        try components.TranscriptWordFramework.generatePrepared(
            prepared.allocator,
            &owners.transcript_word.relation,
            prepared.transcript_word,
            logs[4],
            relations,
        );
    defer transcript_word.deinit(prepared.allocator);
    var transcript_payload =
        try components.TranscriptPayloadFramework.generatePrepared(
            prepared.allocator,
            &owners.transcript_payload.relation,
            prepared.transcript_payload,
            logs[5],
            relations,
        );
    defer transcript_payload.deinit(prepared.allocator);
    var pow_check = try components.PowCheckFramework.generatePrepared(
        prepared.allocator,
        &owners.pow_check.relation,
        prepared.pow_check,
        logs[6],
        relations,
    );
    defer pow_check.deinit(prepared.allocator);
    var pow_frame = try components.PowFrameFramework.generatePrepared(
        prepared.allocator,
        &owners.pow_frame.relation,
        prepared.pow_frame,
        logs[7],
        relations,
    );
    defer pow_frame.deinit(prepared.allocator);
    var relation_challenge =
        try components.RelationChallengeFramework.generatePrepared(
            prepared.allocator,
            &owners.relation_challenge.relation,
            prepared.relation_challenge,
            logs[8],
            relations,
        );
    defer relation_challenge.deinit(prepared.allocator);
    var verifier_randomness =
        try components.VerifierRandomnessFramework.generatePrepared(
            prepared.allocator,
            &owners.verifier_randomness.relation,
            prepared.verifier_randomness,
            logs[9],
            relations,
        );
    defer verifier_randomness.deinit(prepared.allocator);

    try copy(
        components.ControlFramework,
        &control.columns,
        prepared.manifest,
        .control,
        destination,
    );
    try copy(
        components.TranscriptAirFramework,
        &transcript_air.columns,
        prepared.manifest,
        .transcript_air,
        destination,
    );
    try copy(
        components.TranscriptBindingFramework,
        &transcript_binding.columns,
        prepared.manifest,
        .transcript_binding,
        destination,
    );
    try copy(
        components.TranscriptStateFramework,
        &transcript_state.columns,
        prepared.manifest,
        .transcript_state,
        destination,
    );
    try copy(
        components.TranscriptWordFramework,
        &transcript_word.columns,
        prepared.manifest,
        .transcript_word,
        destination,
    );
    try copy(
        components.TranscriptPayloadFramework,
        &transcript_payload.columns,
        prepared.manifest,
        .transcript_payload,
        destination,
    );
    try copy(
        components.PowCheckFramework,
        &pow_check.columns,
        prepared.manifest,
        .pow_check,
        destination,
    );
    try copy(
        components.PowFrameFramework,
        &pow_frame.columns,
        prepared.manifest,
        .pow_frame,
        destination,
    );
    try copy(
        components.RelationChallengeFramework,
        &relation_challenge.columns,
        prepared.manifest,
        .relation_challenge,
        destination,
    );
    try copy(
        components.VerifierRandomnessFramework,
        &verifier_randomness.columns,
        prepared.manifest,
        .verifier_randomness,
        destination,
    );

    return .{ .values = .{
        control.claimed_sum,
        transcript_air.claimed_sum,
        transcript_binding.claimed_sum,
        transcript_state.claimed_sum,
        transcript_word.claimed_sum,
        transcript_payload.claimed_sum,
        pow_check.claimed_sum,
        pow_frame.claimed_sum,
        relation_challenge.claimed_sum,
        verifier_randomness.claimed_sum,
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
