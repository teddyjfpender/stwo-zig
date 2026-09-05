const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const subject =
    @import("recursive_common_canonical_empty_campaign_universal_proof_v2.zig");
const source_mod =
    @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const field_public =
    @import("recursive_common_canonical_empty_campaign_field_public_v2.zig");
const manifest_mod =
    @import("recursive_common_canonical_empty_campaign_universal_manifest_v2.zig");
const cohort_mod =
    @import("recursive_common_canonical_empty_campaign_universal_cohort_v2.zig");
const graph_mod =
    @import("recursive_common_canonical_empty_campaign_composition_graph_v2.zig");
const capture_mod =
    @import("recursive_common_canonical_empty_campaign_composition_capture_v2.zig");
const fold_child =
    @import("recursive_common_canonical_empty_campaign_fold_child_v2.zig");
const prefinal_child =
    @import("recursive_common_canonical_empty_campaign_prefinal_fold_child_v2.zig");
const prefinal_union =
    @import("recursive_pipeline_campaign_prefinal_fold_lease_v2.zig");
const worker_backend =
    @import("recursive_pipeline_worker_campaign_canonical_empty_v2.zig");
const prefinal_worker =
    @import("recursive_pipeline_worker_campaign_canonical_empty_prefinal_v2.zig");
const shape_mod = @import("recursive_pipeline_campaign_shape_v2.zig");
const leaf_mod = @import("recursive_temporal_leaf_or_empty_v1.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const secure_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");

const recursion = frontend.recursion;
const span = recursion.span_statement;

test "campaign canonical-empty structural q193 family is distinct and unrouteable" {
    std.testing.refAllDeclsRecursive(subject);
    std.testing.refAllDeclsRecursive(cohort_mod);
    std.testing.refAllDeclsRecursive(graph_mod);
    std.testing.refAllDeclsRecursive(capture_mod);
    std.testing.refAllDeclsRecursive(fold_child);
    std.testing.refAllDeclsRecursive(prefinal_child);
    std.testing.refAllDeclsRecursive(prefinal_union);
    std.testing.refAllDeclsRecursive(worker_backend);
    std.testing.refAllDeclsRecursive(prefinal_worker);
    try std.testing.expectEqual(@as(u16, 2), subject.SCHEMA_VERSION);
    try std.testing.expectEqual(@as(usize, 173), field_public.POSEIDON_CALL_COUNT);
    try std.testing.expectEqual(@as(u32, 8), manifest_mod.POSEIDON_LOG_SIZE);
    try std.testing.expectEqual(
        @as(u8, 6),
        @intFromEnum(secure_artifact.SourceKindV1.canonical_empty_campaign_v2),
    );
    try std.testing.expectEqual(
        @as(u8, 8),
        @intFromEnum(secure_engine.TranscriptFlavorV1.canonical_empty_campaign_v2),
    );
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(subject.PROOF_REQUIRES_PADDING_TARGET);
    try std.testing.expect(!subject.PROOF_REQUIRES_FINAL_REMINT);
    try std.testing.expect(subject.FOLD_CHILD_REQUIRES_FINAL_REMINT);
    try std.testing.expect(!fold_child.PRODUCTION_ACTIVATION);
    try std.testing.expect(!fold_child.SERIALIZABLE_FRESH_CAPABILITY);
    try std.testing.expect(!prefinal_child.PRODUCTION_ACTIVATION);
    try std.testing.expect(!prefinal_child.SERIALIZABLE_FRESH_CAPABILITY);
    try std.testing.expect(worker_backend.CRYPTO_IMPLEMENTED);
    try std.testing.expect(!worker_backend.Q193_GENUINE_GATE_GREEN);
    try std.testing.expect(!worker_backend.Backend.available);
    try std.testing.expect(!worker_backend.PRODUCTION_ACTIVATION);
    try std.testing.expect(!worker_backend.ROUTER_ACTIVATION);
    try std.testing.expect(!prefinal_worker.Q193_GENUINE_GATE_GREEN);
    try std.testing.expect(!prefinal_worker.PRODUCTION_ACTIVATION);
    try std.testing.expect(!prefinal_worker.ROUTER_ACTIVATION);
    try std.testing.expect(
        prefinal_worker.NODE_PUBLICATION_REQUIRES_FINAL_REMINT,
    );
    try std.testing.expect(!@hasDecl(worker_backend.Backend.LeasePayload, "encode"));
    try std.testing.expect(!@hasDecl(worker_backend.Backend.LeasePayload, "decode"));
}

test "campaign canonical-empty schedule binds runtime shape and rejects legacy session range" {
    const shape = try shape_mod.CampaignShapeAuthorityV2.init(
        sha(10),
        sha(20),
        13,
    );
    var leaf: leaf_mod.LeafOrEmptyV1 = undefined;
    try leaf_mod.admitEmptyInto(
        &leaf,
        try fixtureJob(13),
        13,
        digest(101),
        digest(111),
        digest(121),
    );
    const source = try source_mod.SourceArtifactV2.seal(&shape, &leaf);
    const bytes = try source.encodeCanonical(&shape);
    const cold = try source_mod.ColdInputV2.open(&shape, &bytes);
    const schedule = try field_public.PoseidonScheduleV2.build(&cold);
    try schedule.validateAgainst(&cold);
    try std.testing.expectEqual(@as(usize, 173), schedule.calls.len);
    try std.testing.expectEqual(@as(u16, 62), schedule.phases[1].call_count);

    var statement_words: span.StatementWords = undefined;
    for (&statement_words, source.statement_words) |*destination, word|
        destination.* = @import("stwo_core").fields.m31.M31.fromCanonical(word);
    const campaign_authority = secure_artifact.CampaignCanonicalEmptySessionAuthorityV2{
        .ingress_identity_sha256 = sha(31),
        .parent_statement_words = statement_words,
        .profile_identity_sha256 = sha(32),
        .child_composition_manifest_sha256 = sha(33),
        .parent_outer_manifest_sha256 = sha(34),
        .verification_key_id = digest(131),
        .next_parent_vk_id = digest(141),
        .air_program_id = digest(151),
    };
    try campaign_authority.validate();
    const session = try secure_artifact.SessionV1
        .initCanonicalEmptyCampaignV2(campaign_authority);
    try session.validate();
    try std.testing.expectEqual(
        secure_artifact.SourceKindV1.canonical_empty_campaign_v2,
        session.source_kind,
    );
    var wrong_kind = session;
    wrong_kind.source_kind = .canonical_empty_wrapper_v1;
    try std.testing.expectError(
        error.InvalidSecureTemporalParentSession,
        wrong_kind.validate(),
    );

    const legacy = secure_artifact.CanonicalEmptySessionAuthorityV1{
        .ingress_identity_sha256 = campaign_authority.ingress_identity_sha256,
        .parent_statement_words = campaign_authority.parent_statement_words,
        .profile_identity_sha256 = campaign_authority.profile_identity_sha256,
        .child_composition_manifest_sha256 = campaign_authority.child_composition_manifest_sha256,
        .parent_outer_manifest_sha256 = campaign_authority.parent_outer_manifest_sha256,
        .verification_key_id = campaign_authority.verification_key_id,
        .next_parent_vk_id = campaign_authority.next_parent_vk_id,
        .air_program_id = campaign_authority.air_program_id,
    };
    try std.testing.expectError(
        error.InvalidSecureTemporalParentSession,
        legacy.validate(),
    );
}

test "campaign q193 entrypoint fails closed before proof without final remint" {
    const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
    const shape = try shape_mod.CampaignShapeAuthorityV2.init(
        sha(210),
        sha(220),
        13,
    );
    const invalid_final = std.mem.zeroes(final_mod.FinalRemint);
    const invalid = final_mod.CampaignFinalRemintAuthorityV2{
        .shape = &shape,
        .final_remint = &invalid_final,
        .binding_identity_sha256 = [_]u8{0} ** 32,
    };
    try std.testing.expectError(
        error.InvalidFinalRemintAuthority,
        subject.proveAndColdVerify(
            std.testing.allocator,
            &invalid,
            &.{},
            .{ .worker_count = 1 },
        ),
    );
}

fn fixtureJob(segment_count: u32) !span.JobContext {
    var initial_registers = [_]u32{0} ** 32;
    var final_registers = [_]u32{0} ** 32;
    initial_registers[1] = 7;
    final_registers[1] = 9;
    return span.JobContext.init(
        try span.CompleteExecution.init(
            recursion.protocol.PROTOCOL_ID_WORDS,
            digest(51),
            try span.MachineState.init(
                0x1000,
                initial_registers,
                digest(11),
                digest(21),
            ),
            try span.MachineState.init(
                0x2000,
                final_registers,
                digest(31),
                digest(41),
            ),
            digest(61),
            digest(71),
            88_000,
        ),
        segment_count,
    );
}

fn digest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn sha(seed: u32) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = @truncate(seed + @as(u32, @intCast(index)));
    return result;
}
