const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const subject = @import("recursive_common_fold_field_public_v2.zig");
const artifact = @import("recursive_node_artifact_v1.zig");
const field_public = @import("recursive_field_node_public_v2.zig");
const suffix_boundary =
    @import("recursive_common_fold_suffix_input_boundary_v2.zig");
const suffix_closure =
    @import("recursive_common_fold_suffix_closure_v2.zig");

const recursion = frontend.recursion;
const QM31 = stwo_core.fields.qm31.QM31;

comptime {
    _ = @import("recursive_field_statement_word_v3_test.zig");
}

test "common fold derives exact field parent and 116 Poseidon calls" {
    try @import("recursive_fixed_wire_v3_test.zig").exercise();
    try checkClaimTranscript();
    try @import("recursive_secure_transcript_rows_v1_test.zig").exerciseProviderPartialFixture();
    const left = try emptyLeaf(210, "common-fold-left");
    const right = try emptyLeaf(211, "common-fold-right");
    try @import("recursive_common_canonical_empty_boundary_v3_test.zig").exercise(&left);
    const coordinate = try artifact.TaskCoordinateV1.init(1, 105);
    const schedule = try subject.PoseidonScheduleV2.build(
        &left,
        &right,
        coordinate,
    );
    try schedule.validateAgainst(&left, &right, coordinate);
    try checkSessionTranscript(&schedule.parent);
    try checkRecordedPublicBoundary(&schedule.parent);
    try checkTranscriptProviderBoundary(schedule.callsSlice());
    try @import("recursive_common_fold_public_hash_v3_test.zig").exercise(&left, &right, &schedule);
    try std.testing.expectEqual(
        @as(usize, subject.POSEIDON_CALL_COUNT),
        schedule.callsSlice().len,
    );
    try std.testing.expectEqual(
        @as(u16, subject.STATEMENT_CALL_COUNT),
        schedule.phases[@intFromEnum(subject.PhaseV2.statement)].call_count,
    );
    try std.testing.expectEqual(
        @as(u16, subject.SOURCE_CALL_COUNT),
        schedule.phases[@intFromEnum(subject.PhaseV2.source)].call_count,
    );
    try std.testing.expectEqual(
        @as(u16, subject.SUBTREE_CALL_COUNT),
        schedule.phases[@intFromEnum(subject.PhaseV2.subtree)].call_count,
    );
    try std.testing.expectEqual(
        @as(u16, subject.OUTPUT_CALL_COUNT),
        schedule.phases[@intFromEnum(subject.PhaseV2.output)].call_count,
    );
    const source_preimage = subject.parentSourcePreimage(&left, &right);
    try std.testing.expectEqual(
        recursion.poseidon2_channel.hashCanonicalU32s(
            &source_preimage,
            field_public.PARENT_SOURCE_DOMAIN,
        ),
        schedule.parent.source_digest,
    );
    try schedule.parent.validateParentAgainst(&left, &right);
}

fn checkRecordedPublicBoundary(node: *const field_public.NodePublicV2) !void {
    const output = @import("recursive_common_fold_public_output_v3.zig");
    const recorder = recursion.air.composition_graph_recorder;
    const M31 = stwo_core.fields.m31.M31;
    const allocator = std.testing.allocator;
    const words = try node.canonicalAirWords();
    const relations = recursion.air.universal_challenges.UniversalRelations.dummy();
    const boundary = try output.derive(node, &relations);
    var builder = recorder.Builder.init(allocator);
    defer builder.deinit();
    var symbolic: [field_public.AIR_WORD_COUNT]recorder.Scalar = undefined;
    for (&symbolic) |*word| word.* = (try builder.input()).value;
    const z = (try builder.input()).value;
    const alpha = (try builder.input()).value;
    const claimed = (try builder.input()).value;
    try builder.activate();
    errdefer if (builder.active) builder.deactivate();
    var draws: [recursion.air.universal_challenges.RELATION_COUNT][2]recorder.Scalar = undefined;
    for (&draws, relations.elements) |*draw, element|
        draw.* = .{ recorder.Scalar.fromSecure(element.z), recorder.Scalar.fromSecure(element.alpha) };
    const domain = @intFromEnum(frontend.air.relation.Domain.recursion_statement_word);
    draws[domain] = .{ z, alpha };
    const challenges = try recorder.ChallengeSet.init(draws);
    try builder.constrainZero((try output.recordSum(&symbolic, &challenges)).sub(claimed));
    try builder.check();
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const values = try allocator.alloc(QM31, circuit.nodes.len);
    defer allocator.free(values);
    var inputs: [field_public.AIR_WORD_COUNT + 3]QM31 = undefined;
    for (words, inputs[0..words.len]) |word, *value| value.* = QM31.fromBase(M31.fromCanonical(word));
    inputs[words.len..].* = .{ relations.elements[domain].z, relations.elements[domain].alpha, boundary.claimed_sum };
    try circuit.evaluateInto(&inputs, values);
    for (&inputs) |*input| {
        const original = input.*;
        input.* = original.add(QM31.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(&inputs, values));
        input.* = original;
    }
    const relation = try relations.getExact(.recursion_statement_word);
    const first_denominator = try relation.combineBase(&.{ M31.fromCanonical(recursion.air.field_public_word_v3.PUBLIC_SCOPE), M31.zero(), M31.fromCanonical(words[0]) });
    inputs[words.len] = relation.z.add(first_denominator);
    try std.testing.expectError(error.DivisionByZero, circuit.evaluateInto(&inputs, values));
    std.debug.print("COMMON_FOLD_PUBLIC_BOUNDARY_GRAPH words=450 word_challenge_claim_mutations=453 zero_denominator_rejected=true\n", .{});
}

fn checkClaimTranscript() !void {
    const manifest_mod = @import("recursive_common_fold_universal_manifest_v2.zig");
    var logs = [_]u32{4} ** manifest_mod.COMPONENT_COUNT;
    logs[@intFromEnum(manifest_mod.ComponentKey.poseidon2)] = subject.MINIMUM_POSEIDON_LOG_SIZE;
    logs[@intFromEnum(manifest_mod.ComponentKey.range_check_8_8)] = recursion.air.range_check_8_8_bridge.LOG_SIZE;
    const manifest = try manifest_mod.buildForDerivedLogSizes(logs);
    var claims = try manifest_mod.ClaimVector.init(&manifest);
    for (manifest.roster_rows[0..manifest.roster_count]) |row|
        try claims.bind(@enumFromInt(row), QM31.fromU32Unchecked(@as(u32, row) + 1, 2, 3, 4));
    try claims.sealClaims(&manifest);
    const Channel = recursion.poseidon2_channel.Channel;
    var values = Channel{};
    try claims.mixInteractionClaimValues(&manifest, &values);
    var extended = values;
    var seal_words: [8]u32 = undefined;
    for (&seal_words, 0..) |*word, index|
        word.* = std.mem.readInt(u32, claims.seal[4 * index ..][0..4], .little);
    extended.mixU32s(&seal_words);
    var legacy = Channel{};
    try claims.mixInteractionClaims(&manifest, &legacy);
    try std.testing.expectEqualDeep(legacy, extended);
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        var changed = claims;
        changed.values[row] = changed.values[row].add(QM31.one());
        try changed.sealClaims(&manifest);
        var changed_channel = Channel{};
        try changed.mixInteractionClaimValues(&manifest, &changed_channel);
        try std.testing.expect(!std.meta.eql(values, changed_channel));
    }
    var stale = claims;
    stale.seal[0] ^= 1;
    var untouched = Channel{};
    try std.testing.expectError(error.ClaimSealMismatch, stale.mixInteractionClaimValues(&manifest, &untouched));
    try std.testing.expectEqualDeep(Channel{}, untouched);
    var missing = claims;
    missing.bound_mask ^= 1;
    try std.testing.expectError(error.ClaimMissing, missing.mixInteractionClaimValues(&manifest, &untouched));
    try std.testing.expectEqualDeep(Channel{}, untouched);
    std.debug.print("COMMON_FOLD_CLAIM_TRANSCRIPT bound_claims=36 legacy_suffix_preserved=true invalid_claims_rejected_before_mix=true\n", .{});
}

test "common fold schedule rejects call child order and coordinate drift" {
    const left = try emptyLeaf(210, "common-fold-left");
    const right = try emptyLeaf(211, "common-fold-right");
    const coordinate = try artifact.TaskCoordinateV1.init(1, 105);
    const schedule = try subject.PoseidonScheduleV2.build(
        &left,
        &right,
        coordinate,
    );

    var changed_call = schedule;
    changed_call.calls[0].input[0] ^= 1;
    try std.testing.expectError(
        error.CommonFoldFieldScheduleMismatch,
        changed_call.validateAgainst(&left, &right, coordinate),
    );
    try std.testing.expectError(
        error.CommonFoldPublicInputMismatch,
        subject.PoseidonScheduleV2.build(&right, &left, coordinate),
    );
    try std.testing.expectError(
        error.CommonFoldPublicInputMismatch,
        subject.PoseidonScheduleV2.build(
            &left,
            &right,
            try artifact.TaskCoordinateV1.init(2, 52),
        ),
    );

    var domains: [suffix_boundary.DOMAIN_COUNT]suffix_boundary.DomainEvidenceV2 = undefined;
    for (
        &domains,
        suffix_boundary.DOMAINS,
        suffix_boundary.ROW_MASKS,
        0..,
    ) |*domain, relation_domain, source_row_mask, ordinal| {
        domain.* = .{
            .domain = relation_domain,
            .source_row_mask = source_row_mask,
            .tuple_count = 1,
            .claimed_sum = QM31.fromU32Unchecked(
                @intCast(ordinal + 5),
                0,
                0,
                0,
            ),
            .tuple_provenance_sha256 = [_]u8{1} ** 32,
        };
    }
    const field_public_claim = QM31.fromU32Unchecked(3, 0, 0, 0);
    const framework =
        suffix_closure.frameworkBoundarySumExceptWireAssumeValidated(
            field_public_claim,
            &domains,
        );
    var expected = field_public_claim;
    for (domains) |domain| {
        expected = expected.add(domain.claimed_sum);
    }
    try std.testing.expect(framework.eql(expected));

    var changed_verifier = domains;
    for (&changed_verifier) |*domain| {
        if (domain.domain == .recursion_verifier_input_word)
            domain.claimed_sum = QM31.fromU32Unchecked(101, 0, 0, 0);
    }
    try std.testing.expect(!framework.eql(
        suffix_closure.frameworkBoundarySumExceptWireAssumeValidated(
            field_public_claim,
            &changed_verifier,
        ),
    ));

    var changed_suffix = domains;
    for (&changed_suffix) |*domain| {
        if (domain.domain == .recursion_transcript_payload_word)
            domain.claimed_sum = QM31.fromU32Unchecked(103, 0, 0, 0);
    }
    try std.testing.expect(!framework.eql(
        suffix_closure.frameworkBoundarySumExceptWireAssumeValidated(
            field_public_claim,
            &changed_suffix,
        ),
    ));
}

pub fn emptyLeaf(index: u32, label: []const u8) !field_public.NodePublicV2 {
    const job = try fixtureJob();
    const statement = try recursion.span_statement.SpanStatement.emptyLeaf(
        job,
        index,
    );
    const words = try statement.canonicalWords();
    var canonical: [field_public.STATEMENT_WORD_COUNT]u32 = undefined;
    for (&canonical, words) |*destination, word|
        destination.* = word.toU32();
    return field_public.NodePublicV2.initLeaf(
        try artifact.TaskCoordinateV1.init(0, index),
        canonical,
        recursion.poseidon2_channel.hashBytes(label, 0x464f_4c44),
    );
}

fn fixtureJob() !recursion.span_statement.JobContext {
    const initial = try recursion.span_statement.MachineState.init(
        0,
        [_]u32{0} ** 32,
        [_]u32{1} ** 8,
        [_]u32{2} ** 8,
    );
    const final = try recursion.span_statement.MachineState.init(
        4,
        [_]u32{0} ** 32,
        [_]u32{3} ** 8,
        [_]u32{4} ** 8,
    );
    const complete = try recursion.span_statement.CompleteExecution.init(
        recursion.protocol.PROTOCOL_ID_WORDS,
        [_]u32{5} ** 8,
        initial,
        final,
        [_]u32{6} ** 8,
        [_]u32{7} ** 8,
        8,
    );
    return recursion.span_statement.JobContext.init(complete, 210);
}

fn checkTranscriptProviderBoundary(statement: anytype) !void {
    const layout_mod = @import("recursive_common_fold_poseidon_schedule_v2.zig");
    const closure = @import("recursive_common_fold_field_public_closure_v2.zig");
    const relations = recursion.air.universal_challenges.UniversalRelations.dummy();
    const providers = try recursion.air.universal_shared_provider.SharedProviderRelations.init(&relations);
    const source_identity = [_]u8{1} ** 32;
    const old_layout = try layout_mod.Layout.initBoundary(statement);
    const old_claim = try closure.derive(statement, &old_layout, source_identity, 7, &providers);
    var calls: [118]layout_mod.Call = undefined;
    calls[0] = statement[0];
    calls[1] = statement[1];
    @memcpy(calls[2..], statement);
    const layout = try layout_mod.Layout.initTranscriptBoundary(2, &calls);
    try std.testing.expectEqual(layout_mod.TRANSCRIPT_SCHEMA_VERSION, layout.schema_version);
    const boundary = try closure.derive(&calls, &layout, source_identity, 7, &providers);
    try std.testing.expectEqualDeep(old_claim.claimed_sum, boundary.claimed_sum);
    try std.testing.expect(!std.mem.eql(u8, &old_claim.identity_sha256, &boundary.identity_sha256));
    var gap = layout;
    gap.transcript.end = 1;
    try std.testing.expectError(error.CommonFoldPoseidonScheduleMismatch, gap.validate(&calls));
    var downgraded = layout;
    downgraded.schema_version = layout_mod.SCHEMA_VERSION;
    try std.testing.expectError(error.CommonFoldPoseidonScheduleMismatch, downgraded.validate(&calls));
    var complete_calls: [119]layout_mod.Call = undefined;
    @memcpy(complete_calls[0..118], &calls);
    complete_calls[118] = statement[0];
    const complete = try layout_mod.Layout.initComplete(2, statement.len, 1, &complete_calls);
    try complete.validate(&complete_calls);
    try std.testing.expectEqual(@as(usize, 1), try complete.verifier_core.count());
    try std.testing.expectError(error.CommonFoldPoseidonScheduleMismatch, layout_mod.Layout.initComplete(2, statement.len, 0, &calls));
}

fn checkSessionTranscript(parent: *const field_public.NodePublicV2) !void {
    const session_mod = @import("recursive_temporal_secure_parent_artifact_v1.zig");
    const manifest_mod = @import("recursive_common_fold_universal_manifest_v2.zig");
    const program_mod = @import("recursive_secure_transcript_program_v1.zig");
    const M31 = stwo_core.fields.m31.M31;
    const Channel = recursion.poseidon2_channel.Channel;
    var logs = [_]u32{4} ** manifest_mod.COMPONENT_COUNT;
    logs[34] = subject.MINIMUM_POSEIDON_LOG_SIZE;
    logs[35] = recursion.air.range_check_8_8_bridge.LOG_SIZE;
    const manifest = try manifest_mod.buildForDerivedLogSizes(logs);
    var authority = session_mod.CommonFoldSessionAuthorityV2{
        .ingress_identity_sha256 = [_]u8{1} ** 32,
        .parent_statement_words = undefined,
        .profile_identity_sha256 = try manifest_mod.profileIdentityForDerivedManifest(&manifest, logs),
        .child_composition_manifest_sha256 = [_]u8{2} ** 32,
        .parent_outer_manifest_sha256 = manifest.seal,
        .verification_key_id = try manifest_mod.verificationKeyIdForDerivedManifest(&manifest, logs),
        .next_parent_vk_id = try manifest_mod.nextParentVkIdForDerivedManifest(&manifest, logs),
        .air_program_id = try manifest_mod.airProgramIdForDerivedManifest(&manifest, logs),
    };
    for (parent.statement_words, &authority.parent_statement_words) |word, *dst| dst.* = M31.fromCanonical(word);
    const session = try session_mod.SessionV1.initCommonFoldFieldV2(authority);
    var actual = Channel{};
    try session.mixFieldInto(&actual);
    var expected = Channel{};
    expected.mixU32s(&try session_mod.fieldSessionTranscriptHeader(session.source_kind, session.protocol));
    expected.mixU32s(&authority.verification_key_id);
    expected.mixU32s(&authority.next_parent_vk_id);
    expected.mixU32s(&authority.air_program_id);
    try std.testing.expectEqualDeep(expected, actual);
    inline for (.{ "verification_key_id", "next_parent_vk_id", "air_program_id" }) |field| for (0..8) |word| {
        var changed = authority;
        @field(changed, field)[word] = (@field(changed, field)[word] + 1) % stwo_core.fields.m31.Modulus;
        const altered = try session_mod.SessionV1.initCommonFoldFieldV2(changed);
        var channel = Channel{};
        try altered.mixFieldInto(&channel);
        try std.testing.expect(!std.meta.eql(actual, channel));
    };
    var legacy = Channel{};
    try session.mixInto(&legacy);
    var legacy_expected = Channel{};
    legacy_expected.mixU32s(&session_mod.sessionTranscriptHeader(session.protocol));
    var seal_words: [8]u32 = undefined;
    for (&seal_words, 0..) |*word, index| word.* = std.mem.readInt(u32, session.identity_sha256[index * 4 ..][0..4], .little);
    legacy_expected.mixU32s(&seal_words);
    try std.testing.expectEqualDeep(legacy_expected, legacy);
    var stale = session;
    stale.identity_sha256[0] ^= 1;
    var untouched = Channel{};
    try std.testing.expectError(error.InvalidSecureTemporalParentSession, stale.mixFieldInto(&untouched));
    try std.testing.expectEqualDeep(Channel{}, untouched);

    // Geometry-only fixture checks program literals; it admits no proof.
    const shape = .{
        .commitments = [_][8]u32{.{0} ** 8} ** 4,
        .sampled_values = [_]QM31{QM31.zero()},
        .fri = .{ .layers = [_]u8{0} },
        .last_layer_coefficients = [_]QM31{QM31.zero()},
        .queries = .{ .raw = [_]u32{0} ** 193 },
    };
    var program = try program_mod.Program.init(std.testing.allocator, .common_fold, &manifest, shape);
    defer program.deinit();
    const keys = [_]recursion.poseidon2_channel.Digest{ session.verification_key_id, session.next_parent_vk_id, session.air_program_id };
    var seen: usize = 0;
    for (program.operations) |operation| {
        try std.testing.expect(operation.source != .session_seal);
        if (operation.source != .session_key) continue;
        try std.testing.expectEqual(seen, operation.item);
        try std.testing.expectEqual(@as(u32, 16), operation.payload_words);
        for (keys[seen], 0..) |word, index| {
            try std.testing.expectEqual(word & 0xffff, operation.constant_words[2 * index]);
            try std.testing.expectEqual(word >> 16, operation.constant_words[2 * index + 1]);
        }
        seen += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), seen);
    std.debug.print("COMMON_FOLD_SESSION_KEYS words=24 manifest_literals=true key_mutations_rejected=true stale_session_rejected_before_mix=true legacy_encoding_preserved=true\n", .{});
}
