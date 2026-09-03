const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact = @import("recursive_node_artifact_v1.zig");
const field_public = @import("recursive_field_node_public_v2.zig");
const subject =
    @import("recursive_common_canonical_empty_field_public_v2.zig");

const recursion = frontend.recursion;
const poseidon = frontend.air.memory_commitment.poseidon2;

test "canonical-empty source preimage is exact field-native role authority" {
    const words = try emptyWords(210);
    const coordinate = try artifact.TaskCoordinateV1.init(0, 210);
    const authority = try subject.CanonicalEmptySourceAuthorityV2.seal(
        words,
        coordinate,
    );
    try authority.validateAgainst(words, coordinate);
    const preimage = try subject.sourcePreimage(words, coordinate);
    try std.testing.expectEqualSlices(
        u32,
        &.{
            2,
            1,
            2,
            0,
            210,
            210,
        },
        preimage[0..6],
    );
    try std.testing.expectEqualSlices(
        u32,
        &authority.statement_digest,
        preimage[6..],
    );
    try std.testing.expectEqual(
        authority.source_digest,
        try subject.sourceDigest(words, coordinate),
    );
    const public = try subject.deriveNodePublic(words, coordinate);
    try public.validateLeafSource(authority.source_digest);
    try std.testing.expectEqual(artifact.NodeKindV1.empty, public.node_kind);

    var wrong_coordinate = coordinate;
    wrong_coordinate.index = 211;
    try std.testing.expectError(
        error.InvalidTaskCoordinate,
        authority.validateAgainst(words, wrong_coordinate),
    );

    var wrong_words = words;
    wrong_words[0] ^= 1;
    try std.testing.expectError(
        error.InvalidFieldNodePublic,
        subject.sourcePreimage(wrong_words, coordinate),
    );
}

test "canonical-empty public schedule reproduces all four Poseidon digests" {
    const words = try emptyWords(210);
    const coordinate = try artifact.TaskCoordinateV1.init(0, 210);
    var schedule = try subject.PoseidonScheduleV2.build(words, coordinate);
    try schedule.validateAgainst(words, coordinate);
    try std.testing.expectEqual(@as(usize, 113), schedule.callsSlice().len);
    try std.testing.expectEqual(@as(u32, 7), subject.MINIMUM_POSEIDON_LOG_SIZE);

    const expected_counts = [_]u16{ 52, 2, 3, 56 };
    var next: u16 = 0;
    for (schedule.phases, expected_counts, 0..) |phase, count, ordinal| {
        try std.testing.expectEqual(@as(u8, @intCast(ordinal)), @intFromEnum(phase.phase));
        try std.testing.expectEqual(next, phase.first_call);
        try std.testing.expectEqual(count, phase.call_count);
        const last = schedule.calls[
            @as(usize, phase.first_call) + phase.call_count - 1
        ];
        const state = last.input;
        var field_state: [poseidon.WIDTH]@import("stwo_core").fields.m31.M31 = undefined;
        for (&field_state, state) |*destination, word|
            destination.* = @import("stwo_core").fields.m31.M31.fromCanonical(word);
        poseidon.permute(&field_state);
        for (phase.output_digest, field_state[0..recursion.poseidon2_channel.RATE]) |
            actual,
            expected,
        | try std.testing.expectEqual(expected.toU32(), actual);
        next += count;
    }
    try std.testing.expectEqual(@as(u16, 113), next);
    try std.testing.expectEqual(
        schedule.node_public.statement_digest,
        schedule.phases[@intFromEnum(subject.PhaseV2.statement)].output_digest,
    );
    try std.testing.expectEqual(
        schedule.node_public.source_digest,
        schedule.phases[@intFromEnum(subject.PhaseV2.source)].output_digest,
    );
    try std.testing.expectEqual(
        schedule.node_public.subtree_digest,
        schedule.phases[@intFromEnum(subject.PhaseV2.subtree)].output_digest,
    );
    try std.testing.expectEqual(
        schedule.node_public.output_digest,
        schedule.phases[@intFromEnum(subject.PhaseV2.output)].output_digest,
    );

    schedule.calls[0].input[0] ^= 1;
    try std.testing.expectError(
        error.CanonicalEmptyFieldScheduleMismatch,
        schedule.validateAgainst(words, coordinate),
    );
}

test "canonical-empty public schedule rejects role and output relabeling" {
    const words = try emptyWords(210);
    const coordinate = try artifact.TaskCoordinateV1.init(0, 210);
    var schedule = try subject.PoseidonScheduleV2.build(words, coordinate);

    schedule.source.source_kind = 1;
    try std.testing.expectError(
        error.CanonicalEmptyFieldAuthorityMismatch,
        schedule.validateAgainst(words, coordinate),
    );

    schedule = try subject.PoseidonScheduleV2.build(words, coordinate);
    schedule.node_public.output_digest[0] ^= 1;
    try std.testing.expectError(
        error.InvalidFieldNodePublic,
        schedule.validateAgainst(words, coordinate),
    );

    try std.testing.expectError(
        error.CanonicalEmptyPublicAirOwnerUnavailable,
        subject.requireFieldPublicAirOwner(),
    );
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(!subject.SHA_IN_RECURSIVE_AIR);
    try std.testing.expectEqual(@as(usize, 450), field_public.AIR_WORD_COUNT);
}

fn emptyWords(index: u32) ![subject.STATEMENT_WORD_COUNT]u32 {
    const job = try fixtureJob();
    const statement = try recursion.span_statement.SpanStatement.emptyLeaf(
        job,
        index,
    );
    const words = try statement.canonicalWords();
    var result: [subject.STATEMENT_WORD_COUNT]u32 = undefined;
    for (&result, words) |*destination, word| destination.* = word.toU32();
    return result;
}

fn fixtureJob() !recursion.span_statement.JobContext {
    const initial = try recursion.span_statement.MachineState.init(
        0,
        [_]u32{0} ** 32,
        digest("entry-memory"),
        digest("entry-public"),
    );
    const final = try recursion.span_statement.MachineState.init(
        4,
        [_]u32{0} ** 32,
        digest("exit-memory"),
        digest("exit-public"),
    );
    const complete = try recursion.span_statement.CompleteExecution.init(
        recursion.protocol.PROTOCOL_ID_WORDS,
        digest("program"),
        initial,
        final,
        digest("input"),
        digest("output"),
        8,
    );
    return recursion.span_statement.JobContext.init(
        complete,
        artifact.REAL_LEAF_COUNT,
    );
}

fn digest(label: []const u8) recursion.poseidon2_channel.Digest {
    return recursion.poseidon2_channel.hashBytes(label, 0x4658); // "FX"
}
