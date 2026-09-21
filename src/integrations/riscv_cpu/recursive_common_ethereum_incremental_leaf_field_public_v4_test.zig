const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;

const artifact = @import("recursive_node_artifact_v1.zig");
const field_public = @import("recursive_field_node_public_v2.zig");
const input =
    @import("recursive_common_ethereum_incremental_leaf_input_v4.zig");
const subject =
    @import("recursive_common_ethereum_incremental_leaf_field_public_v4.zig");

const recursion = frontend.recursion;
const public_data = frontend.air.public_data;
const poseidon = frontend.air.memory_commitment.poseidon2;

test "stage102 V4 cold input and field schedule APIs instantiate" {
    const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);
    std.testing.refAllDecls(input.FreshInputV4(Engine));
    std.testing.refAllDecls(input.FreshViewV4(Engine));
    std.testing.refAllDecls(subject.SourceAuthorityV4);
    std.testing.refAllDecls(subject.PoseidonScheduleV4);
}

test "stage102 V4 source preimage pins role checkpoint and commitment order" {
    const words = try executedWords(0);
    var authority = try fixtureAuthority(words, 0);
    try authority.validateStructure();
    const preimage = try authority.preimage();

    try std.testing.expectEqualSlices(u32, &.{
        4,
        2,
        4,
        0,
        4,
        0,
        0,
        0,
    }, preimage[0..subject.SOURCE_HEADER_WORD_COUNT]);
    var at: usize = subject.SOURCE_HEADER_WORD_COUNT;
    inline for (.{
        authority.statement_digest,
        authority.native_statement_authority,
        authority.public_wire_id,
        authority.protocol_id,
    }) |digest_value| {
        try std.testing.expectEqualSlices(
            u32,
            &digest_value,
            preimage[at..][0..recursion.poseidon2_channel.RATE],
        );
        at += recursion.poseidon2_channel.RATE;
    }
    const completion_words = try authority.completion.words();
    try std.testing.expectEqualSlices(
        u32,
        &completion_words,
        preimage[at..][0..subject.COMPLETION_WORD_COUNT],
    );
    at += subject.COMPLETION_WORD_COUNT;
    try std.testing.expectEqualSlices(
        u32,
        &authority.transcript_final_digest,
        preimage[at..][0..recursion.poseidon2_channel.RATE],
    );
    at += recursion.poseidon2_channel.RATE;
    try std.testing.expectEqual(
        authority.transcript_final_draw_count,
        preimage[at],
    );
    at += 1;
    for (authority.commitments) |commitment| {
        try std.testing.expectEqualSlices(
            u32,
            &commitment,
            preimage[at..][0..recursion.poseidon2_channel.RATE],
        );
        at += recursion.poseidon2_channel.RATE;
    }
    try std.testing.expectEqual(preimage.len, at);

    authority.commitments[2][7] ^= 1;
    try std.testing.expectError(
        error.EthereumIncrementalFieldAuthorityMismatchV4,
        authority.validateStructure(),
    );
}

test "stage102 V4 source binds actual Ethereum completion word and tuple" {
    const word = frontend.isa.custom0.encodeKeccakf(5);
    var completion = try subject.CompletionProjectionV4.init(
        public_data.Completion.unretiredProgramFetch(0x1004, word),
    );
    try std.testing.expectEqual(@as(u32, 3), completion.completion_kind);
    try std.testing.expectEqual(@as(u32, word & 0xffff), completion.value_limbs[0]);
    try std.testing.expectEqual(@as(u32, word >> 16), completion.value_limbs[1]);
    try std.testing.expectEqual(@as(u32, 1), completion.program_term_present);
    try std.testing.expectEqualSlices(
        u32,
        &.{ 46, 0, 5, 0 },
        &completion.program_values,
    );

    completion.program_values[2] = 6;
    try std.testing.expectError(
        error.EthereumIncrementalCompletionProjectionMismatchV4,
        completion.validate(),
    );

    const halt = try subject.CompletionProjectionV4.init(.{
        .kind = .halt_flag,
        .address = 0x2000,
        .value = 1,
        .clock = 17,
    });
    try std.testing.expectEqual(@as(u32, 0), halt.program_term_present);
    try std.testing.expectEqualSlices(
        u32,
        &([_]u32{0} ** 4),
        &halt.program_values,
    );
}

test "stage102 V4 schedule is exact 123-call field-native authority" {
    const words = try executedWords(0);
    const authority = try fixtureAuthority(words, 0);
    var schedule = try subject.testing.buildFromProjectedAuthority(
        words,
        authority,
    );
    try subject.testing.validateProjectedSchedule(
        &schedule,
        words,
        authority,
    );
    try schedule.node_public.validateLeafSource(authority.source_digest);
    try std.testing.expectEqual(
        artifact.NodeKindV1.real,
        schedule.node_public.node_kind,
    );
    try std.testing.expectEqual(@as(usize, 123), schedule.callsSlice().len);
    try std.testing.expectEqual(@as(u32, 7), subject.MINIMUM_POSEIDON_LOG_SIZE);

    const expected_counts = [_]u16{ 52, 12, 3, 56 };
    var next: u16 = 0;
    for (schedule.phases, expected_counts, 0..) |phase, count, ordinal| {
        try std.testing.expectEqual(
            @as(u8, @intCast(ordinal)),
            @intFromEnum(phase.phase),
        );
        try std.testing.expectEqual(next, phase.first_call);
        try std.testing.expectEqual(count, phase.call_count);
        const last = schedule.calls[
            @as(usize, phase.first_call) + phase.call_count - 1
        ];
        var state: [poseidon.WIDTH]@import("stwo_core").fields.m31.M31 =
            undefined;
        for (&state, last.input) |*destination, word|
            destination.* = @import("stwo_core").fields.m31.M31
                .fromCanonical(word);
        poseidon.permute(&state);
        for (
            phase.output_digest,
            state[0..recursion.poseidon2_channel.RATE],
        ) |actual, expected| try std.testing.expectEqual(
            expected.toU32(),
            actual,
        );
        next += count;
    }
    try std.testing.expectEqual(@as(u16, 123), next);

    schedule.calls[53].input[0] ^= 1;
    try std.testing.expectError(
        error.EthereumIncrementalFieldScheduleMismatchV4,
        subject.testing.validateProjectedSchedule(
            &schedule,
            words,
            authority,
        ),
    );
}

test "stage102 V4 public source cannot relabel canonical-empty or transport SHA" {
    const words = try executedWords(0);
    var authority = try fixtureAuthority(words, 0);
    authority.circuit_role = .canonical_empty_field_v2;
    try std.testing.expectError(
        error.EthereumIncrementalFieldAuthorityMismatchV4,
        subject.projectedSourceDigest(&authority),
    );

    try std.testing.expectError(
        error.EthereumIncrementalPublicAirOwnerUnavailableV4,
        subject.requireFieldPublicAirOwner(),
    );
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(!subject.SHA_IN_RECURSIVE_AIR);
    try std.testing.expect(!input.DURABLE_FRESH_CAPABILITY);
    try std.testing.expectEqual(@as(usize, 450), field_public.AIR_WORD_COUNT);
}

fn fixtureAuthority(
    words: [subject.STATEMENT_WORD_COUNT]u32,
    index: u32,
) !subject.SourceAuthorityV4 {
    var result = subject.SourceAuthorityV4{
        .coordinate = try artifact.TaskCoordinateV1.init(0, index),
        .statement_digest = try field_public.statementDigest(words),
        .native_statement_authority = digest(20),
        .public_wire_id = digest(40),
        .protocol_id = recursion.protocol.protocolId(),
        .transcript_final_digest = digest(60),
        .transcript_final_draw_count = 3,
        .completion = try subject.CompletionProjectionV4.init(
            public_data.Completion.canonicalSelfLoop(4),
        ),
        .commitments = .{
            digest(80),
            digest(100),
            digest(120),
            digest(140),
        },
        .source_digest = undefined,
    };
    result.source_digest = try subject.projectedSourceDigest(&result);
    return result;
}

fn executedWords(index: u32) ![subject.STATEMENT_WORD_COUNT]u32 {
    const initial = try recursion.span_statement.MachineState.init(
        0,
        [_]u32{0} ** 32,
        digest(1),
        digest(2),
    );
    const final = try recursion.span_statement.MachineState.init(
        4,
        [_]u32{0} ** 32,
        digest(3),
        digest(4),
    );
    const input_digest = digest(5);
    const output_digest = digest(6);
    const complete = try recursion.span_statement.CompleteExecution.init(
        recursion.protocol.protocolId(),
        digest(7),
        initial,
        final,
        input_digest,
        output_digest,
        8,
    );
    const job = try recursion.span_statement.JobContext.init(complete, 1);
    const executed = try recursion.span_statement.ExecutedSpan.init(
        0,
        1,
        0,
        8,
        initial,
        final,
        try recursion.span_statement.EdgeClaim.present(input_digest),
        try recursion.span_statement.EdgeClaim.present(output_digest),
    );
    const statement = try recursion.span_statement.SpanStatement.segmentLeaf(
        job,
        index,
        executed,
    );
    const canonical = try statement.canonicalWords();
    var result: [subject.STATEMENT_WORD_COUNT]u32 = undefined;
    for (&result, canonical) |*destination, word|
        destination.* = word.toU32();
    return result;
}

fn digest(seed: u32) recursion.poseidon2_channel.Digest {
    var result: recursion.poseidon2_channel.Digest = undefined;
    for (&result, 0..) |*word, index| word.* = seed + @as(u32, @intCast(index));
    return result;
}
