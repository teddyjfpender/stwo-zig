const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact = @import("recursive_node_artifact_v1.zig");
const node_public = @import("recursive_field_node_public_v2.zig");
const role_io =
    @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");
const schema2 =
    @import("recursive_common_ethereum_incremental_leaf_field_public_v4.zig");
const subject =
    @import("recursive_common_ethereum_incremental_leaf_field_public_v4_schema3.zig");

const channel = frontend.recursion.poseidon2_channel;

test "schema3 source binds tuple count capacity and field commitment" {
    const words = try executedWords(0);
    const base = try fixtureBaseAuthority(words, 0);
    var source = subject.SourceAuthorityV4{
        .base = base,
        .role_io_tuple_count = 1,
        .role_io_tuple_capacity = 1,
        .role_io_commitment = digest(170),
        .source_digest = undefined,
    };
    source.source_digest = try subject.projectedSourceDigest(&source);
    try source.validateStructure();
    const preimage = try source.preimage();
    const at = schema2.SOURCE_PREIMAGE_WORD_COUNT;
    try std.testing.expectEqual(@as(u32, 1), preimage[at]);
    try std.testing.expectEqual(@as(u32, 1), preimage[at + 1]);
    try std.testing.expectEqualSlices(
        u32,
        &source.role_io_commitment,
        preimage[at + 2 ..][0..channel.RATE],
    );

    var wrong = source;
    wrong.role_io_tuple_count = 0;
    try std.testing.expectError(
        error.EthereumIncrementalFieldAuthorityMismatchV4Schema3,
        wrong.validateStructure(),
    );
    wrong = source;
    wrong.role_io_commitment[7] ^= 1;
    try std.testing.expectError(
        error.EthereumIncrementalFieldAuthorityMismatchV4Schema3,
        wrong.validateStructure(),
    );

    const node = try node_public.NodePublicV2.initLeaf(
        base.coordinate,
        words,
        source.source_digest,
    );
    try node.validateLeafSource(source.source_digest);
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(!subject.CAMPAIGN_PROVIDER_GEOMETRY_FROZEN);
    try std.testing.expect(subject.SCHEMA2_REMAINS_DIAGNOSTIC);
}

test "schema3 field schedule derives provider geometry from committed stream" {
    const words = try executedWords(0);
    const base = try fixtureBaseAuthority(words, 0);
    const tuple = try role_io.TupleV4.init(.program_completion, &.{
        4,
        base.completion.program_values[0],
        base.completion.program_values[1],
        base.completion.program_values[2],
        base.completion.program_values[3],
    });
    const tuples = [_]role_io.TupleV4{tuple};
    const canonical = try role_io.testingCanonicalWordsAlloc(
        std.testing.allocator,
        &tuples,
        1,
    );
    defer std.testing.allocator.free(canonical);
    const io_calls = try role_io.testingBuildCallsAlloc(
        std.testing.allocator,
        canonical,
    );
    defer std.testing.allocator.free(io_calls);

    var source = subject.SourceAuthorityV4{
        .base = base,
        .role_io_tuple_count = 1,
        .role_io_tuple_capacity = 1,
        .role_io_commitment = role_io.testingDigestFromCalls(io_calls),
        .source_digest = undefined,
    };
    source.source_digest = try subject.projectedSourceDigest(&source);
    var schedule = try subject.testing.buildFromProjectedAuthority(
        std.testing.allocator,
        words,
        source,
        io_calls,
    );
    defer schedule.deinit();
    try subject.testing.validateProjectedSchedule(
        &schedule,
        words,
        source,
        io_calls,
    );
    const geometry = try schedule.liveProviderGeometry();
    try std.testing.expectEqual(@as(u32, 1), geometry.role_io_tuple_capacity);
    try std.testing.expectEqual(@as(u32, 24), geometry.role_io_word_count);
    try std.testing.expectEqual(@as(u32, 4), geometry.role_io_call_count);
    try std.testing.expectEqual(@as(u32, 129), geometry.provider_active_row_count);
    try std.testing.expectEqual(@as(u32, 8), geometry.provider_log_size);
    try std.testing.expectEqual(@as(u32, 256), geometry.provider_row_capacity);

    schedule.calls[0].input[0] ^= 1;
    try std.testing.expectError(
        error.EthereumIncrementalFieldScheduleMismatchV4Schema3,
        subject.testing.validateProjectedSchedule(
            &schedule,
            words,
            source,
            io_calls,
        ),
    );
}

fn fixtureBaseAuthority(
    words: [subject.STATEMENT_WORD_COUNT]u32,
    index: u32,
) !schema2.SourceAuthorityV4 {
    var result = schema2.SourceAuthorityV4{
        .coordinate = try artifact.TaskCoordinateV1.init(0, index),
        .statement_digest = try node_public.statementDigest(words),
        .native_statement_authority = digest(30),
        .public_wire_id = digest(50),
        .protocol_id = frontend.recursion.protocol.protocolId(),
        .transcript_final_digest = digest(70),
        .transcript_final_draw_count = 3,
        .completion = try schema2.CompletionProjectionV4.init(
            frontend.air.public_data.Completion.canonicalSelfLoop(4),
        ),
        .commitments = .{
            digest(90),
            digest(110),
            digest(130),
            digest(150),
        },
        .source_digest = undefined,
    };
    result.source_digest = try schema2.projectedSourceDigest(&result);
    return result;
}

fn executedWords(index: u32) ![subject.STATEMENT_WORD_COUNT]u32 {
    const span = frontend.recursion.span_statement;
    const initial = try span.MachineState.init(
        0,
        [_]u32{0} ** 32,
        digest(1),
        digest(2),
    );
    const final = try span.MachineState.init(
        4,
        [_]u32{0} ** 32,
        digest(3),
        digest(4),
    );
    const input_digest = digest(5);
    const output_digest = digest(6);
    const complete = try span.CompleteExecution.init(
        frontend.recursion.protocol.protocolId(),
        digest(7),
        initial,
        final,
        input_digest,
        output_digest,
        8,
    );
    const job = try span.JobContext.init(complete, 1);
    const executed = try span.ExecutedSpan.init(
        0,
        1,
        0,
        8,
        initial,
        final,
        try span.EdgeClaim.present(input_digest),
        try span.EdgeClaim.present(output_digest),
    );
    const statement = try span.SpanStatement.segmentLeaf(job, index, executed);
    const canonical = try statement.canonicalWords();
    var result: [subject.STATEMENT_WORD_COUNT]u32 = undefined;
    for (&result, canonical) |*destination, word|
        destination.* = word.toU32();
    return result;
}

fn digest(seed: u32) channel.Digest {
    var result: channel.Digest = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}
