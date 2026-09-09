const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact = @import("recursive_node_artifact_v1.zig");
const subject = @import("recursive_field_node_public_v2.zig");

const recursion = frontend.recursion;

test "field node public V2 folds ordered children and round trips canonically" {
    const job = try fixtureJob();
    const left_statement = try recursion.span_statement.SpanStatement.emptyLeaf(job, 210);
    const right_statement = try recursion.span_statement.SpanStatement.emptyLeaf(job, 211);
    const left = try subject.NodePublicV2.initLeaf(
        try artifact.TaskCoordinateV1.init(0, 210),
        try u32Words(left_statement),
        digest("left-empty-source"),
    );
    const right = try subject.NodePublicV2.initLeaf(
        try artifact.TaskCoordinateV1.init(0, 211),
        try u32Words(right_statement),
        digest("right-empty-source"),
    );
    const parent_coordinate = try artifact.TaskCoordinateV1.init(1, 105);
    const parent = try subject.NodePublicV2.initParent(&left, &right, parent_coordinate);
    try parent.validateParentAgainst(&left, &right);
    try std.testing.expectEqual(artifact.NodeKindV1.empty, parent.node_kind);
    try std.testing.expectEqual(subject.parentSourceDigest(&left, &right), parent.source_digest);
    const encoded = try parent.encodeCanonical();
    try std.testing.expectEqual(@as(usize, 1800), encoded.len);
    try std.testing.expectEqual(parent, try subject.NodePublicV2.decodeCanonical(&encoded));
    try std.testing.expect(!std.mem.allEqual(u8, &subject.abiIdentitySha256(), 0));
}

test "field node public V2 rejects source word order and digest mutations" {
    const job = try fixtureJob();
    const left_statement = try recursion.span_statement.SpanStatement.emptyLeaf(job, 210);
    const right_statement = try recursion.span_statement.SpanStatement.emptyLeaf(job, 211);
    const left_source = digest("left-empty-source");
    var left = try subject.NodePublicV2.initLeaf(
        try artifact.TaskCoordinateV1.init(0, 210),
        try u32Words(left_statement),
        left_source,
    );
    const right = try subject.NodePublicV2.initLeaf(
        try artifact.TaskCoordinateV1.init(0, 211),
        try u32Words(right_statement),
        digest("right-empty-source"),
    );
    try left.validateLeafSource(left_source);
    var wrong_source = left_source;
    wrong_source[0] ^= 1;
    try std.testing.expectError(error.InvalidFieldNodeSource, left.validateLeafSource(wrong_source));
    const parent_coordinate = try artifact.TaskCoordinateV1.init(1, 105);
    try std.testing.expectError(
        error.ChildCoordinateMismatch,
        subject.NodePublicV2.initParent(&right, &left, parent_coordinate),
    );
    var parent = try subject.NodePublicV2.initParent(&left, &right, parent_coordinate);
    parent.source_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidFieldNodePublic, parent.validate());
    left.statement_words[0] ^= 1;
    try std.testing.expectError(error.InvalidFieldNodePublic, left.validate());
    left.statement_words[0] ^= 1;
    left.output_digest[7] ^= 1;
    try std.testing.expectError(error.InvalidFieldNodePublic, left.validate());
}

fn u32Words(
    statement: recursion.span_statement.SpanStatement,
) ![subject.STATEMENT_WORD_COUNT]u32 {
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
    return recursion.span_statement.JobContext.init(complete, 210);
}

fn digest(label: []const u8) recursion.poseidon2_channel.Digest {
    return recursion.poseidon2_channel.hashBytes(label, 0x4658); // "FX"
}
