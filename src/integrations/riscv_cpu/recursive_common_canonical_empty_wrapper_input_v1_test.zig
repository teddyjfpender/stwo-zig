const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const subject =
    @import("recursive_common_canonical_empty_wrapper_input_v1.zig");
const artifact_mod = @import("recursive_node_artifact_v1.zig");
const leaf_mod = @import("recursive_temporal_leaf_or_empty_v1.zig");

const recursion = frontend.recursion;
const span = recursion.span_statement;

test "canonical empty source roundtrips and cold reconstructs full public ABI" {
    var fixture = try Fixture.init(210);
    const source = try subject.SourceArtifactV1.seal(&fixture.leaf);
    const bytes = try source.encodeCanonical();
    try std.testing.expectEqual(
        subject.SOURCE_ENCODED_BYTE_COUNT,
        bytes.len,
    );

    const decoded = try subject.SourceArtifactV1.decodeCanonical(&bytes);
    try std.testing.expectEqualDeep(source, decoded);
    var cold = try subject.ColdInputV1.open(&bytes);
    try cold.validate(&bytes);
    try std.testing.expectEqual(
        artifact_mod.TaskCoordinateV1{ .height = 0, .index = 210 },
        try cold.coordinate(),
    );
    try std.testing.expectEqualDeep(
        try source.artifactRef(),
        try cold.sourceRef(),
    );
    const public_bytes = try subject.encodeNodePublic(&cold.node_public);
    try std.testing.expectEqual(
        subject.NODE_PUBLIC_SCALAR_BYTE_COUNT,
        public_bytes.len,
    );
    try std.testing.expectEqualSlices(
        u8,
        &cold.node_public.output_identity_sha256,
        public_bytes[public_bytes.len - 32 ..],
    );
}

test "canonical empty source rejects transport and leaf authority mutations" {
    var fixture = try Fixture.init(211);
    const source = try subject.SourceArtifactV1.seal(&fixture.leaf);
    const canonical = try source.encodeCanonical();

    var reserved = canonical;
    reserved[5] = 1;
    try std.testing.expectError(
        error.InvalidCanonicalEmptySource,
        subject.SourceArtifactV1.decodeCanonical(&reserved),
    );

    var boolean = canonical;
    boolean[4] = 2;
    try std.testing.expectError(
        error.InvalidCanonicalEmptySource,
        subject.SourceArtifactV1.decodeCanonical(&boolean),
    );

    var statement = canonical;
    statement[8] ^= 1;
    try std.testing.expectError(
        error.InvalidCanonicalEmptySource,
        subject.SourceArtifactV1.decodeCanonical(&statement),
    );

    var authority = canonical;
    authority[subject.SOURCE_ENCODED_BYTE_COUNT - 64] ^= 1;
    try std.testing.expectError(
        error.InvalidCanonicalEmptySource,
        subject.SourceArtifactV1.decodeCanonical(&authority),
    );

    try std.testing.expectError(
        error.InvalidCanonicalEmptySource,
        subject.SourceArtifactV1.decodeCanonical(
            canonical[0 .. canonical.len - 1],
        ),
    );
}

test "canonical empty source rejects nonempty and out-of-topology leaves" {
    var trailing = try Fixture.init(255);
    _ = try subject.SourceArtifactV1.seal(&trailing.leaf);

    var before_tail: leaf_mod.LeafOrEmptyV1 = undefined;
    try std.testing.expectError(
        error.EmptyIndexNotTrailing,
        leaf_mod.admitEmptyInto(
            &before_tail,
            trailing.job,
            209,
            digest(101),
            digest(111),
            digest(121),
        ),
    );
    var after_tree: leaf_mod.LeafOrEmptyV1 = undefined;
    try std.testing.expectError(
        error.EmptyIndexNotTrailing,
        leaf_mod.admitEmptyInto(
            &after_tree,
            trailing.job,
            256,
            digest(101),
            digest(111),
            digest(121),
        ),
    );

    var wrong_kind = trailing.leaf;
    wrong_kind.payload.empty.child.kind = .segment_v2;
    try std.testing.expectError(
        error.InvalidLeafKind,
        subject.SourceArtifactV1.seal(&wrong_kind),
    );
}

test "cold input and fixed NodePublic reject post-open mutation" {
    var fixture = try Fixture.init(212);
    const source = try subject.SourceArtifactV1.seal(&fixture.leaf);
    const bytes = try source.encodeCanonical();
    var cold = try subject.ColdInputV1.open(&bytes);

    cold.node_authority.authority_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidCanonicalEmptyColdInput,
        cold.validate(&bytes),
    );

    var fresh = try subject.ColdInputV1.open(&bytes);
    fresh.node_public.statement_words[0] ^= 1;
    try std.testing.expectError(
        error.InvalidCanonicalEmptyColdInput,
        fresh.validate(&bytes),
    );

    var invalid_public = (try subject.ColdInputV1.open(&bytes)).node_public;
    invalid_public.output_identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidNodePublic,
        subject.encodeNodePublic(&invalid_public),
    );
}

const Fixture = struct {
    job: span.JobContext,
    leaf: leaf_mod.LeafOrEmptyV1,

    fn init(index: u32) !Fixture {
        const job = try fixtureJob();
        var leaf: leaf_mod.LeafOrEmptyV1 = undefined;
        try leaf_mod.admitEmptyInto(
            &leaf,
            job,
            index,
            digest(101),
            digest(111),
            digest(121),
        );
        return .{ .job = job, .leaf = leaf };
    }
};

fn fixtureJob() !span.JobContext {
    var initial_registers = [_]u32{0} ** 32;
    var final_registers = [_]u32{0} ** 32;
    initial_registers[1] = 7;
    final_registers[1] = 9;
    const initial = try span.MachineState.init(
        0x1000,
        initial_registers,
        digest(11),
        digest(21),
    );
    const final = try span.MachineState.init(
        0x2000,
        final_registers,
        digest(31),
        digest(41),
    );
    return span.JobContext.init(
        try span.CompleteExecution.init(
            recursion.protocol.PROTOCOL_ID_WORDS,
            digest(51),
            initial,
            final,
            digest(61),
            digest(71),
            88_000,
        ),
        artifact_mod.REAL_LEAF_COUNT,
    );
}

fn digest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}
