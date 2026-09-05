const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const subject =
    @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const shape_mod = @import("recursive_pipeline_campaign_shape_v2.zig");
const campaign_public = @import("recursive_campaign_node_public_v2.zig");
const leaf_mod = @import("recursive_temporal_leaf_or_empty_v1.zig");

const recursion = frontend.recursion;
const span = recursion.span_statement;

test "campaign empty source admits exact 13 to 16 range and cold roundtrips" {
    const shape = try campaignShape(13, 10);
    inline for (.{ 13, 15 }) |index| {
        var fixture = try Fixture.init(13, index);
        const source = try subject.SourceArtifactV2.seal(
            &shape,
            &fixture.leaf,
        );
        const bytes = try source.encodeCanonical(&shape);
        try std.testing.expectEqual(
            @as(usize, subject.SOURCE_ENCODED_BYTE_COUNT),
            bytes.len,
        );
        const decoded = try subject.SourceArtifactV2.decodeCanonical(
            &shape,
            &bytes,
        );
        try std.testing.expectEqualDeep(source, decoded);
        const cold = try subject.ColdInputV2.open(&shape, &bytes);
        try cold.validate(&bytes);
        try std.testing.expectEqual(@as(u32, index), cold.node_public.coordinate.index);
        try std.testing.expectEqual(.empty, cold.node_public.node_kind);
        try campaign_public.validate(&shape, &cold.node_public);
        try std.testing.expectEqual(
            @as(u16, subject.SCHEMA_VERSION),
            (try source.artifactRef(&shape)).schema_version,
        );

        var recording = RecordingChannel{};
        try source.mixInto(&shape, &recording);
        try std.testing.expectEqual(
            @as(usize, subject.SOURCE_FIELD_WORD_COUNT),
            recording.count,
        );
    }

    var before: leaf_mod.LeafOrEmptyV1 = undefined;
    const job = try fixtureJob(13);
    try std.testing.expectError(
        error.EmptyIndexNotTrailing,
        leaf_mod.admitEmptyInto(
            &before,
            job,
            12,
            digest(101),
            digest(111),
            digest(121),
        ),
    );
    var after: leaf_mod.LeafOrEmptyV1 = undefined;
    try std.testing.expectError(
        error.EmptyIndexNotTrailing,
        leaf_mod.admitEmptyInto(
            &after,
            job,
            16,
            digest(101),
            digest(111),
            digest(121),
        ),
    );
}

test "campaign empty source supports another non-eight depth and rejects authority drift" {
    const shape = try campaignShape(33, 20);
    try std.testing.expectEqual(@as(u8, 6), shape.root_height);
    var fixture = try Fixture.init(33, 63);
    const source = try subject.SourceArtifactV2.seal(&shape, &fixture.leaf);
    const bytes = try source.encodeCanonical(&shape);
    const cold = try subject.ColdInputV2.open(&shape, &bytes);
    try std.testing.expectEqual(@as(u32, 63), cold.node_public.coordinate.index);

    const root = try campaign_public.coordinate(&shape, shape.root_height, 0);
    try std.testing.expectEqual(@as(u32, 126), root.global_ordinal);
    try campaign_public.validateStageCoordinate(&shape, .root, root);

    var namespace = shape;
    namespace.campaign_namespace_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidCampaignShapeV2,
        source.validateAgainst(&namespace),
    );
    var shape_identity = source;
    shape_identity.campaign_shape_identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.CampaignEmptySourceMismatch,
        shape_identity.validateAgainst(&shape),
    );
    var node = cold.node_public;
    node.source_digest[0] ^= 1;
    try std.testing.expectError(
        error.CampaignNodePublicMismatch,
        campaign_public.validate(&shape, &node),
    );
    var transport = bytes;
    transport[8] ^= 1;
    try std.testing.expectError(
        error.InvalidCampaignShapeV2,
        subject.SourceArtifactV2.decodeCanonical(&shape, &transport),
    );

    const other_shape = try campaignShape(13, 30);
    try std.testing.expectError(
        error.CampaignEmptySourceMismatch,
        subject.SourceArtifactV2.seal(&other_shape, &fixture.leaf),
    );
}

const RecordingChannel = struct {
    count: usize = 0,

    pub fn mixU32s(self: *@This(), words: []const u32) void {
        self.count += words.len;
    }
};

const Fixture = struct {
    job: span.JobContext,
    leaf: leaf_mod.LeafOrEmptyV1,

    fn init(segment_count: u32, index: u32) !Fixture {
        const job = try fixtureJob(segment_count);
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

fn campaignShape(
    real_leaf_count: u32,
    seed: u32,
) !shape_mod.CampaignShapeAuthorityV2 {
    return shape_mod.CampaignShapeAuthorityV2.init(
        sha(seed),
        sha(seed + 1),
        real_leaf_count,
    );
}

fn fixtureJob(segment_count: u32) !span.JobContext {
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
