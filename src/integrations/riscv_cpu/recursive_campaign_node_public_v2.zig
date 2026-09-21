//! Campaign-bound validation for the frozen field-native NodePublic V2 wire.
//!
//! The legacy owner intentionally retains its 210 -> 256 topology defaults.
//! This sibling reuses the exact 1,800-byte ABI while deriving coordinates,
//! node kinds, and root height from an authenticated campaign shape. It does
//! not convert metadata into proof freshness and has no production route.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const legacy_artifact = @import("recursive_node_artifact_v1.zig");
const field_public = @import("recursive_field_node_public_v2.zig");
const shape_mod = @import("recursive_pipeline_campaign_shape_v2.zig");

const recursion = frontend.recursion;
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;

pub const PRODUCTION_ACTIVATION = false;
pub const FORMAT_VERSION = field_public.FORMAT_VERSION;
pub const SCHEMA_VERSION = field_public.SCHEMA_VERSION;
pub const ENCODED_BYTE_COUNT = field_public.ENCODED_BYTE_COUNT;
pub const AIR_WORD_COUNT = field_public.AIR_WORD_COUNT;
pub const CampaignShapeAuthorityV2 = shape_mod.CampaignShapeAuthorityV2;
pub const TaskCoordinateV1 = legacy_artifact.TaskCoordinateV1;
pub const NodeKindV1 = legacy_artifact.NodeKindV1;
pub const StageKindV1 = legacy_artifact.StageKindV1;
pub const NodePublicV2 = field_public.NodePublicV2;

pub const Error = shape_mod.Error || field_public.Error || error{
    CampaignChildCoordinateMismatch,
    CampaignNodeKindMismatch,
    CampaignNodePublicMismatch,
    CampaignStageCoordinateMismatch,
    NonCanonicalCampaignNodePublic,
};

pub fn coordinate(
    shape: *const CampaignShapeAuthorityV2,
    height: u8,
    index: u32,
) Error!TaskCoordinateV1 {
    try shape.validate();
    if (height > shape.root_height or
        index >= shape.padded_leaf_count >> @intCast(height))
    {
        return error.InvalidCampaignShapeCoordinateV2;
    }
    const result = TaskCoordinateV1{
        .height = height,
        .index = index,
        .global_ordinal = try globalOrdinal(shape, height, index),
    };
    try validateCoordinate(shape, result);
    return result;
}

pub fn validateCoordinate(
    shape: *const CampaignShapeAuthorityV2,
    value: TaskCoordinateV1,
) Error!void {
    try shape.validate();
    if (!std.mem.allEqual(u8, &value.reserved, 0) or
        shape.padded_leaf_count >= m31.Modulus or
        value.height > shape.root_height or
        value.index >= shape.padded_leaf_count >> @intCast(value.height) or
        value.index >= m31.Modulus or value.global_ordinal >= m31.Modulus or
        value.global_ordinal != try globalOrdinal(
            shape,
            value.height,
            value.index,
        ))
    {
        return error.InvalidCampaignShapeCoordinateV2;
    }
}

pub fn expectedNodeKind(
    shape: *const CampaignShapeAuthorityV2,
    value: TaskCoordinateV1,
) Error!NodeKindV1 {
    try validateCoordinate(shape, value);
    const width = @as(u32, 1) << @intCast(value.height);
    const first = std.math.mul(u32, value.index, width) catch
        return error.ArithmeticOverflow;
    const end = std.math.add(u32, first, width) catch
        return error.ArithmeticOverflow;
    if (end <= shape.real_leaf_count) return .real;
    if (first >= shape.real_leaf_count) return .empty;
    return .mixed;
}

pub fn validateStageCoordinate(
    shape: *const CampaignShapeAuthorityV2,
    stage: StageKindV1,
    value: TaskCoordinateV1,
) Error!void {
    try validateCoordinate(shape, value);
    switch (stage) {
        .leaf_wrapper => if (value.height != 0)
            return error.CampaignStageCoordinateMismatch,
        .fold => if (value.height == 0 or value.height >= shape.root_height)
            return error.CampaignStageCoordinateMismatch,
        .root => if (value.height != shape.root_height or value.index != 0)
            return error.CampaignStageCoordinateMismatch,
    }
}

pub fn initLeaf(
    shape: *const CampaignShapeAuthorityV2,
    value_coordinate: TaskCoordinateV1,
    statement_words: [field_public.STATEMENT_WORD_COUNT]u32,
    source_digest: recursion.poseidon2_channel.Digest,
) Error!NodePublicV2 {
    try validateCoordinate(shape, value_coordinate);
    if (value_coordinate.height != 0)
        return error.CampaignNodePublicMismatch;
    try validateDigest(source_digest);
    var result = NodePublicV2{
        .node_kind = try expectedNodeKind(shape, value_coordinate),
        .coordinate = value_coordinate,
        .statement_words = statement_words,
        .statement_digest = try field_public.statementDigest(statement_words),
        .source_digest = source_digest,
        .subtree_digest = undefined,
        .output_digest = undefined,
    };
    result.subtree_digest = field_public.nodeSubtreeDigest(&result);
    result.output_digest = field_public.nodeOutputDigest(&result);
    try validate(shape, &result);
    return result;
}

pub fn initParent(
    shape: *const CampaignShapeAuthorityV2,
    left: *const NodePublicV2,
    right: *const NodePublicV2,
    parent_coordinate: TaskCoordinateV1,
) Error!NodePublicV2 {
    try validateChildren(shape, left, right, parent_coordinate);
    const left_statement = try spanStatement(left.statement_words);
    const right_statement = try spanStatement(right.statement_words);
    const parent_statement = recursion.span_statement.SpanStatement.fold(
        left_statement,
        right_statement,
    ) catch return error.CampaignNodePublicMismatch;
    const canonical = parent_statement.canonicalWords() catch
        return error.CampaignNodePublicMismatch;
    var words: [field_public.STATEMENT_WORD_COUNT]u32 = undefined;
    for (&words, canonical) |*destination, word|
        destination.* = word.toU32();
    var result = NodePublicV2{
        .node_kind = try expectedNodeKind(shape, parent_coordinate),
        .coordinate = parent_coordinate,
        .statement_words = words,
        .statement_digest = try field_public.statementDigest(words),
        .source_digest = field_public.parentSourceDigest(left, right),
        .subtree_digest = undefined,
        .output_digest = undefined,
    };
    result.subtree_digest = field_public.nodeSubtreeDigest(&result);
    result.output_digest = field_public.nodeOutputDigest(&result);
    try validateParentAgainst(shape, &result, left, right);
    return result;
}

pub fn validate(
    shape: *const CampaignShapeAuthorityV2,
    value: *const NodePublicV2,
) Error!void {
    if (value.format_version != FORMAT_VERSION or
        value.schema_version != SCHEMA_VERSION)
    {
        return error.CampaignNodePublicMismatch;
    }
    try validateCoordinate(shape, value.coordinate);
    if (value.node_kind != try expectedNodeKind(shape, value.coordinate))
        return error.CampaignNodeKindMismatch;
    const statement = try spanStatement(value.statement_words);
    if (statement.slots.height != value.coordinate.height or
        statement.slots.nodeIndex() != value.coordinate.index)
    {
        return error.CampaignNodePublicMismatch;
    }
    inline for (.{
        value.statement_digest,
        value.source_digest,
        value.subtree_digest,
        value.output_digest,
    }) |digest| try validateDigest(digest);
    if (!std.meta.eql(
        value.statement_digest,
        try field_public.statementDigest(value.statement_words),
    ) or !std.meta.eql(
        value.subtree_digest,
        field_public.nodeSubtreeDigest(value),
    ) or !std.meta.eql(
        value.output_digest,
        field_public.nodeOutputDigest(value),
    )) return error.CampaignNodePublicMismatch;
}

pub fn validateParentAgainst(
    shape: *const CampaignShapeAuthorityV2,
    value: *const NodePublicV2,
    left: *const NodePublicV2,
    right: *const NodePublicV2,
) Error!void {
    try validate(shape, value);
    try validateChildren(shape, left, right, value.coordinate);
    const expected = try initParentUnchecked(
        shape,
        left,
        right,
        value.coordinate,
    );
    if (!std.meta.eql(value.*, expected))
        return error.CampaignNodePublicMismatch;
}

pub fn encodeCanonical(
    shape: *const CampaignShapeAuthorityV2,
    value: *const NodePublicV2,
) Error![ENCODED_BYTE_COUNT]u8 {
    try validate(shape, value);
    const words = canonicalAirWords(value);
    var result: [ENCODED_BYTE_COUNT]u8 = undefined;
    for (words, 0..) |word, index|
        std.mem.writeInt(
            u32,
            result[index * 4 ..][0..4],
            word,
            .little,
        );
    return result;
}

pub fn decodeCanonical(
    shape: *const CampaignShapeAuthorityV2,
    bytes: []const u8,
) Error!NodePublicV2 {
    if (bytes.len != ENCODED_BYTE_COUNT)
        return error.NonCanonicalCampaignNodePublic;
    var words: [AIR_WORD_COUNT]u32 = undefined;
    for (&words, 0..) |*word, index|
        word.* = std.mem.readInt(
            u32,
            bytes[index * 4 ..][0..4],
            .little,
        );
    var at: usize = 0;
    const result = NodePublicV2{
        .format_version = take(&words, &at),
        .schema_version = take(&words, &at),
        .node_kind = std.meta.intToEnum(
            NodeKindV1,
            take(&words, &at),
        ) catch return error.NonCanonicalCampaignNodePublic,
        .coordinate = .{
            .height = std.math.cast(u8, take(&words, &at)) orelse
                return error.NonCanonicalCampaignNodePublic,
            .index = take(&words, &at),
            .global_ordinal = take(&words, &at),
        },
        .statement_words = takeArray(
            field_public.STATEMENT_WORD_COUNT,
            &words,
            &at,
        ),
        .statement_digest = takeArray(
            field_public.DIGEST_WORD_COUNT,
            &words,
            &at,
        ),
        .source_digest = takeArray(
            field_public.DIGEST_WORD_COUNT,
            &words,
            &at,
        ),
        .subtree_digest = takeArray(
            field_public.DIGEST_WORD_COUNT,
            &words,
            &at,
        ),
        .output_digest = takeArray(
            field_public.DIGEST_WORD_COUNT,
            &words,
            &at,
        ),
    };
    if (at != words.len) return error.NonCanonicalCampaignNodePublic;
    try validate(shape, &result);
    const canonical = try encodeCanonical(shape, &result);
    if (!std.mem.eql(u8, bytes, &canonical))
        return error.NonCanonicalCampaignNodePublic;
    return result;
}

fn initParentUnchecked(
    shape: *const CampaignShapeAuthorityV2,
    left: *const NodePublicV2,
    right: *const NodePublicV2,
    parent_coordinate: TaskCoordinateV1,
) Error!NodePublicV2 {
    const left_statement = try spanStatement(left.statement_words);
    const right_statement = try spanStatement(right.statement_words);
    const parent_statement = recursion.span_statement.SpanStatement.fold(
        left_statement,
        right_statement,
    ) catch return error.CampaignNodePublicMismatch;
    const canonical = parent_statement.canonicalWords() catch
        return error.CampaignNodePublicMismatch;
    var words: [field_public.STATEMENT_WORD_COUNT]u32 = undefined;
    for (&words, canonical) |*destination, word|
        destination.* = word.toU32();
    var result = NodePublicV2{
        .node_kind = try expectedNodeKind(shape, parent_coordinate),
        .coordinate = parent_coordinate,
        .statement_words = words,
        .statement_digest = try field_public.statementDigest(words),
        .source_digest = field_public.parentSourceDigest(left, right),
        .subtree_digest = undefined,
        .output_digest = undefined,
    };
    result.subtree_digest = field_public.nodeSubtreeDigest(&result);
    result.output_digest = field_public.nodeOutputDigest(&result);
    return result;
}

fn validateChildren(
    shape: *const CampaignShapeAuthorityV2,
    left: *const NodePublicV2,
    right: *const NodePublicV2,
    parent: TaskCoordinateV1,
) Error!void {
    try validate(shape, left);
    try validate(shape, right);
    try validateCoordinate(shape, parent);
    if (parent.height == 0 or left.coordinate.height + 1 != parent.height or
        right.coordinate.height != left.coordinate.height or
        left.coordinate.index != parent.index * 2 or
        right.coordinate.index != left.coordinate.index + 1)
    {
        return error.CampaignChildCoordinateMismatch;
    }
}

fn globalOrdinal(
    shape: *const CampaignShapeAuthorityV2,
    height: u8,
    index: u32,
) Error!u32 {
    var offset: u32 = 0;
    var cursor: u8 = 0;
    while (cursor < height) : (cursor += 1)
        offset = std.math.add(
            u32,
            offset,
            shape.padded_leaf_count >> @intCast(cursor),
        ) catch return error.ArithmeticOverflow;
    return std.math.add(u32, offset, index) catch
        return error.ArithmeticOverflow;
}

fn spanStatement(
    words: [field_public.STATEMENT_WORD_COUNT]u32,
) Error!recursion.span_statement.SpanStatement {
    var canonical: [field_public.STATEMENT_WORD_COUNT]M31 = undefined;
    for (&canonical, words) |*destination, word| {
        if (word >= m31.Modulus)
            return error.NonCanonicalCampaignNodePublic;
        destination.* = M31.fromCanonical(word);
    }
    return recursion.span_statement.SpanStatement.fromCanonicalWords(
        &canonical,
    ) catch error.CampaignNodePublicMismatch;
}

fn validateDigest(digest: recursion.poseidon2_channel.Digest) Error!void {
    var aggregate: u32 = 0;
    for (digest) |word| {
        if (word >= m31.Modulus)
            return error.NonCanonicalCampaignNodePublic;
        aggregate |= word;
    }
    if (aggregate == 0) return error.CampaignNodePublicMismatch;
}

fn canonicalAirWords(value: *const NodePublicV2) [AIR_WORD_COUNT]u32 {
    var result: [AIR_WORD_COUNT]u32 = undefined;
    var at: usize = 0;
    inline for (.{
        value.format_version,
        value.schema_version,
        @intFromEnum(value.node_kind),
        value.coordinate.height,
        value.coordinate.index,
        value.coordinate.global_ordinal,
    }) |word| append(&result, &at, word);
    appendSlice(&result, &at, &value.statement_words);
    appendSlice(&result, &at, &value.statement_digest);
    appendSlice(&result, &at, &value.source_digest);
    appendSlice(&result, &at, &value.subtree_digest);
    appendSlice(&result, &at, &value.output_digest);
    std.debug.assert(at == result.len);
    return result;
}

fn append(words: []u32, at: *usize, value: anytype) void {
    words[at.*] = @intCast(value);
    at.* += 1;
}

fn appendSlice(words: []u32, at: *usize, values: []const u32) void {
    for (values) |value| append(words, at, value);
}

fn take(words: []const u32, at: *usize) u32 {
    const result = words[at.*];
    at.* += 1;
    return result;
}

fn takeArray(
    comptime count: usize,
    words: []const u32,
    at: *usize,
) [count]u32 {
    var result: [count]u32 = undefined;
    for (&result) |*word| word.* = take(words, at);
    return result;
}

comptime {
    if (PRODUCTION_ACTIVATION or ENCODED_BYTE_COUNT != 1800 or
        AIR_WORD_COUNT != 450)
    {
        @compileError("campaign NodePublic V2 sibling contract drifted");
    }
}
