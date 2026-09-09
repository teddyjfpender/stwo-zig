//! Campaign-bound canonical-empty source transport.
//!
//! The V1 source remains frozen to the historic 210 -> 256 campaign. This
//! additive source accepts exactly the authenticated campaign padding range
//! `[real_leaf_count, padded_leaf_count)`, binds namespace and shape into its
//! field-native source digest/transcript, and emits the unchanged NodePublic
//! V2 ABI through campaign-aware validation.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_v1 = @import("recursive_node_artifact_v1.zig");
const field_public = @import("recursive_field_node_public_v2.zig");
const campaign_public = @import("recursive_campaign_node_public_v2.zig");
const shape_mod = @import("recursive_pipeline_campaign_shape_v2.zig");
const leaf_mod = @import("recursive_temporal_leaf_or_empty_v1.zig");

const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const span = recursion.span_statement;
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 2;
pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const SOURCE_ARTIFACT_KIND: u32 = 14;
pub const SOURCE_ENCODED_BYTE_COUNT: usize = 1892;
pub const SOURCE_FIELD_WORD_COUNT: usize = 489;
pub const SOURCE_DIGEST_DOMAIN: u32 = 0x4345_5632; // "CEV2"

const CONTENT_DOMAIN =
    "stwo-zig/common-canonical-empty-campaign-source/v2\x00";
const COLD_INPUT_DOMAIN =
    "stwo-zig/common-canonical-empty-campaign-cold-input/v2\x00";

pub const CampaignShape = shape_mod.CampaignShapeAuthorityV2;
pub const NodePublic = field_public.NodePublicV2;

pub const Error = artifact_v1.Error || shape_mod.Error || leaf_mod.Error ||
    campaign_public.Error || span.Error || error{
    CampaignEmptyColdInputMismatch,
    CampaignEmptySourceMismatch,
    NonCanonicalCampaignEmptySource,
};

pub const SourceArtifactV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: [3]u8 = .{ 0, 0, 0 },
    campaign_namespace_sha256: [32]u8,
    campaign_shape_identity_sha256: [32]u8,
    real_leaf_count: u32,
    padded_leaf_count: u32,
    root_height: u8,
    shape_reserved: [3]u8 = .{ 0, 0, 0 },
    statement_words: [field_public.STATEMENT_WORD_COUNT]u32,
    session_id: channel.Digest,
    segment_leaf_vk_id: channel.Digest,
    recursive_parent_vk_id: channel.Digest,
    leaf_authority_sha256: [32]u8,
    content_identity_sha256: [32]u8,

    pub fn seal(
        shape: *const CampaignShape,
        leaf: *const leaf_mod.LeafOrEmptyV1,
    ) Error!SourceArtifactV2 {
        try shape.validate();
        try leaf.validate();
        if (leaf.kind() != .empty)
            return error.CampaignEmptySourceMismatch;
        const statement = try leaf.statement();
        try validateStatementAgainstShape(shape, statement);
        var words: [field_public.STATEMENT_WORD_COUNT]u32 = undefined;
        for (&words, leaf.child().statement_words) |*destination, source|
            destination.* = source.toU32();
        var result = SourceArtifactV2{
            .campaign_namespace_sha256 = shape.campaign_namespace_sha256,
            .campaign_shape_identity_sha256 = shape.identity_sha256,
            .real_leaf_count = shape.real_leaf_count,
            .padded_leaf_count = shape.padded_leaf_count,
            .root_height = shape.root_height,
            .statement_words = words,
            .session_id = leaf.child().session_id,
            .segment_leaf_vk_id = leaf.segmentLeafVkId(),
            .recursive_parent_vk_id = leaf.child().recursive_parent_vk_id,
            .leaf_authority_sha256 = leaf.authority_sha_id,
            .content_identity_sha256 = undefined,
        };
        result.content_identity_sha256 = sourceIdentity(&result);
        try result.validateAgainst(shape);
        return result;
    }

    pub fn validateAgainst(
        self: *const SourceArtifactV2,
        shape: *const CampaignShape,
    ) Error!void {
        try shape.validateAgainstCampaign(self.campaign_namespace_sha256);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            !std.mem.allEqual(u8, &self.shape_reserved, 0) or
            !std.mem.eql(
                u8,
                &self.campaign_shape_identity_sha256,
                &shape.identity_sha256,
            ) or self.real_leaf_count != shape.real_leaf_count or
            self.padded_leaf_count != shape.padded_leaf_count or
            self.root_height != shape.root_height or
            self.real_leaf_count >= m31.Modulus or
            self.padded_leaf_count >= m31.Modulus or
            std.mem.allEqual(u8, &self.leaf_authority_sha256, 0))
        {
            return error.CampaignEmptySourceMismatch;
        }
        try requireDigest(self.session_id);
        try requireDigest(self.segment_leaf_vk_id);
        try requireDigest(self.recursive_parent_vk_id);
        const statement = try statementFromWords(&self.statement_words);
        try validateStatementAgainstShape(shape, statement);
        if (!std.mem.eql(
            u8,
            &self.content_identity_sha256,
            &sourceIdentity(self),
        )) return error.CampaignEmptySourceMismatch;

        var reconstructed: leaf_mod.LeafOrEmptyV1 = undefined;
        try leaf_mod.admitEmptyInto(
            &reconstructed,
            statement.job,
            @intCast(statement.slots.first),
            self.session_id,
            self.segment_leaf_vk_id,
            self.recursive_parent_vk_id,
        );
        if (!std.mem.eql(
            u8,
            &reconstructed.authority_sha_id,
            &self.leaf_authority_sha256,
        )) return error.CampaignEmptySourceMismatch;
    }

    pub fn fieldWords(
        self: *const SourceArtifactV2,
        shape: *const CampaignShape,
    ) Error![SOURCE_FIELD_WORD_COUNT]u32 {
        try self.validateAgainst(shape);
        var result: [SOURCE_FIELD_WORD_COUNT]u32 = undefined;
        var at: usize = 0;
        append(&result, &at, self.format_version);
        append(&result, &at, self.schema_version);
        append(&result, &at, self.real_leaf_count);
        append(&result, &at, self.padded_leaf_count);
        append(&result, &at, self.root_height);
        appendDigestLimbs(&result, &at, self.campaign_namespace_sha256);
        appendDigestLimbs(
            &result,
            &at,
            self.campaign_shape_identity_sha256,
        );
        appendSlice(&result, &at, &self.statement_words);
        appendSlice(&result, &at, &self.session_id);
        appendSlice(&result, &at, &self.segment_leaf_vk_id);
        appendSlice(&result, &at, &self.recursive_parent_vk_id);
        appendDigestLimbs(&result, &at, self.leaf_authority_sha256);
        std.debug.assert(at == result.len);
        return result;
    }

    pub fn sourceDigest(
        self: *const SourceArtifactV2,
        shape: *const CampaignShape,
    ) Error!channel.Digest {
        const words = try self.fieldWords(shape);
        return channel.hashCanonicalU32s(&words, SOURCE_DIGEST_DOMAIN);
    }

    /// The prover and cold verifier mix this exact projection. SHA is not
    /// recomputed in AIR: each digest byte is represented by a canonical u16
    /// field limb and bound by the field-native channel.
    pub fn mixInto(
        self: *const SourceArtifactV2,
        shape: *const CampaignShape,
        transcript: anytype,
    ) Error!void {
        const words = try self.fieldWords(shape);
        transcript.mixU32s(&words);
    }

    pub fn encodeCanonical(
        self: *const SourceArtifactV2,
        shape: *const CampaignShape,
    ) Error![SOURCE_ENCODED_BYTE_COUNT]u8 {
        try self.validateAgainst(shape);
        var result: [SOURCE_ENCODED_BYTE_COUNT]u8 = undefined;
        var writer = Writer{ .bytes = &result };
        writeSource(&writer, self, true);
        std.debug.assert(writer.at == result.len);
        return result;
    }

    pub fn decodeCanonical(
        shape: *const CampaignShape,
        bytes: []const u8,
    ) Error!SourceArtifactV2 {
        if (bytes.len != SOURCE_ENCODED_BYTE_COUNT)
            return error.NonCanonicalCampaignEmptySource;
        var reader = Reader{ .bytes = bytes };
        const result = SourceArtifactV2{
            .format_version = try reader.u16Value(),
            .schema_version = try reader.u16Value(),
            .production_activation = try reader.boolValue(),
            .reserved = try reader.array(3),
            .campaign_namespace_sha256 = try reader.array(32),
            .campaign_shape_identity_sha256 = try reader.array(32),
            .real_leaf_count = try reader.u32Value(),
            .padded_leaf_count = try reader.u32Value(),
            .root_height = try reader.u8Value(),
            .shape_reserved = try reader.array(3),
            .statement_words = try reader.words(
                field_public.STATEMENT_WORD_COUNT,
            ),
            .session_id = try reader.words(channel.RATE),
            .segment_leaf_vk_id = try reader.words(channel.RATE),
            .recursive_parent_vk_id = try reader.words(channel.RATE),
            .leaf_authority_sha256 = try reader.array(32),
            .content_identity_sha256 = try reader.array(32),
        };
        if (reader.at != bytes.len)
            return error.NonCanonicalCampaignEmptySource;
        try result.validateAgainst(shape);
        const canonical = try result.encodeCanonical(shape);
        if (!std.mem.eql(u8, bytes, &canonical))
            return error.NonCanonicalCampaignEmptySource;
        return result;
    }

    pub fn artifactRef(
        self: *const SourceArtifactV2,
        shape: *const CampaignShape,
    ) Error!artifact_v1.ArtifactRefV1 {
        const bytes = try self.encodeCanonical(shape);
        const result = artifact_v1.ArtifactRefV1{
            .kind = SOURCE_ARTIFACT_KIND,
            .format_version = artifact_v1.ARTIFACT_REF_FORMAT_VERSION,
            .schema_version = SCHEMA_VERSION,
            .byte_count = bytes.len,
            .sha256 = sha256(&bytes),
        };
        try result.validate();
        return result;
    }
};

/// Process-local owner. Transport bytes never carry this reconstructed leaf
/// or any fresh proof capability.
pub const ColdInputV2 = struct {
    shape: CampaignShape,
    source: SourceArtifactV2,
    leaf: leaf_mod.LeafOrEmptyV1,
    node_public: NodePublic,
    identity_sha256: [32]u8,

    pub fn open(
        shape: *const CampaignShape,
        bytes: []const u8,
    ) Error!ColdInputV2 {
        const source = try SourceArtifactV2.decodeCanonical(shape, bytes);
        const statement = try statementFromWords(&source.statement_words);
        var leaf: leaf_mod.LeafOrEmptyV1 = undefined;
        try leaf_mod.admitEmptyInto(
            &leaf,
            statement.job,
            @intCast(statement.slots.first),
            source.session_id,
            source.segment_leaf_vk_id,
            source.recursive_parent_vk_id,
        );
        const value_coordinate = try campaign_public.coordinate(
            shape,
            0,
            @intCast(statement.slots.first),
        );
        const node_public = try campaign_public.initLeaf(
            shape,
            value_coordinate,
            source.statement_words,
            try source.sourceDigest(shape),
        );
        var result = ColdInputV2{
            .shape = shape.*,
            .source = source,
            .leaf = leaf,
            .node_public = node_public,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = coldInputIdentity(&result);
        try result.validate(bytes);
        return result;
    }

    pub fn validate(self: *const ColdInputV2, bytes: []const u8) Error!void {
        try self.shape.validate();
        try self.source.validateAgainst(&self.shape);
        try self.leaf.validate();
        const canonical = try self.source.encodeCanonical(&self.shape);
        const statement = try statementFromWords(&self.source.statement_words);
        const value_coordinate = try campaign_public.coordinate(
            &self.shape,
            0,
            @intCast(statement.slots.first),
        );
        const expected_public = try campaign_public.initLeaf(
            &self.shape,
            value_coordinate,
            self.source.statement_words,
            try self.source.sourceDigest(&self.shape),
        );
        if (!std.mem.eql(u8, bytes, &canonical) or
            !std.mem.eql(
                u8,
                &self.leaf.authority_sha_id,
                &self.source.leaf_authority_sha256,
            ) or !std.meta.eql(self.node_public, expected_public) or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &coldInputIdentity(self),
            )) return error.CampaignEmptyColdInputMismatch;
    }

    pub fn coordinate(self: *const ColdInputV2) Error!artifact_v1.TaskCoordinateV1 {
        try self.validateShapeOnly();
        const statement = try self.leaf.statement();
        return campaign_public.coordinate(
            &self.shape,
            0,
            @intCast(statement.slots.first),
        );
    }

    fn validateShapeOnly(self: *const ColdInputV2) Error!void {
        try self.shape.validate();
        try self.source.validateAgainst(&self.shape);
        try campaign_public.validate(&self.shape, &self.node_public);
    }
};

fn validateStatementAgainstShape(
    shape: *const CampaignShape,
    statement: span.SpanStatement,
) Error!void {
    try shape.validate();
    if (statement.job.segment_count != shape.real_leaf_count or
        statement.job.slotCapacity() != shape.padded_leaf_count or
        statement.slots.height != 0 or
        statement.slots.first < shape.real_leaf_count or
        statement.slots.first >= shape.padded_leaf_count)
    {
        return error.CampaignEmptySourceMismatch;
    }
    switch (statement.body) {
        .empty => {},
        .executed => return error.CampaignEmptySourceMismatch,
    }
}

fn statementFromWords(
    words: *const [field_public.STATEMENT_WORD_COUNT]u32,
) Error!span.SpanStatement {
    var canonical: span.StatementWords = undefined;
    for (&canonical, words) |*destination, source| {
        if (source >= m31.Modulus)
            return error.NonCanonicalCampaignEmptySource;
        destination.* = M31.fromCanonical(source);
    }
    return span.SpanStatement.fromCanonicalWords(&canonical) catch
        error.NonCanonicalCampaignEmptySource;
}

fn sourceIdentity(value: *const SourceArtifactV2) [32]u8 {
    var bytes: [SOURCE_ENCODED_BYTE_COUNT - 32]u8 = undefined;
    var writer = Writer{ .bytes = &bytes };
    writeSource(&writer, value, false);
    std.debug.assert(writer.at == bytes.len);
    var hash = Sha256.init(.{});
    hash.update(CONTENT_DOMAIN);
    hash.update(&bytes);
    return hash.finalResult();
}

fn coldInputIdentity(value: *const ColdInputV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(COLD_INPUT_DOMAIN);
    hash.update(&value.shape.identity_sha256);
    hash.update(&value.source.content_identity_sha256);
    hash.update(&value.leaf.authority_sha_id);
    const public_bytes = campaign_public.encodeCanonical(
        &value.shape,
        &value.node_public,
    ) catch unreachable;
    hash.update(&public_bytes);
    return hash.finalResult();
}

fn writeSource(
    writer: *Writer,
    value: *const SourceArtifactV2,
    include_identity: bool,
) void {
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u8Value(@intFromBool(value.production_activation));
    writer.bytesValue(&value.reserved);
    writer.bytesValue(&value.campaign_namespace_sha256);
    writer.bytesValue(&value.campaign_shape_identity_sha256);
    writer.u32Value(value.real_leaf_count);
    writer.u32Value(value.padded_leaf_count);
    writer.u8Value(value.root_height);
    writer.bytesValue(&value.shape_reserved);
    for (value.statement_words) |word| writer.u32Value(word);
    writer.words(&value.session_id);
    writer.words(&value.segment_leaf_vk_id);
    writer.words(&value.recursive_parent_vk_id);
    writer.bytesValue(&value.leaf_authority_sha256);
    if (include_identity)
        writer.bytesValue(&value.content_identity_sha256);
}

fn append(words: []u32, at: *usize, value: anytype) void {
    words[at.*] = @intCast(value);
    at.* += 1;
}

fn appendSlice(words: []u32, at: *usize, values: []const u32) void {
    for (values) |value| append(words, at, value);
}

fn appendDigestLimbs(
    words: []u32,
    at: *usize,
    digest: [32]u8,
) void {
    for (0..16) |index|
        append(
            words,
            at,
            std.mem.readInt(
                u16,
                digest[index * 2 ..][0..2],
                .little,
            ),
        );
}

fn requireDigest(value: channel.Digest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus)
            return error.NonCanonicalCampaignEmptySource;
        aggregate |= word;
    }
    if (aggregate == 0) return error.CampaignEmptySourceMismatch;
}

fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    fn bytesValue(self: *Writer, value: []const u8) void {
        @memcpy(self.bytes[self.at..][0..value.len], value);
        self.at += value.len;
    }
    fn words(self: *Writer, value: []const u32) void {
        for (value) |word| self.u32Value(word);
    }
    fn u8Value(self: *Writer, value: u8) void {
        self.bytes[self.at] = value;
        self.at += 1;
    }
    fn u16Value(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.bytes[self.at..][0..2], value, .little);
        self.at += 2;
    }
    fn u32Value(self: *Writer, value: u32) void {
        std.mem.writeInt(u32, self.bytes[self.at..][0..4], value, .little);
        self.at += 4;
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    fn take(self: *Reader, count: usize) Error![]const u8 {
        const end = std.math.add(usize, self.at, count) catch
            return error.NonCanonicalCampaignEmptySource;
        if (end > self.bytes.len)
            return error.NonCanonicalCampaignEmptySource;
        const result = self.bytes[self.at..end];
        self.at = end;
        return result;
    }
    fn array(self: *Reader, comptime count: usize) Error![count]u8 {
        return (try self.take(count))[0..count].*;
    }
    fn words(self: *Reader, comptime count: usize) Error![count]u32 {
        var result: [count]u32 = undefined;
        for (&result) |*word| word.* = try self.u32Value();
        return result;
    }
    fn u8Value(self: *Reader) Error!u8 {
        return (try self.take(1))[0];
    }
    fn boolValue(self: *Reader) Error!bool {
        return switch (try self.u8Value()) {
            0 => false,
            1 => true,
            else => error.NonCanonicalCampaignEmptySource,
        };
    }
    fn u16Value(self: *Reader) Error!u16 {
        const bytes = try self.take(2);
        return std.mem.readInt(u16, @ptrCast(bytes.ptr), .little);
    }
    fn u32Value(self: *Reader) Error!u32 {
        const bytes = try self.take(4);
        return std.mem.readInt(u32, @ptrCast(bytes.ptr), .little);
    }
};

comptime {
    if (PRODUCTION_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY or
        SOURCE_ENCODED_BYTE_COUNT != 1892 or SOURCE_FIELD_WORD_COUNT != 489)
    {
        @compileError("campaign-bound canonical-empty source drifted");
    }
}
