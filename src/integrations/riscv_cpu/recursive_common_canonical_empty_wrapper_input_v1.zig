//! Durable source and cold reconstruction for one canonical-empty wrapper.
//!
//! The source transport contains the exact empty `SpanStatement` and the
//! three protocol digests required to reconstruct `LeafOrEmptyV1`.  It does
//! not contain a proof capture or freshness bit.  `ColdInputV1.open` repeats
//! the canonical empty-leaf constructor, derives the fixed 412-word
//! `NodePublicV1`, and rejects every stored field that does not close.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_mod = @import("recursive_node_artifact_v1.zig");
const leaf_mod = @import("recursive_temporal_leaf_or_empty_v1.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");

const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const span = recursion.span_statement;
const m31 = stwo_core.fields.m31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const SOURCE_ARTIFACT_KIND: u32 = 14;
pub const SOURCE_ENCODED_BYTE_COUNT: usize = 1816;
pub const NODE_PUBLIC_SCALAR_BYTE_COUNT: usize =
    artifact_mod.NODE_PUBLIC_BYTE_COUNT;
pub const FIRST_EMPTY_INDEX: u32 = artifact_mod.REAL_LEAF_COUNT;
pub const LAST_EMPTY_INDEX_EXCLUSIVE: u32 = artifact_mod.PADDED_LEAF_COUNT;

pub const SUBTREE_DIGEST_DOMAIN: u32 = 0x4345_5731; // "CEW1"
const CONTENT_DOMAIN =
    "stwo-zig/common-canonical-empty-source/v1\x00";
const SUBTREE_DOMAIN =
    "stwo-zig/common-canonical-empty-subtree/v1\x00";
const AUTHORITY_DOMAIN =
    "stwo-zig/common-canonical-empty-authority/v1\x00";
const COLD_INPUT_DOMAIN =
    "stwo-zig/common-canonical-empty-cold-input/v1\x00";

pub const Error = artifact_mod.Error || leaf_mod.Error || span.Error || error{
    InvalidCanonicalEmptySource,
    InvalidCanonicalEmptyColdInput,
    InvalidCanonicalEmptyNodePublic,
};

/// Pointer-free source bytes.  `content_identity_sha256` authenticates every
/// preceding byte and is transport identity only; `open` still reconstructs
/// the typed leaf rather than promoting this digest.
pub const SourceArtifactV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: [3]u8 = .{ 0, 0, 0 },
    statement_words: [artifact_mod.STATEMENT_WORD_COUNT]u32,
    session_id: channel.Digest,
    segment_leaf_vk_id: channel.Digest,
    recursive_parent_vk_id: channel.Digest,
    leaf_authority_sha256: [32]u8,
    content_identity_sha256: [32]u8,

    pub fn seal(leaf: *const leaf_mod.LeafOrEmptyV1) Error!SourceArtifactV1 {
        try leaf.validate();
        if (leaf.kind() != .empty) return error.InvalidCanonicalEmptySource;
        const statement = try leaf.statement();
        if (statement.slots.height != 0 or
            statement.slots.first < FIRST_EMPTY_INDEX or
            statement.slots.first >= LAST_EMPTY_INDEX_EXCLUSIVE)
        {
            return error.InvalidCanonicalEmptySource;
        }
        var words: [artifact_mod.STATEMENT_WORD_COUNT]u32 = undefined;
        for (&words, leaf.child().statement_words) |*destination, source|
            destination.* = source.toU32();
        var result = SourceArtifactV1{
            .statement_words = words,
            .session_id = leaf.child().session_id,
            .segment_leaf_vk_id = leaf.segmentLeafVkId(),
            .recursive_parent_vk_id = leaf.child().recursive_parent_vk_id,
            .leaf_authority_sha256 = leaf.authority_sha_id,
            .content_identity_sha256 = undefined,
        };
        result.content_identity_sha256 = sourceIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const SourceArtifactV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            std.mem.allEqual(u8, &self.leaf_authority_sha256, 0))
        {
            return error.InvalidCanonicalEmptySource;
        }
        try requireDigest(self.session_id);
        try requireDigest(self.segment_leaf_vk_id);
        try requireDigest(self.recursive_parent_vk_id);
        const statement = try statementFromWords(&self.statement_words);
        if (statement.slots.height != 0 or
            statement.slots.first < FIRST_EMPTY_INDEX or
            statement.slots.first >= LAST_EMPTY_INDEX_EXCLUSIVE)
        {
            return error.InvalidCanonicalEmptySource;
        }
        switch (statement.body) {
            .empty => {},
            .executed => return error.InvalidCanonicalEmptySource,
        }
        if (!std.mem.eql(
            u8,
            &self.content_identity_sha256,
            &sourceIdentity(self),
        )) return error.InvalidCanonicalEmptySource;

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
        )) return error.InvalidCanonicalEmptySource;
    }

    pub fn encodeCanonical(
        self: *const SourceArtifactV1,
    ) Error![SOURCE_ENCODED_BYTE_COUNT]u8 {
        try self.validate();
        var result: [SOURCE_ENCODED_BYTE_COUNT]u8 = undefined;
        var writer = Writer{ .bytes = &result };
        writeSource(&writer, self, true);
        std.debug.assert(writer.at == result.len);
        return result;
    }

    pub fn decodeCanonical(bytes: []const u8) Error!SourceArtifactV1 {
        if (bytes.len != SOURCE_ENCODED_BYTE_COUNT)
            return error.InvalidCanonicalEmptySource;
        var reader = Reader{ .bytes = bytes };
        const result = SourceArtifactV1{
            .format_version = try reader.u16Value(),
            .schema_version = try reader.u16Value(),
            .production_activation = try reader.boolValue(),
            .reserved = try reader.array(3),
            .statement_words = try reader.words(
                artifact_mod.STATEMENT_WORD_COUNT,
            ),
            .session_id = try reader.words(channel.RATE),
            .segment_leaf_vk_id = try reader.words(channel.RATE),
            .recursive_parent_vk_id = try reader.words(channel.RATE),
            .leaf_authority_sha256 = try reader.array(32),
            .content_identity_sha256 = try reader.array(32),
        };
        if (reader.at != bytes.len)
            return error.InvalidCanonicalEmptySource;
        try result.validate();
        const canonical = try result.encodeCanonical();
        if (!std.mem.eql(u8, bytes, &canonical))
            return error.InvalidCanonicalEmptySource;
        return result;
    }

    pub fn artifactRef(self: *const SourceArtifactV1) Error!artifact_mod.ArtifactRefV1 {
        const bytes = try self.encodeCanonical();
        const result = artifact_mod.ArtifactRefV1{
            .kind = SOURCE_ARTIFACT_KIND,
            .format_version = artifact_mod.ARTIFACT_REF_FORMAT_VERSION,
            .schema_version = SCHEMA_VERSION,
            .byte_count = bytes.len,
            .sha256 = sha256(&bytes),
        };
        try result.validate();
        return result;
    }
};

pub const EmptyNodeAuthorityV1 = struct {
    statement_identity_sha256: [32]u8,
    leaf_authority_sha256: [32]u8,
    subtree_digest: channel.Digest,
    subtree_sha256: [32]u8,
    authority_sha256: [32]u8,

    pub fn derive(source: *const SourceArtifactV1) Error!EmptyNodeAuthorityV1 {
        try source.validate();
        const source_bytes = sourceSemanticBytes(source);
        const subtree_digest = channel.hashBytes(
            &source_bytes,
            SUBTREE_DIGEST_DOMAIN,
        );
        var result = EmptyNodeAuthorityV1{
            .statement_identity_sha256 = statementIdentity(
                &source.statement_words,
            ),
            .leaf_authority_sha256 = source.leaf_authority_sha256,
            .subtree_digest = subtree_digest,
            .subtree_sha256 = undefined,
            .authority_sha256 = undefined,
        };
        result.subtree_sha256 = subtreeIdentity(&result);
        result.authority_sha256 = authorityIdentity(&result);
        try result.validateAgainst(source);
        return result;
    }

    pub fn validateAgainst(
        self: *const EmptyNodeAuthorityV1,
        source: *const SourceArtifactV1,
    ) Error!void {
        try source.validate();
        const expected = deriveUnchecked(source);
        if (!std.meta.eql(self.*, expected))
            return error.InvalidCanonicalEmptyNodePublic;
    }
};

/// Cold-derived, non-serializable owner passed to the wrapper prover and
/// reconstructed independently by its cold verifier.
pub const ColdInputV1 = struct {
    source: SourceArtifactV1,
    leaf: leaf_mod.LeafOrEmptyV1,
    node_authority: EmptyNodeAuthorityV1,
    node_public: artifact_mod.NodePublicV1,
    identity_sha256: [32]u8,

    pub fn open(bytes: []const u8) Error!ColdInputV1 {
        const source = try SourceArtifactV1.decodeCanonical(bytes);
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
        const node_authority = try EmptyNodeAuthorityV1.derive(&source);
        const node_public = try nodePublicFromAuthority(
            &source,
            &node_authority,
        );
        var result = ColdInputV1{
            .source = source,
            .leaf = leaf,
            .node_authority = node_authority,
            .node_public = node_public,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = coldInputIdentity(&result);
        try result.validate(bytes);
        return result;
    }

    pub fn validate(self: *const ColdInputV1, bytes: []const u8) Error!void {
        try self.source.validate();
        try self.leaf.validate();
        const canonical = try self.source.encodeCanonical();
        const authority = try EmptyNodeAuthorityV1.derive(&self.source);
        const public = try nodePublicFromAuthority(&self.source, &authority);
        if (!std.mem.eql(u8, bytes, &canonical) or
            !std.mem.eql(
                u8,
                &self.leaf.authority_sha_id,
                &self.source.leaf_authority_sha256,
            ) or !std.meta.eql(self.node_authority, authority) or
            !std.meta.eql(self.node_public, public) or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &coldInputIdentity(self),
            )) return error.InvalidCanonicalEmptyColdInput;
    }

    pub fn coordinate(self: *const ColdInputV1) Error!artifact_mod.TaskCoordinateV1 {
        const statement = try self.leaf.statement();
        return artifact_mod.TaskCoordinateV1.init(
            0,
            @intCast(statement.slots.first),
        );
    }

    pub fn sourceRef(self: *const ColdInputV1) Error!artifact_mod.ArtifactRefV1 {
        return self.source.artifactRef();
    }
};

pub fn nodePublicFromAuthority(
    source: *const SourceArtifactV1,
    authority: *const EmptyNodeAuthorityV1,
) Error!artifact_mod.NodePublicV1 {
    try authority.validateAgainst(source);
    return artifact_mod.NodePublicV1.seal(.{
        .statement_words = source.statement_words,
        .statement_identity_sha256 = authority.statement_identity_sha256,
        .node_authority_sha256 = authority.authority_sha256,
        .subtree_sha256 = authority.subtree_sha256,
        .subtree_digest = authority.subtree_digest,
        .output_identity_sha256 = undefined,
    });
}

/// Canonical byte projection relation-bound by the wrapper AIR.  Every byte
/// of the fixed ABI is represented as one base-field value, so no arbitrary
/// u32-to-M31 reduction is possible.
pub fn encodeNodePublic(
    value: *const artifact_mod.NodePublicV1,
) Error![NODE_PUBLIC_SCALAR_BYTE_COUNT]u8 {
    try value.validate();
    var result: [NODE_PUBLIC_SCALAR_BYTE_COUNT]u8 = undefined;
    var writer = Writer{ .bytes = &result };
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.bytesValue(&value.reserved);
    for (value.statement_words) |word| writer.u32Value(word);
    writer.bytesValue(&value.statement_identity_sha256);
    writer.bytesValue(&value.node_authority_sha256);
    writer.bytesValue(&value.subtree_sha256);
    for (value.subtree_digest) |word| writer.u32Value(word);
    writer.bytesValue(&value.output_identity_sha256);
    std.debug.assert(writer.at == result.len);
    return result;
}

fn deriveUnchecked(source: *const SourceArtifactV1) EmptyNodeAuthorityV1 {
    const source_bytes = sourceSemanticBytes(source);
    var result = EmptyNodeAuthorityV1{
        .statement_identity_sha256 = statementIdentity(&source.statement_words),
        .leaf_authority_sha256 = source.leaf_authority_sha256,
        .subtree_digest = channel.hashBytes(
            &source_bytes,
            SUBTREE_DIGEST_DOMAIN,
        ),
        .subtree_sha256 = undefined,
        .authority_sha256 = undefined,
    };
    result.subtree_sha256 = subtreeIdentity(&result);
    result.authority_sha256 = authorityIdentity(&result);
    return result;
}

fn statementFromWords(
    words: *const [artifact_mod.STATEMENT_WORD_COUNT]u32,
) Error!span.SpanStatement {
    var canonical: span.StatementWords = undefined;
    for (&canonical, words) |*destination, source| {
        if (source >= m31.Modulus) return error.InvalidCanonicalEmptySource;
        destination.* = stwo_core.fields.m31.M31.fromCanonical(source);
    }
    return span.SpanStatement.fromCanonicalWords(&canonical);
}

fn statementIdentity(
    words: *const [artifact_mod.STATEMENT_WORD_COUNT]u32,
) [32]u8 {
    var canonical: span.StatementWords = undefined;
    for (&canonical, words) |*destination, source|
        destination.* = stwo_core.fields.m31.M31.fromCanonical(source);
    return statement_plan.statementSha256(&canonical);
}

fn sourceIdentity(value: *const SourceArtifactV1) [32]u8 {
    const bytes = sourceSemanticBytes(value);
    var hash = Sha256.init(.{});
    hash.update(CONTENT_DOMAIN);
    hash.update(&bytes);
    return hash.finalResult();
}

fn sourceSemanticBytes(
    value: *const SourceArtifactV1,
) [SOURCE_ENCODED_BYTE_COUNT - 32]u8 {
    var result: [SOURCE_ENCODED_BYTE_COUNT - 32]u8 = undefined;
    var writer = Writer{ .bytes = &result };
    writeSource(&writer, value, false);
    std.debug.assert(writer.at == result.len);
    return result;
}

fn writeSource(
    writer: *Writer,
    value: *const SourceArtifactV1,
    include_identity: bool,
) void {
    writer.u16Value(value.format_version);
    writer.u16Value(value.schema_version);
    writer.u8Value(@intFromBool(value.production_activation));
    writer.bytesValue(&value.reserved);
    for (value.statement_words) |word| writer.u32Value(word);
    writer.words(value.session_id);
    writer.words(value.segment_leaf_vk_id);
    writer.words(value.recursive_parent_vk_id);
    writer.bytesValue(&value.leaf_authority_sha256);
    if (include_identity) writer.bytesValue(&value.content_identity_sha256);
}

fn subtreeIdentity(value: *const EmptyNodeAuthorityV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(SUBTREE_DOMAIN);
    hash.update(&value.statement_identity_sha256);
    hash.update(&value.leaf_authority_sha256);
    for (value.subtree_digest) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn authorityIdentity(value: *const EmptyNodeAuthorityV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hash.update(&value.statement_identity_sha256);
    hash.update(&value.leaf_authority_sha256);
    hash.update(&value.subtree_sha256);
    for (value.subtree_digest) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

fn coldInputIdentity(value: *const ColdInputV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(COLD_INPUT_DOMAIN);
    hash.update(&value.source.content_identity_sha256);
    hash.update(&value.leaf.authority_sha_id);
    hash.update(&value.node_authority.authority_sha256);
    hash.update(&value.node_public.output_identity_sha256);
    return hash.finalResult();
}

fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

fn requireDigest(value: channel.Digest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus)
            return error.InvalidCanonicalEmptySource;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidCanonicalEmptySource;
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

const Writer = struct {
    bytes: []u8,
    at: usize = 0,

    fn bytesValue(self: *Writer, value: []const u8) void {
        @memcpy(self.bytes[self.at..][0..value.len], value);
        self.at += value.len;
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

    fn words(self: *Writer, values: anytype) void {
        for (values) |value| self.u32Value(value);
    }
};

const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    fn take(self: *Reader, count: usize) Error![]const u8 {
        if (count > self.bytes.len -| self.at)
            return error.InvalidCanonicalEmptySource;
        const result = self.bytes[self.at..][0..count];
        self.at += count;
        return result;
    }

    fn u8Value(self: *Reader) Error!u8 {
        return (try self.take(1))[0];
    }

    fn boolValue(self: *Reader) Error!bool {
        return switch (try self.u8Value()) {
            0 => false,
            1 => true,
            else => error.InvalidCanonicalEmptySource,
        };
    }

    fn u16Value(self: *Reader) Error!u16 {
        return std.mem.readInt(u16, (try self.take(2))[0..2], .little);
    }

    fn u32Value(self: *Reader) Error!u32 {
        return std.mem.readInt(u32, (try self.take(4))[0..4], .little);
    }

    fn array(self: *Reader, comptime count: usize) Error![count]u8 {
        var result: [count]u8 = undefined;
        @memcpy(&result, try self.take(count));
        return result;
    }

    fn words(self: *Reader, comptime count: usize) Error![count]u32 {
        var result: [count]u32 = undefined;
        for (&result) |*word| word.* = try self.u32Value();
        return result;
    }
};

comptime {
    if (PRODUCTION_ACTIVATION or SOURCE_ARTIFACT_KIND != 14 or
        SOURCE_ENCODED_BYTE_COUNT != artifact_mod.NODE_PUBLIC_BYTE_COUNT or
        NODE_PUBLIC_SCALAR_BYTE_COUNT != 1816 or FIRST_EMPTY_INDEX != 210 or
        LAST_EMPTY_INDEX_EXCLUSIVE != 256)
    {
        @compileError("canonical-empty wrapper input contract drifted");
    }
}
