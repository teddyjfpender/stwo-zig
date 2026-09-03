//! Field-native public ABI shared by every production recursive wrapper.
//!
//! SHA-256 remains the immutable transport/CAS identity, but it is not a
//! recursion-field primitive and therefore is not part of the AIR relation.
//! The recursive proof publishes canonical M31 words and four Poseidon2
//! digests: statement, role-owned source, subtree, and complete output.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_v1 = @import("recursive_node_artifact_v1.zig");

const m31 = stwo_core.fields.m31;
const M31 = m31.M31;
const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u32 = 2;
pub const SCHEMA_VERSION: u32 = 1;
pub const STATEMENT_WORD_COUNT: usize = artifact_v1.STATEMENT_WORD_COUNT;
pub const DIGEST_WORD_COUNT: usize = channel.RATE;
pub const HEADER_WORD_COUNT: usize = 6;
pub const DIGEST_COUNT: usize = 4;
pub const AIR_WORD_COUNT: usize = HEADER_WORD_COUNT + STATEMENT_WORD_COUNT +
    DIGEST_COUNT * DIGEST_WORD_COUNT;
pub const ENCODED_BYTE_COUNT: usize = AIR_WORD_COUNT * @sizeOf(u32);

pub const STATEMENT_DIGEST_DOMAIN: u32 = 0x5354_5632; // "STV2"
pub const PARENT_SOURCE_DOMAIN: u32 = 0x5053_5632; // "PSV2"
pub const SUBTREE_DIGEST_DOMAIN: u32 = 0x5342_5632; // "SBV2"
pub const OUTPUT_DIGEST_DOMAIN: u32 = 0x4f55_5632; // "OUV2"

const ABI_IDENTITY_DOMAIN =
    "stwo-zig/recursive-field-node-public-abi/v2\x00";

pub const Error = artifact_v1.Error || recursion.span_statement.Error || error{
    ChildCoordinateMismatch,
    InvalidFieldNodePublic,
    InvalidFieldNodeSource,
    NonCanonicalFieldNodeWord,
};

pub const NodePublicV2 = struct {
    format_version: u32 = FORMAT_VERSION,
    schema_version: u32 = SCHEMA_VERSION,
    node_kind: artifact_v1.NodeKindV1,
    coordinate: artifact_v1.TaskCoordinateV1,
    statement_words: [STATEMENT_WORD_COUNT]u32,
    statement_digest: channel.Digest,
    source_digest: channel.Digest,
    subtree_digest: channel.Digest,
    output_digest: channel.Digest,

    /// `source_digest` must be derived by the role-specific wrapper AIR from
    /// its freshly verified native source. This constructor only assembles the
    /// common output relation.
    pub fn initLeaf(
        coordinate: artifact_v1.TaskCoordinateV1,
        statement_words: [STATEMENT_WORD_COUNT]u32,
        source_digest: channel.Digest,
    ) Error!NodePublicV2 {
        try coordinate.validate();
        if (coordinate.height != 0) return error.InvalidFieldNodePublic;
        try validateDigest(source_digest);
        var result = NodePublicV2{
            .node_kind = try artifact_v1.expectedNodeKind(coordinate),
            .coordinate = coordinate,
            .statement_words = statement_words,
            .statement_digest = try statementDigest(statement_words),
            .source_digest = source_digest,
            .subtree_digest = undefined,
            .output_digest = undefined,
        };
        result.subtree_digest = nodeSubtreeDigest(&result);
        result.output_digest = nodeOutputDigest(&result);
        try result.validate();
        return result;
    }

    /// Recomputes the parent SpanStatement and ordered child-source digest;
    /// caller-authored parent words are never accepted.
    pub fn initParent(
        left: *const NodePublicV2,
        right: *const NodePublicV2,
        coordinate: artifact_v1.TaskCoordinateV1,
    ) !NodePublicV2 {
        try validateChildren(left, right, coordinate);
        const result = try initParentUnchecked(left, right, coordinate);
        try result.validateParentAgainst(left, right);
        return result;
    }

    pub fn validate(self: *const NodePublicV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION)
        {
            return error.InvalidFieldNodePublic;
        }
        try self.coordinate.validate();
        if (self.node_kind != try artifact_v1.expectedNodeKind(self.coordinate))
            return error.InvalidFieldNodePublic;
        const statement = try spanStatement(self.statement_words);
        if (statement.slots.height != self.coordinate.height or
            statement.slots.nodeIndex() != self.coordinate.index)
        {
            return error.InvalidFieldNodePublic;
        }
        inline for (.{
            self.statement_digest,
            self.source_digest,
            self.subtree_digest,
            self.output_digest,
        }) |digest| try validateDigest(digest);
        if (!std.meta.eql(
            self.statement_digest,
            try statementDigest(self.statement_words),
        ) or !std.meta.eql(
            self.subtree_digest,
            nodeSubtreeDigest(self),
        ) or !std.meta.eql(
            self.output_digest,
            nodeOutputDigest(self),
        )) return error.InvalidFieldNodePublic;
    }

    pub fn validateLeafSource(
        self: *const NodePublicV2,
        expected_source_digest: channel.Digest,
    ) Error!void {
        try self.validate();
        if (self.coordinate.height != 0 or
            !std.meta.eql(self.source_digest, expected_source_digest))
        {
            return error.InvalidFieldNodeSource;
        }
    }

    pub fn validateParentAgainst(
        self: *const NodePublicV2,
        left: *const NodePublicV2,
        right: *const NodePublicV2,
    ) !void {
        try self.validate();
        try validateChildren(left, right, self.coordinate);
        const expected = try initParentUnchecked(left, right, self.coordinate);
        if (!std.meta.eql(self.*, expected))
            return error.InvalidFieldNodePublic;
    }

    pub fn canonicalAirWords(self: *const NodePublicV2) Error![AIR_WORD_COUNT]u32 {
        try self.validate();
        var result: [AIR_WORD_COUNT]u32 = undefined;
        var at: usize = 0;
        appendHeader(&result, &at, self);
        appendSlice(&result, &at, &self.statement_words);
        appendSlice(&result, &at, &self.statement_digest);
        appendSlice(&result, &at, &self.source_digest);
        appendSlice(&result, &at, &self.subtree_digest);
        appendSlice(&result, &at, &self.output_digest);
        std.debug.assert(at == result.len);
        return result;
    }

    pub fn encodeCanonical(self: *const NodePublicV2) Error![ENCODED_BYTE_COUNT]u8 {
        const words = try self.canonicalAirWords();
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

    pub fn decodeCanonical(bytes: []const u8) Error!NodePublicV2 {
        if (bytes.len != ENCODED_BYTE_COUNT)
            return error.InvalidFieldNodePublic;
        var words: [AIR_WORD_COUNT]u32 = undefined;
        for (&words, 0..) |*word, index|
            word.* = std.mem.readInt(
                u32,
                bytes[index * 4 ..][0..4],
                .little,
            );
        var at: usize = 0;
        const format_version = take(&words, &at);
        const schema_version = take(&words, &at);
        const node_kind = std.meta.intToEnum(
            artifact_v1.NodeKindV1,
            take(&words, &at),
        ) catch return error.InvalidFieldNodePublic;
        const coordinate = artifact_v1.TaskCoordinateV1{
            .height = std.math.cast(u8, take(&words, &at)) orelse
                return error.InvalidFieldNodePublic,
            .index = take(&words, &at),
            .global_ordinal = take(&words, &at),
        };
        const result = NodePublicV2{
            .format_version = format_version,
            .schema_version = schema_version,
            .node_kind = node_kind,
            .coordinate = coordinate,
            .statement_words = takeArray(STATEMENT_WORD_COUNT, &words, &at),
            .statement_digest = takeArray(DIGEST_WORD_COUNT, &words, &at),
            .source_digest = takeArray(DIGEST_WORD_COUNT, &words, &at),
            .subtree_digest = takeArray(DIGEST_WORD_COUNT, &words, &at),
            .output_digest = takeArray(DIGEST_WORD_COUNT, &words, &at),
        };
        if (at != words.len) return error.InvalidFieldNodePublic;
        try result.validate();
        const canonical = try result.encodeCanonical();
        if (!std.mem.eql(u8, bytes, &canonical))
            return error.InvalidFieldNodePublic;
        return result;
    }
};

pub fn abiIdentitySha256() [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(ABI_IDENTITY_DOMAIN);
    hashInt(&hash, u32, FORMAT_VERSION);
    hashInt(&hash, u32, SCHEMA_VERSION);
    hashInt(&hash, u32, AIR_WORD_COUNT);
    hashInt(&hash, u32, STATEMENT_WORD_COUNT);
    hashInt(&hash, u32, DIGEST_WORD_COUNT);
    inline for (.{
        STATEMENT_DIGEST_DOMAIN,
        PARENT_SOURCE_DOMAIN,
        SUBTREE_DIGEST_DOMAIN,
        OUTPUT_DIGEST_DOMAIN,
    }) |domain| hashInt(&hash, u32, domain);
    return hash.finalResult();
}

pub fn statementDigest(
    statement_words: [STATEMENT_WORD_COUNT]u32,
) Error!channel.Digest {
    for (statement_words) |word|
        if (word >= m31.Modulus) return error.NonCanonicalFieldNodeWord;
    _ = try spanStatement(statement_words);
    return channel.hashCanonicalU32s(
        &statement_words,
        STATEMENT_DIGEST_DOMAIN,
    );
}

pub fn parentSourceDigest(
    left: *const NodePublicV2,
    right: *const NodePublicV2,
) channel.Digest {
    var words: [4 * DIGEST_WORD_COUNT]u32 = undefined;
    var at: usize = 0;
    appendSlice(&words, &at, &left.output_digest);
    appendSlice(&words, &at, &left.subtree_digest);
    appendSlice(&words, &at, &right.output_digest);
    appendSlice(&words, &at, &right.subtree_digest);
    return channel.hashCanonicalU32s(&words, PARENT_SOURCE_DOMAIN);
}

pub fn nodeSubtreeDigest(value: *const NodePublicV2) channel.Digest {
    var words: [HEADER_WORD_COUNT + 2 * DIGEST_WORD_COUNT]u32 = undefined;
    var at: usize = 0;
    appendHeader(&words, &at, value);
    appendSlice(&words, &at, &value.statement_digest);
    appendSlice(&words, &at, &value.source_digest);
    return channel.hashCanonicalU32s(&words, SUBTREE_DIGEST_DOMAIN);
}

pub fn nodeOutputDigest(value: *const NodePublicV2) channel.Digest {
    var words: [
        HEADER_WORD_COUNT + STATEMENT_WORD_COUNT +
            3 * DIGEST_WORD_COUNT
    ]u32 = undefined;
    var at: usize = 0;
    appendHeader(&words, &at, value);
    appendSlice(&words, &at, &value.statement_words);
    appendSlice(&words, &at, &value.statement_digest);
    appendSlice(&words, &at, &value.source_digest);
    appendSlice(&words, &at, &value.subtree_digest);
    return channel.hashCanonicalU32s(&words, OUTPUT_DIGEST_DOMAIN);
}

fn initParentUnchecked(
    left: *const NodePublicV2,
    right: *const NodePublicV2,
    coordinate: artifact_v1.TaskCoordinateV1,
) !NodePublicV2 {
    const left_statement = try spanStatement(left.statement_words);
    const right_statement = try spanStatement(right.statement_words);
    const parent_statement = try recursion.span_statement.SpanStatement.fold(
        left_statement,
        right_statement,
    );
    const parent_words_m31 = try parent_statement.canonicalWords();
    var parent_words: [STATEMENT_WORD_COUNT]u32 = undefined;
    for (&parent_words, parent_words_m31) |*destination, word|
        destination.* = word.toU32();
    var result = NodePublicV2{
        .node_kind = try artifact_v1.expectedNodeKind(coordinate),
        .coordinate = coordinate,
        .statement_words = parent_words,
        .statement_digest = try statementDigest(parent_words),
        .source_digest = parentSourceDigest(left, right),
        .subtree_digest = undefined,
        .output_digest = undefined,
    };
    result.subtree_digest = nodeSubtreeDigest(&result);
    result.output_digest = nodeOutputDigest(&result);
    return result;
}

fn validateChildren(
    left: *const NodePublicV2,
    right: *const NodePublicV2,
    parent: artifact_v1.TaskCoordinateV1,
) !void {
    try left.validate();
    try right.validate();
    try parent.validate();
    if (parent.height == 0 or left.coordinate.height + 1 != parent.height or
        right.coordinate.height != left.coordinate.height or
        left.coordinate.index != parent.index * 2 or
        right.coordinate.index != left.coordinate.index + 1)
    {
        return error.ChildCoordinateMismatch;
    }
}

fn spanStatement(
    words: [STATEMENT_WORD_COUNT]u32,
) !recursion.span_statement.SpanStatement {
    var canonical: [STATEMENT_WORD_COUNT]M31 = undefined;
    for (&canonical, words) |*destination, word| {
        if (word >= m31.Modulus) return error.NonCanonicalFieldNodeWord;
        destination.* = M31.fromCanonical(word);
    }
    return recursion.span_statement.SpanStatement.fromCanonicalWords(
        &canonical,
    ) catch error.InvalidFieldNodePublic;
}

fn validateDigest(digest: channel.Digest) Error!void {
    var aggregate: u32 = 0;
    for (digest) |word| {
        if (word >= m31.Modulus) return error.NonCanonicalFieldNodeWord;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidFieldNodePublic;
}

fn appendHeader(words: anytype, at: *usize, value: *const NodePublicV2) void {
    inline for (.{
        value.format_version,
        value.schema_version,
        @intFromEnum(value.node_kind),
        value.coordinate.height,
        value.coordinate.index,
        value.coordinate.global_ordinal,
    }) |word| append(words, at, word);
}

fn appendSlice(words: anytype, at: *usize, values: []const u32) void {
    for (values) |value| append(words, at, value);
}

fn append(words: anytype, at: *usize, value: anytype) void {
    std.debug.assert(at.* < words.len);
    words[at.*] = @intCast(value);
    at.* += 1;
}

fn take(words: []const u32, at: *usize) u32 {
    std.debug.assert(at.* < words.len);
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

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (STATEMENT_WORD_COUNT != 412 or DIGEST_WORD_COUNT != 8 or
        AIR_WORD_COUNT != 450 or ENCODED_BYTE_COUNT != 1800)
    {
        @compileError("recursive field node public V2 ABI drifted");
    }
}
