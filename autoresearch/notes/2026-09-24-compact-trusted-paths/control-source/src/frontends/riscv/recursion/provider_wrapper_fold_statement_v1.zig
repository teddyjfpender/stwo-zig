//! Fixed field-native public statement for an ordered provider-proof fold.
//!
//! A leaf statement identifies one provider verifier program, exact Tree0
//! commitment, relation context, ordered call range, and provider claim. A
//! fold statement appends exactly one right-hand leaf to an existing ordered
//! prefix. Both the program tree and statement subtree use canonical
//! Poseidon-M31 hashing; native SHA identities remain transport-only.

const std = @import("std");
const core = @import("stwo_core");

const channel = @import("poseidon2_channel.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const m31 = core.fields.m31;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const WORD_COUNT: usize = 36;
pub const PROGRAM_LEAF_DOMAIN: u32 = 0x5057_4c31; // "PWL1"
pub const PROGRAM_FOLD_DOMAIN: u32 = 0x5057_4631; // "PWF1"
pub const SUBTREE_DOMAIN: u32 = 0x5057_5331; // "PWS1"

pub const KindV1 = enum(u32) {
    provider_leaf = 1,
    ordered_fold = 2,
};

pub const StatementV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    kind: KindV1,
    height: u32,
    first_shard: u32,
    shard_count: u32,
    first_call: u32,
    call_count: u32,
    relation_context: channel.Digest,
    program_tree: channel.Digest,
    provider_claim: QM31,
    subtree: channel.Digest,

    pub fn validate(self: StatementV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or self.shard_count == 0 or
            self.call_count == 0 or
            (self.kind == .provider_leaf and
                (self.height != 0 or self.shard_count != 1)) or
            (self.kind == .ordered_fold and
                (self.height == 0 or self.shard_count < 2)))
        {
            return error.InvalidProviderWrapperFoldStatement;
        }
        _ = std.math.add(u32, self.first_shard, self.shard_count) catch
            return error.InvalidProviderWrapperFoldStatement;
        _ = std.math.add(u32, self.first_call, self.call_count) catch
            return error.InvalidProviderWrapperFoldStatement;
        try requireDigest(self.relation_context);
        try requireDigest(self.program_tree);
        try requireQm31(self.provider_claim);
        try requireDigest(self.subtree);
        if (!std.meta.eql(self.subtree, try subtreeDigest(self)))
            return error.InvalidProviderWrapperFoldStatement;
    }

    pub fn words(self: StatementV1) ![WORD_COUNT]M31 {
        try self.validate();
        return wordsUnchecked(self);
    }
};

pub const LeafInputV1 = struct {
    shard_ordinal: u32,
    first_call: u32,
    call_count: u32,
    relation_context: channel.Digest,
    verifier_program_authority: channel.Digest,
    preprocessed_commitment_root: channel.Digest,
    provider_claim: QM31,
};

pub fn leaf(input: LeafInputV1) !StatementV1 {
    if (input.call_count == 0) return error.InvalidProviderWrapperFoldInput;
    _ = std.math.add(u32, input.first_call, input.call_count) catch
        return error.InvalidProviderWrapperFoldInput;
    try requireDigest(input.relation_context);
    try requireDigest(input.verifier_program_authority);
    try requireDigest(input.preprocessed_commitment_root);
    try requireQm31(input.provider_claim);
    var program_hasher = channel.CanonicalWordHasher.init(PROGRAM_LEAF_DOMAIN);
    updateDigest(&program_hasher, input.verifier_program_authority);
    updateDigest(&program_hasher, input.preprocessed_commitment_root);
    var result = StatementV1{
        .kind = .provider_leaf,
        .height = 0,
        .first_shard = input.shard_ordinal,
        .shard_count = 1,
        .first_call = input.first_call,
        .call_count = input.call_count,
        .relation_context = input.relation_context,
        .program_tree = program_hasher.finalize(),
        .provider_claim = input.provider_claim,
        .subtree = undefined,
    };
    result.subtree = try subtreeDigest(result);
    try result.validate();
    return result;
}

/// Canonical left fold. The right input is always one freshly verified
/// provider leaf, so arbitrary dynamic N needs no fixed-width flat circuit.
pub fn fold(left: StatementV1, right: StatementV1) !StatementV1 {
    try left.validate();
    try right.validate();
    if (right.kind != .provider_leaf or right.height != 0 or
        !std.meta.eql(left.relation_context, right.relation_context) or
        right.first_shard != try std.math.add(
            u32,
            left.first_shard,
            left.shard_count,
        ) or right.first_call != try std.math.add(
        u32,
        left.first_call,
        left.call_count,
    )) return error.InvalidProviderWrapperFoldInput;
    var program_hasher = channel.CanonicalWordHasher.init(PROGRAM_FOLD_DOMAIN);
    updateDigest(&program_hasher, left.program_tree);
    updateDigest(&program_hasher, right.program_tree);
    var result = StatementV1{
        .kind = .ordered_fold,
        .height = try std.math.add(u32, left.height, 1),
        .first_shard = left.first_shard,
        .shard_count = try std.math.add(u32, left.shard_count, 1),
        .first_call = left.first_call,
        .call_count = try std.math.add(u32, left.call_count, right.call_count),
        .relation_context = left.relation_context,
        .program_tree = program_hasher.finalize(),
        .provider_claim = left.provider_claim.add(right.provider_claim),
        .subtree = undefined,
    };
    result.subtree = try subtreeDigest(result);
    try result.validate();
    return result;
}

pub fn subtreeDigest(value: StatementV1) !channel.Digest {
    var hasher = channel.CanonicalWordHasher.init(SUBTREE_DOMAIN);
    const preimage = preimageWords(value);
    hasher.update(&preimage);
    return hasher.finalize();
}

pub fn preimageWords(value: StatementV1) [WORD_COUNT - 8]M31 {
    var words: [WORD_COUNT - 8]M31 = undefined;
    var cursor: usize = 0;
    appendWord(&words, &cursor, value.format_version);
    appendWord(&words, &cursor, value.schema_version);
    appendWord(&words, &cursor, @intFromEnum(value.kind));
    appendWord(&words, &cursor, value.height);
    appendWord(&words, &cursor, value.first_shard);
    appendWord(&words, &cursor, value.shard_count);
    appendWord(&words, &cursor, value.first_call);
    appendWord(&words, &cursor, value.call_count);
    appendDigest(&words, &cursor, value.relation_context);
    appendDigest(&words, &cursor, value.program_tree);
    for (value.provider_claim.toM31Array()) |limb| {
        words[cursor] = limb;
        cursor += 1;
    }
    std.debug.assert(cursor == words.len);
    return words;
}

fn wordsUnchecked(value: StatementV1) [WORD_COUNT]M31 {
    var result: [WORD_COUNT]M31 = undefined;
    const preimage = preimageWords(value);
    @memcpy(result[0..preimage.len], &preimage);
    var cursor = preimage.len;
    appendDigest(&result, &cursor, value.subtree);
    std.debug.assert(cursor == result.len);
    return result;
}

fn appendWord(destination: anytype, cursor: *usize, value: anytype) void {
    destination[cursor.*] = M31.fromCanonical(@intCast(value));
    cursor.* += 1;
}

fn appendDigest(
    destination: anytype,
    cursor: *usize,
    value: channel.Digest,
) void {
    for (value) |word| appendWord(destination, cursor, word);
}

fn updateDigest(
    hasher: *channel.CanonicalWordHasher,
    value: channel.Digest,
) void {
    var words: [8]M31 = undefined;
    for (value, &words) |word, *destination|
        destination.* = M31.fromCanonical(word);
    hasher.update(&words);
}

fn requireDigest(value: channel.Digest) !void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus)
            return error.InvalidProviderWrapperFoldInput;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidProviderWrapperFoldInput;
}

fn requireQm31(value: QM31) !void {
    for (value.toM31Array()) |limb| if (limb.toU32() >= m31.Modulus)
        return error.InvalidProviderWrapperFoldInput;
}

comptime {
    if (PROGRAM_LEAF_DOMAIN >= m31.Modulus or
        PROGRAM_FOLD_DOMAIN >= m31.Modulus or SUBTREE_DOMAIN >= m31.Modulus or
        WORD_COUNT != 36)
    {
        @compileError("provider wrapper fold statement ABI drifted");
    }
}
