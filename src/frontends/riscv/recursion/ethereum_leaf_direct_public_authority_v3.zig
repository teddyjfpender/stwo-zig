//! Exact public authority boundary for the direct native V3 leaf wrapper.
//!
//! This replaces the legacy 56-limb leaf-authority statement. Only three
//! verifier-owned identities are public here: the link, native ProgramV2,
//! and native preprocessed Tree0 root. The eventual 47-row verifier must mix
//! and consume this exact boundary; this host-side shape is not a proof.

const std = @import("std");
const core = @import("stwo_core");
const source_air = @import("air/ethereum_leaf_link_source_v1.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SCOPE: u32 = 0x4c41_5332; // LAS2, distinct from legacy LAS1.
pub const DIGEST_WORD_COUNT: usize = 8;
pub const DIGEST_COUNT: usize = 3;
pub const WORD_COUNT: usize = DIGEST_COUNT * DIGEST_WORD_COUNT;
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const Digest = [DIGEST_WORD_COUNT]u32;
pub const Words = [WORD_COUNT]u32;

pub const AuthorityV1 = struct {
    words: Words,

    pub fn fromDigests(link: Digest, native_program: Digest, native_tree0: Digest) !AuthorityV1 {
        var result = AuthorityV1{ .words = undefined };
        @memcpy(result.words[0..DIGEST_WORD_COUNT], &link);
        @memcpy(result.words[DIGEST_WORD_COUNT .. 2 * DIGEST_WORD_COUNT], &native_program);
        @memcpy(result.words[2 * DIGEST_WORD_COUNT ..], &native_tree0);
        try result.validate();
        return result;
    }

    pub fn fromSlice(words: []const u32) !AuthorityV1 {
        if (words.len != WORD_COUNT) return error.InvalidDirectLeafPublicAuthorityShape;
        var result = AuthorityV1{ .words = undefined };
        @memcpy(&result.words, words);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const AuthorityV1) !void {
        for (self.words) |word| if (word >= core.fields.m31.Modulus)
            return error.InvalidDirectLeafPublicAuthorityWord;
    }

    pub fn validateAgainst(self: *const AuthorityV1, link: Digest, native_program: Digest, native_tree0: Digest) !void {
        const expected = try fromDigests(link, native_program, native_tree0);
        if (!std.meta.eql(self.words, expected.words))
            return error.DirectLeafPublicAuthorityMismatch;
    }

    pub fn statementTuple(self: *const AuthorityV1, index: usize) ![3]core.fields.m31.M31 {
        try self.validate();
        if (index >= WORD_COUNT) return error.InvalidDirectLeafPublicAuthorityShape;
        const M31 = core.fields.m31.M31;
        return .{
            M31.fromCanonical(SCOPE),
            M31.fromCanonical(@intCast(index)),
            M31.fromCanonical(self.words[index]),
        };
    }
};

/// Row 40 must emit exactly 24 LAS2 tuples and no orphan LAS1 tuple.
pub fn validateProjectionSchedule(rows: anytype) !void {
    if (rows.len < WORD_COUNT) return error.InvalidDirectLeafPublicAuthorityShape;
    var seen = [_]bool{false} ** WORD_COUNT;
    for (rows) |row| {
        if (row.statement_scope == source_air.LEAF_AUTHORITY_SCOPE)
            return error.InvalidDirectLeafPublicAuthorityShape;
        if (row.statement_scope != SCOPE) continue;
        if (row.active != 1 or row.global_statement_mask != 1 or
            row.local_statement_mask != 0 or row.verifier_mask != 1 or
            row.verifier_index_0 != 0 or row.statement_index >= WORD_COUNT or
            row.verifier_index_1 != row.statement_index % DIGEST_WORD_COUNT or
            seen[row.statement_index])
            return error.InvalidDirectLeafPublicAuthorityShape;
        const expected_kind = switch (row.statement_index / DIGEST_WORD_COUNT) {
            0 => source_air.LINK_DIGEST_KIND,
            1 => source_air.PROGRAM_AUTHORITY_KIND,
            2 => source_air.PREPROCESSED_ROOT_KIND,
            else => unreachable,
        };
        if (row.verifier_kind != expected_kind)
            return error.InvalidDirectLeafPublicAuthorityShape;
        seen[row.statement_index] = true;
    }
    for (seen) |present| if (!present)
        return error.InvalidDirectLeafPublicAuthorityShape;
}

test "direct authority rejects omitted or appended legacy limbs" {
    const zero: Digest = .{0} ** DIGEST_WORD_COUNT;
    const authority = try AuthorityV1.fromDigests(zero, zero, zero);
    try authority.validateAgainst(zero, zero, zero);
    try std.testing.expectError(error.InvalidDirectLeafPublicAuthorityShape, AuthorityV1.fromSlice(authority.words[0 .. WORD_COUNT - 1]));
    const legacy = [_]u32{0} ** 56;
    try std.testing.expectError(error.InvalidDirectLeafPublicAuthorityShape, AuthorityV1.fromSlice(&legacy));
    var changed = authority;
    changed.words[WORD_COUNT - 1] = 1;
    try std.testing.expectError(error.DirectLeafPublicAuthorityMismatch, changed.validateAgainst(zero, zero, zero));
    try std.testing.expectError(error.InvalidDirectLeafPublicAuthorityShape, authority.statementTuple(WORD_COUNT));
}
