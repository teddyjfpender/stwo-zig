//! Host-side authority for direct Merkle column word offsets.
//!
//! Individual trace columns remain protocol-bounded below log 31, but their
//! ordered backing span may exceed the legacy u32 word-offset ABI.  This plan
//! performs all arithmetic in u64 and distinguishes the exact inclusive u32
//! boundary from layouts that require the Poseidon-only wide leaf kernel.

const std = @import("std");

pub const Error = error{
    InvalidDirectMerkleColumnLayout,
    DirectMerkleColumnLayoutOverflow,
};

pub const PlanV1 = struct {
    column_count: usize,
    max_offset_words: u64,
    end_exclusive_words: u64,
    requires_wide_offsets: bool,

    pub fn init(offsets: []const u64, lengths: []const usize) Error!PlanV1 {
        if (offsets.len == 0 or offsets.len != lengths.len)
            return error.InvalidDirectMerkleColumnLayout;

        var max_offset_words: u64 = 0;
        var end_exclusive_words: u64 = 0;
        for (offsets, lengths) |offset, length| {
            if (length == 0) return error.InvalidDirectMerkleColumnLayout;
            const length_u64 = std.math.cast(u64, length) orelse
                return error.DirectMerkleColumnLayoutOverflow;
            const end = std.math.add(u64, offset, length_u64) catch
                return error.DirectMerkleColumnLayoutOverflow;
            max_offset_words = @max(max_offset_words, offset);
            end_exclusive_words = @max(end_exclusive_words, end);
        }

        // An end exactly at 2^32 has UINT32_MAX as its final valid index.
        const narrow_end_exclusive = @as(u64, std.math.maxInt(u32)) + 1;
        return .{
            .column_count = offsets.len,
            .max_offset_words = max_offset_words,
            .end_exclusive_words = end_exclusive_words,
            .requires_wide_offsets = end_exclusive_words > narrow_end_exclusive,
        };
    }

    pub fn initContiguous(lengths: []const usize) Error!PlanV1 {
        if (lengths.len == 0) return error.InvalidDirectMerkleColumnLayout;
        var cursor: u64 = 0;
        var max_offset_words: u64 = 0;
        for (lengths) |length| {
            if (length == 0) return error.InvalidDirectMerkleColumnLayout;
            max_offset_words = cursor;
            cursor = std.math.add(
                u64,
                cursor,
                std.math.cast(u64, length) orelse
                    return error.DirectMerkleColumnLayoutOverflow,
            ) catch return error.DirectMerkleColumnLayoutOverflow;
        }
        const narrow_end_exclusive = @as(u64, std.math.maxInt(u32)) + 1;
        return .{
            .column_count = lengths.len,
            .max_offset_words = max_offset_words,
            .end_exclusive_words = cursor,
            .requires_wide_offsets = cursor > narrow_end_exclusive,
        };
    }
};

test "direct Merkle offset plan admits the exact u32 final index" {
    const narrow_end_exclusive = @as(u64, std.math.maxInt(u32)) + 1;
    const narrow = try PlanV1.init(
        &.{narrow_end_exclusive - 2},
        &.{2},
    );
    try std.testing.expect(!narrow.requires_wide_offsets);
    try std.testing.expectEqual(narrow_end_exclusive, narrow.end_exclusive_words);

    const wide = try PlanV1.init(
        &.{narrow_end_exclusive - 2},
        &.{3},
    );
    try std.testing.expect(wide.requires_wide_offsets);
    try std.testing.expectEqual(narrow_end_exclusive + 1, wide.end_exclusive_words);
}

test "direct Merkle offset plan captures retained Stage101 Tree1 geometry" {
    const column_count: usize = 455;
    const column_words: usize = @as(usize, 1) << 24;
    const lengths = [_]usize{column_words} ** column_count;
    const plan = try PlanV1.initContiguous(&lengths);
    try std.testing.expectEqual(column_count, plan.column_count);
    try std.testing.expectEqual(@as(u64, 7_616_856_064), plan.max_offset_words);
    try std.testing.expectEqual(@as(u64, 7_633_633_280), plan.end_exclusive_words);
    try std.testing.expect(plan.requires_wide_offsets);
}

test "direct Merkle offset plan rejects hostile layout arithmetic" {
    try std.testing.expectError(
        error.InvalidDirectMerkleColumnLayout,
        PlanV1.init(&.{0}, &.{}),
    );
    try std.testing.expectError(
        error.InvalidDirectMerkleColumnLayout,
        PlanV1.init(&.{0}, &.{0}),
    );
    try std.testing.expectError(
        error.DirectMerkleColumnLayoutOverflow,
        PlanV1.init(&.{std.math.maxInt(u64)}, &.{2}),
    );
}
