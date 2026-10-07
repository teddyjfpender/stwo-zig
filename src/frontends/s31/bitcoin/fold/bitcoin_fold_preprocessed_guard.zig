//! Exact in-memory topology guard for repeated Bitcoin fold proving.
//!
//! The sealed root is derived once from the witness-free circuit. Each
//! value-bearing step may compare its preprocessed trace to that exact trace
//! instead of rebuilding an FFT/Merkle commitment merely to check equality.
//! This changes no AIR, transcript, key, statement, or proof bytes.
const std = @import("std");

pub fn requireExact(expected: anytype, actual: anytype) !void {
    if (expected.first_permutation_row != actual.first_permutation_row or
        expected.n_outputs != actual.n_outputs)
        return error.BitcoinFoldPreprocessedMetadataMismatch;
    if (expected.columns.len != actual.columns.len)
        return error.BitcoinFoldPreprocessedLayoutMismatch;
    for (expected.columns, actual.columns) |left, right| {
        if (!std.mem.eql(u8, left.id, right.id) or left.values.len != right.values.len)
            return error.BitcoinFoldPreprocessedLayoutMismatch;
        for (left.values, right.values) |a, b| {
            if (a.v != b.v) return error.BitcoinFoldPreprocessedValueMismatch;
        }
    }
}

test "first-retarget fold profile exact guard rejects altered columns and metadata" {
    const Word = struct { v: u32 };
    const Column = struct { id: []const u8, values: []const Word };
    const Trace = struct {
        columns: [45]Column,
        first_permutation_row: usize,
        n_outputs: usize,
    };
    var left_words = [_]Word{ .{ .v = 1 }, .{ .v = 0 } };
    var right_words = left_words;
    var left: Trace = .{
        .columns = undefined,
        .first_permutation_row = 9,
        .n_outputs = 8,
    };
    var right = left;
    for (&left.columns, &right.columns) |*a, *b| {
        a.* = .{ .id = "fixed", .values = &left_words };
        b.* = .{ .id = "fixed", .values = &right_words };
    }
    try requireExact(&left, &right);
    right_words[0].v = 0;
    try std.testing.expectError(error.BitcoinFoldPreprocessedValueMismatch, requireExact(&left, &right));
    right_words[0].v = 1;
    right.columns[0].id = "other";
    try std.testing.expectError(error.BitcoinFoldPreprocessedLayoutMismatch, requireExact(&left, &right));
    right.columns[0].id = "fixed";
    right.first_permutation_row += 1;
    try std.testing.expectError(error.BitcoinFoldPreprocessedMetadataMismatch, requireExact(&left, &right));
    right.first_permutation_row -= 1;
    right.n_outputs -= 1;
    try std.testing.expectError(error.BitcoinFoldPreprocessedMetadataMismatch, requireExact(&left, &right));
}
