//! Physical-table roundtrip and padding tests for Keccak-f lookups.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const infra = @import("../../infra_trace.zig");
const tables = @import("keccakf_tables.zig");

test "keccakf tables: committed sizes and semantic prefixes are pinned" {
    try std.testing.expectEqual(@as(u32, 21), tables.logSize(.chi));
    try std.testing.expectEqual(@as(usize, 2_097_152), tables.size(.chi));
    try std.testing.expectEqual(tables.size(.chi), tables.semanticRows(.chi));
    try std.testing.expectEqual(@as(u32, 16), tables.logSize(.xor5));
    try std.testing.expectEqual(@as(usize, 65_536), tables.size(.xor5));
    try std.testing.expectEqual(@as(usize, 46_656), tables.semanticRows(.xor5));
}

test "keccakf tables: sampled semantic rows roundtrip and mutations reject" {
    const chi_rows = [_]usize{ 0, 1, 15, 16, 1_048_575, 1_048_576, 2_097_151 };
    for (chi_rows) |row| {
        var tuple = try tables.tupleAt(.chi, row);
        try std.testing.expectEqual(row, try tables.index(.chi, &tuple));
        try tables.validateRow(.chi, row, &tuple);
        tuple[5] = tuple[5].add(M31.one());
        try std.testing.expectError(error.InvalidTuple, tables.index(.chi, &tuple));
    }
    const xor_rows = [_]usize{ 0, 1, 35, 36, 1295, 1296, 46_655 };
    for (xor_rows) |row| {
        var tuple = try tables.tupleAt(.xor5, row);
        try std.testing.expectEqual(row, try tables.index(.xor5, &tuple));
        try tables.validateRow(.xor5, row, &tuple);
        tuple[3] = tuple[3].add(M31.one());
        try std.testing.expectError(error.InvalidTuple, tables.index(.xor5, &tuple));
    }
}

test "keccakf tables: xor5 padding is unique and unreachable by semantic indexing" {
    const first = try tables.tupleAt(.xor5, tables.semanticRows(.xor5));
    const last = try tables.tupleAt(.xor5, tables.size(.xor5) - 1);
    try std.testing.expect(!std.meta.eql(first, last));
    try std.testing.expectError(error.SentinelTuple, tables.index(.xor5, &first));
    try std.testing.expectError(error.SentinelTuple, tables.index(.xor5, &last));
    try tables.validateRow(.xor5, tables.semanticRows(.xor5), &first);
    try tables.validateRow(.xor5, tables.size(.xor5) - 1, &last);
}

test "keccakf tables: xor5 generation uses canonical bit-reversed commitment order" {
    var columns = try tables.generatePreprocessed(std.testing.allocator, .xor5);
    defer columns.deinit(std.testing.allocator);
    const reversal = try infra.BitReversalTable.init(std.testing.allocator, tables.logSize(.xor5));
    defer reversal.deinit(std.testing.allocator);
    const samples = [_]usize{ 0, 1, 17, 46_655, 46_656, 65_535 };
    for (samples) |row| {
        const expected = try tables.tupleAt(.xor5, row);
        const committed = reversal.map(row);
        for (expected, columns.columns) |value, column|
            try std.testing.expect(value.eql(column[committed]));
    }
}
