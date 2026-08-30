//! Physical-table roundtrip and padding tests for Keccak-f lookups.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const infra = @import("../../infra_trace.zig");
const tables = @import("keccakf_tables.zig");

test "keccakf tables: committed sizes and semantic prefixes are pinned" {
    try std.testing.expectEqual(@as(u32, 13), tables.logSize(.chi));
    try std.testing.expectEqual(@as(usize, 8_192), tables.size(.chi));
    try std.testing.expectEqual(tables.size(.chi), tables.semanticRows(.chi));
    try std.testing.expectEqual(@as(u32, 10), tables.logSize(.xor5));
    try std.testing.expectEqual(@as(usize, 1_024), tables.size(.xor5));
    try std.testing.expectEqual(tables.size(.xor5), tables.semanticRows(.xor5));
}

test "keccakf tables: sampled semantic rows roundtrip and mutations reject" {
    const chi_rows = [_]usize{ 0, 1, 15, 16, 4095, 4096, 8191 };
    for (chi_rows) |row| {
        var tuple = try tables.tupleAt(.chi, row);
        try std.testing.expectEqual(row, try tables.index(.chi, &tuple));
        try tables.validateRow(.chi, row, &tuple);
        tuple[5] = tuple[5].add(M31.one());
        try std.testing.expectError(error.InvalidTuple, tables.index(.chi, &tuple));
    }
    const xor_rows = [_]usize{ 0, 1, 3, 4, 255, 256, 1023 };
    for (xor_rows) |row| {
        var tuple = try tables.tupleAt(.xor5, row);
        try std.testing.expectEqual(row, try tables.index(.xor5, &tuple));
        try tables.validateRow(.xor5, row, &tuple);
        tuple[3] = tuple[3].add(M31.one());
        try std.testing.expectError(error.InvalidTuple, tables.index(.xor5, &tuple));
    }
}

test "keccakf tables: both compact domains are exact with no padding" {
    for ([_]tables.Kind{ .chi, .xor5 }) |kind| {
        const last_row = tables.size(kind) - 1;
        const last = try tables.tupleAt(kind, last_row);
        try std.testing.expectEqual(last_row, try tables.index(kind, &last));
        try std.testing.expectError(error.ValueOutOfRange, tables.tupleAt(kind, last_row + 1));
    }
}

test "keccakf tables: xor5 generation uses canonical bit-reversed commitment order" {
    var columns = try tables.generatePreprocessed(std.testing.allocator, .xor5);
    defer columns.deinit(std.testing.allocator);
    const reversal = try infra.BitReversalTable.init(std.testing.allocator, tables.logSize(.xor5));
    defer reversal.deinit(std.testing.allocator);
    const samples = [_]usize{ 0, 1, 17, 255, 512, 1023 };
    for (samples) |row| {
        const expected = try tables.tupleAt(.xor5, row);
        const committed = reversal.map(row);
        for (expected, columns.columns) |value, column|
            try std.testing.expect(value.eql(column[committed]));
    }
}
