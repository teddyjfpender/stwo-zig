//! Exact preprocessed lookup-table schemas at the pinned Stark-V revision.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const infra = @import("../../../infra_trace/permutation.zig");

const definition = @import("schema_definition.zig");
pub const MAX_ARITY = definition.MAX_ARITY;
pub const Kind = definition.Kind;
pub const KIND_COUNT = definition.KIND_COUNT;
pub const Error = definition.Error;
pub const domain = definition.domain;
pub const logSize = definition.logSize;
pub const arity = definition.arity;
pub const size = definition.size;
pub const Tuple = definition.Tuple;
pub const tupleAt = definition.tupleAt;
pub const indexBase = definition.indexBase;
pub const indexSecure = definition.indexSecure;
pub const validateRow = definition.validateRow;

pub const PreprocessedColumns = struct {
    columns: [MAX_ARITY][]M31 = .{&.{}} ** MAX_ARITY,
    n_columns: usize,

    pub fn deinit(self: *PreprocessedColumns, allocator: std.mem.Allocator) void {
        for (self.columns[0..self.n_columns]) |column| allocator.free(column);
        self.* = undefined;
    }
};

/// Generate deterministic tuple columns in committed bit-reversed order.
pub fn generatePreprocessed(allocator: std.mem.Allocator, kind: Kind) !PreprocessedColumns {
    const n_columns = arity(kind);
    const domain_size = size(kind);
    var result = PreprocessedColumns{ .n_columns = n_columns };
    var allocated: usize = 0;
    errdefer for (result.columns[0..allocated]) |column| allocator.free(column);
    for (result.columns[0..n_columns]) |*column| {
        column.* = try allocator.alloc(M31, domain_size);
        allocated += 1;
    }
    const table = try infra.BitReversalTable.init(allocator, logSize(kind));
    defer table.deinit(allocator);
    for (0..domain_size) |row| {
        const tuple = try tupleAt(kind, row);
        const dst = table.map(row);
        for (tuple.slice(), result.columns[0..n_columns]) |value, column| column[dst] = value;
    }
    return result;
}

test "table schemas match pinned log sizes, arities, and boundary tuples" {
    const expected_logs = [_]u32{ 18, 20, 19, 20, 16, 15 };
    const expected_arities = [_]usize{ 4, 1, 2, 3, 2, 2 };
    for (0..KIND_COUNT) |index| {
        const kind: Kind = @enumFromInt(index);
        try std.testing.expectEqual(expected_logs[index], logSize(kind));
        try std.testing.expectEqual(expected_arities[index], arity(kind));
    }

    const xor = try tupleAt(.bitwise, 0xaa | (0x55 << 8) | (2 << 16));
    try std.testing.expectEqualSlices(M31, &.{ M31.fromU64(0xaa), M31.fromU64(0x55), M31.fromU64(0xff), M31.fromU64(2) }, xor.slice());
    const range811 = try tupleAt(.range_check_8_11, size(.range_check_8_11) - 1);
    try std.testing.expectEqualSlices(M31, &.{ M31.fromU64(255), M31.fromU64(2047) }, range811.slice());
    const range884 = try tupleAt(.range_check_8_8_4, size(.range_check_8_8_4) - 1);
    try std.testing.expectEqualSlices(M31, &.{ M31.fromU64(255), M31.fromU64(255), M31.fromU64(15) }, range884.slice());
    const duplicate = try tupleAt(.range_check_m31, size(.range_check_m31) - 1);
    try std.testing.expectEqualSlices(M31, &.{ M31.zero(), M31.zero() }, duplicate.slice());
}

test "table indices roundtrip sampled rows and reject mutations" {
    const samples = [_]usize{ 0, 1, 17, 255, 256, 4095, 32766 };
    for (0..KIND_COUNT) |kind_index| {
        const kind: Kind = @enumFromInt(kind_index);
        for (samples) |sample| {
            const row = sample % size(kind);
            if (kind == .range_check_m31 and row == size(kind) - 1) continue;
            const tuple = try tupleAt(kind, row);
            try std.testing.expectEqual(row, try indexBase(kind, tuple.slice()));
            try validateRow(kind, row, tuple.slice());
        }
    }

    const bad_bitwise = [_]M31{ M31.fromU64(7), M31.fromU64(3), M31.fromU64(0), M31.fromU64(2) };
    try std.testing.expectError(error.InvalidTuple, indexBase(.bitwise, &bad_bitwise));
    const forbidden_m31 = [_]M31{ M31.fromU64(255), M31.fromU64(127) };
    try std.testing.expectError(error.InvalidTuple, indexBase(.range_check_m31, &forbidden_m31));
    const swapped = [_]M31{ M31.fromU64(2), M31.fromU64(1) };
    try std.testing.expectEqual(@as(usize, 258), try indexBase(.range_check_8_8, &swapped));
    try std.testing.expectError(error.InvalidTuple, validateRow(.range_check_8_8, 513, &swapped));
}

test "range M31 duplicate row is deterministic but not index-addressable" {
    const zero = [_]M31{ M31.zero(), M31.zero() };
    try std.testing.expectEqual(@as(usize, 0), try indexBase(.range_check_m31, &zero));
    try validateRow(.range_check_m31, size(.range_check_m31) - 1, &zero);
}

test "preprocessed columns use deterministic committed bit-reversed order" {
    const allocator = std.testing.allocator;
    const kind: Kind = .range_check_m31;
    var columns = try generatePreprocessed(allocator, kind);
    defer columns.deinit(allocator);
    try std.testing.expectEqual(arity(kind), columns.n_columns);
    for (columns.columns[0..columns.n_columns]) |column| {
        try std.testing.expectEqual(size(kind), column.len);
    }
    const table = try infra.BitReversalTable.init(allocator, logSize(kind));
    defer table.deinit(allocator);
    for ([_]usize{ 0, 1, 258, size(kind) - 2, size(kind) - 1 }) |row| {
        const tuple = try tupleAt(kind, row);
        const dst = table.map(row);
        var sampled: [MAX_ARITY]M31 = undefined;
        for (sampled[0..tuple.len], columns.columns[0..tuple.len]) |*value, column| {
            value.* = column[dst];
        }
        try validateRow(kind, row, sampled[0..tuple.len]);
        sampled[0] = sampled[0].add(M31.one());
        try std.testing.expectError(error.InvalidTuple, validateRow(kind, row, sampled[0..tuple.len]));
    }
}
