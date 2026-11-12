const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const opcode_entries = @import("../lookups/opcode_entries.zig");
const legacy_oracle = @import("../../runner/witness/fence_legacy_test_oracle.zig");
const witness = @import("typed_fence_witness.zig");

pub const OwnedColumns = struct {
    allocator: std.mem.Allocator,
    storage: [witness.MAIN_COLUMN_COUNT][]M31,
    views: [witness.MAIN_COLUMN_COUNT][]M31,

    pub fn init(
        allocator: std.mem.Allocator,
        len: usize,
        initial: M31,
    ) !OwnedColumns {
        var storage: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
        var views: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
        var initialized: usize = 0;
        errdefer for (storage[0..initialized]) |column| allocator.free(column);
        for (&storage, &views) |*owned, *view| {
            owned.* = try allocator.alloc(M31, len);
            initialized += 1;
            @memset(owned.*, initial);
            view.* = owned.*;
        }
        return .{ .allocator = allocator, .storage = storage, .views = views };
    }

    pub fn deinit(self: *OwnedColumns) void {
        for (self.storage) |column| self.allocator.free(column);
        self.* = undefined;
    }

    pub fn expectStorageValue(self: *const OwnedColumns, expected: M31) !void {
        for (self.storage) |column| {
            for (column) |actual| try std.testing.expectEqual(expected, actual);
        }
    }
};

pub fn makeRow(
    rd: u5,
    rs1: u5,
    immediate: i32,
    clock: u32,
    pc: u32,
    register_value: u32,
) witness.TraceRow {
    std.debug.assert(immediate >= -2048 and immediate <= 2047);
    return .{
        .clk = clock,
        .pc = pc,
        .opcode = .FENCE,
        .rd = rd,
        .rs1 = rs1,
        .rs2 = 0,
        .imm = immediate,
        .rs1_val = register_value,
        .rs2_val = 0,
        .rd_prev_val = register_value,
        .rd_val = register_value,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = pc +% 4,
    };
}

pub fn expectLegacyColumns(
    rows: []const witness.TraceRow,
    log_size: u32,
    actual: *const [witness.MAIN_COLUMN_COUNT][]M31,
) !void {
    const domain_size = @as(usize, 1) << @intCast(log_size);
    try std.testing.expect(rows.len <= domain_size);
    var expected = try OwnedColumns.init(std.testing.allocator, domain_size, M31.zero());
    defer expected.deinit();
    for (rows, 0..) |row, index| legacy_oracle.writeRow(&expected.views, index, row);
    for (actual, expected.views) |actual_column, expected_column| {
        try std.testing.expectEqualSlices(
            u8,
            std.mem.sliceAsBytes(expected_column),
            std.mem.sliceAsBytes(actual_column),
        );
    }
}

pub fn expectProofInputParity(
    actual: *const [witness.MAIN_COLUMN_COUNT][]M31,
    row_index: usize,
    row: witness.TraceRow,
) !void {
    var expected_storage: [witness.MAIN_COLUMN_COUNT][1]M31 = undefined;
    var expected_columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&expected_storage, &expected_columns) |*storage, *column|
        column.* = storage;
    legacy_oracle.writeRow(&expected_columns, 0, row);
    var actual_main: [witness.MAIN_COLUMN_COUNT]QM31 = undefined;
    var expected_main: [witness.MAIN_COLUMN_COUNT]QM31 = undefined;
    for (&actual_main, &expected_main, actual, expected_storage) |
        *actual_value,
        *expected_value,
        actual_column,
        expected_column,
    | {
        actual_value.* = QM31.fromBase(actual_column[row_index]);
        expected_value.* = QM31.fromBase(expected_column[0]);
        try std.testing.expectEqual(expected_column[0], actual_column[row_index]);
    }
    const generated = try opcode_entries.fromMain(.fence, &actual_main);
    const legacy = try opcode_entries.fromMain(.fence, &expected_main);
    try std.testing.expectEqual(legacy.len, generated.len);
    try std.testing.expectEqual(legacy.batch_size, generated.batch_size);
    for (legacy.entries[0..legacy.len], generated.entries[0..generated.len]) |
        expected,
        got,
    | {
        try std.testing.expectEqual(expected.domain, got.domain);
        try std.testing.expect(expected.numerator.eql(got.numerator));
        try std.testing.expectEqual(expected.arity, got.arity);
        try std.testing.expectEqual(expected.role, got.role);
        try std.testing.expectEqual(expected.access_ordinal, got.access_ordinal);
        for (expected.values[0..expected.arity], got.values[0..got.arity]) |want, have|
            try std.testing.expect(want.eql(have));
    }
}
