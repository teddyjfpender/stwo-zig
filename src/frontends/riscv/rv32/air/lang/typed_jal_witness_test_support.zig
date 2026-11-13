//! Allocation-conscious differential support for the typed JAL witness.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const opcode_entries = @import("../lookups/opcode_entries.zig");
const legacy_oracle = @import("../../runner/witness/jal_legacy_test_oracle.zig");
const witness = @import("typed_jal_witness.zig");

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
    immediate: i32,
    clock: u32,
    pc: u32,
    previous: u32,
    previous_clock: u32,
) witness.TraceRow {
    const immediate_bits: u32 = @bitCast(immediate);
    const target = pc +% immediate_bits;
    std.debug.assert(immediate >= -1_048_576 and immediate <= 1_048_574);
    std.debug.assert(immediate_bits & 1 == 0);
    std.debug.assert(pc & 3 == 0 and pc < (@as(u32, 1) << 30));
    std.debug.assert(target & 3 == 0 and target < (@as(u32, 1) << 30));
    const link = pc +% 4;
    return .{
        .clk = clock,
        .pc = pc,
        .opcode = .JAL,
        .rd = rd,
        .rs1 = 0,
        .rs2 = 0,
        .imm = immediate,
        .rs1_val = 0,
        .rs2_val = 0,
        .rs1_prev_clk = 0,
        .rs2_prev_clk = 0,
        .rd_prev_val = if (rd == 0) 0 else previous,
        // The runner records writes to x0 in its state-chain clock history
        // even though the architectural value remains zero.
        .rd_prev_clk = previous_clock,
        .rd_val = if (rd == 0) 0 else link,
        .mem_addr = 0,
        .mem_val = 0,
        .mem_prev_word = 0,
        .mem_next_word = 0,
        .mem_prev_clk = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = target != link,
        .next_pc = target,
        .inst_word = 0,
    };
}

pub fn expectLegacyColumns(
    rows: []const witness.TraceRow,
    log_size: u32,
    actual: *const [witness.MAIN_COLUMN_COUNT][]M31,
) !void {
    const domain_size = @as(usize, 1) << @intCast(log_size);
    try std.testing.expect(rows.len <= domain_size);
    var expected = try OwnedColumns.init(
        std.testing.allocator,
        domain_size,
        M31.zero(),
    );
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

/// Compare every committed cell and every ordered lookup entry for one row.
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
    const generated = try opcode_entries.fromMain(.jal, &actual_main);
    const legacy = try opcode_entries.fromMain(.jal, &expected_main);
    try expectEntryListsEqual(&legacy, &generated);
}

fn expectEntryListsEqual(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    try std.testing.expectEqual(expected.batch_size, actual.batch_size);
    for (expected.entries[0..expected.len], actual.entries[0..actual.len]) |
        expected_entry,
        actual_entry,
    | {
        try std.testing.expectEqual(expected_entry.domain, actual_entry.domain);
        try std.testing.expect(expected_entry.numerator.eql(actual_entry.numerator));
        try std.testing.expectEqual(expected_entry.arity, actual_entry.arity);
        try std.testing.expectEqual(expected_entry.role, actual_entry.role);
        try std.testing.expectEqual(
            expected_entry.access_ordinal,
            actual_entry.access_ordinal,
        );
        for (
            expected_entry.values[0..expected_entry.arity],
            actual_entry.values[0..actual_entry.arity],
        ) |expected_value, actual_value| {
            try std.testing.expect(expected_value.eql(actual_value));
        }
    }
}
