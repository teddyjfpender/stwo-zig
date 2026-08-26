//! Differential support for the typed BRANCH_EQ witness.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const opcode_entries = @import("../lookups/opcode_entries.zig");
const Opcode = @import("../../isa/decode.zig").Opcode;
const legacy = @import("../../runner/witness/branch_eq_legacy_test_oracle.zig");
const witness = @import("typed_branch_eq_witness.zig");

pub const OwnedColumns = struct {
    allocator: std.mem.Allocator,
    storage: [witness.MAIN_COLUMN_COUNT][]M31,
    views: [witness.MAIN_COLUMN_COUNT][]M31,

    pub fn init(allocator: std.mem.Allocator, len: usize, initial: M31) !OwnedColumns {
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
        for (self.storage) |column| for (column) |actual|
            try std.testing.expectEqual(expected, actual);
    }
};

pub fn taken(opcode: Opcode, lhs: u32, rhs: u32) bool {
    return switch (opcode) {
        .BEQ => lhs == rhs,
        .BNE => lhs != rhs,
        else => unreachable,
    };
}

pub fn makeRow(
    opcode: Opcode,
    rs1: u5,
    rs2: u5,
    raw_rs1_value: u32,
    raw_rs2_value: u32,
    immediate: i32,
    clock: u32,
    pc: u32,
    rs1_previous_clock: u32,
    raw_rs2_previous_clock: u32,
) witness.TraceRow {
    std.debug.assert(opcode == .BEQ or opcode == .BNE);
    std.debug.assert(immediate >= -4096 and immediate <= 4094);
    std.debug.assert((@as(u32, @bitCast(immediate)) & 1) == 0);
    std.debug.assert(clock != 0);
    const source_1_clock = (clock - 1) *% 4 +% 1;
    const rs1_value = if (rs1 == 0) 0 else raw_rs1_value;
    const rs2_value = if (rs2 == 0)
        0
    else if (rs2 == rs1)
        rs1_value
    else
        raw_rs2_value;
    const is_taken = taken(opcode, rs1_value, rs2_value);
    const target = if (is_taken)
        pc +% @as(u32, @bitCast(immediate))
    else
        pc +% 4;
    return .{
        .clk = clock,
        .pc = pc,
        .opcode = opcode,
        .rd = 0,
        .rs1 = rs1,
        .rs2 = rs2,
        .imm = immediate,
        .rs1_val = rs1_value,
        .rs2_val = rs2_value,
        .rs1_prev_clk = rs1_previous_clock,
        .rs2_prev_clk = if (rs2 == rs1) source_1_clock else raw_rs2_previous_clock,
        .rd_prev_val = 0,
        .rd_prev_clk = 0,
        .rd_val = 0,
        .mem_addr = 0,
        .mem_val = 0,
        .mem_prev_word = 0,
        .mem_next_word = 0,
        .mem_prev_clk = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = target != pc +% 4,
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
    var expected = try OwnedColumns.init(std.testing.allocator, domain_size, M31.zero());
    defer expected.deinit();
    for (rows, 0..) |row, index| legacy.writeRow(&expected.views, index, row);
    for (actual, expected.views) |actual_column, expected_column| {
        try std.testing.expectEqualSlices(
            u8,
            std.mem.sliceAsBytes(expected_column),
            std.mem.sliceAsBytes(actual_column),
        );
    }
}

pub fn expectRelationParity(
    executor: *const witness.Executor,
    columns: *const [witness.MAIN_COLUMN_COUNT][]M31,
    row_index: usize,
    row: witness.TraceRow,
) !void {
    const actual = try executor.generateRelationRow(row);
    var main: [witness.MAIN_COLUMN_COUNT]QM31 = undefined;
    for (&main, columns) |*value, column| value.* = QM31.fromBase(column[row_index]);
    const expected = try opcode_entries.fromMain(.branch_eq, &main);
    try std.testing.expectEqual(witness.EVENT_COUNT, expected.len);
    try std.testing.expectEqual(@as(usize, 2), expected.batch_size);
    for (actual.events, expected.entries[0..expected.len], 0..) |
        event,
        production,
        index,
    | {
        const spec = witness.EVENT_SPECS[index];
        try std.testing.expectEqual(spec.kind, event.kind);
        try std.testing.expectEqual(
            @intFromEnum(production.domain),
            @intFromEnum(event.domain),
        );
        try std.testing.expectEqual(
            @intFromEnum(production.role),
            @intFromEnum(event.role),
        );
        try std.testing.expectEqual(production.access_ordinal, event.access_ordinal);
        try std.testing.expectEqual(production.arity, event.arity);
        try std.testing.expect(
            production.numerator.eql(QM31.fromBase(event.signedNumerator())),
        );
        for (production.values[0..production.arity], event.values[0..event.arity]) |
            expected_value,
            actual_value,
        | try std.testing.expect(expected_value.eql(QM31.fromBase(actual_value)));
        for (event.values[event.arity..]) |unused| try std.testing.expect(unused.isZero());
    }
}
