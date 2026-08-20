const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const opcode_entries = @import("../lookups/opcode_entries.zig");
const trace_mod = @import("../../runner/trace.zig");
const witness = @import("typed_addi_witness.zig");

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
    raw_source: u32,
    immediate: i32,
    clock: u32,
    pc: u32,
    raw_rd_previous: u32,
    source_previous_clock: u32,
    destination_previous_clock: u32,
) witness.TraceRow {
    std.debug.assert(immediate >= -2048 and immediate <= 2047);
    std.debug.assert(clock != 0);
    const source = if (rs1 == 0) 0 else raw_source;
    const result = source +% @as(u32, @bitCast(immediate));
    const source_clock = (clock - 1) * 4 + 1;
    return .{
        .clk = clock,
        .pc = pc,
        .opcode = .ADDI,
        .rd = rd,
        .rs1 = rs1,
        .rs2 = 0,
        .imm = immediate,
        .rs1_val = source,
        .rs2_val = 0,
        .rs1_prev_clk = source_previous_clock,
        .rs2_prev_clk = 0,
        .rd_prev_val = if (rd == 0)
            0
        else if (rd == rs1)
            source
        else
            raw_rd_previous,
        .rd_prev_clk = if (rd == rs1)
            source_clock
        else
            destination_previous_clock,
        .rd_val = if (rd == 0) 0 else result,
        .mem_addr = 0,
        .mem_val = 0,
        .mem_prev_word = 0,
        .mem_next_word = 0,
        .mem_prev_clk = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = pc +% 4,
        .inst_word = 0,
    };
}

pub fn expectProductionColumns(
    rows: []const witness.TraceRow,
    log_size: u32,
    actual: *const [witness.MAIN_COLUMN_COUNT][]M31,
) !void {
    const allocator = std.testing.allocator;
    var trace = trace_mod.Trace.init(allocator);
    defer trace.deinit();
    for (rows) |row| try trace.append(row);
    var expected = try trace.columnsForFamily(
        allocator,
        .base_alu_imm,
        log_size,
    );
    defer expected.deinit(allocator);
    try std.testing.expectEqual(witness.MAIN_COLUMN_COUNT, expected.n_columns);
    try std.testing.expectEqual(rows.len, expected.n_real_rows);
    for (actual, expected.columns[0..witness.MAIN_COLUMN_COUNT]) |
        actual_column,
        expected_column,
    | {
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
    for (&main, columns) |*value, column|
        value.* = QM31.fromBase(column[row_index]);
    const expected = try opcode_entries.fromMain(.base_alu_imm, &main);
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
        for (event.values[event.arity..]) |unused|
            try std.testing.expect(unused.isZero());
    }
}
