const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const opcode_entries = @import("../lookups/opcode_entries.zig");
const Opcode = @import("../../isa/decode.zig").Opcode;
const legacy = @import("../../runner/witness/mulh_legacy_test_oracle.zig");
const witness = @import("typed_mulh_witness.zig");

pub const operations = [_]Opcode{ .MULH, .MULHSU, .MULHU };

pub const boundary_operands = [_]u32{
    0x0000_0000,
    0x0000_0001,
    0x0000_00ff,
    0x0000_0100,
    0x0000_ffff,
    0x0001_0000,
    0x00ff_ffff,
    0x0100_0000,
    0x3fff_ffff,
    0x4000_0000,
    0x7fff_ffff,
    0x8000_0000,
    0x8000_0001,
    0xffff_fffe,
    0xffff_ffff,
    0xff00_ff00,
};

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

pub fn product(opcode: Opcode, lhs: u32, rhs: u32) u64 {
    return switch (opcode) {
        .MULH => @bitCast(
            @as(i64, @as(i32, @bitCast(lhs))) *%
                @as(i64, @as(i32, @bitCast(rhs))),
        ),
        .MULHSU => @bitCast(
            @as(i64, @as(i32, @bitCast(lhs))) * @as(i64, rhs),
        ),
        .MULHU => @as(u64, lhs) * @as(u64, rhs),
        else => unreachable,
    };
}

pub fn result(opcode: Opcode, lhs: u32, rhs: u32) u32 {
    return @truncate(product(opcode, lhs, rhs) >> 32);
}

pub fn encode(opcode: Opcode, rd: u5, rs1: u5, rs2: u5) u32 {
    const funct3: u32 = switch (opcode) {
        .MULH => 0b001,
        .MULHSU => 0b010,
        .MULHU => 0b011,
        else => unreachable,
    };
    return (@as(u32, 1) << 25) |
        (@as(u32, rs2) << 20) |
        (@as(u32, rs1) << 15) |
        (funct3 << 12) |
        (@as(u32, rd) << 7) |
        0b0110011;
}

pub fn makeRow(
    opcode: Opcode,
    rd: u5,
    rs1: u5,
    rs2: u5,
    raw_rs1_value: u32,
    raw_rs2_value: u32,
    clock: u32,
    pc: u32,
    raw_rd_previous: u32,
    raw_rs1_previous_clock: u32,
    raw_rs2_previous_clock: u32,
    raw_rd_previous_clock: u32,
) witness.TraceRow {
    std.debug.assert(clock != 0);
    const source_1_clock = (clock - 1) * 4 + 1;
    const source_2_clock = source_1_clock + 1;
    const destination_clock = source_1_clock + 2;
    const rs1_value = if (rs1 == 0) 0 else raw_rs1_value;
    const rs2_value = if (rs2 == 0)
        0
    else if (rs2 == rs1)
        rs1_value
    else
        raw_rs2_value;
    const rd_previous = if (rd == 0)
        0
    else if (rd == rs2)
        rs2_value
    else if (rd == rs1)
        rs1_value
    else
        raw_rd_previous;
    const rd_previous_clock = if (rd == rs2)
        source_2_clock
    else if (rd == rs1)
        source_1_clock
    else
        raw_rd_previous_clock % destination_clock;
    const high = result(opcode, rs1_value, rs2_value);
    return .{
        .clk = clock,
        .pc = pc,
        .opcode = opcode,
        .rd = rd,
        .rs1 = rs1,
        .rs2 = rs2,
        .imm = 0,
        .rs1_val = rs1_value,
        .rs2_val = rs2_value,
        .rs1_prev_clk = raw_rs1_previous_clock % source_1_clock,
        .rs2_prev_clk = if (rs2 == rs1)
            source_1_clock
        else
            raw_rs2_previous_clock % source_2_clock,
        .rd_prev_val = rd_previous,
        .rd_prev_clk = rd_previous_clock,
        .rd_val = if (rd == 0) 0 else high,
        .mem_addr = 0,
        .mem_val = 0,
        .mem_prev_word = 0,
        .mem_next_word = 0,
        .mem_prev_clk = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = pc +% 4,
        .inst_word = encode(opcode, rd, rs1, rs2),
    };
}

pub fn corpusRow(index: usize) witness.TraceRow {
    const cases_per_operation = boundary_operands.len * boundary_operands.len;
    std.debug.assert(index < operations.len * cases_per_operation);
    const local = index % cases_per_operation;
    const opcode = operations[index / cases_per_operation];
    const lhs = boundary_operands[local / boundary_operands.len];
    const rhs = boundary_operands[local % boundary_operands.len];
    const rs1: u5 = if (index % 37 == 0) 0 else 5;
    const rs2: u5 = if (index % 41 == 0)
        rs1
    else if (index % 43 == 0)
        0
    else
        6;
    const rd: u5 = if (index % 11 == 0)
        0
    else if (index % 7 == 0)
        rs1
    else if (index % 13 == 0)
        rs2
    else
        10;
    return makeRow(
        opcode,
        rd,
        rs1,
        rs2,
        lhs,
        rhs,
        @intCast(index + 100),
        @intCast(0x1000 + index * 4),
        @truncate(0x1122_3344 +% index),
        @intCast(index % 97),
        @intCast(index % 89),
        @intCast(index % 83),
    );
}

pub fn expectLegacyColumns(
    rows: []const witness.TraceRow,
    log_size: u32,
    actual: *const [witness.MAIN_COLUMN_COUNT][]M31,
) !void {
    const domain_size = @as(usize, 1) << @intCast(log_size);
    var expected = try OwnedColumns.init(std.testing.allocator, domain_size, M31.zero());
    defer expected.deinit();
    for (rows, 0..) |row, index| legacy.writeRow(&expected.views, index, row);
    for (actual, expected.views) |actual_column, expected_column| try std.testing.expectEqualSlices(
        u8,
        std.mem.sliceAsBytes(expected_column),
        std.mem.sliceAsBytes(actual_column),
    );
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
    const expected = try opcode_entries.fromMain(.mulh, &main);
    try std.testing.expectEqual(witness.EVENT_COUNT, expected.len);
    try std.testing.expectEqual(@as(usize, 1), expected.batch_size);
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
