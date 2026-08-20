//! Exact 292-row DIV operand-class corpus and canonical witness adapter.
//!
//! The cross product covers zero, unit and signed boundary magnitudes in every
//! sign combination. The final carry-heavy pair exercises internal zero limbs.
//! Destination selection deterministically includes x0, rd=rs1, and rd=rs2.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const hint_recipe = @import("hint_recipe.zig");
const typed_div = @import("typed_div.zig");
const Opcode = @import("../../runner/decode.zig").Opcode;
const TraceRow = @import("../../runner/trace_row.zig").TraceRow;
const div_writer = @import("../../runner/witness/div_legacy_test_oracle.zig").writeRow;

pub const ROW_WIDTH: usize = typed_div.MAIN_COLUMN_COUNT + 1;

pub const OperandClass = struct {
    lhs: u32,
    rhs: u32,
};

const lhs_classes = [_]u32{
    0,
    1,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
    0x8000_0001,
    7,
    0xffff_fff9,
};

const rhs_classes = [_]u32{
    0,
    1,
    0xffff_ffff,
    2,
    0xffff_fffe,
    0x8000_0000,
    0x7fff_ffff,
    3,
    0xffff_fffd,
};

pub const OPERAND_CLASS_COUNT: usize = lhs_classes.len * rhs_classes.len + 1;
pub const CORPUS_ROW_COUNT: usize = OPERAND_CLASS_COUNT * 4;

comptime {
    if (OPERAND_CLASS_COUNT != 73 or CORPUS_ROW_COUNT != 292)
        @compileError("typed DIV corpus cardinality is protocol evidence");
}

pub fn operandClass(index: usize) OperandClass {
    std.debug.assert(index < OPERAND_CLASS_COUNT);
    if (index == OPERAND_CLASS_COUNT - 1) return .{
        .lhs = 0x0100_0000,
        .rhs = 0x0001_0000,
    };
    return .{
        .lhs = lhs_classes[index / rhs_classes.len],
        .rhs = rhs_classes[index % rhs_classes.len],
    };
}

pub fn opcode(index: usize) Opcode {
    return switch (index) {
        0 => .DIV,
        1 => .DIVU,
        2 => .REM,
        3 => .REMU,
        else => unreachable,
    };
}

pub fn encode(op: Opcode, rd: u5, rs1: u5, rs2: u5) u32 {
    const funct3: u32 = switch (op) {
        .DIV => 0b100,
        .DIVU => 0b101,
        .REM => 0b110,
        .REMU => 0b111,
        else => unreachable,
    };
    return (@as(u32, 1) << 25) |
        (@as(u32, rs2) << 20) |
        (@as(u32, rs1) << 15) |
        (funct3 << 12) |
        (@as(u32, rd) << 7) |
        0b0110011;
}

pub fn traceRow(op: Opcode, operands: OperandClass, case_index: usize) !TraceRow {
    const signed = op == .DIV or op == .REM;
    const result = try hint_recipe.evaluateDivRem(
        hint_recipe.id(.rv32_divrem),
        operands.lhs,
        operands.rhs,
        signed,
    );
    const selected = if (op == .DIV or op == .DIVU)
        result.quotient
    else
        result.remainder;
    const rs1: u5 = 5;
    const rs2: u5 = 6;
    const rd: u5 = if (case_index % 11 == 0)
        0
    else if (case_index % 7 == 0)
        rs1
    else if (case_index % 13 == 0)
        rs2
    else
        10;
    const rd_previous = if (rd == rs1)
        operands.lhs
    else if (rd == rs2)
        operands.rhs
    else
        0x1122_3344;
    const rd_clock: u32 = if (rd == rs1) 33 else if (rd == rs2) 34 else 3;
    return .{
        .clk = 9,
        .pc = 0x1000,
        .opcode = op,
        .rd = rd,
        .rs1 = rs1,
        .rs2 = rs2,
        .rs1_val = operands.lhs,
        .rs2_val = operands.rhs,
        .rs1_prev_clk = 2,
        .rs2_prev_clk = 3,
        .rd_prev_val = rd_previous,
        .rd_prev_clk = rd_clock,
        .rd_val = if (rd == 0) 0 else selected,
        .imm = 0,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x1004,
        .inst_word = encode(op, rd, rs1, rs2),
    };
}

pub fn honestRow(op: Opcode, operands: OperandClass, case_index: usize) ![ROW_WIDTH]M31 {
    const writer_row = try traceRow(op, operands, case_index);
    var storage: [typed_div.MAIN_COLUMN_COUNT][1]M31 =
        .{.{M31.zero()}} ** typed_div.MAIN_COLUMN_COUNT;
    var columns: [typed_div.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&columns, &storage) |*column, *slot| column.* = slot;
    div_writer(&columns, 0, writer_row);
    var row: [ROW_WIDTH]M31 = undefined;
    for (storage, row[0..typed_div.MAIN_COLUMN_COUNT]) |slot, *value|
        value.* = slot[0];
    row[typed_div.MAIN_COLUMN_COUNT] = M31.one();
    return row;
}
