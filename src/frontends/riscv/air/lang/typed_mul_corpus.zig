//! Exact boundary corpus for the RV32 `MUL` witness migration.
//!
//! The 16x16 cross product spans byte/carry boundaries, signed-looking bit
//! patterns, maximal operands, and structured limbs. Destination selection
//! deterministically includes x0 and both source aliases.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const typed_mul = @import("typed_mul.zig");
const Opcode = @import("../../runner/decode.zig").Opcode;
const TraceRow = @import("../../runner/trace_row.zig").TraceRow;
const legacy = @import("../../runner/witness/mul_legacy_test_oracle.zig");

pub const ROW_WIDTH: usize = typed_mul.MAIN_COLUMN_COUNT + 1;

pub const operands = [_]u32{
    0x0000_0000,
    0x0000_0001,
    0x0000_0002,
    0x0000_00ff,
    0x0000_0100,
    0x0000_0101,
    0x0000_ffff,
    0x0001_0000,
    0x00ff_ffff,
    0x0100_0000,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_fffe,
    0xffff_ffff,
    0x0101_0101,
    0xff00_ff00,
};

pub const CORPUS_ROW_COUNT: usize = operands.len * operands.len;

comptime {
    if (CORPUS_ROW_COUNT != 256)
        @compileError("typed MUL corpus cardinality is migration evidence");
}

pub fn operandPair(index: usize) struct { lhs: u32, rhs: u32 } {
    std.debug.assert(index < CORPUS_ROW_COUNT);
    return .{
        .lhs = operands[index / operands.len],
        .rhs = operands[index % operands.len],
    };
}

pub fn traceRow(index: usize) TraceRow {
    const pair = operandPair(index);
    const result: u32 = @truncate(@as(u64, pair.lhs) *% @as(u64, pair.rhs));
    const rs1: u5 = 5;
    const rs2: u5 = 6;
    const rd: u5 = if (index % 11 == 0)
        0
    else if (index % 7 == 0)
        rs1
    else if (index % 13 == 0)
        rs2
    else
        10;
    return .{
        .clk = 9,
        .pc = 0x1000,
        .opcode = Opcode.MUL,
        .rd = rd,
        .rs1 = rs1,
        .rs2 = rs2,
        .rs1_val = pair.lhs,
        .rs2_val = pair.rhs,
        .rs1_prev_clk = 2,
        .rs2_prev_clk = 3,
        .rd_prev_val = if (rd == rs1)
            pair.lhs
        else if (rd == rs2)
            pair.rhs
        else
            0x1122_3344,
        .rd_prev_clk = if (rd == rs1) 5 else if (rd == rs2) 6 else 4,
        .rd_val = if (rd == 0) 0 else result,
        .imm = 0,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x1004,
    };
}

pub fn honestRow(index: usize) [ROW_WIDTH]M31 {
    const row = traceRow(index);
    var storage: [typed_mul.MAIN_COLUMN_COUNT][1]M31 =
        .{.{M31.zero()}} ** typed_mul.MAIN_COLUMN_COUNT;
    var columns: [typed_mul.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&columns, &storage) |*column, *slot| column.* = slot;
    legacy.writeRow(&columns, 0, row);
    var result: [ROW_WIDTH]M31 = undefined;
    for (storage, result[0..typed_mul.MAIN_COLUMN_COUNT]) |slot, *value|
        value.* = slot[0];
    result[typed_mul.MAIN_COLUMN_COUNT] = M31.one();
    return result;
}
