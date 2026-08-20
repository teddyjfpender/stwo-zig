//! Test-only oracle for the retired handwritten BASE_ALU_IMM witness writer.
//!
//! Production code must not import this module. It intentionally preserves the
//! former implementation so differentials can detect cell and proof drift.

const w = @import("writer.zig");

fn result(row: anytype) u32 {
    const immediate: u32 = @bitCast(row.imm);
    return switch (row.opcode) {
        .ADDI => row.rs1_val +% immediate,
        .XORI => row.rs1_val ^ immediate,
        .ORI => row.rs1_val | immediate,
        .ANDI => row.rs1_val & immediate,
        else => unreachable,
    };
}

pub inline fn writeRow(columns: anytype, index: usize, row: anytype) void {
    w.common(columns, index, 0, row);
    w.rd(columns, index, 2, row);
    w.rs1(columns, index, 12, row);
    const bits: u32 = @bitCast(row.imm);
    w.set(columns, index, 22, w.u(bits & 0xff));
    w.set(columns, index, 23, w.u((bits >> 8) & 0x7));
    w.set(columns, index, 24, w.u((bits >> 11) & 1));
    const flags = [_]bool{
        row.opcode == .ADDI, row.opcode == .XORI,
        row.opcode == .ORI,  row.opcode == .ANDI,
    };
    for (flags, 0..) |active, flag_index|
        w.set(columns, index, 25 + flag_index, w.bit(active));
    w.writeLimbs(columns, index, 29, result(row));
    w.destination(columns, index, 33, row.rd);
}
