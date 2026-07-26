//! Exact base ALU committed witnesses.

const w = @import("writer.zig");

fn regResult(row: anytype) u32 {
    return switch (row.opcode) {
        .ADD => row.rs1_val +% row.rs2_val,
        .SUB => row.rs1_val -% row.rs2_val,
        .XOR => row.rs1_val ^ row.rs2_val,
        .OR => row.rs1_val | row.rs2_val,
        .AND => row.rs1_val & row.rs2_val,
        else => unreachable,
    };
}

fn immediateResult(row: anytype) u32 {
    const imm_bits: u32 = @bitCast(row.imm);
    return switch (row.opcode) {
        .ADDI => row.rs1_val +% imm_bits,
        .XORI => row.rs1_val ^ imm_bits,
        .ORI => row.rs1_val | imm_bits,
        .ANDI => row.rs1_val & imm_bits,
        else => unreachable,
    };
}

pub fn reg(columns: anytype, index: usize, row: anytype) void {
    w.common(columns, index, 0, row);
    w.rd(columns, index, 2, row);
    w.rs1(columns, index, 12, row);
    w.rs2(columns, index, 22, row);
    const flags = [_]bool{
        row.opcode == .ADD, row.opcode == .SUB, row.opcode == .XOR,
        row.opcode == .OR,  row.opcode == .AND,
    };
    for (flags, 0..) |flag, i| w.set(columns, index, 32 + i, w.bit(flag));
    w.writeLimbs(columns, index, 37, regResult(row));
    w.destination(columns, index, 41, row.rd);
}

pub fn immediate(columns: anytype, index: usize, row: anytype) void {
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
    for (flags, 0..) |flag, i| w.set(columns, index, 25 + i, w.bit(flag));
    w.writeLimbs(columns, index, 29, immediateResult(row));
    w.destination(columns, index, 33, row.rd);
}
