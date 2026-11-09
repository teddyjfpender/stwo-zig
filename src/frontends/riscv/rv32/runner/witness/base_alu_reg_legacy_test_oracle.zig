//! Test-only oracle for the retired handwritten BASE_ALU_REG witness writer.

const w = @import("writer.zig");

fn result(row: anytype) u32 {
    return switch (row.opcode) {
        .ADD => row.rs1_val +% row.rs2_val,
        .SUB => row.rs1_val -% row.rs2_val,
        .XOR => row.rs1_val ^ row.rs2_val,
        .OR => row.rs1_val | row.rs2_val,
        .AND => row.rs1_val & row.rs2_val,
        else => unreachable,
    };
}

pub inline fn writeRow(columns: anytype, index: usize, row: anytype) void {
    w.common(columns, index, 0, row);
    w.rd(columns, index, 2, row);
    w.readRs1(columns, index, 12, row);
    w.readRs2(columns, index, 18, row);
    const flags = [_]bool{
        row.opcode == .ADD,
        row.opcode == .SUB,
        row.opcode == .XOR,
        row.opcode == .OR,
        row.opcode == .AND,
    };
    for (flags, 0..) |active, flag_index|
        w.set(columns, index, 24 + flag_index, w.bit(active));
    w.writeLimbs(columns, index, 29, result(row));
    w.destination(columns, index, 33, row.rd);
}
