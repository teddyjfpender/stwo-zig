//! Test-only oracle preserving the retired handwritten RV32 high-word writer.
//!
//! This is intentionally independent of the typed witness authority. It is a
//! frozen copy of the pre-cutover production algorithm so semantic and
//! performance differentials retain two separately authored paths.

const Opcode = @import("../decode.zig").Opcode;
const w = @import("writer.zig");

fn product(lhs: u32, rhs: u32, opcode: Opcode) u64 {
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

pub fn writeRow(columns: anytype, index: usize, row: anytype) void {
    const full_product = product(row.rs1_val, row.rs2_val, row.opcode);
    const rs1_signed = row.opcode == .MULH or row.opcode == .MULHSU;
    const rs2_signed = row.opcode == .MULH;
    w.common(columns, index, 0, row);
    w.rd(columns, index, 2, row);
    w.rs1(columns, index, 12, row);
    w.rs2(columns, index, 22, row);
    for (w.limbs(@truncate(full_product)), 0..) |limb, limb_index|
        w.set(columns, index, 32 + limb_index, limb);
    w.set(columns, index, 36, w.bit(rs1_signed and row.rs1_val >> 31 == 1));
    w.set(columns, index, 37, w.bit(rs2_signed and row.rs2_val >> 31 == 1));
    w.set(columns, index, 38, w.bit(row.opcode == .MULH));
    w.set(columns, index, 39, w.bit(row.opcode == .MULHSU));
    w.set(columns, index, 40, w.bit(row.opcode == .MULHU));
    w.writeLimbs(columns, index, 41, @truncate(full_product >> 32));
    w.destination(columns, index, 45, row.rd);
}
