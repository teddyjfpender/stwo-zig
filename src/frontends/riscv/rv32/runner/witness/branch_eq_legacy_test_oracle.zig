//! Test-only oracle for the retired handwritten BEQ/BNE witness writer.
//!
//! Production code must not import this module. It preserves the pre-cutover
//! row algorithm for exact differential and proof A/B acceptance.

const M31 = @import("stwo_core").fields.m31.M31;
const w = @import("writer.zig");

pub inline fn writeRow(columns: anytype, index: usize, row: anytype) void {
    const is_beq = row.opcode == .BEQ;
    const comparison = row.rs1_val == row.rs2_val;
    const taken = if (is_beq) comparison else !comparison;
    w.common(columns, index, 0, row);
    w.rs1(columns, index, 2, row);
    w.rs2(columns, index, 12, row);
    w.set(columns, index, 22, w.signed(row.imm));
    w.set(columns, index, 23, w.bit(taken));
    const lhs = w.limbs(row.rs1_val);
    const rhs = w.limbs(row.rs2_val);
    var wrote_inverse = false;
    for (0..4) |limb| {
        const difference = lhs[limb].sub(rhs[limb]);
        const inverse = if (!wrote_inverse and !difference.isZero()) blk: {
            wrote_inverse = true;
            break :blk difference.invUncheckedNonZero();
        } else M31.zero();
        w.set(columns, index, 24 + limb, inverse);
    }
    w.set(columns, index, 28, w.bit(is_beq));
    w.set(columns, index, 29, w.bit(!is_beq));
}
