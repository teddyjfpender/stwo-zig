//! Test-only oracle for the retired handwritten JALR witness writer.
//!
//! Production code must not import this module. Its deliberately independent
//! implementation is preserved so row, interaction, and proof differential
//! tests can detect any cell-level drift in the typed witness authority.

const w = @import("writer.zig");

pub inline fn writeRow(columns: anytype, index: usize, row: anytype) void {
    w.set(columns, index, 0, w.u(1));
    w.common(columns, index, 1, row);
    w.rd(columns, index, 3, row);
    w.rs1(columns, index, 13, row);

    const unaligned = row.rs1_val +% @as(u32, @bitCast(row.imm));
    const target = unaligned & ~@as(u32, 1);
    const target_word = target >> 2;
    const immediate_bits: u32 = @bitCast(row.imm);
    const immediate_12 = immediate_bits & 0xfff;

    w.set(columns, index, 23, w.u(target / 2));
    w.set(columns, index, 24, w.u(unaligned & 1));
    w.set(columns, index, 25, w.signed(row.imm));
    w.writeLimbs(columns, index, 26, row.pc +% 4);
    w.destination(columns, index, 30, row.rd);
    w.set(columns, index, 32, w.u(target_word & ((@as(u32, 1) << 20) - 1)));
    w.set(columns, index, 33, w.u(target_word >> 20));
    w.writeLimbs(columns, index, 34, target);
    w.set(columns, index, 38, w.u(immediate_12 & 0xff));
    w.set(columns, index, 39, w.u(immediate_12 >> 8));
    w.set(columns, index, 40, w.bit(row.imm < 0));
}
