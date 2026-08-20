//! Test-only oracle for the retired handwritten AUIPC witness writer.
//!
//! Production code must not import this module. Its independent copy preserves
//! the pre-cutover row algorithm for exact differential tests.

const w = @import("writer.zig");

pub inline fn writeRow(columns: anytype, index: usize, row: anytype) void {
    w.set(columns, index, 0, w.u(1));
    w.common(columns, index, 1, row);
    w.rd(columns, index, 3, row);
    w.set(columns, index, 13, w.signed(row.imm));
    w.writeLimbs(columns, index, 14, row.pc +% @as(u32, @bitCast(row.imm)));
    w.destination(columns, index, 18, row.rd);
    w.writeLimbs(columns, index, 20, row.pc);
    w.writeLimbs(columns, index, 24, @bitCast(row.imm));
    w.set(columns, index, 28, w.bit(row.imm < 0));
}
