//! Test-only oracle for the retired handwritten JAL witness writer.
//!
//! Production code must not import this module. Its independent copy preserves
//! the pre-cutover row algorithm for exact differential and proof A/B tests.

const w = @import("writer.zig");

pub inline fn writeRow(columns: anytype, index: usize, row: anytype) void {
    w.set(columns, index, 0, w.u(1));
    w.common(columns, index, 1, row);
    w.rd(columns, index, 3, row);
    w.set(columns, index, 13, w.signed(row.imm));
    w.writeLimbs(columns, index, 14, row.pc +% 4);
    w.destination(columns, index, 18, row.rd);
}
