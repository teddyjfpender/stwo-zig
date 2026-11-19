//! Test-only oracle for the retired handwritten FENCE witness writer.
//!
//! Production code must not import this module. Its independent copy preserves
//! the pre-cutover row algorithm for exact differential tests.

const w = @import("writer.zig");

pub inline fn writeRow(columns: anytype, index: usize, row: anytype) void {
    w.set(columns, index, 0, w.u(1));
    w.common(columns, index, 1, row);
    w.set(columns, index, 3, w.u(row.rd));
    w.set(columns, index, 4, w.u(row.rs1));
    w.set(columns, index, 5, w.u(@as(u32, @bitCast(row.imm)) & 0xfff));
}
