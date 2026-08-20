//! Test-only oracle for the retired handwritten LUI witness writer.
//!
//! Production code must not import this module. Its deliberately independent
//! implementation is preserved so serial differential tests can detect any
//! cell-level or proof-level drift in the generated typed authority.

const w = @import("writer.zig");

pub inline fn writeRow(columns: anytype, index: usize, row: anytype) void {
    w.set(columns, index, 0, w.u(1));
    w.common(columns, index, 1, row);
    w.rd(columns, index, 3, row);
    const immediate = @as(u32, @bitCast(row.imm)) >> 12;
    w.set(columns, index, 13, w.u(immediate & 0xf));
    w.set(columns, index, 14, w.u((immediate >> 4) & 0xff));
    w.set(columns, index, 15, w.u(immediate >> 12));
    w.destination(columns, index, 16, row.rd);
}
