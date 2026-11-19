//! Test-only oracle preserving the retired handwritten RV32 `MUL` writer.
//!
//! Kept independent of the typed implementation so row/proof differentials
//! compare two separately authored paths after production cutover.

const M31 = @import("stwo_core").fields.m31.M31;
const w = @import("writer.zig");

pub fn writeRow(columns: anytype, index: usize, row: anytype) void {
    w.set(columns, index, 0, M31.one());
    w.common(columns, index, 1, row);
    w.rd(columns, index, 3, row);
    w.rs1(columns, index, 13, row);
    w.rs2(columns, index, 23, row);
    const product: u32 = @truncate(@as(u64, row.rs1_val) *% @as(u64, row.rs2_val));
    w.writeLimbs(columns, index, 33, product);
    w.destination(columns, index, 37, row.rd);
}
