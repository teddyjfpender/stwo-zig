//! Borrowed fixed-only hash metadata; never substitutes for trusted preprocessing.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const g = @import("blake3_g_call.zig");
const xor = @import("blake3_xor_call.zig");
pub fn Row(comptime Air: type) type {
    return [Air.LOGICAL_INPUT_COUNT - Air.PHYSICAL_MAIN_COLUMN_COUNT]M;
}
pub const Rows = struct {
    g_rows: []Row(g),
    xor_rows: []Row(xor),
};
pub fn xorUse(rows: []xor.Row, compact: ?Rows, index: usize) *M {
    return if (compact) |v| &v.xor_rows[index][17 - xor.PHYSICAL_MAIN_COLUMN_COUNT] else &rows[index][17];
}
