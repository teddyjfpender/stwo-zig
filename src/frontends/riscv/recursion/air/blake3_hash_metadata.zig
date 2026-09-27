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
    pub fn validate(self: Rows, gs: usize, xs: usize) !void {
        if (self.g_rows.len != gs or self.xor_rows.len != xs) return error.InvalidBlake3WitnessDestination;
    }
    pub fn slice(self: Rows, gf: usize, gs: usize, xf: usize, xs: usize) !Rows {
        if (gf > self.g_rows.len or gs > self.g_rows.len - gf or xf > self.xor_rows.len or xs > self.xor_rows.len - xf) return error.InvalidBlake3WitnessDestination;
        return .{ .g_rows = self.g_rows[gf..][0..gs], .xor_rows = self.xor_rows[xf..][0..xs] };
    }
    /// Caller owns both allocations and frees them with the supplied allocator.
    pub fn allocate(a: std.mem.Allocator, gs: usize, xs: usize) !Rows {
        const g_rows = try a.alloc(Row(g), gs);
        errdefer a.free(g_rows);
        return .{ .g_rows = g_rows, .xor_rows = try a.alloc(Row(xor), xs) };
    }
    pub fn free(self: Rows, a: std.mem.Allocator) void {
        a.free(self.g_rows);
        a.free(self.xor_rows);
    }
};
pub fn xorUse(rows: []xor.Row, compact: ?Rows, index: usize) *M {
    return if (compact) |v| &v.xor_rows[index][17 - xor.PHYSICAL_MAIN_COLUMN_COUNT] else &rows[index][17];
}
