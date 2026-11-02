//! Domain-only fixed polynomials. There are no public steps/register values in
//! these buffers. Register endpoints enter through public coefficient vectors.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const L = @import("layout.zig");
pub fn cpu(a: std.mem.Allocator, log_size: u32) ![]M {
    if (log_size < L.MIN_LOG or log_size > L.MAX_LOG) return error.InvalidWord16CpuGeometry;
    const n = @as(usize, 1) << @intCast(log_size);
    const values = try a.alloc(M, 3 * n);
    @memset(values, M.zero());
    for (0..n) |row| values[L.physical(row, log_size)] = M.fromCanonical(@intCast(row));
    values[n + L.physical(0, log_size)] = M.one();
    values[2 * n + L.physical(n - 1, log_size)] = M.one();
    return values;
}
pub fn boundary(a: std.mem.Allocator) ![]M {
    const values = try a.alloc(M, 34 * 32);
    @memset(values, M.zero());
    for (0..32) |register| values[32 * register + L.physical(register, 5)] = M.one();
    values[32 * 32 + L.physical(0, 5)] = M.one();
    values[33 * 32 + L.physical(31, 5)] = M.one();
    return values;
}
pub fn range(a: std.mem.Allocator, log_size: u32) ![]M {
    if (log_size != 8 and log_size != 16) return error.InvalidWord16RangeGeometry;
    const n = @as(usize, 1) << @intCast(log_size);
    const values = try a.alloc(M, 3 * n);
    @memset(values, M.zero());
    for (0..n) |row| values[L.physical(row, log_size)] = M.fromCanonical(@intCast(row));
    values[n + L.physical(0, log_size)] = M.one();
    values[2 * n + L.physical(n - 1, log_size)] = M.one();
    return values;
}
