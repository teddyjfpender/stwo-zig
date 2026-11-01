//! Test-only legacy row/matrix oracle. Production writes only compact MAIN.
const std = @import("std");
const X = @import("stwo_riscv_frontend").rv64_air.memory.load_store_v2;
const P = X.layout.projection;
const M = X.types.M;
pub fn expandMatrix(a: std.mem.Allocator, physical: []const M, n: usize) ![]M {
    std.debug.assert(physical.len == P.MAIN * n);
    const result = try a.alloc(M, P.LOGICAL_MAIN * n);
    for (0..n) |row| {
        var input: [P.MAIN]M = undefined;
        for (&input, 0..) |*v, c| v.* = physical[c * n + row];
        const expanded = P.expandFor(M, &input);
        for (expanded, 0..) |v, c| result[c * n + row] = v;
    }
    return result;
}
pub fn projectMatrix(logical: []const M, physical: []M, n: usize) void {
    std.debug.assert(logical.len == P.LOGICAL_MAIN * n and physical.len == P.MAIN * n);
    for (P.STORED, 0..) |column, c| @memcpy(physical[c * n ..][0..n], logical[column * n ..][0..n]);
}
