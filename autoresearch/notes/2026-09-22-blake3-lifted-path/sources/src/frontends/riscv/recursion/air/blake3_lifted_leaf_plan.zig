//! Native lifted leaf column order and parity-preserving row projection.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
pub const Plan = struct {
    allocator: std.mem.Allocator,
    logs: []u32,
    order: []usize,
    max_log: u32,
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.logs);
        self.allocator.free(self.order);
        self.* = undefined;
    }
    pub fn columnIndex(self: *const Plan, column: usize, position: u32) !usize {
        if (column >= self.logs.len or @as(u64, position) >= @as(u64, 1) << @as(u6, @intCast(self.max_log))) return error.InvalidBlake3LiftedLeaf;
        const shift: u5 = @intCast(self.max_log - self.logs[column] + 1);
        return ((position >> shift) << 1) | (position & 1);
    }
    /// Input values retain original column order, as native decommitments do.
    pub fn leaf(self: *const Plan, a: std.mem.Allocator, queried: []const M31) ![]M31 {
        if (queried.len != self.logs.len) return error.InvalidBlake3LiftedLeaf;
        const values = try a.alloc(M31, queried.len);
        for (values, self.order) |*value, column| value.* = queried[column];
        return values;
    }
};
pub fn build(a: std.mem.Allocator, logs: []const u32) !Plan {
    var max_log: u32 = 0;
    for (logs) |log| {
        if (log == 0 or log > 31) return error.InvalidBlake3LiftedLeaf;
        max_log = @max(max_log, log);
    }
    const owned = try a.dupe(u32, logs);
    errdefer a.free(owned);
    const order = try a.alloc(usize, logs.len);
    errdefer a.free(order);
    for (order, 0..) |*index, i| index.* = i;
    std.sort.heap(usize, order, logs, less);
    return .{ .allocator = a, .logs = owned, .order = order, .max_log = max_log };
}
fn less(logs: []const u32, lhs: usize, rhs: usize) bool {
    return logs[lhs] < logs[rhs] or (logs[lhs] == logs[rhs] and lhs < rhs);
}
