//! Count-first, area-second AIR sizing for a homogeneous sorted-memory family.
//! Variants share the same columns and differ only in power-of-two row height.
const std = @import("std");

pub const Plan = struct {
    allocator: std.mem.Allocator,
    capacities: []u32,
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.capacities);
        self.* = undefined;
    }
    pub fn committedRows(self: Plan) u64 {
        var total: u64 = 0;
        for (self.capacities) |capacity| total += capacity;
        return total;
    }
};

/// Minimize proof instances first. With equal-width power-of-two variants, a
/// full-height prefix and the smallest sufficient tail then minimize committed
/// area. `maximum_log_size` is a host-memory admission, not a proof claim.
pub fn select(allocator: std.mem.Allocator, rows: u64, minimum_log_size: u32, maximum_log_size: u32) !Plan {
    if (rows == 0 or minimum_log_size < 1 or minimum_log_size > maximum_log_size or
        maximum_log_size > 30) return error.InvalidMemorySizePlan;
    const maximum: u64 = @as(u64, 1) << @intCast(maximum_log_size);
    const count_u64 = try std.math.divCeil(u64, rows, maximum);
    const count = std.math.cast(usize, count_u64) orelse return error.InvalidMemorySizePlan;
    const capacities = try allocator.alloc(u32, count);
    errdefer allocator.free(capacities);
    @memset(capacities, @intCast(maximum));
    const prefix_rows = try std.math.mul(u64, count_u64 - 1, maximum);
    const tail_rows = rows - prefix_rows;
    const minimum: u64 = @as(u64, 1) << @intCast(minimum_log_size);
    const tail_capacity = try std.math.ceilPowerOfTwo(u64, @max(tail_rows, minimum));
    if (tail_capacity > maximum) return error.InvalidMemorySizePlan;
    capacities[count - 1] = @intCast(tail_capacity);
    return .{ .allocator = allocator, .capacities = capacities };
}

test "mainnet memory sizing retains exact proof count and committed coverage" {
    var selected = try select(std.testing.allocator, 356_303_914, 8, 20);
    defer selected.deinit();
    try std.testing.expectEqual(@as(usize, 340), selected.capacities.len);
    try std.testing.expectEqual(@as(u32, 1 << 20), selected.capacities[339]);
    try std.testing.expect(selected.committedRows() >= 356_303_914);
    try std.testing.expect(selected.committedRows() - 356_303_914 < selected.capacities[339]);

    var larger = try select(std.testing.allocator, 356_303_914, 8, 22);
    defer larger.deinit();
    try std.testing.expectEqual(@as(usize, 85), larger.capacities.len);
    try std.testing.expect(larger.committedRows() >= 356_303_914);
    try std.testing.expectEqual(@as(u32, 1 << 22), larger.capacities[84]);
}

test "sizing validates the budget and preserves a single short instance" {
    var selected = try select(std.testing.allocator, 9, 2, 3);
    defer selected.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 8, 4 }, selected.capacities);
    try std.testing.expectError(error.InvalidMemorySizePlan, select(std.testing.allocator, 0, 2, 3));
    try std.testing.expectError(error.InvalidMemorySizePlan, select(std.testing.allocator, 9, 4, 3));
}
