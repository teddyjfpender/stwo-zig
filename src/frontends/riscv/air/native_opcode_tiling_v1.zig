//! Native opcode row-domain policy. Legacy log-16 shapes remain admissible;
//! full descriptor geometry, not this host policy, binds each STARK's key.
const std = @import("std");
pub const MIN_FULL_LOG: u5 = 16;
pub const MAX_FULL_LOG: u5 = 20;
pub const MAX_ROWS: u32 = @as(u32, 1) << MAX_FULL_LOG;
/// Coalesce full old log-16 tiles without increasing their padded area.
pub fn nextRows(remaining: usize) usize {
    std.debug.assert(remaining != 0);
    const bounded = @min(remaining, MAX_ROWS);
    if (bounded <= @as(usize, 1) << MIN_FULL_LOG) return bounded;
    return @as(usize, 1) << std.math.log2_int(usize, bounded);
}

/// Locate a row in admitted cumulative family domains. The caller also checks
/// the final domain's end. Supports legacy uniform and native dyadic tiles.
pub fn shardIndex(starts: []const usize, row: usize) ?usize {
    if (starts.len == 0 or row < starts[0]) return null;
    var low: usize = 0;
    var high = starts.len;
    while (low + 1 < high) {
        const mid = low + (high - low) / 2;
        if (starts[mid] <= row) low = mid else high = mid;
    }
    return low;
}

pub const Cursor = struct {
    family: ?usize = null,
    capacity: u32 = 0,
    previous_rows: u32 = 0,

    /// Full domain sizes may decrease within a family, never increase.
    /// Only its last shard may be partial. Geometry is not witness-derived.
    pub fn admit(self: *@This(), family: usize, rows: u32, log: u32) !void {
        if (rows == 0 or rows > MAX_ROWS or log != @max(1, std.math.log2_int_ceil(u32, rows))) return error.InvalidStatement;
        if (self.family) |previous| {
            if (family < previous) return error.InvalidStatement;
            if (family == previous) {
                if (self.previous_rows != self.capacity or rows > self.capacity) return error.InvalidStatement;
            }
        }
        self.capacity = @as(u32, 1) << @intCast(@max(@as(u32, MIN_FULL_LOG), log));
        self.family = family;
        self.previous_rows = rows;
    }
};

test "native tiling preserves old full shards and admits larger independently sized families" {
    var cursor = Cursor{};
    try cursor.admit(0, 65536, 16);
    try cursor.admit(0, 65536, 16);
    try cursor.admit(0, 3, 2);
    try cursor.admit(1, MAX_ROWS, MAX_FULL_LOG);
    try cursor.admit(1, MAX_ROWS, MAX_FULL_LOG);
    try cursor.admit(1, 262145, 19);
    try cursor.admit(2, 1, 1);
}
test "native tiling rejects partial nonfinal shards, growing tails, reordered families and oversized domains" {
    var cursor = Cursor{};
    try cursor.admit(1, 65535, 16);
    try std.testing.expectError(error.InvalidStatement, cursor.admit(1, 1, 1));
    try std.testing.expectError(error.InvalidStatement, cursor.admit(0, 1, 1));
    cursor = .{};
    try cursor.admit(0, 65536, 16);
    try std.testing.expectError(error.InvalidStatement, cursor.admit(0, 131072, 17));
    cursor = .{};
    try cursor.admit(0, MAX_ROWS, MAX_FULL_LOG);
    try cursor.admit(0, 65536, 16);
    try cursor.admit(0, 1, 1);
    try std.testing.expectError(error.InvalidStatement, cursor.admit(0, 1, 1));
    try std.testing.expectError(error.InvalidStatement, cursor.admit(1, MAX_ROWS + 1, 21));
    try std.testing.expectError(error.InvalidStatement, cursor.admit(1, 65536, 17));
    try std.testing.expectError(error.InvalidStatement, cursor.admit(1, 0, 1));
}

test "native tiling preserves old padded area across dyadic boundaries" {
    for ([_]usize{ 1, 65535, 65536, 65537, 524290, MAX_ROWS - 1, MAX_ROWS, MAX_ROWS + 1, 2 * MAX_ROWS + 131073 }) |total| {
        var remaining = total;
        var cursor = Cursor{};
        var area: usize = 0;
        while (remaining != 0) {
            const rows = nextRows(remaining);
            const log = @max(1, std.math.log2_int_ceil(usize, rows));
            try cursor.admit(0, @intCast(rows), @intCast(log));
            area += @as(usize, 1) << @intCast(log);
            remaining -= rows;
        }
        const tail = total % 65536;
        const old_area = total / 65536 * 65536 + if (tail == 0) @as(usize, 0) else @as(usize, 1) << @intCast(@max(1, std.math.log2_int_ceil(usize, tail)));
        try std.testing.expectEqual(old_area, area);
    }
}

test "native tiling routes legacy and multiple wide shards at every boundary" {
    const starts = [_]usize{ 0, MAX_ROWS, 2 * MAX_ROWS, 2 * MAX_ROWS + 131072, 2 * MAX_ROWS + 196608 };
    for (starts, 0..) |first, index| {
        try std.testing.expectEqual(index, shardIndex(&starts, first).?);
        if (index != 0) try std.testing.expectEqual(index - 1, shardIndex(&starts, first - 1).?);
    }
    const old = [_]usize{ 0, 65536, 131072 };
    for (0..131077) |row| try std.testing.expectEqual(row / 65536, shardIndex(&old, row).?);
    try std.testing.expectEqual(null, shardIndex(&.{}, 0));
    try std.testing.expectEqual(null, shardIndex(&.{1}, 0));
}
