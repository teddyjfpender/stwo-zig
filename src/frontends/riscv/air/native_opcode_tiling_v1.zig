//! Native opcode row-domain policy. Legacy log-16 shapes remain admissible;
//! full descriptor geometry, not this host policy, binds each STARK's key.
const std = @import("std");
pub const MIN_FULL_LOG: u5 = 16;
pub const MAX_FULL_LOG: u5 = 20;
pub const MAX_ROWS: u32 = @as(u32, 1) << MAX_FULL_LOG;
pub const PRODUCER_ROWS: usize = MAX_ROWS;

pub const Cursor = struct {
    family: ?usize = null,
    capacity: u32 = 0,
    previous_rows: u32 = 0,

    /// The first shard chooses a family capacity, bounded independently.
    /// Only its last shard may be partial. Never infer this from witness data.
    pub fn admit(self: *@This(), family: usize, rows: u32, log: u32) !void {
        if (rows == 0 or rows > MAX_ROWS or log != @max(1, std.math.log2_int_ceil(u32, rows))) return error.InvalidStatement;
        if (self.family) |previous| {
            if (family < previous) return error.InvalidStatement;
            if (family == previous) {
                if (self.previous_rows != self.capacity or rows > self.capacity) return error.InvalidStatement;
            } else self.capacity = @as(u32, 1) << @intCast(@max(@as(u32, MIN_FULL_LOG), log));
        } else self.capacity = @as(u32, 1) << @intCast(@max(@as(u32, MIN_FULL_LOG), log));
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
    try std.testing.expectError(error.InvalidStatement, cursor.admit(0, 1, 1));
    try std.testing.expectError(error.InvalidStatement, cursor.admit(1, MAX_ROWS + 1, 21));
    try std.testing.expectError(error.InvalidStatement, cursor.admit(1, 65536, 17));
    try std.testing.expectError(error.InvalidStatement, cursor.admit(1, 0, 1));
}
