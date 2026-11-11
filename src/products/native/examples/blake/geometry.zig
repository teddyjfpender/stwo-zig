//! Exact mixed-height geometry of upstream Stwo's Blake AIR.

const std = @import("std");
const constants = @import("constants.zig");

pub const PROTOCOL_NAME = "raw-stwo-blake-logup-v2";
pub const PROOF_COMMITMENTS: usize = 4;
pub const COMPONENT_COUNT: usize = 8;

pub const PREPROCESSED_COLUMNS: usize = 15;
pub const SCHEDULER_MAIN_COLUMNS: usize = 384;
pub const ROUND_MAIN_COLUMNS: usize = 384;
pub const XOR_MAIN_COLUMNS: usize = 256 + 16 + 16 + 16 + 1;
pub const MAIN_COLUMNS: usize =
    SCHEDULER_MAIN_COLUMNS + 2 * ROUND_MAIN_COLUMNS + XOR_MAIN_COLUMNS;
pub const SCHEDULER_MAIN_OFFSET: usize = 0;
pub const ROUND_MAIN_OFFSETS = [2]usize{
    SCHEDULER_MAIN_COLUMNS,
    SCHEDULER_MAIN_COLUMNS + ROUND_MAIN_COLUMNS,
};
pub const XOR_MAIN_OFFSET: usize =
    SCHEDULER_MAIN_COLUMNS + 2 * ROUND_MAIN_COLUMNS;

pub const SCHEDULER_INTERACTION_SECURE_COLUMNS: usize = 6;
pub const ROUND_INTERACTION_SECURE_COLUMNS: usize = 65;
pub const XOR_INTERACTION_SECURE_COLUMNS: usize = 128 + 8 + 8 + 8 + 1;
pub const INTERACTION_SECURE_COLUMNS: usize =
    SCHEDULER_INTERACTION_SECURE_COLUMNS +
    2 * ROUND_INTERACTION_SECURE_COLUMNS +
    XOR_INTERACTION_SECURE_COLUMNS;
pub const INTERACTION_COLUMNS: usize = 4 * INTERACTION_SECURE_COLUMNS;
pub const SCHEDULER_INTERACTION_OFFSET: usize = 0;
pub const ROUND_INTERACTION_OFFSETS = [2]usize{
    4 * SCHEDULER_INTERACTION_SECURE_COLUMNS,
    4 * (SCHEDULER_INTERACTION_SECURE_COLUMNS +
        ROUND_INTERACTION_SECURE_COLUMNS),
};
pub const XOR_INTERACTION_OFFSET: usize =
    4 * (SCHEDULER_INTERACTION_SECURE_COLUMNS +
        2 * ROUND_INTERACTION_SECURE_COLUMNS);

pub const SCHEDULER_CONSTRAINTS: usize = SCHEDULER_INTERACTION_SECURE_COLUMNS;
pub const ROUND_ALGEBRAIC_CONSTRAINTS: usize = 64;
pub const ROUND_CONSTRAINTS: usize =
    ROUND_ALGEBRAIC_CONSTRAINTS + ROUND_INTERACTION_SECURE_COLUMNS;
pub const XOR_CONSTRAINTS: usize = XOR_INTERACTION_SECURE_COLUMNS;
pub const CONSTRAINT_COUNT: usize =
    SCHEDULER_CONSTRAINTS + 2 * ROUND_CONSTRAINTS + XOR_CONSTRAINTS;

pub const XorTable = struct {
    element_bits: u32,
    expand_bits: u32,

    pub fn limbBits(self: XorTable) u32 {
        return self.element_bits - self.expand_bits;
    }

    pub fn logSize(self: XorTable) u32 {
        return 2 * self.limbBits();
    }

    pub fn multiplicityColumns(self: XorTable) usize {
        return @as(usize, 1) << @intCast(2 * self.expand_bits);
    }

    pub fn interactionSecureColumns(self: XorTable) usize {
        return (self.multiplicityColumns() + 1) / 2;
    }
};

pub const XOR_TABLES = [5]XorTable{
    .{ .element_bits = 12, .expand_bits = 4 },
    .{ .element_bits = 9, .expand_bits = 2 },
    .{ .element_bits = 8, .expand_bits = 2 },
    .{ .element_bits = 7, .expand_bits = 2 },
    .{ .element_bits = 4, .expand_bits = 0 },
};

pub fn committedCells(log_size: u32) !u64 {
    if (log_size >= 31) return error.InvalidLogSize;
    var total: u64 = 0;

    for (XOR_TABLES) |table| {
        total = try checkedColumnsAtLog(total, 3, table.logSize());
    }
    total = try checkedColumnsAtLog(total, SCHEDULER_MAIN_COLUMNS, log_size);
    total = try checkedColumnsAtLog(
        total,
        ROUND_MAIN_COLUMNS,
        log_size + constants.ROUND_LOG_SPLIT[0],
    );
    total = try checkedColumnsAtLog(
        total,
        ROUND_MAIN_COLUMNS,
        log_size + constants.ROUND_LOG_SPLIT[1],
    );
    for (XOR_TABLES) |table| {
        total = try checkedColumnsAtLog(
            total,
            table.multiplicityColumns(),
            table.logSize(),
        );
    }

    total = try checkedColumnsAtLog(
        total,
        4 * SCHEDULER_INTERACTION_SECURE_COLUMNS,
        log_size,
    );
    total = try checkedColumnsAtLog(
        total,
        4 * ROUND_INTERACTION_SECURE_COLUMNS,
        log_size + constants.ROUND_LOG_SPLIT[0],
    );
    total = try checkedColumnsAtLog(
        total,
        4 * ROUND_INTERACTION_SECURE_COLUMNS,
        log_size + constants.ROUND_LOG_SPLIT[1],
    );
    for (XOR_TABLES) |table| {
        total = try checkedColumnsAtLog(
            total,
            4 * table.interactionSecureColumns(),
            table.logSize(),
        );
    }
    return total;
}

fn checkedColumnsAtLog(total: u64, columns: usize, log_size: u32) !u64 {
    if (log_size >= 63) return error.InvalidLogSize;
    const rows = @as(u64, 1) << @intCast(log_size);
    const cells = std.math.mul(u64, @intCast(columns), rows) catch
        return error.ColumnCountOverflow;
    return std.math.add(u64, total, cells) catch error.ColumnCountOverflow;
}

test "exact Blake geometry matches the pinned eight-component AIR" {
    try std.testing.expectEqual(@as(usize, 8), COMPONENT_COUNT);
    try std.testing.expectEqual(@as(usize, 1_457), MAIN_COLUMNS);
    try std.testing.expectEqual(@as(usize, 289), INTERACTION_SECURE_COLUMNS);
    try std.testing.expectEqual(@as(usize, 1_156), INTERACTION_COLUMNS);
    try std.testing.expectEqual(@as(usize, 417), CONSTRAINT_COUNT);
}

test "exact Blake XOR table widths account for every fixed-height column" {
    var main_columns: usize = 0;
    var secure_columns: usize = 0;
    for (XOR_TABLES) |table| {
        main_columns += table.multiplicityColumns();
        secure_columns += table.interactionSecureColumns();
    }
    try std.testing.expectEqual(XOR_MAIN_COLUMNS, main_columns);
    try std.testing.expectEqual(XOR_INTERACTION_SECURE_COLUMNS, secure_columns);
    try std.testing.expectEqual(@as(u32, 16), XOR_TABLES[0].logSize());
    try std.testing.expectEqual(@as(u32, 8), XOR_TABLES[4].logSize());
}

test "exact Blake committed-cell accounting includes mixed component heights" {
    try std.testing.expectEqual(@as(u64, 51_846_144), try committedCells(5));
}
