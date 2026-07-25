//! Fixed XOR-table traces and multiplicity accumulation for exact Blake.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_pcs = @import("stwo_prover_impl").pcs;
const geometry = @import("geometry.zig");

pub const TABLE_COUNT = geometry.XOR_TABLES.len;

pub const Location = struct {
    table_index: usize,
    column_index: usize,
    row_index: usize,
};

pub const Accumulator = struct {
    tables: [TABLE_COUNT][][]M31,

    pub fn init(allocator: std.mem.Allocator) !Accumulator {
        var result: Accumulator = undefined;
        var initialized: usize = 0;
        errdefer {
            for (result.tables[0..initialized]) |table| freeTable(allocator, table);
        }
        for (geometry.XOR_TABLES, 0..) |table, table_index| {
            result.tables[table_index] = try allocateTable(allocator, table);
            initialized += 1;
        }
        return result;
    }

    pub fn deinit(self: *Accumulator, allocator: std.mem.Allocator) void {
        for (self.tables) |table| freeTable(allocator, table);
        self.* = undefined;
    }

    pub fn record(self: *Accumulator, width: u5, a: u32, b: u32, c: u32) void {
        std.debug.assert(c == a ^ b);
        const location = locate(width, a, b) catch unreachable;
        const value = &self.tables[location.table_index][location.column_index][location.row_index];
        value.* = value.add(M31.one());
    }

    pub fn intoColumns(
        self: *Accumulator,
        allocator: std.mem.Allocator,
    ) ![]prover_pcs.ColumnEvaluation {
        const columns = try allocator.alloc(
            prover_pcs.ColumnEvaluation,
            geometry.XOR_MAIN_COLUMNS,
        );
        var output_index: usize = 0;
        for (geometry.XOR_TABLES, 0..) |table, table_index| {
            for (self.tables[table_index]) |values| {
                columns[output_index] = .{
                    .log_size = table.logSize(),
                    .values = values,
                };
                output_index += 1;
            }
            allocator.free(self.tables[table_index]);
            self.tables[table_index] = &.{};
        }
        std.debug.assert(output_index == columns.len);
        self.* = undefined;
        return columns;
    }
};

pub fn generatePreprocessed(
    allocator: std.mem.Allocator,
) ![]prover_pcs.ColumnEvaluation {
    const columns = try allocator.alloc(
        prover_pcs.ColumnEvaluation,
        geometry.PREPROCESSED_COLUMNS,
    );
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column.values);
        allocator.free(columns);
    }

    for (geometry.XOR_TABLES) |table| {
        const row_count = @as(usize, 1) << @intCast(table.logSize());
        const limb_bits = table.limbBits();
        const limb_mask = (@as(u32, 1) << @intCast(limb_bits)) - 1;
        const a_values = try allocator.alloc(M31, row_count);
        errdefer allocator.free(a_values);
        const b_values = try allocator.alloc(M31, row_count);
        errdefer allocator.free(b_values);
        const c_values = try allocator.alloc(M31, row_count);
        errdefer allocator.free(c_values);

        for (0..row_count) |row| {
            const row_u32: u32 = @intCast(row);
            const a = row_u32 >> @intCast(limb_bits);
            const b = row_u32 & limb_mask;
            a_values[row] = M31.fromCanonical(a);
            b_values[row] = M31.fromCanonical(b);
            c_values[row] = M31.fromCanonical(a ^ b);
        }
        columns[initialized] = .{ .log_size = table.logSize(), .values = a_values };
        initialized += 1;
        columns[initialized] = .{ .log_size = table.logSize(), .values = b_values };
        initialized += 1;
        columns[initialized] = .{ .log_size = table.logSize(), .values = c_values };
        initialized += 1;
    }
    std.debug.assert(initialized == columns.len);
    return columns;
}

pub fn locate(width: u5, a: u32, b: u32) !Location {
    const table_index = tableIndex(width) orelse return error.InvalidXorWidth;
    const table = geometry.XOR_TABLES[table_index];
    const element_limit = @as(u32, 1) << @intCast(table.element_bits);
    if (a >= element_limit or b >= element_limit) return error.XorInputOutOfRange;

    const limb_bits = table.limbBits();
    const limb_mask = (@as(u32, 1) << @intCast(limb_bits)) - 1;
    const a_high = a >> @intCast(limb_bits);
    const b_high = b >> @intCast(limb_bits);
    const a_low = a & limb_mask;
    const b_low = b & limb_mask;
    return .{
        .table_index = table_index,
        .column_index = @intCast(
            (a_high << @intCast(table.expand_bits)) + b_high,
        ),
        .row_index = @intCast(
            (a_low << @intCast(limb_bits)) + b_low,
        ),
    };
}

fn tableIndex(width: u5) ?usize {
    return switch (width) {
        12 => 0,
        9 => 1,
        8 => 2,
        7 => 3,
        4 => 4,
        else => null,
    };
}

fn allocateTable(
    allocator: std.mem.Allocator,
    table: geometry.XorTable,
) ![][]M31 {
    const columns = try allocator.alloc([]M31, table.multiplicityColumns());
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column);
        allocator.free(columns);
    }
    const row_count = @as(usize, 1) << @intCast(table.logSize());
    for (columns) |*column| {
        column.* = try allocator.alloc(M31, row_count);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    return columns;
}

fn freeTable(allocator: std.mem.Allocator, table: [][]M31) void {
    for (table) |column| allocator.free(column);
    allocator.free(table);
}

test "exact Blake XOR lookup locations match upstream high-low splitting" {
    const wide = try locate(12, 0xabc, 0x123);
    try std.testing.expectEqual(@as(usize, 0), wide.table_index);
    try std.testing.expectEqual(@as(usize, 0xa1), wide.column_index);
    try std.testing.expectEqual(@as(usize, 0xbc23), wide.row_index);

    const narrow = try locate(4, 0xa, 0x3);
    try std.testing.expectEqual(@as(usize, 4), narrow.table_index);
    try std.testing.expectEqual(@as(usize, 0), narrow.column_index);
    try std.testing.expectEqual(@as(usize, 0xa3), narrow.row_index);
}

test "exact Blake XOR lookup locations reject invalid widths and ranges" {
    try std.testing.expectError(error.InvalidXorWidth, locate(6, 0, 0));
    try std.testing.expectError(error.XorInputOutOfRange, locate(7, 128, 0));
}

test "exact Blake XOR preprocessed columns preserve upstream table order" {
    const allocator = std.testing.allocator;
    const columns = try generatePreprocessed(allocator);
    defer {
        for (columns) |column| allocator.free(column.values);
        allocator.free(columns);
    }

    try std.testing.expectEqual(geometry.PREPROCESSED_COLUMNS, columns.len);
    var column_index: usize = 0;
    for (geometry.XOR_TABLES) |table| {
        const row = (@as(usize, 5) << @intCast(table.limbBits())) | 3;
        try std.testing.expectEqual(table.logSize(), columns[column_index].log_size);
        try std.testing.expect(columns[column_index].values[row].eql(M31.fromCanonical(5)));
        column_index += 1;
        try std.testing.expect(columns[column_index].values[row].eql(M31.fromCanonical(3)));
        column_index += 1;
        try std.testing.expect(columns[column_index].values[row].eql(M31.fromCanonical(6)));
        column_index += 1;
    }
}

test "exact Blake XOR accumulator transfers every multiplicity column" {
    const allocator = std.testing.allocator;
    var accumulator = try Accumulator.init(allocator);
    errdefer accumulator.deinit(allocator);

    accumulator.record(12, 0xabc, 0x123, 0xb9f);
    accumulator.record(12, 0xabc, 0x123, 0xb9f);
    accumulator.record(4, 0xa, 0x3, 0x9);
    const columns = try accumulator.intoColumns(allocator);
    defer {
        for (columns) |column| allocator.free(column.values);
        allocator.free(columns);
    }

    try std.testing.expectEqual(geometry.XOR_MAIN_COLUMNS, columns.len);
    const wide = try locate(12, 0xabc, 0x123);
    try std.testing.expect(
        columns[wide.column_index].values[wide.row_index].eql(M31.fromCanonical(2)),
    );
    const narrow = try locate(4, 0xa, 0x3);
    const narrow_offset: usize = 256 + 16 + 16 + 16;
    try std.testing.expect(
        columns[narrow_offset + narrow.column_index]
            .values[narrow.row_index]
            .eql(M31.one()),
    );
}

fn allocateAndDeinit(allocator: std.mem.Allocator) !void {
    var accumulator = try Accumulator.init(allocator);
    accumulator.deinit(allocator);
}

test "exact Blake XOR accumulator releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocateAndDeinit,
        .{},
    );
}
