//! Shared allocation and committed-row placement for infrastructure traces.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const utils = @import("stwo_core").utils;

/// Precomputed mapping from trace row order to committed circle-domain order.
pub const BitReversalTable = struct {
    mapping: []const usize,

    pub fn init(allocator: std.mem.Allocator, log_size: u32) !BitReversalTable {
        const n = @as(usize, 1) << @intCast(log_size);
        const mapping = try allocator.alloc(usize, n);
        for (mapping, 0..) |*destination, row| {
            destination.* = utils.bitReverseIndex(
                utils.cosetIndexToCircleDomainIndex(row, log_size),
                log_size,
            );
        }
        return .{ .mapping = mapping };
    }

    pub fn deinit(self: BitReversalTable, allocator: std.mem.Allocator) void {
        allocator.free(self.mapping);
    }

    pub inline fn map(self: BitReversalTable, row: usize) usize {
        return self.mapping[row];
    }
};

pub inline fn placeValue(
    column: []M31,
    row: usize,
    table: BitReversalTable,
    value: M31,
) void {
    column[table.map(row)] = value;
}

pub fn allocZeroColumns(
    allocator: std.mem.Allocator,
    comptime count: usize,
    domain_size: usize,
) ![count][]M31 {
    var columns: [count][]M31 = undefined;
    var allocated: usize = 0;
    errdefer for (columns[0..allocated]) |column| allocator.free(column);
    for (&columns) |*column| {
        column.* = try allocator.alloc(M31, domain_size);
        allocated += 1;
        @memset(column.*, M31.zero());
    }
    return columns;
}
