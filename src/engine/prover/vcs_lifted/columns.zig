//! Column validation and canonical ordering for lifted Merkle commitments.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;

pub const ColumnRef = struct {
    values: []const M31,
    log_size: u32,
    original_index: usize,
};

pub fn sortByLogSizeAsc(
    allocator: std.mem.Allocator,
    columns: []const []const M31,
) ![]ColumnRef {
    const result = try allocator.alloc(ColumnRef, columns.len);
    errdefer allocator.free(result);
    for (columns, result, 0..) |column, *reference, index| {
        if (!std.math.isPowerOfTwo(column.len) or column.len < 2) {
            return error.InvalidColumnSize;
        }
        reference.* = .{
            .values = column,
            .log_size = @intCast(std.math.log2_int(usize, column.len)),
            .original_index = index,
        };
    }
    std.sort.heap(ColumnRef, result, {}, lessByLogSizeAscStable);
    return result;
}

pub fn allConstant(columns: []const ColumnRef) bool {
    for (columns) |column| {
        if (column.values.len == 0) return false;
        const first = column.values[0];
        for (column.values[1..]) |value| {
            if (!value.eql(first)) return false;
        }
    }
    return true;
}

fn lessByLogSizeAscStable(_: void, lhs: ColumnRef, rhs: ColumnRef) bool {
    if (lhs.log_size == rhs.log_size) return lhs.original_index < rhs.original_index;
    return lhs.log_size < rhs.log_size;
}

test "lifted VCS columns retain stable order within equal log sizes" {
    const short = [_]M31{ M31.one(), M31.zero() };
    const long_a = [_]M31{ M31.one(), M31.zero(), M31.one(), M31.zero() };
    const long_b = [_]M31{ M31.zero(), M31.one(), M31.zero(), M31.one() };
    const input = [_][]const M31{ &long_a, &short, &long_b };
    const sorted = try sortByLogSizeAsc(std.testing.allocator, &input);
    defer std.testing.allocator.free(sorted);
    try std.testing.expectEqualSlices(usize, &.{ 1, 0, 2 }, &.{
        sorted[0].original_index,
        sorted[1].original_index,
        sorted[2].original_index,
    });
}
