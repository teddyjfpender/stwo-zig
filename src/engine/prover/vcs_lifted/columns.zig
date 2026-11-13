//! Column validation and canonical ordering for lifted Merkle commitments.

const std = @import("std");
const builtin = @import("builtin");
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

/// Canonical little-endian row packing for one bounded leaf tile.
pub fn packLeafTileBytes(
    scratch: []align(@alignOf(M31)) u8,
    column_chunk: []const ColumnRef,
    tile_start: usize,
    tile_size: usize,
) void {
    const bytes_per_leaf = column_chunk.len * @sizeOf(M31);
    std.debug.assert(scratch.len == tile_size * bytes_per_leaf);

    if (builtin.cpu.arch.endian() == .little) {
        const scratch_words = std.mem.bytesAsSlice(M31, scratch);
        var local_leaf: usize = 0;
        while (local_leaf < tile_size) : (local_leaf += 1) {
            const leaf_words = scratch_words[local_leaf * column_chunk.len ..][0..column_chunk.len];
            const leaf_index = tile_start + local_leaf;
            for (column_chunk, 0..) |column, column_idx| {
                leaf_words[column_idx] = column.values[leaf_index];
            }
        }
        return;
    }

    var local_leaf: usize = 0;
    while (local_leaf < tile_size) : (local_leaf += 1) {
        const leaf_index = tile_start + local_leaf;
        const leaf_start = local_leaf * bytes_per_leaf;
        for (column_chunk, 0..) |column, column_idx| {
            const encoded = column.values[leaf_index].toBytesLe();
            const byte_start = leaf_start + (column_idx * @sizeOf(M31));
            @memcpy(scratch[byte_start .. byte_start + @sizeOf(M31)], encoded[0..]);
        }
    }
}
