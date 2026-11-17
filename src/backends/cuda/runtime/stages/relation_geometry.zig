//! Checked resident relation descriptor extents and launch geometry.
const std = @import("std");
const runtime_error = @import("../error.zig");
const pointer_words = @sizeOf(usize) / @sizeOf(u32);

pub fn pointerTableWords(count: u32) usize {
    return @as(usize, count) * pointer_words;
}

pub fn sourceWordExtent(
    extents: []const u32,
    index: usize,
    rows: u32,
) runtime_error.Error!u32 {
    if (extents.len == 0) return rows;
    if (index >= extents.len or extents[index] < rows)
        return error.InvalidKernelDescriptor;
    return extents[index];
}

pub fn blocks(values: u32, block_size: u32) u32 {
    return values / block_size + @intFromBool(values % block_size != 0);
}

pub fn checkedAdd(left: u32, right: u32) runtime_error.Error!u32 {
    return std.math.add(u32, left, right) catch error.SizeOverflow;
}

pub fn checkedMul(left: u32, right: u32) runtime_error.Error!u32 {
    return std.math.mul(u32, left, right) catch error.SizeOverflow;
}

pub fn inverseRows(rows: u32) u32 {
    std.debug.assert(rows != 0 and std.math.isPowerOfTwo(rows));
    const log_rows = std.math.log2_int(u32, rows);
    return if (log_rows == 0) 1 else @as(u32, 1) << @intCast(31 - log_rows);
}
