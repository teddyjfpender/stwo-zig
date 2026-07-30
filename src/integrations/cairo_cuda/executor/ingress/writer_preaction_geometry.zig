//! Checked row and resident-range geometry for writer preactions.

const std = @import("std");
const common = @import("stwo_cuda_backend").runtime.stages.common;

pub fn contains(outer: common.Words, inner: common.Words) bool {
    if (outer.owner != inner.owner or
        outer.generation != inner.generation or
        inner.address < outer.address)
    {
        return false;
    }
    const outer_bytes = std.math.mul(
        usize,
        outer.len,
        @sizeOf(u32),
    ) catch return false;
    const inner_bytes = std.math.mul(
        usize,
        inner.len,
        @sizeOf(u32),
    ) catch return false;
    const outer_end = std.math.add(
        usize,
        outer.address,
        outer_bytes,
    ) catch return false;
    const inner_end = std.math.add(
        usize,
        inner.address,
        inner_bytes,
    ) catch return false;
    return inner_end <= outer_end;
}

pub fn canonicalRows(real_rows: u32) !u32 {
    if (real_rows == 0) return error.InvalidWriterPreactionLayout;
    var rows: u32 = 16;
    while (rows < real_rows) {
        rows = std.math.mul(u32, rows, 2) catch
            return error.InvalidWriterPreactionLayout;
    }
    return rows;
}

pub fn nextPowerOfTwo(rows: u32) !u32 {
    if (rows == 0) return error.InvalidWriterPreactionLayout;
    return std.math.ceilPowerOfTwo(u32, rows) catch
        error.InvalidWriterPreactionLayout;
}

pub fn addU32(left: u32, right: u32) !u32 {
    return std.math.add(u32, left, right) catch
        error.InvalidWriterPreactionLayout;
}

pub fn mulU32(left: u32, right: u32) !u32 {
    return std.math.mul(u32, left, right) catch
        error.InvalidWriterPreactionLayout;
}
