//! Checked word-count arithmetic for the resident Cairo proof plan.

const std = @import("std");

pub const Error = error{GeometryOverflow};

pub fn traceAssemblyWords(
    queries: usize,
    columns: usize,
    leaf_log: u32,
) !usize {
    return addSize(
        try addSize(queries, try mul(columns, queries)),
        try mul(try mul(queries, leaf_log), 28),
    );
}

pub fn friAssemblyWords(
    queries: usize,
    expanded: usize,
    path_log: u32,
) !usize {
    return addSize(
        try addSize(queries, try mul(expanded, 9)),
        try mul(try mul(expanded, path_log), 28),
    );
}

pub fn merkleWords(log_rows: u32) !usize {
    const leaves = try pow2usize(log_rows);
    const hashes = std.math.sub(
        usize,
        try mul(leaves, 2),
        1,
    ) catch return Error.GeometryOverflow;
    return mul(hashes, 8);
}

pub fn divCeil(value: usize, divisor: usize) usize {
    return value / divisor + @intFromBool(value % divisor != 0);
}

pub fn pow2usize(log: u32) !usize {
    return words(try pow2(log));
}

pub fn pow2(log: u32) !u64 {
    if (log >= 63) return Error.GeometryOverflow;
    return @as(u64, 1) << @intCast(log);
}

pub fn words(value: u64) !usize {
    return std.math.cast(usize, value) orelse Error.GeometryOverflow;
}

pub fn addSize(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse return Error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse return Error.GeometryOverflow;
    return std.math.add(usize, lhs, rhs) catch Error.GeometryOverflow;
}

pub fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse return Error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse return Error.GeometryOverflow;
    return std.math.mul(usize, lhs, rhs) catch Error.GeometryOverflow;
}

pub fn add64(left: anytype, right: anytype) !u64 {
    const lhs = std.math.cast(u64, left) orelse return Error.GeometryOverflow;
    const rhs = std.math.cast(u64, right) orelse return Error.GeometryOverflow;
    return std.math.add(u64, lhs, rhs) catch Error.GeometryOverflow;
}

pub fn mul64(left: anytype, right: anytype) !u64 {
    const lhs = std.math.cast(u64, left) orelse return Error.GeometryOverflow;
    const rhs = std.math.cast(u64, right) orelse return Error.GeometryOverflow;
    return std.math.mul(u64, lhs, rhs) catch Error.GeometryOverflow;
}
