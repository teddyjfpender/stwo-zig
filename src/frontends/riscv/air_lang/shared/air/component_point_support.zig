//! Core-only point sampling and owned mask allocation helpers.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const CirclePointQM31 = core.circle.CirclePointQM31;

pub fn sampledSecure(columns: [][]QM31, base: usize, point_index: usize) !QM31 {
    if (columns.len < base + 4) return error.InvalidProofShape;
    var coordinates: [4]QM31 = undefined;
    for (&coordinates, columns[base .. base + 4]) |*coordinate, column| {
        if (column.len <= point_index) return error.InvalidProofShape;
        coordinate.* = column[point_index];
    }
    return QM31.fromPartialEvals(coordinates);
}

pub inline fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}

pub fn emptyOrFilledLogs(
    allocator: std.mem.Allocator,
    count: usize,
    log_size: u32,
) ![]u32 {
    const result = try allocator.alloc(u32, count);
    @memset(result, log_size);
    return result;
}

pub fn currentPointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    point: CirclePointQM31,
) ![][]CirclePointQM31 {
    const result = try allocator.alloc([]CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| allocator.free(column);
        allocator.free(result);
    }
    for (result) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{point});
        initialized += 1;
    }
    return result;
}

pub fn freePointColumns(
    allocator: std.mem.Allocator,
    columns: [][]CirclePointQM31,
) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

pub fn checkedEnd(offset: anytype, count: usize) !usize {
    return std.math.add(usize, @intCast(offset), count) catch
        error.InvalidProofShape;
}
