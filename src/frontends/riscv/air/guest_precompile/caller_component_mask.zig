//! Mask allocation and secure-column sampling helpers for the caller adapter.

const std = @import("std");
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const qm31 = @import("stwo_core").fields.qm31;
const QM31 = qm31.QM31;

const CirclePointQM31 = circle.CirclePointQM31;

pub fn sampledSecure(
    columns: [][]QM31,
    offset: usize,
    point_index: usize,
) error{InvalidProofShape}!QM31 {
    if (offset > columns.len or columns.len - offset < qm31.SECURE_EXTENSION_DEGREE) {
        return error.InvalidProofShape;
    }
    var coordinates: [qm31.SECURE_EXTENSION_DEGREE]QM31 = undefined;
    for (&coordinates, 0..) |*coordinate, index| {
        if (columns[offset + index].len <= point_index) {
            return error.InvalidProofShape;
        }
        coordinate.* = columns[offset + index][point_index];
    }
    return QM31.fromPartialEvals(coordinates);
}

pub fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
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

pub fn currentAndPreviousPointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    point: CirclePointQM31,
    previous: CirclePointQM31,
) ![][]CirclePointQM31 {
    const result = try allocator.alloc([]CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| allocator.free(column);
        allocator.free(result);
    }
    for (result) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, &.{ point, previous });
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
