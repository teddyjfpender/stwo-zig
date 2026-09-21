//! Bit-reversed circle-coordinate inverse preparation for FRI folds.

const std = @import("std");
const core = @import("stwo_core");

pub const Coordinate = enum { x, y };

pub fn prepare(
    coordinates: []core.fields.m31.M31,
    inverses: []core.fields.m31.M31,
    coset: core.circle.Coset,
    comptime coordinate: Coordinate,
) !void {
    const M31 = core.fields.m31.M31;
    if (coordinates.len == 0 or
        coordinates.len != inverses.len or
        !std.math.isPowerOfTwo(coordinates.len) or
        coordinates.len > coset.size())
    {
        return error.ShapeMismatch;
    }

    try @import("../execution_policy.zig").admitHost(.fri_inverse_preparation);
    const log_len: u32 = @intCast(std.math.log2_int(usize, coordinates.len));
    var points = coset.iter();
    for (0..coordinates.len) |natural_index| {
        const point = points.next() orelse unreachable;
        const output_index = core.utils.bitReverseIndex(natural_index, log_len);
        coordinates[output_index] = switch (coordinate) {
            .x => point.x,
            .y => point.y,
        };
    }
    try core.fields.batchInverseInPlace(M31, coordinates, inverses);
}
