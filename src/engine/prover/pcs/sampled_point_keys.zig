//! Canonical sampled-point normalization and process-local plan-key encoding.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const qm31 = core.fields.qm31;
const CirclePointQM31 = core.circle.CirclePointQM31;
const point_evaluation = @import("../poly/circle/point_evaluation.zig");
pub const coefficient_plan_key_point_bytes =
    2 * qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31);

pub fn foldSamplePoint(point: CirclePointQM31, fold_count: u32) CirclePointQM31 {
    return if (fold_count == 0)
        point
    else
        point_evaluation.repeatedDoubleOnCircleQM31(point, fold_count);
}

pub fn packPointKeyBytes(dst: []u8, point: CirclePointQM31) void {
    std.debug.assert(dst.len == coefficient_plan_key_point_bytes);
    var at: usize = 0;
    inline for (.{ point.x, point.y }) |coordinate| {
        const coordinates = coordinate.toM31Array();
        inline for (coordinates) |m31_coordinate| {
            const encoded = m31_coordinate.toBytesLe();
            @memcpy(dst[at .. at + @sizeOf(M31)], encoded[0..]);
            at += @sizeOf(M31);
        }
    }
}
