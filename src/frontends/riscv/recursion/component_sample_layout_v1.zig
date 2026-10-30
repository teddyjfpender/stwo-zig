//! Resolve only original component mask vocabulary and retain its exact step.
//! The caller supplies independently rebuilt masks, never witness-selected ones.
const core = @import("stwo_core");
const Layout = @import("sample_point_layout.zig");
const Point = core.circle.CirclePointQM31;
pub const Resolved = struct { layout: Layout.Layout, mask_log: u32 };
pub fn resolve(points: []const Point, current: Point, composition_log: u32, trace_log: u32) !Resolved {
    const previous = @import("../air/logup.zig").prevRowPoint(composition_log, current);
    if (Layout.classifyColumn(points, current, previous)) |layout|
        return .{ .layout = layout, .mask_log = composition_log }
    else |_| {}
    // Shared caller masks use the original composition-domain +27 opening;
    // native external source masks may instead use the physical trace step.
    if (Layout.classifyKeccakPair(points, current, previous)) |_|
        return .{ .layout = .current_keccak_final_composition, .mask_log = composition_log }
    else |_| {}
    const physical = @import("../air/logup.zig").prevRowPoint(trace_log, current);
    return .{ .layout = try Layout.classifyKeccakPair(points, current, physical), .mask_log = trace_log };
}
test "component mask resolver preserves composition and physical Keccak steps" {
    const std = @import("std");
    const current = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(83);
    const logup = @import("../air/logup.zig");
    const common = current.sub(logup.prevRowPoint(7, current));
    const physical = current.sub(logup.prevRowPoint(5, current));
    const composition_points = [_]Point{ current, current.add(common.mulSigned(27)) };
    const physical_points = [_]Point{ current, current.add(physical.mulSigned(27)) };
    try std.testing.expectEqualDeep(Resolved{ .layout = .current_keccak_final_composition, .mask_log = 7 }, try resolve(&composition_points, current, 7, 5));
    try std.testing.expectEqualDeep(Resolved{ .layout = .current_keccak_final, .mask_log = 5 }, try resolve(&physical_points, current, 7, 5));
    const wrong = [_]Point{ current, current.add(common.mulSigned(26)) };
    try std.testing.expectError(error.SamplePointLayoutMismatch, resolve(&wrong, current, 7, 5));
    const swapped = [_]Point{ composition_points[1], current };
    try std.testing.expectError(error.SamplePointLayoutMismatch, resolve(&swapped, current, 7, 5));
}
