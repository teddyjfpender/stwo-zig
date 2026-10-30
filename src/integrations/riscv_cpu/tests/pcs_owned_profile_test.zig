const std = @import("std");
const study = @import("../pcs_owned_profile_main.zig");

test "PCS owned arena preserves roots coefficients openings and provider originals across dispatch boundaries" {
    for ([_]usize{ 2, 64, 65, 127, 128 }) |total| {
        const report = try study.run(std.testing.allocator, .{ .native_log = 5, .main_columns = total - 1, .provider_logs = &.{5}, .workers = 3, .memory_limit_bytes = 64 << 20 });
        for (report.measurements) |measurement| {
            try std.testing.expect(measurement.provider_original_unchanged);
            try std.testing.expectEqual(measurement.variant == .policy_owned_arena, measurement.all_coefficients_adopt_source);
            try std.testing.expectEqual(@as(usize, total * 32 * 4), measurement.retained_coefficient_bytes);
        }
    }
}
fn allocationCase(a: std.mem.Allocator) !void {
    const result = try study.singleOwned(a, .{ .native_log = 5, .main_columns = 1, .provider_logs = &.{5}, .workers = 1, .memory_limit_bytes = 64 << 20 });
    try std.testing.expect(result.all_coefficients_adopt_source and result.provider_original_unchanged);
}
fn streamingAllocationCase(a: std.mem.Allocator) !void {
    const result = try study.singleOwned(a, .{ .native_log = 5, .main_columns = 127, .provider_logs = &.{5}, .workers = 1, .memory_limit_bytes = 64 << 20 });
    try std.testing.expect(result.all_coefficients_adopt_source and result.provider_original_unchanged);
}
test "PCS owned arena consumes source exactly once on every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, streamingAllocationCase, .{});
}
