const std = @import("std");
const profile = @import("../pcs_commit_profile_main.zig");

test "generic PCS profile requires identical roots coefficients and authenticated openings for all paths" {
    const result = try profile.run(std.testing.allocator, .{ .native_log = 9, .column_count = 8, .small_log = 5, .small_columns = 3, .workers = 3, .memory_limit_bytes = 64 << 20, .tile_bytes = 4096, .group_bytes = 8192 });
    try std.testing.expect(result.complete and result.root_and_opening_parity and !result.whole_execution_proof);
    for (result.measurements) |measurement| {
        try std.testing.expect(measurement.verified);
        try std.testing.expectEqual(@as(usize, (8 * 512 + 3 * 32) * 4), measurement.retained_coefficient_bytes);
        try std.testing.expect(measurement.peak_charged_bytes < result.config.memory_limit_bytes);
    }
    try std.testing.expectError(error.PcsProfileSourceExceedsBudget, profile.run(std.testing.allocator, .{ .memory_limit_bytes = 1 }));
}
