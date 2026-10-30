const std = @import("std");
const P = @import("../block_v7_ram_component_planner_v1.zig");
test "recursive RAM planner reduces opened columns with bounded trace padding" {
    const limits = @import("../block_v7_memory_bundle_v1.zig").Limits{ .max_events = 1 << 24, .max_row_log = 22, .max_matrix_bytes = 8 << 30 };
    const old = try P.fixed(1710496, 1 << 15);
    const new = try P.select(1710496, .{}, limits);
    try std.testing.expectEqual(@as(u32, 53), old.components);
    try std.testing.expectEqual(@as(u32, 4), new.components);
    try std.testing.expectEqual(@as(u32, 1 << 19), new.events_per_component);
    try std.testing.expect(new.private_opening_columns * 13 < old.private_opening_columns);
    try std.testing.expect(new.padded_rows * 100 < old.padded_rows * 108);
}
test "recursive RAM planner respects row matrix shard and event limits" {
    const L = @import("../block_v7_memory_bundle_v1.zig").Limits;
    const capped = try P.select(1000000, .{}, L{ .max_events = 2000000, .max_row_log = 16 });
    try std.testing.expectEqual(@as(u32, 1 << 17), capped.events_per_component);
    try std.testing.expectEqual(@as(u32, 8), capped.components);
    try std.testing.expectError(error.RamComponentPlanningResourceLimit, P.select(1000000, .{}, L{ .max_events = 2000000, .max_row_log = 16, .max_shards = 4 }));
    try std.testing.expectError(error.RamComponentPlanningResourceLimit, P.select(100, .{}, L{ .max_matrix_bytes = 16 }));
    try std.testing.expectError(error.InvalidRamComponentPlanningPolicy, P.select(100, .{ .maximum_events = 123 }, .{}));
    const empty = try P.select(0, .{}, .{});
    try std.testing.expectEqual(@as(u32, 0), empty.components);
}
