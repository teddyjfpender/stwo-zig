//! Placement is shared by both whole-arena and dynamically sized components.
const std = @import("std");
const columns = @import("base_columns.zig");
const claim = @import("../claim_generator.zig");
const execution = @import("../witness/component_executor.zig");
const layout_type = @import("../witness/component_layout.zig").ComponentLayout;

fn placementCase(allocator: std.mem.Allocator) !void {
    var components = [_]claim.ComponentGeometry{.{ .name = "storage-test", .log_size = .{ .known = 4 } }};
    var geometry = claim.OwnedClaimGeometry{ .allocator = allocator, .components = &components };
    var collector = try columns.Collector.init(allocator, &geometry);
    defer collector.deinit();
    const layout = layout_type{ .ordinal = 0, .label = "storage-test", .row_count = 16, .column_count = 2 };
    const destination = (try columns.reserveGenerated(&collector, allocator, layout)).?;
    defer allocator.free(destination);
    for (destination, 0..) |column, index| @memset(column, @intCast(index + 3));
    const produced = execution.Execution{
        .allocator = allocator,
        .row_count = 16,
        .output_storage = &.{},
        .output_columns = destination,
        .lookup_words = &.{},
        .lookup_allocation = null,
        .sub_words = &.{},
    };
    try columns.observeGenerated(&collector, layout, &produced);
    try std.testing.expectEqual(destination[0].ptr, @as([*]u32, @ptrCast(@constCast(collector.components[0].?[0].values.ptr))));
    var invalid = layout;
    invalid.ordinal = 1;
    try std.testing.expectError(error.InvalidBaseTraceGeometry, columns.reserveGenerated(&collector, allocator, invalid));
    try std.testing.expectError(error.InvalidBaseTraceGeometry, columns.reserveGenerated(&collector, allocator, layout));
    const flat = try collector.finish();
    defer {
        for (flat) |column| allocator.free(column.values);
        allocator.free(flat);
    }
    for (flat, 0..) |column, index| for (column.values) |value| try std.testing.expectEqual(@as(u32, @intCast(index + 3)), value.v);
}

test "Cairo witness final storage owns component placement across all allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, placementCase, .{});
}

fn implicitPlacementCase(allocator: std.mem.Allocator) !void {
    var components = [_]claim.ComponentGeometry{.{ .name = "memory-test", .log_size = .{ .known = 4 } }};
    var geometry = claim.OwnedClaimGeometry{ .allocator = allocator, .components = &components };
    var collector = try columns.Collector.init(allocator, &geometry);
    defer collector.deinit();
    const destination = try collector.reserveNamed("memory-test", 0, 3, 16);
    defer allocator.free(destination);
    for (destination, 0..) |column, index| @memset(column, @intCast(index + 7));
    try std.testing.expectError(error.UnknownBaseComponent, collector.reserveNamed("missing", 0, 3, 16));
    try std.testing.expectError(error.InvalidBaseTraceGeometry, collector.reserveNamed("memory-test", 0, 3, 16));
    const flat = try collector.finish();
    defer {
        for (flat) |column| allocator.free(column.values);
        allocator.free(flat);
    }
    for (flat, destination, 0..) |column, source, index| {
        try std.testing.expectEqual(@intFromPtr(source.ptr), @intFromPtr(column.values.ptr));
        for (column.values) |value| try std.testing.expectEqual(@as(u32, @intCast(index + 7)), value.v);
    }
}

test "Cairo witness final storage implicit reservation transfers values without copies across allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, implicitPlacementCase, .{});
}
