const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const Columns = @import("interaction_columns.zig").Columns;
const guest = @import("../air/guest_precompile/interaction.zig");

fn reserveWithPrefix(allocator: std.mem.Allocator) !void {
    var columns = try Columns.init(allocator, guest.total_column_count + 1);
    defer columns.deinit(allocator);
    const prefix = try allocator.alloc(M31, 2);
    @memset(prefix, M31.one());
    columns.append(1, prefix);
    const destinations = columns.reserveGuest(allocator, 2) catch |err| {
        // Failed reservation must retain the preceding owner's live prefix.
        try std.testing.expectEqual(@as(usize, 1), columns.filled);
        try std.testing.expectEqual(@as(u32, 1), prefix[0].toU32());
        return err;
    };
    try std.testing.expectEqual(guest.total_column_count + 1, columns.filled);
    for (destinations.caller, 0..) |buffer, index| {
        try std.testing.expectEqual(@as(usize, 4), buffer.len);
        try std.testing.expect(buffer.ptr == columns.values[1 + index].values.ptr);
    }
    for (destinations.provider, 0..) |buffer, index| {
        try std.testing.expectEqual(@as(usize, 4), buffer.len);
        try std.testing.expect(buffer.ptr == columns.values[1 + guest.caller_column_count + index].values.ptr);
    }
}

test "interaction columns: failed guest reservation preserves the owned prefix" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, reserveWithPrefix, .{});
}

test "interaction columns: rejected block retains caller ownership" {
    const allocator = std.testing.allocator;
    var columns = try Columns.init(allocator, 1);
    defer columns.deinit(allocator);
    const first = try allocator.alloc(M31, 2);
    defer allocator.free(first);
    const second = try allocator.alloc(M31, 2);
    defer allocator.free(second);
    try std.testing.expectError(error.InvalidTraceShape, columns.appendGenerated(1, &.{ first, second }));
    try std.testing.expectEqual(@as(usize, 0), columns.filled);
    @memset(first, M31.one());
    @memset(second, M31.one());
}

test "interaction columns: commitment transfer survives producer teardown" {
    const allocator = std.testing.allocator;
    var columns = try Columns.init(allocator, 1);
    defer columns.deinit(allocator);
    const buffer = try allocator.alloc(M31, 2);
    @memset(buffer, M31.one());
    columns.append(1, buffer);
    const committed = columns.values;
    columns.moved = true;
    columns.deinit(allocator);
    defer {
        for (committed) |column| allocator.free(@constCast(column.values));
        allocator.free(committed);
    }
    try std.testing.expectEqual(@as(u32, 1), committed[0].log_size);
    for (committed[0].values) |word| try std.testing.expectEqual(@as(u32, 1), word.toU32());
}
