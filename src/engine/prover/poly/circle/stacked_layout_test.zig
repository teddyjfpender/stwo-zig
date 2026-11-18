const std = @import("std");
const Layout = @import("stacked_layout.zig").Layout;
const alloc = std.testing.allocator;

fn exercise(a: std.mem.Allocator) !void {
    var heights: [193]u32 = @splat(6);
    var masks: [193][]const i32 = undefined;
    const classes = [_][]const i32{ &.{ 0, -1 }, &.{ 0, 2 }, &.{}, &.{ -1, 0 } };
    for (&masks, 0..) |*mask, i| mask.* = classes[i % 4];
    for (0..16) |i| heights[i * 4] = 8;
    heights[192] = 10;
    var plan = (try Layout.init(a, &heights, &masks, 16)) orelse return error.ExpectedStack;
    defer plan.deinit(a);
    var seen: [193]bool = @splat(false);
    var body: usize = 0;
    for (plan.groups) |g| {
        const members = plan.members(g);
        try std.testing.expect(std.math.isPowerOfTwo(members.len));
        try std.testing.expect(members.len <= 16);
        try std.testing.expect(g.targetLog() <= 10);
        for (members, 0..) |i, j| {
            try std.testing.expect(!seen[i]);
            seen[i] = true;
            if (j > 0) try std.testing.expect(members[j - 1] < i);
            try std.testing.expectEqual(heights[i], g.source_log);
            try std.testing.expectEqualSlices(i32, masks[members[0]], masks[i]);
        }
        body += members.len * (@as(usize, 1) << @intCast(g.source_log));
    }
    try std.testing.expectEqual(@as(usize, 16 * 256 + 176 * 64 + 1024), body);
    try std.testing.expect(std.mem.allEqual(bool, &seen, true));
    try std.testing.expectEqual(@as(usize, 16), plan.groups.len);
    try std.testing.expectEqual(@as(usize, 2), Layout.rowBlocks(plan.groups.len) * 2);
}
test "stacked Circle layout preserves exact masks, degrees and every source ordinal" {
    try exercise(alloc);
    try std.testing.checkAllAllocationFailures(alloc, exercise, .{});
}
test "stacked Circle layout retains direct rows at the hash break-even and rejects invalid geometry" {
    const single = [_][]const i32{&.{0}} ** 32;
    try std.testing.expect((try Layout.init(alloc, &.{}, &.{}, 8)) == null);
    try std.testing.expect((try Layout.init(alloc, &(@as([32]u32, @splat(8))), &single, 8)) == null);
    var mixed: [32]u32 = @splat(6);
    mixed[31] = 9;
    try std.testing.expect((try Layout.init(alloc, &mixed, &single, 8)) == null);
    try std.testing.expectError(error.InvalidStackShape, Layout.init(alloc, &mixed, single[0..31], 8));
    try std.testing.expectError(error.InvalidStackShape, Layout.init(alloc, &mixed, &single, 3));
    const Group = @import("stacked_layout.zig").Group;
    const g = Group{ .first = 0, .source_log = 8, .log_width = 3 };
    try std.testing.expectError(error.InvalidStackShape, g.lift(10));
    try std.testing.expectError(error.InvalidStackShape, g.lift(31));
    mixed[0] = 31;
    try std.testing.expectError(error.InvalidStackShape, Layout.init(alloc, &mixed, &single, 8));
}
