//! Logical FIXED presence is independent of host polynomial storage.
//! A device slot is a real admitted tree, never a fabricated host placeholder.
const std = @import("std");
pub fn preprocessedColumnCount(scheme: anytype) ?usize {
    if (scheme.device_om31_trace_trees[0]) |tree| return tree.columns.len;
    if (scheme.trees.items.len == 0) return null;
    return scheme.trees.items[0].columns.len;
}
test "preprocessed slot admits host or device FIXED with unchanged column counts" {
    const Tree = struct { columns: []const u8 };
    const Scheme = struct { trees: struct { items: []const Tree }, device_om31_trace_trees: [3]?Tree };
    var scheme: Scheme = .{ .trees = .{ .items = @as([]const Tree, &.{.{ .columns = &.{ 1, 2 } }}) }, .device_om31_trace_trees = @as([3]?Tree, .{ null, null, null }) };
    try std.testing.expectEqual(@as(?usize, 2), preprocessedColumnCount(scheme));
    scheme.device_om31_trace_trees[0] = .{ .columns = &.{ 1, 2, 3 } };
    // Host storage can now be the later composition tree, not slot0.
    try std.testing.expectEqual(@as(?usize, 3), preprocessedColumnCount(scheme));
    scheme.trees.items = &.{};
    try std.testing.expectEqual(@as(?usize, 3), preprocessedColumnCount(scheme));
    scheme.device_om31_trace_trees[0] = null;
    scheme.device_om31_trace_trees[1] = .{ .columns = &.{1} };
    try std.testing.expectEqual(@as(?usize, null), preprocessedColumnCount(scheme));
    scheme.device_om31_trace_trees[1] = null;
    try std.testing.expectEqual(@as(?usize, null), preprocessedColumnCount(scheme));
    scheme.trees.items = &.{.{ .columns = &.{} }};
    try std.testing.expectEqual(@as(?usize, 0), preprocessedColumnCount(scheme));
}
