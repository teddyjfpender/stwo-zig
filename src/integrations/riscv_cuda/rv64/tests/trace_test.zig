const std = @import("std");
const T = @import("../trace.zig");
const g = T.Geometry{ .tree_log = 1, .lifting_log = 1, .column_logs = &.{ 1, 1 }, .column_order = &.{ 1, 0 } };
fn exercise(a: std.mem.Allocator) !void {
    var result = try T.assemble(a, g, &.{ 1, 0, 1 }, .{ .root = @splat(0), .values = &.{ 2, 1, 2, 4, 3, 4 }, .paths = &@as([24]u32, @splat(0)) });
    defer result.deinit(a);
    try std.testing.expectEqual(@as(u32, 3), result.queried_values[0][0].v);
    try std.testing.expectEqual(@as(u32, 2), result.queried_values[1][1].v);
    try std.testing.expectEqual(@as(usize, 0), result.decommitment.hash_witness.len);
}
test "native trace opening formatting is failure atomic across column reordering and duplicates" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exercise, .{});
}
test "trace opening geometry and inconsistent redundant readback fail closed" {
    const a = std.testing.allocator;
    var bad = g;
    bad.column_order = &.{ 0, 0 };
    try std.testing.expectError(error.InvalidTraceGeometry, bad.validate(a));
    try std.testing.expectError(error.InvalidTraceQuery, T.assemble(a, g, &.{ 2, 0, 1 }, .{ .root = @splat(0), .values = &.{ 2, 1, 2, 4, 3, 4 }, .paths = &@as([24]u32, @splat(0)) }));
    try std.testing.expectError(error.InconsistentTraceReadback, T.assemble(a, g, &.{ 1, 0, 1 }, .{ .root = @splat(0), .values = &.{ 2, 1, 3, 4, 3, 4 }, .paths = &@as([24]u32, @splat(0)) }));
    try std.testing.expectError(error.NoncanonicalTraceValue, T.assemble(a, g, &.{ 1, 0, 1 }, .{ .root = @splat(0), .values = &.{ 0x7fffffff, 1, 2, 4, 3, 4 }, .paths = &@as([24]u32, @splat(0)) }));
}
