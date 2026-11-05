const std = @import("std");
const A = @import("../pcs_assembly.zig");
const F = @import("../fri.zig");
const shape = A.Shape{ .config = .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 1, .fold_step = 4 } }, .degree_log = 5, .trees = &.{ .{ .coefficient_logs = &.{ 5, 5 }, .sorted_to_original = &.{ 0, 1 }, .sample_counts = &.{ 0, 2 } }, .{ .coefficient_logs = &.{3}, .sorted_to_original = &.{0}, .sample_counts = &.{1} } } };
fn exercise(a: std.mem.Allocator) !void {
    const layers = [_]F.LayerReadback{ .{ .root = @splat(0), .values = &@as([128]u32, @splat(0)), .paths = &@as([128]u32, @splat(0)) }, .{ .root = @splat(0), .values = &@as([16]u32, @splat(0)), .paths = &@as([32]u32, @splat(0)) } };
    var proof = try A.assemble(a, shape, .{ .raw_queries = &.{0}, .samples = &@as([24]u32, @splat(0)), .trace = &.{ .{ .root = @splat(0), .values = &.{ 0, 0 }, .paths = &@as([48]u32, @splat(0)) }, .{ .root = @splat(0), .values = &.{0}, .paths = &@as([32]u32, @splat(0)) } }, .fri = &layers, .terminal = @splat(0), .nonce = 0 });
    defer proof.deinit(a);
    try std.testing.expectEqual(@as(usize, 2), proof.commitments.items.len);
    try std.testing.expectEqual(@as(usize, 0), proof.sampled_values.items[0][0].len);
    try std.testing.expectEqual(@as(usize, 2), proof.sampled_values.items[0][1].len);
    try std.testing.expectEqual(@as(usize, 1), proof.sampled_values.items[1][0].len);
}
test "complete PCS proof assembly transfers every tree atomically across allocator failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exercise, .{});
}
