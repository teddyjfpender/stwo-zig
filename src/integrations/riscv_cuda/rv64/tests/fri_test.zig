const std = @import("std");
const G = @import("../fri.zig");
test "FRI mutated geometry fails before readback allocation" {
    var p = try G.Plan.init(17, .{ .log_blowup_factor = 2, .log_last_layer_degree_bound = 0, .n_queries = 256, .fold_step = 4 });
    p.layers[0].leaf_log = 3;
    try std.testing.expectError(error.InvalidFriGeometry, p.validate());
    p.layers[0].leaf_log = 2;
    p.layers[0].shift = 1;
    try std.testing.expectError(error.InvalidFriReadback, p.validate());
}
fn formatQueriedCoset(allocator: std.mem.Allocator) !void {
    const plan = try G.Plan.init(1, .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 2, .fold_step = 1 });
    // Formatting/ownership fixture only; zero hashes are not a Merkle proof.
    const values = [_]u32{0} ** 32;
    const paths = [_]u32{0} ** 64;
    const layer = G.LayerReadback{ .root = @splat(0), .values = &values, .paths = &paths };
    var proof = try G.assemble(allocator, plan, &.{ 0, 1 }, &.{layer}, &([_]u32{0} ** 8));
    defer proof.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), proof.first_layer.fri_witness.len);
    try std.testing.expectEqual(@as(usize, 1), proof.first_layer.decommitment.hash_witness.len);
}
test "FRI compact readback formatting has failure atomic ownership" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, formatQueriedCoset, .{});
}
