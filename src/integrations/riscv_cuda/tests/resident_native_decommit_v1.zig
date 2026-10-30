//! Cold ordinal geometry regression, not proof qualification.
const std = @import("std");
const Topology = @import("stwo_cairo_cuda_integration").executor.pcs_decommit_topology;
test "native five tree openings retain distinct witness ordinal" {
    const a = std.testing.allocator;
    const tree = Topology.GenericTree{ .column_logs = &.{4}, .lifted_log = 5 };
    const layers = [_]Topology.GenericFriLayer{
        .{ .evaluation_log = 5, .cumulative_fold = 0, .fold_step = 2, .log_rows_per_leaf = 2 },
        .{ .evaluation_log = 3, .cumulative_fold = 2, .fold_step = 2, .log_rows_per_leaf = 2 },
    };
    var result = try Topology.deriveNativeFiveTrees(a, @splat(tree), &layers, 1, 5, 8, 65536, @splat(1));
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 5), result.trace_openings.len);
    try std.testing.expectEqual(@as(u32, 2), result.trace_openings[2].tree_index);
    try std.testing.expectEqual(@as(u32, 3), result.trace_openings[3].tree_index);
    try std.testing.expectEqual(@as(u32, 5), result.fri_openings[0].tree_index);
    try std.testing.expectEqual(@as(u32, 7), result.tree_count);
    for (result.trace_groups, 0..) |group, i| try std.testing.expectEqual(i, group.tree_ordinal);
    var original = try Topology.deriveGeneric(a, @splat(tree), &layers, 1, 5, 8, 65536, @splat(1));
    defer original.deinit();
    try std.testing.expectEqual(@as(usize, 4), original.trace_openings.len);
    try std.testing.expectEqual(@as(u32, 4), original.fri_openings[0].tree_index);
}

test "native five tree opening controller uses original capacity planner" {
    const a = std.testing.allocator;
    const G = @import("../../circuit_cuda/geometry.zig");
    var logs = [_]u32{4};
    const Shape = struct { trees: [5]G.Tree, fri_layers: []const G.FriLayer, fri_input_log: u32 = 5, identity: [32]u8 = @splat(1) };
    const layers = [_]G.FriLayer{
        .{ .evaluation_log = 5, .cumulative_fold = 0, .fold_step = 2, .leaf_log = 3 },
        .{ .evaluation_log = 3, .cumulative_fold = 2, .fold_step = 2, .leaf_log = 1 },
    };
    const tree = G.Tree{ .role = .main, .column_logs = &logs, .lifted_log = 5 };
    const shape = Shape{ .trees = @splat(tree), .fri_layers = &layers };
    const C = @import("../../circuit_cuda/resident_decommit.zig");
    var plan = try C.ForCommitments(5).init(a, &shape, .{ .fri_config = .{ .n_queries = @as(u32, 8), .log_blowup_factor = @as(u32, 1) } });
    defer plan.deinit();
    try std.testing.expectEqual(try C.capacityWords(&shape, 8), plan.topology.assembly_capacity_words);
    try std.testing.expectEqual(@as(usize, 5), plan.topology.trace_openings.len);
}
