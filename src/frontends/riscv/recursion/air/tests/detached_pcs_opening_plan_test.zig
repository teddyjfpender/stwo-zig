const std = @import("std");
const graph = @import("../composition_circuit.zig");
const pcs = @import("../pcs_deep_circuit.zig");
const opening = @import("../detached_opening_accumulation_plan.zig");
const fusion = @import("../detached_pcs_opening_plan.zig");
const lowering = @import("../verifier_arithmetic_lowering.zig");

test "fused PCS matcher preserves query sources and refuses shared or exported inputs" {
    var nodes: [17]graph.Node = undefined;
    for (nodes[0..9]) |*node| node.* = .{ .op = .input };
    for (0..4) |term| {
        const multiply: u32 = @intCast(9 + term * 2);
        nodes[multiply] = .{ .op = .{ .mul = .{ .lhs = @intCast(1 + term * 2), .rhs = @intCast(2 + term * 2) } } };
        nodes[multiply + 1] = .{ .op = .{ .add = .{ .lhs = if (term == 0) 0 else multiply - 1, .rhs = multiply } } };
    }
    const g = try graph.CircuitGraph.authenticate(&nodes, &.{16}, graph.computeGraphDigest(&nodes, &.{16}));
    var bindings: [9]pcs.InputBinding = undefined;
    var index: [17]u32 = @splat(0);
    for (&bindings, 0..) |*binding, i| {
        binding.* = .{ .node_id = @intCast(i), .source = if (i % 2 == 1) .{ .queried_value = .{ .tree = 2, .column = @intCast(i), .query = 3 } } else .active_selector };
        index[i] = @intCast(i + 1);
    }
    var uses: [17]u32 = undefined;
    var lane = lowering.Lane{ .circuit_id = 412, .active_in = .binary, .circuit_identity = g.identity_digest, .graph = g };
    _ = try lowering.computeLaneUseCountsInto(lane, &uses);
    const reserved: [17]bool = @splat(false);
    const item = opening.matchAt(g, &uses, &reserved, 16).?;
    const candidate = fusion.match(g, &uses, &index, &bindings, item).?;
    try std.testing.expectEqualSlices(u32, &.{ 1, 3, 5, 7 }, &candidate.query_nodes);
    try std.testing.expectEqualSlices(u32, &.{ 2, 4, 6, 8 }, &candidate.weight_nodes);
    for (candidate.queries, candidate.query_nodes) |q, node| {
        try std.testing.expectEqual(@as(u32, 2), q.tree);
        try std.testing.expectEqual(node, q.column);
        try std.testing.expectEqual(@as(u32, 3), q.query);
    }
    // External uses participate in the actual lowering use-count calculation.
    lane.exports = &.{.{ .node_id = 1, .uses = 1 }};
    _ = try lowering.computeLaneUseCountsInto(lane, &uses);
    try std.testing.expectEqual(@as(u32, 2), uses[1]);
    try std.testing.expect(fusion.match(g, &uses, &index, &bindings, item) == null);
    uses[1] = 1;
    const original = bindings[1];
    bindings[1].source = .{ .sampled_value_word = .{ .sample = 0, .word = 0 } };
    try std.testing.expect(fusion.match(g, &uses, &index, &bindings, item) == null);
    bindings[1] = original;
    bindings[1].node_id = 3;
    try std.testing.expect(fusion.match(g, &uses, &index, &bindings, item) == null);
    bindings[1] = original;
    index[1] = 100;
    try std.testing.expect(fusion.match(g, &uses, &index, &bindings, item) == null);
    index[1] = 2;
    // Either multiply operand may be the query input; stable selection retains
    // the original query coordinates and binds the other operand as a weight.
    nodes[9].op.mul = .{ .lhs = 2, .rhs = 1 };
    const swapped_graph = try graph.CircuitGraph.authenticate(&nodes, &.{16}, graph.computeGraphDigest(&nodes, &.{16}));
    const swapped = fusion.match(swapped_graph, &uses, &index, &bindings, item).?;
    try std.testing.expectEqualDeep(candidate, swapped);
}
