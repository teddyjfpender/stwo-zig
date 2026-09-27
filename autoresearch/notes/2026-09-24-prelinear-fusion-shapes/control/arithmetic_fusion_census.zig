//! Read-only use of the canonical fusion matchers; never alters graph authority.
const std = @import("std");
const lowering = @import("verifier_arithmetic_lowering.zig");
const dot4 = @import("detached_opening_accumulation_plan.zig");
const fma = @import("detached_arithmetic_fusion_plan.zig");
pub const Census = struct {
    nodes: usize,
    multiply: usize = 0,
    linear: usize = 0,
    inverse: usize = 0,
    dot4_matches: usize,
    fma_matches: usize,
    remaining_multiply: usize = 0,
    remaining_linear: usize = 0,
    remaining_inverse: usize = 0,
    /// Candidate savings beyond the existing lowering, not admitted AIR rows.
    quotient_accumulations: usize = 0,
    prelinear_products: usize = 0,
    prelinear_hidden_rows: usize = 0,
    pub fn removedRows(self: Census) usize {
        return 7 * self.dot4_matches + self.fma_matches;
    }
};
pub fn inspect(a: std.mem.Allocator, lane: lowering.Lane) !Census {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const uses = try lowering.computeLaneUseCountsInto(lane, try temp.alloc(u32, lane.graph.nodes.len));
    const reserved = try temp.alloc(bool, lane.graph.nodes.len);
    @memset(reserved, false);
    var dots: std.ArrayList(dot4.Match) = .empty;
    try dot4.reserve(&dots, temp, lane.graph, uses, reserved);
    var singles: std.ArrayList(fma.Match) = .empty;
    try fma.reserve(&singles, temp, lane.graph, uses, reserved);
    var result = Census{ .nodes = lane.graph.nodes.len, .dot4_matches = dots.items.len, .fma_matches = singles.items.len };
    // An inverse consumed only by an existing FMA can be hidden together with
    // its multiply result. A future quotient AIR MUST also enforce d * inv = 1:
    // d * (out - accumulator) = numerator alone admits d = numerator = 0.
    for (singles.items) |item| {
        const operands = lane.graph.nodes[item.multiply_node].op.mul;
        for ([_]u32{ operands.lhs, operands.rhs }) |operand| {
            if (!reserved[operand] and uses[operand] == 1 and lane.graph.nodes[operand].op == .inverse) {
                result.quotient_accumulations += 1;
                break;
            }
        }
    }
    for (lane.graph.nodes, 0..) |node, index| {
        if (!reserved[index]) switch (node.op) {
            .mul => |operands| {
                result.remaining_multiply += 1;
                var hidden: usize = 0;
                for ([_]u32{ operands.lhs, operands.rhs }) |operand| {
                    if (reserved[operand] or uses[operand] != 1) continue;
                    switch (lane.graph.nodes[operand].op) {
                        .add, .sub, .neg => hidden += 1,
                        else => {},
                    }
                }
                result.prelinear_products += @intFromBool(hidden != 0);
                result.prelinear_hidden_rows += hidden;
            },
            .add, .sub, .neg => result.remaining_linear += 1,
            .inverse => result.remaining_inverse += 1,
            else => {},
        };
        switch (node.op) {
            .mul => result.multiply += 1,
            .add, .sub, .neg => result.linear += 1,
            .inverse => result.inverse += 1,
            else => {},
        }
    }
    return result;
}

test "residual arithmetic census respects shared and exported intermediates" {
    const a = std.testing.allocator;
    const graph = @import("composition_circuit.zig");
    const nodes = [_]graph.Node{
        .{ .op = .input },                              .{ .op = .input },                              .{ .op = .input },
        .{ .op = .{ .inverse = 0 } },                   .{ .op = .{ .mul = .{ .lhs = 3, .rhs = 1 } } }, .{ .op = .{ .add = .{ .lhs = 4, .rhs = 2 } } },
        .{ .op = .{ .sub = .{ .lhs = 0, .rhs = 1 } } }, .{ .op = .{ .mul = .{ .lhs = 6, .rhs = 2 } } },
    };
    const outputs = [_]u32{ 5, 7 };
    const g = try graph.CircuitGraph.authenticate(&nodes, &outputs, graph.computeGraphDigest(&nodes, &outputs));
    var lane = lowering.Lane{ .circuit_id = 1502, .active_in = .segment, .circuit_identity = g.identity_digest, .graph = g };
    const candidate = try inspect(a, lane);
    try std.testing.expectEqual(@as(usize, 1), candidate.fma_matches);
    try std.testing.expectEqual(@as(usize, 1), candidate.quotient_accumulations);
    try std.testing.expectEqual(@as(usize, 1), candidate.prelinear_products);
    try std.testing.expectEqual(@as(usize, 1), candidate.prelinear_hidden_rows);
    lane.exports = &.{ .{ .node_id = 3, .uses = 1 }, .{ .node_id = 6, .uses = 1 } };
    const shared = try inspect(a, lane);
    try std.testing.expectEqual(@as(usize, 0), shared.quotient_accumulations);
    try std.testing.expectEqual(@as(usize, 0), shared.prelinear_products);
    try std.testing.expectEqual(candidate.remaining_multiply, shared.remaining_multiply);
}
