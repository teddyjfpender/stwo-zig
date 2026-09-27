//! Canonical positive quotient schedule for the native parent AIR roster.
//! Run after dot4 reservation and before FMA reservation. Shared/exported inverse
//! and product wires must remain visible to their other consumers.
const std = @import("std");
const graph = @import("composition_circuit.zig");
const fma = @import("detached_arithmetic_fusion_plan.zig");
pub const Match = struct {
    inverse_node: u32,
    multiply_node: u32,
    output_node: u32,
    denominator_node: u32,
    numerator_node: u32,
    accumulator_node: u32,
};
pub fn matchAt(g: graph.CircuitGraph, uses: []const u32, reserved: []const bool, output: u32) ?Match {
    const item = fma.matchAt(g, uses, reserved, output) orelse return null;
    if (item.operation != .product_plus_addend) return null;
    const operands = g.nodes[item.multiply_node].op.mul;
    for ([_]u32{ operands.lhs, operands.rhs }, 0..) |operand, side| {
        if (operand >= item.multiply_node or reserved[operand] or uses[operand] != 1) continue;
        const denominator = switch (g.nodes[operand].op) {
            .inverse => |node| node,
            else => continue,
        };
        return .{
            .inverse_node = operand,
            .multiply_node = item.multiply_node,
            .output_node = output,
            .denominator_node = denominator,
            .numerator_node = if (side == 0) operands.rhs else operands.lhs,
            .accumulator_node = item.addend_node,
        };
    }
    return null;
}
pub fn reserve(matches: *std.ArrayList(Match), a: std.mem.Allocator, g: graph.CircuitGraph, uses: []const u32, reserved: []bool) !void {
    if (uses.len != g.nodes.len or reserved.len != g.nodes.len) return error.InvalidFusionShape;
    for (g.nodes, 0..) |_, output| if (matchAt(g, uses, reserved, @intCast(output))) |item| {
        try matches.append(a, item);
        reserved[item.inverse_node] = true;
        reserved[item.multiply_node] = true;
        reserved[item.output_node] = true;
    };
}
