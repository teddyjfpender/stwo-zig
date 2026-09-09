//! Local graph matching for the admitted detached multiply-add schedule.
//! Uses include graph outputs and cross-circuit exports. A product is hidden
//! only when its sole consumer is the matching add/subtract operation.
const std = @import("std");
const graph = @import("composition_circuit.zig");
const fused = @import("qm31_mul_add_v1.zig");
pub const Match = struct {
    multiply_node: u32,
    output_node: u32,
    addend_node: u32,
    operation: fused.Operation,
};
pub fn matchAt(g: graph.CircuitGraph, uses: []const u32, reserved: []const bool, output: u32) ?Match {
    if (uses.len != g.nodes.len or reserved.len != g.nodes.len or output >= g.nodes.len or reserved[output] or uses[output] == 0) return null;
    const op = switch (g.nodes[output].op) {
        .add, .sub => |v| v,
        else => return null,
    };
    for ([_]u32{ op.lhs, op.rhs }, 0..) |candidate, side| {
        if (candidate >= output or reserved[candidate] or uses[candidate] != 1 or g.nodes[candidate].op != .mul) continue;
        return .{
            .multiply_node = candidate,
            .output_node = output,
            .addend_node = if (side == 0) op.rhs else op.lhs,
            .operation = if (g.nodes[output].op == .add) .product_plus_addend else if (side == 0) .product_minus_addend else .addend_minus_product,
        };
    }
    return null;
}
/// Reserve both operation rows. Input/output publisher counts remain unchanged;
/// only the hidden multiply output loses its sole consume/emit pair.
pub fn reserve(matches: *std.ArrayList(Match), allocator: std.mem.Allocator, g: graph.CircuitGraph, uses: []const u32, reserved: []bool) !void {
    if (uses.len != g.nodes.len or reserved.len != g.nodes.len) return error.InvalidFusionShape;
    for (g.nodes, 0..) |_, output| if (matchAt(g, uses, reserved, @intCast(output))) |item| {
        try matches.append(allocator, item);
        reserved[item.multiply_node] = true;
        reserved[item.output_node] = true;
    };
}
