//! Match four-term opening accumulations in the admitted arithmetic graph.
//! Only single-use internal nodes disappear. Every external wire occurrence,
//! graph output and cross-circuit export retains its original multiplicity.
const std = @import("std");
const graph = @import("composition_circuit.zig");
pub const TERM_COUNT: usize = 4;
pub const Match = struct {
    /// Oldest to newest term; the last add is the externally visible output.
    multiply_nodes: [TERM_COUNT]u32,
    add_nodes: [TERM_COUNT]u32,
    accumulator_node: u32,
    output_node: u32,
};
pub fn matchAt(g: graph.CircuitGraph, uses: []const u32, reserved: []const bool, output: u32) ?Match {
    if (uses.len != g.nodes.len or reserved.len != g.nodes.len or output >= g.nodes.len or uses[output] == 0) return null;
    var result: Match = undefined;
    result.output_node = output;
    var current = output;
    for (0..TERM_COUNT) |depth| {
        if (reserved[current] or (depth != 0 and uses[current] != 1)) return null;
        const add = switch (g.nodes[current].op) {
            .add => |v| v,
            else => return null,
        };
        var found = false;
        for ([_]u32{ add.lhs, add.rhs }, 0..) |candidate, side| {
            if (candidate >= current or reserved[candidate] or uses[candidate] != 1 or g.nodes[candidate].op != .mul) continue;
            const accumulator = if (side == 0) add.rhs else add.lhs;
            if (accumulator >= current) continue;
            if (depth + 1 < TERM_COUNT and g.nodes[accumulator].op != .add) continue;
            const term = TERM_COUNT - 1 - depth;
            result.multiply_nodes[term] = candidate;
            result.add_nodes[term] = current;
            result.accumulator_node = accumulator;
            current = accumulator;
            found = true;
            break;
        }
        if (!found) return null;
    }
    return result;
}
/// Run before two-operation multiply-add fusion. Fused outputs may be inputs
/// to subsequent blocks; reservation prohibits hiding them a second time.
pub fn reserve(matches: *std.ArrayList(Match), allocator: std.mem.Allocator, g: graph.CircuitGraph, uses: []const u32, reserved: []bool) !void {
    if (uses.len != g.nodes.len or reserved.len != g.nodes.len) return error.InvalidFusionShape;
    for (g.nodes, 0..) |_, output| if (matchAt(g, uses, reserved, @intCast(output))) |item| {
        try matches.append(allocator, item);
        for (item.multiply_nodes) |node| reserved[node] = true;
        for (item.add_nodes) |node| reserved[node] = true;
    };
}
