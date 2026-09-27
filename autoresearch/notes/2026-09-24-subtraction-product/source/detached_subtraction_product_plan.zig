//! Experimental contraction after existing dot4/FMA reservations.
const std = @import("std");
const graph = @import("composition_circuit.zig");
pub const Match = struct { subtraction: u32, output: u32, minuend: u32, subtrahend: u32, factor: u32 };
pub fn matchAt(g: graph.CircuitGraph, uses: []const u32, reserved: []const bool, output: u32) ?Match {
    if (uses.len != g.nodes.len or reserved.len != g.nodes.len or output >= g.nodes.len or reserved[output] or uses[output] == 0) return null;
    const operands = switch (g.nodes[output].op) {
        .mul => |v| v,
        else => return null,
    };
    for ([_]u32{ operands.lhs, operands.rhs }, 0..) |node, side| {
        if (node >= output or reserved[node] or uses[node] != 1) continue;
        const subtraction = switch (g.nodes[node].op) {
            .sub => |v| v,
            else => continue,
        };
        return .{ .subtraction = node, .output = output, .minuend = subtraction.lhs, .subtrahend = subtraction.rhs, .factor = if (side == 0) operands.rhs else operands.lhs };
    }
    return null;
}
/// Input multiplicities and the multiplication output multiplicity are unchanged.
/// Only the subtraction's single producer/consumer pair becomes internal.
pub fn reserve(matches: *std.ArrayList(Match), a: std.mem.Allocator, g: graph.CircuitGraph, uses: []const u32, reserved: []bool) !void {
    if (uses.len != g.nodes.len or reserved.len != g.nodes.len) return error.InvalidFusionShape;
    for (g.nodes, 0..) |_, output| if (matchAt(g, uses, reserved, @intCast(output))) |item| {
        try matches.append(a, item);
        reserved[item.subtraction] = true;
        reserved[item.output] = true;
    };
}
