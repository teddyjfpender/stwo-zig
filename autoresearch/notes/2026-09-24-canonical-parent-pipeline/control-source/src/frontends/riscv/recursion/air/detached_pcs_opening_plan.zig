//! Conservative query-binding fusion over already admitted opening4 matches.
//! This planner is experimental and is not yet a production lowering authority.
const std = @import("std");
const pcs = @import("pcs_deep_circuit.zig");
const graph = @import("composition_circuit.zig");
const opening = @import("detached_opening_accumulation_plan.zig");
const lowering = @import("verifier_arithmetic_lowering.zig");
const component = @import("detached_pcs_opening4_v1.zig");

pub const Candidate = struct {
    opening: opening.Match,
    query_nodes: [4]u32,
    queries: [4]component.Query,
    weight_nodes: [4]u32,
};
pub fn match(g: graph.CircuitGraph, uses: []const u32, input_index: []const u32, bindings: []const pcs.InputBinding, item: opening.Match) ?Candidate {
    if (uses.len != g.nodes.len or input_index.len != g.nodes.len) return null;
    var result: Candidate = .{ .opening = item, .query_nodes = undefined, .queries = undefined, .weight_nodes = undefined };
    for (item.multiply_nodes, 0..) |node, term| {
        if (node >= g.nodes.len or g.nodes[node].op != .mul) return null;
        const operands = g.nodes[node].op.mul;
        var found = false;
        for ([_]u32{ operands.lhs, operands.rhs }, 0..) |input, side| {
            if (input >= uses.len or uses[input] != 1 or g.nodes[input].op != .input) continue;
            const index = input_index[input];
            if (index == 0 or index > bindings.len) continue;
            const binding = bindings[index - 1];
            if (binding.node_id != input or binding.source != .queried_value) continue;
            const source = binding.source.queried_value;
            result.query_nodes[term] = input;
            result.queries[term] = .{ .tree = source.tree, .column = source.column, .query = source.query };
            result.weight_nodes[term] = if (side == 0) operands.rhs else operands.lhs;
            found = true;
            break;
        }
        if (!found) return null;
    }
    return result;
}
pub const Census = struct {
    graph_nodes: usize,
    queried_inputs: usize = 0,
    single_use_queried_inputs: usize = 0,
    shared_queried_inputs: usize = 0,
    opening4_groups: usize = 0,
    eligible_groups: usize = 0,
    removable_input_rows: usize = 0,
    logical_fields_removed: usize = 0,
};
/// The caller supplies the graph's actual external exports; they participate in
/// use counts and prevent an externally consumed input from disappearing.
pub fn census(allocator: std.mem.Allocator, prepared: *const pcs.Prepared, exports: []const lowering.Export) !Census {
    return censusGraph(allocator, prepared.graph(), prepared.view().bindings, exports);
}
/// Shared read-only census for canonical owned or native circuit views. Binding
/// provenance remains the caller's obligation; this does not admit a schedule.
pub fn censusGraph(allocator: std.mem.Allocator, g: graph.CircuitGraph, bindings: []const pcs.InputBinding, exports: []const lowering.Export) !Census {
    const uses = try allocator.alloc(u32, g.nodes.len);
    defer allocator.free(uses);
    _ = try lowering.computeLaneUseCountsInto(.{ .circuit_id = 412, .active_in = .binary, .circuit_identity = g.identity_digest, .graph = g, .exports = exports }, uses);
    const input_index = try allocator.alloc(u32, g.nodes.len);
    defer allocator.free(input_index);
    @memset(input_index, 0);
    var result = Census{ .graph_nodes = g.nodes.len };
    for (bindings, 0..) |binding, index| {
        input_index[binding.node_id] = std.math.cast(u32, index + 1) orelse return error.InvalidFusionShape;
        if (binding.source == .queried_value) {
            result.queried_inputs += 1;
            result.single_use_queried_inputs += @intFromBool(uses[binding.node_id] == 1);
            result.shared_queried_inputs += @intFromBool(uses[binding.node_id] > 1);
        }
    }
    const reserved = try allocator.alloc(bool, g.nodes.len);
    defer allocator.free(reserved);
    @memset(reserved, false);
    var matches: std.ArrayList(opening.Match) = .empty;
    defer matches.deinit(allocator);
    try opening.reserve(&matches, allocator, g, uses, reserved);
    result.opening4_groups = matches.items.len;
    for (matches.items) |item| if (match(g, uses, input_index, bindings, item) != null) {
        result.eligible_groups += 1;
    };
    result.removable_input_rows = result.eligible_groups * 4;
    result.logical_fields_removed = result.eligible_groups * (54 + 4 * 26 - component.LOGICAL_INPUT_COUNT);
    return result;
}
