//! Every arithmetic input has one matching scalar, secure-pack or public producer.
const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
const scalar = @import("scalar_wire_source.zig");
const boundary = @import("blake3_boundary.zig");
const pack = @import("qm31_pack_wire.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
pub fn check(a: std.mem.Allocator, graphs: anytype, values: anytype, scalars: anytype, boundaries: anytype, packs: anytype) !usize {
    return checkExternal(a, graphs, values, scalars, boundaries, packs, &.{});
}
pub fn checkExternal(a: std.mem.Allocator, graphs: anytype, values: anytype, scalars: anytype, boundaries: anytype, packs: anytype, external_nodes: []const u32) !usize {
    var seen: [graphs.len][]bool = undefined;
    var initialized: usize = 0;
    defer for (seen[0..initialized]) |mask| a.free(mask);
    for (graphs, &seen) |graph, *mask| {
        mask.* = try a.alloc(bool, graph.nodes.len);
        initialized += 1;
        @memset(mask.*, false);
    }
    const scalar_count = if (@typeInfo(@TypeOf(scalars)) == .@"struct") scalars.rowCount() else scalars.len;
    for (0..scalar_count) |index| {
        const row: scalar.Row = if (@typeInfo(@TypeOf(scalars)) == .@"struct") scalars.rowAt(index) else scalars[index];
        try mark(graphs, values, seen, row[1].v, row[2].v, Q.fromBase(row[0]));
    }
    const boundary_count = if (@typeInfo(@TypeOf(boundaries)) == .@"struct") boundaries.rowCount() else boundaries.len;
    if (comptime @typeInfo(@TypeOf(boundaries)) == .@"struct") try boundaries.validate();
    for (0..boundary_count) |index| {
        const row: boundary.Row = if (@typeInfo(@TypeOf(boundaries)) == .@"struct") boundaries.rowAt(index) else boundaries[index];
        try mark(graphs, values, seen, row[5].v, row[6].v, Q.fromM31Array(row[0..4].*));
    }
    const packed_count = if (@typeInfo(@TypeOf(packs)) == .@"struct") packs.rowCount() else packs.len;
    for (0..packed_count) |index| {
        const row: pack.Row = if (@typeInfo(@TypeOf(packs)) == .@"struct") packs.rowAt(index) else packs[index];
        try mark(graphs, values, seen, row[10].v, row[11].v, Q.fromM31Array(row[0..4].*));
    }
    for (external_nodes, 0..) |node, i| {
        if (graphs.len != 3 or node >= graphs[0].nodes.len or graphs[0].nodes[node].op != .input or seen[0][node]) return error.InvalidNativeParentInput;
        for (external_nodes[0..i]) |previous| if (previous == node) return error.DuplicateNativeParentInput;
        // The versioned admission proves closure against these independently
        // supplied public tuples; callers cannot use this list with old keys.
        seen[0][node] = true;
    }
    var count: usize = 0;
    for (graphs, seen, 0..) |graph, mask, lane| {
        const scratch = try a.alloc(u32, graph.nodes.len);
        defer a.free(scratch);
        const uses = try lower.computeUseCountsInto(graph, scratch);
        for (graph.nodes, mask, uses) |node, present, reads| {
            if (node.op == .input) {
                // Execution draws all universal challenges, including domains
                // unused by this statement. Zero-use secure inputs need no rows.
                if (!present and !(graphs.len == 3 and lane == 0 and reads == 0)) return error.MissingNativeParentInput;
                count += 1;
            }
        }
    }
    return count;
}
fn mark(graphs: anytype, values: anytype, seen: anytype, circuit: u32, node: u32, value: Q) !void {
    if (circuit < 1500 or circuit >= 1500 + 2 * graphs.len) return;
    if (circuit % 2 != 0) return error.InvalidNativeParentInput;
    const lane = (circuit - 1500) / 2;
    if (node >= graphs[lane].nodes.len or graphs[lane].nodes[node].op != .input or !values[lane][node].eql(value)) return error.InvalidNativeParentInput;
    if (seen[lane][node]) return error.DuplicateNativeParentInput;
    seen[lane][node] = true;
}
