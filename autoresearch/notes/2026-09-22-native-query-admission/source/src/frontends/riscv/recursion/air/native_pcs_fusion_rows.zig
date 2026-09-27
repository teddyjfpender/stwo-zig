//! Contract canonical native dot4 rows with their exact single-use query sources.
const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
const M = @import("stwo_core").fields.m31.M31;
const deep = @import("blake3_native_deep.zig");
const old = @import("detached_opening_accumulate4_v1.zig");
const native = @import("native_pcs_opening4_v1.zig");
const scalar = @import("scalar_wire_source.zig");
const opening = @import("detached_opening_accumulation_plan.zig");
const matcher = @import("detached_pcs_opening_plan.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
pub const Rows = struct {
    arena: std.heap.ArenaAllocator,
    opening: []old.Row,
    native: []native.Row,
    scalars: []scalar.Row,
    pub fn deinit(self: *Rows) void { self.arena.deinit(); self.* = undefined; }
};
pub fn materialize(a: std.mem.Allocator, source: *const deep.Prepared, originals: []const old.Row, scalars: []const scalar.Row) !Rows {
    try source.graph.validateEvaluation(&source.evaluation);
    return materializeGraph(a, source.graph.graph(), source.graph.bindings, source.evaluation.values, originals, scalars);
}
// Private kernel: the production entry above validates the owned evaluation.
fn materializeGraph(a: std.mem.Allocator, g: @import("composition_circuit.zig").CircuitGraph, bindings: []const @import("pcs_deep_circuit.zig").InputBinding, values: []const Q, originals: []const old.Row, scalars: []const scalar.Row) !Rows {
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    const uses = try temp.alloc(u32, g.nodes.len);
    _ = try lower.computeLaneUseCountsInto(.{ .circuit_id = 1502, .active_in = .segment, .circuit_identity = g.identity_digest, .graph = g }, uses);
    const indices = try temp.alloc(u32, g.nodes.len);
    @memset(indices, 0);
    for (bindings, 0..) |b, i| indices[b.node_id] = @intCast(i + 1);
    const reserved = try temp.alloc(bool, g.nodes.len);
    @memset(reserved, false);
    var matches: std.ArrayList(opening.Match) = .empty;
    try opening.reserve(&matches, temp, g, uses, reserved);
    const candidates = try temp.alloc(?matcher.Candidate, g.nodes.len);
    @memset(candidates, null);
    const selected = try temp.alloc(bool, g.nodes.len);
    @memset(selected, false);
    var candidate_count: usize = 0;
    for (matches.items) |item| if (matcher.match(g, uses, indices, bindings, item)) |candidate| {
        candidates[item.output_node] = candidate;
        candidate_count += 1;
        for (candidate.query_nodes) |node| {
            if (selected[node]) return error.InvalidNativePcsFusion;
            selected[node] = true;
        }
    };
    const pending = try temp.dupe(bool, selected);
    const emitted = try temp.alloc(bool, g.nodes.len);
    @memset(emitted, false);
    var retained: std.ArrayList(old.Row) = .empty;
    var fused: std.ArrayList(native.Row) = .empty;
    for (originals) |row| {
        const pp = row[old.PHYSICAL_MAIN_COLUMN_COUNT..];
        if (pp[1].v == 1502 and pp[11].v < emitted.len and emitted[pp[11].v]) return error.InvalidNativePcsFusion;
        const candidate = if (pp[1].v == 1502 and pp[11].v < candidates.len) candidates[pp[11].v] else null;
        if (candidate) |c| {
            const item = c.opening;
            var lhs: [4]u32 = undefined;
            var rhs: [4]u32 = undefined;
            var lv: [4]Q = undefined;
            var rv: [4]Q = undefined;
            var queries: [4]M = undefined;
            var weights: [4]Q = undefined;
            for (item.multiply_nodes, 0..) |node, i| {
                const operands = g.nodes[node].op.mul;
                lhs[i] = operands.lhs; rhs[i] = operands.rhs;
                lv[i] = values[lhs[i]]; rv[i] = values[rhs[i]];
                const words = values[c.query_nodes[i]].toM31Array();
                if (!words[1].isZero() or !words[2].isZero() or !words[3].isZero()) return error.InvalidNativePcsFusion;
                queries[i] = words[0]; weights[i] = values[c.weight_nodes[i]];
            }
            const expected = try old.logicalRow(.{ .circuit = 1502, .accumulator = item.accumulator_node, .lhs = lhs, .rhs = rhs, .output = item.output_node, .uses = uses[item.output_node] }, values[item.accumulator_node], lv, rv, values[item.output_node]);
            for (row, expected) |actual, wanted| if (!actual.eql(wanted)) return error.InvalidNativePcsFusion;
            try fused.append(temp, try native.logicalRow(.{ .circuit = 1502, .accumulator = item.accumulator_node, .queries = c.query_nodes, .weights = c.weight_nodes, .output = item.output_node, .uses = uses[item.output_node] }, values[item.accumulator_node], queries, weights, values[item.output_node]));
            candidates[item.output_node] = null;
            emitted[item.output_node] = true;
        } else try retained.append(temp, row);
    }
    if (fused.items.len != candidate_count) return error.InvalidNativePcsFusion;
    var kept: std.ArrayList(scalar.Row) = .empty;
    var removed: usize = 0;
    for (scalars) |row| {
        const node = row[2].v;
        if (row[1].v == 1502 and node < selected.len and selected[node]) {
            const expected = try scalar.logicalRow(1502, node, 3, values[node].toM31Array()[0]);
            for (row, expected) |actual, wanted| if (!actual.eql(wanted)) return error.InvalidNativePcsFusion;
            if (!pending[node]) return error.InvalidNativePcsFusion;
            pending[node] = false;
            removed += 1;
        } else try kept.append(temp, row);
    }
    if (removed != candidate_count * 4) return error.InvalidNativePcsFusion;
    return .{ .arena = arena, .opening = try retained.toOwnedSlice(temp), .native = try fused.toOwnedSlice(temp), .scalars = try kept.toOwnedSlice(temp) };
}

test "native query fusion admission rejects altered missing and duplicate sources" {
    const a = std.testing.allocator;
    const graph = @import("composition_circuit.zig");
    const pcs = @import("pcs_deep_circuit.zig");
    var nodes: [17]graph.Node = undefined;
    var values: [17]Q = undefined;
    var bindings: [9]pcs.InputBinding = undefined;
    for (nodes[0..9], values[0..9], &bindings, 0..) |*node, *value, *b, i| {
        node.* = .{ .op = .input };
        value.* = Q.fromBase(M.fromCanonical(@intCast(i + 1)));
        b.* = .{ .node_id = @intCast(i), .source = if (i % 2 == 1) .{ .queried_value = .{ .tree = 0, .column = @intCast(i), .query = 0 } } else .active_selector };
    }
    const queries: [4]u32 = .{1, 3, 5, 7};
    const weights: [4]u32 = .{2, 4, 6, 8};
    var lhs: [4]Q = undefined;
    var rhs: [4]Q = undefined;
    var scalars: [4]scalar.Row = undefined;
    for (0..4) |i| {
        const mul: u32 = @intCast(9 + 2 * i);
        const acc: u32 = if (i == 0) 0 else mul - 1;
        nodes[mul] = .{ .op = .{ .mul = .{ .lhs = queries[i], .rhs = weights[i] } } };
        nodes[mul + 1] = .{ .op = .{ .add = .{ .lhs = acc, .rhs = mul } } };
        lhs[i] = values[queries[i]]; rhs[i] = values[weights[i]];
        values[mul] = lhs[i].mul(rhs[i]);
        values[mul + 1] = values[acc].add(values[mul]);
        scalars[i] = try scalar.logicalRow(1502, queries[i], 3, lhs[i].toM31Array()[0]);
    }
    const g = try graph.CircuitGraph.authenticate(&nodes, &.{16}, graph.computeGraphDigest(&nodes, &.{16}));
    const row = try old.logicalRow(.{ .circuit = 1502, .accumulator = 0, .lhs = queries, .rhs = weights, .output = 16, .uses = 1 }, values[0], lhs, rhs, values[16]);
    var actual = try materializeGraph(a, g, &bindings, &values, &.{row}, &scalars);
    defer actual.deinit();
    try std.testing.expectEqual(@as(usize, 1), actual.native.len);
    try std.testing.expectEqual(@as(usize, 0), actual.opening.len);
    try std.testing.expectEqual(@as(usize, 0), actual.scalars.len);
    for (0..scalars.len) |index| for (0..scalar.LOGICAL_INPUT_COUNT) |column| {
        var changed = scalars;
        changed[index][column] = changed[index][column].add(M.one());
        try std.testing.expectError(error.InvalidNativePcsFusion, materializeGraph(a, g, &bindings, &values, &.{row}, &changed));
    };
    for (0..old.LOGICAL_INPUT_COUNT) |column| {
        var changed = row;
        changed[column] = changed[column].add(M.one());
        try std.testing.expectError(error.InvalidNativePcsFusion, materializeGraph(a, g, &bindings, &values, &.{changed}, &scalars));
    }
    try std.testing.expectError(error.InvalidNativePcsFusion, materializeGraph(a, g, &bindings, &values, &.{}, &scalars));
    try std.testing.expectError(error.InvalidNativePcsFusion, materializeGraph(a, g, &bindings, &values, &.{row, row}, &scalars));
    try std.testing.expectError(error.InvalidNativePcsFusion, materializeGraph(a, g, &bindings, &values, &.{row}, scalars[1..]));
    try std.testing.expectError(error.InvalidNativePcsFusion, materializeGraph(a, g, &bindings, &values, &.{row}, &(scalars ++ .{scalars[0]})));
    const extra = try scalar.logicalRow(1504, 1, 2, M.one());
    var retained = try materializeGraph(a, g, &bindings, &values, &.{row}, &(scalars ++ .{extra}));
    defer retained.deinit();
    try std.testing.expectEqual(@as(usize, 1), retained.scalars.len);
    try std.testing.expectEqualDeep(extra, retained.scalars[0]);
}
