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
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    const g = source.graph.graph();
    const values = source.evaluation.values;
    const uses = try temp.alloc(u32, g.nodes.len);
    _ = try lower.computeLaneUseCountsInto(.{ .circuit_id = 1502, .active_in = .segment, .circuit_identity = g.identity_digest, .graph = g }, uses);
    const indices = try temp.alloc(u32, g.nodes.len);
    @memset(indices, 0);
    for (source.graph.bindings, 0..) |b, i| indices[b.node_id] = @intCast(i + 1);
    const reserved = try temp.alloc(bool, g.nodes.len);
    @memset(reserved, false);
    var matches: std.ArrayList(opening.Match) = .empty;
    try opening.reserve(&matches, temp, g, uses, reserved);
    const candidates = try temp.alloc(?matcher.Candidate, g.nodes.len);
    @memset(candidates, null);
    const selected = try temp.alloc(bool, g.nodes.len);
    @memset(selected, false);
    var candidate_count: usize = 0;
    for (matches.items) |item| if (matcher.match(g, uses, indices, source.graph.bindings, item)) |candidate| {
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
