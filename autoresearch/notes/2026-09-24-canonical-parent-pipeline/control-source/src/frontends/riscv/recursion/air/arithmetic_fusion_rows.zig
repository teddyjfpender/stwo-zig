//! Canonical typed dot4/FMA materialization for authenticated arithmetic lanes.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const lowering = @import("verifier_arithmetic_lowering.zig");
const air = struct {
    pub const qm31_mul_full_witness = @import("qm31_mul_full_witness.zig");
    pub const qm31_inv_witness = @import("qm31_inv_witness.zig");
    pub const linear_ops_witness = @import("linear_ops_witness.zig");
    pub const linear_ops = @import("linear_ops.zig");
    pub const qm31_inv = @import("qm31_inv.zig");
    pub const qm31_mul_add_v1 = @import("qm31_mul_add_v1.zig");
    pub const detached_arithmetic_fusion_plan = @import("detached_arithmetic_fusion_plan.zig");
    pub const detached_opening_accumulate4_v1 = @import("detached_opening_accumulate4_v1.zig");
    pub const detached_opening_accumulation_plan = @import("detached_opening_accumulation_plan.zig");
};
pub const Rows = struct {
    arena: std.heap.ArenaAllocator,
    opening: []air.detached_opening_accumulate4_v1.Row,
    multiply: []air.qm31_mul_add_v1.Row,
    inverse: []air.qm31_inv.Row,
    linear: []air.linear_ops.Row,
    dot4_matches: usize,
    fma_matches: usize,
    pub fn deinit(self: *Rows) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
pub fn materialize(a: std.mem.Allocator, plan: *const lowering.Plan, reference: lowering.Reference, evaluations: lowering.Evaluations, kind: lowering.ProofKind) !Rows {
    const mode: lowering.Mode = switch (kind) {
        .segment_leaf => .segment,
        .binary_node => .binary,
        else => return error.UnsupportedArithmeticFusionKind,
    };
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temporary = arena.allocator();
    var dot4_count: usize = 0;
    var fma_count: usize = 0;
    const counts = plan.counts(kind);
    const mul = air.qm31_mul_full_witness;
    const inv = air.qm31_inv_witness;
    const lin = air.linear_ops_witness;
    const buffers = lowering.InvocationBuffers{ .multiply = try temporary.alloc(mul.Invocation, counts.multiply), .inverse = try temporary.alloc(inv.Invocation, counts.inverse), .linear = try temporary.alloc(lin.Invocation, counts.linear) };
    try plan.materializeInto(reference, evaluations, kind, buffers);
    // The original admitted graph remains the routing authority. Only a
    // product with one consumer can disappear inside the fused arithmetic AIR.
    const fused = air.qm31_mul_add_v1;
    const fusion = air.detached_arithmetic_fusion_plan;
    const opening = air.detached_opening_accumulate4_v1;
    const opening_plan = air.detached_opening_accumulation_plan;
    var opening_rows: std.ArrayList(opening.Row) = .empty;
    var mul_rows: std.ArrayList(fused.Row) = .empty;
    var lin_rows: std.ArrayList([air.linear_ops.LOGICAL_INPUT_COUNT]M31) = .empty;
    var mul_cursor: usize = 0;
    var lin_cursor: usize = 0;
    for (reference.lanes, evaluations.lanes) |item, values| {
        if (item.active_in != mode) continue;
        var lane_scratch = std.heap.ArenaAllocator.init(temporary);
        defer lane_scratch.deinit();
        const scratch = lane_scratch.allocator();
        const uses = try scratch.alloc(u32, item.graph.nodes.len);
        _ = try lowering.computeLaneUseCountsInto(item, uses);
        const reserved = try scratch.alloc(bool, item.graph.nodes.len);
        @memset(reserved, false);
        var opening_matches: std.ArrayList(opening_plan.Match) = .empty;
        try opening_plan.reserve(&opening_matches, scratch, item.graph, uses, reserved);
        for (opening_matches.items) |match| {
            var lhs: [4]u32 = undefined;
            var rhs: [4]u32 = undefined;
            var lhs_values: [4]QM31 = undefined;
            var rhs_values: [4]QM31 = undefined;
            for (match.multiply_nodes, 0..) |node_id, index| {
                const operands = item.graph.nodes[node_id].op.mul;
                lhs[index] = operands.lhs;
                rhs[index] = operands.rhs;
                lhs_values[index] = values.values[operands.lhs];
                rhs_values[index] = values.values[operands.rhs];
            }
            try opening_rows.append(temporary, try opening.logicalRow(.{
                .circuit = item.circuit_id,
                .output = match.output_node,
                .uses = uses[match.output_node],
                .accumulator = match.accumulator_node,
                .lhs = lhs,
                .rhs = rhs,
            }, values.values[match.accumulator_node], lhs_values, rhs_values, values.values[match.output_node]));
        }
        var matches: std.ArrayList(fusion.Match) = .empty;
        try fusion.reserve(&matches, scratch, item.graph, uses, reserved);
        const by_multiply = try scratch.alloc(u32, item.graph.nodes.len);
        @memset(by_multiply, 0);
        for (matches.items, 0..) |match, index| by_multiply[match.multiply_node] = @intCast(index + 1);
        for (item.graph.nodes, 0..) |node, node_id| switch (node.op) {
            .mul => |operands| {
                const invocation = buffers.multiply[mul_cursor];
                mul_cursor += 1;
                const match: ?fusion.Match = if (by_multiply[node_id] == 0) null else matches.items[by_multiply[node_id] - 1];
                if (reserved[node_id] and match == null) continue;
                const output = if (match) |m| m.output_node else @as(u32, @intCast(node_id));
                try mul_rows.append(temporary, try fused.logicalRow(.{
                    .circuit = item.circuit_id,
                    .output = output,
                    .lhs = operands.lhs,
                    .rhs = operands.rhs,
                    .addend = if (match) |m| m.addend_node else 0,
                    .uses = uses[output],
                    .operation = if (match) |m| m.operation else .multiply,
                }, invocation.a, invocation.b, if (match) |m| values.values[m.addend_node] else QM31.zero()));
            },
            .add, .sub, .neg => {
                const invocation = buffers.linear[lin_cursor];
                const pp = plan.linear_rows[lin_cursor];
                lin_cursor += 1;
                if (!reserved[node_id]) try lin_rows.append(temporary, lin.logicalInputs(try lin.mainRow(invocation), lin.preprocessedRow(pp), kind));
            },
            else => {},
        };
        dot4_count += opening_matches.items.len;
        fma_count += matches.items.len;
    }
    if (mul_cursor != buffers.multiply.len or lin_cursor != buffers.linear.len) return error.DetachedParentArithmeticCountMismatch;
    const inv_rows = try temporary.alloc([air.qm31_inv.LOGICAL_INPUT_COUNT]M31, counts.inverse);
    for (inv_rows, buffers.inverse, plan.inverse_rows[0..counts.inverse]) |*row, invocation, pp| row.* = inv.logicalInputs(try inv.mainRow(invocation), inv.preprocessedRow(pp), kind);
    return .{ .arena = arena, .opening = try opening_rows.toOwnedSlice(temporary), .multiply = try mul_rows.toOwnedSlice(temporary), .inverse = inv_rows, .linear = try lin_rows.toOwnedSlice(temporary), .dot4_matches = dot4_count, .fma_matches = fma_count };
}
