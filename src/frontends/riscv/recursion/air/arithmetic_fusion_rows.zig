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
    allocator: std.mem.Allocator,
    opening: []air.detached_opening_accumulate4_v1.Row,
    multiply: []air.qm31_mul_add_v1.Row,
    inverse: []air.qm31_inv.Row,
    linear: []air.linear_ops.Row,
    dot4_matches: usize,
    fma_matches: usize,
    pub fn deinit(self: *Rows) void {
        self.allocator.free(self.opening);
        self.allocator.free(self.multiply);
        self.allocator.free(self.inverse);
        self.allocator.free(self.linear);
        self.* = undefined;
    }
};
const Direct = @import("blake3_direct_cohort_columns_v1.zig");
const FixedColumns = @import("arithmetic_fusion_fixed_columns_v1.zig");
pub const Fixed = FixedColumns.Fixed;
const Stats = struct { dot4_matches: usize, fma_matches: usize };
const RowSink = struct {
    pub const NEEDS_ROWS = true;
    a: std.mem.Allocator,
    open: std.ArrayList(air.detached_opening_accumulate4_v1.Row) = .empty,
    mul: std.ArrayList(air.qm31_mul_add_v1.Row) = .empty,
    inv: std.ArrayList(air.qm31_inv.Row) = .empty,
    lin: std.ArrayList(air.linear_ops.Row) = .empty,
    fn deinit(self: *@This()) void {
        self.open.deinit(self.a);
        self.mul.deinit(self.a);
        self.inv.deinit(self.a);
        self.lin.deinit(self.a);
    }
    fn opening(self: *@This(), row: air.detached_opening_accumulate4_v1.Row) !void {
        try self.open.append(self.a, row);
    }
    fn multiply(self: *@This(), row: air.qm31_mul_add_v1.Row) !void {
        try self.mul.append(self.a, row);
    }
    fn inverse(self: *@This(), row: air.qm31_inv.Row) !void {
        try self.inv.append(self.a, row);
    }
    fn linear(self: *@This(), row: air.linear_ops.Row) !void {
        try self.lin.append(self.a, row);
    }
    fn take(self: *@This(), stats: Stats) !Rows {
        const opening_rows = try self.open.toOwnedSlice(self.a);
        errdefer self.a.free(opening_rows);
        const multiply_rows = try self.mul.toOwnedSlice(self.a);
        errdefer self.a.free(multiply_rows);
        const inverse_rows = try self.inv.toOwnedSlice(self.a);
        errdefer self.a.free(inverse_rows);
        const linear_rows = try self.lin.toOwnedSlice(self.a);
        return .{ .allocator = self.a, .opening = opening_rows, .multiply = multiply_rows, .inverse = inverse_rows, .linear = linear_rows, .dot4_matches = stats.dot4_matches, .fma_matches = stats.fma_matches };
    }
};
pub fn materialize(a: std.mem.Allocator, plan: *const lowering.Plan, reference: lowering.Reference, evaluations: lowering.Evaluations, kind: lowering.ProofKind) !Rows {
    var sink = RowSink{ .a = a };
    defer sink.deinit();
    const stats = try emit(a, plan, reference, evaluations, kind, &sink);
    return sink.take(stats);
}
const Counts = struct {
    pub const NEEDS_ROWS = false;
    open: usize = 0,
    mul: usize = 0,
    inv: usize = 0,
    lin: usize = 0,
    fn opening(self: *@This(), _: air.detached_opening_accumulate4_v1.Row) !void {
        self.open = try std.math.add(usize, self.open, 1);
    }
    fn multiply(self: *@This(), _: air.qm31_mul_add_v1.Row) !void {
        self.mul = try std.math.add(usize, self.mul, 1);
    }
    fn inverse(self: *@This(), _: air.qm31_inv.Row) !void {
        self.inv = try std.math.add(usize, self.inv, 1);
    }
    fn linear(self: *@This(), _: air.linear_ops.Row) !void {
        self.lin = try std.math.add(usize, self.lin, 1);
    }
};
pub const Columns = struct {
    allocator: std.mem.Allocator,
    // Native PCS contraction still requires these exact dot4 row sources.
    opening: []air.detached_opening_accumulate4_v1.Row,
    multiply: Direct.ForAir(air.qm31_mul_add_v1),
    inverse: Direct.ForAir(air.qm31_inv),
    linear: Direct.ForAir(air.linear_ops),
    dot4_matches: usize,
    fma_matches: usize,
    pub fn deinit(self: *Columns) void {
        self.allocator.free(self.opening);
        self.multiply.deinit();
        self.inverse.deinit();
        self.linear.deinit();
        self.* = undefined;
    }
};
const ColumnSink = struct {
    pub const NEEDS_ROWS = true;
    a: std.mem.Allocator,
    open: std.ArrayList(air.detached_opening_accumulate4_v1.Row),
    mul: Direct.ForAir(air.qm31_mul_add_v1),
    inv: Direct.ForAir(air.qm31_inv),
    lin: Direct.ForAir(air.linear_ops),
    fn init(a: std.mem.Allocator, counts: Counts) !@This() {
        var open = try std.ArrayList(air.detached_opening_accumulate4_v1.Row).initCapacity(a, counts.open);
        errdefer open.deinit(a);
        var mul = try Direct.ForAir(air.qm31_mul_add_v1).init(a, counts.mul);
        errdefer mul.deinit();
        var inv = try Direct.ForAir(air.qm31_inv).init(a, counts.inv);
        errdefer inv.deinit();
        const lin = try Direct.ForAir(air.linear_ops).init(a, counts.lin);
        return .{ .a = a, .open = open, .mul = mul, .inv = inv, .lin = lin };
    }
    fn deinit(self: *@This()) void {
        self.open.deinit(self.a);
        self.mul.deinit();
        self.inv.deinit();
        self.lin.deinit();
    }
    fn opening(self: *@This(), row: air.detached_opening_accumulate4_v1.Row) !void {
        try self.open.append(self.a, row);
    }
    fn multiply(self: *@This(), row: air.qm31_mul_add_v1.Row) !void {
        try self.mul.append(row);
    }
    fn inverse(self: *@This(), row: air.qm31_inv.Row) !void {
        try self.inv.append(row);
    }
    fn linear(self: *@This(), row: air.linear_ops.Row) !void {
        try self.lin.append(row);
    }
    fn take(self: *@This(), counts: Counts, stats: Stats) !Columns {
        if (self.open.items.len != counts.open) return error.DirectRecursiveRowCountMismatch;
        try self.mul.requireFinished();
        try self.inv.requireFinished();
        try self.lin.requireFinished();
        const opening_rows = try self.open.toOwnedSlice(self.a);
        const result = Columns{ .allocator = self.a, .opening = opening_rows, .multiply = self.mul, .inverse = self.inv, .linear = self.lin, .dot4_matches = stats.dot4_matches, .fma_matches = stats.fma_matches };
        self.mul.main = &.{};
        self.mul.fixed = &.{};
        self.mul.mutable_main = @splat(&.{});
        self.inv.main = &.{};
        self.inv.fixed = &.{};
        self.inv.mutable_main = @splat(&.{});
        self.lin.main = &.{};
        self.lin.fixed = &.{};
        self.lin.mutable_main = @splat(&.{});
        return result;
    }
};
/// Same authenticated typed emission as legacy materialization, with exact
/// count-admitted final columns for multiply/inverse/linear. Count planning does
/// not materialize invocation buffers or arithmetic witness row rosters.
pub fn materializeColumns(a: std.mem.Allocator, plan: *const lowering.Plan, reference: lowering.Reference, evaluations: lowering.Evaluations, kind: lowering.ProofKind) !Columns {
    var counts = Counts{};
    _ = try emit(a, plan, reference, evaluations, kind, &counts);
    var sink = try ColumnSink.init(a, counts);
    defer sink.deinit();
    const stats = try emit(a, plan, reference, evaluations, kind, &sink);
    return sink.take(counts, stats);
}
/// Fresh receivers reconstruct the original fixed schedule from graph authority
/// alone, using the same dot4/FMA reservation and routing as the producer.
pub fn materializeFixed(a: std.mem.Allocator, plan: *const lowering.Plan, reference: lowering.Reference, kind: lowering.ProofKind) !Fixed {
    var counts = Counts{};
    _ = try emit(a, plan, reference, null, kind, &counts);
    var sink = try FixedColumns.Sink.init(a, .{ counts.open, counts.mul, counts.inv, counts.lin });
    defer sink.deinit();
    const stats = try emit(a, plan, reference, null, kind, &sink);
    return sink.take(stats);
}
/// Metadata-only ORIGINAL selected-lane identifier emission. MAIN circuit IDs
/// are emitted by the actual same reservation walk, not inferred from inactive
/// AIR gates or read from a private witness. No arithmetic values are required.
pub const Identifiers = struct {
    allocator: std.mem.Allocator,
    lease: ?*@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    inverse: []u32,
    linear: []u32,
    pub fn deinit(self: *Identifiers) void {
        const lease = self.lease;
        self.allocator.free(self.inverse);
        self.allocator.free(self.linear);
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
};
const IdentifierSink = struct {
    pub const NEEDS_ROWS = false;
    a: std.mem.Allocator,
    inverse_ids: std.ArrayList(u32) = .empty,
    linear_ids: std.ArrayList(u32) = .empty,
    inverse_rows: usize = 0,
    linear_rows: usize = 0,
    fn deinit(self: *@This()) void {
        self.inverse_ids.deinit(self.a);
        self.linear_ids.deinit(self.a);
    }
    fn opening(_: *@This(), _: air.detached_opening_accumulate4_v1.Row) !void {}
    fn multiply(_: *@This(), _: air.qm31_mul_add_v1.Row) !void {}
    fn inverse(self: *@This(), _: air.qm31_inv.Row) !void {
        self.inverse_rows = try std.math.add(usize, self.inverse_rows, 1);
    }
    fn linear(self: *@This(), _: air.linear_ops.Row) !void {
        self.linear_rows = try std.math.add(usize, self.linear_rows, 1);
    }
    fn inverseIdentifier(self: *@This(), id: u32) !void {
        try self.inverse_ids.append(self.a, id);
    }
    fn linearIdentifier(self: *@This(), id: u32) !void {
        try self.linear_ids.append(self.a, id);
    }
};
pub fn materializeIdentifiers(a: std.mem.Allocator, plan: *const lowering.Plan, reference: lowering.Reference, kind: lowering.ProofKind) !Identifiers {
    // This is a cold independently reconstructed setup boundary, not the live
    // hot path's self-digest check. A resealed mutated Plan is not authority.
    try plan.validateAgainstAuthority(a, reference);
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
    errdefer if (lease) |owner| owner.destroy();
    var sink = IdentifierSink{ .a = a };
    defer sink.deinit();
    _ = try emit(a, plan, reference, null, kind, &sink);
    if (sink.inverse_rows != sink.inverse_ids.items.len or sink.linear_rows != sink.linear_ids.items.len) return error.DetachedParentArithmeticCountMismatch;
    const inverse = try sink.inverse_ids.toOwnedSlice(a);
    errdefer a.free(inverse);
    return .{ .allocator = a, .lease = lease, .inverse = inverse, .linear = try sink.linear_ids.toOwnedSlice(a) };
}
fn fixedLogicalRow(comptime Air: type, fixed: @import("blake3_parent_row_storage.zig").FixedRow(Air)) Air.Row {
    var row: Air.Row = @splat(M31.zero());
    row[Air.PHYSICAL_MAIN_COLUMN_COUNT..].* = fixed;
    return row;
}
fn emit(a: std.mem.Allocator, plan: *const lowering.Plan, reference: lowering.Reference, evaluations: ?lowering.Evaluations, kind: lowering.ProofKind, sink: anytype) !Stats {
    const needs_rows = @TypeOf(sink.*).NEEDS_ROWS;
    const needs_fixed = if (@hasDecl(@TypeOf(sink.*), "NEEDS_FIXED")) @TypeOf(sink.*).NEEDS_FIXED else false;
    const mode: lowering.Mode = switch (kind) {
        .segment_leaf => .segment,
        .binary_node => .binary,
        else => return error.UnsupportedArithmeticFusionKind,
    };

    var dot4_count: usize = 0;
    var fma_count: usize = 0;
    const counts = plan.counts(kind);
    const mul = air.qm31_mul_full_witness;
    const inv = air.qm31_inv_witness;
    const lin = air.linear_ops_witness;
    try plan.validateAgainst(reference);
    if (needs_rows) try (evaluations orelse return error.MissingArithmeticFusionEvaluations).validateAgainst(reference);
    const multiply = try a.alloc(mul.Invocation, if (needs_rows) counts.multiply else 0);
    defer a.free(multiply);
    const inverse = try a.alloc(inv.Invocation, if (needs_rows) counts.inverse else 0);
    defer a.free(inverse);
    const linear = try a.alloc(lin.Invocation, if (needs_rows) counts.linear else 0);
    defer a.free(linear);
    const buffers = lowering.InvocationBuffers{ .multiply = multiply, .inverse = inverse, .linear = linear };
    if (needs_rows) try plan.materializeInto(reference, evaluations.?, kind, buffers);
    // The original admitted graph remains the routing authority. Only a
    // product with one consumer can disappear inside the fused arithmetic AIR.
    const fused = air.qm31_mul_add_v1;
    const fusion = air.detached_arithmetic_fusion_plan;
    const opening = air.detached_opening_accumulate4_v1;
    const opening_plan = air.detached_opening_accumulation_plan;
    var mul_cursor: usize = 0;
    var lin_cursor: usize = 0;
    for (reference.lanes, 0..) |item, lane_index| {
        if (item.active_in != mode) continue;
        const values = if (needs_rows) evaluations.?.lanes[lane_index] else undefined;
        var lane_scratch = std.heap.ArenaAllocator.init(a);
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
                if (needs_rows) {
                    lhs_values[index] = values.values[operands.lhs];
                    rhs_values[index] = values.values[operands.rhs];
                }
            }
            const schedule = opening.Schedule{
                .circuit = item.circuit_id,
                .output = match.output_node,
                .uses = uses[match.output_node],
                .accumulator = match.accumulator_node,
                .lhs = lhs,
                .rhs = rhs,
            };
            try sink.opening(if (needs_rows)
                try opening.logicalRow(schedule, values.values[match.accumulator_node], lhs_values, rhs_values, values.values[match.output_node])
            else if (needs_fixed) fixedLogicalRow(opening, try opening.fixedRow(schedule)) else undefined);
        }
        var matches: std.ArrayList(fusion.Match) = .empty;
        try fusion.reserve(&matches, scratch, item.graph, uses, reserved);
        const by_multiply = try scratch.alloc(u32, item.graph.nodes.len);
        @memset(by_multiply, 0);
        for (matches.items, 0..) |match, index| by_multiply[match.multiply_node] = @intCast(index + 1);
        for (item.graph.nodes, 0..) |node, node_id| switch (node.op) {
            .mul => |operands| {
                const invocation = if (needs_rows) buffers.multiply[mul_cursor] else undefined;
                mul_cursor += 1;
                const match: ?fusion.Match = if (by_multiply[node_id] == 0) null else matches.items[by_multiply[node_id] - 1];
                if (reserved[node_id] and match == null) continue;
                const output = if (match) |m| m.output_node else @as(u32, @intCast(node_id));
                const schedule = fused.Schedule{
                    .circuit = item.circuit_id,
                    .output = output,
                    .lhs = operands.lhs,
                    .rhs = operands.rhs,
                    .addend = if (match) |m| m.addend_node else 0,
                    .uses = uses[output],
                    .operation = if (match) |m| m.operation else .multiply,
                };
                try sink.multiply(if (needs_rows)
                    try fused.logicalRow(schedule, invocation.a, invocation.b, if (match) |m| values.values[m.addend_node] else QM31.zero())
                else if (needs_fixed) fixedLogicalRow(fused, try fused.fixedRow(schedule)) else undefined);
            },
            .add, .sub, .neg => {
                const invocation = if (needs_rows) buffers.linear[lin_cursor] else undefined;
                const pp = if (needs_rows or needs_fixed) plan.linear_rows[lin_cursor] else undefined;
                lin_cursor += 1;
                if (!reserved[node_id]) {
                    if (@hasDecl(@TypeOf(sink.*), "linearIdentifier")) try sink.linearIdentifier(item.circuit_id);
                    try sink.linear(if (needs_rows)
                        lin.logicalInputs(try lin.mainRow(invocation), lin.preprocessedRow(pp), kind)
                    else if (needs_fixed) lin.logicalInputs(@splat(M31.zero()), lin.preprocessedRow(pp), kind) else undefined);
                }
            },
            .inverse => if (@hasDecl(@TypeOf(sink.*), "inverseIdentifier")) try sink.inverseIdentifier(item.circuit_id),
            else => {},
        };
        dot4_count += opening_matches.items.len;
        fma_count += matches.items.len;
    }
    if (mul_cursor != counts.multiply or lin_cursor != counts.linear) return error.DetachedParentArithmeticCountMismatch;
    for (0..counts.inverse) |i| try sink.inverse(if (needs_rows)
        inv.logicalInputs(try inv.mainRow(buffers.inverse[i]), inv.preprocessedRow(plan.inverse_rows[i]), kind)
    else if (needs_fixed) inv.logicalInputs(@splat(M31.zero()), inv.preprocessedRow(plan.inverse_rows[i]), kind) else undefined);
    return .{ .dot4_matches = dot4_count, .fma_matches = fma_count };
}
