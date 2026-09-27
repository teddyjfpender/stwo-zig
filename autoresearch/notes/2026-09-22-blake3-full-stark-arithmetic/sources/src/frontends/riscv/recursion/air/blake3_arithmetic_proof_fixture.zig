//! Existing production FRI arithmetic AIRs committed under BLAKE3.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const mul = @import("qm31_mul_full.zig");
const inv = @import("qm31_inv.zig");
const linear = @import("linear_ops.zig");
const MW = @import("qm31_mul_full_witness.zig");
const IW = @import("qm31_inv_witness.zig");
const LW = @import("linear_ops_witness.zig");
const F = @import("blake3_fixture_roster.zig").WithExtras(.{ mul, inv, linear });
const selectors = @import("proof_kind.zig").ProofKind.segment_leaf.selectors();
pub const Graph = @import("composition_circuit.zig").CircuitGraph;
pub fn check(a: std.mem.Allocator, graph: Graph, values: []const f.QM31) !void {
    return checkMany(a, &.{graph}, &.{values});
}
pub fn checkMany(a: std.mem.Allocator, graphs: []const Graph, values: []const []const f.QM31) !void {
    if (graphs.len == 0 or graphs.len != values.len) return error.InvalidArithmeticFixture;
    const lanes = try a.alloc(lower.Lane, graphs.len * 2);
    const evaluations = try a.alloc(lower.Evaluation, lanes.len);
    for (graphs, values, 0..) |graph, evaluated, i| {
        lanes[2 * i] = .{ .circuit_id = @intCast(1500 + 2 * i), .active_in = .segment, .circuit_identity = graph.identity_digest, .graph = graph };
        lanes[2 * i + 1] = lanes[2 * i];
        lanes[2 * i + 1].circuit_id += 1;
        lanes[2 * i + 1].active_in = .binary;
        evaluations[2 * i] = .{ .circuit_identity = graph.identity_digest, .values = evaluated };
        evaluations[2 * i + 1] = evaluations[2 * i];
    }
    const reference = try lower.Reference.seal(lanes);
    var plan = try lower.Plan.init(a, reference);
    defer plan.deinit();
    const counts = plan.counts(.segment_leaf);
    const buffers = lower.InvocationBuffers{ .multiply = try a.alloc(MW.Invocation, counts.multiply), .inverse = try a.alloc(IW.Invocation, counts.inverse), .linear = try a.alloc(LW.Invocation, counts.linear) };
    try plan.materializeInto(reference, .{ .lanes = evaluations }, .segment_leaf, buffers);
    const mrows = try a.alloc(mul.Row, counts.multiply);
    const irows = try a.alloc(inv.Row, counts.inverse);
    const lrows = try a.alloc(linear.Row, counts.linear);
    for (mrows, buffers.multiply, plan.multiply_rows) |*row, invocation, fixed| row.* = MW.logicalInputs(MW.mainRow(invocation), MW.preprocessedRow(fixed), .segment_leaf);
    for (irows, buffers.inverse, plan.inverse_rows) |*row, invocation, fixed| row.* = IW.logicalInputs(try IW.mainRow(invocation), IW.preprocessedRow(fixed), .segment_leaf);
    for (lrows, buffers.linear, plan.linear_rows) |*row, invocation, fixed| row.* = LW.logicalInputs(try LW.mainRow(invocation), LW.preprocessedRow(fixed), .segment_leaf);
    var boundaries: std.ArrayList(f.boundary.Row) = .empty;
    for (graphs, values, 0..) |graph, evaluated, i| {
        const uses = try lower.computeUseCountsInto(graph, try a.alloc(u32, graph.nodes.len));
        for (graph.nodes, 0..) |node, id| if (node.op == .input) {
            try boundaries.append(a, try f.boundary.logicalCoordinates(lanes[2 * i].circuit_id, @intCast(id), f.M31.fromCanonical(uses[id]), evaluated[id].toM31Array()));
        };
    }
    for (plan.public_terms) |term| if (term.active_in == .segment) {
        const weight = f.M31.fromCanonical(term.multiplicity);
        try boundaries.append(a, try f.boundary.logicalCoordinates(term.circuit_id, term.node_id, if (term.role == .emit) weight else weight.neg(), term.value.toM31Array()));
    };
    const logs = [6]u32{ 1, 1, log(boundaries.items.len), log(mrows.len), log(irows.len), log(lrows.len) };
    const rows = .{ try f.padded(f.g, a, &.{}, logs[0]), try f.padded(f.xor, a, &.{}, logs[1]), try f.padded(f.boundary, a, boundaries.items, logs[2]), try padded(mul, a, mrows, logs[3]), try padded(inv, a, irows, logs[4]), try padded(linear, a, lrows, logs[5]) };
    // Reconstruct operation preprocessing solely from the admitted lowering plan.
    const trusted_m = try a.alloc(mul.Row, mrows.len);
    const trusted_i = try a.alloc(inv.Row, irows.len);
    const trusted_l = try a.alloc(linear.Row, lrows.len);
    for (trusted_m, plan.multiply_rows) |*row, fixed| row.* = MW.logicalInputs(@splat(f.M31.zero()), MW.preprocessedRow(fixed), .segment_leaf);
    for (trusted_i, plan.inverse_rows) |*row, fixed| row.* = IW.logicalInputs(@splat(f.M31.zero()), IW.preprocessedRow(fixed), .segment_leaf);
    for (trusted_l, plan.linear_rows) |*row, fixed| row.* = LW.logicalInputs(@splat(f.M31.zero()), LW.preprocessedRow(fixed), .segment_leaf);
    const trusted_rows = .{ rows[0], rows[1], boundaries.items, trusted_m, trusted_i, trusted_l };
    const trusted = try preprocessing(a, trusted_rows, logs);
    boundaries.items[0][8] = boundaries.items[0][8].add(f.M31.one());
    const false_pp = try preprocessing(a, trusted_rows, logs);
    try @import("blake3_proof_gate_test_support.zig").runForParameters(F, a, rows, logs, trusted, false_pp, .{ .{}, .{}, .{}, selectors, selectors, selectors });
}
fn log(n: usize) u32 {
    return if (n <= 1) 1 else std.math.log2_int_ceil(usize, n);
}
fn padded(comptime Air: type, a: std.mem.Allocator, rows: []const Air.Row, size: u32) ![]Air.Row {
    const result = try f.padded(Air, a, rows, size);
    for (result) |*row| row[Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT ..].* = selectors;
    return result;
}
fn preprocessing(a: std.mem.Allocator, rows: anytype, logs: [6]u32) ![]f.Column {
    var columns: std.ArrayList(f.Column) = .empty;
    inline for (F.Airs, 0..) |Air, i| try f.project(Air, a, rows[i], logs[i], 0, &columns);
    for (f.kinds) |kind| try f.tablePreprocessed(a, kind, &columns);
    return columns.toOwnedSlice(a);
}
