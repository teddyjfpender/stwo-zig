const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
const graph = @import("composition_circuit.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const rows = @import("arithmetic_fusion_rows.zig");
test "quotient lowering validates hidden values and releases failed allocations" {
    const a = std.testing.allocator;
    const nodes = [_]graph.Node{
        .{ .op = .input },            .{ .op = .input },                              .{ .op = .input },
        .{ .op = .{ .inverse = 0 } }, .{ .op = .{ .mul = .{ .lhs = 3, .rhs = 1 } } }, .{ .op = .{ .add = .{ .lhs = 4, .rhs = 2 } } },
    };
    const outputs = [_]u32{5};
    const g = try graph.CircuitGraph.authenticate(&nodes, &outputs, graph.computeGraphDigest(&nodes, &outputs));
    const lanes = [_]lower.Lane{
        .{ .circuit_id = 1502, .active_in = .segment, .circuit_identity = g.identity_digest, .graph = g },
        .{ .circuit_id = 1503, .active_in = .binary, .circuit_identity = g.identity_digest, .graph = g },
    };
    const reference = try lower.Reference.seal(&lanes);
    var plan = try lower.Plan.init(a, reference);
    defer plan.deinit();
    var values: [6]Q = undefined;
    values[0] = Q.fromU32Unchecked(3, 5, 7, 11);
    values[1] = Q.fromU32Unchecked(13, 17, 19, 23);
    values[3] = try values[0].inv();
    values[4] = values[3].mul(values[1]);
    values[2] = values[4].neg();
    values[5] = Q.zero();
    const evals = [_]lower.Evaluation{ .{ .circuit_identity = g.identity_digest, .values = &values }, .{ .circuit_identity = g.identity_digest, .values = &values } };
    const evaluations = lower.Evaluations{ .lanes = &evals };
    var ordinary = try rows.materialize(a, &plan, reference, evaluations, .segment_leaf);
    defer ordinary.deinit();
    try std.testing.expectEqual(@as(usize, 0), ordinary.quotient.len);
    try std.testing.expectEqual(@as(usize, 1), ordinary.inverse.len);
    try std.testing.expectEqual(@as(usize, 1), ordinary.multiply.len);
    var fused = try rows.materializeNative(a, &plan, reference, evaluations, .segment_leaf);
    defer fused.deinit();
    try std.testing.expectEqual(@as(usize, 1), fused.quotient.len);
    try std.testing.expectEqual(@as(usize, 0), fused.inverse.len + fused.multiply.len + fused.linear.len);
    for ([_]usize{ 3, 4, 5 }) |index| {
        const saved = values[index];
        values[index] = saved.add(Q.one());
        try std.testing.expectError(error.InvalidQuotientEvaluation, rows.materializeNative(a, &plan, reference, evaluations, .segment_leaf));
        values[index] = saved;
    }
    const Case = struct {
        fn run(allocator: std.mem.Allocator, p: *const lower.Plan, r: lower.Reference, e: lower.Evaluations) !void {
            var result = try rows.materializeNative(allocator, p, r, e, .segment_leaf);
            defer result.deinit();
            try std.testing.expectEqual(@as(usize, 1), result.quotient.len);
        }
    };
    try std.testing.checkAllAllocationFailures(a, Case.run, .{ &plan, reference, evaluations });
}
