const std = @import("std");
const runtime_mod = @import("../runtime.zig");
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const circle_poly = @import("stwo_prover_engine").poly.circle.poly;

const M31 = m31.M31;
const QM31 = qm31.QM31;

const EvalPlan = struct {
    coeff_log_size: u32,
    normalized_points: []const circle.CirclePointQM31,
    flat_factors: []const QM31,
    column_indices: std.ArrayList(usize),
};

const EvalTreePlan = struct {
    coefficients: []const circle_poly.CircleCoefficients,
    tree_values: []const []QM31,
    plans: []const EvalPlan,
};

test "metal: polynomial evaluation shader unit matches scalar circle evaluation" {
    const allocator = std.testing.allocator;
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();

    const first_coefficients = [_]M31{
        M31.fromCanonical(3),
        M31.fromCanonical(5),
        M31.fromCanonical(8),
        M31.fromCanonical(13),
        M31.fromCanonical(21),
        M31.fromCanonical(34),
        M31.fromCanonical(55),
        M31.fromCanonical(89),
    };
    const second_coefficients = [_]M31{
        M31.fromCanonical(144),
        M31.fromCanonical(233),
        M31.fromCanonical(377),
        M31.fromCanonical(610),
        M31.fromCanonical(987),
        M31.fromCanonical(1597),
        M31.fromCanonical(2584),
        M31.fromCanonical(4181),
    };
    const coefficients = [_]circle_poly.CircleCoefficients{
        try circle_poly.CircleCoefficients.initBorrowed(&first_coefficients),
        try circle_poly.CircleCoefficients.initBorrowed(&second_coefficients),
    };
    const points = [_]circle.CirclePointQM31{
        circle.SECURE_FIELD_CIRCLE_GEN.mul(17),
        circle.SECURE_FIELD_CIRCLE_GEN.mul(29),
    };
    var factors: [points.len * 3]QM31 = undefined;
    circle_poly.fillEvalFactorsForPointsFolded(&points, 0, 3, &factors);

    var column_indices = std.ArrayList(usize).empty;
    defer column_indices.deinit(allocator);
    try column_indices.appendSlice(allocator, &.{ 0, 1 });
    const plans = [_]EvalPlan{.{
        .coeff_log_size = 3,
        .normalized_points = &points,
        .flat_factors = &factors,
        .column_indices = column_indices,
    }};
    var first_output: [points.len]QM31 = undefined;
    var second_output: [points.len]QM31 = undefined;
    const outputs = [_][]QM31{ &first_output, &second_output };

    const result = try runtime.evaluateCoefficientPlans(
        allocator,
        &coefficients,
        &outputs,
        &plans,
    );
    try result.execution.validate();
    try std.testing.expectEqual(@as(u64, 1), result.execution.plan_count);
    try std.testing.expectEqual(@as(u64, 2), result.execution.basis_task_count);
    try std.testing.expectEqual(@as(u64, 4), result.execution.evaluation_task_count);
    try std.testing.expectEqual(
        @as(u64, 32),
        result.execution.evaluation_coefficient_terms,
    );
    try std.testing.expect(result.execution.basis_threadgroup_width > 0);
    try std.testing.expect(result.execution.evaluation_threadgroup_width > 0);

    for (coefficients, outputs) |polynomial, output| {
        for (points, output) |point, actual| {
            try std.testing.expect(polynomial.evalAtPoint(point).eql(actual));
        }
    }
}

test "metal: polynomial evaluation batches tree-local indices in one epoch" {
    const allocator = std.testing.allocator;
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();

    const coefficient_values = [_][8]M31{
        .{ .{ .v = 3 }, .{ .v = 5 }, .{ .v = 8 }, .{ .v = 13 }, .{ .v = 21 }, .{ .v = 34 }, .{ .v = 55 }, .{ .v = 89 } },
        .{ .{ .v = 144 }, .{ .v = 233 }, .{ .v = 377 }, .{ .v = 610 }, .{ .v = 987 }, .{ .v = 1597 }, .{ .v = 2584 }, .{ .v = 4181 } },
    };
    const coefficients = [_]circle_poly.CircleCoefficients{
        try circle_poly.CircleCoefficients.initBorrowed(&coefficient_values[0]),
        try circle_poly.CircleCoefficients.initBorrowed(&coefficient_values[1]),
    };
    const points = [_]circle.CirclePointQM31{
        circle.SECURE_FIELD_CIRCLE_GEN.mul(17),
        circle.SECURE_FIELD_CIRCLE_GEN.mul(29),
    };
    var factors: [points.len * 3]QM31 = undefined;
    circle_poly.fillEvalFactorsForPointsFolded(&points, 0, 3, &factors);

    var first_indices = std.ArrayList(usize).empty;
    defer first_indices.deinit(allocator);
    try first_indices.append(allocator, 0);
    var second_indices = std.ArrayList(usize).empty;
    defer second_indices.deinit(allocator);
    try second_indices.append(allocator, 0);
    const first_plans = [_]EvalPlan{.{
        .coeff_log_size = 3,
        .normalized_points = &points,
        .flat_factors = &factors,
        .column_indices = first_indices,
    }};
    const second_plans = [_]EvalPlan{.{
        .coeff_log_size = 3,
        .normalized_points = &points,
        .flat_factors = &factors,
        .column_indices = second_indices,
    }};
    var first_output: [points.len]QM31 = undefined;
    var second_output: [points.len]QM31 = undefined;
    const first_outputs = [_][]QM31{&first_output};
    const second_outputs = [_][]QM31{&second_output};
    const tree_plans = [_]EvalTreePlan{
        .{ .coefficients = coefficients[0..1], .tree_values = &first_outputs, .plans = &first_plans },
        .{ .coefficients = coefficients[1..2], .tree_values = &second_outputs, .plans = &second_plans },
    };

    const result = try runtime.evaluateCoefficientTreePlans(allocator, &tree_plans);
    try result.execution.validate();
    try std.testing.expectEqual(@as(u64, 2), result.execution.plan_count);
    try std.testing.expectEqual(@as(u64, 4), result.execution.basis_task_count);
    try std.testing.expectEqual(@as(u64, 4), result.execution.evaluation_task_count);
    try std.testing.expectEqual(
        @as(u64, 32),
        result.execution.evaluation_coefficient_terms,
    );

    for (coefficients, tree_plans) |polynomial, tree_plan| {
        for (points, tree_plan.tree_values[0]) |point, actual| {
            try std.testing.expect(polynomial.evalAtPoint(point).eql(actual));
        }
    }
}
