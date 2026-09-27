const std = @import("std");
const runtime_mod = @import("../runtime.zig");
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const circle_poly = @import("stwo_prover_engine").poly.circle.poly;
const circle_evaluation = @import("stwo_prover_engine").poly.circle.evaluation;
const sampled_plans = @import("stwo_prover_engine").pcs.sampled_coefficient_plans;
const prover_api = @import("stwo_prover_api");
const canonic = @import("stwo_core").poly.circle.canonic;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const metal_merkle = @import("../merkle_tree.zig");

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

test "metal: resident barycentric epoch matches CPU across trees and points" {
    const allocator = std.testing.allocator;
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();

    const log_size: u32 = 4;
    var first_values: [1 << log_size]M31 = undefined;
    var second_values: [1 << log_size]M31 = undefined;
    var third_values: [1 << log_size]M31 = undefined;
    for (0..first_values.len) |index| {
        first_values[index] = M31.fromCanonical(@intCast(index * 3 + 1));
        second_values[index] = M31.fromCanonical(@intCast(index * 5 + 2));
        third_values[index] = M31.fromCanonical(@intCast(index * 7 + 3));
    }
    const first_slices = [_][]const M31{ &first_values, &second_values };
    const second_slices = [_][]const M31{&third_values};
    const Hasher = blake2_merkle.Blake2sMerkleHasher;
    var first_tree = try metal_merkle.MetalMerkleTree(Hasher).commit(
        &runtime,
        allocator,
        &first_slices,
    );
    defer first_tree.deinit(allocator);
    var second_tree = try metal_merkle.MetalMerkleTree(Hasher).commit(
        &runtime,
        allocator,
        &second_slices,
    );
    defer second_tree.deinit(allocator);

    const first_columns = [_]prover_api.ColumnEvaluation{
        .{ .log_size = log_size, .values = &first_values },
        .{ .log_size = log_size, .values = &second_values },
    };
    const second_columns = [_]prover_api.ColumnEvaluation{
        .{ .log_size = log_size, .values = &third_values },
    };
    var points = [_]circle.CirclePointQM31{
        circle.SECURE_FIELD_CIRCLE_GEN.mul(17),
        circle.SECURE_FIELD_CIRCLE_GEN.mul(29),
    };
    var first_indices = std.ArrayList(usize).empty;
    defer first_indices.deinit(allocator);
    try first_indices.appendSlice(allocator, &.{ 0, 1 });
    var second_indices = std.ArrayList(usize).empty;
    defer second_indices.deinit(allocator);
    try second_indices.append(allocator, 0);
    const first_plan = [_]sampled_plans.BarycentricEvalPlan{.{
        .log_size = log_size,
        .fold_count = 0,
        .raw_points = &points,
        .normalized_points = &points,
        .column_indices = first_indices,
        .next_same_hash = null,
    }};
    const second_plan = [_]sampled_plans.BarycentricEvalPlan{.{
        .log_size = log_size,
        .fold_count = 0,
        .raw_points = &points,
        .normalized_points = &points,
        .column_indices = second_indices,
        .next_same_hash = null,
    }};
    var first_output_a: [points.len]QM31 = undefined;
    var first_output_b: [points.len]QM31 = undefined;
    var second_output: [points.len]QM31 = undefined;
    var first_outputs = [_][]QM31{ &first_output_a, &first_output_b };
    var second_outputs = [_][]QM31{&second_output};
    const tree_plans = [_]sampled_plans.BarycentricEvalTreePlan{
        .{
            .columns = &first_columns,
            .tree_values = &first_outputs,
            .plans = &first_plan,
            .resident_tree = first_tree.quotientResidencyHandle().?,
        },
        .{
            .columns = &second_columns,
            .tree_values = &second_outputs,
            .plans = &second_plan,
            .resident_tree = second_tree.quotientResidencyHandle().?,
        },
    };

    const result = try runtime.evaluateBarycentricTreePlans(
        allocator,
        &tree_plans,
    );
    try result.execution.validate();
    try std.testing.expectEqual(@as(u64, 2), result.execution.point_plan_count);
    try std.testing.expectEqual(@as(u64, 1), result.execution.domain_plan_count);
    try std.testing.expectEqual(@as(u64, 6), result.execution.evaluation_task_count);

    const domain = canonic.CanonicCoset.new(log_size).circleDomain();
    const all_values = [_][]const M31{ &first_values, &second_values, &third_values };
    const all_outputs = [_][]const QM31{ &first_output_a, &first_output_b, &second_output };
    for (all_values, all_outputs) |values, outputs| {
        const evaluation = try circle_evaluation.CircleEvaluation.init(domain, values);
        for (points, outputs) |point, actual| {
            const expected = try evaluation.barycentricEvalAtPoint(
                allocator,
                point,
            );
            try std.testing.expect(expected.eql(actual));
        }
    }
}
