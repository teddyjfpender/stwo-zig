//! Adversarial exact-work tests for sampled-value evaluation.

const std = @import("std");
const builtin = @import("builtin");
const work_profile = @import("stwo_prover_api").work_profile;
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover_circle = @import("../poly/circle/mod.zig");
const work_pool_mod = @import("../work_pool.zig");
const sampled_work = @import("sampled_value_work.zig");
const coefficient_plans = @import("sampled_coefficient_plans.zig");
const owner = @import("sampled_values.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const WorkRecorder = work_profile.Recorder(true);
const CoefficientEvalPlan = coefficient_plans.CoefficientEvalPlan;
const CoefficientEvalTreePlan = coefficient_plans.CoefficientEvalTreePlan;
const getOrCreateCoefficientEvalPlan = coefficient_plans.getOrCreateCoefficientEvalPlan;
const deinitCoefficientEvalPlans = coefficient_plans.deinitCoefficientEvalPlans;
const finishCoefficientWork = owner.testing.finishCoefficientWork;
const finishBarycentricWork = owner.testing.finishBarycentricWork;
const parallelEvaluationPool = owner.testing.parallelEvaluationPool;
const mergeBackendCoefficientExecution = owner.testing.mergeBackendCoefficientExecution;

test "sampled-value completion publishes exact work and fails closed without an audit" {
    var exact_recorder: WorkRecorder = .{};
    var audit: sampled_work.Audit = .{};
    audit.observePointFolds(2);
    finishCoefficientWork(&exact_recorder, audit);

    try std.testing.expect(!exact_recorder.incomplete);
    try std.testing.expectEqual(@as(u64, 6), exact_recorder.counters.field_additions);
    try std.testing.expectEqual(@as(u64, 4), exact_recorder.counters.field_multiplications);
    try std.testing.expectEqual(
        @as(u64, 1),
        exact_recorder.completed_sites[
            @intFromEnum(work_profile.Site.sampled_value_coefficient_evaluation)
        ],
    );

    var unavailable_recorder: WorkRecorder = .{};
    finishBarycentricWork(&unavailable_recorder, null);
    try std.testing.expect(unavailable_recorder.incomplete);
    try std.testing.expectEqual(
        @as(u64, 0),
        unavailable_recorder.completed_sites[
            @intFromEnum(work_profile.Site.sampled_value_barycentric_evaluation)
        ],
    );
    try std.testing.expect(unavailable_recorder.counters.isZero());
}

// Parallel execution resolves only through the work-pool policy. Tests opt in
// explicitly because `getGlobalPool` refuses lazy process-pool creation.

test "sampled-value parallelism requires explicit scoped authority in tests" {
    if (builtin.single_threaded) return;

    try std.testing.expect(parallelEvaluationPool(1) == null);
    try std.testing.expect(parallelEvaluationPool(2) == null);

    var pool: work_pool_mod.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2 });
    defer pool.deinit();
    var binding = try work_pool_mod.ScopedPoolBinding.init(&pool);
    defer binding.deinit();

    try std.testing.expect(parallelEvaluationPool(1) == null);
    try std.testing.expect(parallelEvaluationPool(2) == &pool);
}

test "sampled-value backend receipt is independently shape-validated" {
    const allocator = std.testing.allocator;
    var coefficient_storage = [_][8]M31{
        .{M31.one()} ** 8,
        .{M31.fromCanonical(2)} ** 8,
    };
    const coefficients = [_]prover_circle.CircleCoefficients{
        try prover_circle.CircleCoefficients.initBorrowed(&coefficient_storage[0]),
        try prover_circle.CircleCoefficients.initBorrowed(&coefficient_storage[1]),
    };
    var points = [_]CirclePointQM31{
        circle.SECURE_FIELD_CIRCLE_GEN.mul(17),
        circle.SECURE_FIELD_CIRCLE_GEN.mul(29),
    };
    var column_indices = std.ArrayList(usize).empty;
    defer column_indices.deinit(allocator);
    try column_indices.appendSlice(allocator, &.{ 0, 1 });
    const plans = [_]CoefficientEvalPlan{.{
        .coeff_log_size = 3,
        .fold_count = 0,
        .normalized_points = &points,
        .flat_factors = &.{},
        .column_indices = column_indices,
        .next_same_hash = null,
    }};
    var output_storage: [2][2]QM31 = undefined;
    var output_slices = [_][]QM31{
        output_storage[0][0..],
        output_storage[1][0..],
    };
    const tree_plans = [_]CoefficientEvalTreePlan{.{
        .coefficients = &coefficients,
        .tree_values = &output_slices,
        .plans = &plans,
    }};
    const execution = work_profile.SampledCoefficientExecution{
        .plan_count = 1,
        .basis_task_count = 2,
        .evaluation_task_count = 4,
        .evaluation_coefficient_terms = 32,
        .basis_multiplications = 768,
        .basis_threadgroup_width = 256,
        .evaluation_threadgroup_width = 256,
    };
    var audit: sampled_work.Audit = .{};
    mergeBackendCoefficientExecution(&audit, execution, &tree_plans);
    try std.testing.expect(audit.complete);
    try std.testing.expectEqual(@as(u64, 1_052), audit.counters.field_additions);
    try std.testing.expectEqual(@as(u64, 800), audit.counters.field_multiplications);

    var malformed = execution;
    malformed.evaluation_coefficient_terms -= 1;
    var rejected: sampled_work.Audit = .{};
    mergeBackendCoefficientExecution(&rejected, malformed, &tree_plans);
    try std.testing.expect(!rejected.complete);
}

test "prover pcs: coefficient eval plan cache reuses duplicate point sets" {
    const allocator = std.testing.allocator;
    const points_a = try allocator.dupe(CirclePointQM31, &[_]CirclePointQM31{
        circle.SECURE_FIELD_CIRCLE_GEN.mul(17),
        circle.SECURE_FIELD_CIRCLE_GEN.mul(23),
    });
    defer allocator.free(points_a);
    const points_b = try allocator.dupe(CirclePointQM31, points_a);
    defer allocator.free(points_b);
    const points_c = try allocator.dupe(CirclePointQM31, &[_]CirclePointQM31{
        circle.SECURE_FIELD_CIRCLE_GEN.mul(29),
    });
    defer allocator.free(points_c);

    var plans = std.ArrayList(CoefficientEvalPlan).empty;
    defer deinitCoefficientEvalPlans(allocator, &plans);
    var index = std.AutoHashMap(u64, usize).init(allocator);
    defer index.deinit();

    const plan_a = try getOrCreateCoefficientEvalPlan(
        allocator,
        &index,
        &plans,
        6,
        1,
        points_a,
        null,
    );
    try plan_a.column_indices.append(allocator, 0);

    _ = try getOrCreateCoefficientEvalPlan(
        allocator,
        &index,
        &plans,
        6,
        1,
        points_b,
        null,
    );
    try std.testing.expectEqual(@as(usize, 1), plans.items.len);

    _ = try getOrCreateCoefficientEvalPlan(
        allocator,
        &index,
        &plans,
        6,
        1,
        points_c,
        null,
    );
    try std.testing.expectEqual(@as(usize, 2), plans.items.len);
}
