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
const point_evaluation = @import("../poly/circle/point_evaluation.zig");
const owner = @import("sampled_values.zig");
const evaluation_mod = @import("../poly/circle/evaluation.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const WorkRecorder = work_profile.Recorder(true);
const CoefficientEvalPlan = coefficient_plans.CoefficientEvalPlan;
const CoefficientEvalTreePlan = coefficient_plans.CoefficientEvalTreePlan;
const BarycentricEvalPlan = coefficient_plans.BarycentricEvalPlan;
const getOrCreateCoefficientEvalPlan = coefficient_plans.getOrCreateCoefficientEvalPlan;
const getOrCreateBarycentricEvalPlan = coefficient_plans.getOrCreateBarycentricEvalPlan;
const deinitCoefficientEvalPlans = coefficient_plans.deinitCoefficientEvalPlans;
const deinitBarycentricEvalPlans = coefficient_plans.deinitBarycentricEvalPlans;
const evaluateBarycentricPlan = coefficient_plans.evaluateBarycentricPlan;
const finishCoefficientWork = owner.testing.finishCoefficientWork;
const finishBarycentricWork = owner.testing.finishBarycentricWork;
const parallelEvaluationPool = owner.testing.parallelEvaluationPool;
const mergeBackendCoefficientExecution = owner.testing.mergeBackendCoefficientExecution;

test "prover pcs: parallel barycentric weights match reference with exact runtime receipt" {
    if (builtin.single_threaded) return;

    const allocator = std.testing.allocator;
    const log_size: u32 = 14;
    const domain_size: usize = @as(usize, 1) << log_size;
    const sampled = circle.SECURE_FIELD_CIRCLE_GEN.mul(0x1234_5678);
    var context = try evaluation_mod.BarycentricContext.init(
        allocator,
        log_size,
    );
    defer context.deinit(allocator);
    var parallel_workspace = evaluation_mod.BarycentricWorkspace.init();
    defer parallel_workspace.deinit(allocator);
    var sequential_workspace = evaluation_mod.BarycentricWorkspace.init();
    defer sequential_workspace.deinit(allocator);

    var pool: work_pool_mod.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4 });
    defer pool.deinit();
    var binding = try work_pool_mod.ScopedPoolBinding.init(&pool);
    defer binding.deinit();

    const parallel = try context.computeWeightsWithReceipt(
        allocator,
        &parallel_workspace,
        sampled,
        .{ .allow_parallel = true },
    );
    const sequential = try context.computeWeightsWithReceipt(
        allocator,
        &sequential_workspace,
        sampled,
        .{ .allow_parallel = false },
    );
    const reference = try prover_circle.CircleEvaluation.barycentricWeights(
        allocator,
        canonic.CanonicCoset.new(log_size),
        sampled,
    );
    defer allocator.free(reference);

    try parallel.receipt.validate();
    try sequential.receipt.validate();
    try std.testing.expect(parallel.receipt.used_parallel);
    try std.testing.expect(!sequential.receipt.used_parallel);
    try std.testing.expectEqual(@as(usize, 4), parallel.receipt.batch_inverse_chunk_count);
    try std.testing.expectEqual(@as(usize, 4), parallel.receipt.field_inversion_count);
    try std.testing.expectEqual(
        @as(usize, 3 * domain_size - 8),
        parallel.receipt.batch_inverse_multiplication_count,
    );
    for (parallel.weights, sequential.weights, reference) |
        parallel_weight,
        sequential_weight,
        reference_weight,
    | {
        try std.testing.expect(parallel_weight.eql(sequential_weight));
        try std.testing.expect(parallel_weight.eql(reference_weight));
    }

    var audit: sampled_work.Audit = .{};
    audit.observeBarycentricWeightsExecution(
        log_size,
        parallel.receipt.batch_inverse_chunk_count,
        parallel.receipt.field_inversion_count,
        parallel.receipt.batch_inverse_multiplication_count,
    );
    try std.testing.expect(audit.complete);
    try std.testing.expectEqual(@as(u64, 1), audit.barycentric_weight_vector_count);
    try std.testing.expectEqual(@as(u64, 4), audit.barycentric_weight_chunk_count);
    try std.testing.expectEqual(@as(u64, 4), audit.barycentric_batch_inversion_count);
    try std.testing.expectEqual(@as(u64, 49_180), audit.counters.field_additions);
    try std.testing.expectEqual(@as(u64, 163_849), audit.counters.field_multiplications);
    try std.testing.expectEqual(@as(u64, 4), audit.counters.field_inversions);

    var guessed_audit: sampled_work.Audit = .{};
    guessed_audit.observeBarycentricWeightsExecution(
        log_size,
        parallel.receipt.batch_inverse_chunk_count,
        1,
        parallel.receipt.batch_inverse_multiplication_count,
    );
    try std.testing.expect(!guessed_audit.complete);
}

test "prover pcs: parallel barycentric weights reject a domain point" {
    if (builtin.single_threaded) return;

    const allocator = std.testing.allocator;
    var context = try evaluation_mod.BarycentricContext.init(allocator, 13);
    defer context.deinit(allocator);
    var workspace = evaluation_mod.BarycentricWorkspace.init();
    defer workspace.deinit(allocator);
    var pool: work_pool_mod.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2 });
    defer pool.deinit();
    var binding = try work_pool_mod.ScopedPoolBinding.init(&pool);
    defer binding.deinit();

    try std.testing.expectError(
        error.PointOnDomain,
        context.computeWeightsWithReceipt(
            allocator,
            &workspace,
            context.domain_points[0],
            .{ .allow_parallel = true },
        ),
    );
}

fn computeBarycentricWeightsUnderAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    var workspace = evaluation_mod.BarycentricWorkspace.init();
    defer workspace.deinit(allocator);
    try workspace.ensureCapacity(allocator, 4);
    var context = try evaluation_mod.BarycentricContext.init(allocator, 6);
    defer context.deinit(allocator);
    _ = try context.computeWeightsWithReceipt(
        allocator,
        &workspace,
        circle.SECURE_FIELD_CIRCLE_GEN.mul(0x8765_4321),
        .{ .allow_parallel = false },
    );
}

test "prover pcs: barycentric workspace allocation failures retain one owner" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        computeBarycentricWeightsUnderAllocationFailure,
        .{},
    );
}

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

test "prover pcs: barycentric plan constructs weights once per shared point" {
    const allocator = std.testing.allocator;
    var column_storage: [2][8]M31 = undefined;
    for (&column_storage[0], 0..) |*value, index| {
        value.* = M31.fromCanonical(@intCast(index + 1));
    }
    for (&column_storage[1], 0..) |*value, index| {
        value.* = M31.fromCanonical(@intCast(3 * index + 7));
    }
    const columns = [_]@import("stwo_prover_api").ColumnEvaluation{
        .{ .log_size = 3, .values = &column_storage[0] },
        .{ .log_size = 3, .values = &column_storage[1] },
    };
    const points_a = [_]CirclePointQM31{
        circle.SECURE_FIELD_CIRCLE_GEN.mul(17),
        circle.SECURE_FIELD_CIRCLE_GEN.mul(29),
    };
    const points_b = points_a;

    var plans = std.ArrayList(BarycentricEvalPlan).empty;
    defer deinitBarycentricEvalPlans(allocator, &plans);
    var index = std.AutoHashMap(u64, usize).init(allocator);
    defer index.deinit();
    var audit: sampled_work.Audit = .{};
    const first = try getOrCreateBarycentricEvalPlan(
        allocator,
        &index,
        &plans,
        3,
        1,
        &points_a,
        &audit,
    );
    try first.column_indices.append(allocator, 0);
    const second = try getOrCreateBarycentricEvalPlan(
        allocator,
        &index,
        &plans,
        3,
        1,
        &points_b,
        &audit,
    );
    try second.column_indices.append(allocator, 1);
    try std.testing.expectEqual(@as(usize, 1), plans.items.len);

    var output_storage: [2][2]QM31 = undefined;
    var outputs = [_][]QM31{
        output_storage[0][0..],
        output_storage[1][0..],
    };
    var context = try @import("../poly/circle/evaluation.zig").BarycentricContext.init(
        allocator,
        3,
    );
    defer context.deinit(allocator);
    var workspace = @import("../poly/circle/evaluation.zig").BarycentricWorkspace.init();
    defer workspace.deinit(allocator);
    const parallel = try evaluateBarycentricPlan(
        allocator,
        &columns,
        &outputs,
        plans.items[0],
        &context,
        &workspace,
        false,
        &audit,
    );
    try std.testing.expect(!parallel);

    for (columns, 0..) |column, column_idx| {
        const evaluation = try prover_circle.CircleEvaluation.init(
            canonic.CanonicCoset.new(3).circleDomain(),
            column.values,
        );
        for (points_a, 0..) |point, point_idx| {
            const expected = try evaluation.barycentricEvalAtPoint(
                allocator,
                point_evaluation.repeatedDoubleOnCircleQM31(point, 1),
            );
            try std.testing.expect(expected.eql(outputs[column_idx][point_idx]));
        }
    }
    // Two points share one weight construction across both columns.  The old
    // per-column fallback performed four batch inversions here.
    try std.testing.expectEqual(@as(u64, 2), audit.counters.field_inversions);
}

test "prover pcs: wide barycentric plan uses the scoped worker pool" {
    if (builtin.single_threaded) return;

    const allocator = std.testing.allocator;
    const column_count: usize = 8;
    const log_size: u32 = 10;
    const domain_size: usize = @as(usize, 1) << log_size;
    const storage = try allocator.alloc(M31, column_count * domain_size);
    defer allocator.free(storage);
    var columns: [column_count]@import("stwo_prover_api").ColumnEvaluation =
        undefined;
    for (&columns, 0..) |*column, column_idx| {
        const values = storage[column_idx * domain_size .. (column_idx + 1) * domain_size];
        for (values, 0..) |*value, row| value.* = M31.fromCanonical(
            @intCast((column_idx + 3) * (row + 5)),
        );
        column.* = .{ .log_size = log_size, .values = values };
    }

    const points = [_]CirclePointQM31{
        circle.SECURE_FIELD_CIRCLE_GEN.mul(47),
    };
    var plans = std.ArrayList(BarycentricEvalPlan).empty;
    defer deinitBarycentricEvalPlans(allocator, &plans);
    var index = std.AutoHashMap(u64, usize).init(allocator);
    defer index.deinit();
    const plan = try getOrCreateBarycentricEvalPlan(
        allocator,
        &index,
        &plans,
        log_size,
        0,
        &points,
        null,
    );
    for (0..column_count) |column_idx|
        try plan.column_indices.append(allocator, column_idx);

    var parallel_values: [column_count][1]QM31 = undefined;
    var parallel_outputs: [column_count][]QM31 = undefined;
    var sequential_values: [column_count][1]QM31 = undefined;
    var sequential_outputs: [column_count][]QM31 = undefined;
    for (0..column_count) |column_idx| {
        parallel_outputs[column_idx] = parallel_values[column_idx][0..];
        sequential_outputs[column_idx] = sequential_values[column_idx][0..];
    }

    var context = try @import("../poly/circle/evaluation.zig").BarycentricContext.init(
        allocator,
        log_size,
    );
    defer context.deinit(allocator);
    var workspace = @import("../poly/circle/evaluation.zig").BarycentricWorkspace.init();
    defer workspace.deinit(allocator);

    var pool: work_pool_mod.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2 });
    defer pool.deinit();
    var binding = try work_pool_mod.ScopedPoolBinding.init(&pool);
    defer binding.deinit();

    const used_parallel = try evaluateBarycentricPlan(
        allocator,
        &columns,
        &parallel_outputs,
        plans.items[0],
        &context,
        &workspace,
        true,
        null,
    );
    try std.testing.expect(used_parallel);
    const used_sequential = try evaluateBarycentricPlan(
        allocator,
        &columns,
        &sequential_outputs,
        plans.items[0],
        &context,
        &workspace,
        false,
        null,
    );
    try std.testing.expect(!used_sequential);
    for (parallel_values, sequential_values) |actual, expected|
        try std.testing.expect(actual[0].eql(expected[0]));
}

fn buildBarycentricPlanUnderAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    const points = [_]CirclePointQM31{
        circle.SECURE_FIELD_CIRCLE_GEN.mul(41),
        circle.SECURE_FIELD_CIRCLE_GEN.mul(43),
    };
    var plans = std.ArrayList(BarycentricEvalPlan).empty;
    defer deinitBarycentricEvalPlans(allocator, &plans);
    var index = std.AutoHashMap(u64, usize).init(allocator);
    defer index.deinit();
    _ = try getOrCreateBarycentricEvalPlan(
        allocator,
        &index,
        &plans,
        5,
        2,
        &points,
        null,
    );
}

test "prover pcs: barycentric plan transfers allocation ownership exactly once" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        buildBarycentricPlanUnderAllocationFailure,
        .{},
    );
}
