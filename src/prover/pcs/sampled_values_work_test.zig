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

test "sampled-value allocation cleanup owns partial trees exactly once" {
    const Backend = struct {
        pub fn MerkleTree(comptime H: type) type {
            return @import("../vcs_lifted/prover.zig").MerkleProverLifted(H);
        }

        pub fn commitMerkle(comptime H: type, allocator: std.mem.Allocator, columns: []const []const M31) !MerkleTree(H) {
            return MerkleTree(H).commit(allocator, columns);
        }
    };
    const H = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const Tree = @import("commitment_tree.zig").CommitmentTreeProverForBackend(Backend, H);
    const Points = @import("stwo_core").pcs.TreeVec([][]CirclePointQM31);
    const allocator = std.testing.allocator;
    const values = [_]M31{M31.one()} ** 8;
    const columns = [_]@import("stwo_prover_api").ColumnEvaluation{
        .{ .log_size = 2, .values = values[0..4] },
        .{ .log_size = 3, .values = &values },
    };
    var first = try Tree.init(allocator, columns[0..1]);
    defer first.deinit(allocator);
    var second = try Tree.init(allocator, &columns);
    defer second.deinit(allocator);
    // Borrow these trees; output allocation failures must not consume them.
    var trees = [_]Tree{ first, second };
    var point = [_]CirclePointQM31{circle.SECURE_FIELD_CIRCLE_GEN.mul(17)};
    var first_points = [_][]CirclePointQM31{&point};
    var second_points = [_][]CirclePointQM31{ &point, &point };
    var point_trees = [_][][]CirclePointQM31{ &first_points, &second_points };
    const points = Points{ .items = &point_trees };

    // Reject after one complete tree and two allocated columns in the next.
    try std.testing.expectError(error.ShapeMismatch, owner.evaluateAndRelease(
        Backend,
        H,
        allocator,
        &trees,
        points,
        2,
    ));
    const AllocationCheck = struct {
        fn run(a: std.mem.Allocator, borrowed_trees: []Tree, p: Points) !void {
            var result = try owner.evaluateAndRelease(Backend, H, a, borrowed_trees, p, 3);
            defer result.deinitDeep(a);
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, AllocationCheck.run, .{ &trees, points });
}

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

    {
        var held = try pool.acquire(try work_pool_mod.WorkerBudget.init(4));
        defer held.deinit();
        const fallback = try context.computeWeightsWithReceipt(allocator, &parallel_workspace, sampled, .{ .allow_parallel = true });
        try std.testing.expect(!fallback.receipt.used_parallel);
        for (fallback.weights, reference) |actual, expected| try std.testing.expect(actual.eql(expected));
    }
    {
        var borrowed = try pool.acquire(try work_pool_mod.WorkerBudget.init(2));
        defer borrowed.deinit();
        const bounded = try context.computeWeightsWithReceipt(allocator, &parallel_workspace, sampled, .{ .allow_parallel = true, .lease = &borrowed });
        try std.testing.expectEqual(@as(usize, 2), bounded.receipt.batch_inverse_chunk_count);
        for (bounded.weights, reference) |actual, expected| try std.testing.expect(actual.eql(expected));
        try borrowed.validateRetained(try work_pool_mod.WorkerBudget.init(2));
        try std.testing.expectError(error.PointOnDomain, context.computeWeightsWithReceipt(allocator, &parallel_workspace, context.pointAt(0), .{ .allow_parallel = true, .lease = &borrowed }));
        try borrowed.validateRetained(try work_pool_mod.WorkerBudget.init(2));
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
            context.pointAt(0),
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

const ResidencyEpochBackend = struct {
    pub const supportsBarycentricResidencyEpochs = true;
    var handle: u8 = 0;
    var calls: usize = 0;
    pub fn quotientResidencyHandle(comptime _: type, resident: bool) ?*anyopaque {
        return if (resident) @ptrCast(&handle) else null;
    }
    pub fn supportsHostBarycentricColumns(columns: anytype) bool {
        for (columns) |column| if (column.log_size > 3) return false;
        return true;
    }
    pub fn evaluateBarycentricTreePlans(_: std.mem.Allocator, plans: anytype) !void {
        calls += 1;
        const resident = plans[0].resident_tree != null;
        for (plans) |plan| {
            try std.testing.expectEqual(resident, plan.resident_tree != null);
            for (plan.columns) |column| if (column.log_size > 3) try std.testing.expect(resident);
            for (plan.tree_values) |values| for (values) |*value| {
                value.* = QM31.fromU32Unchecked(if (resident) 7 else 11, 0, 0, 0);
            };
        }
    }
};
fn residencyEpochCase(allocator: std.mem.Allocator, large_resident: bool) !void {
    const Tree = struct { columns: []const @import("stwo_prover_api").ColumnEvaluation, coefficients: ?[]const u8 = null, commitment: bool };
    const words = [_]M31{M31.one()} ** 16;
    const device_columns = [_]@import("stwo_prover_api").ColumnEvaluation{.{ .log_size = 4, .values = &words }};
    const host_columns = [_]@import("stwo_prover_api").ColumnEvaluation{.{ .log_size = 3, .values = words[0..8] }};
    // Host first deliberately exercises reordering and output ownership.
    var trees = [_]Tree{ .{ .columns = &host_columns, .commitment = false }, .{ .columns = &device_columns, .commitment = large_resident } };
    var point = [_]CirclePointQM31{circle.SECURE_FIELD_CIRCLE_GEN.mul(17)};
    var host_points = [_][]CirclePointQM31{&point};
    var device_points = [_][]CirclePointQM31{&point};
    var points = [_][][]CirclePointQM31{ &host_points, &device_points };
    var host_value = [_]QM31{QM31.zero()};
    var device_value = [_]QM31{QM31.zero()};
    var host_output = [_][]QM31{&host_value};
    var device_output = [_][]QM31{&device_value};
    var output = [_][][]QM31{ &host_output, &device_output };
    ResidencyEpochBackend.calls = 0;
    const accepted = try owner.testing.evaluateBarycentricTreesWithBackend(ResidencyEpochBackend, void, &trees, &points, &output, allocator, 5, null);
    try std.testing.expectEqual(large_resident, accepted);
    if (large_resident) {
        try std.testing.expectEqual(@as(usize, 2), ResidencyEpochBackend.calls);
        try std.testing.expectEqual(QM31.fromU32Unchecked(11, 0, 0, 0), host_value[0]);
        try std.testing.expectEqual(QM31.fromU32Unchecked(7, 0, 0, 0), device_value[0]);
    } else {
        try std.testing.expectEqual(@as(usize, 0), ResidencyEpochBackend.calls);
        try std.testing.expectEqual(QM31.zero(), host_value[0]);
        try std.testing.expectEqual(QM31.zero(), device_value[0]);
    }
}
test "sampled barycentric residency keeps large device trees out of the host slab" {
    try residencyEpochCase(std.testing.allocator, true);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, residencyEpochCase, .{true});
}
test "sampled barycentric residency declines unsupported host geometry before changing outputs" {
    try residencyEpochCase(std.testing.allocator, false);
}

fn expectSharedPointsMatchReference(allocator: std.mem.Allocator) !void {
    const ColumnEvaluation = @import("stwo_prover_api").ColumnEvaluation;
    const lifting_log_size: u32 = 10;
    // Two trees on two domains; the out-of-domain point and its predecessor
    // recur across trees and mask shapes, as a proof's trees sample them.
    const log_sizes = [_]u32{ 10, 8, 10, 10 };
    var storage: [log_sizes.len][]M31 = undefined;
    var built: usize = 0;
    defer for (storage[0..built]) |values| allocator.free(values);
    var columns: [log_sizes.len]ColumnEvaluation = undefined;
    for (log_sizes, &storage, &columns, 0..) |log_size, *values, *column, column_idx| {
        values.* = try allocator.alloc(M31, @as(usize, 1) << @intCast(log_size));
        built += 1;
        for (values.*, 0..) |*value, row| value.* = M31.fromCanonical(@intCast(((column_idx + 3) * (row + 5) * 2654435761) % m31.Modulus));
        column.* = .{ .log_size = log_size, .values = values.* };
    }
    const p = circle.SECURE_FIELD_CIRCLE_GEN.mul(17);
    const p_prev = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    const single = [_]CirclePointQM31{p};
    const pair = [_]CirclePointQM31{ p_prev, p };
    const tree_a_points = [_][]const CirclePointQM31{ &single, &pair };
    const tree_b_points = [_][]const CirclePointQM31{ &pair, &single };
    var values_storage: [4][2]QM31 = undefined;
    var tree_a_values = [_][]QM31{ values_storage[0][0..1], values_storage[1][0..2] };
    var tree_b_values = [_][]QM31{ values_storage[2][0..2], values_storage[3][0..1] };
    const trees = [_]coefficient_plans.SharedPointTree{
        .{ .columns = columns[0..2], .points = &tree_a_points, .values = &tree_a_values },
        .{ .columns = columns[2..4], .points = &tree_b_points, .values = &tree_b_values },
    };

    var contexts = std.AutoHashMap(u32, evaluation_mod.BarycentricContext).init(allocator);
    defer {
        var iterator = contexts.valueIterator();
        while (iterator.next()) |context| context.deinit(allocator);
        contexts.deinit();
    }
    for ([_]u32{ 8, 10 }) |log_size| try contexts.put(log_size, try evaluation_mod.BarycentricContext.init(allocator, log_size));

    var audit: sampled_work.Audit = .{};
    try coefficient_plans.evaluateBarycentricSharedPoints(allocator, &trees, lifting_log_size, &contexts, &audit);
    // One vector per (domain, lifted point): (10, p), (10, p_prev) and both
    // points lifted to 8, where per-tree plans build six.
    try std.testing.expectEqual(@as(u64, 4), audit.barycentric_weight_vector_count);

    for (trees) |tree| {
        for (tree.columns, tree.points, tree.values) |column, points, values| {
            const evaluation = try prover_circle.CircleEvaluation.init(
                canonic.CanonicCoset.new(column.log_size).circleDomain(),
                column.values,
            );
            for (points, values) |point, value| {
                const expected = try evaluation.barycentricEvalAtPoint(
                    allocator,
                    point_evaluation.repeatedDoubleOnCircleQM31(point, lifting_log_size - column.log_size),
                );
                try std.testing.expect(expected.eql(value));
            }
        }
    }
}

test "prover pcs: shared-point barycentric weights serve every tree and mask shape" {
    try expectSharedPointsMatchReference(std.testing.allocator);
}

test "prover pcs: shared-point barycentric dots use the scoped worker pool" {
    if (builtin.single_threaded) return;
    var pool: work_pool_mod.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4 });
    defer pool.deinit();
    var binding = try work_pool_mod.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try expectSharedPointsMatchReference(std.testing.allocator);
}
