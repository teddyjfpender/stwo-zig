//! Sampled-value planning and evaluation for committed PCS trees.
//!
//! This module owns coefficient-plan caching, backend batch dispatch,
//! barycentric fallback, parallel scheduling, and coefficient lifetime release.

const std = @import("std");
const builtin = @import("builtin");
const work_profile = @import("stwo_prover_api").work_profile;
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const pcs_core = @import("stwo_core").pcs;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover_circle = @import("../poly/circle/mod.zig");
const prover_circle_eval = @import("../poly/circle/evaluation.zig");
const point_evaluation = @import("../poly/circle/point_evaluation.zig");
const work_pool_mod = @import("../work_pool.zig");
const commitment_tree = @import("commitment_tree.zig");
const sampled_work = @import("sampled_value_work.zig");
const coefficient_plan_ops = @import("sampled_coefficient_plans.zig");
const CoefficientEvalPlan = coefficient_plan_ops.CoefficientEvalPlan;
const CoefficientEvalTreePlan = coefficient_plan_ops.CoefficientEvalTreePlan;
const deinitCoefficientEvalPlans = coefficient_plan_ops.deinitCoefficientEvalPlans;
const getOrCreateCoefficientEvalPlan = coefficient_plan_ops.getOrCreateCoefficientEvalPlan;
const evaluateBarycentricColumn = coefficient_plan_ops.evaluateBarycentricColumn;
const evaluateCoefficientPlans = coefficient_plan_ops.evaluateCoefficientPlans;
const coefficientsAreZero = coefficient_plan_ops.coefficientsAreZero;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const TreeVec = pcs_core.TreeVec;
const WorkRecorder = work_profile.Recorder(true);

pub fn evaluateAndRelease(
    comptime B: type,
    comptime H: type,
    allocator: std.mem.Allocator,
    trees: []commitment_tree.CommitmentTreeProverForBackend(B, H),
    sampled_points: TreeVec([][]CirclePointQM31),
    lifting_log_size: u32,
) !TreeVec([][]QM31) {
    return evaluateAndReleaseWithWorkRecorder(
        B,
        H,
        allocator,
        trees,
        sampled_points,
        lifting_log_size,
        null,
    );
}

pub fn evaluateAndReleaseWithWorkRecorder(
    comptime B: type,
    comptime H: type,
    allocator: std.mem.Allocator,
    trees: []commitment_tree.CommitmentTreeProverForBackend(B, H),
    sampled_points: TreeVec([][]CirclePointQM31),
    lifting_log_size: u32,
    work_recorder: ?*WorkRecorder,
) !TreeVec([][]QM31) {
    if (trees.len != sampled_points.items.len) return error.ShapeMismatch;

    const out = try allocator.alloc([][]QM31, trees.len);
    errdefer allocator.free(out);

    var initialized_trees: usize = 0;
    errdefer {
        for (out[0..initialized_trees]) |tree_values| {
            for (tree_values) |column_values| allocator.free(column_values);
            allocator.free(tree_values);
        }
    }

    for (trees, sampled_points.items, 0..) |*tree, tree_points, tree_idx| {
        if (tree.columns.len != tree_points.len) return error.ShapeMismatch;
        if (tree.coefficients) |coeffs| {
            if (coeffs.len != tree.columns.len) return error.ShapeMismatch;
        }

        const tree_values = try allocator.alloc([]QM31, tree.columns.len);
        out[tree_idx] = tree_values;
        initialized_trees += 1;

        var initialized_columns: usize = 0;
        errdefer {
            for (tree_values[0..initialized_columns]) |column_values| allocator.free(column_values);
            allocator.free(tree_values);
        }

        for (tree.columns, tree_points, 0..) |column, points, column_idx| {
            try column.validate();
            tree_values[column_idx] = try allocator.alloc(QM31, points.len);
            initialized_columns += 1;
            if (points.len != 0 and column.log_size > lifting_log_size) {
                return error.ShapeMismatch;
            }
        }
    }

    var selected_coefficient_evaluation = false;
    var selected_barycentric_evaluation = false;
    if (work_recorder) |active| {
        // Selection is a profile-only planning pass. Keeping it outside the
        // validation/allocation loop gives recorder-null proofs their original
        // branch-free per-column path.
        for (trees, sampled_points.items) |tree, tree_points| {
            for (tree_points) |points| {
                if (points.len == 0) continue;
                if (tree.coefficients != null)
                    selected_coefficient_evaluation = true
                else
                    selected_barycentric_evaluation = true;
            }
        }
        if (selected_coefficient_evaluation)
            try active.expectProducer(.sampled_value_coefficient_evaluation);
        // work-profile-plan:sampled-value-coefficient-evaluation
        if (selected_barycentric_evaluation)
            try active.expectProducer(.sampled_value_barycentric_evaluation);
        // work-profile-plan:sampled-value-barycentric-evaluation
    }

    // Keep logical-work accounting entirely outside the ordinary prover path.
    // The optional pointers below are resolved once per request; hot
    // polynomial loops only touch an audit when the caller explicitly enabled
    // work capture.
    const capture_work = work_recorder != null;
    var coefficient_work: sampled_work.Audit = .{};
    var barycentric_work: sampled_work.Audit = .{};
    const coefficient_work_audit = if (capture_work) &coefficient_work else null;
    const barycentric_work_audit = if (capture_work) &barycentric_work else null;

    if (comptime @hasDecl(B, "evaluateCoefficientPlans")) {
        if (try evaluateCoefficientTreesWithBackend(
            B,
            H,
            trees,
            sampled_points.items,
            out,
            allocator,
            lifting_log_size,
            coefficient_work_audit,
        )) {
            releaseTreeCoefficients(B, H, trees, allocator);
            if (selected_coefficient_evaluation) {
                finishCoefficientWork(work_recorder, coefficient_work);
            }
            return TreeVec([][]QM31).initOwned(out);
        }
    }

    if (comptime @hasDecl(B, "recordSampledValueFallback")) {
        B.recordSampledValueFallback();
    }

    var barycentric_cache = std.AutoHashMap(u32, prover_circle_eval.BarycentricContext).init(allocator);
    defer {
        var iterator = barycentric_cache.valueIterator();
        while (iterator.next()) |context| {
            var mutable_context = context.*;
            mutable_context.deinit(allocator);
        }
        barycentric_cache.deinit();
    }

    for (trees, sampled_points.items) |*tree, tree_points| {
        if (tree.coefficients != null) continue;
        for (tree.columns, tree_points) |column, points| {
            if (points.len == 0) continue;
            const entry = try barycentric_cache.getOrPut(column.log_size);
            if (!entry.found_existing) {
                entry.value_ptr.* = try prover_circle_eval.BarycentricContext.init(
                    allocator,
                    column.log_size,
                );
                if (barycentric_work_audit) |audit|
                    audit.observeBarycentricContext(column.log_size);
            }
        }
    }

    // Tests must never create the process-global pool implicitly, but an
    // explicitly scoped proof pool is deterministic transaction authority,
    // not ambient test parallelism. `getGlobalPool` already enforces exactly
    // that distinction in test builds: it returns null unless the coordinator
    // installed a `ScopedPoolBinding`. Keeping a second `builtin.is_test`
    // prohibition here silently serialized the largest real-proof evidence
    // gates even when they requested and owned a bounded worker pool.
    if (parallelEvaluationPool(trees.len)) |pool| {
        const worker_contexts = try allocator.alloc(SampledValueWorkerCtx(B, H), trees.len);
        defer allocator.free(worker_contexts);

        for (trees, sampled_points.items, out, worker_contexts) |
            *tree,
            tree_points,
            tree_values,
            *worker_context,
        | {
            worker_context.* = .{
                .tree = tree,
                .tree_points = tree_points,
                .tree_values = tree_values,
                .lifting_log_size = lifting_log_size,
                .barycentric_cache = &barycentric_cache,
                .parallel_coefficient_plans = false,
                .capture_work = capture_work,
                .coefficient_work = .{},
                .barycentric_work = .{},
                .failed = false,
            };
        }

        const primary_tree = largestTreeIndex(trees, sampled_points.items);
        worker_contexts[primary_tree].parallel_coefficient_plans = true;

        var wait_group: std.Thread.WaitGroup = .{};
        for (worker_contexts, 0..) |*worker_context, tree_idx| {
            if (tree_idx == primary_tree) continue;
            pool.spawnWg(
                &wait_group,
                SampledValueWorkerCtx(B, H).run,
                .{worker_context},
            );
        }
        SampledValueWorkerCtx(B, H).run(&worker_contexts[primary_tree]);
        wait_group.wait();

        for (worker_contexts) |worker_context| {
            if (worker_context.failed) return error.ShapeMismatch;
            if (capture_work) {
                coefficient_work.merge(worker_context.coefficient_work);
                barycentric_work.merge(worker_context.barycentric_work);
            }
        }
    } else {
        try evaluateTreesSequential(
            B,
            H,
            trees,
            sampled_points.items,
            out,
            allocator,
            &barycentric_cache,
            lifting_log_size,
            coefficient_work_audit,
            barycentric_work_audit,
        );
    }

    releaseTreeCoefficients(B, H, trees, allocator);
    if (selected_coefficient_evaluation)
        finishCoefficientWork(work_recorder, coefficient_work);
    if (selected_barycentric_evaluation)
        finishBarycentricWork(work_recorder, barycentric_work);
    return TreeVec([][]QM31).initOwned(out);
}

const exact_field_source_mask = work_profile.SourceMask{
    .bits = work_profile.SourceMask.one(.field_additions).bits |
        work_profile.SourceMask.one(.field_multiplications).bits |
        work_profile.SourceMask.one(.field_inversions).bits,
};

fn finishCoefficientWork(
    recorder: ?*WorkRecorder,
    audit: ?sampled_work.Audit,
) void {
    const active = recorder orelse return;
    const exact = audit != null and audit.?.complete;
    if (!exact) {
        // An unavailable execution receipt is not a zero-work receipt. Keep
        // the planned site incomplete instead of publishing invented zeros.
        active.markIncomplete();
        return;
    }
    active.recordCompletedDelta(.{
        .site = .sampled_value_coefficient_evaluation,
        .producer = work_profile.boundaryForSite(
            .sampled_value_coefficient_evaluation,
        ),
        .source_mask = exact_field_source_mask,
        .counters = audit.?.counters,
    }) catch active.markIncomplete();
    // work-profile-complete:sampled-value-coefficient-evaluation
}

fn finishBarycentricWork(
    recorder: ?*WorkRecorder,
    audit: ?sampled_work.Audit,
) void {
    const active = recorder orelse return;
    const exact = audit != null and audit.?.complete;
    if (!exact) {
        // See `finishCoefficientWork`: absence is fail-closed, never encoded
        // as an exact zero contribution.
        active.markIncomplete();
        return;
    }
    active.recordCompletedDelta(.{
        .site = .sampled_value_barycentric_evaluation,
        .producer = work_profile.boundaryForSite(
            .sampled_value_barycentric_evaluation,
        ),
        .source_mask = exact_field_source_mask,
        .counters = audit.?.counters,
    }) catch active.markIncomplete();
    // work-profile-complete:sampled-value-barycentric-evaluation
}

fn parallelEvaluationPool(tree_count: usize) ?*work_pool_mod.WorkPool {
    if (builtin.single_threaded or tree_count <= 1) return null;
    return work_pool_mod.getGlobalPool();
}

fn largestTreeIndex(
    trees: anytype,
    sampled_points: [][][]CirclePointQM31,
) usize {
    var primary_tree: usize = 0;
    var primary_cost: usize = 0;
    for (trees, sampled_points, 0..) |tree, tree_points, tree_idx| {
        var cost: usize = 0;
        for (tree.columns, tree_points) |column, points| {
            const column_cost = std.math.mul(usize, column.values.len, points.len) catch
                std.math.maxInt(usize);
            cost = std.math.add(usize, cost, column_cost) catch std.math.maxInt(usize);
        }
        if (cost > primary_cost) {
            primary_cost = cost;
            primary_tree = tree_idx;
        }
    }
    return primary_tree;
}

fn SampledValueWorkerCtx(comptime B: type, comptime H: type) type {
    return struct {
        tree: *commitment_tree.CommitmentTreeProverForBackend(B, H),
        tree_points: [][]CirclePointQM31,
        tree_values: [][]QM31,
        lifting_log_size: u32,
        barycentric_cache: *const std.AutoHashMap(u32, prover_circle_eval.BarycentricContext),
        parallel_coefficient_plans: bool,
        capture_work: bool,
        coefficient_work: sampled_work.Audit,
        barycentric_work: sampled_work.Audit,
        failed: bool,

        const WorkerSelf = @This();

        fn run(self: *WorkerSelf) void {
            self.runInner() catch {
                self.failed = true;
            };
        }

        fn runInner(self: *WorkerSelf) !void {
            const scratch_allocator = std.heap.page_allocator;
            const coefficient_work_audit = if (self.capture_work)
                &self.coefficient_work
            else
                null;
            const barycentric_work_audit = if (self.capture_work)
                &self.barycentric_work
            else
                null;
            var coefficient_plans = std.ArrayList(CoefficientEvalPlan).empty;
            defer deinitCoefficientEvalPlans(scratch_allocator, &coefficient_plans);
            var coefficient_plan_index = std.AutoHashMap(u64, usize).init(scratch_allocator);
            defer coefficient_plan_index.deinit();

            const tree = self.tree;
            for (tree.columns, self.tree_points, 0..) |column, points, column_idx| {
                if (points.len == 0) continue;
                const values = self.tree_values[column_idx];
                const fold_count = self.lifting_log_size - column.log_size;
                if (tree.coefficients) |coefficients| {
                    const coefficient = coefficients[column_idx];
                    if (coefficientsAreZero(coefficient)) {
                        @memset(values, QM31.zero());
                        continue;
                    }
                    const plan = try getOrCreateCoefficientEvalPlan(
                        scratch_allocator,
                        &coefficient_plan_index,
                        &coefficient_plans,
                        coefficient.logSize(),
                        fold_count,
                        points,
                        coefficient_work_audit,
                    );
                    try plan.column_indices.append(scratch_allocator, column_idx);
                } else {
                    const evaluation = try prover_circle.CircleEvaluation.init(
                        canonic.CanonicCoset.new(column.log_size).circleDomain(),
                        column.values,
                    );
                    const context = self.barycentric_cache.getPtr(column.log_size) orelse
                        return error.ShapeMismatch;
                    var workspace = prover_circle_eval.BarycentricWorkspace.init();
                    defer workspace.deinit(scratch_allocator);

                    try evaluateBarycentricColumn(
                        scratch_allocator,
                        evaluation,
                        context,
                        &workspace,
                        points,
                        values,
                        fold_count,
                        barycentric_work_audit,
                    );
                }
            }

            if (tree.coefficients) |coefficients| {
                try evaluateCoefficientPlans(
                    scratch_allocator,
                    coefficients,
                    self.tree_values,
                    coefficient_plans.items,
                    self.parallel_coefficient_plans,
                    coefficient_work_audit,
                );
            }
        }
    };
}

fn evaluateTreesSequential(
    comptime B: type,
    comptime H: type,
    trees: []commitment_tree.CommitmentTreeProverForBackend(B, H),
    tree_points_list: [][][]CirclePointQM31,
    out: [][][]QM31,
    allocator: std.mem.Allocator,
    barycentric_cache: *std.AutoHashMap(u32, prover_circle_eval.BarycentricContext),
    lifting_log_size: u32,
    coefficient_work: ?*sampled_work.Audit,
    barycentric_work: ?*sampled_work.Audit,
) !void {
    var workspace_cache = std.AutoHashMap(u32, prover_circle_eval.BarycentricWorkspace).init(allocator);
    defer {
        var iterator = workspace_cache.valueIterator();
        while (iterator.next()) |workspace| {
            var mutable_workspace = workspace.*;
            mutable_workspace.deinit(allocator);
        }
        workspace_cache.deinit();
    }

    for (trees, tree_points_list, out) |*tree, tree_points, tree_values| {
        var coefficient_plans = std.ArrayList(CoefficientEvalPlan).empty;
        defer deinitCoefficientEvalPlans(allocator, &coefficient_plans);
        var coefficient_plan_index = std.AutoHashMap(u64, usize).init(allocator);
        defer coefficient_plan_index.deinit();

        for (tree.columns, tree_points, 0..) |column, points, column_idx| {
            if (points.len == 0) continue;
            const values = tree_values[column_idx];
            const fold_count = lifting_log_size - column.log_size;
            if (tree.coefficients) |coefficients| {
                const coefficient = coefficients[column_idx];
                if (coefficientsAreZero(coefficient)) {
                    @memset(values, QM31.zero());
                    continue;
                }
                const plan = try getOrCreateCoefficientEvalPlan(
                    allocator,
                    &coefficient_plan_index,
                    &coefficient_plans,
                    coefficient.logSize(),
                    fold_count,
                    points,
                    coefficient_work,
                );
                try plan.column_indices.append(allocator, column_idx);
            } else {
                const evaluation = try prover_circle.CircleEvaluation.init(
                    canonic.CanonicCoset.new(column.log_size).circleDomain(),
                    column.values,
                );
                const context = barycentric_cache.getPtr(column.log_size) orelse
                    return error.ShapeMismatch;
                const workspace = try workspace_cache.getOrPut(column.log_size);
                if (!workspace.found_existing) {
                    workspace.value_ptr.* = prover_circle_eval.BarycentricWorkspace.init();
                }
                try evaluateBarycentricColumn(
                    allocator,
                    evaluation,
                    context,
                    workspace.value_ptr,
                    points,
                    values,
                    fold_count,
                    barycentric_work,
                );
            }
        }

        if (tree.coefficients) |coefficients| {
            try evaluateCoefficientPlans(
                allocator,
                coefficients,
                tree_values,
                coefficient_plans.items,
                false,
                coefficient_work,
            );
        }
    }
}

fn evaluateCoefficientTreesWithBackend(
    comptime B: type,
    comptime H: type,
    trees: []commitment_tree.CommitmentTreeProverForBackend(B, H),
    tree_points_list: [][][]CirclePointQM31,
    out: [][][]QM31,
    allocator: std.mem.Allocator,
    lifting_log_size: u32,
    work_audit: ?*sampled_work.Audit,
) !bool {
    for (trees, 0..) |tree, tree_index| if (tree.coefficients == null) {
        std.log.debug(
            "backend sampled evaluation unavailable: tree {d} has no coefficients",
            .{tree_index},
        );
        return false;
    };

    if (comptime @hasDecl(B, "evaluateCoefficientTreePlans")) {
        const plan_lists = try allocator.alloc(std.ArrayList(CoefficientEvalPlan), trees.len);
        defer allocator.free(plan_lists);
        var initialized: usize = 0;
        defer for (plan_lists[0..initialized]) |*plans| {
            deinitCoefficientEvalPlans(allocator, plans);
        };

        const tree_plans = try allocator.alloc(CoefficientEvalTreePlan, trees.len);
        defer allocator.free(tree_plans);
        for (trees, tree_points_list, out, 0..) |tree, tree_points, tree_values, tree_index| {
            plan_lists[tree_index] = try buildCoefficientPlansForTree(
                allocator,
                tree.columns,
                tree_points,
                tree.coefficients.?,
                lifting_log_size,
                work_audit,
            );
            initialized += 1;
            tree_plans[tree_index] = .{
                .coefficients = tree.coefficients.?,
                .tree_values = tree_values,
                .plans = plan_lists[tree_index].items,
            };
        }
        if (comptime @hasDecl(B, "evaluateCoefficientTreePlansWithReceipt")) {
            if (work_audit) |audit| {
                const execution = try B.evaluateCoefficientTreePlansWithReceipt(
                    allocator,
                    tree_plans,
                );
                mergeBackendCoefficientExecution(audit, execution, tree_plans);
            } else {
                try B.evaluateCoefficientTreePlans(allocator, tree_plans);
            }
        } else {
            try B.evaluateCoefficientTreePlans(allocator, tree_plans);
            if (work_audit) |audit| audit.complete = false;
        }
        return true;
    }

    for (trees, tree_points_list, out) |tree, tree_points, tree_values| {
        const coefficients = tree.coefficients.?;
        var plans = try buildCoefficientPlansForTree(
            allocator,
            tree.columns,
            tree_points,
            coefficients,
            lifting_log_size,
            work_audit,
        );
        defer deinitCoefficientEvalPlans(allocator, &plans);
        if (comptime @hasDecl(B, "evaluateCoefficientPlansWithReceipt")) {
            if (work_audit) |audit| {
                const execution = try B.evaluateCoefficientPlansWithReceipt(
                    allocator,
                    coefficients,
                    tree_values,
                    plans.items,
                );
                const SingleTreePlan = struct {
                    coefficients: @TypeOf(coefficients),
                    tree_values: @TypeOf(tree_values),
                    plans: @TypeOf(plans.items),
                };
                const tree_plan = [_]SingleTreePlan{.{
                    .coefficients = coefficients,
                    .tree_values = tree_values,
                    .plans = plans.items,
                }};
                mergeBackendCoefficientExecution(audit, execution, &tree_plan);
            } else {
                try B.evaluateCoefficientPlans(
                    allocator,
                    coefficients,
                    tree_values,
                    plans.items,
                );
            }
        } else {
            try B.evaluateCoefficientPlans(
                allocator,
                coefficients,
                tree_values,
                plans.items,
            );
            if (work_audit) |audit| audit.complete = false;
        }
    }
    return true;
}

fn mergeBackendCoefficientExecution(
    audit: *sampled_work.Audit,
    execution: work_profile.SampledCoefficientExecution,
    tree_plans: anytype,
) void {
    if (!audit.complete) return;
    execution.validate() catch return invalidateSampledAudit(audit);

    var plan_count: u64 = 0;
    var basis_task_count: u64 = 0;
    var evaluation_task_count: u64 = 0;
    var evaluation_coefficient_terms: u64 = 0;
    var basis_multiplications: u64 = 0;
    for (tree_plans) |tree_plan| {
        for (tree_plan.plans) |plan| {
            plan_count = checkedSampledAdd(plan_count, 1) orelse
                return invalidateSampledAudit(audit);
            const point_count = std.math.cast(u64, plan.normalized_points.len) orelse
                return invalidateSampledAudit(audit);
            basis_task_count = checkedSampledAdd(
                basis_task_count,
                point_count,
            ) orelse return invalidateSampledAudit(audit);
            const column_count = std.math.cast(u64, plan.column_indices.items.len) orelse
                return invalidateSampledAudit(audit);
            const plan_evaluations = checkedSampledMul(
                point_count,
                column_count,
            ) orelse return invalidateSampledAudit(audit);
            evaluation_task_count = checkedSampledAdd(
                evaluation_task_count,
                plan_evaluations,
            ) orelse return invalidateSampledAudit(audit);
            const basis_per_point = work_profile.logicalSampledCoefficientBasisMultiplications(
                plan.coeff_log_size,
                execution.basis_threadgroup_width,
            ) catch return invalidateSampledAudit(audit);
            basis_multiplications = checkedSampledAdd(
                basis_multiplications,
                checkedSampledMul(point_count, basis_per_point) orelse
                    return invalidateSampledAudit(audit),
            ) orelse return invalidateSampledAudit(audit);
            for (plan.column_indices.items) |column_index| {
                if (column_index >= tree_plan.coefficients.len)
                    return invalidateSampledAudit(audit);
                const coefficient_count = std.math.cast(
                    u64,
                    tree_plan.coefficients[column_index].coefficients().len,
                ) orelse return invalidateSampledAudit(audit);
                evaluation_coefficient_terms = checkedSampledAdd(
                    evaluation_coefficient_terms,
                    checkedSampledMul(point_count, coefficient_count) orelse
                        return invalidateSampledAudit(audit),
                ) orelse return invalidateSampledAudit(audit);
            }
        }
    }

    if (execution.plan_count != plan_count or
        execution.basis_task_count != basis_task_count or
        execution.evaluation_task_count != evaluation_task_count or
        execution.evaluation_coefficient_terms != evaluation_coefficient_terms or
        execution.basis_multiplications != basis_multiplications)
    {
        return invalidateSampledAudit(audit);
    }
    const device_work = execution.exactWork() catch
        return invalidateSampledAudit(audit);
    audit.merge(.{ .counters = device_work });
}

fn checkedSampledAdd(lhs: u64, rhs: u64) ?u64 {
    return std.math.add(u64, lhs, rhs) catch null;
}

fn checkedSampledMul(lhs: u64, rhs: u64) ?u64 {
    return std.math.mul(u64, lhs, rhs) catch null;
}

fn invalidateSampledAudit(audit: *sampled_work.Audit) void {
    audit.complete = false;
}

fn buildCoefficientPlansForTree(
    allocator: std.mem.Allocator,
    columns: []const commitment_tree.ColumnEvaluation,
    tree_points: [][]CirclePointQM31,
    coefficients: []const prover_circle.CircleCoefficients,
    lifting_log_size: u32,
    work_audit: ?*sampled_work.Audit,
) !std.ArrayList(CoefficientEvalPlan) {
    var plans = std.ArrayList(CoefficientEvalPlan).empty;
    errdefer deinitCoefficientEvalPlans(allocator, &plans);
    var plan_index = std.AutoHashMap(u64, usize).init(allocator);
    defer plan_index.deinit();
    for (columns, tree_points, 0..) |column, points, column_idx| {
        if (points.len == 0) continue;
        const plan = try getOrCreateCoefficientEvalPlan(
            allocator,
            &plan_index,
            &plans,
            coefficients[column_idx].logSize(),
            lifting_log_size - column.log_size,
            points,
            work_audit,
        );
        try plan.column_indices.append(allocator, column_idx);
    }
    return plans;
}

fn releaseTreeCoefficients(
    comptime B: type,
    comptime H: type,
    trees: []commitment_tree.CommitmentTreeProverForBackend(B, H),
    allocator: std.mem.Allocator,
) void {
    for (trees) |*tree| {
        if (tree.coefficients) |coefficients| {
            for (coefficients) |*coefficient| coefficient.deinit(allocator);
            allocator.free(coefficients);
            tree.coefficients = null;
        }
    }
}

const Root = @This();

pub const testing = if (builtin.is_test) struct {
    pub const finishCoefficientWork = Root.finishCoefficientWork;
    pub const finishBarycentricWork = Root.finishBarycentricWork;
    pub const parallelEvaluationPool = Root.parallelEvaluationPool;
    pub const mergeBackendCoefficientExecution = Root.mergeBackendCoefficientExecution;
} else struct {};
