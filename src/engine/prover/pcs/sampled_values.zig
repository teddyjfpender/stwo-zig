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
const prover_circle = @import("../poly/circle/mod.zig");
const prover_circle_eval = @import("../poly/circle/evaluation.zig");
const point_evaluation = @import("../poly/circle/point_evaluation.zig");
const work_pool_mod = @import("../work_pool.zig");
const commitment_tree = @import("commitment_tree.zig");
const sampled_work = @import("sampled_value_work.zig");
const plan_overlap = @import("sampled_value_plan_overlap.zig");
const coefficient_plan_ops = @import("sampled_coefficient_plans.zig");
const CoefficientEvalPlan = coefficient_plan_ops.CoefficientEvalPlan;
const CoefficientEvalTreePlan = coefficient_plan_ops.CoefficientEvalTreePlan;
const BarycentricEvalPlan = coefficient_plan_ops.BarycentricEvalPlan;
const BarycentricEvalTreePlan = coefficient_plan_ops.BarycentricEvalTreePlan;
const deinitCoefficientEvalPlans = coefficient_plan_ops.deinitCoefficientEvalPlans;
const deinitBarycentricEvalPlans = coefficient_plan_ops.deinitBarycentricEvalPlans;
const getOrCreateCoefficientEvalPlan = coefficient_plan_ops.getOrCreateCoefficientEvalPlan;
const getOrCreateBarycentricEvalPlan = coefficient_plan_ops.getOrCreateBarycentricEvalPlan;
const evaluateBarycentricPlan = coefficient_plan_ops.evaluateBarycentricPlan;
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

        var initialized_columns: usize = 0;
        errdefer {
            for (tree_values[0..initialized_columns]) |column_values| allocator.free(column_values);
            allocator.free(tree_values);
        }

        for (tree.columns, tree_points, 0..) |column, points, column_idx| {
            try column.validateRetained();
            tree_values[column_idx] = try allocator.alloc(QM31, points.len);
            initialized_columns += 1;
            if (points.len != 0 and column.log_size > lifting_log_size) {
                return error.ShapeMismatch;
            }
        }
        // Transfer cleanup to the outer owner only after every column exists.
        // Until then the inner errdefer owns this partially initialized tree.
        initialized_trees += 1;
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

    if (std.process.hasEnvVarConstant("STWO_ZIG_PROFILE_SAMPLED_DISPATCH")) {
        std.debug.print("SAMPLED_DISPATCH backend={s} coefficient={} barycentric={} mixed={}\n", .{
            @typeName(B),                                @hasDecl(B, "evaluateCoefficientPlans"),
            @hasDecl(B, "evaluateBarycentricTreePlans"), @hasDecl(B, "supportsMixedSampledEvaluation"),
        });
        for (trees, 0..) |tree, i| {
            var log: u32 = 0;
            for (tree.columns) |column| log = @max(log, column.log_size);
            std.debug.print("SAMPLED_TREE index={d} coefficients={} columns={d} max_log={d}\n", .{
                i, tree.coefficients != null, tree.columns.len, log,
            });
        }
    }

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

    if (comptime @hasDecl(B, "evaluateBarycentricTreePlans") and
        @hasDecl(B, "quotientResidencyHandle"))
    {
        if (try evaluateBarycentricTreesWithBackend(
            B,
            H,
            trees,
            sampled_points.items,
            out,
            allocator,
            lifting_log_size,
            barycentric_work_audit,
        )) {
            releaseTreeCoefficients(B, H, trees, allocator);
            if (selected_barycentric_evaluation)
                finishBarycentricWork(work_recorder, barycentric_work);
            return TreeVec([][]QM31).initOwned(out);
        }
    }

    if (comptime @hasDecl(B, "supportsMixedSampledEvaluation") and
        @hasDecl(B, "evaluateCoefficientPlans") and
        @hasDecl(B, "evaluateBarycentricTreePlans") and
        @hasDecl(B, "quotientResidencyHandle"))
    {
        if (B.supportsMixedSampledEvaluation() and try @import("sampled_mixed_backend.zig").evaluate(
            B,
            H,
            trees,
            sampled_points.items,
            out,
            allocator,
            lifting_log_size,
            coefficient_work_audit,
            barycentric_work_audit,
            evaluateCoefficientTreesWithBackend,
            evaluateBarycentricTreesWithBackend,
        )) {
            releaseTreeCoefficients(B, H, trees, allocator);
            if (selected_coefficient_evaluation) finishCoefficientWork(work_recorder, coefficient_work);
            if (selected_barycentric_evaluation) finishBarycentricWork(work_recorder, barycentric_work);
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
                // An unsuccessful constructor must not leave a map entry
                // whose uninitialized value is later destroyed.
                errdefer _ = barycentric_cache.remove(column.log_size);
                entry.value_ptr.* = try prover_circle_eval.BarycentricContext.init(
                    allocator,
                    column.log_size,
                );
                if (barycentric_work_audit) |audit|
                    audit.observeBarycentricContext(column.log_size);
            }
        }
    }

    if (std.process.hasEnvVarConstant(
        "STWO_ZIG_PROFILE_SAMPLED_PLAN_OVERLAP",
    )) {
        var overlap_timer = try std.time.Timer.start();
        var overlap = try plan_overlap.derive(
            allocator,
            trees,
            sampled_points.items,
            lifting_log_size,
        );
        defer overlap.deinit();
        plan_overlap.print(overlap.value, overlap_timer.read());
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
                .parallel_barycentric_plans = false,
                .capture_work = capture_work,
                .coefficient_work = .{},
                .barycentric_work = .{},
                .failed = false,
            };
        }

        var all_coefficients = true;
        for (trees) |tree| if (tree.coefficients == null) {
            all_coefficients = false;
            break;
        };
        if (all_coefficients and !std.process.hasEnvVarConstant("STWO_ZIG_LEGACY_SAMPLED_TREE_SCHEDULE")) {
            const Callback = struct {
                fn run(raw: *anyopaque, index: usize) void {
                    const workers: [*]SampledValueWorkerCtx(B, H) = @ptrCast(@alignCast(raw));
                    workers[index].run();
                }
            };
            for (worker_contexts) |*context| context.parallel_coefficient_plans = true;
            @import("sampled_value_queue.zig").run(pool, trees.len, largestTreeIndex(trees, sampled_points.items), worker_contexts.ptr, Callback.run);
        } else if (preferBarycentricWaves(trees, sampled_points.items) or std.process.hasEnvVarConstant("STWO_ZIG_EXPERIMENTAL_PARALLEL_BARYCENTRIC_WEIGHTS")) {
            // Large evaluation-form trees benefit from inner parallelism.
            // Drain one tree at a time so its bounded weight/dot lease does not
            // compete with unrelated tree workers or nested waits. The
            // evaluation-form trees are drained together, one weight vector
            // per distinct (domain, point) across all of them.
            var shared_trees = std.ArrayList(coefficient_plan_ops.SharedPointTree).empty;
            defer shared_trees.deinit(allocator);
            for (worker_contexts) |*context| {
                if (context.tree.coefficients == null) {
                    try shared_trees.append(allocator, .{
                        .columns = context.tree.columns,
                        .points = context.tree_points,
                        .values = context.tree_values,
                    });
                    continue;
                }
                context.parallel_coefficient_plans = true;
                context.parallel_barycentric_plans = true;
                context.run();
            }
            try coefficient_plan_ops.evaluateBarycentricSharedPoints(
                std.heap.page_allocator,
                shared_trees.items,
                lifting_log_size,
                &barycentric_cache,
                barycentric_work_audit,
            );
        } else {
            const primary_tree = largestTreeIndex(trees, sampled_points.items);
            worker_contexts[primary_tree].parallel_coefficient_plans = true;
            var wait_group: std.Thread.WaitGroup = .{};
            for (worker_contexts, 0..) |*worker_context, tree_idx| {
                if (tree_idx == primary_tree) continue;
                pool.spawnWg(&wait_group, SampledValueWorkerCtx(B, H).run, .{worker_context});
            }
            SampledValueWorkerCtx(B, H).run(&worker_contexts[primary_tree]);
            wait_group.wait();
        }

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

fn preferBarycentricWaves(trees: anytype, sampled_points: [][][]CirclePointQM31) bool {
    for (trees, sampled_points) |tree, points| {
        if (tree.coefficients != null) continue;
        for (tree.columns, points) |column, locations| {
            if (column.log_size >= 18 and locations.len != 0) return true;
        }
    }
    return false;
}

fn largestTreeIndex(
    trees: anytype,
    sampled_points: [][][]CirclePointQM31,
) usize {
    return largestTreeIndexForStorage(trees, sampled_points, !std.process.hasEnvVarConstant("STWO_ZIG_LEGACY_SAMPLED_TREE_SCHEDULE"));
}

fn largestTreeIndexForStorage(trees: anytype, sampled_points: [][][]CirclePointQM31, retained_coefficients: bool) usize {
    var primary_tree: usize = 0;
    var primary_cost: usize = 0;
    for (trees, sampled_points, 0..) |tree, tree_points, tree_idx| {
        var cost: usize = 0;
        for (tree.columns, tree_points, 0..) |column, points, column_index| {
            // Compact trees deliberately drop LDE values. Their coefficient
            // evaluations still cost O(n): measuring the released values made
            // large MAIN/INTER trees score zero and stranded them on one core.
            const rows = if (retained_coefficients and tree.coefficients != null)
                tree.coefficients.?[column_index].coeffs.len
            else
                column.values.len;
            const column_cost = std.math.mul(usize, rows, points.len) catch
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
        parallel_barycentric_plans: bool,
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
            var barycentric_plans = std.ArrayList(BarycentricEvalPlan).empty;
            defer deinitBarycentricEvalPlans(scratch_allocator, &barycentric_plans);
            var barycentric_plan_index = std.AutoHashMap(u64, usize).init(scratch_allocator);
            defer barycentric_plan_index.deinit();

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
                    const plan = try getOrCreateBarycentricEvalPlan(
                        scratch_allocator,
                        &barycentric_plan_index,
                        &barycentric_plans,
                        column.log_size,
                        fold_count,
                        points,
                        barycentric_work_audit,
                    );
                    try plan.column_indices.append(scratch_allocator, column_idx);
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
            } else {
                var workspace = prover_circle_eval.BarycentricWorkspace.init();
                defer workspace.deinit(scratch_allocator);
                for (barycentric_plans.items) |plan| {
                    const context = self.barycentric_cache.getPtr(plan.log_size) orelse
                        return error.ShapeMismatch;
                    _ = try evaluateBarycentricPlan(
                        scratch_allocator,
                        tree.columns,
                        self.tree_values,
                        plan,
                        context,
                        &workspace,
                        self.parallel_barycentric_plans,
                        barycentric_work_audit,
                    );
                }
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
    var barycentric_workspace = prover_circle_eval.BarycentricWorkspace.init();
    defer barycentric_workspace.deinit(allocator);

    for (trees, tree_points_list, out) |*tree, tree_points, tree_values| {
        var coefficient_plans = std.ArrayList(CoefficientEvalPlan).empty;
        defer deinitCoefficientEvalPlans(allocator, &coefficient_plans);
        var coefficient_plan_index = std.AutoHashMap(u64, usize).init(allocator);
        defer coefficient_plan_index.deinit();
        var barycentric_plans = std.ArrayList(BarycentricEvalPlan).empty;
        defer deinitBarycentricEvalPlans(allocator, &barycentric_plans);
        var barycentric_plan_index = std.AutoHashMap(u64, usize).init(allocator);
        defer barycentric_plan_index.deinit();

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
                const plan = try getOrCreateBarycentricEvalPlan(
                    allocator,
                    &barycentric_plan_index,
                    &barycentric_plans,
                    column.log_size,
                    fold_count,
                    points,
                    barycentric_work,
                );
                try plan.column_indices.append(allocator, column_idx);
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
        } else {
            for (barycentric_plans.items) |plan| {
                const context = barycentric_cache.getPtr(plan.log_size) orelse
                    return error.ShapeMismatch;
                _ = try evaluateBarycentricPlan(
                    allocator,
                    tree.columns,
                    tree_values,
                    plan,
                    context,
                    &barycentric_workspace,
                    false,
                    barycentric_work,
                );
            }
        }
    }
}

const sampled_dispatch = @import("sampled_backend_dispatch.zig");
const evaluateCoefficientTreesWithBackend = sampled_dispatch.evaluateCoefficientTreesWithBackend;
const evaluateBarycentricTreesWithBackend = sampled_dispatch.evaluateBarycentricTreesWithBackend;
const mergeBackendCoefficientExecution = sampled_dispatch.mergeBackendCoefficientExecution;

fn releaseTreeCoefficients(
    comptime B: type,
    comptime H: type,
    trees: []commitment_tree.CommitmentTreeProverForBackend(B, H),
    allocator: std.mem.Allocator,
) void {
    for (trees) |*tree| tree.releaseCoefficients(allocator);
}

const Root = @This();

pub const testing = if (builtin.is_test) struct {
    pub const finishCoefficientWork = Root.finishCoefficientWork;
    pub const finishBarycentricWork = Root.finishBarycentricWork;
    pub const parallelEvaluationPool = Root.parallelEvaluationPool;
    pub const largestTreeIndexForStorage = Root.largestTreeIndexForStorage;
    pub const mergeBackendCoefficientExecution = Root.mergeBackendCoefficientExecution;
    pub const evaluateBarycentricTreesWithBackend = Root.evaluateBarycentricTreesWithBackend;
} else struct {};

pub fn ForField(comptime S: type) type {
    if (S == QM31) return @This();
    return @import("sampled_values_field.zig").ForField(S);
}
