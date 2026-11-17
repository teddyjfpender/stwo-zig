//! Shared sampled-point barycentric weights and bounded parallel dot ownership.
//! Normalized sampled-coefficient plans and host batch evaluation.

const std = @import("std");
const prover_api = @import("stwo_prover_api");
const circle = @import("stwo_core").circle;
const qm31 = @import("stwo_core").fields.qm31;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover_circle = @import("../poly/circle/mod.zig");
const prover_circle_eval = @import("../poly/circle/evaluation.zig");
const work_pool_mod = @import("../work_pool.zig");
const sampled_work = @import("sampled_value_work.zig");

const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const ColumnEvaluation = prover_api.ColumnEvaluation;

const point_keys = @import("sampled_point_keys.zig");
const foldSamplePoint = point_keys.foldSamplePoint;
const packPointKeyBytes = point_keys.packPointKeyBytes;
const coefficient_plan_key_point_bytes = point_keys.coefficient_plan_key_point_bytes;

/// One evaluation-form tree of a shared-point evaluation.
pub const SharedPointTree = struct {
    columns: []const ColumnEvaluation,
    /// Per column, its sampled points (before lifting folds).
    points: []const []const CirclePointQM31,
    /// Per column, one value per sampled point.
    values: [][]QM31,
};

/// A column slot that reads one shared (domain, point) weight vector.
const SharedPointTarget = struct {
    tree: u32,
    slot: u32,
    column: usize,
};

const SharedPointGroup = struct {
    log_size: u32,
    point: CirclePointQM31,
    targets: std.ArrayList(SharedPointTarget),
};

const SharedPointKey = [@sizeOf(u32) + coefficient_plan_key_point_bytes]u8;

/// Barycentric sampled values of several evaluation-form trees, one weight
/// vector per distinct (domain, lifted point) across all of them.
///
/// Per-tree plans (`evaluateBarycentricPlan`) key weights by a column's whole
/// point list, so the out-of-domain point is re-weighted for every tree and
/// again for every mask shape (`[p]` and `[p_prev, p]`) on the same domain.
/// Weights depend only on the domain and the point, and every value is the
/// same exact field dot product, so sharing them never changes a value.
pub fn evaluateBarycentricSharedPoints(
    allocator: std.mem.Allocator,
    trees: []const SharedPointTree,
    lifting_log_size: u32,
    contexts: *const std.AutoHashMap(u32, prover_circle_eval.BarycentricContext),
    work_audit: ?*sampled_work.Audit,
) !void {
    var groups = std.ArrayList(SharedPointGroup).empty;
    defer {
        for (groups.items) |*group| group.targets.deinit(allocator);
        groups.deinit(allocator);
    }
    var index = std.AutoHashMap(SharedPointKey, usize).init(allocator);
    defer index.deinit();

    for (trees, 0..) |tree, tree_idx| {
        if (tree.columns.len != tree.points.len or tree.columns.len != tree.values.len)
            return error.ShapeMismatch;
        for (tree.columns, tree.points, tree.values, 0..) |column, points, values, column_idx| {
            if (points.len == 0) continue;
            if (column.log_size > lifting_log_size or values.len != points.len) return error.ShapeMismatch;
            const fold_count = lifting_log_size - column.log_size;
            for (points, 0..) |point, slot| {
                const normalized = foldSamplePoint(point, fold_count);
                if (work_audit) |audit| audit.observePointFolds(fold_count);
                var key: SharedPointKey = undefined;
                std.mem.writeInt(u32, key[0..4], column.log_size, .little);
                packPointKeyBytes(key[4..], normalized);
                const entry = try index.getOrPut(key);
                if (!entry.found_existing) {
                    errdefer _ = index.remove(key);
                    try groups.append(allocator, .{ .log_size = column.log_size, .point = normalized, .targets = .empty });
                    entry.value_ptr.* = groups.items.len - 1;
                }
                try groups.items[entry.value_ptr.*].targets.append(allocator, .{
                    .tree = @intCast(tree_idx),
                    .slot = @intCast(slot),
                    .column = column_idx,
                });
            }
        }
    }

    var lease: ?work_pool_mod.WorkLease = null;
    defer if (lease) |*active| active.deinit();
    if (work_pool_mod.getGlobalPool()) |pool| {
        if (pool.workerCount() > 1) lease = pool.acquire(try work_pool_mod.WorkerBudget.init(pool.workerCount())) catch null;
    }
    var workspace = prover_circle_eval.BarycentricWorkspace.init();
    defer workspace.deinit(allocator);
    for (groups.items) |group| {
        const context = contexts.getPtr(group.log_size) orelse return error.ShapeMismatch;
        if (context.log_size != group.log_size) return error.ShapeMismatch;
        const construction = try context.computeWeightsWithReceipt(
            allocator,
            &workspace,
            group.point,
            .{ .allow_parallel = lease != null, .lease = if (lease) |*active| active else null },
        );
        if (work_audit) |audit| audit.observeBarycentricWeightsExecution(
            group.log_size,
            construction.receipt.batch_inverse_chunk_count,
            construction.receipt.field_inversion_count,
            construction.receipt.batch_inverse_multiplication_count,
        );
        try evaluateSharedPointDots(if (lease) |*active| active else null, trees, group.targets.items, group.log_size, construction.weights);
        if (work_audit) |audit| for (group.targets.items) |_| audit.observeBarycentricDot(group.log_size);
    }
}

const SharedPointDotWork = struct {
    trees: []const SharedPointTree,
    targets: []const SharedPointTarget,
    log_size: u32,
    weights: []const QM31,
    failed: *std.atomic.Value(bool),

    fn run(self: *const SharedPointDotWork) void {
        self.runInner() catch self.failed.store(true, .release);
    }

    fn runInner(self: *const SharedPointDotWork) !void {
        const domain = canonic.CanonicCoset.new(self.log_size).circleDomain();
        for (self.targets) |target| {
            const tree = self.trees[target.tree];
            const evaluation = try prover_circle.CircleEvaluation.init(domain, tree.columns[target.column].values);
            tree.values[target.column][target.slot] = try evaluation.barycentricEvalAtPointWithWeights(self.weights);
        }
    }
};

fn evaluateSharedPointDots(
    lease: ?*work_pool_mod.WorkLease,
    trees: []const SharedPointTree,
    targets: []const SharedPointTarget,
    log_size: u32,
    weights: []const QM31,
) !void {
    var failed = std.atomic.Value(bool).init(false);
    // Each worker takes at least 4K exact multiply/add pairs, as the
    // per-tree dots do.
    const terms_per_column = @as(usize, 1) << @intCast(log_size);
    const total_terms = std.math.mul(usize, terms_per_column, targets.len) catch std.math.maxInt(usize);
    const worker_count = if (lease) |active|
        @min(active.workerCount(), targets.len, @max(@as(usize, 1), total_terms / 4096))
    else
        1;
    if (worker_count <= 1) {
        const work: SharedPointDotWork = .{ .trees = trees, .targets = targets, .log_size = log_size, .weights = weights, .failed = &failed };
        return work.runInner();
    }
    var work: [work_pool_mod.MAX_WORKERS]SharedPointDotWork = undefined;
    const chunk_len = (targets.len + worker_count - 1) / worker_count;
    for (0..worker_count) |worker| {
        const start = @min(targets.len, worker * chunk_len);
        const end = @min(targets.len, start + chunk_len);
        work[worker] = .{ .trees = trees, .targets = targets[start..end], .log_size = log_size, .weights = weights, .failed = &failed };
    }
    const active = lease.?;
    var wait_group: std.Thread.WaitGroup = .{};
    for (work[1..worker_count]) |*item| {
        active.spawnWg(&wait_group, SharedPointDotWork.run, .{@as(*const SharedPointDotWork, item)}) catch item.run();
    }
    work[0].run();
    wait_group.wait();
    active.completeWave();
    if (failed.load(.acquire)) return error.ShapeMismatch;
}

pub fn evaluateBarycentricColumn(
    allocator: std.mem.Allocator,
    evaluation: prover_circle.CircleEvaluation,
    context: *const prover_circle_eval.BarycentricContext,
    workspace: *prover_circle_eval.BarycentricWorkspace,
    points: []const CirclePointQM31,
    values: []QM31,
    fold_count: u32,
    work_audit: ?*sampled_work.Audit,
) !void {
    std.debug.assert(points.len == values.len);
    if (work_audit) |audit| {
        for (points, values) |point, *value| {
            const normalized = foldSamplePoint(point, fold_count);
            const construction = try context.computeWeightsWithReceipt(
                allocator,
                workspace,
                normalized,
                .{},
            );
            value.* = try evaluation.barycentricEvalAtPointWithWeights(
                construction.weights,
            );
            audit.observePointFolds(fold_count);
            audit.observeBarycentricWeightsExecution(
                evaluation.domain.logSize(),
                construction.receipt.batch_inverse_chunk_count,
                construction.receipt.field_inversion_count,
                construction.receipt.batch_inverse_multiplication_count,
            );
            audit.observeBarycentricDot(evaluation.domain.logSize());
        }
        return;
    }

    // This is the ordinary proving path. It deliberately contains no audit
    // branch in the per-point loop.
    for (points, values) |point, *value| {
        value.* = try evaluation.barycentricEvalAtPointWithContext(
            allocator,
            context,
            workspace,
            foldSamplePoint(point, fold_count),
        );
    }
}
