//! Normalized sampled-coefficient plans and host batch evaluation.

const std = @import("std");
const prover_api = @import("stwo_prover_api");
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover_circle = @import("../poly/circle/mod.zig");
const prover_circle_eval = @import("../poly/circle/evaluation.zig");
const point_evaluation = @import("../poly/circle/point_evaluation.zig");
const work_pool_mod = @import("../work_pool.zig");
const sampled_work = @import("sampled_value_work.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;
const ColumnEvaluation = prover_api.ColumnEvaluation;

pub const CoefficientEvalPlan = struct {
    coeff_log_size: u32,
    fold_count: u32,
    normalized_points: []CirclePointQM31,
    flat_factors: []QM31,
    column_indices: std.ArrayList(usize),
    next_same_hash: ?usize,

    fn deinit(self: *CoefficientEvalPlan, allocator: std.mem.Allocator) void {
        allocator.free(self.normalized_points);
        allocator.free(self.flat_factors);
        self.column_indices.deinit(allocator);
        self.* = undefined;
    }
};

pub const CoefficientEvalTreePlan = struct {
    coefficients: []const prover_circle.CircleCoefficients,
    tree_values: [][]QM31,
    plans: []const CoefficientEvalPlan,
};

/// A set of evaluation-form columns that share an exact sampled-point list.
///
/// Barycentric weights depend only on the domain and sampled point, not on the
/// column values.  Keeping this plan process-local lets the fallback prover
/// construct each weight vector once and apply it to every matching column.
/// No proof, transcript, or durable representation depends on this cache.
pub const BarycentricEvalPlan = struct {
    log_size: u32,
    fold_count: u32,
    raw_points: []CirclePointQM31,
    normalized_points: []CirclePointQM31,
    column_indices: std.ArrayList(usize),
    next_same_hash: ?usize,

    /// Revalidates the exact public-point normalization before a borrowed plan
    /// crosses a backend boundary. This is process-local structural custody;
    /// the digest bucket used by the planner is never sufficient by itself.
    pub fn hasCanonicalNormalization(self: BarycentricEvalPlan) bool {
        if (self.raw_points.len != self.normalized_points.len) return false;
        for (self.raw_points, self.normalized_points) |raw, normalized| {
            if (!foldSamplePoint(raw, self.fold_count).eql(normalized))
                return false;
        }
        return true;
    }

    fn deinit(self: *BarycentricEvalPlan, allocator: std.mem.Allocator) void {
        allocator.free(self.raw_points);
        allocator.free(self.normalized_points);
        self.column_indices.deinit(allocator);
        self.* = undefined;
    }
};

/// One commitment tree participating in a backend-owned evaluation-form
/// sampled-value epoch. `resident_tree` is a borrowed, process-local backend
/// capability: it is meaningful only while the concrete commitment in the
/// owning `CommitmentTreeProverForBackend` remains live.  No codec may promote
/// this pointer-shaped authority.
pub const BarycentricEvalTreePlan = struct {
    columns: []const ColumnEvaluation,
    tree_values: [][]QM31,
    plans: []const BarycentricEvalPlan,
    /// Null explicitly selects bounded host-column staging on capable backends.
    resident_tree: ?*anyopaque,
};

pub fn deinitCoefficientEvalPlans(
    allocator: std.mem.Allocator,
    plans: *std.ArrayList(CoefficientEvalPlan),
) void {
    for (plans.items) |*plan| plan.deinit(allocator);
    plans.deinit(allocator);
}

pub fn deinitBarycentricEvalPlans(
    allocator: std.mem.Allocator,
    plans: *std.ArrayList(BarycentricEvalPlan),
) void {
    for (plans.items) |*plan| plan.deinit(allocator);
    plans.deinit(allocator);
}

pub fn getOrCreateBarycentricEvalPlan(
    allocator: std.mem.Allocator,
    index: *std.AutoHashMap(u64, usize),
    plans: *std.ArrayList(BarycentricEvalPlan),
    log_size: u32,
    fold_count: u32,
    points: []const CirclePointQM31,
    work_audit: ?*sampled_work.Audit,
) !*BarycentricEvalPlan {
    const plan_hash = hashBarycentricEvalPlanKey(log_size, fold_count, points);
    var existing_plan_idx = index.get(plan_hash);
    while (existing_plan_idx) |plan_idx| {
        const plan = &plans.items[plan_idx];
        if (plan.log_size == log_size and
            plan.fold_count == fold_count and
            pointsEqual(plan.raw_points, points))
        {
            return plan;
        }
        existing_plan_idx = plan.next_same_hash;
    }

    var ownership_transferred = false;
    const raw_points = try allocator.dupe(CirclePointQM31, points);
    errdefer if (!ownership_transferred) allocator.free(raw_points);
    const normalized_points = try allocator.alloc(CirclePointQM31, points.len);
    errdefer if (!ownership_transferred) allocator.free(normalized_points);
    for (points, normalized_points) |point, *normalized| {
        normalized.* = foldSamplePoint(point, fold_count);
        if (work_audit) |audit| audit.observePointFolds(fold_count);
    }

    try plans.append(allocator, .{
        .log_size = log_size,
        .fold_count = fold_count,
        .raw_points = raw_points,
        .normalized_points = normalized_points,
        .column_indices = std.ArrayList(usize).empty,
        .next_same_hash = index.get(plan_hash),
    });
    ownership_transferred = true;
    errdefer {
        var plan = plans.items[plans.items.len - 1];
        plans.items.len -= 1;
        plan.deinit(allocator);
    }
    try index.put(plan_hash, plans.items.len - 1);
    return &plans.items[plans.items.len - 1];
}

pub fn getOrCreateCoefficientEvalPlan(
    allocator: std.mem.Allocator,
    index: *std.AutoHashMap(u64, usize),
    plans: *std.ArrayList(CoefficientEvalPlan),
    coeff_log_size: u32,
    fold_count: u32,
    points: []const CirclePointQM31,
    work_audit: ?*sampled_work.Audit,
) !*CoefficientEvalPlan {
    const plan_hash = hashCoefficientEvalPlanKey(
        coeff_log_size,
        fold_count,
        points,
        work_audit,
    );
    var existing_plan_idx = index.get(plan_hash);
    while (existing_plan_idx) |plan_idx| {
        const plan = &plans.items[plan_idx];
        if (plan.coeff_log_size == coeff_log_size and
            plan.fold_count == fold_count and
            coefficientEvalPlanMatchesPoints(plan.*, points, work_audit))
        {
            return plan;
        }
        existing_plan_idx = plan.next_same_hash;
    }

    var ownership_transferred = false;
    const normalized = try buildCoefficientEvalPlanData(
        allocator,
        coeff_log_size,
        fold_count,
        points,
        work_audit,
    );
    errdefer if (!ownership_transferred)
        allocator.free(normalized.normalized_points);
    errdefer if (!ownership_transferred) allocator.free(normalized.flat_factors);

    try plans.append(allocator, .{
        .coeff_log_size = coeff_log_size,
        .fold_count = fold_count,
        .normalized_points = normalized.normalized_points,
        .flat_factors = normalized.flat_factors,
        .column_indices = std.ArrayList(usize).empty,
        .next_same_hash = index.get(plan_hash),
    });
    ownership_transferred = true;
    errdefer {
        var plan = plans.items[plans.items.len - 1];
        plans.items.len -= 1;
        plan.deinit(allocator);
    }
    try index.put(plan_hash, plans.items.len - 1);
    return &plans.items[plans.items.len - 1];
}

const CoefficientEvalPlanData = struct {
    normalized_points: []CirclePointQM31,
    flat_factors: []QM31,
};

const coefficient_plan_key_point_bytes =
    2 * qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31);

fn hashCoefficientEvalPlanKey(
    coeff_log_size: u32,
    fold_count: u32,
    points: []const CirclePointQM31,
    work_audit: ?*sampled_work.Audit,
) u64 {
    var hasher = std.hash.Wyhash.init(0);
    var header: [3 * @sizeOf(u32)]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], coeff_log_size, .little);
    std.mem.writeInt(u32, header[4..8], fold_count, .little);
    std.mem.writeInt(u32, header[8..12], @intCast(points.len), .little);
    hasher.update(header[0..]);

    var point_bytes: [coefficient_plan_key_point_bytes]u8 = undefined;
    for (points) |point| {
        packPointKeyBytes(
            point_bytes[0..],
            foldCoefficientPoint(point, fold_count, work_audit),
        );
        hasher.update(point_bytes[0..]);
    }
    return hasher.final();
}

fn buildCoefficientEvalPlanData(
    allocator: std.mem.Allocator,
    coeff_log_size: u32,
    fold_count: u32,
    points: []const CirclePointQM31,
    work_audit: ?*sampled_work.Audit,
) !CoefficientEvalPlanData {
    const normalized_points = try allocator.alloc(CirclePointQM31, points.len);
    errdefer allocator.free(normalized_points);

    const flat_factors = try allocator.alloc(QM31, points.len * coeff_log_size);
    errdefer allocator.free(flat_factors);

    var factor_buffer: [circle.M31_CIRCLE_LOG_ORDER]QM31 = undefined;
    var factor_at: usize = 0;
    for (points, 0..) |point, point_idx| {
        const folded_point = foldCoefficientPoint(point, fold_count, work_audit);
        normalized_points[point_idx] = folded_point;

        if (coeff_log_size == 0) continue;
        const factors = prover_circle.poly.fillEvalFactorsForPoint(
            folded_point,
            coeff_log_size,
            &factor_buffer,
        );
        if (work_audit) |audit| audit.observeFactorConstruction(coeff_log_size);
        @memcpy(flat_factors[factor_at .. factor_at + coeff_log_size], factors);
        factor_at += coeff_log_size;
    }

    return .{
        .normalized_points = normalized_points,
        .flat_factors = flat_factors,
    };
}

fn coefficientEvalPlanMatchesPoints(
    plan: CoefficientEvalPlan,
    points: []const CirclePointQM31,
    work_audit: ?*sampled_work.Audit,
) bool {
    if (plan.normalized_points.len != points.len) return false;
    for (points, plan.normalized_points) |point, normalized_point| {
        const folded_point = foldCoefficientPoint(
            point,
            plan.fold_count,
            work_audit,
        );
        if (!folded_point.eql(normalized_point)) return false;
    }
    return true;
}

fn foldCoefficientPoint(
    point: CirclePointQM31,
    fold_count: u32,
    work_audit: ?*sampled_work.Audit,
) CirclePointQM31 {
    if (fold_count == 0) return point;
    const folded = point_evaluation.repeatedDoubleOnCircleQM31(point, fold_count);
    if (work_audit) |audit| audit.observePointFolds(fold_count);
    return folded;
}

fn foldSamplePoint(point: CirclePointQM31, fold_count: u32) CirclePointQM31 {
    return if (fold_count == 0)
        point
    else
        point_evaluation.repeatedDoubleOnCircleQM31(point, fold_count);
}

fn hashBarycentricEvalPlanKey(
    log_size: u32,
    fold_count: u32,
    points: []const CirclePointQM31,
) u64 {
    var hasher = std.hash.Wyhash.init(0);
    var header: [3 * @sizeOf(u32)]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], log_size, .little);
    std.mem.writeInt(u32, header[4..8], fold_count, .little);
    std.mem.writeInt(u32, header[8..12], @intCast(points.len), .little);
    hasher.update(header[0..]);

    var point_bytes: [coefficient_plan_key_point_bytes]u8 = undefined;
    for (points) |point| {
        packPointKeyBytes(point_bytes[0..], point);
        hasher.update(point_bytes[0..]);
    }
    return hasher.final();
}

fn pointsEqual(
    lhs: []const CirclePointQM31,
    rhs: []const CirclePointQM31,
) bool {
    if (lhs.len != rhs.len) return false;
    for (lhs, rhs) |lhs_point, rhs_point| {
        if (!lhs_point.eql(rhs_point)) return false;
    }
    return true;
}

pub fn evaluateBarycentricPlan(
    allocator: std.mem.Allocator,
    columns: []const ColumnEvaluation,
    tree_values: [][]QM31,
    plan: BarycentricEvalPlan,
    context: *const prover_circle_eval.BarycentricContext,
    workspace: *prover_circle_eval.BarycentricWorkspace,
    allow_parallel: bool,
    work_audit: ?*sampled_work.Audit,
) !bool {
    if (context.log_size != plan.log_size or
        plan.raw_points.len != plan.normalized_points.len)
    {
        return error.ShapeMismatch;
    }
    for (plan.column_indices.items) |column_idx| {
        if (column_idx >= columns.len or column_idx >= tree_values.len or
            columns[column_idx].log_size != plan.log_size or
            tree_values[column_idx].len != plan.normalized_points.len)
        {
            return error.ShapeMismatch;
        }
    }

    var lease: ?work_pool_mod.WorkLease = null;
    defer if (lease) |*active| active.deinit();
    if (allow_parallel) {
        if (work_pool_mod.getGlobalPool()) |pool| {
            if (pool.workerCount() > 1) lease = pool.acquire(try work_pool_mod.WorkerBudget.init(pool.workerCount())) catch null;
        }
    }
    var used_parallel = false;
    for (plan.normalized_points, 0..) |point, point_idx| {
        const construction = try context.computeWeightsWithReceipt(
            allocator,
            workspace,
            point,
            .{ .allow_parallel = lease != null, .lease = if (lease) |*active| active else null },
        );
        const weights = construction.weights;
        if (construction.receipt.used_parallel) used_parallel = true;
        if (work_audit) |audit| audit.observeBarycentricWeightsExecution(
            plan.log_size,
            construction.receipt.batch_inverse_chunk_count,
            construction.receipt.field_inversion_count,
            construction.receipt.batch_inverse_multiplication_count,
        );

        const parallel = if (lease) |*active| try evaluateBarycentricDotsParallel(
            active,
            columns,
            tree_values,
            plan.column_indices.items,
            point_idx,
            plan.log_size,
            weights,
        ) else false;
        if (parallel) {
            used_parallel = true;
        } else {
            try evaluateBarycentricDots(
                columns,
                tree_values,
                plan.column_indices.items,
                point_idx,
                plan.log_size,
                weights,
            );
        }
        if (work_audit) |audit| for (plan.column_indices.items) |_|
            audit.observeBarycentricDot(plan.log_size);
    }
    return used_parallel;
}

const BarycentricDotWork = struct {
    columns: []const ColumnEvaluation,
    tree_values: [][]QM31,
    column_indices: []const usize,
    point_idx: usize,
    log_size: u32,
    weights: []const QM31,
    failed: *std.atomic.Value(bool),

    fn run(self: *const BarycentricDotWork) void {
        evaluateBarycentricDots(
            self.columns,
            self.tree_values,
            self.column_indices,
            self.point_idx,
            self.log_size,
            self.weights,
        ) catch self.failed.store(true, .release);
    }
};

fn evaluateBarycentricDots(
    columns: []const ColumnEvaluation,
    tree_values: [][]QM31,
    column_indices: []const usize,
    point_idx: usize,
    log_size: u32,
    weights: []const QM31,
) !void {
    const domain = canonic.CanonicCoset.new(log_size).circleDomain();
    for (column_indices) |column_idx| {
        const evaluation = try prover_circle.CircleEvaluation.init(
            domain,
            columns[column_idx].values,
        );
        tree_values[column_idx][point_idx] =
            try evaluation.barycentricEvalAtPointWithWeights(weights);
    }
}

fn evaluateBarycentricDotsParallel(
    lease: *work_pool_mod.WorkLease,
    columns: []const ColumnEvaluation,
    tree_values: [][]QM31,
    column_indices: []const usize,
    point_idx: usize,
    log_size: u32,
    weights: []const QM31,
) !bool {
    if (column_indices.len < 2 or log_size >= @bitSizeOf(usize)) return false;

    // Each worker receives at least 4K exact field multiply/add pairs. This
    // keeps tiny proof tests sequential while allowing one wide production
    // tree to use the process-owned pool instead of stranding its workers.
    const terms_per_column = @as(usize, 1) << @intCast(log_size);
    const total_terms = std.math.mul(
        usize,
        terms_per_column,
        column_indices.len,
    ) catch return false;
    const worker_count = @min(
        lease.workerCount(),
        column_indices.len,
        @max(@as(usize, 1), total_terms / 4096),
    );
    if (worker_count <= 1) return false;

    var failed = std.atomic.Value(bool).init(false);
    var work: [work_pool_mod.MAX_WORKERS]BarycentricDotWork = undefined;
    const chunk_len = (column_indices.len + worker_count - 1) / worker_count;
    for (0..worker_count) |worker| {
        const start = @min(column_indices.len, worker * chunk_len);
        const end = @min(column_indices.len, start + chunk_len);
        work[worker] = .{
            .columns = columns,
            .tree_values = tree_values,
            .column_indices = column_indices[start..end],
            .point_idx = point_idx,
            .log_size = log_size,
            .weights = weights,
            .failed = &failed,
        };
    }

    var wait_group: std.Thread.WaitGroup = .{};
    for (work[1..worker_count]) |*item| {
        lease.spawnWg(
            &wait_group,
            BarycentricDotWork.run,
            .{@as(*const BarycentricDotWork, item)},
        ) catch item.run();
    }
    work[0].run();
    wait_group.wait();
    lease.completeWave();
    if (failed.load(.acquire)) return error.ShapeMismatch;
    return true;
}

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

fn packPointKeyBytes(dst: []u8, point: CirclePointQM31) void {
    std.debug.assert(dst.len == coefficient_plan_key_point_bytes);
    var at: usize = 0;
    inline for (.{ point.x, point.y }) |coordinate| {
        const coordinates = coordinate.toM31Array();
        inline for (coordinates) |m31_coordinate| {
            const encoded = m31_coordinate.toBytesLe();
            @memcpy(dst[at .. at + @sizeOf(M31)], encoded[0..]);
            at += @sizeOf(M31);
        }
    }
}

pub fn evaluateCoefficientPlans(
    allocator: std.mem.Allocator,
    coefficients: []const prover_circle.CircleCoefficients,
    tree_values: [][]QM31,
    plans: []const CoefficientEvalPlan,
    allow_parallel: bool,
    work_audit: ?*sampled_work.Audit,
) !void {
    var batch_coefficients: []prover_circle.CircleCoefficients =
        &[_]prover_circle.CircleCoefficients{};
    defer if (batch_coefficients.len != 0) allocator.free(batch_coefficients);
    var batch_out: [][]QM31 = &[_][]QM31{};
    defer if (batch_out.len != 0) allocator.free(batch_out);
    var basis_scratch: []QM31 = &[_]QM31{};
    defer if (basis_scratch.len != 0) allocator.free(basis_scratch);

    for (plans) |plan| {
        if (plan.column_indices.items.len == 0) continue;
        if (plan.column_indices.items.len == 1) {
            const column_idx = plan.column_indices.items[0];
            if (work_audit == null and @import("sampled_coefficient_split.zig").evaluate(
                coefficients[column_idx..][0..1],
                plan.flat_factors,
                tree_values[column_idx..][0..1],
                false,
            )) continue;
            coefficients[column_idx].evalAtPointsWithFlatFactors(
                plan.flat_factors,
                tree_values[column_idx],
            );
            if (work_audit) |audit|
                audit.observeIterativeEvaluations(
                    plan.coeff_log_size,
                    tree_values[column_idx].len,
                );
            continue;
        }

        const batch_len = plan.column_indices.items.len;
        if (batch_coefficients.len < batch_len) {
            if (batch_coefficients.len != 0) allocator.free(batch_coefficients);
            if (batch_out.len != 0) allocator.free(batch_out);
            // Clear released owners before either replacement allocation can fail.
            batch_coefficients = &.{};
            batch_out = &.{};
            batch_coefficients = try allocator.alloc(prover_circle.CircleCoefficients, batch_len);
            batch_out = try allocator.alloc([]QM31, batch_len);
        }
        const coefficient_view = batch_coefficients[0..batch_len];
        const out_view = batch_out[0..batch_len];

        for (plan.column_indices.items, 0..) |column_idx, batch_idx| {
            coefficient_view[batch_idx] = coefficients[column_idx];
            out_view[batch_idx] = tree_values[column_idx];
        }

        // Exact-work capture executes its existing counted schedule. Ordinary
        // proofs can use bounded split bases without a full domain-sized slab.
        const split = work_audit == null and @import("sampled_coefficient_split.zig").evaluate(
            coefficient_view,
            plan.flat_factors,
            out_view,
            allow_parallel,
        );
        if (!split and (!allow_parallel or !evaluateCoefficientBatchParallel(
            coefficient_view,
            plan.flat_factors,
            out_view,
        ))) {
            const basis_len = std.math.mul(
                usize,
                @as(usize, 1) << @intCast(plan.coeff_log_size),
                plan.normalized_points.len,
            ) catch return error.ShapeMismatch;
            if (basis_scratch.len < basis_len) {
                if (basis_scratch.len != 0) allocator.free(basis_scratch);
                basis_scratch = &.{};
                basis_scratch = try allocator.alloc(QM31, basis_len);
            }
            prover_circle.poly.CircleCoefficients.evalManyAtPointsWithFlatFactors(
                coefficient_view,
                plan.flat_factors,
                out_view,
                basis_scratch,
            );
        }
        if (work_audit) |audit|
            audit.observeSubsetEvaluations(
                plan.coeff_log_size,
                plan.normalized_points.len,
                plan.column_indices.items.len,
            );
    }
}

const CoefficientEvalWork = struct {
    coefficients: []const prover_circle.CircleCoefficients,
    out: []const []QM31,
    point_bases: []const QM31,
    cursor: *std.atomic.Value(usize),

    fn run(self: *const CoefficientEvalWork) void {
        const width = @import("stwo_core").fields.m31.PACK_WIDTH;
        while (true) {
            const start = self.cursor.fetchAdd(width, .monotonic);
            if (start >= self.coefficients.len) return;
            const end = @min(start + width, self.coefficients.len);
            prover_circle.poly.CircleCoefficients.evalManyAtPointsWithSubsetProductBases(
                self.coefficients[start..end],
                self.point_bases,
                self.out[start..end],
            );
        }
    }
};

fn evaluateCoefficientBatchParallel(
    coefficients: []const prover_circle.CircleCoefficients,
    flat_factors: []const QM31,
    out: []const []QM31,
) bool {
    // Each wide column evaluates a full 2^log basis, so even four columns
    // provide ample work to amortize one existing-pool dispatch. Keeping the
    // old eight-column floor stranded six of eighteen M5 Max cores for the
    // width-100 tree's final OODS evaluations.
    const min_columns_per_worker: usize = @max(4, m31.PACK_WIDTH);
    const pool = work_pool_mod.getGlobalPool() orelse return false;
    const worker_count = @min(pool.workerCount(), coefficients.len / min_columns_per_worker);
    if (worker_count <= 1) return false;

    const basis_len = coefficients[0].coeffs.len;
    const point_count = out[0].len;
    const total_basis_len = std.math.mul(usize, point_count, basis_len) catch return false;
    const basis_storage = std.heap.page_allocator.alloc(QM31, total_basis_len) catch return false;
    defer std.heap.page_allocator.free(basis_storage);
    var factor_at: usize = 0;
    var basis_at: usize = 0;
    for (0..point_count) |_| {
        @import("../poly/circle/point_evaluation.zig").fillSubsetProductBasis(
            flat_factors[factor_at .. factor_at + coefficients[0].log_size],
            basis_storage[basis_at .. basis_at + basis_len],
        );
        factor_at += coefficients[0].log_size;
        basis_at += basis_len;
    }

    var cursor = std.atomic.Value(usize).init(0);
    var work: [work_pool_mod.MAX_WORKERS]CoefficientEvalWork = undefined;
    for (work[0..worker_count]) |*worker| {
        // Claim complete native-width column batches: ceiling-dividing raw
        // columns used to create a scalar tail in almost every worker.
        worker.* = .{
            .coefficients = coefficients,
            .out = out,
            .point_bases = basis_storage,
            .cursor = &cursor,
        };
    }

    var wait_group: std.Thread.WaitGroup = .{};
    for (work[1..worker_count]) |*item| {
        pool.spawnWg(&wait_group, CoefficientEvalWork.run, .{@as(*const CoefficientEvalWork, item)});
    }
    work[0].run();
    wait_group.wait();
    return true;
}

pub fn coefficientsAreZero(coefficients: prover_circle.CircleCoefficients) bool {
    for (coefficients.coeffs) |coefficient| {
        if (!coefficient.isZero()) return false;
    }
    return true;
}

test "sampled coefficient native batches cover ragged columns with bounded workers" {
    const allocator = std.testing.allocator;
    const max_columns = 103;
    const log_size = 8;
    const rows = 1 << log_size;
    const storage = try allocator.alloc(M31, max_columns * rows);
    defer allocator.free(storage);
    var rng = std.Random.DefaultPrng.init(0x5276aabc103);
    const random = rng.random();
    for (storage) |*value| value.* = M31.fromCanonical(random.uintLessThan(u32, m31.Modulus));
    var factors: [2 * log_size]QM31 = undefined;
    for (&factors) |*factor| factor.* = QM31.fromU32Unchecked(
        random.uintLessThan(u32, m31.Modulus),
        random.uintLessThan(u32, m31.Modulus),
        random.uintLessThan(u32, m31.Modulus),
        random.uintLessThan(u32, m31.Modulus),
    );
    var coefficients: [max_columns]prover_circle.CircleCoefficients = undefined;
    var values: [max_columns][2]QM31 = undefined;
    var outputs: [max_columns][]QM31 = undefined;
    for (&coefficients, &outputs, 0..) |*polynomial, *output, column| {
        polynomial.* = try prover_circle.CircleCoefficients.initBorrowed(storage[column * rows ..][0..rows]);
        output.* = &values[column];
    }
    for ([_]usize{ 2, 7, 18 }) |workers| {
        var pool: work_pool_mod.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers });
        defer pool.deinit();
        var binding = try work_pool_mod.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        for ([_]usize{ 99, 100, 103 }) |columns| {
            for (values[0..columns]) |*output| @memset(output, QM31.zero());
            try std.testing.expect(evaluateCoefficientBatchParallel(coefficients[0..columns], &factors, outputs[0..columns]));
            for (coefficients[0..columns], values[0..columns]) |polynomial, actual| {
                for (actual, 0..) |value, point| {
                    const expected = polynomial.evalAtPointWithFactors(factors[point * log_size ..][0..log_size]);
                    try std.testing.expect(expected.eql(value));
                }
            }
        }
    }
}
