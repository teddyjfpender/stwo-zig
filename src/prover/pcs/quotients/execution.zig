//! Eager FRI quotient construction over materialized or streaming inputs.
//!
//! Planning and allocation-backed input views are prepared by `planning.zig`;
//! this module owns sequential/parallel execution and fallback policy.

const std = @import("std");
const builtin = @import("builtin");
const circle = @import("stwo_core").circle;
const qm31 = @import("stwo_core").fields.qm31;
const quotients = @import("stwo_core").pcs.quotients;
const pcs_utils = @import("stwo_core").pcs.utils;
const canonic = @import("stwo_core").poly.circle.canonic;
const column_geometry = @import("../quotient_column_geometry.zig");
const row_executor = @import("../quotient_row_executor.zig");
const planning = @import("planning.zig");
const secure_column = @import("../../secure_column.zig");
const work_pool = @import("../../work_pool.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const QM31 = qm31.QM31;
const TreeVec = pcs_utils.TreeVec;
const ColumnEvaluation = column_geometry.ColumnEvaluation;
const QuotientOpsError = column_geometry.QuotientOpsError;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;

pub const min_positions_per_worker: usize = 256;

pub fn compute(
    allocator: std.mem.Allocator,
    columns: TreeVec([]const ColumnEvaluation),
    sampled_points: TreeVec([][]CirclePointQM31),
    sampled_values: TreeVec([][]QM31),
    random_coeff: QM31,
    lifting_log_size: u32,
    forced_strategy: ?planning.ConstructionStrategy,
) !SecureColumnByCoords {
    if (columns.items.len != sampled_points.items.len) return QuotientOpsError.ShapeMismatch;
    if (columns.items.len != sampled_values.items.len) return QuotientOpsError.ShapeMismatch;

    for (columns.items, sampled_points.items, sampled_values.items) |tree_columns, tree_points, tree_values| {
        if (tree_columns.len != tree_points.len) return QuotientOpsError.ShapeMismatch;
        if (tree_columns.len != tree_values.len) return QuotientOpsError.ShapeMismatch;
        for (tree_columns, tree_points) |column, points| {
            try column.validate();
            if (points.len != 0 and column.log_size > lifting_log_size) {
                return QuotientOpsError.InvalidColumnLogSize;
            }
        }
    }

    var column_log_sizes = try column_geometry.buildColumnLogSizes(allocator, columns);
    defer column_log_sizes.deinitDeep(allocator);

    const domain_size = try column_geometry.checkedPow2(lifting_log_size);
    const flat_columns = try column_geometry.flattenColumnsBorrowed(allocator, columns);
    defer allocator.free(flat_columns);

    var prepared = try planning.prepareContext(
        allocator,
        column_log_sizes,
        sampled_points,
        sampled_values,
        random_coeff,
        lifting_log_size,
        flat_columns.len,
    );
    defer prepared.deinit(allocator);

    const strategy = forced_strategy orelse planning.chooseConstructionStrategy(
        prepared.contribution_plan.activeColumnCount(),
        domain_size,
    );
    return switch (strategy) {
        .materialized => computeMaterializedParallel(
            allocator,
            flat_columns,
            &prepared,
            lifting_log_size,
            domain_size,
        ) catch |err| switch (err) {
            error.ParallelUnavailable => computeMaterialized(
                allocator,
                flat_columns,
                &prepared,
                lifting_log_size,
                domain_size,
            ),
            else => return err,
        },
        .streaming => computeStreamingParallel(
            allocator,
            flat_columns,
            &prepared,
            lifting_log_size,
            domain_size,
        ) catch |err| switch (err) {
            error.ParallelUnavailable => computeStreaming(
                allocator,
                flat_columns,
                &prepared,
                lifting_log_size,
                domain_size,
            ),
            else => return err,
        },
    };
}

fn computeMaterialized(
    allocator: std.mem.Allocator,
    flat_columns: []const ColumnEvaluation,
    prepared: *const planning.PreparedContext,
    lifting_log_size: u32,
    domain_size: usize,
) !SecureColumnByCoords {
    const domain = canonic.CanonicCoset.new(lifting_log_size).circleDomain();
    std.debug.assert(domain.size() == domain_size);

    var lifted_columns = try planning.materializeActiveLiftedColumns(
        allocator,
        flat_columns,
        prepared.contribution_plan.active_column_indices,
        lifting_log_size,
    );
    defer lifted_columns.deinit(allocator);

    var workspace = try quotients.RowQuotientWorkspace.init(allocator, prepared.sample_batches);
    defer workspace.deinit(allocator);
    var scratch = try row_executor.initScratchOrScalarFallback(
        allocator,
        prepared.sample_batches.len,
        @min(domain_size, row_executor.MAX_ROWS),
        domain_size,
    );
    defer if (scratch) |*value| value.deinit(allocator);

    var out = try SecureColumnByCoords.uninitialized(allocator, domain_size);
    errdefer out.deinit(allocator);

    const item = row_executor.MaterializedWork{
        .out_columns = out.columns,
        .start = 0,
        .end = domain_size,
        .workspace = &workspace,
        .scratch = if (scratch) |*value| value else null,
        .domain = domain,
        .lifted_columns = lifted_columns.columns,
        .contribution_plan_ranges = prepared.contribution_plan.ranges,
        .contributions = prepared.contribution_plan.contributions,
        .quotient_constants = &prepared.quotient_constants,
        .lifting_log_size = lifting_log_size,
    };
    try row_executor.executeMaterialized(&item);

    return out;
}

fn computeStreaming(
    allocator: std.mem.Allocator,
    flat_columns: []const ColumnEvaluation,
    prepared: *const planning.PreparedContext,
    lifting_log_size: u32,
    domain_size: usize,
) !SecureColumnByCoords {
    const domain = canonic.CanonicCoset.new(lifting_log_size).circleDomain();
    std.debug.assert(domain.size() == domain_size);

    const nonzero_columns = try allocator.alloc(bool, flat_columns.len);
    defer allocator.free(nonzero_columns);
    @memset(nonzero_columns, true);
    var combined_plan = try planning.buildCombinedContributionPlan(
        allocator,
        flat_columns,
        prepared.contribution_plan.active_column_indices,
        prepared.contribution_plan.ranges,
        prepared.contribution_plan.contributions,
        nonzero_columns,
        lifting_log_size,
    );
    defer combined_plan.deinit(allocator);

    var workspace = try quotients.RowQuotientWorkspace.init(allocator, prepared.sample_batches);
    defer workspace.deinit(allocator);
    var scratch = try row_executor.initScratchOrScalarFallback(
        allocator,
        prepared.sample_batches.len,
        @min(domain_size, row_executor.MAX_ROWS),
        domain_size,
    );
    defer if (scratch) |*value| value.deinit(allocator);

    var out = try SecureColumnByCoords.uninitialized(allocator, domain_size);
    errdefer out.deinit(allocator);

    var item = row_executor.StreamingWork{
        .out_columns = out.columns,
        .start = 0,
        .end = domain_size,
        .workspace = &workspace,
        .scratch = if (scratch) |*value| value else null,
        .domain = domain,
        .combined_views = combined_plan.views,
        .quotient_constants = &prepared.quotient_constants,
        .lifting_log_size = lifting_log_size,
    };
    try row_executor.executeStreaming(&item);

    return out;
}

/// Parallel materialized execution falls back through `ParallelUnavailable`.
fn computeMaterializedParallel(
    allocator: std.mem.Allocator,
    flat_columns: []const ColumnEvaluation,
    prepared: *const planning.PreparedContext,
    lifting_log_size: u32,
    domain_size: usize,
) !SecureColumnByCoords {
    if (comptime builtin.single_threaded) return error.ParallelUnavailable;
    const pool = work_pool.getGlobalPool() orelse return error.ParallelUnavailable;

    const n_workers = @min(pool.workerCount(), domain_size / min_positions_per_worker);
    if (n_workers <= 1) return error.ParallelUnavailable;
    const worker_span = try row_executor.workerSpan(domain_size, n_workers);
    const use_batched_inversion = try row_executor.prepareParallelScratchPolicy(
        prepared.sample_batches.len,
        @min(worker_span, row_executor.MAX_ROWS),
        domain_size,
    );

    const domain = canonic.CanonicCoset.new(lifting_log_size).circleDomain();

    var lifted_columns = try planning.materializeActiveLiftedColumns(
        allocator,
        flat_columns,
        prepared.contribution_plan.active_column_indices,
        lifting_log_size,
    );
    defer lifted_columns.deinit(allocator);

    const workspaces = try allocator.alloc(quotients.RowQuotientWorkspace, n_workers);
    defer allocator.free(workspaces);
    var ws_initialized: usize = 0;
    defer for (workspaces[0..ws_initialized]) |*ws| ws.deinit(allocator);
    for (workspaces) |*ws| {
        ws.* = try quotients.RowQuotientWorkspace.init(allocator, prepared.sample_batches);
        ws_initialized += 1;
    }

    var scratches: ?[]row_executor.Scratch = null;
    var scratch_initialized: usize = 0;
    defer if (scratches) |values| {
        for (values[0..scratch_initialized]) |*scratch| scratch.deinit(allocator);
        allocator.free(values);
    };
    if (use_batched_inversion) {
        scratches = try allocator.alloc(row_executor.Scratch, n_workers);
        for (scratches.?) |*scratch| {
            scratch.* = try row_executor.initParallelScratch(
                allocator,
                prepared.sample_batches.len,
                @min(worker_span, row_executor.MAX_ROWS),
                domain_size,
            );
            scratch_initialized += 1;
        }
    }

    var out = try SecureColumnByCoords.uninitialized(allocator, domain_size);
    errdefer out.deinit(allocator);

    var work_items: [work_pool.MAX_WORKERS]row_executor.MaterializedWork = undefined;
    for (0..n_workers) |worker| {
        const worker_range = try row_executor.workerRange(domain_size, worker_span, worker);
        work_items[worker] = .{
            .out_columns = out.columns,
            .start = worker_range.start,
            .end = worker_range.end,
            .workspace = &workspaces[worker],
            .scratch = if (scratches) |values| &values[worker] else null,
            .domain = domain,
            .lifted_columns = lifted_columns.columns,
            .contribution_plan_ranges = prepared.contribution_plan.ranges,
            .contributions = prepared.contribution_plan.contributions,
            .quotient_constants = &prepared.quotient_constants,
            .lifting_log_size = lifting_log_size,
        };
    }

    var wait_group: std.Thread.WaitGroup = .{};
    for (work_items[1..n_workers]) |*item| {
        pool.spawnWg(&wait_group, row_executor.materializedWorker, .{item});
    }
    row_executor.materializedWorker(&work_items[0]);
    wait_group.wait();
    for (work_items[0..n_workers]) |item| {
        if (item.failure) |err| return err;
    }

    return out;
}

/// Parallel streaming execution falls back through `ParallelUnavailable`.
fn computeStreamingParallel(
    allocator: std.mem.Allocator,
    flat_columns: []const ColumnEvaluation,
    prepared: *const planning.PreparedContext,
    lifting_log_size: u32,
    domain_size: usize,
) !SecureColumnByCoords {
    if (comptime builtin.single_threaded) return error.ParallelUnavailable;
    const pool = work_pool.getGlobalPool() orelse return error.ParallelUnavailable;

    const n_workers = @min(pool.workerCount(), domain_size / min_positions_per_worker);
    if (n_workers <= 1) return error.ParallelUnavailable;
    const worker_span = try row_executor.workerSpan(domain_size, n_workers);
    const use_batched_inversion = try row_executor.prepareParallelScratchPolicy(
        prepared.sample_batches.len,
        @min(worker_span, row_executor.MAX_ROWS),
        domain_size,
    );

    const domain = canonic.CanonicCoset.new(lifting_log_size).circleDomain();

    const nonzero_columns = try allocator.alloc(bool, flat_columns.len);
    defer allocator.free(nonzero_columns);
    @memset(nonzero_columns, true);
    var combined_plan = try planning.buildCombinedContributionPlan(
        allocator,
        flat_columns,
        prepared.contribution_plan.active_column_indices,
        prepared.contribution_plan.ranges,
        prepared.contribution_plan.contributions,
        nonzero_columns,
        lifting_log_size,
    );
    defer combined_plan.deinit(allocator);

    const workspaces = try allocator.alloc(quotients.RowQuotientWorkspace, n_workers);
    defer allocator.free(workspaces);
    var ws_initialized: usize = 0;
    defer for (workspaces[0..ws_initialized]) |*ws| ws.deinit(allocator);
    for (workspaces) |*ws| {
        ws.* = try quotients.RowQuotientWorkspace.init(allocator, prepared.sample_batches);
        ws_initialized += 1;
    }

    var scratches: ?[]row_executor.Scratch = null;
    var scratch_initialized: usize = 0;
    defer if (scratches) |values| {
        for (values[0..scratch_initialized]) |*scratch| scratch.deinit(allocator);
        allocator.free(values);
    };
    if (use_batched_inversion) {
        scratches = try allocator.alloc(row_executor.Scratch, n_workers);
        for (scratches.?) |*scratch| {
            scratch.* = try row_executor.initParallelScratch(
                allocator,
                prepared.sample_batches.len,
                @min(worker_span, row_executor.MAX_ROWS),
                domain_size,
            );
            scratch_initialized += 1;
        }
    }

    var out = try SecureColumnByCoords.uninitialized(allocator, domain_size);
    errdefer out.deinit(allocator);

    var work_items: [work_pool.MAX_WORKERS]row_executor.StreamingWork = undefined;
    for (0..n_workers) |worker| {
        const worker_range = try row_executor.workerRange(domain_size, worker_span, worker);
        work_items[worker] = .{
            .out_columns = out.columns,
            .start = worker_range.start,
            .end = worker_range.end,
            .workspace = &workspaces[worker],
            .scratch = if (scratches) |values| &values[worker] else null,
            .domain = domain,
            .combined_views = combined_plan.views,
            .quotient_constants = &prepared.quotient_constants,
            .lifting_log_size = lifting_log_size,
        };
    }

    var wait_group: std.Thread.WaitGroup = .{};
    for (work_items[1..n_workers]) |*item| {
        pool.spawnWg(&wait_group, row_executor.streamingWorker, .{item});
    }
    row_executor.streamingWorker(&work_items[0]);
    wait_group.wait();
    for (work_items[0..n_workers]) |item| {
        if (item.failure) |err| return err;
    }

    return out;
}
