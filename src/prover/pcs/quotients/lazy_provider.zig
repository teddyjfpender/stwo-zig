//! Stateful lazy quotient provider.
//!
//! This module owns the bounded-memory quotient cursor, scratch buffers, and
//! parallel tile execution state. The public facade re-exports its API.

const std = @import("std");
const builtin = @import("builtin");
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const quotients = @import("stwo_core").pcs.quotients;
const pcs_utils = @import("stwo_core").pcs.utils;
const canonic = @import("stwo_core").poly.circle.canonic;
const circle_domain = @import("stwo_core").poly.circle.domain;
const column_geometry = @import("../quotient_column_geometry.zig");
const row_executor = @import("../quotient_row_executor.zig");
const tile_executor = @import("../quotient_tile_executor.zig");
const tile_sink = @import("../quotient_tile_sink.zig");
const execution = @import("execution.zig");
const planning = @import("planning.zig");
const secure_column = @import("../../secure_column.zig");
const work_pool_mod = @import("../../work_pool.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const M31 = m31.M31;
const QM31 = qm31.QM31;
const TreeVec = pcs_utils.TreeVec;
const ColumnEvaluation = column_geometry.ColumnEvaluation;
const CombinedContributionView = row_executor.CombinedContributionView;
const QuotientOpsError = column_geometry.QuotientOpsError;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;
const MIN_POSITIONS_PER_WORKER = execution.min_positions_per_worker;
const COMPACT_GROUP_MIN_SHIFT: std.math.Log2Int(usize) = 2;
const MAX_COMPACT_GROUP_BYTES: usize = 1024 * 1024;

/// Number of rows processed per chunk in lazy quotient evaluation.
/// Chosen to amortize function-call overhead while keeping chunk memory bounded.
pub const LAZY_QUOTIENT_CHUNK_SIZE: usize = 1024;

pub const InputMode = enum {
    bounded_cpu,
    combined_compatibility,
    raw_backend,
};

/// Lazy quotient provider for fused quotient-computation + Merkle commitment.
///
/// Encapsulates all state needed to compute FRI quotient values on demand,
/// one chunk at a time, without materializing the full quotient column
/// or the lifted column matrix before Merkle hashing begins.
///
/// Usage:
///   1. `init()` — prepare the provider from the same inputs as `computeFriQuotients`.
///   2. Call `computeChunk()` repeatedly with ascending, non-overlapping position ranges.
///      Each call fills the 4 coordinate buffers for a chunk of the output column.
///   3. `deinit()` — release internal scratch memory.
pub const LazyQuotientProvider = struct {
    prepared: planning.PreparedContext,
    input_mode: InputMode,
    combined_views: []CombinedContributionView,
    compact_plan: planning.CompactContributionPlan,
    direct_plan: tile_executor.DirectContributionPlan,
    raw_columns: []ColumnEvaluation,
    /// Backend-owned resources explicitly borrowed from the commitment trees
    /// in this proof session. Backends may use these handles to reuse resident
    /// data, but must never discover resources from runtime-global state.
    backend_residency_handles: []const *anyopaque,
    workspace: quotients.RowQuotientWorkspace,
    chunk_scratch: ?row_executor.Scratch,
    direct_chunk_scratch: ?tile_executor.Scratch,
    allow_parallel_scalar: bool,
    domain: circle_domain.CircleDomain,
    lifting_log_size: u32,
    domain_size: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        columns: TreeVec([]const ColumnEvaluation),
        sampled_points: TreeVec([][]CirclePointQM31),
        sampled_values: TreeVec([][]QM31),
        random_coeff: QM31,
        lifting_log_size: u32,
    ) !LazyQuotientProvider {
        return initWithMode(
            allocator,
            columns,
            sampled_points,
            sampled_values,
            random_coeff,
            lifting_log_size,
            if (tile_executor.shouldUseBoundedInput(lifting_log_size))
                .bounded_cpu
            else
                .combined_compatibility,
        );
    }

    pub fn initWithMode(
        allocator: std.mem.Allocator,
        columns: TreeVec([]const ColumnEvaluation),
        sampled_points: TreeVec([][]CirclePointQM31),
        sampled_values: TreeVec([][]QM31),
        random_coeff: QM31,
        lifting_log_size: u32,
        input_mode: InputMode,
    ) !LazyQuotientProvider {
        return initForBackendWithMode(
            void,
            allocator,
            columns,
            sampled_points,
            sampled_values,
            random_coeff,
            lifting_log_size,
            input_mode,
        );
    }

    pub fn initForBackend(
        comptime B: type,
        allocator: std.mem.Allocator,
        columns: TreeVec([]const ColumnEvaluation),
        sampled_points: TreeVec([][]CirclePointQM31),
        sampled_values: TreeVec([][]QM31),
        random_coeff: QM31,
        lifting_log_size: u32,
    ) !LazyQuotientProvider {
        const backend_raw = comptime B != void and @hasDecl(B, "rawQuotientInputs") and B.rawQuotientInputs;
        return initForBackendWithMode(
            B,
            allocator,
            columns,
            sampled_points,
            sampled_values,
            random_coeff,
            lifting_log_size,
            if (backend_raw)
                .raw_backend
            else if (tile_executor.shouldUseBoundedInput(lifting_log_size))
                .bounded_cpu
            else
                .combined_compatibility,
        );
    }

    pub fn initForBackendWithMode(
        comptime B: type,
        allocator: std.mem.Allocator,
        columns: TreeVec([]const ColumnEvaluation),
        sampled_points: TreeVec([][]CirclePointQM31),
        sampled_values: TreeVec([][]QM31),
        random_coeff: QM31,
        lifting_log_size: u32,
        input_mode: InputMode,
    ) !LazyQuotientProvider {
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
        errdefer allocator.free(flat_columns);

        var prepared = try planning.prepareContext(
            allocator,
            column_log_sizes,
            sampled_points,
            sampled_values,
            random_coeff,
            lifting_log_size,
            flat_columns.len,
        );
        errdefer prepared.deinit(allocator);

        const nonzero_columns = try planning.markNonzeroColumnsAndSamples(
            allocator,
            columns,
            sampled_values,
        );
        defer allocator.free(nonzero_columns);

        const backend_raw = comptime B != void and @hasDecl(B, "rawQuotientInputs") and B.rawQuotientInputs;
        if ((input_mode == .raw_backend) != backend_raw) return error.InvalidQuotientInputMode;
        var combined_views: []CombinedContributionView = &.{};
        var compact_plan = planning.CompactContributionPlan{ .groups = &.{}, .members = &.{} };
        var direct_plan = tile_executor.DirectContributionPlan{ .views = &.{}, .ranges = &.{} };
        errdefer {
            var combined_plan = planning.CombinedContributionPlan{ .views = combined_views };
            combined_plan.deinit(allocator);
            compact_plan.deinit(allocator);
            direct_plan.deinit(allocator);
        }
        switch (input_mode) {
            .combined_compatibility => {
                const combined_plan = try planning.buildCombinedContributionPlan(
                    allocator,
                    flat_columns,
                    prepared.contribution_plan.active_column_indices,
                    prepared.contribution_plan.ranges,
                    prepared.contribution_plan.contributions,
                    nonzero_columns,
                    lifting_log_size,
                );
                combined_views = combined_plan.views;
            },
            .bounded_cpu => {
                const optional_compact_plan = try planning.buildCompactContributionPlan(
                    allocator,
                    flat_columns,
                    prepared.contribution_plan.active_column_indices,
                    prepared.contribution_plan.ranges,
                    prepared.contribution_plan.contributions,
                    nonzero_columns,
                    lifting_log_size,
                    COMPACT_GROUP_MIN_SHIFT,
                    MAX_COMPACT_GROUP_BYTES,
                );
                const compact_admitted = optional_compact_plan != null;
                if (optional_compact_plan) |plan| compact_plan = plan;
                direct_plan = try tile_executor.buildDirectContributionPlan(
                    allocator,
                    flat_columns,
                    prepared.contribution_plan.active_column_indices,
                    prepared.contribution_plan.ranges,
                    nonzero_columns,
                    lifting_log_size,
                    if (compact_admitted) COMPACT_GROUP_MIN_SHIFT else null,
                );
            },
            .raw_backend => {},
        }

        var workspace = try quotients.RowQuotientWorkspace.init(allocator, prepared.sample_batches);
        errdefer workspace.deinit(allocator);
        var chunk_scratch: ?row_executor.Scratch = null;
        if (input_mode == .combined_compatibility) {
            chunk_scratch = try row_executor.initScratchOrScalarFallback(
                allocator,
                prepared.sample_batches.len,
                LAZY_QUOTIENT_CHUNK_SIZE,
                domain_size,
            );
        }
        errdefer if (chunk_scratch) |*scratch| scratch.deinit(allocator);
        var direct_chunk_scratch: ?tile_executor.Scratch = null;
        if (input_mode == .bounded_cpu) {
            direct_chunk_scratch = try tile_executor.initScratchOrScalarFallback(
                allocator,
                prepared.sample_batches.len,
                tile_sink.DEFAULT_TILE_ROWS,
                domain_size,
            );
        }
        errdefer if (direct_chunk_scratch) |*scratch| scratch.deinit(allocator);

        const domain = canonic.CanonicCoset.new(lifting_log_size).circleDomain();

        return .{
            .prepared = prepared,
            .input_mode = input_mode,
            .combined_views = combined_views,
            .compact_plan = compact_plan,
            .direct_plan = direct_plan,
            .raw_columns = if (input_mode == .raw_backend) flat_columns else blk: {
                allocator.free(flat_columns);
                break :blk &.{};
            },
            .backend_residency_handles = &.{},
            .workspace = workspace,
            .chunk_scratch = chunk_scratch,
            .direct_chunk_scratch = direct_chunk_scratch,
            .allow_parallel_scalar = input_mode != .raw_backend and !row_executor.shouldBatchDomain(domain_size),
            .domain = domain,
            .lifting_log_size = lifting_log_size,
            .domain_size = domain_size,
        };
    }

    /// Borrows the proof-session residency set for the lifetime of this
    /// provider. The caller retains ownership of both the slice and handles.
    pub fn setBackendResidencyHandles(
        self: *LazyQuotientProvider,
        handles: []const *anyopaque,
    ) void {
        self.backend_residency_handles = handles;
    }

    pub fn deinit(self: *LazyQuotientProvider, allocator: std.mem.Allocator) void {
        if (self.direct_chunk_scratch) |*scratch| scratch.deinit(allocator);
        if (self.chunk_scratch) |*scratch| scratch.deinit(allocator);
        self.workspace.deinit(allocator);
        var combined_plan = planning.CombinedContributionPlan{ .views = self.combined_views };
        combined_plan.deinit(allocator);
        self.compact_plan.deinit(allocator);
        self.direct_plan.deinit(allocator);
        if (self.raw_columns.len != 0) allocator.free(self.raw_columns);
        self.prepared.deinit(allocator);
        self.* = undefined;
    }

    /// Compute quotient values for positions `[chunk_start .. chunk_start + chunk_len)`.
    ///
    /// The 4 output coordinate buffers must each have length >= `chunk_len`.
    /// Positions must be in range `[0, domain_size)`.
    pub fn computeChunk(
        self: *LazyQuotientProvider,
        chunk_start: usize,
        chunk_len: usize,
        out_coords: *[qm31.SECURE_EXTENSION_DEGREE][]M31,
    ) !void {
        const chunk_end = std.math.add(usize, chunk_start, chunk_len) catch
            return QuotientOpsError.ShapeMismatch;
        if (chunk_end > self.domain_size) return QuotientOpsError.ShapeMismatch;
        for (out_coords) |coord_buf| {
            if (coord_buf.len < chunk_len) return QuotientOpsError.ShapeMismatch;
        }

        switch (self.input_mode) {
            .bounded_cpu => {
                var work = tile_executor.Work{
                    .out_columns = out_coords.*,
                    .start = chunk_start,
                    .end = chunk_end,
                    .output_start = chunk_start,
                    .workspace = &self.workspace,
                    .scratch = if (self.direct_chunk_scratch) |*scratch| scratch else null,
                    .domain = self.domain,
                    .compact_groups = self.compact_plan.groups,
                    .column_views = self.direct_plan.views,
                    .contribution_ranges = self.direct_plan.ranges,
                    .contributions = self.prepared.contribution_plan.contributions,
                    .quotient_constants = &self.prepared.quotient_constants,
                    .lifting_log_size = self.lifting_log_size,
                };
                try tile_executor.execute(&work);
            },
            .combined_compatibility => {
                var work = row_executor.StreamingWork{
                    .out_columns = out_coords.*,
                    .start = chunk_start,
                    .end = chunk_end,
                    .output_start = chunk_start,
                    .workspace = &self.workspace,
                    .scratch = if (self.chunk_scratch) |*scratch| scratch else null,
                    .domain = self.domain,
                    .combined_views = self.combined_views,
                    .quotient_constants = &self.prepared.quotient_constants,
                    .lifting_log_size = self.lifting_log_size,
                };
                try row_executor.executeStreaming(&work);
            },
            .raw_backend => return error.UnsupportedQuotientInputMode,
        }
    }

    /// Materialize the full quotient column, splitting disjoint domain ranges
    /// across the global prover pool when enough work is available.
    pub fn computeAll(
        self: *LazyQuotientProvider,
        allocator: std.mem.Allocator,
        out: *SecureColumnByCoords,
    ) !void {
        if (out.len() != self.domain_size) return QuotientOpsError.ShapeMismatch;

        if (!builtin.single_threaded) {
            if (try self.computeAllParallel(allocator, out, null) != null) return;
        }

        var chunk_start: usize = 0;
        while (chunk_start < self.domain_size) {
            const chunk_len = @min(LAZY_QUOTIENT_CHUNK_SIZE, self.domain_size - chunk_start);
            var chunk_coords: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
            inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coord| {
                chunk_coords[coord] = out.columns[coord][chunk_start..][0..chunk_len];
            }
            try self.computeChunk(chunk_start, chunk_len, &chunk_coords);
            chunk_start += chunk_len;
        }
    }

    /// Computes the retained quotient column and emits each completed row tile
    /// to a worker-local sink before its output cache lines are reused.
    pub fn computeAllWithTileSink(
        self: *LazyQuotientProvider,
        allocator: std.mem.Allocator,
        out: *SecureColumnByCoords,
        factory: tile_sink.Factory,
    ) !tile_sink.ExecutionStats {
        if (out.len() != self.domain_size) return QuotientOpsError.ShapeMismatch;

        if (!builtin.single_threaded) {
            if (try self.computeAllParallel(allocator, out, factory)) |stats| return stats;
        }

        const writer = try factory.prepareWriter(0, .{ .start = 0, .end = self.domain_size });
        var tile_count: usize = 0;
        switch (self.input_mode) {
            .bounded_cpu => {
                var work = tile_executor.Work{
                    .out_columns = out.columns,
                    .start = 0,
                    .end = self.domain_size,
                    .workspace = &self.workspace,
                    .scratch = if (self.direct_chunk_scratch) |*scratch| scratch else null,
                    .domain = self.domain,
                    .compact_groups = self.compact_plan.groups,
                    .column_views = self.direct_plan.views,
                    .contribution_ranges = self.direct_plan.ranges,
                    .contributions = self.prepared.contribution_plan.contributions,
                    .quotient_constants = &self.prepared.quotient_constants,
                    .lifting_log_size = self.lifting_log_size,
                    .tile_writer = writer,
                };
                try tile_executor.execute(&work);
                tile_count = work.completed_tiles;
            },
            .combined_compatibility => {
                var work = row_executor.StreamingWork{
                    .out_columns = out.columns,
                    .start = 0,
                    .end = self.domain_size,
                    .workspace = &self.workspace,
                    .scratch = if (self.chunk_scratch) |*scratch| scratch else null,
                    .domain = self.domain,
                    .combined_views = self.combined_views,
                    .quotient_constants = &self.prepared.quotient_constants,
                    .lifting_log_size = self.lifting_log_size,
                    .tile_writer = writer,
                };
                try row_executor.executeStreaming(&work);
                tile_count = work.completed_tiles;
            },
            .raw_backend => return error.UnsupportedQuotientInputMode,
        }
        try factory.finishWriters(1);
        const scratch_bytes = switch (self.input_mode) {
            .bounded_cpu => if (self.direct_chunk_scratch) |scratch| scratch.retainedBytes() else 0,
            .combined_compatibility => if (self.chunk_scratch) |scratch| scratch.retainedBytes() else 0,
            .raw_backend => 0,
        };
        return .{
            .tile_pipeline_selected = true,
            .worker_count = 1,
            .tile_row_limit = tile_sink.DEFAULT_TILE_ROWS,
            .tile_count = tile_count,
            .peak_scratch_bytes_per_worker = scratch_bytes,
            .total_scratch_bytes = scratch_bytes,
            .bounded_numerator_tile_bytes_per_worker = if (self.direct_chunk_scratch) |scratch|
                scratch.numeratorBytes()
            else
                0,
            .complete_column_combined_intermediate_bytes = try self.combinedIntermediateBytes(),
            .post_compute_leaf_pass_count = 0,
        };
    }

    pub fn combinedIntermediateBytes(self: *const LazyQuotientProvider) !usize {
        var bytes: usize = 0;
        for (self.combined_views) |view| {
            for (view.coordinates) |coordinate| {
                const coordinate_bytes = std.math.mul(usize, coordinate.len, @sizeOf(M31)) catch
                    return error.ScratchSizeOverflow;
                bytes = std.math.add(usize, bytes, coordinate_bytes) catch
                    return error.ScratchSizeOverflow;
            }
        }
        return bytes;
    }

    fn computeAllParallel(
        self: *const LazyQuotientProvider,
        allocator: std.mem.Allocator,
        out: *SecureColumnByCoords,
        factory: ?tile_sink.Factory,
    ) !?tile_sink.ExecutionStats {
        switch (self.input_mode) {
            .bounded_cpu => return self.computeAllParallelDirect(allocator, out, factory),
            .combined_compatibility => {},
            .raw_backend => return null,
        }
        const use_batched_inversion = self.chunk_scratch != null;
        if (!use_batched_inversion and !self.allow_parallel_scalar) return null;
        const pool = work_pool_mod.getGlobalPool() orelse return null;
        const n_workers = @min(pool.workerCount(), self.domain_size / MIN_POSITIONS_PER_WORKER);
        if (n_workers <= 1) return null;

        const workspaces = try allocator.alloc(quotients.RowQuotientWorkspace, n_workers);
        defer allocator.free(workspaces);
        var initialized: usize = 0;
        defer for (workspaces[0..initialized]) |*workspace| workspace.deinit(allocator);
        for (workspaces) |*workspace| {
            workspace.* = try quotients.RowQuotientWorkspace.init(allocator, self.prepared.sample_batches);
            initialized += 1;
        }

        const worker_span = try row_executor.workerSpan(self.domain_size, n_workers);
        var scratches: ?[]row_executor.Scratch = null;
        var scratch_initialized: usize = 0;
        defer if (scratches) |values| {
            for (values[0..scratch_initialized]) |*scratch| scratch.deinit(allocator);
            allocator.free(values);
        };
        if (use_batched_inversion) {
            scratches = try allocator.alloc(row_executor.Scratch, n_workers);
            for (scratches.?) |*scratch| {
                scratch.* = row_executor.initParallelScratch(
                    allocator,
                    self.prepared.sample_batches.len,
                    @min(worker_span, row_executor.MAX_ROWS),
                    self.domain_size,
                ) catch |err| switch (err) {
                    error.ParallelUnavailable => return null,
                    else => return err,
                };
                scratch_initialized += 1;
            }
        }

        var work_items: [work_pool_mod.MAX_WORKERS]row_executor.StreamingWork = undefined;
        for (0..n_workers) |worker| {
            const worker_range = try row_executor.workerRange(self.domain_size, worker_span, worker);
            const writer = if (factory) |active|
                try active.prepareWriter(worker, .{
                    .start = worker_range.start,
                    .end = worker_range.end,
                })
            else
                null;
            work_items[worker] = .{
                .out_columns = out.columns,
                .start = worker_range.start,
                .end = worker_range.end,
                .workspace = &workspaces[worker],
                .scratch = if (scratches) |values| &values[worker] else null,
                .domain = self.domain,
                .combined_views = self.combined_views,
                .quotient_constants = &self.prepared.quotient_constants,
                .lifting_log_size = self.lifting_log_size,
                .tile_writer = writer,
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
        if (factory) |active| try active.finishWriters(n_workers);

        var tile_count: usize = 0;
        for (work_items[0..n_workers]) |item| tile_count += item.completed_tiles;
        var total_scratch_bytes: usize = 0;
        var peak_scratch_bytes: usize = 0;
        if (scratches) |values| {
            for (values) |scratch| {
                const retained = scratch.retainedBytes();
                total_scratch_bytes = std.math.add(usize, total_scratch_bytes, retained) catch
                    return error.ScratchSizeOverflow;
                peak_scratch_bytes = @max(peak_scratch_bytes, retained);
            }
        }
        return .{
            .tile_pipeline_selected = factory != null,
            .worker_count = n_workers,
            .tile_row_limit = tile_sink.DEFAULT_TILE_ROWS,
            .tile_count = tile_count,
            .peak_scratch_bytes_per_worker = peak_scratch_bytes,
            .total_scratch_bytes = total_scratch_bytes,
            .bounded_numerator_tile_bytes_per_worker = 0,
            .complete_column_combined_intermediate_bytes = if (factory != null)
                try self.combinedIntermediateBytes()
            else
                0,
            .post_compute_leaf_pass_count = if (factory == null) 1 else 0,
        };
    }

    fn computeAllParallelDirect(
        self: *const LazyQuotientProvider,
        allocator: std.mem.Allocator,
        out: *SecureColumnByCoords,
        factory: ?tile_sink.Factory,
    ) !?tile_sink.ExecutionStats {
        return tile_executor.executeParallel(allocator, .{
            .out_columns = out.columns,
            .domain_size = self.domain_size,
            .sample_batches = self.prepared.sample_batches,
            .use_batched_inversion = self.direct_chunk_scratch != null,
            .allow_parallel_scalar = self.allow_parallel_scalar,
            .domain = self.domain,
            .compact_groups = self.compact_plan.groups,
            .column_views = self.direct_plan.views,
            .contribution_ranges = self.direct_plan.ranges,
            .contributions = self.prepared.contribution_plan.contributions,
            .quotient_constants = &self.prepared.quotient_constants,
            .lifting_log_size = self.lifting_log_size,
            .factory = factory,
            .combined_intermediate_bytes = try self.combinedIntermediateBytes(),
        });
    }
};
