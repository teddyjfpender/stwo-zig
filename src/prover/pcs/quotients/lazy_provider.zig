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
const quotient_work = @import("../quotient_work_profile.zig");
const secure_column = @import("../../secure_column.zig");
const work_pool_mod = @import("../../work_pool.zig");
const work_profile = @import("stwo_prover_api").work_profile;

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
    work_recorder: ?*quotient_work.WorkRecorder,
    row_work_tally: quotient_work.Tally,
    row_work_next: usize,
    row_work_path: ?work_profile.QuotientRowPath,
    row_work_contribution_count: usize,
    row_work_completed: bool,

    const InitOps = @import("lazy_provider_init.zig").InitOps(@This(), InputMode);
    pub const init = InitOps.init;
    pub const initWithMode = InitOps.initWithMode;
    pub const initForBackend = InitOps.initForBackend;
    pub const initForBackendWithWorkRecorder = InitOps.initForBackendWithWorkRecorder;
    pub const initForBackendWithMode = InitOps.initForBackendWithMode;

    /// Borrows the proof-session residency set for the lifetime of this
    /// provider. The caller retains ownership of both the slice and handles.
    pub fn setBackendResidencyHandles(
        self: *LazyQuotientProvider,
        handles: []const *anyopaque,
    ) void {
        self.backend_residency_handles = handles;
    }

    pub inline fn rowWorkProfileEnabled(self: *const LazyQuotientProvider) bool {
        return self.work_recorder != null;
    }

    pub fn materializedDomainCircleAdditions(
        self: *const LazyQuotientProvider,
    ) !u64 {
        return quotient_work.materializedDomainCircleAdditions(
            self.domain,
            self.lifting_log_size,
        );
    }

    pub inline fn combinedPlanSourceCells(
        self: *const LazyQuotientProvider,
    ) u64 {
        return self.row_work_tally.combined_plan_source_cells;
    }

    pub inline fn executedContributionCount(
        self: *const LazyQuotientProvider,
    ) usize {
        return self.row_work_contribution_count;
    }

    fn observeHostRowRange(
        self: *LazyQuotientProvider,
        path: work_profile.QuotientRowPath,
        start: usize,
        end: usize,
        tally: quotient_work.Tally,
    ) !void {
        if (self.work_recorder == null) return;
        if (self.row_work_completed or start != self.row_work_next or
            end <= start or end > self.domain_size)
        {
            return error.InvalidRowGeometry;
        }
        if (self.row_work_path) |selected| {
            if (selected != path) return error.InvalidRowGeometry;
        } else {
            self.row_work_path = path;
        }
        try self.row_work_tally.merge(tally);
        self.row_work_next = end;
        if (end != self.domain_size) return;

        const execution_receipt = try quotient_work.executionFromTally(
            path,
            self.lifting_log_size,
            self.prepared.sample_batches.len,
            self.row_work_contribution_count,
            self.combined_views.len,
            0,
            self.row_work_tally,
        );
        try quotient_work.recordRows(self.work_recorder, execution_receipt);
        self.row_work_completed = true;
    }

    pub fn completeMetalRowExecution(
        self: *LazyQuotientProvider,
        execution_receipt: work_profile.QuotientRowExecution,
    ) !void {
        if (self.work_recorder == null) return;
        if (self.row_work_completed or self.row_work_next != 0)
            return error.InvalidRowGeometry;
        try execution_receipt.validate();
        const expected_row_count: u64 = @intCast(self.domain_size);
        const expected_batch_count: u64 = @intCast(self.prepared.sample_batches.len);
        const expected_contribution_count: u64 = @intCast(self.row_work_contribution_count);
        const expected_combined_view_count: u64 = @intCast(self.combined_views.len);
        if (execution_receipt.lifting_log_size != self.lifting_log_size or
            execution_receipt.row_count != expected_row_count or
            execution_receipt.sample_batch_count != expected_batch_count or
            execution_receipt.contribution_count != expected_contribution_count or
            execution_receipt.combined_view_count != expected_combined_view_count or
            execution_receipt.combined_plan_source_cells !=
                self.row_work_tally.combined_plan_source_cells)
        {
            return error.InvalidRowGeometry;
        }
        switch (execution_receipt.path) {
            .metal_combined,
            .metal_raw_direct,
            .metal_raw_segmented,
            .metal_raw_grouped_partials,
            => {},
            else => return error.InvalidRowGeometry,
        }
        try quotient_work.recordRows(self.work_recorder, execution_receipt);
        self.row_work_next = self.domain_size;
        self.row_work_path = execution_receipt.path;
        self.row_work_completed = true;
    }

    fn observeCpuFullExecution(
        self: *LazyQuotientProvider,
        worker_count: usize,
    ) !void {
        if (!self.rowWorkProfileEnabled()) return;
        if (worker_count == 0) return error.InvalidRowGeometry;
        const worker_span = try row_executor.workerSpan(self.domain_size, worker_count);
        var total: quotient_work.Tally = .{};
        var selected_path: work_profile.QuotientRowPath = undefined;
        for (0..worker_count) |worker| {
            const range = try row_executor.workerRange(
                self.domain_size,
                worker_span,
                worker,
            );
            if (range.start == range.end) continue;
            const partial = switch (self.input_mode) {
                .bounded_cpu => blk: {
                    const schedule: quotient_work.InverseSchedule = if (self.direct_chunk_scratch != null) schedule: {
                        const capacity = if (worker_count == 1)
                            self.direct_chunk_scratch.?.row_capacity
                        else
                            try tile_executor.rowCapacityForBatchCount(
                                self.prepared.sample_batches.len,
                                @min(worker_span, tile_sink.DEFAULT_TILE_ROWS),
                            );
                        break :schedule .{ .batched_rows = capacity };
                    } else .scalar_per_row;
                    selected_path = if (self.direct_chunk_scratch != null)
                        .host_bounded_batched
                    else
                        .host_bounded_scalar;
                    break :blk try quotient_work.boundedRangeTally(
                        self.domain,
                        self.lifting_log_size,
                        range.start,
                        range.end,
                        self.prepared.sample_batches.len,
                        self.compact_plan.groups,
                        self.direct_plan.views,
                        self.direct_plan.ranges,
                        schedule,
                    );
                },
                .combined_compatibility => blk: {
                    const schedule: quotient_work.InverseSchedule = if (self.chunk_scratch != null) schedule: {
                        const capacity = if (worker_count == 1)
                            self.chunk_scratch.?.rowCapacity()
                        else
                            try row_executor.rowCapacityForBatchCount(
                                self.prepared.sample_batches.len,
                                @min(worker_span, row_executor.MAX_ROWS),
                            );
                        break :schedule .{ .batched_rows = capacity };
                    } else if (self.prepared.sample_batches.len <= 16)
                        .scalar_chunked
                    else
                        .scalar_per_row;
                    selected_path = .host_streaming;
                    break :blk try quotient_work.streamingRangeTally(
                        self.domain,
                        self.lifting_log_size,
                        range.start,
                        range.end,
                        self.prepared.sample_batches.len,
                        self.combined_views.len,
                        schedule,
                    );
                },
                .raw_backend => return error.UnsupportedQuotientInputMode,
            };
            try total.merge(partial);
        }
        try self.observeHostRowRange(
            selected_path,
            0,
            self.domain_size,
            total,
        );
    }

    pub fn deinit(self: *LazyQuotientProvider, allocator: std.mem.Allocator) void {
        if (self.work_recorder) |active| {
            if (!self.row_work_completed) active.markIncomplete();
        }
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
                if (self.rowWorkProfileEnabled()) {
                    const schedule: quotient_work.InverseSchedule = if (work.scratch) |scratch|
                        .{ .batched_rows = scratch.row_capacity }
                    else
                        .scalar_per_row;
                    const path: work_profile.QuotientRowPath = if (work.scratch != null)
                        .host_bounded_batched
                    else
                        .host_bounded_scalar;
                    const tally = try quotient_work.boundedRangeTally(
                        self.domain,
                        self.lifting_log_size,
                        chunk_start,
                        chunk_end,
                        self.prepared.sample_batches.len,
                        self.compact_plan.groups,
                        self.direct_plan.views,
                        self.direct_plan.ranges,
                        schedule,
                    );
                    try self.observeHostRowRange(path, chunk_start, chunk_end, tally);
                }
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
                if (self.rowWorkProfileEnabled()) {
                    const schedule: quotient_work.InverseSchedule = if (work.scratch) |scratch|
                        .{ .batched_rows = scratch.rowCapacity() }
                    else if (self.prepared.sample_batches.len <= 16)
                        .scalar_chunked
                    else
                        .scalar_per_row;
                    const tally = try quotient_work.streamingRangeTally(
                        self.domain,
                        self.lifting_log_size,
                        chunk_start,
                        chunk_end,
                        self.prepared.sample_batches.len,
                        self.combined_views.len,
                        schedule,
                    );
                    try self.observeHostRowRange(
                        .host_streaming,
                        chunk_start,
                        chunk_end,
                        tally,
                    );
                }
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
            if (try self.computeAllParallel(allocator, out, null)) |stats| {
                try self.observeCpuFullExecution(stats.worker_count);
                return;
            }
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
            if (try self.computeAllParallel(allocator, out, factory)) |stats| {
                try self.observeCpuFullExecution(stats.worker_count);
                return stats;
            }
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
        try self.observeCpuFullExecution(1);
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
