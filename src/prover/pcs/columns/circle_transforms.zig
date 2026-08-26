//! Batched circle interpolation and evaluation for PCS columns.

const std = @import("std");
const builtin = @import("builtin");
const m31 = @import("stwo_core").fields.m31;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover_circle = @import("../../poly/circle/mod.zig");
const work_profile = @import("stwo_prover_api").work_profile;
const twiddle_source_mod = @import("../../poly/twiddle_source.zig");
const twiddles_mod = @import("../../poly/twiddles.zig");
const work_pool_mod = @import("../../work_pool.zig");
const commitment_tree = @import("../commitment_tree.zig");
const column_storage = @import("storage.zig");

const M31 = m31.M31;
const ColumnEvaluation = commitment_tree.ColumnEvaluation;
const TwiddleSource = twiddle_source_mod.TwiddleSource;
const WorkRecorder = work_profile.Recorder(true);
const fft_batch_target_bytes: usize = 256 * 1024;

pub const InterpolatedCoefficients = struct {
    coefficients: []prover_circle.CircleCoefficients,
    /// Contiguous backing buffers for batched coefficients. Each entry is a
    /// single allocation whose sub-slices are borrowed by the corresponding
    /// CircleCoefficients (owns_coeffs == false). Must be freed separately.
    backing_buffers: [][]M31,

    pub fn deinit(self: *InterpolatedCoefficients, allocator: std.mem.Allocator) void {
        for (self.coefficients) |*coeff| {
            @constCast(coeff).deinit(allocator);
        }
        allocator.free(self.coefficients);
        for (self.backing_buffers) |buf| allocator.free(buf);
        allocator.free(self.backing_buffers);
        self.* = undefined;
    }
};

pub fn interpolateCoefficientColumns(
    allocator: std.mem.Allocator,
    columns: []const ColumnEvaluation,
    twiddle_source: *TwiddleSource,
    work_recorder: ?*WorkRecorder,
) !InterpolatedCoefficients {
    const out = try allocator.alloc(prover_circle.CircleCoefficients, columns.len);

    var backing_buffers = std.ArrayList([]M31).empty;
    defer backing_buffers.deinit(allocator);

    var initialized_indices = std.ArrayList(usize).empty;
    defer initialized_indices.deinit(allocator);
    errdefer {
        // Individually-owned coefficients (from the single-column path)
        // are freed via deinit; borrowed coefficients (from the batch path)
        // are no-ops since their data lives in backing_buffers.
        for (initialized_indices.items) |idx| out[idx].deinit(allocator);
        for (backing_buffers.items) |buf| allocator.free(buf);
        allocator.free(out);
    }

    var groups = try buildLogSizeGroupsFromColumns(allocator, columns);
    defer deinitLogSizeGroups(allocator, &groups);

    // --- Phase 1: pre-allocate contiguous buffers and copy column data ---
    const InterpBatchMeta = struct {
        group_indices_start: usize,
        group_indices_end: usize,
        group_item_idx: usize,
    };

    var work_items = std.ArrayList(IfftWorkItem).empty;
    defer work_items.deinit(allocator);

    var work_meta = std.ArrayList(InterpBatchMeta).empty;
    defer work_meta.deinit(allocator);

    var work_value_slices = std.ArrayList([][]M31).empty;
    defer {
        for (work_value_slices.items) |s| allocator.free(s);
        work_value_slices.deinit(allocator);
    }

    var total_columns: usize = 0;

    for (groups.items, 0..) |group, group_idx| {
        const twiddle_tree = try twiddle_source.getWithWorkRecorder(
            allocator,
            group.log_size,
            work_recorder,
        );
        const domain = canonic.CanonicCoset.new(group.log_size).circleDomain();
        const batch_len = preferredCpuFftBatchLen(domain.size(), group.indices.items.len);
        var batch_start: usize = 0;
        while (batch_start < group.indices.items.len) : (batch_start += batch_len) {
            const chunk_len = @min(batch_len, group.indices.items.len - batch_start);

            // Allocate a single contiguous buffer for the entire batch instead
            // of chunk_len separate allocations. This reduces allocator overhead
            // and keeps FFT working data cache-contiguous.
            const domain_size = domain.size();
            const batch_buffer = try allocator.alloc(M31, chunk_len * domain_size);

            // Track the contiguous buffer immediately so the outer errdefer
            // handles cleanup on any subsequent failure.
            backing_buffers.append(allocator, batch_buffer) catch |err| {
                allocator.free(batch_buffer);
                return err;
            };

            const batch_values = try allocator.alloc([]M31, chunk_len);
            errdefer allocator.free(batch_values);

            for (group.indices.items[batch_start .. batch_start + chunk_len], 0..) |idx, batch_idx| {
                const slice = batch_buffer[batch_idx * domain_size .. (batch_idx + 1) * domain_size];
                @memcpy(slice, columns[idx].values);
                batch_values[batch_idx] = slice;
            }

            total_columns += chunk_len;

            try work_value_slices.append(allocator, batch_values);
            try work_items.append(allocator, .{
                .values = batch_values,
                .domain = domain,
                .twiddle_tree = twiddle_tree,
            });
            try work_meta.append(allocator, .{
                .group_indices_start = batch_start,
                .group_indices_end = batch_start + chunk_len,
                .group_item_idx = group_idx,
            });
        }
    }

    // --- Phase 2: run IFFT on all buffers ---
    const use_parallel = !builtin.single_threaded and
        work_items.items.len > 1 and
        total_columns >= 4;

    if (use_parallel) {
        if (getOrInitFftPool()) |pool| {
            var wait_group: std.Thread.WaitGroup = .{};
            for (work_items.items[1..]) |*item| {
                pool.spawnWg(&wait_group, ifftWorker, .{item});
            }
            ifftWorker(&work_items.items[0]);
            wait_group.wait();
        } else {
            for (work_items.items) |*item| {
                ifftWorker(item);
            }
        }
    } else {
        for (work_items.items) |*item| {
            ifftWorker(item);
        }
    }

    // --- Phase 3: wrap results into CircleCoefficients (main thread) ---
    for (work_meta.items, 0..) |meta, wi| {
        const group = groups.items[meta.group_item_idx];
        const batch_values = work_items.items[wi].values;
        for (group.indices.items[meta.group_indices_start..meta.group_indices_end], 0..) |idx, bi| {
            out[idx] = try prover_circle.CircleCoefficients.initBorrowed(batch_values[bi]);
            try initialized_indices.append(allocator, idx);
        }
    }

    try recordInterpolationCompletion(
        work_recorder,
        .column_interpolate_only_fft,
        work_items.items,
        true,
    );
    const owned_backing = try backing_buffers.toOwnedSlice(allocator);
    return .{
        .coefficients = out,
        .backing_buffers = owned_backing,
    };
}

pub fn interpolateOwnedColumnsForExtensionForBackend(
    comptime B: type,
    allocator: std.mem.Allocator,
    owned_columns: []ColumnEvaluation,
    twiddle_source: *TwiddleSource,
    work_recorder: ?*WorkRecorder,
) ![]prover_circle.CircleCoefficients {
    const out = try allocator.alloc(prover_circle.CircleCoefficients, owned_columns.len);
    errdefer allocator.free(out);

    var initialized_indices = std.ArrayList(usize).empty;
    defer initialized_indices.deinit(allocator);
    errdefer {
        for (initialized_indices.items) |idx| out[idx].deinit(allocator);
        allocator.free(out);
    }

    var groups = try buildLogSizeGroupsFromColumns(allocator, owned_columns);
    defer deinitLogSizeGroups(allocator, &groups);

    // --- Phase 1: collect IFFT work items (buffers are already allocated) ---
    const IfftBatchMeta = struct {
        group_indices_start: usize,
        group_indices_end: usize,
        group_item_idx: usize,
    };

    var work_items = std.ArrayList(IfftWorkItem).empty;
    defer work_items.deinit(allocator);

    var work_meta = std.ArrayList(IfftBatchMeta).empty;
    defer work_meta.deinit(allocator);

    var work_value_slices = std.ArrayList([][]M31).empty;
    defer {
        for (work_value_slices.items) |s| allocator.free(s);
        work_value_slices.deinit(allocator);
    }

    var total_columns: usize = 0;

    for (groups.items, 0..) |group, group_idx| {
        const twiddle_tree = try twiddle_source.getWithWorkRecorder(
            allocator,
            group.log_size,
            work_recorder,
        );
        const domain = canonic.CanonicCoset.new(group.log_size).circleDomain();
        const batch_len = if (comptime @hasDecl(B, "interpolateCircleBuffers"))
            group.indices.items.len
        else
            preferredCpuFftBatchLen(domain.size(), group.indices.items.len);
        var batch_start: usize = 0;
        while (batch_start < group.indices.items.len) : (batch_start += batch_len) {
            const chunk_len = @min(batch_len, group.indices.items.len - batch_start);

            const batch_values = try allocator.alloc([]M31, chunk_len);
            errdefer allocator.free(batch_values);

            for (group.indices.items[batch_start .. batch_start + chunk_len], 0..) |idx, bi| {
                batch_values[bi] = @constCast(owned_columns[idx].values);
            }

            total_columns += chunk_len;

            try work_value_slices.append(allocator, batch_values);
            try work_items.append(allocator, .{
                .values = batch_values,
                .domain = domain,
                .twiddle_tree = twiddle_tree,
            });
            try work_meta.append(allocator, .{
                .group_indices_start = batch_start,
                .group_indices_end = batch_start + chunk_len,
                .group_item_idx = group_idx,
            });
        }
    }

    // --- Phase 2: run IFFT on all buffers ---
    const use_parallel = !builtin.single_threaded and
        work_items.items.len > 1 and
        total_columns >= 4;

    if (comptime @hasDecl(B, "interpolateCircleBuffers")) {
        for (work_items.items) |*item| {
            item.backend_execution = try B.interpolateCircleBuffers(
                allocator,
                item.values,
                item.domain,
                item.twiddle_tree,
            );
        }
    } else if (use_parallel) {
        if (getOrInitFftPool()) |pool| {
            var wait_group: std.Thread.WaitGroup = .{};
            for (work_items.items[1..]) |*item| {
                pool.spawnWg(&wait_group, ifftWorker, .{item});
            }
            ifftWorker(&work_items.items[0]);
            wait_group.wait();
        } else {
            for (work_items.items) |*item| {
                ifftWorker(item);
            }
        }
    } else {
        for (work_items.items) |*item| {
            ifftWorker(item);
        }
    }

    // --- Phase 3: wrap results into CircleCoefficients (main thread) ---
    for (work_meta.items, 0..) |meta, wi| {
        const group = groups.items[meta.group_item_idx];
        const batch_values = work_items.items[wi].values;
        for (group.indices.items[meta.group_indices_start..meta.group_indices_end], 0..) |idx, bi| {
            out[idx] = try prover_circle.CircleCoefficients.initOwned(batch_values[bi]);
            owned_columns[idx].values = &[_]M31{};
            try initialized_indices.append(allocator, idx);
        }
    }

    try recordInterpolationCompletion(
        work_recorder,
        .column_interpolate_for_extension_fft,
        work_items.items,
        comptime !@hasDecl(B, "interpolateCircleBuffers"),
    );

    return out;
}

fn recordInterpolationCompletion(
    recorder: ?*WorkRecorder,
    site: work_profile.Site,
    work_items: []const IfftWorkItem,
    comptime generic_execution: bool,
) !void {
    const active = recorder orelse return;
    var counters: work_profile.Counters = .{};
    for (work_items) |item| {
        const batch_columns = std.math.cast(u64, item.values.len) orelse
            return error.CounterOverflow;
        if (generic_execution) {
            counters = try counters.add(try work_profile.logicalM31InterpolationWork(
                item.domain.logSize(),
                batch_columns,
            ));
        } else {
            const execution = item.backend_execution orelse
                return error.InvalidCounterGroup;
            try execution.validate();
            if (execution.log_size != item.domain.logSize() or
                execution.column_count != batch_columns)
            {
                return error.InvalidCounterGroup;
            }
            counters = try counters.add(try execution.exactWork());
        }
    }
    try active.recordCompletedDelta(.{
        .site = site,
        .producer = work_profile.boundaryForSite(site),
        .source_mask = .{ .bits = work_profile.SourceMask.one(.field_additions).bits |
            work_profile.SourceMask.one(.field_multiplications).bits |
            work_profile.SourceMask.one(.field_inversions).bits |
            work_profile.SourceMask.one(.fft_butterflies).bits },
        .counters = counters,
    });
}

// ---------------------------------------------------------------------------
// Parallel FFT infrastructure
// ---------------------------------------------------------------------------

/// Unified work pool shared across FFT, Merkle, and other proving phases.
/// Replaces the previous FFT-specific FftPoolState with a single global pool
/// from work_pool.zig, avoiding duplicate thread pool creation overhead.
fn getOrInitFftPool() ?*std.Thread.Pool {
    const pool = work_pool_mod.getGlobalPool() orelse return null;
    return &pool.pool;
}

/// A self-contained work item for parallel forward-FFT evaluation.
/// Each item references a sub-slice of pre-allocated value buffers that share
/// the same domain and twiddle tree, so the worker performs pure in-place
/// computation with no allocator interaction.
const FftEvalWorkItem = struct {
    values: [][]M31,
    domain: prover_circle.CircleDomain,
    twiddle_tree: twiddles_mod.TwiddleTree([]const M31),
    /// Upper halves are unwritten and mathematically zero (2x extension);
    /// the worker uses the degenerate-first-layer path.
    extension: bool = false,
    /// Populated only by a selected backend transform. It prevents the caller
    /// from inferring device layer execution from input geometry.
    backend_execution: ?work_profile.M31ForwardFftExecution = null,
};

fn fftEvalWorker(item: *const FftEvalWorkItem) void {
    if (item.extension) {
        prover_circle.poly.evaluateExtensionBuffersWithTwiddles(
            item.values,
            item.domain,
            item.twiddle_tree,
        ) catch {};
        return;
    }
    prover_circle.poly.evaluateBuffersWithTwiddles(
        item.values,
        item.domain,
        item.twiddle_tree,
    ) catch {};
}

/// A self-contained work item for parallel inverse-FFT (interpolation).
const IfftWorkItem = struct {
    values: [][]M31,
    domain: prover_circle.CircleDomain,
    twiddle_tree: twiddles_mod.TwiddleTree([]const M31),
    /// Populated only by a selected backend transform. Generic host work is
    /// derived from the live batch item instead.
    backend_execution: ?work_profile.M31InterpolationExecution = null,
};

fn ifftWorker(item: *const IfftWorkItem) void {
    prover_circle.poly.interpolateBuffersWithTwiddles(
        item.values,
        item.domain,
        item.twiddle_tree,
    ) catch {};
}

// ---------------------------------------------------------------------------

pub fn extendCoefficientColumnsByGroupForBackend(
    comptime B: type,
    allocator: std.mem.Allocator,
    coeffs: []const prover_circle.CircleCoefficients,
    log_blowup_factor: u32,
    twiddle_source: *TwiddleSource,
    work_recorder: ?*WorkRecorder,
    completion_site: work_profile.Site,
) ![]ColumnEvaluation {
    const out = try allocator.alloc(ColumnEvaluation, coeffs.len);
    errdefer allocator.free(out);
    for (out) |*column| {
        column.* = .{
            .log_size = 0,
            .values = &[_]M31{},
        };
    }
    errdefer {
        for (out) |column| {
            if (column.values.len != 0) allocator.free(column.values);
        }
        allocator.free(out);
    }

    var groups = try buildLogSizeGroupsFromCoefficients(allocator, coeffs);
    defer deinitLogSizeGroups(allocator, &groups);

    // --- Phase 1: pre-allocate output buffers and copy coefficient data ---
    // We collect all (buffer-slice, domain, twiddle) tuples so that the FFT
    // phase can run without any allocator interaction.

    var work_items = std.ArrayList(FftEvalWorkItem).empty;
    defer work_items.deinit(allocator);

    // Temporary storage for the per-work-item value-slice arrays. Each
    // entry is an allocated [][]M31 that must be freed after use.
    var work_value_slices = std.ArrayList([][]M31).empty;
    defer {
        for (work_value_slices.items) |s| allocator.free(s);
        work_value_slices.deinit(allocator);
    }

    var total_columns: usize = 0;

    for (groups.items) |group| {
        const extended_log_size = std.math.add(u32, group.log_size, log_blowup_factor) catch
            return error.ShapeMismatch;
        const twiddle_tree = try twiddle_source.getWithWorkRecorder(
            allocator,
            extended_log_size,
            work_recorder,
        );
        const domain = canonic.CanonicCoset.new(extended_log_size).circleDomain();
        const domain_size = domain.size();

        const batch_len = if (comptime @hasDecl(B, "evaluateCircleBuffers"))
            group.indices.items.len
        else
            preferredCpuFftBatchLen(domain_size, group.indices.items.len);
        var batch_start: usize = 0;
        while (batch_start < group.indices.items.len) : (batch_start += batch_len) {
            const chunk_len = @min(batch_len, group.indices.items.len - batch_start);

            // Allocate value-buffer slice for this batch.
            const batch_values = try allocator.alloc([]M31, chunk_len);
            errdefer allocator.free(batch_values);

            var batch_extension = chunk_len > 0;
            for (group.indices.items[batch_start .. batch_start + chunk_len], 0..) |idx, bi| {
                const values = try allocator.alloc(M31, domain_size);
                const coeff_slice = coeffs[idx].coefficients();
                @memcpy(values[0..coeff_slice.len], coeff_slice);
                if (coeff_slice.len * 2 != values.len) {
                    batch_extension = false;
                    if (coeff_slice.len < values.len) @memset(values[coeff_slice.len..], M31.zero());
                }
                batch_values[bi] = values;
                out[idx] = .{
                    .log_size = extended_log_size,
                    .values = values,
                };
            }
            if (!batch_extension) {
                for (batch_values, group.indices.items[batch_start .. batch_start + chunk_len]) |values, idx| {
                    const coeff_slice = coeffs[idx].coefficients();
                    if (coeff_slice.len * 2 == values.len) @memset(values[coeff_slice.len..], M31.zero());
                }
            }

            total_columns += chunk_len;

            try work_value_slices.append(allocator, batch_values);
            try work_items.append(allocator, .{
                .values = batch_values,
                .domain = domain,
                .twiddle_tree = twiddle_tree,
                .extension = batch_extension,
            });
        }
    }

    // --- Phase 2: run FFT on all pre-allocated buffers ---
    const use_parallel = !builtin.single_threaded and
        work_items.items.len > 1 and
        total_columns >= 4;

    if (comptime @hasDecl(B, "evaluateCircleBuffers")) {
        // The CPU extension transform treats an unwritten upper half as
        // implicit zero. Generic backend hooks receive ordinary full buffers,
        // so materialize that invariant before they can read or upload them.
        materializeBackendExtensionZeros(work_items.items);
        for (work_items.items) |*item| {
            item.backend_execution = try B.evaluateCircleBuffers(
                allocator,
                item.values,
                item.domain,
                item.twiddle_tree,
            );
        }
    } else if (use_parallel) {
        if (getOrInitFftPool()) |pool| {
            var wait_group: std.Thread.WaitGroup = .{};
            // Dispatch all but the first item to the pool; process the first
            // item on the calling thread to keep it busy.
            for (work_items.items[1..]) |*item| {
                pool.spawnWg(&wait_group, fftEvalWorker, .{item});
            }
            fftEvalWorker(&work_items.items[0]);
            wait_group.wait();
        } else {
            for (work_items.items) |*item| fftEvalWorker(item);
        }
    } else {
        // Sequential fallback.
        for (work_items.items) |*item| fftEvalWorker(item);
    }

    try recordForwardCompletion(
        work_recorder,
        completion_site,
        work_items.items,
        comptime @hasDecl(B, "evaluateCircleBuffers"),
    );
    return out;
}

fn recordForwardCompletion(
    recorder: ?*WorkRecorder,
    site: work_profile.Site,
    work_items: []const FftEvalWorkItem,
    comptime backend_execution: bool,
) !void {
    const active = recorder orelse return;
    var butterflies: u64 = 0;
    for (work_items) |item| {
        const column_count = std.math.cast(u64, item.values.len) orelse
            return error.CounterOverflow;
        const execution = if (backend_execution) blk: {
            const completed = item.backend_execution orelse
                return error.InvalidCounterGroup;
            try completed.validate();
            if (completed.log_size != item.domain.logSize() or
                completed.column_count != column_count)
            {
                return error.InvalidCounterGroup;
            }
            break :blk completed;
        } else work_profile.M31ForwardFftExecution{
            .log_size = item.domain.logSize(),
            .column_count = column_count,
            .skipped_layers = if (item.extension) 1 else 0,
        };
        butterflies = std.math.add(
            u64,
            butterflies,
            (try execution.exactWork()).fft_butterflies,
        ) catch return error.CounterOverflow;
    }
    const fields = try work_profile.logicalM31ForwardFftFieldOperations(butterflies);
    try active.recordCompletedDelta(.{
        .site = site,
        .producer = work_profile.boundaryForSite(site),
        .source_mask = .{ .bits = work_profile.SourceMask.one(.field_additions).bits |
            work_profile.SourceMask.one(.field_multiplications).bits |
            work_profile.SourceMask.one(.field_inversions).bits |
            work_profile.SourceMask.one(.fft_butterflies).bits },
        .counters = .{
            .field_additions = fields.additions,
            .field_multiplications = fields.multiplications,
            .field_inversions = fields.inversions,
            .fft_butterflies = butterflies,
        },
    });
}

fn materializeBackendExtensionZeros(work_items: []const FftEvalWorkItem) void {
    for (work_items) |item| {
        if (!item.extension) continue;
        for (item.values) |values| {
            @memset(values[values.len / 2 ..], M31.zero());
        }
    }
}

fn interpolateSingleCoefficientColumn(
    allocator: std.mem.Allocator,
    column: ColumnEvaluation,
    twiddle_source: *TwiddleSource,
) !prover_circle.CircleCoefficients {
    const domain = canonic.CanonicCoset.new(column.log_size).circleDomain();
    const twiddle_tree = try twiddle_source.get(allocator, column.log_size);
    const evaluation = try prover_circle.CircleEvaluation.init(domain, column.values);
    return prover_circle.poly.interpolateFromEvaluationWithTwiddles(
        allocator,
        evaluation,
        twiddle_tree,
    );
}

fn interpolateOwnedSingleCoefficientColumn(
    allocator: std.mem.Allocator,
    column: ColumnEvaluation,
    twiddle_source: *TwiddleSource,
) !prover_circle.CircleCoefficients {
    const domain = canonic.CanonicCoset.new(column.log_size).circleDomain();
    const twiddle_tree = try twiddle_source.get(allocator, column.log_size);
    return prover_circle.poly.interpolateOwnedValuesWithTwiddles(
        domain,
        @constCast(column.values),
        twiddle_tree,
    );
}

pub const LogSizeGroup = struct {
    log_size: u32,
    indices: std.ArrayList(usize),

    fn deinit(self: *LogSizeGroup, allocator: std.mem.Allocator) void {
        self.indices.deinit(allocator);
        self.* = undefined;
    }
};

pub fn buildLogSizeGroupsFromColumns(
    allocator: std.mem.Allocator,
    columns: []const ColumnEvaluation,
) !std.ArrayList(LogSizeGroup) {
    var groups = std.ArrayList(LogSizeGroup).empty;
    errdefer deinitLogSizeGroups(allocator, &groups);

    for (columns, 0..) |column, idx| {
        try appendLogSizeGroupIndex(allocator, &groups, column.log_size, idx);
    }
    return groups;
}

fn buildLogSizeGroupsFromCoefficients(
    allocator: std.mem.Allocator,
    coeffs: []const prover_circle.CircleCoefficients,
) !std.ArrayList(LogSizeGroup) {
    var groups = std.ArrayList(LogSizeGroup).empty;
    errdefer deinitLogSizeGroups(allocator, &groups);

    for (coeffs, 0..) |coeff, idx| {
        try appendLogSizeGroupIndex(allocator, &groups, coeff.logSize(), idx);
    }
    return groups;
}

fn appendLogSizeGroupIndex(
    allocator: std.mem.Allocator,
    groups: *std.ArrayList(LogSizeGroup),
    log_size: u32,
    idx: usize,
) !void {
    for (groups.items, 0..) |group, group_idx| {
        if (group.log_size == log_size) {
            try groups.items[group_idx].indices.append(allocator, idx);
            return;
        }
    }

    try groups.append(allocator, .{
        .log_size = log_size,
        .indices = std.ArrayList(usize).empty,
    });
    try groups.items[groups.items.len - 1].indices.append(allocator, idx);
}

pub fn deinitLogSizeGroups(
    allocator: std.mem.Allocator,
    groups: *std.ArrayList(LogSizeGroup),
) void {
    for (groups.items) |*group| group.deinit(allocator);
    groups.deinit(allocator);
}

fn preferredFftBatchLen(value_len: usize) usize {
    const value_bytes = std.math.mul(usize, value_len, @sizeOf(M31)) catch return 1;
    if (value_bytes == 0) return 1;
    const max_batch = fft_batch_target_bytes / value_bytes;
    return std.math.clamp(max_batch, 1, 32);
}

fn preferredCpuFftBatchLen(value_len: usize, column_count: usize) usize {
    const cache_batch = preferredFftBatchLen(value_len);
    if (value_len < 4096 or column_count < 2) return cache_batch;

    const pool = work_pool_mod.getGlobalPool() orelse return cache_batch;
    return preferredCpuFftBatchLenForWorkers(
        cache_batch,
        column_count,
        pool.workerCount(),
    );
}

fn preferredCpuFftBatchLenForWorkers(
    cache_batch: usize,
    column_count: usize,
    worker_count: usize,
) usize {
    std.debug.assert(worker_count != 0);
    const columns_per_worker = (column_count + worker_count - 1) / worker_count;
    return @min(cache_batch, @max(@as(usize, 1), columns_per_worker));
}

const Root = @This();

pub const testing = if (builtin.is_test) struct {
    pub const IfftWorkItem = Root.IfftWorkItem;
    pub const FftEvalWorkItem = Root.FftEvalWorkItem;
    pub const preferredCpuFftBatchLenForWorkers = Root.preferredCpuFftBatchLenForWorkers;
    pub const recordInterpolationCompletion = Root.recordInterpolationCompletion;
    pub const recordForwardCompletion = Root.recordForwardCompletion;
    pub const materializeBackendExtensionZeros = Root.materializeBackendExtensionZeros;
} else struct {};
