//! Batched circle interpolation and evaluation for PCS columns.

const std = @import("std");
const builtin = @import("builtin");
const m31 = @import("stwo_core").fields.m31;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover_circle = @import("../../poly/circle/mod.zig");
const twiddle_source_mod = @import("../../poly/twiddle_source.zig");
const twiddles_mod = @import("../../poly/twiddles.zig");
const work_pool_mod = @import("../../work_pool.zig");
const commitment_tree = @import("../commitment_tree.zig");
const column_storage = @import("storage.zig");

const M31 = m31.M31;
const ColumnEvaluation = commitment_tree.ColumnEvaluation;
const TwiddleSource = twiddle_source_mod.TwiddleSource;
const fft_batch_target_bytes: usize = 256 * 1024;

pub const InterpolatedCoefficients = struct {
    coefficients: []prover_circle.CircleCoefficients,
    /// Contiguous backing buffers for batched coefficients. Each entry is a
    /// single allocation whose sub-slices are borrowed by the corresponding
    /// CircleCoefficients (owns_coeffs == false). Must be freed separately.
    backing_buffers: [][]M31,

    fn deinit(self: *InterpolatedCoefficients, allocator: std.mem.Allocator) void {
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
        const twiddle_tree = try twiddle_source.get(allocator, group.log_size);
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
        const twiddle_tree = try twiddle_source.get(allocator, group.log_size);
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
            try B.interpolateCircleBuffers(allocator, item.values, item.domain, item.twiddle_tree);
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

    return out;
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
    /// Number of unwritten, degenerate largest-block layers in the power-of-two
    /// extension. Supported fast paths are 1 (2x) and 2 (4x).
    extension_layers: u32 = 0,
};

fn fftEvalWorker(item: *const FftEvalWorkItem) void {
    switch (item.extension_layers) {
        1 => {
            prover_circle.poly.evaluateExtensionBuffersWithTwiddles(
                item.values,
                item.domain,
                item.twiddle_tree,
            ) catch {};
            return;
        },
        2 => {
            prover_circle.poly.evaluateFourfoldExtensionBuffersWithTwiddles(
                item.values,
                item.domain,
                item.twiddle_tree,
            ) catch {};
            return;
        },
        else => {},
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
        const twiddle_tree = try twiddle_source.get(allocator, extended_log_size);
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

            var batch_extension_layers: u32 = 0;
            for (group.indices.items[batch_start .. batch_start + chunk_len], 0..) |idx, bi| {
                const values = try allocator.alloc(M31, domain_size);
                const coeff_slice = coeffs[idx].coefficients();
                @memcpy(values[0..coeff_slice.len], coeff_slice);
                const extension_layers: u32 = if (coeff_slice.len * 4 == values.len)
                    2
                else if (coeff_slice.len * 2 == values.len)
                    1
                else
                    0;
                if (bi == 0) {
                    batch_extension_layers = extension_layers;
                } else if (batch_extension_layers != extension_layers) {
                    batch_extension_layers = 0;
                }
                if (extension_layers == 0) {
                    if (coeff_slice.len < values.len) @memset(values[coeff_slice.len..], M31.zero());
                }
                batch_values[bi] = values;
                out[idx] = .{
                    .log_size = extended_log_size,
                    .values = values,
                };
            }
            if (batch_extension_layers == 0) {
                for (batch_values, group.indices.items[batch_start .. batch_start + chunk_len]) |values, idx| {
                    const coeff_slice = coeffs[idx].coefficients();
                    if (coeff_slice.len < values.len) @memset(values[coeff_slice.len..], M31.zero());
                }
            }

            total_columns += chunk_len;

            try work_value_slices.append(allocator, batch_values);
            try work_items.append(allocator, .{
                .values = batch_values,
                .domain = domain,
                .twiddle_tree = twiddle_tree,
                .extension_layers = batch_extension_layers,
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
            try B.evaluateCircleBuffers(allocator, item.values, item.domain, item.twiddle_tree);
        }
        return out;
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
            return out;
        }
    }

    // Sequential fallback.
    for (work_items.items) |*item| {
        fftEvalWorker(item);
    }

    return out;
}

fn materializeBackendExtensionZeros(work_items: []const FftEvalWorkItem) void {
    for (work_items) |item| {
        if (item.extension_layers == 0) continue;
        for (item.values) |values| {
            const initialized_len = values.len >> @intCast(item.extension_layers);
            @memset(values[initialized_len..], M31.zero());
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

test "circle transforms: CPU FFT batch exposes one task per worker" {
    try std.testing.expectEqual(
        @as(usize, 8),
        preferredCpuFftBatchLenForWorkers(16, 32, 4),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        preferredCpuFftBatchLenForWorkers(16, 4, 12),
    );
    try std.testing.expectEqual(
        @as(usize, 16),
        preferredCpuFftBatchLenForWorkers(16, 64, 2),
    );
}

test "circle transforms: backend extension buffers materialize implicit zeros" {
    const allocator = std.testing.allocator;
    const twofold_values = try allocator.alloc(M31, 16);
    defer allocator.free(twofold_values);
    const fourfold_values = try allocator.alloc(M31, 16);
    defer allocator.free(fourfold_values);
    @memset(twofold_values, M31.fromCanonical(0x5a5a));
    @memset(fourfold_values, M31.fromCanonical(0x5a5a));

    var twofold_slices = [_][]M31{twofold_values};
    var fourfold_slices = [_][]M31{fourfold_values};
    const items = [_]FftEvalWorkItem{
        .{
            .values = twofold_slices[0..],
            .domain = canonic.CanonicCoset.new(4).circleDomain(),
            .twiddle_tree = undefined,
            .extension_layers = 1,
        },
        .{
            .values = fourfold_slices[0..],
            .domain = canonic.CanonicCoset.new(4).circleDomain(),
            .twiddle_tree = undefined,
            .extension_layers = 2,
        },
    };
    materializeBackendExtensionZeros(items[0..]);

    for (twofold_values[0..8]) |value| try std.testing.expectEqual(M31.fromCanonical(0x5a5a), value);
    for (twofold_values[8..]) |value| try std.testing.expectEqual(M31.zero(), value);
    for (fourfold_values[0..4]) |value| try std.testing.expectEqual(M31.fromCanonical(0x5a5a), value);
    for (fourfold_values[4..]) |value| try std.testing.expectEqual(M31.zero(), value);
}

test "circle transforms: batched fourfold extension matches explicit zero padding" {
    const allocator = std.testing.allocator;
    var domain_log_size: u32 = 5;
    while (domain_log_size <= 12) : (domain_log_size += 1) {
        const domain = canonic.CanonicCoset.new(domain_log_size).circleDomain();
        const domain_size = domain.size();
        const coefficient_len = domain_size / 4;
        const sentinel = M31.fromCanonical(0x5a5a);

        const explicit_a = try allocator.alloc(M31, domain_size);
        defer allocator.free(explicit_a);
        const explicit_b = try allocator.alloc(M31, domain_size);
        defer allocator.free(explicit_b);
        const candidate_a = try allocator.alloc(M31, domain_size);
        defer allocator.free(candidate_a);
        const candidate_b = try allocator.alloc(M31, domain_size);
        defer allocator.free(candidate_b);

        for (0..coefficient_len) |index| {
            const value_a = M31.fromCanonical(@intCast((index * 29 + 17) % m31.Modulus));
            const value_b = M31.fromCanonical(@intCast((index * 43 + 11) % m31.Modulus));
            explicit_a[index] = value_a;
            candidate_a[index] = value_a;
            explicit_b[index] = value_b;
            candidate_b[index] = value_b;
        }
        @memset(explicit_a[coefficient_len..], M31.zero());
        @memset(explicit_b[coefficient_len..], M31.zero());
        @memset(candidate_a[coefficient_len..], sentinel);
        @memset(candidate_b[coefficient_len..], sentinel);

        var twiddle_tree = try twiddles_mod.precomputeM31(allocator, domain.half_coset);
        defer twiddles_mod.deinitM31(allocator, &twiddle_tree);
        const twiddles: twiddles_mod.TwiddleTree([]const M31) = .{
            .root_coset = twiddle_tree.root_coset,
            .twiddles = twiddle_tree.twiddles,
            .itwiddles = twiddle_tree.itwiddles,
        };
        var explicit_batch = [_][]M31{ explicit_a, explicit_b };
        var candidate_batch = [_][]M31{ candidate_a, candidate_b };
        try prover_circle.poly.evaluateBuffersWithTwiddles(
            explicit_batch[0..],
            domain,
            twiddles,
        );
        try prover_circle.poly.evaluateFourfoldExtensionBuffersWithTwiddles(
            candidate_batch[0..],
            domain,
            twiddles,
        );

        try std.testing.expectEqualSlices(M31, explicit_a, candidate_a);
        try std.testing.expectEqualSlices(M31, explicit_b, candidate_b);
    }
}
