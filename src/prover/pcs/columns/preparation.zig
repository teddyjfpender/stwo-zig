//! Ownership-preserving preparation of PCS columns for commitment.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover_circle = @import("../../poly/circle/mod.zig");
const stage_profile = @import("stwo_prover_api").stage_profile;
const work_profile = @import("stwo_prover_api").work_profile;
const twiddle_source_mod = @import("../../poly/twiddle_source.zig");
const commitment_tree = @import("../commitment_tree.zig");
const circle_transforms = @import("circle_transforms.zig");
const column_storage = @import("storage.zig");

const M31 = m31.M31;
const ColumnEvaluation = commitment_tree.ColumnEvaluation;
const CoefficientRetentionPolicy = column_storage.CoefficientRetentionPolicy;
const PreparedCommitmentColumns = column_storage.PreparedCommitmentColumns;
const TwiddleSource = twiddle_source_mod.TwiddleSource;
const WorkRecorder = work_profile.Recorder(true);

const PreparationWorkPlan = enum {
    passthrough,
    interpolate_only,
    interpolate_and_extend,
    combined,
};

pub fn columnEvaluationsAreConstant(columns: []const ColumnEvaluation) bool {
    if (columns.len == 0) return false;
    for (columns) |column| {
        if (column.values.len == 0) return false;
        const first = column.values[0];
        for (column.values[1..]) |value| {
            if (!value.eql(first)) return false;
        }
    }
    return true;
}

pub fn prepareConstantColumnsForCommitOwned(
    allocator: std.mem.Allocator,
    owned_columns: []ColumnEvaluation,
    log_blowup_factor: u32,
    retention_policy: CoefficientRetentionPolicy,
) !PreparedCommitmentColumns {
    const retain_coefficients = column_storage.shouldRetainCoefficients(owned_columns, retention_policy);
    const coefficients = if (retain_coefficients)
        try allocator.alloc(prover_circle.CircleCoefficients, owned_columns.len)
    else
        null;
    var initialized_coefficients: usize = 0;
    errdefer if (coefficients) |coeffs| {
        for (coeffs[0..initialized_coefficients]) |*coefficient| coefficient.deinit(allocator);
        allocator.free(coeffs);
    };

    for (owned_columns, 0..) |*column, i| {
        try column.validate();
        const constant = column.values[0];
        if (coefficients) |coeffs| {
            const coefficient_values = try allocator.alloc(M31, column.values.len);
            @memset(coefficient_values, M31.zero());
            coefficient_values[0] = constant;
            coeffs[i] = prover_circle.CircleCoefficients.initOwned(coefficient_values) catch |err| {
                allocator.free(coefficient_values);
                return err;
            };
            initialized_coefficients += 1;
        }

        if (log_blowup_factor != 0) {
            const extended_log_size = std.math.add(u32, column.log_size, log_blowup_factor) catch
                return error.InvalidColumnLogSize;
            if (extended_log_size >= @bitSizeOf(usize)) return error.InvalidColumnLogSize;
            const extended_len = @as(usize, 1) << @intCast(extended_log_size);
            const extended_values = try allocator.alloc(M31, extended_len);
            @memset(extended_values, constant);
            allocator.free(column.values);
            column.* = .{ .log_size = extended_log_size, .values = extended_values };
        }
    }

    return .{ .columns = owned_columns, .coefficients = coefficients };
}

pub fn prepareColumnsForCommitBorrowedForBackend(
    comptime B: type,
    allocator: std.mem.Allocator,
    columns: []const ColumnEvaluation,
    log_blowup_factor: u32,
    retention_policy: CoefficientRetentionPolicy,
    twiddle_source: *TwiddleSource,
) !PreparedCommitmentColumns {
    const owned = try allocator.alloc(ColumnEvaluation, columns.len);
    errdefer allocator.free(owned);

    var initialized: usize = 0;
    errdefer {
        for (owned[0..initialized]) |column| allocator.free(column.values);
    }

    for (columns, 0..) |column, i| {
        try column.validate();
        owned[i] = .{
            .log_size = column.log_size,
            .values = try allocator.dupe(M31, column.values),
        };
        initialized += 1;
    }

    return prepareColumnsForCommitOwnedForBackend(
        B,
        allocator,
        owned,
        log_blowup_factor,
        retention_policy,
        twiddle_source,
        null,
        null,
    );
}

pub fn prepareColumnsForCommitOwnedForBackend(
    comptime B: type,
    allocator: std.mem.Allocator,
    owned_columns: []ColumnEvaluation,
    log_blowup_factor: u32,
    retention_policy: CoefficientRetentionPolicy,
    twiddle_source: *TwiddleSource,
    recorder: ?*stage_profile.Recorder,
    /// One contiguous buffer that every source column already lives inside.
    /// Adopting backends bind each log-size group's run directly; groups that
    /// are not contiguous inside it still get their own coefficient buffer.
    source_arena: ?[]M31,
) !PreparedCommitmentColumns {
    const work_recorder: ?*WorkRecorder = if (recorder) |active|
        active.workCaptureRecorder()
    else
        null;
    return prepareColumnsForCommitOwnedForBackendWithWorkRecorder(
        B,
        allocator,
        owned_columns,
        log_blowup_factor,
        retention_policy,
        twiddle_source,
        recorder,
        source_arena,
        work_recorder,
    );
}

/// Variant for a deferred commitment worker. Stage timing remains on its
/// owning thread while the independently synchronized work recorder can cross
/// the join boundary safely.
pub fn prepareColumnsForCommitOwnedForBackendWithWorkRecorder(
    comptime B: type,
    allocator: std.mem.Allocator,
    owned_columns: []ColumnEvaluation,
    log_blowup_factor: u32,
    retention_policy: CoefficientRetentionPolicy,
    twiddle_source: *TwiddleSource,
    recorder: ?*stage_profile.Recorder,
    source_arena: ?[]M31,
    work_recorder: ?*WorkRecorder,
) !PreparedCommitmentColumns {
    const retain_coefficients = column_storage.shouldRetainCoefficients(owned_columns, retention_policy);
    if (source_arena != null and (log_blowup_factor == 0 or
        !(comptime @hasDecl(B, "interpolateAndEvaluateCircleBuffers"))))
        return error.UnsupportedTraceArena;
    const combined_commit_min_columns = if (comptime @hasDecl(B, "combined_commit_min_columns"))
        B.combined_commit_min_columns
    else
        0;
    const combined_commit_max_columns = if (comptime @hasDecl(B, "combined_commit_max_columns"))
        B.combined_commit_max_columns
    else
        std.math.maxInt(usize);
    const work_plan: PreparationWorkPlan = if (log_blowup_factor == 0 and
        !retain_coefficients)
        .passthrough
    else if (log_blowup_factor != 0 and
        (comptime @hasDecl(B, "interpolateAndEvaluateCircleBuffers")) and
        owned_columns.len >= combined_commit_min_columns and
        owned_columns.len <= combined_commit_max_columns)
        .combined
    else if (log_blowup_factor == 0)
        .interpolate_only
    else
        .interpolate_and_extend;
    try planPreparationWork(work_recorder, work_plan);

    if (work_plan == .passthrough) {
        try recordFftButterflies(work_recorder, .column_passthrough_fft, 0);
        // work-profile-complete:column-passthrough-fft
        return .{
            .columns = owned_columns,
            .coefficients = null,
        };
    }

    if (work_plan == .combined) {
        return prepareColumnsCombinedForBackend(
            B,
            allocator,
            owned_columns,
            log_blowup_factor,
            retain_coefficients,
            twiddle_source,
            source_arena,
            work_recorder,
        );
    }
    if (source_arena != null) return error.UnsupportedTraceArena;

    if (work_plan == .interpolate_only) {
        {
            var interpolate_stage = try stage_profile.StageScope.begin(
                recorder,
                "interpolate_columns",
                "Interpolate columns",
            );
            defer interpolate_stage.end();
            var result = try circle_transforms.interpolateCoefficientColumns(
                allocator,
                owned_columns,
                twiddle_source,
                work_recorder,
            );
            errdefer result.deinit(allocator);
            // work-profile-complete:column-interpolate-only-fft
            return .{
                .columns = owned_columns,
                .coefficients = result.coefficients,
                .coefficient_backing_buffers = result.backing_buffers,
            };
        }
    }

    const coeffs = blk: {
        var interpolate_stage = try stage_profile.StageScope.begin(
            recorder,
            "interpolate_columns",
            "Interpolate columns",
        );
        defer interpolate_stage.end();
        break :blk try circle_transforms.interpolateOwnedColumnsForExtensionForBackend(
            B,
            allocator,
            owned_columns,
            twiddle_source,
            work_recorder,
        );
    };
    errdefer column_storage.deinitOwnedCoefficientColumns(allocator, coeffs);
    allocator.free(owned_columns);
    // work-profile-complete:column-interpolate-for-extension-fft

    const extended = blk: {
        var eval_stage = try stage_profile.StageScope.begin(
            recorder,
            "evaluate_extended_domain",
            "Evaluate extended domain",
        );
        defer eval_stage.end();
        break :blk try circle_transforms.extendCoefficientColumnsByGroupForBackend(
            B,
            allocator,
            coeffs,
            log_blowup_factor,
            twiddle_source,
            work_recorder,
            .column_extension_fft,
        );
    };
    errdefer column_storage.freeOwnedColumnEvaluations(allocator, extended);
    // work-profile-complete:column-extension-fft

    if (!retain_coefficients) {
        column_storage.deinitOwnedCoefficientColumns(allocator, coeffs);
        return .{
            .columns = extended,
            .coefficients = null,
        };
    }

    return .{
        .columns = extended,
        .coefficients = coeffs,
    };
}

fn prepareColumnsCombinedForBackend(
    comptime B: type,
    allocator: std.mem.Allocator,
    owned_columns: []ColumnEvaluation,
    log_blowup_factor: u32,
    retain_coefficients: bool,
    twiddle_source: *TwiddleSource,
    source_arena: ?[]M31,
    work_recorder: ?*WorkRecorder,
) !PreparedCommitmentColumns {
    var completed_work: work_profile.Counters = .{};
    const extended = try allocator.alloc(ColumnEvaluation, owned_columns.len);
    for (extended) |*column| column.* = .{ .log_size = 0, .values = &.{} };
    errdefer allocator.free(extended);

    const coefficients = try allocator.alloc(prover_circle.CircleCoefficients, owned_columns.len);
    errdefer allocator.free(coefficients);
    var initialized_indices = std.ArrayList(usize).empty;
    defer initialized_indices.deinit(allocator);
    errdefer for (initialized_indices.items) |index| coefficients[index].deinit(allocator);

    var coefficient_buffers = std.ArrayList([]M31).empty;
    defer coefficient_buffers.deinit(allocator);
    errdefer for (coefficient_buffers.items) |buffer| allocator.free(buffer);
    var column_buffers = std.ArrayList([]M31).empty;
    defer column_buffers.deinit(allocator);
    errdefer for (column_buffers.items) |buffer| allocator.free(buffer);

    var groups = try circle_transforms.buildLogSizeGroupsFromColumns(allocator, owned_columns);
    defer circle_transforms.deinitLogSizeGroups(allocator, &groups);

    // Keep every extended log-size group in one page-aligned allocation.  The
    // columns themselves may have different lengths and padded strides, but a
    // single backing lets unified-memory backends expose the finished trace to
    // the GPU with one `newBufferWithBytesNoCopy` view.  One allocation per
    // group forced the Merkle boundary to repack multi-gigabyte RISC-V traces
    // into a second private staging arena even though the GPU had produced all
    // of the values in shared memory immediately beforehand.
    const page_words = std.heap.pageSize() / @sizeOf(M31);
    const compact_resident_columns = comptime @hasDecl(B, "requires_contiguous_resident_columns") and
        B.requires_contiguous_resident_columns;
    var transform_arena_words: usize = 0;
    for (groups.items) |group| {
        const extended_log_size = std.math.add(u32, group.log_size, log_blowup_factor) catch
            return error.ShapeMismatch;
        if (extended_log_size >= @bitSizeOf(usize)) return error.ShapeMismatch;
        const extended_len = @as(usize, 1) << @intCast(extended_log_size);
        const column_count = group.indices.items.len;
        if (column_count == 0) return error.ShapeMismatch;
        const page_rotate = column_count >= 64 and extended_len >= (1 << 18);
        const extended_stride = try std.math.add(
            usize,
            extended_len,
            if (compact_resident_columns)
                0
            else if (page_rotate)
                page_words + 16
            else if (column_count >= 64)
                16
            else
                0,
        );
        const extended_span = try std.math.add(
            usize,
            try std.math.mul(usize, column_count - 1, extended_stride),
            extended_len,
        );
        const group_words = std.mem.alignForward(usize, extended_span, page_words);
        transform_arena_words = try std.math.add(
            usize,
            transform_arena_words,
            group_words,
        );
    }
    if (transform_arena_words == 0) return error.ShapeMismatch;
    const transform_arena: []M31 = if (comptime @hasDecl(B, "resident_column_arena_alignment"))
        try allocator.alignedAlloc(
            M31,
            B.resident_column_arena_alignment,
            transform_arena_words,
        )
    else
        try allocator.alloc(M31, transform_arena_words);
    column_buffers.append(allocator, transform_arena) catch |err| {
        allocator.free(transform_arena);
        return err;
    };
    var transform_arena_cursor: usize = 0;

    for (groups.items) |group| {
        const extended_log_size = std.math.add(u32, group.log_size, log_blowup_factor) catch
            return error.ShapeMismatch;
        const base_domain = canonic.CanonicCoset.new(group.log_size).circleDomain();
        const extended_domain = canonic.CanonicCoset.new(extended_log_size).circleDomain();
        const base_twiddles = try twiddle_source.getWithWorkRecorder(
            allocator,
            group.log_size,
            work_recorder,
        );
        const extended_twiddles = try twiddle_source.getWithWorkRecorder(
            allocator,
            extended_log_size,
            work_recorder,
        );

        const column_count = group.indices.items.len;
        const base_in_place = comptime @hasDecl(B, "combined_base_in_place") and
            B.combined_base_in_place;
        // Keep Metal coefficients independently releasable from the skewed
        // evaluation arena; CPU backends transform their owned inputs in place.
        // A planned arena already holds this group's columns as one run in
        // exactly the order the group walks them. Bind that run as the
        // coefficient arena so the backend sees source == base and can skip
        // the upload entirely.
        const adopted = if (base_in_place)
            null
        else
            arenaGroupRun(source_arena, owned_columns, group, base_domain.size());
        const base_buffer: []M31 = if (base_in_place)
            &.{}
        else if (adopted) |run|
            run
        else blk: {
            const buffer = try allocator.alloc(
                M31,
                try std.math.mul(usize, column_count, base_domain.size()),
            );
            try coefficient_buffers.append(allocator, buffer);
            break :blk buffer;
        };
        const extended_start: usize = 0;
        // AIR evaluators walk a row across columns. An exact power-of-two
        // column stride aliases cache and translation structures. Large
        // columns amortize an odd-page rotation; retain the cheaper cache-line
        // rotation for small columns where a page of padding is material.
        const page_rotate = column_count >= 64 and extended_domain.size() >= (1 << 18);
        const extended_stride = extended_domain.size() +
            @as(usize, if (compact_resident_columns)
                0
            else if (page_rotate)
                page_words + 16
            else if (column_count >= 64)
                16
            else
                0);
        const extended_span = try std.math.add(
            usize,
            try std.math.mul(usize, column_count - 1, extended_stride),
            extended_domain.size(),
        );
        const backing_words = std.mem.alignForward(usize, extended_span, page_words);
        const transform_buffer = transform_arena[transform_arena_cursor..][0..backing_words];
        transform_arena_cursor += backing_words;

        const base_values = try allocator.alloc([]M31, group.indices.items.len);
        defer allocator.free(base_values);
        const source_values = try allocator.alloc([]const M31, group.indices.items.len);
        defer allocator.free(source_values);
        const extended_values = try allocator.alloc([]M31, group.indices.items.len);
        defer allocator.free(extended_values);
        for (group.indices.items, 0..) |column_index, group_index| {
            const base = if (base_in_place)
                @constCast(owned_columns[column_index].values)
            else
                base_buffer[group_index * base_domain.size() ..][0..base_domain.size()];
            source_values[group_index] = owned_columns[column_index].values;
            base_values[group_index] = base;
            const values = transform_buffer[extended_start + group_index * extended_stride ..][0..extended_domain.size()];
            extended_values[group_index] = values;
            extended[column_index] = .{ .log_size = extended_log_size, .values = values };
        }
        const execution: work_profile.M31CircleLdeExecution =
            try B.interpolateAndEvaluateCircleBuffers(
                allocator,
                source_values,
                base_values,
                extended_values,
                transform_buffer,
                extended_start,
                extended_stride,
                base_domain,
                base_twiddles,
                extended_domain,
                extended_twiddles,
            );
        if (work_recorder != null) {
            try validateCombinedExecution(
                execution,
                group.log_size,
                extended_log_size,
                column_count,
            );
            completed_work = try completed_work.add(try execution.exactWork());
        }

        for (group.indices.items, base_values) |column_index, base| {
            coefficients[column_index] = if (base_in_place) blk: {
                const coefficient = try prover_circle.CircleCoefficients.initOwned(base);
                owned_columns[column_index].values = &.{};
                break :blk coefficient;
            } else try prover_circle.CircleCoefficients.initBorrowed(base);
            try initialized_indices.append(allocator, column_index);
        }
    }
    std.debug.assert(transform_arena_cursor == transform_arena.len);
    try recordM31TransformCompletion(
        work_recorder,
        .column_combined_fft,
        if (work_recorder != null) completed_work else null,
        0,
    );
    // work-profile-complete:column-combined-fft

    if (source_arena) |arena| {
        // Column values borrow the arena; the arena is released exactly once,
        // with the coefficients that now live inside it.
        try coefficient_buffers.append(allocator, arena);
    } else {
        for (owned_columns) |column| if (column.values.len != 0) allocator.free(column.values);
    }
    allocator.free(owned_columns);

    const owned_column_buffers = try allocator.dupe([]M31, column_buffers.items);
    errdefer allocator.free(owned_column_buffers);

    if (!retain_coefficients) {
        column_storage.deinitOwnedCoefficientColumns(allocator, coefficients);
        for (coefficient_buffers.items) |buffer| allocator.free(buffer);
        coefficient_buffers.clearRetainingCapacity();
        column_buffers.clearRetainingCapacity();
        return .{
            .columns = extended,
            .coefficients = null,
            .column_backing_buffers = owned_column_buffers,
        };
    }
    const owned_coefficient_buffers: ?[][]M31 = if (coefficient_buffers.items.len == 0)
        null
    else blk: {
        const buffers = try allocator.dupe([]M31, coefficient_buffers.items);
        coefficient_buffers.clearRetainingCapacity();
        break :blk buffers;
    };
    column_buffers.clearRetainingCapacity();
    return .{
        .columns = extended,
        .coefficients = coefficients,
        .column_backing_buffers = owned_column_buffers,
        .coefficient_backing_buffers = owned_coefficient_buffers,
    };
}

pub fn coefficientExtensionFftButterflies(
    comptime B: type,
    coefficients: []const prover_circle.CircleCoefficients,
    log_blowup_factor: u32,
) !u64 {
    var total: u64 = 0;
    for (coefficients) |coefficient| {
        const extended_log_size = std.math.add(
            u32,
            coefficient.logSize(),
            log_blowup_factor,
        ) catch return error.CounterOverflow;
        // Generic backend hooks consume materialized zero tails and perform a
        // full FFT. The host engine alone uses its exact-2x degenerate-layer
        // specialization, and small domains deliberately fall back to full.
        const skipped_layers: u32 = if (!(comptime @hasDecl(B, "evaluateCircleBuffers")) and
            log_blowup_factor == 1 and extended_log_size > 2)
            1
        else
            0;
        total = std.math.add(
            u64,
            total,
            try work_profile.logicalFftButterflies(extended_log_size, skipped_layers),
        ) catch return error.CounterOverflow;
    }
    return total;
}

fn validateCombinedExecution(
    execution: work_profile.M31CircleLdeExecution,
    base_log_size: u32,
    extended_log_size: u32,
    column_count: usize,
) !void {
    try execution.validate();
    const columns = std.math.cast(u64, column_count) orelse
        return error.CounterOverflow;
    if (execution.interpolation.log_size != base_log_size or
        execution.interpolation.column_count != columns or
        execution.forward.log_size != extended_log_size or
        execution.forward.column_count != columns)
    {
        return error.InvalidProducerCoverage;
    }
}

pub fn recordFftButterflies(
    recorder: ?*WorkRecorder,
    site: work_profile.Site,
    count: u64,
) !void {
    return recordM31TransformCompletion(recorder, site, null, count);
}

/// Records the complete scalar-field work of a forward M31 FFT together with
/// its logical butterfly count. This intentionally excludes interpolation
/// normalization/inversion, whose formula is a separate producer boundary.
pub fn recordM31ForwardFftWork(
    recorder: ?*WorkRecorder,
    site: work_profile.Site,
    butterflies: u64,
) !void {
    if (recorder == null) return;
    const fields = try work_profile.logicalM31ForwardFftFieldOperations(
        butterflies,
    );
    return recordM31TransformCompletion(
        recorder,
        site,
        .{
            .field_additions = fields.additions,
            .field_multiplications = fields.multiplications,
            .field_inversions = fields.inversions,
            .fft_butterflies = butterflies,
        },
        butterflies,
    );
}

fn recordM31TransformCompletion(
    recorder: ?*WorkRecorder,
    site: work_profile.Site,
    exact_work: ?work_profile.Counters,
    diagnostic_butterflies: u64,
) !void {
    const active = recorder orelse return;
    try active.recordCompletedDelta(.{
        .site = site,
        .producer = work_profile.boundaryForSite(site),
        .source_mask = if (exact_work != null)
            .{ .bits = work_profile.SourceMask.one(.field_additions).bits |
                work_profile.SourceMask.one(.field_multiplications).bits |
                work_profile.SourceMask.one(.field_inversions).bits |
                work_profile.SourceMask.one(.fft_butterflies).bits }
        else
            work_profile.SourceMask.one(.fft_butterflies),
        .counters = exact_work orelse .{
            .fft_butterflies = diagnostic_butterflies,
        },
    });
}

fn planPreparationWork(
    recorder: ?*WorkRecorder,
    plan: PreparationWorkPlan,
) !void {
    const active = recorder orelse return;
    switch (plan) {
        .passthrough => {
            try active.expectProducer(.column_passthrough_fft);
            // work-profile-plan:column-passthrough-fft
        },
        .interpolate_only => {
            try active.expectProducer(.column_interpolate_only_fft);
            // work-profile-plan:column-interpolate-only-fft
        },
        .interpolate_and_extend => {
            try active.expectProducer(.column_interpolate_for_extension_fft);
            // work-profile-plan:column-interpolate-for-extension-fft
            try active.expectProducer(.column_extension_fft);
            // work-profile-plan:column-extension-fft
        },
        .combined => {
            try active.expectProducer(.column_combined_fft);
            // work-profile-plan:column-combined-fft
        },
    }
}

/// Returns the arena run that already holds this group's columns, in group
/// order, or null when the group is not one contiguous run inside the arena.
/// The no-copy device binding rests on this being checked, not assumed.
fn arenaGroupRun(
    source_arena: ?[]M31,
    owned_columns: []const ColumnEvaluation,
    group: circle_transforms.LogSizeGroup,
    column_len: usize,
) ?[]M31 {
    const arena = source_arena orelse return null;
    if (group.indices.items.len == 0) return null;
    const first = owned_columns[group.indices.items[0]].values;
    if (first.len != column_len) return null;
    const start = (@intFromPtr(first.ptr) -% @intFromPtr(arena.ptr)) / @sizeOf(M31);
    if (@intFromPtr(first.ptr) < @intFromPtr(arena.ptr)) return null;
    const words = std.math.mul(usize, group.indices.items.len, column_len) catch return null;
    if (start + words > arena.len) return null;
    for (group.indices.items, 0..) |column_index, position| {
        const column = owned_columns[column_index];
        if (column.values.len != column_len) return null;
        if (column.values.ptr != arena.ptr + start + position * column_len) return null;
    }
    return arena[start..][0..words];
}

test "column preparation: combined backend receipts are bound to request geometry" {
    const execution = work_profile.M31CircleLdeExecution{
        .interpolation = .{ .log_size = 3, .column_count = 2, .batch_count = 1 },
        .forward = .{ .log_size = 4, .column_count = 2, .skipped_layers = 1 },
    };
    try validateCombinedExecution(execution, 3, 4, 2);
    try std.testing.expectError(
        error.InvalidProducerCoverage,
        validateCombinedExecution(execution, 3, 5, 2),
    );
    try std.testing.expectError(
        error.InvalidProducerCoverage,
        validateCombinedExecution(execution, 3, 4, 3),
    );
}
