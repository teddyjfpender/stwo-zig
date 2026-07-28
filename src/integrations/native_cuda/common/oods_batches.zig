//! Explicit OODS evaluation batches over resident trace-tree subviews.

const std = @import("std");
const compact_source = @import("stwo_cuda_backend").abi.compact_source;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const oods_stage = @import("stwo_cuda_backend").runtime.stages.oods;
const resident_views = @import("resident_views.zig");
const trace_layout = @import("uniform_layout.zig");

pub const max_batches: usize = 8;

pub const Batch = struct {
    coefficients: common.WordMatrix,
    coefficient_rows: u32,
    coefficient_log_size: u32,
    first_sample: usize,
    sample_count: usize,
    factor_first: usize = 0,
    scratch_first: usize = 0,
};

pub const Descriptor = struct {
    role: trace_layout.TraceRole,
    first_column: u32,
    column_count: u32,
    first_execution_sample: u32,
};

pub const CompactSource = compact_source.Descriptor;

pub const CompactSample = struct {
    source_index: u32,
};

pub const CompactCohort = struct {
    source_offset_words: usize,
    source_stride_words: usize,
    coefficient_log_size: u32,
    first_sample: usize,
    sample_count: usize,
};

pub const CompactSchedule = struct {
    cohorts: []const CompactCohort,
    source_word_count: usize,
    sample_count: usize,
};

/// Builds copy-free batches from immutable source/sample policy. Repeated
/// source ranges are intentional: they evaluate one committed column at
/// multiple mask points without duplicating its coefficient storage.
pub fn buildExplicit(
    prepared: anytype,
    ingress: anytype,
    views: anytype,
    descriptors: []const Descriptor,
    storage: []Batch,
) ![]const Batch {
    const logical = prepared.logical;
    const sample_count = logical.quotient.sample_count;
    const source_count = logical.quotient.source_column_count;
    if (descriptors.len == 0 or descriptors.len > storage.len or
        ingress.coefficient_log_sizes.len != source_count or
        ingress.oods_offset_points.len != sample_count or
        ingress.oods_fold_counts.len != sample_count or
        ingress.oods_output_indices.len != sample_count or
        views.oods.parameter.len != 1 or
        views.oods.offset_points.len != sample_count or
        views.oods.fold_counts.len != sample_count or
        views.oods.output_indices.len != sample_count or
        views.oods.sample_points.len != sample_count or
        views.oods.evaluation_points.len != sample_count or
        views.oods.sampled_values.len != sample_count or
        views.quotient.challenge.len != 1)
    {
        return error.InvalidKernelDescriptor;
    }

    var sample_cursor: usize = 0;
    var factor_cursor: usize = 0;
    var scratch_cursor: usize = 0;
    for (descriptors, storage[0..descriptors.len]) |descriptor, *batch| {
        if (descriptor.column_count == 0 or
            descriptor.first_execution_sample != sample_cursor)
        {
            return error.InvalidKernelDescriptor;
        }
        const tree = try findLogicalTree(logical, descriptor.role);
        const resident = try views.trace.trees.require(descriptor.role);
        const first_column = @as(usize, descriptor.first_column);
        const column_count = @as(usize, descriptor.column_count);
        const end_column = try add(first_column, column_count);
        if (end_column > tree.column_count or
            resident.column_log_sizes.len != tree.column_count)
        {
            return error.InvalidKernelDescriptor;
        }
        const source_first = try treeSourceFirst(logical, descriptor.role);
        const coefficient_log_size =
            ingress.coefficient_log_sizes[source_first + first_column];
        if (coefficient_log_size > tree.column_log_size)
            return error.InvalidKernelDescriptor;
        for (source_first + first_column..source_first + end_column) |index| {
            if (ingress.coefficient_log_sizes[index] !=
                coefficient_log_size)
                return error.InvalidKernelDescriptor;
        }
        const end_sample = try add(sample_cursor, column_count);
        if (end_sample > sample_count)
            return error.InvalidKernelDescriptor;
        for (sample_cursor..end_sample) |index| {
            if (ingress.oods_fold_counts[index] > 31 or
                ingress.oods_output_indices[index] >= sample_count)
            {
                return error.InvalidKernelDescriptor;
            }
            for (ingress.oods_output_indices[0..index]) |previous| {
                if (previous == ingress.oods_output_indices[index])
                    return error.DuplicateOutputIndex;
            }
        }

        const rows = try pow2(coefficient_log_size);
        const stride = resident.coefficients.column_stride_words;
        if (stride < rows or
            resident.coefficients.storage.len !=
                try mul(tree.column_count, stride))
        {
            return error.InvalidKernelDescriptor;
        }
        const blocks = try ceilDiv(
            rows,
            oods_stage.first_coefficients_per_block,
        );
        batch.* = .{
            .coefficients = .{
                .storage = try resident.coefficients.storage.sub(
                    try mul(first_column, stride),
                    try mul(column_count, stride),
                ),
                .column_stride_words = stride,
            },
            .coefficient_rows = try u32Count(rows),
            .coefficient_log_size = coefficient_log_size,
            .first_sample = sample_cursor,
            .sample_count = column_count,
            .factor_first = factor_cursor,
            .scratch_first = scratch_cursor,
        };
        factor_cursor = try add(
            factor_cursor,
            try mul(column_count, coefficient_log_size),
        );
        scratch_cursor = try add(
            scratch_cursor,
            try mul(column_count, blocks),
        );
        sample_cursor = end_sample;
    }
    if (sample_cursor != sample_count)
        return error.InvalidKernelDescriptor;

    if (views.oods.folding_factors.len != factor_cursor)
        return error.InvalidKernelDescriptor;
    if (views.oods.reduce_a.len != scratch_cursor or
        views.oods.reduce_b.len != scratch_cursor)
    {
        return error.InvalidKernelDescriptor;
    }
    return storage[0..descriptors.len];
}

/// Compiles canonical sample order into directly addressable source cohorts.
///
/// Adjacent samples are coalesced only when their source columns are physically
/// contiguous with identical logs and strides. Repeated samples of one source
/// therefore share bytes but remain distinct cohorts instead of being copied.
pub fn compileCompactSchedule(
    sources: []const CompactSource,
    samples: []const CompactSample,
    source_word_count: usize,
    storage: []CompactCohort,
) !CompactSchedule {
    if (sources.len == 0 or samples.len == 0 or source_word_count == 0 or
        storage.len == 0 or samples.len > std.math.maxInt(u32))
    {
        return error.InvalidKernelDescriptor;
    }
    for (sources) |source| try validateCompactSource(
        source,
        source_word_count,
    );

    var cohort_count: usize = 0;
    for (samples, 0..) |sample, sample_index| {
        if (sample.source_index >= sources.len)
            return error.InvalidKernelDescriptor;
        const source = sources[sample.source_index];
        const offset = std.math.cast(usize, source.offset_words) orelse
            return error.SizeOverflow;
        const stride: usize = source.stride_words;
        var coalesced = false;
        if (cohort_count != 0) {
            const previous = &storage[cohort_count - 1];
            const span = try mul(
                previous.sample_count,
                previous.source_stride_words,
            );
            const expected = try add(previous.source_offset_words, span);
            if (previous.coefficient_log_size == source.log_size and
                previous.source_stride_words == stride and
                previous.sample_count < 65_535 and expected == offset)
            {
                previous.sample_count += 1;
                coalesced = true;
            }
        }
        if (coalesced) continue;
        if (cohort_count == storage.len)
            return error.InvalidKernelDescriptor;
        storage[cohort_count] = .{
            .source_offset_words = offset,
            .source_stride_words = stride,
            .coefficient_log_size = source.log_size,
            .first_sample = sample_index,
            .sample_count = 1,
        };
        cohort_count += 1;
    }
    return .{
        .cohorts = storage[0..cohort_count],
        .source_word_count = source_word_count,
        .sample_count = samples.len,
    };
}

/// Binds a prevalidated compact schedule to resident buffers without repack.
pub fn bindCompact(
    ingress: anytype,
    views: anytype,
    source_backing: common.Words,
    schedule: CompactSchedule,
    storage: []Batch,
) ![]const Batch {
    const sample_count = schedule.sample_count;
    if (schedule.cohorts.len == 0 or
        schedule.cohorts.len > storage.len or
        source_backing.len != schedule.source_word_count or
        ingress.oods_offset_points.len != sample_count or
        ingress.oods_fold_counts.len != sample_count or
        ingress.oods_output_indices.len != sample_count or
        views.oods.parameter.len != 1 or
        views.oods.offset_points.len != sample_count or
        views.oods.fold_counts.len != sample_count or
        views.oods.output_indices.len != sample_count or
        views.oods.sample_points.len != sample_count or
        views.oods.evaluation_points.len != sample_count or
        views.oods.sampled_values.len != sample_count or
        views.quotient.challenge.len != 1)
    {
        return error.InvalidKernelDescriptor;
    }
    for (ingress.oods_output_indices, 0..) |output, index| {
        if (output >= sample_count or ingress.oods_fold_counts[index] > 31)
            return error.InvalidKernelDescriptor;
        for (ingress.oods_output_indices[0..index]) |previous| {
            if (output == previous) return error.DuplicateOutputIndex;
        }
    }

    var sample_cursor: usize = 0;
    var factor_cursor: usize = 0;
    var scratch_cursor: usize = 0;
    for (schedule.cohorts, storage[0..schedule.cohorts.len]) |cohort, *batch| {
        if (cohort.first_sample != sample_cursor or
            cohort.sample_count == 0 or cohort.sample_count > 65_535 or
            cohort.coefficient_log_size == 0 or
            cohort.coefficient_log_size > 31)
        {
            return error.InvalidKernelDescriptor;
        }
        const rows = try pow2(cohort.coefficient_log_size);
        if (rows > cohort.source_stride_words)
            return error.InvalidKernelDescriptor;
        const source_words = try mul(
            cohort.sample_count,
            cohort.source_stride_words,
        );
        const source_end = try add(
            cohort.source_offset_words,
            source_words,
        );
        if (source_end > schedule.source_word_count)
            return error.InvalidKernelDescriptor;
        const blocks = try ceilDiv(
            rows,
            oods_stage.first_coefficients_per_block,
        );
        batch.* = .{
            .coefficients = .{
                .storage = try source_backing.sub(
                    cohort.source_offset_words,
                    source_words,
                ),
                .column_stride_words = cohort.source_stride_words,
            },
            .coefficient_rows = try u32Count(rows),
            .coefficient_log_size = cohort.coefficient_log_size,
            .first_sample = sample_cursor,
            .sample_count = cohort.sample_count,
            .factor_first = factor_cursor,
            .scratch_first = scratch_cursor,
        };
        sample_cursor = try add(sample_cursor, cohort.sample_count);
        factor_cursor = try add(
            factor_cursor,
            try mul(cohort.sample_count, cohort.coefficient_log_size),
        );
        scratch_cursor = try add(
            scratch_cursor,
            try mul(cohort.sample_count, blocks),
        );
    }
    if (sample_cursor != sample_count or
        views.oods.folding_factors.len != factor_cursor or
        views.oods.reduce_a.len != scratch_cursor or
        views.oods.reduce_b.len != scratch_cursor)
    {
        return error.InvalidKernelDescriptor;
    }
    return storage[0..schedule.cohorts.len];
}

fn validateCompactSource(
    source: CompactSource,
    source_word_count: usize,
) !void {
    if (source.log_size == 0 or source.log_size > 31 or
        source.stride_words == 0)
    {
        return error.InvalidKernelDescriptor;
    }
    const logical_words = try pow2(source.log_size);
    if (logical_words > source.stride_words)
        return error.InvalidKernelDescriptor;
    const offset = std.math.cast(usize, source.offset_words) orelse
        return error.SizeOverflow;
    const end = try add(offset, source.stride_words);
    if (end > source_word_count) return error.InvalidKernelDescriptor;
}

fn findLogicalTree(logical: anytype, role: trace_layout.TraceRole) !trace_layout.TraceTree {
    for (logical.trace_trees) |tree| {
        if (tree.role == role) return tree;
    }
    return error.InvalidKernelDescriptor;
}

fn treeSourceFirst(logical: anytype, role: trace_layout.TraceRole) !usize {
    var first: usize = 0;
    for (logical.trace_trees) |tree| {
        if (tree.role == role) return first;
        if (tree.sampled) first = try add(first, tree.column_count);
    }
    return error.InvalidKernelDescriptor;
}

fn pow2(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.SizeOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

fn u32Count(value: usize) !u32 {
    return std.math.cast(u32, value) orelse error.SizeOverflow;
}

fn add(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch error.SizeOverflow;
}

fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return error.SizeOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.SizeOverflow;
}

fn ceilDiv(value: usize, divisor: usize) !usize {
    return std.math.divCeil(usize, value, divisor) catch
        error.SizeOverflow;
}
