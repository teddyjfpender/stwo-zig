//! Explicit OODS evaluation batches over resident trace-tree subviews.

const std = @import("std");
const common = @import("../../../backends/cuda/runtime/stages/common.zig");
const oods_stage = @import(
    "../../../backends/cuda/runtime/stages/oods.zig",
);
const resident_views = @import("resident_views.zig");
const trace_layout = @import("uniform_layout.zig");

pub const max_batches: usize = 8;

pub const Batch = struct {
    coefficients: common.WordMatrix,
    coefficient_rows: u32,
    coefficient_log_size: u32,
    first_sample: usize,
    sample_count: usize,
};

pub const Descriptor = struct {
    role: trace_layout.TraceRole,
    first_column: u32,
    column_count: u32,
    first_execution_sample: u32,
};

/// Builds copy-free batches from immutable source/sample policy. Repeated
/// source ranges are intentional: they evaluate one committed column at
/// multiple mask points without duplicating its coefficient storage.
pub fn buildExplicit(
    prepared: anytype,
    ingress: anytype,
    views: anytype,
    descriptors: []const Descriptor,
    storage: *[max_batches]Batch,
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
    var common_log_size: ?u32 = null;
    var common_rows: ?usize = null;
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
        for (source_first + first_column..source_first + end_column) |index| {
            if (ingress.coefficient_log_sizes[index] !=
                tree.column_log_size)
            {
                return error.InvalidKernelDescriptor;
            }
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

        const rows = try pow2(tree.column_log_size);
        const stride = resident.coefficients.column_stride_words;
        if (stride < rows or
            resident.coefficients.storage.len !=
                try mul(tree.column_count, stride))
        {
            return error.InvalidKernelDescriptor;
        }
        if (common_log_size) |expected| {
            if (expected != tree.column_log_size)
                return error.InvalidKernelDescriptor;
        } else {
            common_log_size = tree.column_log_size;
            common_rows = rows;
        }
        batch.* = .{
            .coefficients = .{
                .storage = try resident.coefficients.storage.sub(
                    try mul(first_column, stride),
                    try mul(column_count, stride),
                ),
                .column_stride_words = stride,
            },
            .coefficient_rows = try u32Count(rows),
            .coefficient_log_size = tree.column_log_size,
            .first_sample = sample_cursor,
            .sample_count = column_count,
        };
        sample_cursor = end_sample;
    }
    if (sample_cursor != sample_count)
        return error.InvalidKernelDescriptor;

    const log_size = common_log_size orelse
        return error.InvalidKernelDescriptor;
    const rows = common_rows orelse
        return error.InvalidKernelDescriptor;
    if (views.oods.folding_factors.len !=
        try mul(sample_count, log_size))
    {
        return error.InvalidKernelDescriptor;
    }
    const blocks = try ceilDiv(
        rows,
        oods_stage.first_coefficients_per_block,
    );
    const scratch = try mul(sample_count, blocks);
    if (views.oods.reduce_a.len != scratch or
        views.oods.reduce_b.len != scratch)
    {
        return error.InvalidKernelDescriptor;
    }
    return storage[0..descriptors.len];
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
