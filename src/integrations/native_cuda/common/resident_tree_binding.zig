//! Geometry-checked binding for one resident commitment tree.

const std = @import("std");
const field = @import("stwo_cuda_backend").abi.field;
const column = @import("stwo_cuda_backend").runtime.column;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const views = @import("resident_views.zig");

pub fn bind(
    provider: anytype,
    role: @import("uniform_layout.zig").TraceRole,
    coefficient_slot: anytype,
    evaluations: common.WordMatrix,
    log_slot: anytype,
    hash_slot: anytype,
    layer_slot: anytype,
    column_count: usize,
    coefficient_stride: usize,
    hash_count: usize,
    layer_count: usize,
) !views.TraceTree {
    return .{
        .role = role,
        .coefficients = .{
            .storage = try exactWords(
                provider,
                coefficient_slot,
                try mul(column_count, coefficient_stride),
            ),
            .column_stride_words = coefficient_stride,
        },
        .evaluations = evaluations,
        .column_log_sizes = try exactWords(
            provider,
            log_slot,
            column_count,
        ),
        .merkle_hashes = try exactAs(
            provider,
            field.Blake2sHash,
            hash_slot,
            hash_count,
        ),
        .merkle_layers = try exactAs(
            provider,
            field.MerkleLayerDescriptor,
            layer_slot,
            layer_count,
        ),
    };
}

fn exactWords(
    provider: anytype,
    id: anytype,
    expected: usize,
) !column.DeviceSlice(u32) {
    const value = try provider.slot(id);
    if (value.len != expected) return error.InvalidKernelDescriptor;
    return value;
}

fn exactAs(
    provider: anytype,
    comptime F: type,
    id: anytype,
    expected: usize,
) !column.DeviceSlice(F) {
    const words_per_element = @sizeOf(F) / @sizeOf(u32);
    const words = try exactWords(
        provider,
        id,
        try mul(expected, words_per_element),
    );
    const result = try words.cast(F);
    if (result.len != expected) return error.InvalidKernelDescriptor;
    return result;
}

fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.SizeOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.SizeOverflow;
}
