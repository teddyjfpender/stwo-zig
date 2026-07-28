//! Generic relation-graph views over immutable Poseidon witness sources.

const std = @import("std");
const field = @import("stwo_cuda_backend").abi.field;
const relation_abi = @import("stwo_cuda_backend").abi.stages.relation;
const column = @import("stwo_cuda_backend").runtime.column;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const relation_stage = @import("stwo_cuda_backend").runtime.stages.relation;
const geometry_mod = @import("../geometry.zig");
const relation_mod = @import("../relation.zig");
const slots = @import("../slots.zig");
const types = @import("types.zig");

const Words = column.DeviceSlice(u32);

pub fn bind(
    provider: anytype,
    geometry: geometry_mod.Geometry,
    trace: types.Trace,
) !types.Relation {
    const rows = try geometry.traceRowCount();
    const source_values = try matrix(
        provider,
        slots.relation_source_values,
        relation_mod.source_pointer_count,
        rows,
    );
    var source_columns: [relation_mod.source_pointer_count]Words = undefined;
    for (&source_columns, 0..) |*source, index| {
        source.* = try matrixColumn(source_values, index, rows);
    }
    var output_coordinates: [relation_mod.output_coordinate_count]Words = undefined;
    for (&output_coordinates, 0..) |*output, index| {
        output.* = try matrixColumn(
            trace.interaction_coefficients,
            index,
            rows,
        );
    }
    return .{
        .source_values = source_values,
        .buffers = .{
            .drawn_z_alpha = try exactAs(
                provider,
                field.SecureField,
                slots.lookup_elements,
                2,
            ),
            .alpha_powers = try exactAs(
                provider,
                field.SecureField,
                slots.relation_alpha_powers,
                relation_mod.max_alpha_powers,
            ),
            .z = try exactAs(
                provider,
                field.SecureField,
                slots.relation_z,
                1,
            ),
            .source_tables = try exactWords(
                provider,
                slots.relation_source_tables,
                2,
            ),
            .descriptors = try exactWords(
                provider,
                slots.relation_descriptor_tables,
                2,
            ),
            .output_tables = try exactWords(
                provider,
                slots.relation_output_tables,
                2,
            ),
            .denominator_slabs = try exactWords(
                provider,
                slots.relation_denominator_tables,
                2,
            ),
            .geometry = try exactAs(
                provider,
                relation_stage.Geometry,
                slots.relation_geometry,
                1,
            ),
            .claimed_sums = try exactWords(
                provider,
                slots.relation_claimed_sum_tables,
                2,
            ),
            .reduction_partials = try exactWords(
                provider,
                slots.relation_reduction_partials,
                try scratchWords(geometry.log_n_rows),
            ),
            .scan_block_sums = try exactWords(
                provider,
                slots.relation_scan_block_sums,
                try scratchWords(geometry.log_n_rows),
            ),
        },
        .source_columns = source_columns,
        .output_coordinates = output_coordinates,
        .source_pointer_table = try exactWords(
            provider,
            slots.relation_source_pointer_table,
            try mul(relation_mod.source_pointer_count, 2),
        ),
        .descriptor_storage = try exactWords(
            provider,
            slots.relation_descriptors,
            try mul(
                relation_mod.interaction_column_count,
                relation_abi.descriptor_words,
            ),
        ),
        .output_pointer_table = try exactWords(
            provider,
            slots.relation_output_pointer_table,
            try mul(relation_mod.output_coordinate_count, 2),
        ),
        .denominator_slab = try exactAs(
            provider,
            field.SecureField,
            slots.relation_denominator_slab,
            try mul(relation_mod.interaction_column_count, rows),
        ),
        .claimed_sum = try exactAs(
            provider,
            field.SecureField,
            slots.relation_claimed_sum,
            1,
        ),
    };
}

fn matrixColumn(
    value: common.WordMatrix,
    index: usize,
    rows: usize,
) !Words {
    if (value.column_stride_words < rows or
        value.storage.len % value.column_stride_words != 0 or
        index >= value.storage.len / value.column_stride_words)
    {
        return error.InvalidKernelDescriptor;
    }
    return value.storage.sub(
        try mul(index, value.column_stride_words),
        rows,
    );
}

fn matrix(
    provider: anytype,
    id: slots.SlotId,
    columns: usize,
    stride: usize,
) !common.WordMatrix {
    return .{
        .storage = try exactWords(
            provider,
            id,
            try mul(columns, stride),
        ),
        .column_stride_words = stride,
    };
}

fn scratchWords(log_rows: u32) !usize {
    const plan = try relation_mod.Plan.init(log_rows);
    return std.math.cast(
        usize,
        try plan.topology().scratchWords(),
    ) orelse error.SizeOverflow;
}

fn exactWords(provider: anytype, id: slots.SlotId, expected: usize) !Words {
    const value = try provider.slot(id);
    if (value.len != expected) return error.InvalidKernelDescriptor;
    return value;
}

fn exactAs(
    provider: anytype,
    comptime F: type,
    id: slots.SlotId,
    expected: usize,
) !column.DeviceSlice(F) {
    const words = try exactWords(
        provider,
        id,
        try mul(expected, @sizeOf(F) / @sizeOf(u32)),
    );
    const value = try words.cast(F);
    if (value.len != expected) return error.InvalidKernelDescriptor;
    return value;
}

fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.SizeOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.SizeOverflow;
}
