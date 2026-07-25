//! Exact tree storage and commitment-domain views for Native Poseidon.

const std = @import("std");
const field = @import("../../../../backends/cuda/abi/field.zig");
const column = @import("../../../../backends/cuda/runtime/column.zig");
const common = @import(
    "../../../../backends/cuda/runtime/stages/common.zig",
);
const geometry_mod = @import("../geometry.zig");
const slots = @import("../slots.zig");
const types = @import("types.zig");

const Words = column.DeviceSlice(u32);

pub fn bind(
    provider: anytype,
    geometry: geometry_mod.Geometry,
) !types.Trace {
    const rows = try geometry.traceRowCount();
    const committed_rows = geometry.commitment_rows;
    const main_words = try mul(geometry.main_columns, committed_rows);
    const interaction_words = try mul(
        geometry_mod.interaction_columns,
        committed_rows,
    );
    const composition_words = try mul(
        geometry_mod.composition_columns,
        rows,
    );
    const main_coefficients = common.WordMatrix{
        .storage = try exactWords(
            provider,
            slots.main_coefficients,
            main_words,
        ),
        .column_stride_words = committed_rows,
    };
    const interaction_coefficients = common.WordMatrix{
        .storage = try exactWords(
            provider,
            slots.interaction_coefficients,
            interaction_words,
        ),
        .column_stride_words = committed_rows,
    };
    const composition_split_coefficients = common.WordMatrix{
        .storage = try exactWords(
            provider,
            slots.composition_split_coefficients,
            try mul(8, committed_rows),
        ),
        .column_stride_words = committed_rows,
    };
    const composition_coefficients = common.WordMatrix{
        .storage = try exactWords(
            provider,
            slots.composition_coefficients,
            composition_words,
        ),
        .column_stride_words = rows,
    };

    const source_words = try exactWords(
        provider,
        slots.source_evaluations,
        try mul(geometry_mod.source_columns, committed_rows),
    );
    const main_evaluations = common.WordMatrix{
        .storage = try source_words.sub(0, main_words),
        .column_stride_words = committed_rows,
    };
    const interaction_evaluations = common.WordMatrix{
        .storage = try source_words.sub(main_words, interaction_words),
        .column_stride_words = committed_rows,
    };
    const composition_evaluations = common.WordMatrix{
        .storage = try source_words.sub(
            try add(main_words, interaction_words),
            try mul(
                geometry_mod.composition_columns,
                committed_rows,
            ),
        ),
        .column_stride_words = committed_rows,
    };
    const constraint_source_count = try add(
        geometry.main_columns,
        geometry_mod.interaction_columns,
    );
    const hash_count = try sub(try mul(committed_rows, 2), 1);
    const layer_count = @as(usize, geometry.queryLogSize()) + 1;
    return .{
        .trees = .{ .storage = undefined, .len = 0 },
        .twiddles_forward = try exactWords(
            provider,
            slots.twiddles_forward,
            committed_rows,
        ),
        .twiddles_inverse = try exactWords(
            provider,
            slots.twiddles_inverse,
            committed_rows,
        ),
        .main_coefficients = main_coefficients,
        .interaction_coefficients = interaction_coefficients,
        .composition_split_coefficients = composition_split_coefficients,
        .composition_coefficients = composition_coefficients,
        .committed_evaluation_slab = source_words,
        .main_evaluations = main_evaluations,
        .interaction_evaluations = interaction_evaluations,
        .composition_evaluations = composition_evaluations,
        .all_evaluations = .{
            .storage = source_words,
            .column_stride_words = committed_rows,
        },
        .constraint_evaluations = try matrix(
            provider,
            slots.constraint_source_evaluations,
            constraint_source_count,
            geometry.composition_rows,
        ),
        .coefficient_log_sizes = try exactWords(
            provider,
            slots.coefficient_log_sizes,
            geometry_mod.source_columns,
        ),
        .main_merkle_hashes = try exactAs(
            provider,
            field.Blake2sHash,
            slots.main_merkle_hashes,
            hash_count,
        ),
        .interaction_merkle_hashes = try exactAs(
            provider,
            field.Blake2sHash,
            slots.interaction_merkle_hashes,
            hash_count,
        ),
        .composition_merkle_hashes = try exactAs(
            provider,
            field.Blake2sHash,
            slots.composition_merkle_hashes,
            hash_count,
        ),
        .main_merkle_layers = try exactAs(
            provider,
            field.MerkleLayerDescriptor,
            slots.main_merkle_layers,
            layer_count,
        ),
        .interaction_merkle_layers = try exactAs(
            provider,
            field.MerkleLayerDescriptor,
            slots.interaction_merkle_layers,
            layer_count,
        ),
        .composition_merkle_layers = try exactAs(
            provider,
            field.MerkleLayerDescriptor,
            slots.composition_merkle_layers,
            layer_count,
        ),
    };
}

pub fn bindTrees(
    trace: types.Trace,
    decommit: types.Decommit,
) !types.TraceTrees {
    return types.TraceTrees.init(&.{
        .{
            .role = .main,
            .coefficients = trace.main_coefficients,
            .evaluations = trace.main_evaluations,
            .column_log_sizes = decommit.main_column_log_sizes,
            .merkle_hashes = trace.main_merkle_hashes,
            .merkle_layers = trace.main_merkle_layers,
        },
        .{
            .role = .interaction,
            .coefficients = trace.interaction_coefficients,
            .evaluations = trace.interaction_evaluations,
            .column_log_sizes = decommit.interaction_column_log_sizes,
            .merkle_hashes = trace.interaction_merkle_hashes,
            .merkle_layers = trace.interaction_merkle_layers,
        },
        .{
            .role = .composition,
            .coefficients = trace.composition_coefficients,
            .evaluations = trace.composition_evaluations,
            .column_log_sizes = decommit.composition_column_log_sizes,
            .merkle_hashes = trace.composition_merkle_hashes,
            .merkle_layers = trace.composition_merkle_layers,
        },
    });
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

fn add(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.SizeOverflow;
    return std.math.add(usize, lhs, rhs) catch error.SizeOverflow;
}

fn sub(left: usize, right: usize) !usize {
    return std.math.sub(usize, left, right) catch error.SizeOverflow;
}

fn mul(left: anytype, right: anytype) !usize {
    const lhs = std.math.cast(usize, left) orelse return error.SizeOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.SizeOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.SizeOverflow;
}
