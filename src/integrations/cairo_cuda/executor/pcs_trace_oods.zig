//! Mixed-height trace and OODS resident bindings for Cairo CUDA.

const proof_ir = @import("stwo_backend_contracts").proof_program;
const field = @import("../../../backends/cuda/abi/field.zig");
const shared_views = @import(
    "../../native_cuda/common/resident_views.zig",
);
const shared_layout = @import(
    "../../native_cuda/common/uniform_layout.zig",
);
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const resident_plan = @import("resident_plan.zig");
const slots = @import("pcs_slot_binding.zig");
const types = @import("pcs_hooks_types.zig");

pub fn bindTrees(
    provider: anytype,
    plan: *const resident_plan.Plan,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
) !types.TraceTrees {
    if (program.commitments.len == 0 or
        program.commitments.len > types.max_trace_trees)
    {
        return error.InvalidKernelDescriptor;
    }
    var result = types.TraceTrees{
        .storage = undefined,
        .len = program.commitments.len,
    };
    for (program.commitments, 0..) |tree, ordinal| {
        const index: u32 = @intCast(ordinal);
        const columns = program.trace_columns[tree.first_column .. tree.first_column + tree.column_count];
        var coefficient_words: usize = 0;
        for (columns) |trace_column| {
            coefficient_words = try slots.add(
                coefficient_words,
                try slots.pow2(trace_column.log_rows),
            );
        }
        const evaluation_words = try slots.mul(
            coefficient_words,
            try slots.pow2(protocol.log_blowup_factor),
        );
        const coefficient_kind: resident_plan.SlotKind =
            if (tree.role == .composition)
                .constraint_composition_output
            else
                .trace_coefficients;
        const hashes = try slots.exact(
            provider,
            plan,
            .trace_merkle_hashes,
            index,
        );
        const layers = try slots.exact(
            provider,
            plan,
            .trace_merkle_layers,
            index,
        );
        result.storage[ordinal] = .{
            .ordinal = index,
            .role = tree.role,
            .first_column = tree.first_column,
            .column_count = tree.column_count,
            .evaluation_log_rows = tree.evaluation_log_rows,
            .coefficients = try slots.exactWords(
                provider,
                plan,
                coefficient_kind,
                index,
                coefficient_words,
            ),
            .evaluations = try slots.exactWords(
                provider,
                plan,
                .trace_evaluations,
                index,
                evaluation_words,
            ),
            .column_log_sizes = try slots.exactWords(
                provider,
                plan,
                .trace_column_logs,
                index,
                columns.len,
            ),
            .column_offsets = try slots.exactWords(
                provider,
                plan,
                .trace_column_offsets,
                index,
                columns.len + 1,
            ),
            .merkle_hashes = try hashes.cast(field.Blake2sHash),
            .merkle_layers = try layers.cast(
                field.MerkleLayerDescriptor,
            ),
            .root = try (try slots.exactWords(
                provider,
                plan,
                .trace_root,
                index,
                8,
            )).cast(field.Blake2sHash),
        };
    }
    return result;
}

pub fn uniformCompositionView(
    tree: types.CompactTree,
    program: proof_ir.ProofProgram,
) !shared_views.TraceTree {
    const columns = program.trace_columns[tree.first_column .. tree.first_column + tree.column_count];
    if (columns.len == 0) return error.InvalidKernelDescriptor;
    const coefficient_log = columns[0].log_rows;
    for (columns[1..]) |trace_column| {
        if (trace_column.log_rows != coefficient_log)
            return error.InvalidKernelDescriptor;
    }
    const coefficient_rows = try slots.pow2(coefficient_log);
    const evaluation_rows = try slots.pow2(tree.evaluation_log_rows);
    if (tree.coefficients.len !=
        try slots.mul(columns.len, coefficient_rows) or
        tree.evaluations.len !=
            try slots.mul(columns.len, evaluation_rows))
    {
        return error.InvalidKernelDescriptor;
    }
    return .{
        .role = shared_layout.TraceRole.composition,
        .coefficients = .{
            .storage = tree.coefficients,
            .column_stride_words = coefficient_rows,
        },
        .evaluations = .{
            .storage = tree.evaluations,
            .column_stride_words = evaluation_rows,
        },
        .column_log_sizes = tree.column_log_sizes,
        .merkle_hashes = tree.merkle_hashes,
        .merkle_layers = tree.merkle_layers,
    };
}

pub fn bindOods(
    provider: anytype,
    plan: anytype,
    sample_count: usize,
    max_log: u32,
) !shared_views.Oods {
    if (sample_count == 0 or max_log == 0)
        return error.InvalidKernelDescriptor;
    return .{
        .parameter = try (try slots.exactWords(
            provider,
            plan,
            .oods_parameter,
            0,
            4,
        )).cast(field.SecureField),
        .offset_points = try (try slots.exactWords(
            provider,
            plan,
            .oods_offset_points,
            0,
            try slots.mul(sample_count, 2),
        )).cast(field.CirclePointBaseField),
        .fold_counts = try slots.exactWords(
            provider,
            plan,
            .oods_fold_counts,
            0,
            sample_count,
        ),
        .output_indices = try slots.exactWords(
            provider,
            plan,
            .oods_output_indices,
            0,
            sample_count,
        ),
        .sample_points = try (try slots.exactWords(
            provider,
            plan,
            .oods_sample_points,
            0,
            try slots.mul(sample_count, 8),
        )).cast(field.SecureCirclePoint),
        .evaluation_points = try (try slots.exactWords(
            provider,
            plan,
            .oods_evaluation_points,
            0,
            try slots.mul(sample_count, 8),
        )).cast(field.SecureCirclePoint),
        .folding_factors = try (try slots.exact(
            provider,
            plan,
            .oods_folding_factors,
            0,
        )).cast(field.SecureField),
        .reduce_a = try (try slots.exact(
            provider,
            plan,
            .oods_reduce_a,
            0,
        )).cast(field.SecureField),
        .reduce_b = try (try slots.exact(
            provider,
            plan,
            .oods_reduce_b,
            0,
        )).cast(field.SecureField),
        .sampled_values = try (try slots.exactWords(
            provider,
            plan,
            .oods_sampled_values,
            0,
            try slots.mul(sample_count, 4),
        )).cast(field.SecureField),
    };
}
