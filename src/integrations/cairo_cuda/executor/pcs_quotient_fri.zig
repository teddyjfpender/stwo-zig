//! Quotient and FRI resident bindings for Cairo CUDA.

const proof_ir = @import("stwo_backend_contracts").proof_program;
const field = @import("../../../backends/cuda/abi/field.zig");
const quotient_abi = @import(
    "../../../backends/cuda/abi/stages/quotient.zig",
);
const shared_views = @import(
    "../../native_cuda/common/resident_views.zig",
);
const compact = @import(
    "../../../frontends/cairo/compact_verifier_interchange.zig",
);
const resident_plan = @import("resident_plan.zig");
const slots = @import("pcs_slot_binding.zig");
const types = @import("pcs_hooks_types.zig");

pub fn bindQuotient(
    provider: anytype,
    plan: *const resident_plan.Plan,
) !types.Quotient {
    const terms = plan.quotient_geometry.term_count;
    const groups = plan.quotient_geometry.group_count;
    const sources = plan.quotient_geometry.source_count;
    const partial_storage = try slots.exact(
        provider,
        plan,
        .quotient_partial_coordinates,
        0,
    );
    if (partial_storage.len % 4 != 0)
        return error.InvalidKernelDescriptor;
    const partial_words = partial_storage.len / 4;
    const result = try slots.exact(
        provider,
        plan,
        .quotient_result_coordinates,
        0,
    );
    if (result.len % 4 != 0)
        return error.InvalidKernelDescriptor;
    const result_words = result.len / 4;
    return .{
        .challenge = try (try slots.exactWords(
            provider,
            plan,
            .quotient_challenge,
            0,
            4,
        )).cast(field.SecureField),
        .prepared_terms = try (try slots.exactWords(
            provider,
            plan,
            .quotient_prepared_terms,
            0,
            try slots.mul(terms, 5),
        )).cast(quotient_abi.PreparedTermDescriptor),
        .group_offsets = try slots.exactWords(
            provider,
            plan,
            .quotient_group_offsets,
            0,
            groups + 1,
        ),
        .group_term_indices = try slots.exactWords(
            provider,
            plan,
            .quotient_group_term_indices,
            0,
            terms,
        ),
        .batch_terms = try (try slots.exactWords(
            provider,
            plan,
            .quotient_batch_terms,
            0,
            try slots.mul(terms, 3),
        )).cast(quotient_abi.BatchTermDescriptor),
        .source_descriptors = try (try slots.exactWords(
            provider,
            plan,
            .quotient_source_descriptors,
            0,
            try slots.mul(sources, 4),
        )).cast(quotient_abi.AddressedSourceDescriptor),
        .group_log_sizes = try slots.exactWords(
            provider,
            plan,
            .quotient_group_logs,
            0,
            groups,
        ),
        .partial_log_sizes = try slots.exactWords(
            provider,
            plan,
            .quotient_partial_logs,
            0,
            groups,
        ),
        .partial_offsets = try (try slots.exactWords(
            provider,
            plan,
            .quotient_partial_offsets,
            0,
            try slots.mul(groups + 1, 2),
        )).cast(u64),
        .term_points = try (try slots.exactWords(
            provider,
            plan,
            .quotient_term_points,
            0,
            try slots.mul(terms, 8),
        )).cast(field.SecureCirclePoint),
        .line_coefficients = try (try slots.exactWords(
            provider,
            plan,
            .quotient_line_coefficients,
            0,
            try slots.mul(terms, 12),
        )).cast(field.SecureField),
        .group_points = try (try slots.exactWords(
            provider,
            plan,
            .quotient_group_points,
            0,
            try slots.mul(groups, 8),
        )).cast(field.SecureCirclePoint),
        .first_linear_terms = try (try slots.exactWords(
            provider,
            plan,
            .quotient_first_linear_terms,
            0,
            try slots.mul(groups, 4),
        )).cast(field.SecureField),
        .partial_coordinates = .{
            try partial_storage.sub(0, partial_words),
            try partial_storage.sub(partial_words, partial_words),
            try partial_storage.sub(
                try slots.mul(2, partial_words),
                partial_words,
            ),
            try partial_storage.sub(
                try slots.mul(3, partial_words),
                partial_words,
            ),
        },
        .result_coordinates = .{
            .c0 = try result.sub(0, result_words),
            .c1 = try result.sub(result_words, result_words),
            .c2 = try result.sub(
                try slots.mul(2, result_words),
                result_words,
            ),
            .c3 = try result.sub(
                try slots.mul(3, result_words),
                result_words,
            ),
        },
    };
}

pub fn bindFri(
    provider: anytype,
    plan: *const resident_plan.Plan,
    program: proof_ir.ProofProgram,
    protocol: compact.CompactProtocolV1,
) !shared_views.Fri {
    if (program.fri_layers.len == 0 or
        program.fri_layers.len > shared_views.max_fri_layers)
    {
        return error.InvalidKernelDescriptor;
    }
    var layers: [shared_views.max_fri_layers]shared_views.FriLayer =
        undefined;
    for (program.fri_layers, 0..) |layer, ordinal| {
        const index: u32 = @intCast(ordinal);
        const rows = try slots.pow2(layer.evaluation_log_rows);
        const coordinate_storage = if (ordinal == 0)
            try slots.exactWords(
                provider,
                plan,
                .quotient_result_coordinates,
                0,
                try slots.mul(rows, 4),
            )
        else
            try slots.exactWords(
                provider,
                plan,
                .fri_coordinates,
                index,
                try slots.mul(rows, 4),
            );
        layers[ordinal] = .{
            .coordinates = .{
                .storage = coordinate_storage,
                .column_stride_words = rows,
            },
            .merkle_hashes = try (try slots.exact(
                provider,
                plan,
                .fri_merkle_hashes,
                index,
            )).cast(field.Blake2sHash),
            .merkle_layers = try (try slots.exactWords(
                provider,
                plan,
                .fri_merkle_layers,
                index,
                try slots.mul(
                    @as(usize, layer.evaluation_log_rows) + 1,
                    4,
                ),
            )).cast(field.MerkleLayerDescriptor),
        };
    }
    return .{
        .alpha = try (try slots.exactWords(
            provider,
            plan,
            .fri_alpha,
            0,
            4,
        )).cast(field.SecureField),
        .layers = layers,
        .layer_count = program.fri_layers.len,
        .last_evaluation = try (try slots.exact(
            provider,
            plan,
            .fri_last_evaluation,
            0,
        )).cast(field.SecureField),
        .last_coefficients = try (try slots.exact(
            provider,
            plan,
            .fri_last_coefficients,
            0,
        )).cast(field.SecureField),
        .last_degree_error = try slots.exactWords(
            provider,
            plan,
            .fri_last_degree_error,
            0,
            1,
        ),
        .last_transcript = try (try slots.exactWords(
            provider,
            plan,
            .fri_last_transcript,
            0,
            try slots.mul(protocol.final_line_coefficient_count, 4),
        )).cast(field.SecureField),
    };
}

pub fn terminalFriMatches(
    fri: shared_views.Fri,
    program: proof_ir.ProofProgram,
) !bool {
    const layer = program.fri_layers[program.fri_layers.len - 1];
    if (layer.fold_step > layer.evaluation_log_rows)
        return false;
    const expected = try slots.pow2(
        layer.evaluation_log_rows - layer.fold_step,
    );
    return fri.last_evaluation.len == expected and
        fri.last_coefficients.len == expected;
}
