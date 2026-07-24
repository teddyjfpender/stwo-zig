#include "secure_field_support.h"

static inline uint stwo_metal_trace_value(
    device const uint *trace_evaluations,
    uint eval_domain_size,
    uint column_index,
    uint row_index
) {
    return trace_evaluations[column_index * eval_domain_size + row_index];
}

static inline uint stwo_metal_lifted_index(uint index, uint log_ratio) {
    if (log_ratio == 0u) {
        return index;
    }
    return (index >> (log_ratio + 1u) << 1u) + (index & 1u);
}

kernel void accumulate_secure_columns_coords_u32x4(
    device const uint *lhs_0 [[buffer(0)]],
    device const uint *lhs_1 [[buffer(1)]],
    device const uint *lhs_2 [[buffer(2)]],
    device const uint *lhs_3 [[buffer(3)]],
    device const uint *rhs_0 [[buffer(4)]],
    device const uint *rhs_1 [[buffer(5)]],
    device const uint *rhs_2 [[buffer(6)]],
    device const uint *rhs_3 [[buffer(7)]],
    device uint *dst_0 [[buffer(8)]],
    device uint *dst_1 [[buffer(9)]],
    device uint *dst_2 [[buffer(10)]],
    device uint *dst_3 [[buffer(11)]],
    constant uint &element_len [[buffer(12)]],
    uint row_index [[thread_position_in_grid]]
) {
    if (row_index >= element_len) {
        return;
    }

    dst_0[row_index] = stwo_metal_m31_add(lhs_0[row_index], rhs_0[row_index]);
    dst_1[row_index] = stwo_metal_m31_add(lhs_1[row_index], rhs_1[row_index]);
    dst_2[row_index] = stwo_metal_m31_add(lhs_2[row_index], rhs_2[row_index]);
    dst_3[row_index] = stwo_metal_m31_add(lhs_3[row_index], rhs_3[row_index]);
}

kernel void lift_accumulate_secure_columns_coords_u32x4(
    device const uint *lifted_0 [[buffer(0)]],
    device const uint *lifted_1 [[buffer(1)]],
    device const uint *lifted_2 [[buffer(2)]],
    device const uint *lifted_3 [[buffer(3)]],
    device const uint *current_0 [[buffer(4)]],
    device const uint *current_1 [[buffer(5)]],
    device const uint *current_2 [[buffer(6)]],
    device const uint *current_3 [[buffer(7)]],
    device uint *dst_0 [[buffer(8)]],
    device uint *dst_1 [[buffer(9)]],
    device uint *dst_2 [[buffer(10)]],
    device uint *dst_3 [[buffer(11)]],
    constant uint &current_log_size [[buffer(12)]],
    constant uint &log_ratio [[buffer(13)]],
    uint row_index [[thread_position_in_grid]]
) {
    uint element_len = 1u << current_log_size;
    if (row_index >= element_len) {
        return;
    }

    uint lifted_index = stwo_metal_lifted_index(row_index, log_ratio);
    dst_0[row_index] = stwo_metal_m31_add(current_0[row_index], lifted_0[lifted_index]);
    dst_1[row_index] = stwo_metal_m31_add(current_1[row_index], lifted_1[lifted_index]);
    dst_2[row_index] = stwo_metal_m31_add(current_2[row_index], lifted_2[lifted_index]);
    dst_3[row_index] = stwo_metal_m31_add(current_3[row_index], lifted_3[lifted_index]);
}

kernel void accumulate_wide_fibonacci_quotients_u32x4(
    device const uint *trace_evaluations [[buffer(0)]],
    device const uint *random_coeff_powers [[buffer(1)]],
    device const uint *denominator_inverses [[buffer(2)]],
    device uint *dst [[buffer(3)]],
    constant uint &eval_domain_size [[buffer(4)]],
    constant uint &n_constraints [[buffer(5)]],
    constant uint &domain_log_size [[buffer(6)]],
    uint row_index [[thread_position_in_grid]]
) {
    if (row_index >= eval_domain_size) {
        return;
    }

    uint a = stwo_metal_trace_value(trace_evaluations, eval_domain_size, 0u, row_index);
    uint b = stwo_metal_trace_value(trace_evaluations, eval_domain_size, 1u, row_index);
    StwoMetalQm31 row_res = StwoMetalQm31 { 0u, 0u, 0u, 0u };

    for (uint constraint_index = 0u; constraint_index < n_constraints; ++constraint_index) {
        uint column_index = constraint_index + 2u;
        uint c = stwo_metal_trace_value(trace_evaluations, eval_domain_size, column_index, row_index);
        uint recurrence = stwo_metal_m31_add(stwo_metal_m31_square(a), stwo_metal_m31_square(b));
        uint constraint = stwo_metal_m31_sub(c, recurrence);
        row_res = stwo_metal_qm31_add(
            row_res,
            stwo_metal_qm31_mul_base(
                stwo_metal_load_qm31(random_coeff_powers, constraint_index),
                constraint
            )
        );
        a = b;
        b = c;
    }

    uint denominator_index = row_index >> domain_log_size;
    uint denominator_inverse = denominator_inverses[denominator_index];
    stwo_metal_store_qm31(dst, row_index, stwo_metal_qm31_mul_base(row_res, denominator_inverse));
}

kernel void accumulate_partial_numerators_u32x4(
    device const uint *columns [[buffer(0)]],
    device const uint *column_indices [[buffer(1)]],
    device const uint *b_coeffs [[buffer(2)]],
    device const uint *c_coeffs [[buffer(3)]],
    device uint *dst [[buffer(4)]],
    constant uint &row_count [[buffer(5)]],
    constant uint &n_terms [[buffer(6)]],
    uint row_index [[thread_position_in_grid]]
) {
    if (row_index >= row_count) {
        return;
    }

    StwoMetalQm31 numerator = StwoMetalQm31 { 0u, 0u, 0u, 0u };
    for (uint term_index = 0u; term_index < n_terms; ++term_index) {
        uint column_index = column_indices[term_index];
        uint value = columns[column_index * row_count + row_index];
        numerator = stwo_metal_qm31_add(
            numerator,
            stwo_metal_qm31_sub(
                stwo_metal_qm31_mul_base(stwo_metal_load_qm31(c_coeffs, term_index), value),
                stwo_metal_load_qm31(b_coeffs, term_index)
            )
        );
    }

    stwo_metal_store_qm31(dst, row_index, numerator);
}

kernel void accumulate_partial_numerators_batched_u32x4(
    device const uint *columns [[buffer(0)]],
    device const uint *column_indices [[buffer(1)]],
    device const uint *b_coeffs [[buffer(2)]],
    device const uint *c_coeffs [[buffer(3)]],
    device const uint *term_offsets [[buffer(4)]],
    device const uint *term_counts [[buffer(5)]],
    device uint *dst [[buffer(6)]],
    constant uint &row_count [[buffer(7)]],
    constant uint &n_batches [[buffer(8)]],
    uint gid [[thread_position_in_grid]]
) {
    uint total_rows = row_count * n_batches;
    if (gid >= total_rows) {
        return;
    }

    uint batch_index = gid / row_count;
    uint row_index = gid - batch_index * row_count;
    uint term_offset = term_offsets[batch_index];
    uint n_terms = term_counts[batch_index];

    StwoMetalQm31 numerator = StwoMetalQm31 { 0u, 0u, 0u, 0u };
    for (uint term_index = 0u; term_index < n_terms; ++term_index) {
        uint offset = term_offset + term_index;
        uint column_index = column_indices[offset];
        uint value = columns[column_index * row_count + row_index];
        numerator = stwo_metal_qm31_add(
            numerator,
            stwo_metal_qm31_sub(
                stwo_metal_qm31_mul_base(stwo_metal_load_qm31(c_coeffs, offset), value),
                stwo_metal_load_qm31(b_coeffs, offset)
            )
        );
    }

    stwo_metal_store_qm31(dst, gid, numerator);
}

// Indirect variant: reads column data through GPU virtual addresses, avoiding
// the CPU-side memmove staging copy needed by the flat-buffer variant above.
// `column_addrs` contains one uint64_t GPU address per unique column buffer.
kernel void accumulate_partial_numerators_indirect_batched_u32x4(
    device const uint64_t *column_addrs [[buffer(0)]],
    device const uint *column_indices [[buffer(1)]],
    device const uint *b_coeffs [[buffer(2)]],
    device const uint *c_coeffs [[buffer(3)]],
    device const uint *term_offsets [[buffer(4)]],
    device const uint *term_counts [[buffer(5)]],
    device uint *dst [[buffer(6)]],
    constant uint &row_count [[buffer(7)]],
    constant uint &n_batches [[buffer(8)]],
    uint gid [[thread_position_in_grid]]
) {
    uint total_rows = row_count * n_batches;
    if (gid >= total_rows) {
        return;
    }

    uint batch_index = gid / row_count;
    uint row_index = gid - batch_index * row_count;
    uint term_offset = term_offsets[batch_index];
    uint n_terms = term_counts[batch_index];

    StwoMetalQm31 numerator = StwoMetalQm31 { 0u, 0u, 0u, 0u };
    for (uint term_index = 0u; term_index < n_terms; ++term_index) {
        uint offset = term_offset + term_index;
        uint column_index = column_indices[offset];
        device const uint *col_ptr = (device const uint *)column_addrs[column_index];
        uint value = col_ptr[row_index];
        numerator = stwo_metal_qm31_add(
            numerator,
            stwo_metal_qm31_sub(
                stwo_metal_qm31_mul_base(stwo_metal_load_qm31(c_coeffs, offset), value),
                stwo_metal_load_qm31(b_coeffs, offset)
            )
        );
    }

    stwo_metal_store_qm31(dst, gid, numerator);
}

kernel void compute_quotients_and_combine_u32x4(
    device const uint *partial_coord_0 [[buffer(0)]],
    device const uint *partial_coord_1 [[buffer(1)]],
    device const uint *partial_coord_2 [[buffer(2)]],
    device const uint *partial_coord_3 [[buffer(3)]],
    device const uint *sample_points [[buffer(4)]],
    device const uint *first_linear_terms [[buffer(5)]],
    device const uint *partial_log_sizes [[buffer(6)]],
    device const uint *partial_offsets [[buffer(7)]],
    device const uint *domain_x [[buffer(8)]],
    device const uint *domain_y [[buffer(9)]],
    device uint *dst [[buffer(10)]],
    constant uint &lifting_log_size [[buffer(11)]],
    constant uint &n_accumulations [[buffer(12)]],
    uint row_index [[thread_position_in_grid]]
) {
    uint row_count = 1u << lifting_log_size;
    if (row_index >= row_count) {
        return;
    }

    uint x = domain_x[row_index];
    uint y = domain_y[row_index];
    StwoMetalQm31 quotient = StwoMetalQm31 { 0u, 0u, 0u, 0u };

    for (uint accumulation_index = 0u; accumulation_index < n_accumulations; ++accumulation_index) {
        uint sample_base = accumulation_index * 8u;
        StwoMetalCm31 prx = stwo_metal_cm31(sample_points[sample_base + 0u], sample_points[sample_base + 1u]);
        StwoMetalCm31 pix = stwo_metal_cm31(sample_points[sample_base + 2u], sample_points[sample_base + 3u]);
        StwoMetalCm31 pry = stwo_metal_cm31(sample_points[sample_base + 4u], sample_points[sample_base + 5u]);
        StwoMetalCm31 piy = stwo_metal_cm31(sample_points[sample_base + 6u], sample_points[sample_base + 7u]);

        StwoMetalCm31 denominator = stwo_metal_cm31_sub(
            stwo_metal_cm31_mul(stwo_metal_cm31_sub(prx, stwo_metal_cm31(x, 0u)), piy),
            stwo_metal_cm31_mul(stwo_metal_cm31_sub(pry, stwo_metal_cm31(y, 0u)), pix)
        );
        StwoMetalCm31 denominator_inverse = stwo_metal_cm31_inverse(denominator);

        uint partial_log_size = partial_log_sizes[accumulation_index];
        uint log_ratio = lifting_log_size - partial_log_size;
        uint lifted_index = (row_index >> (log_ratio + 1u) << 1u) + (row_index & 1u);
        uint offset = partial_offsets[accumulation_index] + lifted_index;
        StwoMetalQm31 partial_numerator = StwoMetalQm31 {
            partial_coord_0[offset],
            partial_coord_1[offset],
            partial_coord_2[offset],
            partial_coord_3[offset],
        };
        StwoMetalQm31 full_numerator = stwo_metal_qm31_sub(
            partial_numerator,
            stwo_metal_qm31_mul_base(stwo_metal_load_qm31(first_linear_terms, accumulation_index), y)
        );
        quotient = stwo_metal_qm31_add(
            quotient,
            stwo_metal_qm31_mul_cm31(full_numerator, denominator_inverse)
        );
    }

    stwo_metal_store_qm31(dst, row_index, quotient);
}

kernel void compute_quotients_and_combine_packed_u32x4(
    device const uint *partials [[buffer(0)]],
    device const uint *sample_points [[buffer(1)]],
    device const uint *first_linear_terms [[buffer(2)]],
    device const uint *partial_log_sizes [[buffer(3)]],
    device const uint *partial_offsets [[buffer(4)]],
    device const uint *domain_x [[buffer(5)]],
    device const uint *domain_y [[buffer(6)]],
    device uint *dst [[buffer(7)]],
    constant uint &lifting_log_size [[buffer(8)]],
    constant uint &n_accumulations [[buffer(9)]],
    uint row_index [[thread_position_in_grid]]
) {
    uint row_count = 1u << lifting_log_size;
    if (row_index >= row_count) {
        return;
    }

    uint x = domain_x[row_index];
    uint y = domain_y[row_index];
    StwoMetalQm31 quotient = StwoMetalQm31 { 0u, 0u, 0u, 0u };

    for (uint accumulation_index = 0u; accumulation_index < n_accumulations; ++accumulation_index) {
        uint sample_base = accumulation_index * 8u;
        StwoMetalCm31 prx = stwo_metal_cm31(sample_points[sample_base + 0u], sample_points[sample_base + 1u]);
        StwoMetalCm31 pix = stwo_metal_cm31(sample_points[sample_base + 2u], sample_points[sample_base + 3u]);
        StwoMetalCm31 pry = stwo_metal_cm31(sample_points[sample_base + 4u], sample_points[sample_base + 5u]);
        StwoMetalCm31 piy = stwo_metal_cm31(sample_points[sample_base + 6u], sample_points[sample_base + 7u]);

        StwoMetalCm31 denominator = stwo_metal_cm31_sub(
            stwo_metal_cm31_mul(stwo_metal_cm31_sub(prx, stwo_metal_cm31(x, 0u)), piy),
            stwo_metal_cm31_mul(stwo_metal_cm31_sub(pry, stwo_metal_cm31(y, 0u)), pix)
        );
        StwoMetalCm31 denominator_inverse = stwo_metal_cm31_inverse(denominator);

        uint partial_log_size = partial_log_sizes[accumulation_index];
        uint log_ratio = lifting_log_size - partial_log_size;
        uint lifted_index = (row_index >> (log_ratio + 1u) << 1u) + (row_index & 1u);
        uint offset = (partial_offsets[accumulation_index] + lifted_index) * 4u;
        StwoMetalQm31 partial_numerator = StwoMetalQm31 {
            partials[offset + 0u],
            partials[offset + 1u],
            partials[offset + 2u],
            partials[offset + 3u],
        };
        StwoMetalQm31 full_numerator = stwo_metal_qm31_sub(
            partial_numerator,
            stwo_metal_qm31_mul_base(stwo_metal_load_qm31(first_linear_terms, accumulation_index), y)
        );
        quotient = stwo_metal_qm31_add(
            quotient,
            stwo_metal_qm31_mul_cm31(full_numerator, denominator_inverse)
        );
    }

    stwo_metal_store_qm31(dst, row_index, quotient);
}

// Indirect-packed variant: reads per-accumulation packed partial buffers via GPU
// virtual addresses, eliminating the contiguous staging copy required by the
// packed variant above.  Each entry in `partial_addrs` is a uint64_t GPU
// address pointing to the start of that accumulation's packed QM31 buffer.
// The `partial_log_sizes` buffer still carries the per-accumulation log sizes
// for domain lifting, while `partial_offsets` are offsets within each
// individual buffer (typically zero when each accumulation owns its own buffer).
kernel void compute_quotients_and_combine_indirect_packed_u32x4(
    device const uint64_t *partial_addrs [[buffer(0)]],
    device const uint *sample_points [[buffer(1)]],
    device const uint *first_linear_terms [[buffer(2)]],
    device const uint *partial_log_sizes [[buffer(3)]],
    device const uint *partial_offsets [[buffer(4)]],
    device const uint *domain_x [[buffer(5)]],
    device const uint *domain_y [[buffer(6)]],
    device uint *dst [[buffer(7)]],
    constant uint &lifting_log_size [[buffer(8)]],
    constant uint &n_accumulations [[buffer(9)]],
    uint row_index [[thread_position_in_grid]]
) {
    uint row_count = 1u << lifting_log_size;
    if (row_index >= row_count) {
        return;
    }

    uint x = domain_x[row_index];
    uint y = domain_y[row_index];
    StwoMetalQm31 quotient = StwoMetalQm31 { 0u, 0u, 0u, 0u };

    for (uint accumulation_index = 0u; accumulation_index < n_accumulations; ++accumulation_index) {
        uint sample_base = accumulation_index * 8u;
        StwoMetalCm31 prx = stwo_metal_cm31(sample_points[sample_base + 0u], sample_points[sample_base + 1u]);
        StwoMetalCm31 pix = stwo_metal_cm31(sample_points[sample_base + 2u], sample_points[sample_base + 3u]);
        StwoMetalCm31 pry = stwo_metal_cm31(sample_points[sample_base + 4u], sample_points[sample_base + 5u]);
        StwoMetalCm31 piy = stwo_metal_cm31(sample_points[sample_base + 6u], sample_points[sample_base + 7u]);

        StwoMetalCm31 denominator = stwo_metal_cm31_sub(
            stwo_metal_cm31_mul(stwo_metal_cm31_sub(prx, stwo_metal_cm31(x, 0u)), piy),
            stwo_metal_cm31_mul(stwo_metal_cm31_sub(pry, stwo_metal_cm31(y, 0u)), pix)
        );
        StwoMetalCm31 denominator_inverse = stwo_metal_cm31_inverse(denominator);

        uint partial_log_size = partial_log_sizes[accumulation_index];
        uint log_ratio = lifting_log_size - partial_log_size;
        uint lifted_index = (row_index >> (log_ratio + 1u) << 1u) + (row_index & 1u);
        uint offset = (partial_offsets[accumulation_index] + lifted_index) * 4u;

        device const uint *acc_partials = (device const uint *)partial_addrs[accumulation_index];
        StwoMetalQm31 partial_numerator = StwoMetalQm31 {
            acc_partials[offset + 0u],
            acc_partials[offset + 1u],
            acc_partials[offset + 2u],
            acc_partials[offset + 3u],
        };
        StwoMetalQm31 full_numerator = stwo_metal_qm31_sub(
            partial_numerator,
            stwo_metal_qm31_mul_base(stwo_metal_load_qm31(first_linear_terms, accumulation_index), y)
        );
        quotient = stwo_metal_qm31_add(
            quotient,
            stwo_metal_qm31_mul_cm31(full_numerator, denominator_inverse)
        );
    }

    stwo_metal_store_qm31(dst, row_index, quotient);
}
