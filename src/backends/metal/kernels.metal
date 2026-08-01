#include <metal_stdlib>
using namespace metal;

#ifndef STWO_ZIG_AMALGAMATED
#include "stwo_zig/blake2s.metal"
#include "stwo_zig/m31.metal"
#include "stwo_zig/extension_fields.metal"
#include "stwo_zig/circle.metal"
#endif

struct QuotientView { uint offset, length, batch, shift, direct; };
struct RawQuotientView {
    uint offset, length, batch, shift, direct;
    uint coeff_a, coeff_b, coeff_c, coeff_d;
};
struct ResidentRawQuotientView {
    uint offset, length, batch, shift, direct;
    uint coeff_a, coeff_b, coeff_c, coeff_d;
    uint source_slot;
};

struct QuadraticRecurrenceColumn {
    device uint *values;
};

// One independent lane per stored row. The inverse order mapping keeps every
// column write coalesced while preserving coset-natural statement semantics.
kernel void stwo_zig_quadratic_recurrence_trace(
    device const QuadraticRecurrenceColumn *columns [[buffer(0)]],
    constant uint &row_count [[buffer(1)]],
    constant uint &log_n_rows [[buffer(2)]],
    constant uint &column_count [[buffer(3)]],
    constant uint *recipe [[buffer(4)]],
    uint storage_index [[thread_position_in_grid]]
) {
    if (storage_index >= row_count) return;
    uint circle_index = reverse_bits(storage_index) >> (32u - log_n_rows);
    uint half_count = row_count >> 1u;
    uint logical_row = circle_index < half_count
        ? circle_index << 1u
        : ((row_count - 1u - circle_index) << 1u) + 1u;

    // The common unit sum-of-squares recipe is a structural property, not a
    // workload identity. Keep it free of redundant multiplies by 0 and 1.
    bool unit_sum_of_squares = recipe[0] == 1u && recipe[1] == 0u &&
        recipe[2] == 0u && recipe[3] == 1u && recipe[4] == 1u &&
        recipe[5] == 1u && recipe[6] == 0u;
    uint previous = unit_sum_of_squares
        ? 1u
        : m31_add(recipe[0], m31_mul(recipe[1], logical_row));
    uint current = unit_sum_of_squares
        ? logical_row
        : m31_add(recipe[2], m31_mul(recipe[3], logical_row));
    columns[0].values[storage_index] = previous;
    columns[1].values[storage_index] = current;
    for (uint column = 2u; column < column_count; ++column) {
        uint next = unit_sum_of_squares
            ? m31_add(m31_mul(previous, previous), m31_mul(current, current))
            : m31_add(
                m31_add(
                    m31_mul(recipe[4], m31_mul(previous, previous)),
                    m31_mul(recipe[5], m31_mul(current, current))
                ),
                recipe[6]
            );
        columns[column].values[storage_index] = next;
        previous = current;
        current = next;
    }
}

kernel void stwo_zig_compact_gather(
    device uint *arena [[buffer(0)]], device const uint *source_offsets [[buffer(1)]],
    device const uint *descriptors [[buffer(2)]], constant uint *params [[buffer(3)]],
    uint row [[thread_position_in_grid]]
) {
    uint edge_count = params[0], tuple_words = params[1], total_rows = params[2];
    uint sort_rows = params[3], tuples_offset = params[4], indices_offset = params[5];
    if (row >= sort_rows) return;
    if (row == 0u) arena[params[13]] = 0u;
    arena[indices_offset + row] = row;
    if (row >= total_rows) {
        for (uint word = 0; word < tuple_words; ++word)
            arena[tuples_offset + row * tuple_words + word] = 0xffffffffu;
        return;
    }
    for (uint edge = 0; edge < edge_count; ++edge) {
        uint base = edge * 5u, producer_rows = descriptors[base];
        uint edge_rows = producer_rows * descriptors[base + 3u];
        uint destination = descriptors[base + 4u];
        if (row < destination || row >= destination + edge_rows) continue;
        uint local = row - destination;
        uint instance = local / producer_rows, producer_row = local % producer_rows;
        for (uint word = 0; word < tuple_words; ++word) {
            uint source_word = descriptors[base + 1u] + instance * descriptors[base + 2u] + word;
            arena[tuples_offset + row * tuple_words + word] =
                arena[source_offsets[edge] + source_word * producer_rows + producer_row];
        }
        return;
    }
}

kernel void stwo_zig_compact_radix_histogram(
    device uint *arena [[buffer(0)]], constant uint *params [[buffer(1)]],
    constant uint &word [[buffer(2)]], constant uint &shift [[buffer(3)]],
    constant uint &indices_offset [[buffer(4)]],
    uint row [[thread_position_in_grid]], uint lane [[thread_index_in_threadgroup]],
    uint group [[threadgroup_position_in_grid]]
) {
    threadgroup atomic_uint counts[16];
    if (lane < 16u) atomic_store_explicit(&counts[lane], 0u, memory_order_relaxed);
    threadgroup_barrier(mem_flags::mem_threadgroup);
    uint tuple_words = params[1], sort_rows = params[3], tuples_offset = params[4];
    uint counts_offset = params[7];
    if (row < sort_rows) {
        uint source = arena[indices_offset + row];
        uint digit = (arena[tuples_offset + source * tuple_words + word] >> shift) & 15u;
        atomic_fetch_add_explicit(&counts[digit], 1u, memory_order_relaxed);
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);
    if (lane < 16u) arena[counts_offset + group * 16u + lane] = atomic_load_explicit(&counts[lane], memory_order_relaxed);
}

kernel void stwo_zig_compact_radix_prefix(
    device uint *arena [[buffer(0)]], constant uint *params [[buffer(1)]],
    constant uint &block_count [[buffer(2)]], uint digit [[thread_index_in_threadgroup]]
) {
    threadgroup uint totals[16];
    uint counts_offset = params[7], offsets_offset = params[8], bases_offset = params[9];
    if (digit < 16u) {
        uint sum = 0u;
        for (uint block = 0; block < block_count; ++block) {
            uint index = block * 16u + digit;
            arena[offsets_offset + index] = sum;
            sum += arena[counts_offset + index];
        }
        totals[digit] = sum;
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);
    if (digit == 0u) {
        uint sum = 0u;
        for (uint value = 0; value < 16u; ++value) {
            arena[bases_offset + value] = sum;
            sum += totals[value];
        }
    }
}

kernel void stwo_zig_compact_radix_scatter(
    device uint *arena [[buffer(0)]], constant uint *params [[buffer(1)]],
    constant uint &word [[buffer(2)]], constant uint &shift [[buffer(3)]],
    constant uint &source_indices [[buffer(4)]], constant uint &destination_indices [[buffer(5)]],
    uint row [[thread_position_in_grid]], uint lane [[thread_index_in_threadgroup]],
    uint group [[threadgroup_position_in_grid]], uint simd_lane [[thread_index_in_simdgroup]],
    uint simd_group [[simdgroup_index_in_threadgroup]], uint group_width [[threads_per_threadgroup]]
) {
    threadgroup uint subgroup_counts[8][16];
    uint tuple_words = params[1], tuples_offset = params[4];
    uint offsets_offset = params[8], bases_offset = params[9];
    uint source = arena[source_indices + row];
    uint digit = (arena[tuples_offset + source * tuple_words + word] >> shift) & 15u;
    uint local_rank = 0u;
    for (uint value = 0; value < 16u; ++value) {
        uint present = digit == value ? 1u : 0u;
        uint rank = simd_prefix_exclusive_sum(present);
        uint count = simd_sum(present);
        if (simd_lane == 0u) subgroup_counts[simd_group][value] = count;
        if (digit == value) local_rank = rank;
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);
    uint preceding = 0u;
    for (uint subgroup = 0; subgroup < simd_group; ++subgroup) preceding += subgroup_counts[subgroup][digit];
    uint destination = arena[bases_offset + digit] + arena[offsets_offset + group * 16u + digit] + preceding + local_rank;
    arena[destination_indices + destination] = source;
}

inline bool compact_tuple_equal(
    device uint *arena, uint tuples_offset, uint tuple_words, uint lhs, uint rhs
) {
    for (uint word = 0; word < tuple_words; ++word)
        if (arena[tuples_offset + lhs * tuple_words + word] != arena[tuples_offset + rhs * tuple_words + word]) return false;
    return true;
}

inline bool compact_key_equal(
    device uint *arena, uint tuples_offset, uint tuple_words, uint key_words, uint lhs, uint rhs
) {
    for (uint word = 0; word < key_words; ++word)
        if (arena[tuples_offset + lhs * tuple_words + word] != arena[tuples_offset + rhs * tuple_words + word]) return false;
    return true;
}

kernel void stwo_zig_compact_heads(
    device uint *arena [[buffer(0)]], constant uint *params [[buffer(1)]], uint row [[thread_position_in_grid]]
) {
    uint tuple_words = params[1], total_rows = params[2], sort_rows = params[3];
    uint tuples_offset = params[4], indices_offset = params[5], heads_offset = params[10];
    uint error_offset = params[13], key_words = params[14];
    if (row >= sort_rows) return;
    if (row >= total_rows) { arena[heads_offset + row] = 0u; return; }
    if (row == 0u) { arena[heads_offset] = 1u; return; }
    uint current = arena[indices_offset + row], previous = arena[indices_offset + row - 1u];
    bool same_tuple = compact_tuple_equal(arena, tuples_offset, tuple_words, current, previous);
    if (!same_tuple && compact_key_equal(arena, tuples_offset, tuple_words, key_words, current, previous))
        atomic_store_explicit((device atomic_uint *)&arena[error_offset], 1u, memory_order_relaxed);
    arena[heads_offset + row] = same_tuple ? 0u : 1u;
}

kernel void stwo_zig_compact_scan_local(
    device uint *arena [[buffer(0)]], constant uint *params [[buffer(1)]],
    uint row [[thread_position_in_grid]], uint lane [[thread_index_in_threadgroup]],
    uint group [[threadgroup_position_in_grid]], uint group_width [[threads_per_threadgroup]]
) {
    threadgroup uint values[256];
    uint sort_rows = params[3], heads_offset = params[10], positions_offset = params[11];
    uint block_sums_offset = params[12];
    values[lane] = row < sort_rows ? arena[heads_offset + row] : 0u;
    threadgroup_barrier(mem_flags::mem_threadgroup);
    for (uint stride = 1u; stride < group_width; stride <<= 1u) {
        uint addend = lane >= stride ? values[lane - stride] : 0u;
        threadgroup_barrier(mem_flags::mem_threadgroup);
        values[lane] += addend;
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }
    if (row < sort_rows) arena[positions_offset + row] = values[lane];
    if (lane + 1u == group_width) arena[block_sums_offset + group] = values[lane];
}

kernel void stwo_zig_compact_scan_blocks(
    device uint *arena [[buffer(0)]], constant uint *params [[buffer(1)]],
    constant uint &block_count [[buffer(2)]], uint row [[thread_position_in_grid]]
) {
    if (row != 0u) return;
    uint block_sums_offset = params[12], sum = 0u;
    for (uint block = 0; block < block_count; ++block) {
        uint value = arena[block_sums_offset + block];
        arena[block_sums_offset + block] = sum;
        sum += value;
    }
}

kernel void stwo_zig_compact_scan_add(
    device uint *arena [[buffer(0)]], constant uint *params [[buffer(1)]],
    uint row [[thread_position_in_grid]], uint group [[threadgroup_position_in_grid]]
) {
    if (row < params[3]) arena[params[11] + row] += arena[params[12] + group];
}

kernel void stwo_zig_compact_clear_outputs(
    device uint *arena [[buffer(0)]], device const uint *output_offsets [[buffer(1)]],
    constant uint *params [[buffer(2)]], uint row [[thread_position_in_grid]]
) {
    uint input_count = params[15], consumer_rows = params[16];
    if (row >= consumer_rows) return;
    for (uint input = 0; input < input_count; ++input) arena[output_offsets[input] + row] = 0u;
}

kernel void stwo_zig_compact_scatter(
    device uint *arena [[buffer(0)]], device const uint *output_offsets [[buffer(1)]],
    constant uint *params [[buffer(2)]], uint row [[thread_position_in_grid]]
) {
    uint tuple_words = params[1], total_rows = params[2];
    if (row >= total_rows) return;
    uint tuples_offset = params[4], indices_offset = params[5], heads_offset = params[10];
    uint positions_offset = params[11], multiplicity_slot = params[19];
    uint compact_row = arena[positions_offset + row] - 1u;
    if (arena[heads_offset + row] != 0u) {
        uint source = arena[indices_offset + row];
        for (uint word = 0; word < tuple_words; ++word)
            arena[output_offsets[word] + compact_row] = arena[tuples_offset + source * tuple_words + word];
    }
    atomic_fetch_add_explicit((device atomic_uint *)&arena[output_offsets[multiplicity_slot] + compact_row], 1u, memory_order_relaxed);
}

kernel void stwo_zig_compact_finalize(
    device uint *arena [[buffer(0)]], device const uint *output_offsets [[buffer(1)]],
    constant uint *params [[buffer(2)]], uint row [[thread_position_in_grid]]
) {
    uint tuple_words = params[1], total_rows = params[2], positions_offset = params[11];
    uint error_offset = params[13], consumer_rows = params[16], unique_offset = params[17];
    uint enabler_slot = params[18], multiplicity_slot = params[19], iota_slot = params[20];
    uint unique = arena[positions_offset + total_rows - 1u];
    uint expected = unique < 16u ? 16u : 1u << (32u - clz(unique - 1u));
    bool invalid = arena[error_offset] != 0u || unique == 0u || unique > consumer_rows || expected != consumer_rows;
    if (row == 0u) arena[unique_offset] = invalid ? 0xffffffffu : unique;
    if (row >= consumer_rows || invalid) return;
    if (row >= unique) {
        for (uint word = 0; word < tuple_words; ++word)
            arena[output_offsets[word] + row] = arena[output_offsets[word]];
        arena[output_offsets[multiplicity_slot] + row] = 0u;
    }
    if (enabler_slot != 0xffffffffu) arena[output_offsets[enabler_slot] + row] = row < unique ? 1u : 0u;
    if (iota_slot != 0xffffffffu) arena[output_offsets[iota_slot] + row] = row;
}

kernel void stwo_zig_fri_fold_circle(
    device const uint *source [[buffer(0)]],
    device const uint *inverse_y [[buffer(1)]],
    constant Qm31Value &alpha [[buffer(2)]],
    device Qm31Value *destination [[buffer(3)]],
    constant uint &destination_count [[buffer(4)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= destination_count) return;
    uint source_count = destination_count << 1u;
    uint left = index << 1u;
    uint right = left + 1u;
    Qm31Value f0 = { source[left], source[source_count + left],
                     source[2u * source_count + left], source[3u * source_count + left] };
    Qm31Value f1 = { source[right], source[source_count + right],
                     source[2u * source_count + right], source[3u * source_count + right] };
    Qm31Value sum = qm_add(f0, f1);
    Qm31Value difference = qm_mul_m31(qm_sub(f0, f1), inverse_y[index]);
    destination[index] = qm_add(sum, qm_mul(alpha, difference));
}

// Runtime quotient requests precompute prx*piy - pry*pix once per sample.
// Since domain x/y are base-field values, each row then needs only two CM31
// by M31 products instead of two full CM31 products.
inline Cm31Value quotient_denominator_precomputed(
    device const uint *sample_components,
    uint sample_base,
    uint domain_x,
    uint domain_y
) {
    Cm31Value determinant = {
        sample_components[sample_base], sample_components[sample_base + 1u]
    };
    Cm31Value pix = {
        sample_components[sample_base + 4u], sample_components[sample_base + 5u]
    };
    Cm31Value piy = {
        sample_components[sample_base + 6u], sample_components[sample_base + 7u]
    };
    return cm_add(
        cm_sub(determinant, cm_mul_m31(piy, domain_x)),
        cm_mul_m31(pix, domain_y)
    );
}

kernel void stwo_zig_quotient_rows(
    device const uint *flat_views [[buffer(0)]],
    device const QuotientView *views [[buffer(1)]],
    constant uint &view_count [[buffer(2)]],
    device const uint *sample_components [[buffer(3)]],
    device const uint *linear_terms [[buffer(4)]],
    constant uint &batch_count [[buffer(5)]],
    device const uint *domain_x [[buffer(6)]],
    device const uint *domain_y [[buffer(7)]],
    device uint *output [[buffer(8)]],
    constant uint &row_count [[buffer(9)]],
    uint row [[thread_position_in_grid]]
) {
    if (row >= row_count) return;
    Qm31Value accumulator = { 0u, 0u, 0u, 0u };
    for (uint batch = 0; batch < batch_count; ++batch) {
        Qm31Value numerator_sum = { 0u, 0u, 0u, 0u };
        for (uint view_index = 0; view_index < view_count; ++view_index) {
            QuotientView view = views[view_index];
            if (view.batch != batch) continue;
            uint source = view.direct != 0u
                ? row
                : ((row >> view.shift) << 1u) | (row & 1u);
            uint base = view.offset + source;
            Qm31Value value = {
                flat_views[base],
                flat_views[base + view.length],
                flat_views[base + 2u * view.length],
                flat_views[base + 3u * view.length],
            };
            numerator_sum = qm_add(numerator_sum, value);
        }

        uint sample_base = batch * 8u;
        Cm31Value denominator = quotient_denominator_precomputed(
            sample_components, sample_base, domain_x[row], domain_y[row]
        );
        Cm31Value denominator_inverse = cm_inv(denominator);

        uint linear_base = batch * 8u;
        Qm31Value sum_a = { linear_terms[linear_base], linear_terms[linear_base + 1u],
                            linear_terms[linear_base + 2u], linear_terms[linear_base + 3u] };
        Qm31Value sum_b = { linear_terms[linear_base + 4u], linear_terms[linear_base + 5u],
                            linear_terms[linear_base + 6u], linear_terms[linear_base + 7u] };
        Qm31Value numerator = qm_sub(numerator_sum, qm_add(qm_mul_m31(sum_a, domain_y[row]), sum_b));
        accumulator = qm_add(accumulator, qm_mul_cm(numerator, denominator_inverse));
    }
    output[row] = accumulator.a;
    output[row_count + row] = accumulator.b;
    output[2u * row_count + row] = accumulator.c;
    output[3u * row_count + row] = accumulator.d;
}

kernel void stwo_zig_quotient_rows_raw(
    device const uint *source_0 [[buffer(0)]],
    device const uint *source_1 [[buffer(1)]],
    device const uint *source_2 [[buffer(2)]],
    device const uint *source_3 [[buffer(3)]],
    device const ResidentRawQuotientView *views [[buffer(4)]],
    constant uint &view_count [[buffer(5)]],
    device const uint *sample_components [[buffer(6)]],
    device const uint *linear_terms [[buffer(7)]],
    constant uint &batch_count [[buffer(8)]],
    device const uint *domain_x [[buffer(9)]],
    device const uint *domain_y [[buffer(10)]],
    device uint *output [[buffer(11)]],
    constant uint &row_count [[buffer(12)]],
    uint row [[thread_position_in_grid]]
) {
    if (row >= row_count) return;
    Qm31Value accumulator = { 0u, 0u, 0u, 0u };
    for (uint batch = 0; batch < batch_count; ++batch) {
        Qm31Value numerator_sum = { 0u, 0u, 0u, 0u };
        for (uint view_index = 0; view_index < view_count; ++view_index) {
            ResidentRawQuotientView view = views[view_index];
            if (view.batch != batch) continue;
            uint source = view.direct != 0u
                ? row
                : ((row >> view.shift) << 1u) | (row & 1u);
            uint source_index = view.offset + source;
            uint value;
            switch (view.source_slot) {
                case 0u: value = source_0[source_index]; break;
                case 1u: value = source_1[source_index]; break;
                case 2u: value = source_2[source_index]; break;
                default: value = source_3[source_index]; break;
            }
            numerator_sum = qm_add(numerator_sum, {
                m31_mul(value, view.coeff_a), m31_mul(value, view.coeff_b),
                m31_mul(value, view.coeff_c), m31_mul(value, view.coeff_d),
            });
        }

        uint sample_base = batch * 8u;
        Cm31Value denominator = quotient_denominator_precomputed(
            sample_components, sample_base, domain_x[row], domain_y[row]
        );
        Cm31Value denominator_inverse = cm_inv(denominator);
        uint linear_base = batch * 8u;
        Qm31Value sum_a = { linear_terms[linear_base], linear_terms[linear_base + 1u],
                            linear_terms[linear_base + 2u], linear_terms[linear_base + 3u] };
        Qm31Value sum_b = { linear_terms[linear_base + 4u], linear_terms[linear_base + 5u],
                            linear_terms[linear_base + 6u], linear_terms[linear_base + 7u] };
        Qm31Value numerator = qm_sub(numerator_sum, qm_add(qm_mul_m31(sum_a, domain_y[row]), sum_b));
        accumulator = qm_add(accumulator, qm_mul_cm(numerator, denominator_inverse));
    }
    output[row] = accumulator.a;
    output[row_count + row] = accumulator.b;
    output[2u * row_count + row] = accumulator.c;
    output[3u * row_count + row] = accumulator.d;
}

kernel void stwo_zig_quotient_numerator_raw(
    device const uint *flat_columns [[buffer(0)]],
    device const RawQuotientView *views [[buffer(1)]],
    constant uint &view_count [[buffer(2)]],
    device Qm31Value *numerators [[buffer(3)]],
    constant uint &batch_count [[buffer(4)]],
    constant uint &row_count [[buffer(5)]],
    uint row [[thread_position_in_grid]]
) {
    if (row >= row_count) return;
    for (uint batch = 0; batch < batch_count; ++batch) {
        Qm31Value sum = numerators[batch * row_count + row];
        for (uint view_index = 0; view_index < view_count; ++view_index) {
            RawQuotientView view = views[view_index];
            if (view.batch != batch) continue;
            uint source = view.direct != 0u
                ? row
                : ((row >> view.shift) << 1u) | (row & 1u);
            uint value = flat_columns[view.offset + source];
            sum = qm_add(sum, {
                m31_mul(value, view.coeff_a), m31_mul(value, view.coeff_b),
                m31_mul(value, view.coeff_c), m31_mul(value, view.coeff_d),
            });
        }
        numerators[batch * row_count + row] = sum;
    }
}

kernel void stwo_zig_quotient_finalize(
    device const Qm31Value *numerators [[buffer(0)]],
    device const uint *sample_components [[buffer(1)]],
    device const uint *linear_terms [[buffer(2)]],
    constant uint &batch_count [[buffer(3)]],
    device const uint *domain_x [[buffer(4)]],
    device const uint *domain_y [[buffer(5)]],
    device uint *output [[buffer(6)]],
    constant uint &row_count [[buffer(7)]],
    uint row [[thread_position_in_grid]]
) {
    if (row >= row_count) return;
    Qm31Value accumulator = { 0u, 0u, 0u, 0u };
    for (uint batch = 0; batch < batch_count; ++batch) {
        uint sample_base = batch * 8u;
        Cm31Value denominator = quotient_denominator_precomputed(
            sample_components, sample_base, domain_x[row], domain_y[row]
        );
        uint linear_base = batch * 8u;
        Qm31Value sum_a = { linear_terms[linear_base], linear_terms[linear_base + 1u],
                            linear_terms[linear_base + 2u], linear_terms[linear_base + 3u] };
        Qm31Value sum_b = { linear_terms[linear_base + 4u], linear_terms[linear_base + 5u],
                            linear_terms[linear_base + 6u], linear_terms[linear_base + 7u] };
        Qm31Value numerator = qm_sub(
            numerators[batch * row_count + row],
            qm_add(qm_mul_m31(sum_a, domain_y[row]), sum_b)
        );
        accumulator = qm_add(accumulator, qm_mul_cm(numerator, cm_inv(denominator)));
    }
    output[row] = accumulator.a;
    output[row_count + row] = accumulator.b;
    output[2u * row_count + row] = accumulator.c;
    output[3u * row_count + row] = accumulator.d;
}

inline CircleM31Value quotient_domain_point(
    uint initial_index,
    uint step_size,
    uint row,
    uint row_count,
    uint log_size
) {
    uint domain_index = reverse_bits(row) >> (32u - log_size);
    uint half_count = row_count >> 1u;
    uint local = domain_index < half_count ? domain_index : domain_index - half_count;
    ulong global = (ulong)initial_index + (ulong)step_size * local;
    uint exponent = (uint)(global & 0x7ffffffful);
    if (domain_index >= half_count) exponent = (0x80000000u - exponent) & 0x7fffffffu;
    return circle_pow(exponent);
}

struct QuotientCoefficientTerm {
    ulong source_offset;
    uint source_words;
    uint c0;
    uint c1;
    uint c2;
    uint c3;
};

struct QuotientCoefficientTask {
    uint term_start;
    uint term_count;
    uint destination0;
    uint destination1;
    uint destination2;
    uint destination3;
    uint row_count;
    uint b0;
    uint b1;
    uint b2;
    uint b3;
};

kernel void stwo_zig_quotient_coefficients_resident(
    device uint *arena [[buffer(0)]],
    device const QuotientCoefficientTerm *terms [[buffer(1)]],
    device const QuotientCoefficientTask *tasks [[buffer(2)]],
    device const uint *row_starts [[buffer(3)]],
    constant uint &task_count [[buffer(4)]],
    constant uint &total_rows [[buffer(5)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= total_rows) return;
    uint low = 0u;
    uint high = task_count;
    while (low + 1u < high) {
        uint middle = low + ((high - low) >> 1u);
        if (row_starts[middle] <= gid) low = middle;
        else high = middle;
    }
    QuotientCoefficientTask task = tasks[low];
    uint row = gid - row_starts[low];
    if (row >= task.row_count) return;

    uint accum0 = 0u;
    uint accum1 = 0u;
    uint accum2 = 0u;
    uint accum3 = 0u;
    for (uint i = 0u; i < task.term_count; ++i) {
        QuotientCoefficientTerm term = terms[task.term_start + i];
        if (row >= term.source_words) continue;
        uint value = arena[term.source_offset + (ulong)row];
        accum0 = m31_add(accum0, m31_mul(value, term.c0));
        accum1 = m31_add(accum1, m31_mul(value, term.c1));
        accum2 = m31_add(accum2, m31_mul(value, term.c2));
        accum3 = m31_add(accum3, m31_mul(value, term.c3));
    }
    if (row == 0u) {
        accum0 = m31_sub(accum0, task.b0);
        accum1 = m31_sub(accum1, task.b1);
        accum2 = m31_sub(accum2, task.b2);
        accum3 = m31_sub(accum3, task.b3);
    }
    arena[task.destination0 + row] = accum0;
    arena[task.destination1 + row] = accum1;
    arena[task.destination2 + row] = accum2;
    arena[task.destination3 + row] = accum3;
}

kernel void stwo_zig_quotient_domain_points_resident(
    device uint *arena [[buffer(0)]],
    constant uint &destination_offset [[buffer(1)]],
    constant uint &row_count [[buffer(2)]],
    constant uint &log_size [[buffer(3)]],
    constant uint &initial_index [[buffer(4)]],
    constant uint &step_size [[buffer(5)]],
    constant uint &mode [[buffer(6)]],
    uint row [[thread_position_in_grid]]
) {
    if (row >= row_count) return;
    if (mode != 0u) {
        uint natural = reverse_bits(row) >> (32u - log_size);
        ulong global = (ulong)initial_index + (ulong)step_size * natural;
        CircleM31Value point = circle_pow((uint)(global & 0x7ffffffful));
        uint coordinate = mode == 1u ? point.x : point.y;
        arena[destination_offset + row] = m31_inv(coordinate);
        return;
    }
    CircleM31Value point = quotient_domain_point(initial_index, step_size, row, row_count, log_size);
    arena[destination_offset + row] = point.x;
    arena[destination_offset + row_count + row] = point.y;
}

kernel void stwo_zig_quotient_denominators_resident(
    device uint *arena [[buffer(0)]],
    constant uint &domain_offset [[buffer(1)]],
    constant uint &sample_offset [[buffer(2)]],
    constant uint &scratch_offset [[buffer(3)]],
    constant uint &row_count [[buffer(4)]],
    constant uint &sample_count [[buffer(5)]],
    uint gid [[thread_position_in_grid]]
) {
    uint total = row_count * sample_count;
    if (gid >= total) return;
    uint row = gid / sample_count;
    uint sample = gid - row * sample_count;
    uint base = sample_offset + sample * 8u;
    Cm31Value prx = { arena[base], arena[base + 1u] };
    Cm31Value pix = { arena[base + 2u], arena[base + 3u] };
    Cm31Value pry = { arena[base + 4u], arena[base + 5u] };
    Cm31Value piy = { arena[base + 6u], arena[base + 7u] };
    uint x = arena[domain_offset + row];
    uint y = arena[domain_offset + row_count + row];
    Cm31Value denominator = cm_sub(
        cm_mul(cm_sub(prx, { x, 0u }), piy),
        cm_mul(cm_sub(pry, { y, 0u }), pix)
    );
    Cm31Value inverse = cm_inv(denominator);
    arena[scratch_offset + gid * 2u] = inverse.a;
    arena[scratch_offset + gid * 2u + 1u] = inverse.b;
}

kernel void stwo_zig_quotient_combine_resident(
    device uint *arena [[buffer(0)]],
    device const uint *partial_offsets [[buffer(1)]],
    device const uint *partial_logs [[buffer(2)]],
    constant uint &sample_offset [[buffer(3)]],
    constant uint &linear_offset [[buffer(4)]],
    constant uint &scratch_offset [[buffer(5)]],
    constant uint &output_offset [[buffer(6)]],
    constant uint &row_count [[buffer(7)]],
    constant uint &log_size [[buffer(8)]],
    constant uint &sample_count [[buffer(9)]],
    uint row [[thread_position_in_grid]]
) {
    if (row >= row_count) return;
    uint y = arena[output_offset + row_count + row];
    Qm31Value quotient = { 0u, 0u, 0u, 0u };
    for (uint sample = 0u; sample < sample_count; ++sample) {
        uint partial_log = partial_logs[sample];
        uint log_ratio = log_size - partial_log;
        uint lifted = (row >> (log_ratio + 1u) << 1u) + (row & 1u);
        Qm31Value partial = {
            arena[partial_offsets[sample] + lifted],
            arena[partial_offsets[sample_count + sample] + lifted],
            arena[partial_offsets[2u * sample_count + sample] + lifted],
            arena[partial_offsets[3u * sample_count + sample] + lifted],
        };
        uint linear = linear_offset + sample * 4u;
        Qm31Value first = { arena[linear], arena[linear + 1u], arena[linear + 2u], arena[linear + 3u] };
        uint inverse = scratch_offset + (row * sample_count + sample) * 2u;
        quotient = qm_add(quotient, qm_mul_cm(
            qm_sub(partial, qm_mul_m31(first, y)),
            { arena[inverse], arena[inverse + 1u] }
        ));
    }
    arena[output_offset + row] = quotient.a;
    arena[output_offset + row_count + row] = quotient.b;
    arena[output_offset + 2u * row_count + row] = quotient.c;
    arena[output_offset + 3u * row_count + row] = quotient.d;
}

inline Qm31Value fri_load_planar(device const uint *arena, uint base, uint stride, uint index) {
    return {
        arena[base + index], arena[base + stride + index],
        arena[base + 2u * stride + index], arena[base + 3u * stride + index],
    };
}

inline uint fri_circle_twiddle(device const uint *twiddles, uint offset, uint index) {
    uint k = index >> 2u;
    uint a = twiddles[offset + 2u * k];
    uint b = twiddles[offset + 2u * k + 1u];
    switch (index & 3u) {
        case 0u: return b;
        case 1u: return m31_neg(b);
        case 2u: return m31_neg(a);
        default: return a;
    }
}

inline Qm31Value fri_fold_pair(Qm31Value left, Qm31Value right, uint inverse, Qm31Value alpha) {
    return qm_add(qm_add(left, right), qm_mul(alpha, qm_mul_m31(qm_sub(left, right), inverse)));
}

kernel void stwo_zig_fri_fold3_resident(
    device uint *arena [[buffer(0)]],
    constant uint &twiddle_base [[buffer(1)]],
    constant uint &twiddle_offset_0 [[buffer(2)]],
    constant uint &twiddle_offset_1 [[buffer(3)]],
    constant uint &twiddle_offset_2 [[buffer(4)]],
    constant uint &input_base [[buffer(5)]],
    constant uint &input_stride [[buffer(6)]],
    constant uint &alpha_base [[buffer(7)]],
    constant uint &output_base [[buffer(8)]],
    constant uint &output_stride [[buffer(9)]],
    constant uint &n [[buffer(10)]],
    constant uint &first_circle [[buffer(11)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= (n >> 3u)) return;
    Qm31Value alpha0 = { arena[alpha_base], arena[alpha_base + 1u], arena[alpha_base + 2u], arena[alpha_base + 3u] };
    Qm31Value alpha1 = qm_mul(alpha0, alpha0);
    Qm31Value alpha2 = qm_mul(alpha1, alpha1);
    Qm31Value stage0[4];
    for (uint k = 0u; k < 4u; ++k) {
        uint out = 4u * index + k;
        uint inverse = first_circle != 0u
            ? fri_circle_twiddle(arena, twiddle_base + twiddle_offset_0, out)
            : arena[twiddle_base + twiddle_offset_0 + out];
        stage0[k] = fri_fold_pair(
            fri_load_planar(arena, input_base, input_stride, 2u * out),
            fri_load_planar(arena, input_base, input_stride, 2u * out + 1u),
            inverse,
            alpha0
        );
    }
    Qm31Value stage1[2];
    for (uint k = 0u; k < 2u; ++k) {
        uint out = 2u * index + k;
        stage1[k] = fri_fold_pair(
            stage0[2u * k], stage0[2u * k + 1u],
            arena[twiddle_base + twiddle_offset_1 + out], alpha1
        );
    }
    Qm31Value result = fri_fold_pair(
        stage1[0], stage1[1], arena[twiddle_base + twiddle_offset_2 + index], alpha2
    );
    arena[output_base + index] = result.a;
    arena[output_base + output_stride + index] = result.b;
    arena[output_base + 2u * output_stride + index] = result.c;
    arena[output_base + 3u * output_stride + index] = result.d;
}

kernel void stwo_zig_fri_fold2_resident(
    device uint *arena [[buffer(0)]],
    constant uint &twiddle_base [[buffer(1)]],
    constant uint &twiddle_offset_0 [[buffer(2)]],
    constant uint &twiddle_offset_1 [[buffer(3)]],
    constant uint &input_base [[buffer(4)]],
    constant uint &input_stride [[buffer(5)]],
    constant uint &alpha_base [[buffer(6)]],
    constant uint &output_base [[buffer(7)]],
    constant uint &output_stride [[buffer(8)]],
    constant uint &n [[buffer(9)]],
    uint index [[thread_position_in_grid]]
) {
    if (index >= (n >> 2u)) return;
    Qm31Value alpha0 = { arena[alpha_base], arena[alpha_base + 1u], arena[alpha_base + 2u], arena[alpha_base + 3u] };
    Qm31Value alpha1 = qm_mul(alpha0, alpha0);
    Qm31Value stage0[2];
    for (uint k = 0u; k < 2u; ++k) {
        uint out = 2u * index + k;
        stage0[k] = fri_fold_pair(
            fri_load_planar(arena, input_base, input_stride, 2u * out),
            fri_load_planar(arena, input_base, input_stride, 2u * out + 1u),
            arena[twiddle_base + twiddle_offset_0 + out], alpha0
        );
    }
    Qm31Value result = fri_fold_pair(
        stage0[0], stage0[1], arena[twiddle_base + twiddle_offset_1 + index], alpha1
    );
    arena[output_base + index] = result.a;
    arena[output_base + output_stride + index] = result.b;
    arena[output_base + 2u * output_stride + index] = result.c;
    arena[output_base + 3u * output_stride + index] = result.d;
}

kernel void stwo_zig_fri_packed_leaves_resident(
    device uint *arena [[buffer(0)]],
    constant uint &evaluation_base [[buffer(1)]],
    constant uint &coordinate_stride [[buffer(2)]],
    constant uint &evaluation_size [[buffer(3)]],
    constant uint &log_rows_per_leaf [[buffer(4)]],
    constant uint &destination_base [[buffer(5)]],
    constant uint *leaf_seed [[buffer(6)]],
    constant uint &prefix_bytes [[buffer(7)]],
    uint leaf [[thread_position_in_grid]]
) {
    uint leaf_count = evaluation_size >> log_rows_per_leaf;
    if (leaf >= leaf_count) return;
    uint state[8], message[16];
    if (prefix_bytes == 0u) blake2s_init_hash(state);
    else blake2s_init_seeded(state, leaf_seed);
    for (uint i = 0u; i < 16u; ++i) message[i] = 0u;
    if (log_rows_per_leaf == 0u) {
        for (uint coordinate = 0u; coordinate < 4u; ++coordinate)
            message[coordinate] = arena[evaluation_base + coordinate * coordinate_stride + leaf];
        blake2s_compress(state, message, prefix_bytes + 16u, true);
    } else {
        for (uint offset = 0u; offset < 4u; ++offset) {
            for (uint coordinate = 0u; coordinate < 4u; ++coordinate) {
                message[coordinate + 4u * offset] =
                    arena[evaluation_base + coordinate * coordinate_stride + 4u * leaf + offset];
            }
        }
        blake2s_compress(state, message, prefix_bytes + 64u, true);
    }
    for (uint i = 0u; i < 8u; ++i) arena[destination_base + leaf * 8u + i] = state[i];
}

kernel void stwo_zig_fri_final_line_resident(
    device uint *arena [[buffer(0)]],
    constant uint &evaluation_base [[buffer(1)]],
    constant uint &coordinate_stride [[buffer(2)]],
    constant uint &inverse_x [[buffer(3)]],
    constant uint &coefficient_base [[buffer(4)]],
    constant uint &degree_error [[buffer(5)]],
    uint lane [[thread_position_in_grid]]
) {
    if (lane != 0u) return;
    Qm31Value left = fri_load_planar(arena, evaluation_base, coordinate_stride, 0u);
    Qm31Value right = fri_load_planar(arena, evaluation_base, coordinate_stride, 1u);
    Qm31Value c0 = qm_mul_m31(qm_add(left, right), 1073741824u);
    Qm31Value c1 = qm_mul_m31(qm_mul_m31(qm_sub(left, right), inverse_x), 1073741824u);
    arena[coefficient_base] = c0.a;
    arena[coefficient_base + 1u] = c0.b;
    arena[coefficient_base + 2u] = c0.c;
    arena[coefficient_base + 3u] = c0.d;
    arena[coefficient_base + 4u] = c1.a;
    arena[coefficient_base + 5u] = c1.b;
    arena[coefficient_base + 6u] = c1.c;
    arena[coefficient_base + 7u] = c1.d;
    arena[degree_error] = (c1.a | c1.b | c1.c | c1.d) != 0u ? 1u : 0u;
}
