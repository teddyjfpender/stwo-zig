#include "quotients.cuh"
#include "poly_utils.cuh"
#include <cstdio>


typedef struct {
    secure_field_point point;
    uint32_t *columns;
    qm31 *values;
    uint32_t size;
    size_t offset;
} column_sample_batch;

HOST_DEVICE_FORCEINLINE point index_to_point(uint32_t index) {
    return point_pow(m31_circle_gen, (int)index);
}

DEVICE_FORCEINLINE point domain_at_index(uint32_t half_coset_initial_index, uint32_t half_coset_step_size, uint32_t index, uint32_t domain_size) {
    uint32_t half_coset_size = domain_size >> 1;

    if (index < half_coset_size) {
        int modulo_u31_mask = 0x7fffffff;
        uint64_t global_index = (uint64_t) half_coset_initial_index + (uint64_t) half_coset_step_size * (uint64_t) index;
        return index_to_point(global_index & modulo_u31_mask);
    } else {
        int modulo_u31_mask = 0x7fffffff;
        uint64_t global_index = (uint64_t) half_coset_initial_index + (uint64_t) half_coset_step_size * (uint64_t) (index - half_coset_size);
        return index_to_point((2147483648 - global_index) & modulo_u31_mask);
    }
}

void column_sample_batches_for(
        secure_field_point *sample_points,
        uint32_t *sample_column_indexes,
        qm31 *sample_column_values,
        const uint32_t *sample_column_and_values_sizes,
        uint32_t sample_size,
        column_sample_batch *result
) {
    unsigned int offset = 0;
    for (unsigned int index = 0; index < sample_size; index++) {
        result[index].point = sample_points[index];
        result[index].columns = &sample_column_indexes[offset];
        result[index].values = &sample_column_values[offset];
        result[index].size = sample_column_and_values_sizes[index];
        result[index].offset = offset;
        offset += sample_column_and_values_sizes[index];
    }
}

DEVICE_FORCEINLINE void complex_conjugate_line_coeffs(secure_field_point point, qm31 value, qm31 alpha, qm31* a_out, qm31* b_out, qm31* c_out) {
    qm31 a = sub(qm31{value.a, neg(value.b)}, value);
    qm31 c = sub(qm31{point.y.a, neg(point.y.b)}, point.y);
    qm31 b = sub(mul(value, c), mul(a, point.y));

    *a_out = mul(alpha, a);
    *b_out = mul(alpha, b);
    *c_out = mul(alpha, c);
}

__global__ void column_line_and_batch_random_coeffs(
    column_sample_batch *sample_batches,
    uint32_t sample_size,
    qm31 random_coefficient,
    qm31 *flattened_line_coeffs,
    uint32_t *line_coeffs_sizes,
    qm31 *batch_random_coeffs
) {
    int tid = threadIdx.x + blockDim.x * blockIdx.x;
    if(tid < sample_size) {
        // Calculate Batch Random Coeffs
        batch_random_coeffs[tid] = pow(random_coefficient, sample_batches[tid].size);

        // Calculate Column Line Coeffs
        line_coeffs_sizes[tid] = sample_batches[tid].size;
        size_t sample_batches_offset = sample_batches[tid].offset * 3;

        qm31 alpha = qm31{cm31{m31{1}, m31{0}}, cm31{m31{0}, m31{0}}};

        for(size_t j = 0; j < sample_batches[tid].size; ++j) {
            qm31 sampled_value = sample_batches[tid].values[j];
            alpha = mul(alpha, random_coefficient);
            secure_field_point point = sample_batches[tid].point;
            qm31 value = sampled_value;

            size_t sampled_offset = sample_batches_offset + (j * 3);
            complex_conjugate_line_coeffs(point, value, alpha, &flattened_line_coeffs[sampled_offset], &flattened_line_coeffs[sampled_offset + 1], &flattened_line_coeffs[sampled_offset + 2]);
        }
    }
}


constexpr uint32_t ACCUMULATE_QUOTIENT_INVERSE_CHUNK = 4;
constexpr uint32_t COMBINE_QUOTIENT_INVERSE_CHUNK = 8;
constexpr int QUOTIENT_COMBINE_BLOCK_DIM = 512;
constexpr int QUOTIENT_PRODUCER_B2N_BLOCK_DIM = 128;
constexpr uint32_t QUOTIENT_PRODUCER_B2N_FIRST_STAGES = 7;

DEVICE_FORCEINLINE cm31 denominator_for_sample(
        const secure_field_point sample_point,
        const point domain_point
) {
    const cm31 prx = sample_point.x.a;
    const cm31 pry = sample_point.y.a;
    const cm31 pix = sample_point.x.b;
    const cm31 piy = sample_point.y.b;
    const cm31 first_subtraction = {sub(prx.a, domain_point.x), prx.b};
    const cm31 second_subtraction = {sub(pry.a, domain_point.y), pry.b};
    return sub(mul(first_subtraction, piy), mul(second_subtraction, pix));
}

DEVICE_FORCEINLINE secure_field_point quotient_sample_point(
        const secure_field_point *sample_points,
        const uint32_t sample
) {
    return sample_points[sample];
}

DEVICE_FORCEINLINE secure_field_point quotient_sample_point(
        const column_sample_batch *sample_batches,
        const uint32_t sample
) {
    return sample_batches[sample].point;
}

// Batch the sequential inversions owned by one row. Padding a tail chunk with
// ones keeps every array index compile-time constant, so ptxas can retain the
// prefix products in registers. Denominators are recomputed on the reverse
// sweep rather than retained, limiting the live array to two words per sample.
// Zeros retain the scalar device convention inv(0) == 0.
template <uint32_t CHUNK_SIZE, typename Sample>
DEVICE_FORCEINLINE void quotient_inverse_chunk(
        const Sample *samples,
        const uint32_t sample_start,
        const uint32_t sample_count,
        const point domain_point,
        cm31 *inverses
) {
    uint32_t zero_mask = 0;

#pragma unroll
    for (uint32_t offset = 0; offset < CHUNK_SIZE; ++offset) {
        cm31 denominator = cm31{1, 0};
        if (offset < sample_count) {
            denominator = denominator_for_sample(
                    quotient_sample_point(samples, sample_start + offset), domain_point);
            const bool is_zero = denominator.a == 0 && denominator.b == 0;
            zero_mask |= static_cast<uint32_t>(is_zero) << offset;
            denominator = is_zero ? cm31{1, 0} : denominator;
        }
        inverses[offset] =
            offset == 0 ? denominator : mul(inverses[offset - 1], denominator);
    }

    cm31 inverse_product = inv(inverses[CHUNK_SIZE - 1]);
#pragma unroll
    for (int offset = CHUNK_SIZE - 1; offset > 0; --offset) {
        cm31 denominator = cm31{1, 0};
        if (static_cast<uint32_t>(offset) < sample_count) {
            denominator = denominator_for_sample(
                    quotient_sample_point(samples, sample_start + offset), domain_point);
            if (denominator.a == 0 && denominator.b == 0) {
                denominator = cm31{1, 0};
            }
        }
        const cm31 denominator_inverse = mul(inverse_product, inverses[offset - 1]);
        inverse_product = mul(inverse_product, denominator);
        inverses[offset] = (zero_mask & (1u << offset)) != 0
            ? cm31{0, 0}
            : denominator_inverse;
    }
    inverses[0] = (zero_mask & 1u) != 0 ? cm31{0, 0} : inverse_product;
}

__global__ void __launch_bounds__(QUOTIENT_COMBINE_BLOCK_DIM, 1)
accumulate_quotients_in_gpu(
        uint32_t half_coset_initial_index,
        uint32_t half_coset_step_size,
        uint32_t domain_size,
        int domain_log_size,
        m31 **columns,
        uint32_t number_of_columns,
        qm31 random_coefficient,
        column_sample_batch *sample_batches,
        uint32_t sample_size,
        uint32_t *result_column_0,
        uint32_t *result_column_1,
        uint32_t *result_column_2,
        uint32_t *result_column_3,
        qm31 *flattened_line_coeffs,
        uint32_t *line_coeffs_sizes,
        qm31 *batch_random_coeffs
) {
    int row = threadIdx.x + blockDim.x * blockIdx.x;
    if (row < domain_size) {
        uint32_t domain_index = bit_reverse(row, domain_log_size);
        point domain_point = domain_at_index(half_coset_initial_index, half_coset_step_size, domain_index, domain_size);

        qm31 row_accumulator = qm31{cm31{0, 0}, cm31{0, 0}};
        int line_coeffs_offset = 0;
        for (uint32_t sample_start = 0; sample_start < sample_size;
             sample_start += ACCUMULATE_QUOTIENT_INVERSE_CHUNK) {
            const uint32_t remaining = sample_size - sample_start;
            const uint32_t sample_count = remaining < ACCUMULATE_QUOTIENT_INVERSE_CHUNK
                ? remaining
                : ACCUMULATE_QUOTIENT_INVERSE_CHUNK;
            cm31 denominator_inverses[ACCUMULATE_QUOTIENT_INVERSE_CHUNK];
            quotient_inverse_chunk<ACCUMULATE_QUOTIENT_INVERSE_CHUNK>(
                    sample_batches,
                    sample_start,
                    sample_count,
                    domain_point,
                    denominator_inverses);

#pragma unroll
            for (uint32_t offset = 0; offset < ACCUMULATE_QUOTIENT_INVERSE_CHUNK;
                 ++offset) {
                if (offset >= sample_count) {
                    continue;
                }
                const uint32_t sample = sample_start + offset;
                column_sample_batch sample_batch = sample_batches[sample];
                qm31 *line_coeffs = &flattened_line_coeffs[line_coeffs_offset * 3];
                qm31 batch_coeff = batch_random_coeffs[sample];
                int line_coeffs_size = line_coeffs_sizes[sample];

                qm31 numerator = qm31{cm31{0, 0}, cm31{0, 0}};
                for(int j = 0; j < line_coeffs_size; j++) {
                    qm31 a = line_coeffs[3 * j + 0];
                    qm31 b = line_coeffs[3 * j + 1];
                    qm31 c = line_coeffs[3 * j + 2];

                    int column_index = sample_batch.columns[j];
                    qm31 linear_term = add(mul_by_scalar(a, domain_point.y), b);
                    qm31 value = mul_by_scalar(c, columns[column_index][row]);

                    numerator = add(numerator, sub(value, linear_term));
                }

                row_accumulator = add(
                    mul(row_accumulator, batch_coeff),
                    mul(numerator, denominator_inverses[offset]));
                line_coeffs_offset += line_coeffs_size;
            }
        }

        result_column_0[row] = row_accumulator.a.a;
        result_column_1[row] = row_accumulator.a.b;
        result_column_2[row] = row_accumulator.b.a;
        result_column_3[row] = row_accumulator.b.b;

    }
}
__global__ void dump_qm31_array(qm31 *array, int size) {
    for (int i = 0; i < size; i++) {
        printf("(%d + %di) + (%d + %di)u, ", array[i].a.a, array[i].a.b, array[i].b.a, array[i].b.b);
    }
    printf("\n");
}

__global__ void accumulate_partial_quotient_numerators_in_gpu(
        uint32_t domain_size,
        m31 **columns,
        uint32_t *sample_column_indexes,
        uint32_t sample_column_indexes_size,
        qm31 *line_coeffs_b,
        qm31 *line_coeffs_c,
        uint32_t *result_column_0,
        uint32_t *result_column_1,
        uint32_t *result_column_2,
        uint32_t *result_column_3
) {
    int row = threadIdx.x + blockDim.x * blockIdx.x;
    if (row < domain_size) {
        qm31 numerator = qm31{cm31{0, 0}, cm31{0, 0}};
        for (uint32_t j = 0; j < sample_column_indexes_size; ++j) {
            uint32_t column_index = sample_column_indexes[j];
            qm31 value = mul_by_scalar(line_coeffs_c[j], columns[column_index][row]);
            numerator = add(numerator, sub(value, line_coeffs_b[j]));
        }

        result_column_0[row] = numerator.a.a;
        result_column_1[row] = numerator.a.b;
        result_column_2[row] = numerator.b.a;
        result_column_3[row] = numerator.b.b;
    }
}

DEVICE_FORCEINLINE qm31 combine_quotient_row(
        uint32_t half_coset_initial_index,
        uint32_t half_coset_step_size,
        uint32_t domain_size,
        uint32_t domain_log_size,
        const secure_field_point *sample_points,
        uint32_t sample_size,
        const qm31 *first_linear_term_accs,
        const uint32_t *partial_numerator_log_sizes,
        const m31 *const *partial_numerators_0,
        const m31 *const *partial_numerators_1,
        const m31 *const *partial_numerators_2,
        const m31 *const *partial_numerators_3,
        uint32_t row
) {
    uint32_t domain_index = bit_reverse(row, domain_log_size);
    point domain_point = domain_at_index(
            half_coset_initial_index,
            half_coset_step_size,
            domain_index,
            domain_size
    );

    qm31 quotient = qm31{cm31{0, 0}, cm31{0, 0}};
    for (uint32_t sample_start = 0; sample_start < sample_size;
         sample_start += COMBINE_QUOTIENT_INVERSE_CHUNK) {
        const uint32_t remaining = sample_size - sample_start;
        const uint32_t sample_count = remaining < COMBINE_QUOTIENT_INVERSE_CHUNK
            ? remaining
            : COMBINE_QUOTIENT_INVERSE_CHUNK;
        cm31 denominator_inverses[COMBINE_QUOTIENT_INVERSE_CHUNK];
        quotient_inverse_chunk<COMBINE_QUOTIENT_INVERSE_CHUNK>(
                sample_points,
                sample_start,
                sample_count,
                domain_point,
                denominator_inverses);

#pragma unroll
        for (uint32_t offset = 0; offset < COMBINE_QUOTIENT_INVERSE_CHUNK;
             ++offset) {
            if (offset >= sample_count) {
                continue;
            }
            const uint32_t sample = sample_start + offset;
            uint32_t partial_log_size = partial_numerator_log_sizes[sample];
            uint32_t log_ratio = domain_log_size - partial_log_size;
            uint32_t lifted_idx = (row >> (log_ratio + 1) << 1) + (row & 1);

            qm31 partial_numerator = qm31{
                    cm31{
                            partial_numerators_0[sample][lifted_idx],
                            partial_numerators_1[sample][lifted_idx]
                    },
                    cm31{
                            partial_numerators_2[sample][lifted_idx],
                            partial_numerators_3[sample][lifted_idx]
                    }
            };
            qm31 full_numerator = sub(
                    partial_numerator,
                    mul_by_scalar(first_linear_term_accs[sample], domain_point.y)
            );
            quotient = add(
                    quotient,
                    mul(full_numerator, denominator_inverses[offset]));
        }
    }
    return quotient;
}

__global__ void __launch_bounds__(QUOTIENT_COMBINE_BLOCK_DIM, 1)
combine_quotients_from_numerators_in_gpu(
        uint32_t half_coset_initial_index,
        uint32_t half_coset_step_size,
        uint32_t domain_size,
        uint32_t domain_log_size,
        const secure_field_point *sample_points,
        uint32_t sample_size,
        const qm31 *first_linear_term_accs,
        const uint32_t *partial_numerator_log_sizes,
        const m31 *const *partial_numerators_0,
        const m31 *const *partial_numerators_1,
        const m31 *const *partial_numerators_2,
        const m31 *const *partial_numerators_3,
        uint32_t *result_column_0,
        uint32_t *result_column_1,
        uint32_t *result_column_2,
        uint32_t *result_column_3
) {
    const uint32_t row = threadIdx.x + blockDim.x * blockIdx.x;
    if (row < domain_size) {
        const qm31 quotient = combine_quotient_row(
                half_coset_initial_index,
                half_coset_step_size,
                domain_size,
                domain_log_size,
                sample_points,
                sample_size,
                first_linear_term_accs,
                partial_numerator_log_sizes,
                partial_numerators_0,
                partial_numerators_1,
                partial_numerators_2,
                partial_numerators_3,
                row);

        result_column_0[row] = quotient.a.a;
        result_column_1[row] = quotient.a.b;
        result_column_2[row] = quotient.b.a;
        result_column_3[row] = quotient.b.b;
    }
}

// Exact SN2 producer boundary. One row thread computes all four quotient
// coordinates once, then the CTA retains the 128-row tile through inverse
// stages 1..7. This retires the standalone quotient write and the first seven
// full-image B2N reads/writes without recomputing any lifted numerator.
__global__ void __launch_bounds__(QUOTIENT_PRODUCER_B2N_BLOCK_DIM, 4)
combine_quotients_b2n_init7_in_gpu(
        uint32_t half_coset_initial_index,
        uint32_t half_coset_step_size,
        uint32_t domain_size,
        uint32_t domain_log_size,
        const secure_field_point *sample_points,
        uint32_t sample_size,
        const qm31 *first_linear_term_accs,
        const uint32_t *partial_numerator_log_sizes,
        const m31 *const *partial_numerators_0,
        const m31 *const *partial_numerators_1,
        const m31 *const *partial_numerators_2,
        const m31 *const *partial_numerators_3,
        m31 *result_column_0,
        m31 *result_column_1,
        m31 *result_column_2,
        m31 *result_column_3,
        m31 *inverse_twiddles
) {
    static_assert(
            QUOTIENT_PRODUCER_B2N_BLOCK_DIM ==
                    (1 << QUOTIENT_PRODUCER_B2N_FIRST_STAGES));
    const uint32_t local_row = threadIdx.x;
    const uint32_t row = blockIdx.x * QUOTIENT_PRODUCER_B2N_BLOCK_DIM + local_row;
    const qm31 quotient = combine_quotient_row(
            half_coset_initial_index,
            half_coset_step_size,
            domain_size,
            domain_log_size,
            sample_points,
            sample_size,
            first_linear_term_accs,
            partial_numerator_log_sizes,
            partial_numerators_0,
            partial_numerators_1,
            partial_numerators_2,
            partial_numerators_3,
            row);

    __shared__ m31 tile[4][QUOTIENT_PRODUCER_B2N_BLOCK_DIM];
    tile[0][local_row] = quotient.a.a;
    tile[1][local_row] = quotient.a.b;
    tile[2][local_row] = quotient.b.a;
    tile[3][local_row] = quotient.b.b;
    __syncthreads();

    uint32_t layer_size = domain_size >> 1;
    uint32_t layer_offset = 0;
#pragma unroll
    for (uint32_t stage = 1; stage <= QUOTIENT_PRODUCER_B2N_FIRST_STAGES; ++stage) {
        if (local_row < QUOTIENT_PRODUCER_B2N_BLOCK_DIM / 2) {
            const uint32_t stride = 1u << (stage - 1);
            const uint32_t group = local_row & (stride - 1);
            const uint32_t pair_in_tile = local_row >> (stage - 1);
            const uint32_t left = group + pair_in_tile * 2 * stride;
            const uint32_t right = left + stride;
            const uint32_t global_pair =
                    (blockIdx.x * (QUOTIENT_PRODUCER_B2N_BLOCK_DIM / 2) + local_row)
                    >> (stage - 1);
            const m31 twiddle = stage == 1
                    ? get_circle_twiddle(inverse_twiddles, global_pair)
                    : inverse_twiddles[layer_offset + global_pair];
#pragma unroll
            for (uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
                const m31 left_value = tile[coordinate][left];
                const m31 right_value = tile[coordinate][right];
                tile[coordinate][left] = add(left_value, right_value);
                tile[coordinate][right] = mul(sub(left_value, right_value), twiddle);
            }
        }
        __syncthreads();
        if (stage >= 2) {
            layer_size >>= 1;
            layer_offset += layer_size;
        }
    }

    result_column_0[row] = tile[0][local_row];
    result_column_1[row] = tile[1][local_row];
    result_column_2[row] = tile[2][local_row];
    result_column_3[row] = tile[3][local_row];
}

void accumulate_quotients(
        uint32_t half_coset_initial_index,
        uint32_t half_coset_step_size,
        uint32_t domain_size,
        m31 **columns,
        uint32_t number_of_columns,
        qm31 random_coefficient,
        secure_field_point *sample_points,
        uint32_t *sample_column_indexes,
        uint32_t sample_column_indexes_size,
        qm31 *sample_column_values,
        uint32_t *sample_column_and_values_sizes,
        uint32_t sample_size,
        uint32_t *result_column_0,
        uint32_t *result_column_1,
        uint32_t *result_column_2,
        uint32_t *result_column_3,
        uint32_t flattened_line_coeffs_size
) {
    int domain_log_size = log_2((int)domain_size);

    auto sample_batches = (column_sample_batch *)malloc(sizeof(column_sample_batch) * sample_size);
    memset(sample_batches, 0, sizeof(column_sample_batch) * sample_size);

    column_sample_batch *sample_batches_device = cuda_proving_malloc<column_sample_batch>(sample_size);
    uint32_t *sample_column_indexes_device =
        cuda_proving_clone_to_device<uint32_t>(sample_column_indexes, sample_column_indexes_size);
    qm31 *sample_column_values_device =
        cuda_proving_clone_to_device<qm31>(sample_column_values, sample_column_indexes_size);

    column_sample_batches_for(
            sample_points,
            sample_column_indexes_device,
            sample_column_values_device,
            sample_column_and_values_sizes,
            sample_size,
            sample_batches
    );

    cuda_mem_copy_host_to_device(sample_batches, sample_batches_device, sample_size);
    qm31 *batch_random_coeffs_device = cuda_proving_malloc<qm31>(sample_size);
    uint32_t *line_coeffs_sizes_device = cuda_proving_malloc<uint32_t>(sample_size);
    qm31 *flattened_line_coeffs_device = cuda_proving_malloc<qm31>(flattened_line_coeffs_size);

    // Accumulate Quotient Constants
    int block_dim = sample_size < THREAD_COUNT_MAX ? sample_size : THREAD_COUNT_MAX;
    int num_blocks = block_dim < THREAD_COUNT_MAX ? 1 : (sample_size + block_dim - 1) / block_dim;
    column_line_and_batch_random_coeffs<<<num_blocks, block_dim>>>(
            sample_batches_device,
            sample_size,
            random_coefficient,
            flattened_line_coeffs_device,
            line_coeffs_sizes_device,
            batch_random_coeffs_device
    );
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    block_dim = QUOTIENT_COMBINE_BLOCK_DIM;
    num_blocks = (domain_size + block_dim - 1) / block_dim;
    accumulate_quotients_in_gpu<<<num_blocks, block_dim>>>(
            half_coset_initial_index,
            half_coset_step_size,
            domain_size,
            domain_log_size,
            columns,
            number_of_columns,
            random_coefficient,
            sample_batches_device,
            sample_size,
            result_column_0,
            result_column_1,
            result_column_2,
            result_column_3,
            flattened_line_coeffs_device,
            line_coeffs_sizes_device,
            batch_random_coeffs_device
    );
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    free(sample_batches);
    cuda_proving_free(sample_batches_device);
    cuda_proving_free(sample_column_indexes_device);
    cuda_proving_free(sample_column_values_device);
    cuda_proving_free(batch_random_coeffs_device);
    cuda_proving_free(line_coeffs_sizes_device);
    cuda_proving_free(flattened_line_coeffs_device);
}

void accumulate_partial_quotient_numerators(
        uint32_t domain_size,
        m31 **columns,
        uint32_t *sample_column_indexes,
        uint32_t sample_column_indexes_size,
        qm31 *line_coeffs_b,
        qm31 *line_coeffs_c,
        uint32_t *result_column_0,
        uint32_t *result_column_1,
        uint32_t *result_column_2,
        uint32_t *result_column_3
) {
    if (sample_column_indexes_size == 0) {
        return;
    }

    uint32_t *sample_column_indexes_device =
        cuda_proving_clone_to_device<uint32_t>(sample_column_indexes, sample_column_indexes_size);
    qm31 *line_coeffs_b_device =
        cuda_proving_clone_to_device<qm31>(line_coeffs_b, sample_column_indexes_size);
    qm31 *line_coeffs_c_device =
        cuda_proving_clone_to_device<qm31>(line_coeffs_c, sample_column_indexes_size);

    int block_dim = 512;
    int num_blocks = (domain_size + block_dim - 1) / block_dim;
    accumulate_partial_quotient_numerators_in_gpu<<<num_blocks, block_dim>>>(
            domain_size,
            columns,
            sample_column_indexes_device,
            sample_column_indexes_size,
            line_coeffs_b_device,
            line_coeffs_c_device,
            result_column_0,
            result_column_1,
            result_column_2,
            result_column_3
    );
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    cuda_proving_free(sample_column_indexes_device);
    cuda_proving_free(line_coeffs_b_device);
    cuda_proving_free(line_coeffs_c_device);
}

void combine_quotients_from_numerators(
        uint32_t half_coset_initial_index,
        uint32_t half_coset_step_size,
        uint32_t domain_size,
        uint32_t domain_log_size,
        secure_field_point *sample_points,
        uint32_t sample_size,
        qm31 *first_linear_term_accs,
        uint32_t *partial_numerator_log_sizes,
        m31 **partial_numerators_0,
        m31 **partial_numerators_1,
        m31 **partial_numerators_2,
        m31 **partial_numerators_3,
        uint32_t *result_column_0,
        uint32_t *result_column_1,
        uint32_t *result_column_2,
        uint32_t *result_column_3
) {
    if (sample_size == 0) {
        return;
    }

    secure_field_point *sample_points_device =
        cuda_proving_clone_to_device<secure_field_point>(sample_points, sample_size);
    qm31 *first_linear_term_accs_device =
        cuda_proving_clone_to_device<qm31>(first_linear_term_accs, sample_size);
    uint32_t *partial_numerator_log_sizes_device =
        cuda_proving_clone_to_device<uint32_t>(partial_numerator_log_sizes, sample_size);
    int block_dim = QUOTIENT_COMBINE_BLOCK_DIM;
    int num_blocks = (domain_size + block_dim - 1) / block_dim;
    combine_quotients_from_numerators_in_gpu<<<num_blocks, block_dim>>>(
            half_coset_initial_index,
            half_coset_step_size,
            domain_size,
            domain_log_size,
            sample_points_device,
            sample_size,
            first_linear_term_accs_device,
            partial_numerator_log_sizes_device,
            partial_numerators_0,
            partial_numerators_1,
            partial_numerators_2,
            partial_numerators_3,
            result_column_0,
            result_column_1,
            result_column_2,
            result_column_3
    );
    stwo_maybe_debug_sync();
    ASSERT_CUDA_SUCCESS(cudaGetLastError());

    cuda_proving_free(sample_points_device);
    cuda_proving_free(first_linear_term_accs_device);
    cuda_proving_free(partial_numerator_log_sizes_device);
}

extern "C" int stwo_combine_quotients_from_numerators_on(
        uint32_t half_coset_initial_index,
        uint32_t half_coset_step_size,
        uint32_t domain_size,
        uint32_t domain_log_size,
        const secure_field_point *sample_points,
        uint32_t sample_size,
        const qm31 *first_linear_term_accs,
        const uint32_t *partial_numerator_log_sizes,
        const m31 *const *partial_numerators_0,
        const m31 *const *partial_numerators_1,
        const m31 *const *partial_numerators_2,
        const m31 *const *partial_numerators_3,
        uint32_t *result_column_0,
        uint32_t *result_column_1,
        uint32_t *result_column_2,
        uint32_t *result_column_3,
        void *stream
) {
    if (half_coset_step_size == 0 || domain_size == 0 || sample_size == 0 ||
        domain_log_size == 0 || domain_log_size > 30 ||
        domain_size != (1u << domain_log_size) || sample_points == nullptr ||
        first_linear_term_accs == nullptr || partial_numerator_log_sizes == nullptr ||
        partial_numerators_0 == nullptr || partial_numerators_1 == nullptr ||
        partial_numerators_2 == nullptr || partial_numerators_3 == nullptr ||
        result_column_0 == nullptr || result_column_1 == nullptr ||
        result_column_2 == nullptr || result_column_3 == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }

    constexpr int block_dim = QUOTIENT_COMBINE_BLOCK_DIM;
    const int num_blocks = (domain_size + block_dim - 1) / block_dim;
    combine_quotients_from_numerators_in_gpu<<<
        num_blocks, block_dim, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
            half_coset_initial_index,
            half_coset_step_size,
            domain_size,
            domain_log_size,
            sample_points,
            sample_size,
            first_linear_term_accs,
            partial_numerator_log_sizes,
            partial_numerators_0,
            partial_numerators_1,
            partial_numerators_2,
            partial_numerators_3,
            result_column_0,
            result_column_1,
            result_column_2,
            result_column_3);
    return cudaGetLastError();
}

extern "C" int stwo_combine_quotients_b2n_init7_on(
        uint32_t half_coset_initial_index,
        uint32_t half_coset_step_size,
        uint32_t domain_size,
        uint32_t domain_log_size,
        const secure_field_point *sample_points,
        uint32_t sample_size,
        const qm31 *first_linear_term_accs,
        const uint32_t *partial_numerator_log_sizes,
        const m31 *const *partial_numerators_0,
        const m31 *const *partial_numerators_1,
        const m31 *const *partial_numerators_2,
        const m31 *const *partial_numerators_3,
        uint32_t *result_column_0,
        uint32_t *result_column_1,
        uint32_t *result_column_2,
        uint32_t *result_column_3,
        const uint32_t *inverse_twiddles,
        uint32_t inverse_twiddle_words,
        uint32_t eval_domain_size,
        void *stream
) {
    constexpr uint32_t production_log = 23;
    constexpr uint32_t production_size = 1u << production_log;
    if (half_coset_step_size == 0 || domain_size != production_size ||
        domain_log_size != production_log || sample_size == 0 ||
        sample_points == nullptr || first_linear_term_accs == nullptr ||
        partial_numerator_log_sizes == nullptr || partial_numerators_0 == nullptr ||
        partial_numerators_1 == nullptr || partial_numerators_2 == nullptr ||
        partial_numerators_3 == nullptr || result_column_0 == nullptr ||
        result_column_1 == nullptr || result_column_2 == nullptr ||
        result_column_3 == nullptr || inverse_twiddles == nullptr || stream == nullptr ||
        eval_domain_size != (production_size >> 1) ||
        eval_domain_size > inverse_twiddle_words) {
        return cudaErrorInvalidValue;
    }

    const auto twiddles = reinterpret_cast<m31 *>(const_cast<uint32_t *>(
            inverse_twiddles + inverse_twiddle_words - eval_domain_size));
    combine_quotients_b2n_init7_in_gpu<<<
        production_size / QUOTIENT_PRODUCER_B2N_BLOCK_DIM,
        QUOTIENT_PRODUCER_B2N_BLOCK_DIM,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            half_coset_initial_index,
            half_coset_step_size,
            domain_size,
            domain_log_size,
            sample_points,
            sample_size,
            first_linear_term_accs,
            partial_numerator_log_sizes,
            partial_numerators_0,
            partial_numerators_1,
            partial_numerators_2,
            partial_numerators_3,
            reinterpret_cast<m31 *>(result_column_0),
            reinterpret_cast<m31 *>(result_column_1),
            reinterpret_cast<m31 *>(result_column_2),
            reinterpret_cast<m31 *>(result_column_3),
            twiddles);
    return cudaGetLastError();
}

extern "C" int stwo_combine_quotients_b2n_init7_function_attributes(
        StwoCudaFunctionAttributes *out
) {
    return stwo_cuda_function_attributes(
            combine_quotients_b2n_init7_in_gpu, out);
}

namespace {

constexpr uint32_t PREPARED_TERM_WORDS = 5;
constexpr uint32_t PREPARED_BATCH_TERM_WORDS = 3;

__device__ secure_field_point add_secure_point_offset(
        secure_field_point value,
        point offset
) {
    return secure_field_point{
        sub(mul_by_scalar(value.x, offset.x), mul_by_scalar(value.y, offset.y)),
        add(mul_by_scalar(value.x, offset.y), mul_by_scalar(value.y, offset.x)),
    };
}

__global__ void prepare_quotient_numerator_terms(
        const uint32_t *term_descriptors,
        uint32_t term_count,
        const secure_field_point *sample_points,
        const qm31 *sample_values,
        const qm31 *random_coefficient,
        secure_field_point *term_points,
        qm31 *line_coefficients
) {
    const uint32_t term = blockIdx.x * blockDim.x + threadIdx.x;
    if (term >= term_count) {
        return;
    }
    const uint32_t *descriptor =
        term_descriptors + static_cast<size_t>(term) * PREPARED_TERM_WORDS;
    const uint32_t sample_index = descriptor[0];
    const uint32_t exponent = descriptor[1];
    const bool periodic = descriptor[2] != 0;
    const point period = point{descriptor[3], descriptor[4]};

    secure_field_point sample_point = sample_points[sample_index];
    if (periodic) {
        sample_point = add_secure_point_offset(sample_point, period);
    }
    term_points[term] = sample_point;

    qm31 a;
    qm31 b;
    qm31 c;
    const qm31 alpha = pow(*random_coefficient, exponent);
    complex_conjugate_line_coeffs(
        sample_point, sample_values[sample_index], alpha, &a, &b, &c);
    line_coefficients[static_cast<size_t>(term) * 3] = a;
    line_coefficients[static_cast<size_t>(term) * 3 + 1] = b;
    line_coefficients[static_cast<size_t>(term) * 3 + 2] = c;
}

__global__ void finalize_quotient_numerator_groups(
        const uint32_t *group_offsets,
        const uint32_t *group_term_indices,
        uint32_t group_count,
        const secure_field_point *term_points,
        qm31 *line_coefficients,
        secure_field_point *sample_points,
        qm31 *first_linear_terms
) {
    const uint32_t group = blockIdx.x * blockDim.x + threadIdx.x;
    if (group >= group_count) {
        return;
    }
    const uint32_t begin = group_offsets[group];
    const uint32_t end = group_offsets[group + 1];
    const uint32_t representative = group_term_indices[begin];
    sample_points[group] = term_points[representative];

    qm31 first = qm31{cm31{0, 0}, cm31{0, 0}};
    qm31 group_b = qm31{cm31{0, 0}, cm31{0, 0}};
    for (uint32_t index = begin; index < end; ++index) {
        const uint32_t term = group_term_indices[index];
        first = add(first, line_coefficients[static_cast<size_t>(term) * 3]);
        group_b = add(
            group_b,
            line_coefficients[static_cast<size_t>(term) * 3 + 1]);
    }
    first_linear_terms[group] = first;
    // Per-term a coefficients are dead after this finalizer. Reuse the
    // representative term's a slot for the exact group-wide B constant, so the
    // direct numerator path adds no allocation, descriptor pass, or launch.
    line_coefficients[static_cast<size_t>(representative) * 3] = group_b;
}

__global__ void zero_quotient_numerator_outputs(
        const uint32_t *group_log_sizes,
        uint32_t group_count,
        uint32_t max_output_size,
        uint32_t *const *outputs_0,
        uint32_t *const *outputs_1,
        uint32_t *const *outputs_2,
        uint32_t *const *outputs_3
) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t group = blockIdx.y;
    if (group >= group_count || row >= max_output_size ||
        row >= (1u << group_log_sizes[group])) {
        return;
    }
    outputs_0[group][row] = 0;
    outputs_1[group][row] = 0;
    outputs_2[group][row] = 0;
    outputs_3[group][row] = 0;
}

__global__ void accumulate_quotient_numerator_batch(
        const uint32_t *group_offsets,
        const uint32_t *term_descriptors,
        uint32_t group_count,
        uint32_t max_output_size,
        const uint32_t *const *source_evaluations,
        const qm31 *line_coefficients,
        const uint32_t *group_log_sizes,
        uint32_t *const *outputs_0,
        uint32_t *const *outputs_1,
        uint32_t *const *outputs_2,
        uint32_t *const *outputs_3
) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t group = blockIdx.y;
    if (group >= group_count || row >= max_output_size) {
        return;
    }
    const uint32_t group_log_size = group_log_sizes[group];
    if (row >= (1u << group_log_size)) {
        return;
    }

    qm31 numerator = qm31{cm31{0, 0}, cm31{0, 0}};
    for (uint32_t index = group_offsets[group];
         index < group_offsets[group + 1]; ++index) {
        const uint32_t *descriptor =
            term_descriptors + static_cast<size_t>(index) * PREPARED_BATCH_TERM_WORDS;
        const uint32_t source = descriptor[0];
        const uint32_t term = descriptor[1];
        const uint32_t source_log_size = descriptor[2];
        const uint32_t log_ratio = group_log_size - source_log_size;
        const uint32_t source_row =
            (row >> (log_ratio + 1) << 1) + (row & 1);
        const qm31 b = line_coefficients[static_cast<size_t>(term) * 3 + 1];
        const qm31 c = line_coefficients[static_cast<size_t>(term) * 3 + 2];
        numerator = add(
            numerator,
            sub(mul_by_scalar(c, source_evaluations[source][source_row]), b));
    }

    qm31 current = qm31{
        cm31{outputs_0[group][row], outputs_1[group][row]},
        cm31{outputs_2[group][row], outputs_3[group][row]},
    };
    current = add(current, numerator);
    outputs_0[group][row] = current.a.a;
    outputs_1[group][row] = current.a.b;
    outputs_2[group][row] = current.b.a;
    outputs_3[group][row] = current.b.b;
}

} // namespace

extern "C" int stwo_prepare_quotient_numerator_terms_on(
        const uint32_t *term_descriptors,
        uint32_t term_count,
        const secure_field_point *sample_points,
        const qm31 *sample_values,
        const qm31 *random_coefficient,
        secure_field_point *term_points,
        qm31 *line_coefficients,
        void *stream
) {
    if (term_descriptors == nullptr || term_count == 0 ||
        sample_points == nullptr || sample_values == nullptr ||
        random_coefficient == nullptr || term_points == nullptr ||
        line_coefficients == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    constexpr uint32_t block_size = 256;
    const uint32_t blocks = (term_count + block_size - 1) / block_size;
    prepare_quotient_numerator_terms<<<
        blocks, block_size, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
            term_descriptors, term_count, sample_points, sample_values,
            random_coefficient, term_points, line_coefficients);
    return cudaGetLastError();
}

extern "C" int stwo_finalize_quotient_numerator_groups_on(
        const uint32_t *group_offsets,
        const uint32_t *group_term_indices,
        uint32_t group_count,
        const secure_field_point *term_points,
        qm31 *line_coefficients,
        secure_field_point *sample_points,
        qm31 *first_linear_terms,
        void *stream
) {
    if (group_offsets == nullptr || group_term_indices == nullptr ||
        group_count == 0 || term_points == nullptr ||
        line_coefficients == nullptr || sample_points == nullptr ||
        first_linear_terms == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    constexpr uint32_t block_size = 256;
    const uint32_t blocks = (group_count + block_size - 1) / block_size;
    finalize_quotient_numerator_groups<<<
        blocks, block_size, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
            group_offsets, group_term_indices, group_count, term_points,
            line_coefficients, sample_points, first_linear_terms);
    return cudaGetLastError();
}

extern "C" int stwo_zero_quotient_numerator_outputs_on(
        const uint32_t *group_log_sizes,
        uint32_t group_count,
        uint32_t max_output_size,
        uint32_t *const *outputs_0,
        uint32_t *const *outputs_1,
        uint32_t *const *outputs_2,
        uint32_t *const *outputs_3,
        void *stream
) {
    if (group_log_sizes == nullptr || group_count == 0 ||
        group_count > 65535 || max_output_size == 0 ||
        outputs_0 == nullptr || outputs_1 == nullptr ||
        outputs_2 == nullptr || outputs_3 == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    constexpr uint32_t block_size = 256;
    const uint32_t blocks = (max_output_size + block_size - 1) / block_size;
    zero_quotient_numerator_outputs<<<
        dim3(blocks, group_count), block_size, 0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            group_log_sizes, group_count, max_output_size, outputs_0,
            outputs_1, outputs_2, outputs_3);
    return cudaGetLastError();
}

extern "C" int stwo_accumulate_quotient_numerator_batch_on(
        const uint32_t *group_offsets,
        const uint32_t *term_descriptors,
        uint32_t group_count,
        uint32_t max_output_size,
        const uint32_t *const *source_evaluations,
        const qm31 *line_coefficients,
        const uint32_t *group_log_sizes,
        uint32_t *const *outputs_0,
        uint32_t *const *outputs_1,
        uint32_t *const *outputs_2,
        uint32_t *const *outputs_3,
        void *stream
) {
    if (group_offsets == nullptr || term_descriptors == nullptr ||
        group_count == 0 || group_count > 65535 || max_output_size == 0 ||
        source_evaluations == nullptr || line_coefficients == nullptr ||
        group_log_sizes == nullptr || outputs_0 == nullptr ||
        outputs_1 == nullptr || outputs_2 == nullptr ||
        outputs_3 == nullptr || stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    constexpr uint32_t block_size = 256;
    const uint32_t blocks = (max_output_size + block_size - 1) / block_size;
    accumulate_quotient_numerator_batch<<<
        dim3(blocks, group_count), block_size, 0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            group_offsets, term_descriptors, group_count, max_output_size,
            source_evaluations, line_coefficients, group_log_sizes, outputs_0,
            outputs_1, outputs_2, outputs_3);
    return cudaGetLastError();
}
