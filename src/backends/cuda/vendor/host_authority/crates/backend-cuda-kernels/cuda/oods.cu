#include "oods.cuh"
#include "batch_inverse.cuh"

#include <cuda_runtime.h>

namespace {

constexpr uint32_t OODS_BLOCK_DIM = 256;
constexpr uint32_t OODS_COEFFICIENTS_PER_BLOCK = 2 * OODS_BLOCK_DIM;

DEVICE_FORCEINLINE qm31 qm31_zero() {
    return qm31{cm31{0, 0}, cm31{0, 0}};
}

DEVICE_FORCEINLINE qm31 qm31_one() {
    return qm31{cm31{1, 0}, cm31{0, 0}};
}

DEVICE_FORCEINLINE secure_field_point secure_point_add_base(
    secure_field_point lhs,
    point rhs
) {
    return secure_field_point{
        sub(mul(rhs.x, lhs.x), mul(rhs.y, lhs.y)),
        add(mul(rhs.y, lhs.x), mul(rhs.x, lhs.y)),
    };
}

DEVICE_FORCEINLINE secure_field_point secure_point_double(secure_field_point value) {
    qm31 x = value.x;
    qm31 y = value.y;
    return secure_field_point{
        sub(square(x), square(y)),
        add(mul(x, y), mul(x, y)),
    };
}

__global__ void derive_points_kernel(
    const qm31 *oods_parameter,
    const point *offset_points,
    const uint32_t *fold_counts,
    const uint32_t *output_indices,
    uint32_t sample_count,
    uint32_t coefficient_log_size,
    secure_field_point *sample_points,
    secure_field_point *evaluation_points,
    qm31 *folding_factors
) {
    uint32_t sample = blockIdx.x * blockDim.x + threadIdx.x;
    if (sample >= sample_count) {
        return;
    }

    // CirclePoint::get_random_point: t -> ((1-t^2)/(1+t^2), 2t/(1+t^2)).
    qm31 t = oods_parameter[0];
    qm31 t_squared = square(t);
    qm31 denominator_inverse = inv(add(qm31_one(), t_squared));
    secure_field_point point_at_mask = {
        mul(sub(qm31_one(), t_squared), denominator_inverse),
        mul(add(t, t), denominator_inverse),
    };
    point_at_mask = secure_point_add_base(point_at_mask, offset_points[sample]);
    sample_points[output_indices[sample]] = point_at_mask;

    // proof_driver evaluates a log-size column at
    // mask_point.repeated_double(lifting_log_size - column_log_size).
    secure_field_point evaluation_point = point_at_mask;
    for (uint32_t i = 0; i < fold_counts[sample]; ++i) {
        evaluation_point = secure_point_double(evaluation_point);
    }
    evaluation_points[sample] = evaluation_point;

    qm31 *factors = folding_factors + (size_t)sample * coefficient_log_size;
    factors[coefficient_log_size - 1] = evaluation_point.y;
    if (coefficient_log_size > 1) {
        qm31 x = evaluation_point.x;
        for (int i = (int)coefficient_log_size - 2; i >= 0; --i) {
            factors[i] = x;
            x = sub(add(square(x), square(x)), qm31_one());
        }
    }
}

__global__ void eval_first_kernel(
    const m31 *const *coefficients,
    uint32_t coefficient_size,
    uint32_t sample_count,
    const qm31 *folding_factors,
    uint32_t coefficient_log_size,
    uint32_t blocks_per_sample,
    qm31 *scratch
) {
    uint32_t sample = blockIdx.y;
    if (sample >= sample_count || blockIdx.x >= blocks_per_sample) {
        return;
    }

    extern __shared__ unsigned char shared_bytes[];
    m31 *shared_coefficients = reinterpret_cast<m31 *>(shared_bytes);
    qm31 *shared_level = reinterpret_cast<qm31 *>(
        shared_bytes + OODS_COEFFICIENTS_PER_BLOCK * sizeof(m31));

    uint32_t lane = threadIdx.x;
    uint32_t base = blockIdx.x * OODS_COEFFICIENTS_PER_BLOCK;
    uint32_t left = base + lane;
    uint32_t right = left + OODS_BLOCK_DIM;
    const m31 *column = coefficients[sample];
    shared_coefficients[lane] = left < coefficient_size ? column[left] : 0;
    shared_coefficients[lane + OODS_BLOCK_DIM] =
        right < coefficient_size ? column[right] : 0;
    __syncthreads();

    uint32_t local_size = coefficient_size < OODS_COEFFICIENTS_PER_BLOCK
                              ? coefficient_size
                              : OODS_COEFFICIENTS_PER_BLOCK;
    uint32_t level_size = local_size >> 1;
    int factor_index = (int)coefficient_log_size - 1;
    const qm31 *factors = folding_factors + (size_t)sample * coefficient_log_size;

    if (lane < level_size) {
        shared_level[lane] = add(
            shared_coefficients[2 * lane],
            mul(shared_coefficients[2 * lane + 1], factors[factor_index]));
    }
    --factor_index;
    level_size >>= 1;

    while (level_size > 0) {
        __syncthreads();
        qm31 left_value = qm31_zero();
        qm31 right_value = qm31_zero();
        if (lane < level_size) {
            left_value = shared_level[2 * lane];
            right_value = shared_level[2 * lane + 1];
        }
        __syncthreads();
        if (lane < level_size) {
            shared_level[lane] = add(left_value, mul(right_value, factors[factor_index]));
        }
        --factor_index;
        level_size >>= 1;
    }

    if (lane == 0) {
        scratch[(size_t)sample * blocks_per_sample + blockIdx.x] = shared_level[0];
    }
}

__global__ void eval_reduce_kernel(
    const qm31 *input,
    uint32_t input_size,
    uint32_t input_stride,
    uint32_t factor_index,
    uint32_t coefficient_log_size,
    uint32_t sample_count,
    const qm31 *folding_factors,
    qm31 *output,
    uint32_t output_stride
) {
    uint32_t sample = blockIdx.y;
    if (sample >= sample_count || blockIdx.x >= output_stride) {
        return;
    }

    extern __shared__ qm31 shared[];
    uint32_t lane = threadIdx.x;
    uint32_t base = blockIdx.x * OODS_COEFFICIENTS_PER_BLOCK;
    uint32_t left = base + lane;
    uint32_t right = left + OODS_BLOCK_DIM;
    const qm31 *row = input + (size_t)sample * input_stride;
    shared[lane] = left < input_size ? row[left] : qm31_zero();
    shared[lane + OODS_BLOCK_DIM] = right < input_size ? row[right] : qm31_zero();
    __syncthreads();

    uint32_t local_size = input_size < OODS_COEFFICIENTS_PER_BLOCK
                              ? input_size
                              : OODS_COEFFICIENTS_PER_BLOCK;
    uint32_t level_size = local_size >> 1;
    int current_factor = (int)factor_index;
    const qm31 *factors = folding_factors + (size_t)sample * coefficient_log_size;
    while (level_size > 0) {
        qm31 left_value = qm31_zero();
        qm31 right_value = qm31_zero();
        if (lane < level_size) {
            left_value = shared[2 * lane];
            right_value = shared[2 * lane + 1];
        }
        __syncthreads();
        if (lane < level_size) {
            shared[lane] = add(left_value, mul(right_value, factors[current_factor]));
        }
        --current_factor;
        level_size >>= 1;
        __syncthreads();
    }

    if (lane == 0) {
        output[(size_t)sample * output_stride + blockIdx.x] = shared[0];
    }
}

__global__ void store_results_kernel(
    const qm31 *reduced,
    uint32_t reduced_stride,
    const uint32_t *output_indices,
    uint32_t sample_count,
    qm31 *sampled_values
) {
    uint32_t sample = blockIdx.x * blockDim.x + threadIdx.x;
    if (sample < sample_count) {
        sampled_values[output_indices[sample]] = reduced[(size_t)sample * reduced_stride];
    }
}

DEVICE_FORCEINLINE point domain_at_index(
    uint32_t half_coset_initial_index,
    uint32_t half_coset_step_size,
    uint32_t index,
    uint32_t domain_size
) {
    uint32_t half_coset_size = domain_size >> 1;
    constexpr uint64_t CIRCLE_ORDER = 2147483648ULL;
    constexpr uint64_t CIRCLE_MASK = CIRCLE_ORDER - 1;
    uint64_t global_index;
    if (index < half_coset_size) {
        global_index = (uint64_t)half_coset_initial_index +
                       (uint64_t)half_coset_step_size * index;
    } else {
        global_index = CIRCLE_ORDER -
                       ((uint64_t)half_coset_initial_index +
                        (uint64_t)half_coset_step_size * (index - half_coset_size));
    }
    return point_pow(m31_circle_gen, (int)(global_index & CIRCLE_MASK));
}

__global__ void barycentric_scales_kernel(
    const secure_field_point *evaluation_point,
    qm31 si0,
    point vanishing_rotation,
    uint32_t log_size,
    qm31 *scales
) {
    if (blockIdx.x != 0 || threadIdx.x != 0) {
        return;
    }
    secure_field_point rotated =
        secure_point_add_base(evaluation_point[0], vanishing_rotation);
    qm31 vanishing = rotated.x;
    for (uint32_t i = 1; i < log_size; ++i) {
        vanishing = sub(add(square(vanishing), square(vanishing)), qm31_one());
    }
    scales[0] = mul(si0, vanishing);
    scales[1] = sub(qm31_zero(), scales[0]);
}

__global__ void barycentric_parts_kernel(
    uint32_t half_coset_initial_index,
    uint32_t half_coset_step_size,
    uint32_t size,
    uint32_t log_size,
    const secure_field_point *evaluation_point,
    qm31 *numerators,
    qm31 *denominators
) {
    uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= size) {
        return;
    }
    point domain_point = domain_at_index(
        half_coset_initial_index,
        half_coset_step_size,
        bit_reverse(index, (int)log_size),
        size);
    secure_field_point p = evaluation_point[0];
    qm31 hx = add(mul(domain_point.x, p.x), mul(domain_point.y, p.y));
    qm31 hy = sub(mul(domain_point.x, p.y), mul(domain_point.y, p.x));
    numerators[index] = hy;
    denominators[index] = add(qm31_one(), hx);
}

__global__ void barycentric_finish_weights_kernel(
    const qm31 *numerator_inverses,
    qm31 *weights,
    const qm31 *scales,
    uint32_t size
) {
    uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index < size) {
        weights[index] = mul(mul(weights[index], numerator_inverses[index]), scales[index & 1U]);
    }
}

__global__ void barycentric_eval_many_kernel(
    const m31 *const *columns,
    const qm31 *weights,
    uint32_t size,
    qm31 *partial_sums
) {
    extern __shared__ qm31 shared[];
    const m31 *column = columns[blockIdx.y];
    qm31 sum = qm31_zero();
    uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t stride = blockDim.x * gridDim.x;
    while (index < size) {
        sum = add(sum, mul(column[index], weights[index]));
        index += stride;
    }
    shared[threadIdx.x] = sum;
    __syncthreads();
    for (uint32_t offset = blockDim.x >> 1; offset > 0; offset >>= 1) {
        if (threadIdx.x < offset) {
            shared[threadIdx.x] = add(shared[threadIdx.x], shared[threadIdx.x + offset]);
        }
        __syncthreads();
    }
    if (threadIdx.x == 0) {
        partial_sums[(size_t)blockIdx.y * gridDim.x + blockIdx.x] = shared[0];
    }
}

__global__ void barycentric_reduce_rows_kernel(
    const qm31 *partial_sums,
    uint32_t row_width,
    const uint32_t *output_indices,
    qm31 *sampled_values
) {
    extern __shared__ qm31 shared[];
    const qm31 *row = partial_sums + (size_t)blockIdx.x * row_width;
    qm31 sum = qm31_zero();
    for (uint32_t i = threadIdx.x; i < row_width; i += blockDim.x) {
        sum = add(sum, row[i]);
    }
    shared[threadIdx.x] = sum;
    __syncthreads();
    for (uint32_t offset = blockDim.x >> 1; offset > 0; offset >>= 1) {
        if (threadIdx.x < offset) {
            shared[threadIdx.x] = add(shared[threadIdx.x], shared[threadIdx.x + offset]);
        }
        __syncthreads();
    }
    if (threadIdx.x == 0) {
        sampled_values[output_indices[blockIdx.x]] = shared[0];
    }
}

} // namespace

extern "C" int stwo_oods_derive_points_on(
    const qm31 *oods_parameter,
    const point *offset_points,
    const uint32_t *fold_counts,
    const uint32_t *output_indices,
    uint32_t sample_count,
    uint32_t coefficient_log_size,
    secure_field_point *sample_points,
    secure_field_point *evaluation_points,
    qm31 *folding_factors,
    void *stream
) {
    if (sample_count == 0 || coefficient_log_size == 0) {
        return cudaErrorInvalidValue;
    }
    cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    uint32_t blocks = (sample_count + OODS_BLOCK_DIM - 1) / OODS_BLOCK_DIM;
    derive_points_kernel<<<blocks, OODS_BLOCK_DIM, 0, cuda_stream>>>(
        oods_parameter,
        offset_points,
        fold_counts,
        output_indices,
        sample_count,
        coefficient_log_size,
        sample_points,
        evaluation_points,
        folding_factors);
    return cudaPeekAtLastError();
}

extern "C" int stwo_oods_eval_first_on(
    const m31 *const *coefficients,
    uint32_t coefficient_size,
    uint32_t sample_count,
    const qm31 *folding_factors,
    qm31 *scratch,
    void *stream
) {
    if (sample_count == 0 || coefficient_size < 2 ||
        (coefficient_size & (coefficient_size - 1)) != 0) {
        return cudaErrorInvalidValue;
    }
    uint32_t coefficient_log_size = 31U - __builtin_clz(coefficient_size);
    uint32_t blocks_per_sample =
        (coefficient_size + OODS_COEFFICIENTS_PER_BLOCK - 1) /
        OODS_COEFFICIENTS_PER_BLOCK;
    dim3 grid(blocks_per_sample, sample_count);
    size_t shared_bytes = OODS_COEFFICIENTS_PER_BLOCK * sizeof(m31) +
                          OODS_BLOCK_DIM * sizeof(qm31);
    eval_first_kernel<<<grid, OODS_BLOCK_DIM, shared_bytes,
                        reinterpret_cast<cudaStream_t>(stream)>>>(
        coefficients,
        coefficient_size,
        sample_count,
        folding_factors,
        coefficient_log_size,
        blocks_per_sample,
        scratch);
    return cudaPeekAtLastError();
}

extern "C" int stwo_oods_eval_reduce_on(
    const qm31 *input,
    uint32_t input_size,
    uint32_t input_stride,
    uint32_t factor_index,
    uint32_t coefficient_log_size,
    uint32_t sample_count,
    const qm31 *folding_factors,
    qm31 *output,
    uint32_t output_stride,
    void *stream
) {
    if (sample_count == 0 || input_size < 2 || output_stride == 0) {
        return cudaErrorInvalidValue;
    }
    dim3 grid(output_stride, sample_count);
    eval_reduce_kernel<<<grid, OODS_BLOCK_DIM,
                         OODS_COEFFICIENTS_PER_BLOCK * sizeof(qm31),
                         reinterpret_cast<cudaStream_t>(stream)>>>(
        input,
        input_size,
        input_stride,
        factor_index,
        coefficient_log_size,
        sample_count,
        folding_factors,
        output,
        output_stride);
    return cudaPeekAtLastError();
}

extern "C" int stwo_oods_store_results_on(
    const qm31 *reduced,
    uint32_t reduced_stride,
    const uint32_t *output_indices,
    uint32_t sample_count,
    qm31 *sampled_values,
    void *stream
) {
    if (sample_count == 0 || reduced_stride == 0) {
        return cudaErrorInvalidValue;
    }
    uint32_t blocks = (sample_count + OODS_BLOCK_DIM - 1) / OODS_BLOCK_DIM;
    store_results_kernel<<<blocks, OODS_BLOCK_DIM, 0,
                           reinterpret_cast<cudaStream_t>(stream)>>>(
        reduced, reduced_stride, output_indices, sample_count, sampled_values);
    return cudaPeekAtLastError();
}

extern "C" int stwo_oods_barycentric_weights_on(
    uint32_t half_coset_initial_index,
    uint32_t half_coset_step_size,
    uint32_t size,
    uint32_t log_size,
    const secure_field_point *evaluation_point,
    qm31 si0,
    point vanishing_rotation,
    qm31 *numerator_inverses,
    qm31 *weights,
    qm31 *scales,
    void *stream
) {
    if (size < 2 || (size & (size - 1)) != 0 || log_size == 0) {
        return cudaErrorInvalidValue;
    }
    cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    barycentric_scales_kernel<<<1, 1, 0, cuda_stream>>>(
        evaluation_point, si0, vanishing_rotation, log_size, scales);
    cudaError_t error = cudaPeekAtLastError();
    if (error != cudaSuccess) {
        return error;
    }
    uint32_t blocks = (size + OODS_BLOCK_DIM - 1) / OODS_BLOCK_DIM;
    barycentric_parts_kernel<<<blocks, OODS_BLOCK_DIM, 0, cuda_stream>>>(
        half_coset_initial_index,
        half_coset_step_size,
        size,
        log_size,
        evaluation_point,
        numerator_inverses,
        weights);
    error = cudaPeekAtLastError();
    if (error != cudaSuccess) {
        return error;
    }
    error = batch_inverse_secure_field_on(
        cuda_stream, numerator_inverses, numerator_inverses, (int)size);
    if (error != cudaSuccess) {
        return error;
    }
    barycentric_finish_weights_kernel<<<blocks, OODS_BLOCK_DIM, 0, cuda_stream>>>(
        numerator_inverses, weights, scales, size);
    return cudaPeekAtLastError();
}

extern "C" int stwo_oods_barycentric_eval_many_on(
    const m31 *const *columns,
    uint32_t column_count,
    const qm31 *weights,
    uint32_t size,
    qm31 *partial_sums,
    uint32_t reduction_blocks,
    const uint32_t *output_indices,
    qm31 *sampled_values,
    void *stream
) {
    if (column_count == 0 || size == 0 || reduction_blocks == 0) {
        return cudaErrorInvalidValue;
    }
    cudaStream_t cuda_stream = reinterpret_cast<cudaStream_t>(stream);
    dim3 grid(reduction_blocks, column_count);
    barycentric_eval_many_kernel<<<grid, OODS_BLOCK_DIM,
                                   OODS_BLOCK_DIM * sizeof(qm31), cuda_stream>>>(
        columns, weights, size, partial_sums);
    cudaError_t error = cudaPeekAtLastError();
    if (error != cudaSuccess) {
        return error;
    }
    barycentric_reduce_rows_kernel<<<column_count, OODS_BLOCK_DIM,
                                     OODS_BLOCK_DIM * sizeof(qm31), cuda_stream>>>(
        partial_sums, reduction_blocks, output_indices, sampled_values);
    return cudaPeekAtLastError();
}
