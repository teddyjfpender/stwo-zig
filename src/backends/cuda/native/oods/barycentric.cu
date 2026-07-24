// Resident barycentric OODS weights and multi-column evaluation.

#include "batch_inverse.cuh"
#include "field.cuh"
#include "safety.cuh"

#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>

namespace stwo::cuda::oods {

constexpr std::uint32_t kBarycentricBlockSize = 256;

__device__ __forceinline__ CirclePoint domain_at_index(
    std::uint32_t half_coset_initial_index,
    std::uint32_t half_coset_step_size,
    std::uint32_t index,
    std::uint32_t domain_size) {
    const std::uint32_t half_coset_size = domain_size >> 1;
    constexpr std::uint64_t circle_order = 1ull << 31;
    constexpr std::uint64_t circle_mask = circle_order - 1;
    std::uint64_t global_index;
    if (index < half_coset_size) {
        global_index =
            static_cast<std::uint64_t>(half_coset_initial_index) +
            static_cast<std::uint64_t>(half_coset_step_size) * index;
    } else {
        global_index =
            circle_order -
            (static_cast<std::uint64_t>(half_coset_initial_index) +
             static_cast<std::uint64_t>(half_coset_step_size) *
                 (index - half_coset_size));
    }
    return point_pow(
        kCircleGenerator,
        static_cast<std::uint32_t>(global_index & circle_mask));
}

__global__ void scales_kernel(
    const SecureCirclePoint *evaluation_point,
    QM31 si0,
    CirclePoint vanishing_rotation,
    std::uint32_t log_size,
    QM31 *scales) {
    if (blockIdx.x != 0 || threadIdx.x != 0) return;
    const SecureCirclePoint rotated =
        add_base(evaluation_point[0], vanishing_rotation);
    QM31 vanishing = rotated.x;
    for (std::uint32_t index = 1; index < log_size; ++index) {
        vanishing = sub(add(square(vanishing), square(vanishing)), one());
    }
    scales[0] = mul(si0, vanishing);
    scales[1] = sub(zero(), scales[0]);
}

__global__ void parts_kernel(
    std::uint32_t half_coset_initial_index,
    std::uint32_t half_coset_step_size,
    std::uint32_t size,
    std::uint32_t log_size,
    const SecureCirclePoint *evaluation_point,
    QM31 *numerators,
    QM31 *denominators) {
    const std::uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index >= size) return;
    const std::uint32_t reversed = __brev(index) >> (32u - log_size);
    const CirclePoint domain_point = domain_at_index(
        half_coset_initial_index,
        half_coset_step_size,
        reversed,
        size);
    const SecureCirclePoint point = evaluation_point[0];
    const QM31 hx = add(
        mul(domain_point.x, point.x),
        mul(domain_point.y, point.y));
    const QM31 hy = sub(
        mul(domain_point.x, point.y),
        mul(domain_point.y, point.x));
    numerators[index] = hy;
    denominators[index] = add(one(), hx);
}

__global__ void finish_weights_kernel(
    const QM31 *numerator_inverses,
    QM31 *weights,
    const QM31 *scales,
    std::uint32_t size) {
    const std::uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index < size) {
        weights[index] = mul(
            mul(weights[index], numerator_inverses[index]),
            scales[index & 1u]);
    }
}

__global__ void evaluate_many_kernel(
    const M31 *columns,
    std::size_t column_stride_words,
    const QM31 *weights,
    std::uint32_t size,
    QM31 *partial_sums) {
    extern __shared__ QM31 shared[];
    const M31 *column =
        columns + static_cast<std::size_t>(blockIdx.y) * column_stride_words;
    QM31 sum = zero();
    std::size_t index =
        static_cast<std::size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    const std::size_t stride =
        static_cast<std::size_t>(blockDim.x) * gridDim.x;
    while (index < static_cast<std::size_t>(size)) {
        sum = add(sum, mul(column[index], weights[index]));
        index += stride;
    }
    shared[threadIdx.x] = sum;
    __syncthreads();
    for (std::uint32_t offset = blockDim.x >> 1;
         offset != 0;
         offset >>= 1) {
        if (threadIdx.x < offset) {
            shared[threadIdx.x] =
                add(shared[threadIdx.x], shared[threadIdx.x + offset]);
        }
        __syncthreads();
    }
    if (threadIdx.x == 0) {
        partial_sums[
            static_cast<std::size_t>(blockIdx.y) * gridDim.x + blockIdx.x] =
            shared[0];
    }
}

__global__ void reduce_rows_kernel(
    const QM31 *partial_sums,
    std::uint32_t row_width,
    const std::uint32_t *output_indices,
    QM31 *sampled_values,
    std::size_t sampled_value_capacity) {
    extern __shared__ QM31 shared[];
    const QM31 *row =
        partial_sums + static_cast<std::size_t>(blockIdx.x) * row_width;
    QM31 sum = zero();
    for (std::size_t index = threadIdx.x;
         index < static_cast<std::size_t>(row_width);
         index += blockDim.x) {
        sum = add(sum, row[index]);
    }
    shared[threadIdx.x] = sum;
    __syncthreads();
    for (std::uint32_t offset = blockDim.x >> 1;
         offset != 0;
         offset >>= 1) {
        if (threadIdx.x < offset) {
            shared[threadIdx.x] =
                add(shared[threadIdx.x], shared[threadIdx.x + offset]);
        }
        __syncthreads();
    }
    if (threadIdx.x == 0 &&
        static_cast<std::size_t>(output_indices[blockIdx.x]) <
            sampled_value_capacity) {
        sampled_values[output_indices[blockIdx.x]] = shared[0];
    }
}

}  // namespace stwo::cuda::oods

extern "C" int stwo_oods_barycentric_weights_on(
    std::uint32_t half_coset_initial_index,
    std::uint32_t half_coset_step_size,
    std::uint32_t size,
    std::uint32_t log_size,
    const stwo::cuda::oods::SecureCirclePoint *evaluation_point,
    stwo::cuda::oods::QM31 si0,
    stwo::cuda::oods::CirclePoint vanishing_rotation,
    stwo::cuda::oods::QM31 *numerator_inverses,
    stwo::cuda::oods::QM31 *weights,
    stwo::cuda::oods::QM31 *scales,
    void *stream) {
    using namespace stwo::cuda::oods;
    if (half_coset_step_size == 0 || size < 2 || !is_power_of_two(size) ||
        log_size == 0 || log_size >= 31 ||
        size != (1u << log_size) || evaluation_point == nullptr ||
        numerator_inverses == nullptr || weights == nullptr ||
        numerator_inverses == weights || scales == nullptr ||
        stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    ByteRange evaluation_range;
    ByteRange numerator_range;
    ByteRange weight_range;
    ByteRange scale_range;
    if (!element_range(evaluation_point, 1, &evaluation_range) ||
        !element_range(numerator_inverses, size, &numerator_range) ||
        !element_range(weights, size, &weight_range) ||
        !element_range(scales, 2, &scale_range) ||
        ranges_overlap(numerator_range, weight_range) ||
        ranges_overlap(numerator_range, scale_range) ||
        ranges_overlap(weight_range, scale_range) ||
        ranges_overlap(evaluation_range, numerator_range) ||
        ranges_overlap(evaluation_range, weight_range) ||
        ranges_overlap(evaluation_range, scale_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const cudaStream_t cuda_stream =
        reinterpret_cast<cudaStream_t>(stream);
    scales_kernel<<<1, 1, 0, cuda_stream>>>(
        evaluation_point, si0, vanishing_rotation, log_size, scales);
    cudaError_t error = cudaPeekAtLastError();
    if (error != cudaSuccess) return static_cast<int>(error);

    const std::uint32_t blocks =
        1u + (size - 1u) / kBarycentricBlockSize;
    parts_kernel<<<blocks, kBarycentricBlockSize, 0, cuda_stream>>>(
        half_coset_initial_index,
        half_coset_step_size,
        size,
        log_size,
        evaluation_point,
        numerator_inverses,
        weights);
    error = cudaPeekAtLastError();
    if (error != cudaSuccess) return static_cast<int>(error);
    error = batch_inverse_on(
        cuda_stream, numerator_inverses, numerator_inverses, size);
    if (error != cudaSuccess) return static_cast<int>(error);

    finish_weights_kernel<<<blocks, kBarycentricBlockSize, 0, cuda_stream>>>(
        numerator_inverses, weights, scales, size);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_oods_barycentric_eval_many_on(
    const stwo::cuda::oods::M31 *columns,
    std::size_t column_stride_words,
    std::uint32_t column_count,
    const stwo::cuda::oods::QM31 *weights,
    std::uint32_t size,
    stwo::cuda::oods::QM31 *partial_sums,
    std::uint32_t reduction_blocks,
    const std::uint32_t *output_indices,
    stwo::cuda::oods::QM31 *sampled_values,
    std::size_t sampled_value_capacity,
    void *stream) {
    using namespace stwo::cuda::oods;
    if (columns == nullptr || column_count == 0 || column_count > 65535 ||
        column_stride_words < size ||
        weights == nullptr || size == 0 || partial_sums == nullptr ||
        reduction_blocks == 0 ||
        reduction_blocks > 0xffffffffu / kBarycentricBlockSize ||
        output_indices == nullptr ||
        sampled_values == nullptr || sampled_value_capacity == 0 ||
        stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    std::size_t column_elements;
    std::size_t partial_count;
    ByteRange column_range;
    ByteRange weight_range;
    ByteRange partial_range;
    ByteRange index_range;
    ByteRange sampled_range;
    if (!matrix_elements(
            column_count,
            column_stride_words,
            size,
            &column_elements) ||
        !checked_product(
            column_count, reduction_blocks, &partial_count) ||
        !element_range(columns, column_elements, &column_range) ||
        !element_range(weights, size, &weight_range) ||
        !element_range(partial_sums, partial_count, &partial_range) ||
        !element_range(output_indices, column_count, &index_range) ||
        !element_range(
            sampled_values, sampled_value_capacity, &sampled_range) ||
        ranges_overlap(partial_range, column_range) ||
        ranges_overlap(partial_range, weight_range) ||
        ranges_overlap(partial_range, index_range) ||
        ranges_overlap(partial_range, sampled_range) ||
        ranges_overlap(sampled_range, column_range) ||
        ranges_overlap(sampled_range, weight_range) ||
        ranges_overlap(sampled_range, index_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const cudaStream_t cuda_stream =
        reinterpret_cast<cudaStream_t>(stream);
    const dim3 grid(reduction_blocks, column_count);
    evaluate_many_kernel<<<
        grid,
        kBarycentricBlockSize,
        kBarycentricBlockSize * sizeof(QM31),
        cuda_stream>>>(
        columns, column_stride_words, weights, size, partial_sums);
    cudaError_t error = cudaPeekAtLastError();
    if (error != cudaSuccess) return static_cast<int>(error);
    reduce_rows_kernel<<<
        column_count,
        kBarycentricBlockSize,
        kBarycentricBlockSize * sizeof(QM31),
        cuda_stream>>>(
        partial_sums,
        reduction_blocks,
        output_indices,
        sampled_values,
        sampled_value_capacity);
    return static_cast<int>(cudaPeekAtLastError());
}
