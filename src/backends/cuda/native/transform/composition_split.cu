// Resident four-coordinate B2N and canonical compact composition split.

#include "../common/circle_twiddle.cuh"
#include "transform_internal.cuh"

namespace {

using stwo::cuda::M31;
using stwo::cuda::circle_twiddle;
using stwo::cuda::m31_add;
using stwo::cuda::m31_inverse_power_of_two;
using stwo::cuda::m31_mul;
using stwo::cuda::m31_sub;

constexpr uint32_t kCoordinateCount = 4u;

__global__ void b2n_composition_stage(
    M31 *coordinates,
    uint32_t log_n,
    uint32_t stage,
    const M31 *layer_twiddles) {
    const uint32_t pair_index =
        blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t coordinate = blockIdx.y;
    const uint32_t pair_count = 1u << (log_n - 1u);
    if (pair_index >= pair_count) return;

    const uint32_t values = 1u << log_n;
    const uint32_t stride = 1u << (stage - 1u);
    const uint32_t group_index = pair_index & (stride - 1u);
    const uint32_t butterfly_index = pair_index >> (stage - 1u);
    const uint32_t left_index =
        group_index + butterfly_index * 2u * stride;
    const uint32_t right_index = left_index + stride;
    M31 *values_for_coordinate =
        coordinates + static_cast<size_t>(coordinate) * values;

    const M31 left = values_for_coordinate[left_index];
    const M31 right = values_for_coordinate[right_index];
    const M31 twiddle = stage == 1u
        ? circle_twiddle(layer_twiddles, butterfly_index)
        : layer_twiddles[butterfly_index];
    values_for_coordinate[left_index] = m31_add(left, right);
    values_for_coordinate[right_index] =
        m31_mul(m31_sub(left, right), twiddle);
}

__global__ void b2n_composition_split_final(
    const M31 *coordinates,
    M31 *coefficients,
    uint32_t log_n,
    const M31 *layer_twiddles,
    M31 rescale_factor) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t coordinate = blockIdx.y;
    const uint32_t half_rows = 1u << (log_n - 1u);
    if (row >= half_rows) return;

    const M31 *source =
        coordinates + static_cast<size_t>(coordinate) * (2u * half_rows);
    const M31 left = source[row];
    const M31 right = source[row + half_rows];
    const M31 twiddle = layer_twiddles[0];
    const M31 left_result =
        m31_mul(m31_add(left, right), rescale_factor);
    const M31 right_result =
        m31_mul(m31_mul(m31_sub(left, right), twiddle), rescale_factor);

    M31 *left_output =
        coefficients + static_cast<size_t>(coordinate) * half_rows;
    M31 *right_output = coefficients +
        static_cast<size_t>(coordinate + kCoordinateCount) * half_rows;
    left_output[row] = left_result;
    right_output[row] = right_result;
}

cudaError_t launch_composition_split(
    uint32_t *coordinate_values,
    uint32_t *coefficients,
    uint32_t log_n,
    const uint32_t *twiddles,
    uint32_t twiddle_words,
    uint32_t evaluation_domain_size,
    cudaStream_t stream) {
    using namespace stwo::cuda::transform;
    const auto *inverse_twiddles = reinterpret_cast<const M31 *>(
        twiddles + twiddle_words - evaluation_domain_size);
    const uint32_t pair_count = 1u << (log_n - 1u);
    const uint32_t blocks =
        (pair_count + kThreadsPerBlock - 1u) / kThreadsPerBlock;
    const dim3 grid(blocks, kCoordinateCount);
    const M31 rescale_factor = m31_inverse_power_of_two(log_n);

    b2n_composition_stage<<<grid, kThreadsPerBlock, 0, stream>>>(
        reinterpret_cast<M31 *>(coordinate_values),
        log_n,
        1u,
        inverse_twiddles);
    cudaError_t status = cudaPeekAtLastError();
    if (status != cudaSuccess) return status;

    uint32_t layer_size = pair_count;
    uint32_t layer_offset = 0u;
    for (uint32_t stage = 2u; stage < log_n; ++stage) {
        b2n_composition_stage<<<grid, kThreadsPerBlock, 0, stream>>>(
            reinterpret_cast<M31 *>(coordinate_values),
            log_n,
            stage,
            inverse_twiddles + layer_offset);
        status = cudaPeekAtLastError();
        if (status != cudaSuccess) return status;
        layer_size >>= 1u;
        layer_offset += layer_size;
    }

    b2n_composition_split_final<<<grid, kThreadsPerBlock, 0, stream>>>(
        reinterpret_cast<const M31 *>(coordinate_values),
        reinterpret_cast<M31 *>(coefficients),
        log_n,
        inverse_twiddles + layer_offset,
        rescale_factor);
    return cudaPeekAtLastError();
}

}  // namespace

extern "C" int stwo_ntt_b2n_composition_split_compact_on(
    uint32_t *coordinate_values,
    size_t coordinate_capacity_words,
    size_t coordinate_stride_words,
    uint32_t *coefficients,
    size_t coefficient_capacity_words,
    size_t coefficient_stride_words,
    uint32_t log_n,
    const uint32_t *inverse_twiddles,
    uint32_t inverse_twiddle_words,
    uint32_t evaluation_domain_size,
    void *stream_raw) {
    using namespace stwo::cuda::transform;
    if (!valid_shape(
            log_n,
            kCoordinateCount,
            inverse_twiddle_words,
            evaluation_domain_size) ||
        stream_raw == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }

    const size_t values = static_cast<size_t>(1) << log_n;
    const size_t half_values = values / 2u;
    if (values > SIZE_MAX / kCoordinateCount ||
        coordinate_stride_words != values ||
        coefficient_stride_words != half_values ||
        coordinate_capacity_words != kCoordinateCount * values ||
        coefficient_capacity_words != kCoordinateCount * values) {
        return static_cast<int>(cudaErrorInvalidValue);
    }

    DeviceRange input_range{};
    DeviceRange output_range{};
    DeviceRange twiddle_range{};
    if (!word_range(
            coordinate_values,
            coordinate_capacity_words,
            &input_range) ||
        !word_range(
            coefficients,
            coefficient_capacity_words,
            &output_range) ||
        !word_range(
            inverse_twiddles,
            inverse_twiddle_words,
            &twiddle_range) ||
        ranges_overlap(input_range, output_range) ||
        ranges_overlap(input_range, twiddle_range) ||
        ranges_overlap(output_range, twiddle_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }

    return static_cast<int>(launch_composition_split(
        coordinate_values,
        coefficients,
        log_n,
        inverse_twiddles,
        inverse_twiddle_words,
        evaluation_domain_size,
        reinterpret_cast<cudaStream_t>(stream_raw)));
}
