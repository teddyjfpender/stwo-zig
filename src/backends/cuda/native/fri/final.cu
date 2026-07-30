// Terminal FRI line interpolation over one contiguous four-coordinate slab.

#include "field.cuh"
#include "safety.cuh"

#include <cuda_runtime_api.h>

#include <stddef.h>
#include <stdint.h>

namespace stwo::cuda::fri {

constexpr uint32_t kFinalThreads = 256;

__global__ void initialize_degree_error_kernel(uint32_t *degree_error) {
    if (blockIdx.x == 0 && threadIdx.x == 0) *degree_error = 0;
}

__global__ void naturalize_kernel(
    const uint32_t *evaluation,
    uint32_t evaluation_stride,
    uint32_t log_size,
    uint32_t *coefficients) {
    const uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t coordinate = blockIdx.y;
    const uint32_t size = 1u << log_size;
    if (row < size && coordinate < 4) {
        coefficients[coordinate * size + row] =
            evaluation[
                coordinate * evaluation_stride + bit_reverse(row, log_size)];
    }
}

__global__ void line_ifft_stage_kernel(
    uint32_t *coefficients,
    uint32_t size,
    uint32_t domain_log_size,
    const uint32_t *inverse_twiddles,
    uint32_t inverse_twiddle_words) {
    const uint32_t butterfly = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t coordinate = blockIdx.y;
    if (butterfly >= size / 2 || coordinate >= 4) return;

    const uint32_t domain_size = 1u << domain_log_size;
    const uint32_t half = domain_size / 2;
    const uint32_t chunk = butterfly / half;
    const uint32_t index = butterfly - chunk * half;
    const uint32_t left = chunk * domain_size + index;
    const uint32_t right = left + half;
    const uint32_t twiddle_index = domain_log_size == 1
        ? 0
        : bit_reverse(index, domain_log_size - 1);
    const uint32_t twiddle =
        inverse_twiddles[inverse_twiddle_words - domain_size + twiddle_index];

    uint32_t *column = coefficients + coordinate * size;
    const uint32_t left_value = column[left];
    const uint32_t right_value = column[right];
    column[left] = m31_add(left_value, right_value);
    column[right] =
        m31_mul(m31_sub(left_value, right_value), twiddle);
}

__global__ void normalize_kernel(
    uint32_t *coefficients,
    size_t word_count,
    uint32_t factor) {
    const size_t index =
        static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (index < word_count) {
        coefficients[index] = m31_mul(coefficients[index], factor);
    }
}

__global__ void validate_degree_kernel(
    const uint32_t *coefficients,
    uint32_t size,
    uint32_t log_size,
    uint32_t degree_bound,
    uint32_t *degree_error) {
    const uint32_t ordered_index =
        degree_bound + blockIdx.x * blockDim.x + threadIdx.x;
    if (ordered_index >= size) return;

    const uint32_t source_index = bit_reverse(ordered_index, log_size);
    uint32_t nonzero = 0;
#pragma unroll
    for (uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
        nonzero |= coefficients[coordinate * size + source_index];
    }
    if (nonzero != 0) atomicExch(degree_error, 1u);
}

__global__ void emit_coefficients_kernel(
    const uint32_t *coefficients,
    uint32_t size,
    uint32_t log_size,
    uint32_t degree_bound,
    const uint32_t *degree_error,
    uint32_t *transcript_coefficients) {
    const uint32_t output_index = blockIdx.x * blockDim.x + threadIdx.x;
    if (output_index >= degree_bound) return;

    const uint32_t log_degree_bound = degree_bound == 1
        ? 0
        : 31u - static_cast<uint32_t>(__clz(degree_bound));
    const uint32_t ordered_index = log_degree_bound == 0
        ? 0
        : bit_reverse(output_index, log_degree_bound);
    const uint32_t source_index = bit_reverse(ordered_index, log_size);
#pragma unroll
    for (uint32_t coordinate = 0; coordinate < 4; ++coordinate) {
        transcript_coefficients[4 * output_index + coordinate] =
            coefficients[coordinate * size + source_index];
    }
    if (output_index == 0 && *degree_error != 0) {
        transcript_coefficients[0] = kM31Prime;
    }
}

inline bool disjoint_final_buffers(
    const uint32_t *evaluation,
    size_t evaluation_bytes,
    const uint32_t *inverse_twiddles,
    size_t inverse_twiddle_bytes,
    uint32_t *coefficients,
    size_t coefficient_bytes,
    uint32_t *degree_error,
    uint32_t *transcript_coefficients,
    size_t transcript_bytes) {
    constexpr size_t error_bytes = sizeof(uint32_t);
    return
        !ranges_overlap(
            evaluation, evaluation_bytes, coefficients, coefficient_bytes) &&
        !ranges_overlap(
            inverse_twiddles, inverse_twiddle_bytes,
            coefficients, coefficient_bytes) &&
        !ranges_overlap(
            evaluation, evaluation_bytes, degree_error, error_bytes) &&
        !ranges_overlap(
            inverse_twiddles, inverse_twiddle_bytes,
            degree_error, error_bytes) &&
        !ranges_overlap(
            evaluation, evaluation_bytes,
            transcript_coefficients, transcript_bytes) &&
        !ranges_overlap(
            inverse_twiddles, inverse_twiddle_bytes,
            transcript_coefficients, transcript_bytes) &&
        !ranges_overlap(
            coefficients, coefficient_bytes, degree_error, error_bytes) &&
        !ranges_overlap(
            coefficients, coefficient_bytes,
            transcript_coefficients, transcript_bytes) &&
        !ranges_overlap(
            degree_error, error_bytes,
            transcript_coefficients, transcript_bytes);
}

}  // namespace stwo::cuda::fri

extern "C" int stwo_fri_last_layer_on(
    const uint32_t *evaluation,
    size_t evaluation_words,
    uint32_t evaluation_stride,
    uint32_t log_size,
    const uint32_t *inverse_twiddles,
    uint32_t inverse_twiddle_words,
    uint32_t log_degree_bound,
    uint32_t *coefficients,
    size_t coefficient_words,
    uint32_t *degree_error,
    size_t degree_error_words,
    uint32_t *transcript_coefficients,
    size_t transcript_words,
    void *stream) {
    if (evaluation == nullptr || inverse_twiddles == nullptr ||
        coefficients == nullptr || degree_error == nullptr ||
        transcript_coefficients == nullptr || stream == nullptr ||
        log_size == 0 || log_size > 30 || log_degree_bound > log_size) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const uint32_t size = 1u << log_size;
    const uint32_t degree_bound = 1u << log_degree_bound;
    if (evaluation_stride < size || inverse_twiddle_words < size) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    if (evaluation_words != static_cast<size_t>(4) * evaluation_stride ||
        coefficient_words != static_cast<size_t>(4) * size ||
        degree_error_words != 1 ||
        transcript_words != static_cast<size_t>(4) * degree_bound) {
        return static_cast<int>(cudaErrorInvalidValue);
    }

    size_t evaluation_bytes = 0;
    size_t inverse_twiddle_bytes = 0;
    size_t coefficient_bytes = 0;
    size_t transcript_bytes = 0;
    if (!stwo::cuda::fri::checked_bytes(
            evaluation_words, sizeof(uint32_t), &evaluation_bytes) ||
        !stwo::cuda::fri::checked_bytes(
            inverse_twiddle_words, sizeof(uint32_t),
            &inverse_twiddle_bytes) ||
        !stwo::cuda::fri::checked_bytes(
            coefficient_words, sizeof(uint32_t), &coefficient_bytes) ||
        !stwo::cuda::fri::checked_bytes(
            transcript_words, sizeof(uint32_t), &transcript_bytes) ||
        !stwo::cuda::fri::disjoint_final_buffers(
            evaluation, evaluation_bytes, inverse_twiddles,
            inverse_twiddle_bytes, coefficients, coefficient_bytes,
            degree_error, transcript_coefficients, transcript_bytes)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }

    const cudaStream_t proof_stream = reinterpret_cast<cudaStream_t>(stream);
    stwo::cuda::fri::initialize_degree_error_kernel<<<
        1, 1, 0, proof_stream>>>(degree_error);
    cudaError_t status = cudaPeekAtLastError();
    if (status != cudaSuccess) return static_cast<int>(status);

    const uint32_t row_blocks =
        (size + stwo::cuda::fri::kFinalThreads - 1) /
        stwo::cuda::fri::kFinalThreads;
    stwo::cuda::fri::naturalize_kernel<<<
        dim3(row_blocks, 4),
        stwo::cuda::fri::kFinalThreads,
        0,
        proof_stream>>>(
            evaluation, evaluation_stride, log_size, coefficients);
    status = cudaPeekAtLastError();
    if (status != cudaSuccess) return static_cast<int>(status);

    const uint32_t butterfly_blocks =
        (size / 2 + stwo::cuda::fri::kFinalThreads - 1) /
        stwo::cuda::fri::kFinalThreads;
    for (uint32_t stage = log_size; stage > 0; --stage) {
        stwo::cuda::fri::line_ifft_stage_kernel<<<
            dim3(butterfly_blocks, 4),
            stwo::cuda::fri::kFinalThreads,
            0,
            proof_stream>>>(
                coefficients, size, stage, inverse_twiddles,
                inverse_twiddle_words);
        status = cudaPeekAtLastError();
        if (status != cudaSuccess) return static_cast<int>(status);
    }

    const size_t coefficient_launch_words = static_cast<size_t>(4) * size;
    stwo::cuda::fri::normalize_kernel<<<
        (coefficient_launch_words + stwo::cuda::fri::kFinalThreads - 1) /
            stwo::cuda::fri::kFinalThreads,
        stwo::cuda::fri::kFinalThreads,
        0,
        proof_stream>>>(
            coefficients,
            coefficient_launch_words,
            stwo::cuda::m31_inverse_power_of_two(log_size));
    status = cudaPeekAtLastError();
    if (status != cudaSuccess) return static_cast<int>(status);

    const uint32_t high_count = size - degree_bound;
    if (high_count != 0) {
        stwo::cuda::fri::validate_degree_kernel<<<
            (high_count + stwo::cuda::fri::kFinalThreads - 1) /
                stwo::cuda::fri::kFinalThreads,
            stwo::cuda::fri::kFinalThreads,
            0,
            proof_stream>>>(
                coefficients, size, log_size, degree_bound, degree_error);
        status = cudaPeekAtLastError();
        if (status != cudaSuccess) return static_cast<int>(status);
    }

    stwo::cuda::fri::emit_coefficients_kernel<<<
        (degree_bound + stwo::cuda::fri::kFinalThreads - 1) /
            stwo::cuda::fri::kFinalThreads,
        stwo::cuda::fri::kFinalThreads,
        0,
        proof_stream>>>(
            coefficients, size, log_size, degree_bound, degree_error,
            transcript_coefficients);
    return static_cast<int>(cudaPeekAtLastError());
}
