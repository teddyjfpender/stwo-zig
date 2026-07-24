// Resident quotient combination copied from the pinned authority.

#include "field.cuh"
#include "safety.cuh"

#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>

namespace stwo::cuda::quotient {

constexpr std::uint32_t kBlockSize = 512;
constexpr std::uint32_t kInverseChunk = 8;
constexpr std::uint32_t kMaximumLogSize = 30;

template <std::uint32_t Chunk>
__device__ __forceinline__ void denominator_inverse_chunk(
    const SecureCirclePoint *sample_points,
    std::uint32_t sample_start,
    std::uint32_t sample_count,
    CirclePoint domain_point,
    CM31 *inverses) {
    std::uint32_t zero_mask = 0;
#pragma unroll
    for (std::uint32_t offset = 0; offset < Chunk; ++offset) {
        CM31 value{1u, 0u};
        if (offset < sample_count) {
            value = denominator(
                sample_points[sample_start + offset],
                domain_point);
            const bool is_zero = value.a == 0 && value.b == 0;
            zero_mask |= static_cast<std::uint32_t>(is_zero) << offset;
            if (is_zero) value = CM31{1u, 0u};
        }
        inverses[offset] =
            offset == 0 ? value : mul(inverses[offset - 1], value);
    }
    CM31 inverse_product = inverse(inverses[Chunk - 1]);
#pragma unroll
    for (int offset = static_cast<int>(Chunk) - 1; offset > 0; --offset) {
        CM31 value{1u, 0u};
        if (static_cast<std::uint32_t>(offset) < sample_count) {
            value = denominator(
                sample_points[sample_start + offset],
                domain_point);
            if (value.a == 0 && value.b == 0) value = CM31{1u, 0u};
        }
        const CM31 value_inverse =
            mul(inverse_product, inverses[offset - 1]);
        inverse_product = mul(inverse_product, value);
        inverses[offset] =
            (zero_mask & (1u << offset)) != 0
                ? CM31{0u, 0u}
                : value_inverse;
    }
    inverses[0] =
        (zero_mask & 1u) != 0 ? CM31{0u, 0u} : inverse_product;
}

__global__ void combine_kernel(
    std::uint32_t half_coset_initial_index,
    std::uint32_t half_coset_step_size,
    std::uint32_t domain_size,
    std::uint32_t domain_log_size,
    const SecureCirclePoint *sample_points,
    std::uint32_t sample_count,
    const QM31 *first_linear_terms,
    const std::uint32_t *partial_log_sizes,
    const std::uint32_t *partial_0,
    const std::uint32_t *partial_1,
    const std::uint32_t *partial_2,
    const std::uint32_t *partial_3,
    std::size_t partial_stride_words,
    std::uint32_t *result_0,
    std::uint32_t *result_1,
    std::uint32_t *result_2,
    std::uint32_t *result_3) {
    const std::uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= domain_size) return;
    const CirclePoint domain_point = domain_at_index(
        half_coset_initial_index,
        half_coset_step_size,
        bit_reverse(row, domain_log_size),
        domain_size);

    QM31 quotient = zero();
    for (std::uint32_t start = 0; start < sample_count;
         start += kInverseChunk) {
        const std::uint32_t remaining = sample_count - start;
        const std::uint32_t count =
            remaining < kInverseChunk ? remaining : kInverseChunk;
        CM31 inverses[kInverseChunk];
        denominator_inverse_chunk<kInverseChunk>(
            sample_points,
            start,
            count,
            domain_point,
            inverses);
#pragma unroll
        for (std::uint32_t offset = 0; offset < kInverseChunk; ++offset) {
            if (offset >= count) continue;
            const std::uint32_t sample = start + offset;
            const std::uint32_t partial_log_size =
                partial_log_sizes[sample];
            if (partial_log_size == 0 ||
                partial_log_size > domain_log_size ||
                partial_log_size > kMaximumLogSize ||
                (1u << partial_log_size) > partial_stride_words) {
                return;
            }
            const std::uint32_t log_ratio =
                domain_log_size - partial_log_size;
            const std::uint32_t lifted =
                (row >> (log_ratio + 1u) << 1u) + (row & 1u);
            if (lifted >= (1u << partial_log_size)) return;
            const std::size_t index =
                static_cast<std::size_t>(sample) *
                    partial_stride_words +
                lifted;
            const QM31 partial{
                CM31{partial_0[index], partial_1[index]},
                CM31{partial_2[index], partial_3[index]},
            };
            const QM31 full_numerator = sub(
                partial,
                mul_scalar(first_linear_terms[sample], domain_point.y));
            quotient = add(
                quotient,
                mul(full_numerator, QM31{inverses[offset], CM31{0u, 0u}}));
        }
    }
    result_0[row] = quotient.a.a;
    result_1[row] = quotient.a.b;
    result_2[row] = quotient.b.a;
    result_3[row] = quotient.b.b;
}

}  // namespace stwo::cuda::quotient

extern "C" int stwo_combine_quotients_from_numerators_on(
    std::uint32_t half_coset_initial_index,
    std::uint32_t half_coset_step_size,
    std::uint32_t domain_size,
    std::uint32_t domain_log_size,
    const stwo::cuda::quotient::SecureCirclePoint *sample_points,
    std::uint32_t sample_count,
    const stwo::cuda::quotient::QM31 *first_linear_terms,
    const std::uint32_t *partial_log_sizes,
    const std::uint32_t *partial_0,
    const std::uint32_t *partial_1,
    const std::uint32_t *partial_2,
    const std::uint32_t *partial_3,
    std::size_t partial_stride_words,
    std::uint32_t *result_0,
    std::uint32_t *result_1,
    std::uint32_t *result_2,
    std::uint32_t *result_3,
    void *stream) {
    using namespace stwo::cuda::quotient;
    if (half_coset_step_size == 0 || domain_size == 0 ||
        domain_log_size == 0 || domain_log_size > kMaximumLogSize ||
        domain_size != (1u << domain_log_size) ||
        sample_points == nullptr || sample_count == 0 ||
        first_linear_terms == nullptr || partial_log_sizes == nullptr ||
        partial_stride_words == 0 || result_0 == nullptr ||
        result_1 == nullptr || result_2 == nullptr ||
        result_3 == nullptr || stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    ByteRange sample_range;
    ByteRange first_range;
    ByteRange log_range;
    ByteRange partial_ranges[4];
    ByteRange result_ranges[4];
    if (!element_range(sample_points, sample_count, &sample_range) ||
        !element_range(first_linear_terms, sample_count, &first_range) ||
        !element_range(partial_log_sizes, sample_count, &log_range) ||
        !matrix_range(
            partial_0,
            sample_count,
            partial_stride_words,
            partial_stride_words,
            &partial_ranges[0]) ||
        !matrix_range(
            partial_1,
            sample_count,
            partial_stride_words,
            partial_stride_words,
            &partial_ranges[1]) ||
        !matrix_range(
            partial_2,
            sample_count,
            partial_stride_words,
            partial_stride_words,
            &partial_ranges[2]) ||
        !matrix_range(
            partial_3,
            sample_count,
            partial_stride_words,
            partial_stride_words,
            &partial_ranges[3]) ||
        !element_range(result_0, domain_size, &result_ranges[0]) ||
        !element_range(result_1, domain_size, &result_ranges[1]) ||
        !element_range(result_2, domain_size, &result_ranges[2]) ||
        !element_range(result_3, domain_size, &result_ranges[3])) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const ByteRange reads[]{
        sample_range,
        first_range,
        log_range,
        partial_ranges[0],
        partial_ranges[1],
        partial_ranges[2],
        partial_ranges[3],
    };
    if (!ranges_disjoint(result_ranges, 4, reads, 7)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    combine_kernel<<<
        (domain_size + kBlockSize - 1) / kBlockSize,
        kBlockSize,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            half_coset_initial_index,
            half_coset_step_size,
            domain_size,
            domain_log_size,
            sample_points,
            sample_count,
            first_linear_terms,
            partial_log_sizes,
            partial_0,
            partial_1,
            partial_2,
            partial_3,
            partial_stride_words,
            result_0,
            result_1,
            result_2,
            result_3);
    return static_cast<int>(cudaPeekAtLastError());
}
