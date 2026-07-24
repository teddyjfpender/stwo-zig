// Direct single-write quotient numerators over contiguous resident slabs.

#include "field.cuh"
#include "safety.cuh"

#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>

namespace stwo::cuda::quotient {

constexpr std::uint32_t kBlockSize = 256;
constexpr std::uint32_t kMaximumGroups = 65535;
constexpr std::uint32_t kMaximumLogSize = 30;

__global__ void zero_outputs_kernel(
    const std::uint32_t *group_log_sizes,
    std::uint32_t group_count,
    std::uint32_t max_output_size,
    std::uint32_t *output_0,
    std::uint32_t *output_1,
    std::uint32_t *output_2,
    std::uint32_t *output_3,
    std::size_t output_stride_words) {
    const std::uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    const std::uint32_t group = blockIdx.y;
    if (group >= group_count || row >= max_output_size) return;
    const std::uint32_t log_size = group_log_sizes[group];
    if (log_size > kMaximumLogSize ||
        row >= (1u << log_size) ||
        (1u << log_size) > max_output_size) {
        return;
    }
    const std::size_t offset =
        static_cast<std::size_t>(group) * output_stride_words + row;
    output_0[offset] = 0;
    output_1[offset] = 0;
    output_2[offset] = 0;
    output_3[offset] = 0;
}

__global__ void accumulate_single_write_kernel(
    const std::uint32_t *group_offsets,
    const BatchTermDescriptor *term_descriptors,
    std::uint32_t term_count,
    std::uint32_t group_count,
    std::uint32_t max_output_size,
    const std::uint32_t *source_evaluations,
    std::size_t source_stride_words,
    std::uint32_t source_count,
    const QM31 *line_coefficients,
    std::uint32_t line_term_count,
    const std::uint32_t *group_log_sizes,
    std::uint32_t *output_0,
    std::uint32_t *output_1,
    std::uint32_t *output_2,
    std::uint32_t *output_3,
    std::size_t output_stride_words) {
    const std::uint32_t row = blockIdx.x * blockDim.x + threadIdx.x;
    const std::uint32_t group = blockIdx.y;
    if (group >= group_count || row >= max_output_size ||
        group_offsets[0] != 0 ||
        group_offsets[group_count] != term_count) {
        return;
    }
    const std::uint32_t group_log_size = group_log_sizes[group];
    if (group_log_size == 0 || group_log_size > kMaximumLogSize ||
        (1u << group_log_size) > max_output_size ||
        row >= (1u << group_log_size)) {
        return;
    }
    const std::uint32_t begin = group_offsets[group];
    const std::uint32_t end = group_offsets[group + 1];
    if (begin > end || end > term_count) return;

    QM31 numerator = zero();
    for (std::uint32_t index = begin; index < end; ++index) {
        const BatchTermDescriptor descriptor = term_descriptors[index];
        if (descriptor.source_index >= source_count ||
            descriptor.term_index >= line_term_count ||
            descriptor.source_log_size == 0 ||
            descriptor.source_log_size > group_log_size ||
            descriptor.source_log_size > kMaximumLogSize ||
            (1u << descriptor.source_log_size) > source_stride_words) {
            return;
        }
        const std::uint32_t log_ratio =
            group_log_size - descriptor.source_log_size;
        const std::uint32_t source_row =
            (row >> (log_ratio + 1u) << 1u) + (row & 1u);
        if (source_row >= (1u << descriptor.source_log_size)) return;
        const std::size_t source_offset =
            static_cast<std::size_t>(descriptor.source_index) *
                source_stride_words +
            source_row;
        const std::size_t line_offset =
            static_cast<std::size_t>(descriptor.term_index) * 3;
        numerator = add(
            numerator,
            sub(
                mul_scalar(
                    line_coefficients[line_offset + 2],
                    source_evaluations[source_offset]),
                line_coefficients[line_offset + 1]));
    }

    const std::size_t output_offset =
        static_cast<std::size_t>(group) * output_stride_words + row;
    output_0[output_offset] = numerator.a.a;
    output_1[output_offset] = numerator.a.b;
    output_2[output_offset] = numerator.b.a;
    output_3[output_offset] = numerator.b.b;
}

bool output_ranges(
    std::uint32_t *output_0,
    std::uint32_t *output_1,
    std::uint32_t *output_2,
    std::uint32_t *output_3,
    std::size_t stride,
    std::uint32_t group_count,
    std::uint32_t width,
    ByteRange *ranges) {
    return matrix_range(output_0, group_count, stride, width, &ranges[0]) &&
           matrix_range(output_1, group_count, stride, width, &ranges[1]) &&
           matrix_range(output_2, group_count, stride, width, &ranges[2]) &&
           matrix_range(output_3, group_count, stride, width, &ranges[3]);
}

}  // namespace stwo::cuda::quotient

extern "C" int stwo_zero_quotient_numerator_outputs_on(
    const std::uint32_t *group_log_sizes,
    std::uint32_t group_count,
    std::uint32_t max_output_size,
    std::uint32_t *output_0,
    std::uint32_t *output_1,
    std::uint32_t *output_2,
    std::uint32_t *output_3,
    std::size_t output_stride_words,
    void *stream) {
    using namespace stwo::cuda::quotient;
    if (group_log_sizes == nullptr || group_count == 0 ||
        group_count > kMaximumGroups ||
        !is_power_of_two(max_output_size) ||
        max_output_size > (1u << kMaximumLogSize) ||
        output_stride_words < max_output_size || stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    ByteRange log_range;
    ByteRange writes[4];
    if (!element_range(group_log_sizes, group_count, &log_range) ||
        !output_ranges(
            output_0,
            output_1,
            output_2,
            output_3,
            output_stride_words,
            group_count,
            max_output_size,
            writes) ||
        !ranges_disjoint(writes, 4, &log_range, 1)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    zero_outputs_kernel<<<
        dim3(
            (max_output_size + kBlockSize - 1) / kBlockSize,
            group_count),
        kBlockSize,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            group_log_sizes,
            group_count,
            max_output_size,
            output_0,
            output_1,
            output_2,
            output_3,
            output_stride_words);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_accumulate_quotient_numerator_single_write_on(
    const std::uint32_t *group_offsets,
    const stwo::cuda::quotient::BatchTermDescriptor *term_descriptors,
    std::uint32_t term_count,
    std::uint32_t group_count,
    std::uint32_t max_output_size,
    const std::uint32_t *source_evaluations,
    std::size_t source_stride_words,
    std::uint32_t source_count,
    const stwo::cuda::quotient::QM31 *line_coefficients,
    std::uint32_t line_term_count,
    const std::uint32_t *group_log_sizes,
    std::uint32_t *output_0,
    std::uint32_t *output_1,
    std::uint32_t *output_2,
    std::uint32_t *output_3,
    std::size_t output_stride_words,
    void *stream) {
    using namespace stwo::cuda::quotient;
    if (group_offsets == nullptr || term_descriptors == nullptr ||
        term_count == 0 || group_count == 0 ||
        group_count > kMaximumGroups ||
        !is_power_of_two(max_output_size) ||
        max_output_size > (1u << kMaximumLogSize) ||
        source_evaluations == nullptr || source_stride_words == 0 ||
        source_count == 0 || line_coefficients == nullptr ||
        line_term_count == 0 || group_log_sizes == nullptr ||
        output_stride_words < max_output_size || stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    std::size_t offset_count;
    std::size_t line_count;
    ByteRange offset_range;
    ByteRange descriptor_range;
    ByteRange source_range;
    ByteRange line_range;
    ByteRange log_range;
    ByteRange writes[4];
    if (!stwo::cuda::oods::checked_sum(group_count, 1, &offset_count) ||
        !checked_product(line_term_count, 3, &line_count) ||
        !element_range(group_offsets, offset_count, &offset_range) ||
        !element_range(term_descriptors, term_count, &descriptor_range) ||
        !matrix_range(
            source_evaluations,
            source_count,
            source_stride_words,
            source_stride_words,
            &source_range) ||
        !element_range(line_coefficients, line_count, &line_range) ||
        !element_range(group_log_sizes, group_count, &log_range) ||
        !output_ranges(
            output_0,
            output_1,
            output_2,
            output_3,
            output_stride_words,
            group_count,
            max_output_size,
            writes)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const ByteRange reads[]{
        offset_range,
        descriptor_range,
        source_range,
        line_range,
        log_range,
    };
    if (!ranges_disjoint(writes, 4, reads, 5)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    accumulate_single_write_kernel<<<
        dim3(
            (max_output_size + kBlockSize - 1) / kBlockSize,
            group_count),
        kBlockSize,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            group_offsets,
            term_descriptors,
            term_count,
            group_count,
            max_output_size,
            source_evaluations,
            source_stride_words,
            source_count,
            line_coefficients,
            line_term_count,
            group_log_sizes,
            output_0,
            output_1,
            output_2,
            output_3,
            output_stride_words);
    return static_cast<int>(cudaPeekAtLastError());
}
