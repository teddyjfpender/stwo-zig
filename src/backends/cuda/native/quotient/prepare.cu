// Allocation-free quotient term preparation copied from the pinned authority.

#include "field.cuh"
#include "safety.cuh"

#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>

namespace stwo::cuda::quotient {

constexpr std::uint32_t kBlockSize = 256;

__global__ void prepare_terms_kernel(
    const PreparedTermDescriptor *descriptors,
    std::uint32_t term_count,
    const SecureCirclePoint *sample_points,
    const QM31 *sample_values,
    std::uint32_t sample_count,
    const QM31 *random_coefficient,
    SecureCirclePoint *term_points,
    QM31 *line_coefficients) {
    const std::uint32_t term = blockIdx.x * blockDim.x + threadIdx.x;
    if (term >= term_count) return;

    const PreparedTermDescriptor descriptor = descriptors[term];
    if (descriptor.sample_index >= sample_count) return;
    SecureCirclePoint point = sample_points[descriptor.sample_index];
    if (descriptor.periodic != 0) {
        point = add_base_offset(
            point,
            CirclePoint{descriptor.period_x, descriptor.period_y});
    }
    QM31 a;
    QM31 b;
    QM31 c;
    conjugate_line_coefficients(
        point,
        sample_values[descriptor.sample_index],
        power(*random_coefficient, descriptor.exponent),
        &a,
        &b,
        &c);
    term_points[term] = point;
    line_coefficients[static_cast<std::size_t>(term) * 3] = a;
    line_coefficients[static_cast<std::size_t>(term) * 3 + 1] = b;
    line_coefficients[static_cast<std::size_t>(term) * 3 + 2] = c;
}

__global__ void finalize_groups_kernel(
    const std::uint32_t *group_offsets,
    const std::uint32_t *group_term_indices,
    std::uint32_t group_term_index_count,
    std::uint32_t group_count,
    const SecureCirclePoint *term_points,
    std::uint32_t term_count,
    QM31 *line_coefficients,
    SecureCirclePoint *sample_points,
    QM31 *first_linear_terms) {
    const std::uint32_t group = blockIdx.x * blockDim.x + threadIdx.x;
    if (group >= group_count) return;

    const std::uint32_t begin = group_offsets[group];
    const std::uint32_t end = group_offsets[group + 1];
    if (begin >= end || end > group_term_index_count) return;
    const std::uint32_t representative = group_term_indices[begin];
    if (representative >= term_count) return;

    QM31 first = zero();
    QM31 group_b = zero();
    for (std::uint32_t index = begin; index < end; ++index) {
        const std::uint32_t term = group_term_indices[index];
        if (term >= term_count) return;
        first = add(
            first,
            line_coefficients[static_cast<std::size_t>(term) * 3]);
        group_b = add(
            group_b,
            line_coefficients[static_cast<std::size_t>(term) * 3 + 1]);
    }
    sample_points[group] = term_points[representative];
    first_linear_terms[group] = first;
    line_coefficients[static_cast<std::size_t>(representative) * 3] = group_b;
}

}  // namespace stwo::cuda::quotient

extern "C" int stwo_prepare_quotient_numerator_terms_on(
    const stwo::cuda::quotient::PreparedTermDescriptor *term_descriptors,
    std::uint32_t term_count,
    const stwo::cuda::quotient::SecureCirclePoint *sample_points,
    const stwo::cuda::quotient::QM31 *sample_values,
    std::uint32_t sample_count,
    const stwo::cuda::quotient::QM31 *random_coefficient,
    stwo::cuda::quotient::SecureCirclePoint *term_points,
    stwo::cuda::quotient::QM31 *line_coefficients,
    void *stream) {
    using namespace stwo::cuda::quotient;
    if (term_descriptors == nullptr || term_count == 0 ||
        sample_points == nullptr || sample_values == nullptr ||
        sample_count == 0 || random_coefficient == nullptr ||
        term_points == nullptr || line_coefficients == nullptr ||
        stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    std::size_t line_count;
    ByteRange descriptor_range;
    ByteRange point_range;
    ByteRange value_range;
    ByteRange random_range;
    ByteRange term_point_range;
    ByteRange line_range;
    if (!checked_product(term_count, 3, &line_count) ||
        !element_range(term_descriptors, term_count, &descriptor_range) ||
        !element_range(sample_points, sample_count, &point_range) ||
        !element_range(sample_values, sample_count, &value_range) ||
        !element_range(random_coefficient, 1, &random_range) ||
        !element_range(term_points, term_count, &term_point_range) ||
        !element_range(line_coefficients, line_count, &line_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const ByteRange writes[]{term_point_range, line_range};
    const ByteRange reads[]{
        descriptor_range,
        point_range,
        value_range,
        random_range,
    };
    if (!ranges_disjoint(writes, 2, reads, 4)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    prepare_terms_kernel<<<
        (term_count + kBlockSize - 1) / kBlockSize,
        kBlockSize,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            term_descriptors,
            term_count,
            sample_points,
            sample_values,
            sample_count,
            random_coefficient,
            term_points,
            line_coefficients);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_finalize_quotient_numerator_groups_on(
    const std::uint32_t *group_offsets,
    const std::uint32_t *group_term_indices,
    std::uint32_t group_term_index_count,
    std::uint32_t group_count,
    const stwo::cuda::quotient::SecureCirclePoint *term_points,
    std::uint32_t term_count,
    stwo::cuda::quotient::QM31 *line_coefficients,
    stwo::cuda::quotient::SecureCirclePoint *sample_points,
    stwo::cuda::quotient::QM31 *first_linear_terms,
    void *stream) {
    using namespace stwo::cuda::quotient;
    if (group_offsets == nullptr || group_term_indices == nullptr ||
        group_term_index_count == 0 || group_count == 0 ||
        term_points == nullptr || term_count == 0 ||
        line_coefficients == nullptr || sample_points == nullptr ||
        first_linear_terms == nullptr || stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    std::size_t offset_count;
    std::size_t line_count;
    ByteRange offset_range;
    ByteRange index_range;
    ByteRange term_point_range;
    ByteRange line_range;
    ByteRange sample_range;
    ByteRange first_range;
    if (!stwo::cuda::oods::checked_sum(group_count, 1, &offset_count) ||
        !checked_product(term_count, 3, &line_count) ||
        !element_range(group_offsets, offset_count, &offset_range) ||
        !element_range(
            group_term_indices,
            group_term_index_count,
            &index_range) ||
        !element_range(term_points, term_count, &term_point_range) ||
        !element_range(line_coefficients, line_count, &line_range) ||
        !element_range(sample_points, group_count, &sample_range) ||
        !element_range(first_linear_terms, group_count, &first_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const ByteRange writes[]{line_range, sample_range, first_range};
    const ByteRange reads[]{offset_range, index_range, term_point_range};
    if (!ranges_disjoint(writes, 3, reads, 3)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    finalize_groups_kernel<<<
        (group_count + kBlockSize - 1) / kBlockSize,
        kBlockSize,
        0,
        reinterpret_cast<cudaStream_t>(stream)>>>(
            group_offsets,
            group_term_indices,
            group_term_index_count,
            group_count,
            term_points,
            term_count,
            line_coefficients,
            sample_points,
            first_linear_terms);
    return static_cast<int>(cudaPeekAtLastError());
}
