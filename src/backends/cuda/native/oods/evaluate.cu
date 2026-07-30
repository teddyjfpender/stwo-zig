// Resident out-of-domain point derivation and coefficient evaluation.
// Inputs, pointer tables, scratch, and outputs are caller-owned device memory.

#include "field.cuh"
#include "safety.cuh"

#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>

namespace stwo::cuda::oods {

constexpr std::uint32_t kBlockSize = 256;
constexpr std::uint32_t kFirstCoefficientsPerThread = 16;
constexpr std::uint32_t kFirstFoldLevels = 4;
constexpr std::uint32_t kFirstCoefficientsPerBlock =
    kFirstCoefficientsPerThread * kBlockSize;
constexpr std::uint32_t kReduceCoefficientsPerBlock = 2 * kBlockSize;
static_assert(
    kFirstCoefficientsPerThread == (1u << kFirstFoldLevels),
    "the register tile must consume exactly kFirstFoldLevels factors");

__global__ void derive_points_kernel(
    const QM31 *oods_parameter,
    const CirclePoint *offset_points,
    const std::uint32_t *fold_counts,
    const std::uint32_t *output_indices,
    std::uint32_t sample_count,
    std::uint32_t coefficient_log_size,
    std::size_t sample_point_capacity,
    SecureCirclePoint *sample_points,
    SecureCirclePoint *evaluation_points,
    QM31 *folding_factors) {
    const std::uint32_t sample = blockIdx.x * blockDim.x + threadIdx.x;
    if (sample >= sample_count) return;

    const QM31 parameter = oods_parameter[0];
    const QM31 parameter_squared = square(parameter);
    const QM31 denominator_inverse =
        inverse(add(one(), parameter_squared));
    SecureCirclePoint sample_point{
        mul(sub(one(), parameter_squared), denominator_inverse),
        mul(add(parameter, parameter), denominator_inverse),
    };
    sample_point = add_base(sample_point, offset_points[sample]);
    if (static_cast<std::size_t>(output_indices[sample]) <
        sample_point_capacity) {
        sample_points[output_indices[sample]] = sample_point;
    }

    SecureCirclePoint evaluation_point = sample_point;
    const std::uint32_t requested_folds = fold_counts[sample];
    const std::uint32_t fold_count =
        requested_folds < 31u ? requested_folds : 31u;
    for (std::uint32_t index = 0; index < fold_count; ++index) {
        evaluation_point = double_point(evaluation_point);
    }
    evaluation_points[sample] = evaluation_point;

    QM31 *factors =
        folding_factors + static_cast<std::size_t>(sample) * coefficient_log_size;
    factors[coefficient_log_size - 1] = evaluation_point.y;
    QM31 x = evaluation_point.x;
    for (int index = static_cast<int>(coefficient_log_size) - 2;
         index >= 0;
         --index) {
        factors[index] = x;
        x = sub(add(square(x), square(x)), one());
    }
}

__global__ void evaluate_first_kernel(
    const M31 *coefficients,
    std::size_t column_stride_words,
    std::uint32_t coefficient_size,
    std::uint32_t sample_count,
    const QM31 *folding_factors,
    std::uint32_t coefficient_log_size,
    std::uint32_t blocks_per_sample,
    QM31 *scratch) {
    const std::uint32_t sample = blockIdx.y;
    if (sample >= sample_count || blockIdx.x >= blocks_per_sample) return;

    extern __shared__ QM31 shared_level[];
    const std::uint32_t lane = threadIdx.x;
    const M31 *column =
        coefficients + static_cast<std::size_t>(sample) * column_stride_words;
    const QM31 *factors =
        folding_factors + static_cast<std::size_t>(sample) * coefficient_log_size;

    if (coefficient_size < kFirstCoefficientsPerThread) {
        if (lane == 0u) {
            QM31 values[kFirstCoefficientsPerThread];
            for (std::uint32_t index = 0; index < coefficient_size; ++index) {
                values[index] = QM31{{column[index], 0u}, {0u, 0u}};
            }
            std::uint32_t size = coefficient_size;
            int factor = static_cast<int>(coefficient_log_size) - 1;
            while (size > 1u) {
                for (std::uint32_t index = 0; index < size / 2u; ++index) {
                    values[index] = add(
                        values[2u * index],
                        mul(values[2u * index + 1u], factors[factor]));
                }
                size >>= 1;
                --factor;
            }
            scratch[static_cast<std::size_t>(sample) * blocks_per_sample] =
                values[0];
        }
        return;
    }

    const std::uint32_t local_coefficient_size =
        coefficient_size < kFirstCoefficientsPerBlock
            ? coefficient_size
            : kFirstCoefficientsPerBlock;
    const std::uint32_t active_lanes =
        local_coefficient_size / kFirstCoefficientsPerThread;
    const std::uint32_t base =
        blockIdx.x * kFirstCoefficientsPerBlock +
        lane * kFirstCoefficientsPerThread;
    int factor_index = static_cast<int>(coefficient_log_size) - 1;
    if (lane < active_lanes) {
        QM31 thread_values[kFirstCoefficientsPerThread / 2u];
        for (std::uint32_t index = 0;
             index < kFirstCoefficientsPerThread / 2u;
             ++index) {
            thread_values[index] = add(
                column[base + 2u * index],
                mul(
                    column[base + 2u * index + 1u],
                    factors[factor_index]));
        }
        std::uint32_t thread_size = kFirstCoefficientsPerThread / 2u;
        int thread_factor = factor_index - 1;
        while (thread_size > 1u) {
            for (std::uint32_t index = 0; index < thread_size / 2u; ++index) {
                thread_values[index] = add(
                    thread_values[2u * index],
                    mul(
                        thread_values[2u * index + 1u],
                        factors[thread_factor]));
            }
            thread_size >>= 1;
            --thread_factor;
        }
        shared_level[lane] = thread_values[0];
    }
    factor_index -= kFirstFoldLevels;
    std::uint32_t level_size = active_lanes >> 1;
    while (level_size != 0) {
        __syncthreads();
        QM31 left_value = zero();
        QM31 right_value = zero();
        if (lane < level_size) {
            left_value = shared_level[2 * lane];
            right_value = shared_level[2 * lane + 1];
        }
        __syncthreads();
        if (lane < level_size) {
            shared_level[lane] =
                add(left_value, mul(right_value, factors[factor_index]));
        }
        --factor_index;
        level_size >>= 1;
    }
    if (lane == 0) {
        scratch[
            static_cast<std::size_t>(sample) * blocks_per_sample + blockIdx.x] =
            shared_level[0];
    }
}

__global__ void evaluate_reduce_kernel(
    const QM31 *input,
    std::uint32_t input_size,
    std::uint32_t input_stride,
    std::uint32_t factor_index,
    std::uint32_t coefficient_log_size,
    std::uint32_t sample_count,
    const QM31 *folding_factors,
    QM31 *output,
    std::uint32_t output_stride) {
    const std::uint32_t sample = blockIdx.y;
    if (sample >= sample_count || blockIdx.x >= output_stride) return;

    extern __shared__ QM31 shared[];
    const std::uint32_t lane = threadIdx.x;
    const std::uint32_t base = blockIdx.x * kReduceCoefficientsPerBlock;
    const std::uint32_t left = base + lane;
    const std::uint32_t right = left + kBlockSize;
    const QM31 *row =
        input + static_cast<std::size_t>(sample) * input_stride;
    shared[lane] = left < input_size ? row[left] : zero();
    shared[lane + kBlockSize] =
        right < input_size ? row[right] : zero();
    __syncthreads();

    std::uint32_t level_size =
        (input_size < kReduceCoefficientsPerBlock
             ? input_size
             : kReduceCoefficientsPerBlock) >>
        1;
    int current_factor = static_cast<int>(factor_index);
    const QM31 *factors =
        folding_factors + static_cast<std::size_t>(sample) * coefficient_log_size;
    while (level_size != 0) {
        QM31 left_value = zero();
        QM31 right_value = zero();
        if (lane < level_size) {
            left_value = shared[2 * lane];
            right_value = shared[2 * lane + 1];
        }
        __syncthreads();
        if (lane < level_size) {
            shared[lane] =
                add(left_value, mul(right_value, factors[current_factor]));
        }
        --current_factor;
        level_size >>= 1;
        __syncthreads();
    }
    if (lane == 0) {
        output[
            static_cast<std::size_t>(sample) * output_stride + blockIdx.x] =
            shared[0];
    }
}

__global__ void store_results_kernel(
    const QM31 *reduced,
    std::uint32_t reduced_stride,
    const std::uint32_t *output_indices,
    std::uint32_t sample_count,
    std::size_t sampled_value_capacity,
    QM31 *sampled_values) {
    const std::uint32_t sample = blockIdx.x * blockDim.x + threadIdx.x;
    if (sample < sample_count &&
        static_cast<std::size_t>(output_indices[sample]) <
            sampled_value_capacity) {
        sampled_values[output_indices[sample]] =
            reduced[static_cast<std::size_t>(sample) * reduced_stride];
    }
}

__host__ constexpr std::uint32_t log2_exact(std::uint32_t value) {
    std::uint32_t result = 0;
    while (value > 1) {
        value >>= 1;
        ++result;
    }
    return result;
}

inline bool overlaps_output(
    ByteRange read,
    ByteRange first,
    ByteRange second,
    ByteRange third) {
    return ranges_overlap(read, first) ||
           ranges_overlap(read, second) ||
           ranges_overlap(read, third);
}

}  // namespace stwo::cuda::oods

extern "C" int stwo_oods_derive_points_on(
    const stwo::cuda::oods::QM31 *oods_parameter,
    const stwo::cuda::oods::CirclePoint *offset_points,
    const std::uint32_t *fold_counts,
    const std::uint32_t *output_indices,
    std::uint32_t sample_count,
    std::uint32_t coefficient_log_size,
    stwo::cuda::oods::SecureCirclePoint *sample_points,
    std::size_t sample_point_capacity,
    stwo::cuda::oods::SecureCirclePoint *evaluation_points,
    stwo::cuda::oods::QM31 *folding_factors,
    void *stream) {
    using namespace stwo::cuda::oods;
    if (oods_parameter == nullptr || offset_points == nullptr ||
        fold_counts == nullptr || output_indices == nullptr ||
        sample_count == 0 || coefficient_log_size == 0 ||
        coefficient_log_size > 31 || sample_points == nullptr ||
        sample_point_capacity == 0 ||
        evaluation_points == nullptr || folding_factors == nullptr ||
        stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    std::size_t factor_count;
    ByteRange parameter_range;
    ByteRange offset_range;
    ByteRange fold_range;
    ByteRange index_range;
    ByteRange sample_range;
    ByteRange evaluation_range;
    ByteRange factor_range;
    if (!checked_product(
            sample_count,
            coefficient_log_size,
            &factor_count) ||
        !element_range(oods_parameter, 1, &parameter_range) ||
        !element_range(offset_points, sample_count, &offset_range) ||
        !element_range(fold_counts, sample_count, &fold_range) ||
        !element_range(output_indices, sample_count, &index_range) ||
        !element_range(sample_points, sample_point_capacity, &sample_range) ||
        !element_range(evaluation_points, sample_count, &evaluation_range) ||
        !element_range(folding_factors, factor_count, &factor_range) ||
        ranges_overlap(sample_range, evaluation_range) ||
        ranges_overlap(sample_range, factor_range) ||
        ranges_overlap(evaluation_range, factor_range) ||
        overlaps_output(
            parameter_range, sample_range, evaluation_range, factor_range) ||
        overlaps_output(
            offset_range, sample_range, evaluation_range, factor_range) ||
        overlaps_output(
            fold_range, sample_range, evaluation_range, factor_range) ||
        overlaps_output(
            index_range, sample_range, evaluation_range, factor_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const std::uint32_t blocks =
        1u + (sample_count - 1u) / kBlockSize;
    derive_points_kernel<<<
        blocks, kBlockSize, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        oods_parameter,
        offset_points,
        fold_counts,
        output_indices,
        sample_count,
        coefficient_log_size,
        sample_point_capacity,
        sample_points,
        evaluation_points,
        folding_factors);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_oods_eval_first_on(
    const stwo::cuda::oods::M31 *coefficients,
    std::size_t column_stride_words,
    std::uint32_t coefficient_size,
    std::uint32_t sample_count,
    const stwo::cuda::oods::QM31 *folding_factors,
    stwo::cuda::oods::QM31 *scratch,
    void *stream) {
    using namespace stwo::cuda::oods;
    if (coefficients == nullptr ||
        column_stride_words < coefficient_size || coefficient_size < 2 ||
        !is_power_of_two(coefficient_size) || sample_count == 0 ||
        sample_count > 65535 || folding_factors == nullptr ||
        scratch == nullptr || stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const std::uint32_t coefficient_log_size = log2_exact(coefficient_size);
    const std::uint32_t blocks_per_sample =
        1u + (coefficient_size - 1u) / kFirstCoefficientsPerBlock;
    std::size_t coefficient_count;
    std::size_t factor_count;
    std::size_t scratch_count;
    ByteRange coefficient_range;
    ByteRange factor_range;
    ByteRange scratch_range;
    if (!matrix_elements(
            sample_count,
            column_stride_words,
            coefficient_size,
            &coefficient_count) ||
        !checked_product(
            sample_count,
            coefficient_log_size,
            &factor_count) ||
        !checked_product(sample_count, blocks_per_sample, &scratch_count) ||
        !element_range(coefficients, coefficient_count, &coefficient_range) ||
        !element_range(folding_factors, factor_count, &factor_range) ||
        !element_range(scratch, scratch_count, &scratch_range) ||
        ranges_overlap(scratch_range, coefficient_range) ||
        ranges_overlap(scratch_range, factor_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const dim3 grid(blocks_per_sample, sample_count);
    const std::size_t shared_bytes = kBlockSize * sizeof(QM31);
    evaluate_first_kernel<<<
        grid,
        kBlockSize,
        shared_bytes,
        reinterpret_cast<cudaStream_t>(stream)>>>(
        coefficients,
        column_stride_words,
        coefficient_size,
        sample_count,
        folding_factors,
        coefficient_log_size,
        blocks_per_sample,
        scratch);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_oods_eval_reduce_on(
    const stwo::cuda::oods::QM31 *input,
    std::uint32_t input_size,
    std::uint32_t input_stride,
    std::uint32_t factor_index,
    std::uint32_t coefficient_log_size,
    std::uint32_t sample_count,
    const stwo::cuda::oods::QM31 *folding_factors,
    stwo::cuda::oods::QM31 *output,
    std::uint32_t output_stride,
    void *stream) {
    using namespace stwo::cuda::oods;
    const std::uint32_t required_output_stride =
        input_size == 0
            ? 0
            : 1u + (input_size - 1u) / kReduceCoefficientsPerBlock;
    const std::uint32_t local_size =
        input_size < kReduceCoefficientsPerBlock
            ? input_size
            : kReduceCoefficientsPerBlock;
    const std::uint32_t consumed_factors =
        is_power_of_two(local_size) ? log2_exact(local_size) : 0;
    if (input == nullptr || input_size < 2 || !is_power_of_two(input_size) ||
        input_stride < input_size || coefficient_log_size == 0 ||
        coefficient_log_size > 31 ||
        factor_index >= coefficient_log_size ||
        consumed_factors == 0 ||
        factor_index + 1 != log2_exact(input_size) ||
        sample_count == 0 || sample_count > 65535 ||
        folding_factors == nullptr || output == nullptr ||
        output_stride != required_output_stride || stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    std::size_t input_count;
    std::size_t factor_count;
    std::size_t output_count;
    ByteRange input_range;
    ByteRange factor_range;
    ByteRange output_range;
    if (!matrix_elements(
            sample_count, input_stride, input_size, &input_count) ||
        !checked_product(
            sample_count, coefficient_log_size, &factor_count) ||
        !checked_product(sample_count, output_stride, &output_count) ||
        !element_range(input, input_count, &input_range) ||
        !element_range(folding_factors, factor_count, &factor_range) ||
        !element_range(output, output_count, &output_range) ||
        ranges_overlap(output_range, input_range) ||
        ranges_overlap(output_range, factor_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const dim3 grid(output_stride, sample_count);
    evaluate_reduce_kernel<<<
        grid,
        kBlockSize,
        kReduceCoefficientsPerBlock * sizeof(QM31),
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
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_oods_store_results_on(
    const stwo::cuda::oods::QM31 *reduced,
    std::uint32_t reduced_stride,
    const std::uint32_t *output_indices,
    std::uint32_t sample_count,
    stwo::cuda::oods::QM31 *sampled_values,
    std::size_t sampled_value_capacity,
    void *stream) {
    using namespace stwo::cuda::oods;
    if (reduced == nullptr || reduced_stride == 0 ||
        output_indices == nullptr || sample_count == 0 ||
        sampled_values == nullptr || sampled_value_capacity == 0 ||
        stream == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    std::size_t reduced_count;
    ByteRange reduced_range;
    ByteRange index_range;
    ByteRange sampled_range;
    if (!matrix_elements(
            sample_count, reduced_stride, 1, &reduced_count) ||
        !element_range(reduced, reduced_count, &reduced_range) ||
        !element_range(output_indices, sample_count, &index_range) ||
        !element_range(
            sampled_values, sampled_value_capacity, &sampled_range) ||
        ranges_overlap(sampled_range, reduced_range) ||
        ranges_overlap(sampled_range, index_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    const std::uint32_t blocks =
        1u + (sample_count - 1u) / kBlockSize;
    store_results_kernel<<<
        blocks, kBlockSize, 0, reinterpret_cast<cudaStream_t>(stream)>>>(
        reduced,
        reduced_stride,
        output_indices,
        sample_count,
        sampled_value_capacity,
        sampled_values);
    return static_cast<int>(cudaPeekAtLastError());
}
