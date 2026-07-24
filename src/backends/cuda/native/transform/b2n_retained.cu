#include "../common/circle_twiddle.cuh"
#include "b2n_fused.cuh"
#include "transform_internal.cuh"

// Qualified multi-stage intervals from pinned ifft.cu drive production logs;
// the exact stagewise path remains the fallback. Both use the same resident
// retained-output ABI and admit disjoint slabs or one exact base/stride alias.

namespace {

using stwo::cuda::M31;
using stwo::cuda::circle_twiddle;
using stwo::cuda::m31_add;
using stwo::cuda::m31_inverse_power_of_two;
using stwo::cuda::m31_mul;
using stwo::cuda::m31_sub;

template <bool DuplicateToRetained>
__global__ void b2n_stage(
    const M31 *inputs,
    size_t input_column_stride_words,
    M31 *outputs,
    size_t output_column_stride_words,
    uint32_t log_n,
    uint32_t stage,
    const M31 *layer_twiddles,
    M31 rescale_factor) {
    const uint32_t pair_index =
        blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t column_index = blockIdx.y;
    const uint32_t pair_count = 1u << (log_n - 1u);
    if (pair_index >= pair_count) return;

    const uint32_t stride = 1u << (stage - 1u);
    const uint32_t group_index = pair_index & (stride - 1u);
    const uint32_t butterfly_index = pair_index >> (stage - 1u);
    const uint32_t left_index =
        group_index + butterfly_index * 2u * stride;
    const uint32_t right_index = left_index + stride;
    const M31 *input =
        inputs + static_cast<size_t>(column_index) *
            input_column_stride_words;
    M31 *output =
        outputs + static_cast<size_t>(column_index) *
            output_column_stride_words;

    const M31 left = input[left_index];
    const M31 right = input[right_index];
    const M31 twiddle = stage == 1u
        ? circle_twiddle(layer_twiddles, butterfly_index)
        : layer_twiddles[butterfly_index];
    M31 left_result = m31_add(left, right);
    M31 right_result = m31_mul(m31_sub(left, right), twiddle);
    if (stage == log_n) {
        left_result = m31_mul(left_result, rescale_factor);
        right_result = m31_mul(right_result, rescale_factor);
    }
    output[left_index] = left_result;
    output[right_index] = right_result;
    if constexpr (DuplicateToRetained) {
        const uint32_t retained_offset = 1u << log_n;
        output[left_index + retained_offset] = left_result;
        output[right_index + retained_offset] = right_result;
    }
}

cudaError_t launch_columns(
    const uint32_t *inputs,
    size_t input_column_stride_words,
    uint32_t *retained_outputs,
    size_t output_column_stride_words,
    uint32_t log_n,
    uint32_t polynomial_count,
    const uint32_t *twiddles,
    uint32_t twiddle_words,
    uint32_t evaluation_domain_size,
    cudaStream_t stream,
    uint32_t *launches_out) {
    using namespace stwo::cuda::transform;
    const auto *inverse_twiddles = reinterpret_cast<const M31 *>(
        twiddles + twiddle_words - evaluation_domain_size);
    const uint32_t pair_count = 1u << (log_n - 1u);
    const uint32_t blocks =
        (pair_count + kThreadsPerBlock - 1u) / kThreadsPerBlock;
    const M31 rescale_factor = m31_inverse_power_of_two(log_n);

    for (uint32_t base = 0; base < polynomial_count;
         base += kMaxColumnsPerLaunch) {
        const uint32_t remaining = polynomial_count - base;
        const uint32_t chunk = remaining < kMaxColumnsPerLaunch
            ? remaining
            : kMaxColumnsPerLaunch;
        const auto *chunk_inputs = reinterpret_cast<const M31 *>(inputs) +
            static_cast<size_t>(base) * input_column_stride_words;
        auto *chunk_outputs = reinterpret_cast<M31 *>(retained_outputs) +
            static_cast<size_t>(base) * output_column_stride_words;
        if (log_n >= kFirstFusedLogN && log_n <= kLastFusedLogN) {
            const TransformSchedule &schedule =
                kB2nSchedules[log_n - kFirstFusedLogN];
            const ColumnSlab<const M31> input_slab{
                chunk_inputs,
                input_column_stride_words,
            };
            const ColumnSlab<M31> output_slab{
                chunk_outputs,
                output_column_stride_words,
            };
            cudaError_t status = launch_b2n_init(
                input_slab,
                output_slab,
                log_n,
                chunk,
                schedule.intervals[0],
                inverse_twiddles,
                stream);
            if (status != cudaSuccess) return status;
            ++*launches_out;
            uint32_t start_stage = 1u + schedule.intervals[0];
            for (uint32_t i = 1; i < schedule.interval_count; ++i) {
                const uint32_t stages = schedule.intervals[i];
                status = i + 1u == schedule.interval_count
                    ? launch_b2n_continue<true>(
                          output_slab,
                          log_n,
                          chunk,
                          start_stage,
                          stages,
                          inverse_twiddles,
                          stream)
                    : launch_b2n_continue<false>(
                          output_slab,
                          log_n,
                          chunk,
                          start_stage,
                          stages,
                          inverse_twiddles,
                          stream);
                if (status != cudaSuccess) return status;
                ++*launches_out;
                start_stage += stages;
            }
            continue;
        }

        b2n_stage<false><<<
            dim3(blocks, chunk),
            kThreadsPerBlock,
            0,
            stream>>>(
                chunk_inputs,
                input_column_stride_words,
                chunk_outputs,
                output_column_stride_words,
                log_n,
                1,
                inverse_twiddles,
                rescale_factor);
        cudaError_t status = cudaPeekAtLastError();
        if (status != cudaSuccess) return status;
        ++*launches_out;

        uint32_t layer_size = pair_count;
        uint32_t layer_offset = 0;
        for (uint32_t stage = 2; stage <= log_n; ++stage) {
            const bool final_stage = stage == log_n;
            if (final_stage) {
                b2n_stage<true><<<
                    dim3(blocks, chunk),
                    kThreadsPerBlock,
                    0,
                    stream>>>(
                        chunk_outputs,
                        output_column_stride_words,
                        chunk_outputs,
                        output_column_stride_words,
                        log_n,
                        stage,
                        inverse_twiddles + layer_offset,
                        rescale_factor);
            } else {
                b2n_stage<false><<<
                    dim3(blocks, chunk),
                    kThreadsPerBlock,
                    0,
                    stream>>>(
                        chunk_outputs,
                        output_column_stride_words,
                        chunk_outputs,
                        output_column_stride_words,
                        log_n,
                        stage,
                        inverse_twiddles + layer_offset,
                        rescale_factor);
            }
            status = cudaPeekAtLastError();
            if (status != cudaSuccess) return status;
            ++*launches_out;
            if (!final_stage) {
                layer_size >>= 1;
                layer_offset += layer_size;
            }
        }
    }
    return cudaSuccess;
}

}  // namespace

extern "C" int stwo_ntt_b2n_columns_to_retained_on(
    const uint32_t *inputs,
    size_t input_column_stride_words,
    uint32_t *retained_outputs,
    size_t output_column_stride_words,
    uint32_t log_n,
    uint32_t polynomial_count,
    const uint32_t *twiddles,
    uint32_t twiddle_words,
    uint32_t evaluation_domain_size,
    void *stream_raw,
    uint32_t *launches_out) {
    using namespace stwo::cuda::transform;
    if (launches_out != nullptr) *launches_out = 0;
    if (!valid_shape(
            log_n,
            polynomial_count,
            twiddle_words,
            evaluation_domain_size) ||
        stream_raw == nullptr ||
        launches_out == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    DeviceRange input_range{};
    DeviceRange output_range{};
    DeviceRange twiddle_range{};
    const size_t values = static_cast<size_t>(1) << log_n;
    const bool exact_alias =
        inputs == retained_outputs &&
        input_column_stride_words == output_column_stride_words;
    if (!column_range(
            inputs,
            input_column_stride_words,
            polynomial_count,
            values,
            &input_range) ||
        !column_range(
            retained_outputs,
            output_column_stride_words,
            polynomial_count,
            2u * values,
            &output_range) ||
        !word_range(twiddles, twiddle_words, &twiddle_range) ||
        (!exact_alias && ranges_overlap(input_range, output_range)) ||
        ranges_overlap(output_range, twiddle_range)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    return static_cast<int>(launch_columns(
        inputs,
        input_column_stride_words,
        retained_outputs,
        output_column_stride_words,
        log_n,
        polynomial_count,
        twiddles,
        twiddle_words,
        evaluation_domain_size,
        reinterpret_cast<cudaStream_t>(stream_raw),
        launches_out));
}
