#ifndef STWO_ZIG_CUDA_N2B_FUSED_CUH
#define STWO_ZIG_CUDA_N2B_FUSED_CUH

#include "../common/circle_twiddle.cuh"
#include "transform_internal.cuh"

namespace stwo::cuda::transform {

constexpr uint32_t kN2bLogWarp = 5;

template <uint32_t LogValues>
__device__ __forceinline__ void n2b_shuffle(
    M31 *values,
    uint32_t log_stride,
    uint32_t lane) {
    const uint32_t mask = 1u << log_stride;
    __syncwarp(0xffffffffu);
#pragma unroll
    for (uint32_t i = 0; i < 1u << (LogValues - 1u); ++i) {
        M31 *value = lane & mask ? values + 2u * i : values + 2u * i + 1u;
        *value = __shfl_xor_sync(0xffffffffu, *value, mask);
    }
}

template <
    uint32_t LogValues,
    uint32_t LogWarps = LogValues,
    bool LoadCoefficients = false>
__global__ __launch_bounds__(
    1u << (kN2bLogWarp + LogWarps),
    LogValues == 3 ? 6 : 2)
void n2b_continue(
    ColumnSlab<const M31> inputs,
    const uint32_t *input_log_sizes,
    ColumnSlab<M31> columns,
    uint32_t log_n,
    uint32_t min_stage,
    uint32_t max_stage,
    const M31 *twiddles) {
    const uint32_t min_stride = 1u << (log_n - max_stage);
    const uint32_t middle_stage = min_stage + LogValues;
    constexpr uint32_t stage_count = LogValues + LogWarps;
    const uint32_t column_index = blockIdx.z;
    const uint32_t block_start =
        (blockIdx.x << kN2bLogWarp) +
        (blockIdx.y << (log_n - max_stage + stage_count));
    const uint32_t warp = threadIdx.y;
    const uint32_t lane = threadIdx.x;
    uint32_t offset = warp * min_stride + lane;
    const M31 *input = inputs.column(column_index);
    M31 *column = columns.column(column_index);
    M31 values[1u << LogValues];
    uint32_t input_count = 0;
    if constexpr (LoadCoefficients) {
        const uint32_t input_log_size = input_log_sizes[column_index];
        const uint32_t requested_count = input_log_size < 31u
            ? 1u << input_log_size
            : 0u;
        const uint32_t coefficient_domain_size = 1u << (log_n - 1u);
        input_count = requested_count < coefficient_domain_size
            ? requested_count
            : coefficient_domain_size;
    }

#pragma unroll
    for (uint32_t i = 0; i < 1u << LogValues; ++i) {
        const uint32_t input_index =
            block_start + i * (min_stride << LogWarps) + offset;
        if constexpr (LoadCoefficients) {
            values[i] = input_index < input_count ? input[input_index] : 0u;
        } else {
            values[i] = input[input_index];
        }
    }

    uint32_t layer_size = 1;
    uint32_t layer_offset = (1u << (log_n - 1u)) - 2u;
    for (uint32_t stage = 1; stage < min_stage; ++stage) {
        layer_size <<= 1;
        layer_offset -= layer_size;
    }
#pragma unroll
    for (uint32_t stage = min_stage; stage < middle_stage; ++stage) {
        const uint32_t log_stride =
            LogValues - 1u - (stage - min_stage);
#pragma unroll
        for (uint32_t pair = 0; pair < 1u << (LogValues - 1u); ++pair) {
            const uint32_t group = pair & ((1u << log_stride) - 1u);
            const uint32_t inner_pair = pair >> log_stride;
            const uint32_t left = group + (inner_pair << (log_stride + 1u));
            const uint32_t right = left + (1u << log_stride);
            const uint32_t outer_pair =
                (block_start + offset) >> (1u + log_n - stage);
            const M31 product = m31_mul(
                twiddles[layer_offset + inner_pair + outer_pair],
                values[right]);
            const M31 left_value = values[left];
            values[left] = m31_add(left_value, product);
            values[right] = m31_sub(left_value, product);
        }
        layer_size <<= 1;
        layer_offset -= layer_size;
    }

    __shared__ M31 shared[
        32u << (LogValues + LogWarps)];
#pragma unroll
    for (uint32_t i = 0; i < 1u << LogValues; ++i) {
        shared[
            lane + (i << (kN2bLogWarp + LogWarps)) +
            (warp << kN2bLogWarp)] = values[i];
    }
    __syncthreads();
    offset = warp * (min_stride << LogValues) + lane;
#pragma unroll
    for (uint32_t i = 0; i < 1u << LogValues; ++i) {
        values[i] = shared[
            lane + (i << kN2bLogWarp) +
            (warp << (kN2bLogWarp + LogValues))];
    }

#pragma unroll
    for (uint32_t stage = middle_stage; stage <= max_stage; ++stage) {
        const uint32_t log_stride =
            LogWarps - 1u - (stage - middle_stage);
#pragma unroll
        for (uint32_t pair = 0; pair < 1u << (LogValues - 1u); ++pair) {
            const uint32_t group = pair & ((1u << log_stride) - 1u);
            const uint32_t inner_pair = pair >> log_stride;
            const uint32_t left = group + (inner_pair << (log_stride + 1u));
            const uint32_t right = left + (1u << log_stride);
            const uint32_t outer_pair =
                (block_start + offset) >> (1u + log_n - stage);
            const M31 product = m31_mul(
                twiddles[layer_offset + inner_pair + outer_pair],
                values[right]);
            const M31 left_value = values[left];
            values[left] = m31_add(left_value, product);
            values[right] = m31_sub(left_value, product);
        }
        layer_size <<= 1;
        layer_offset -= layer_size;
    }

#pragma unroll
    for (uint32_t i = 0; i < 1u << LogValues; ++i) {
        column[block_start + i * min_stride + offset] = values[i];
    }
}

template <uint32_t LogValues, bool IncludeCircle>
__global__ void n2b_final_warp(
    ColumnSlab<M31> columns,
    uint32_t log_n,
    uint32_t min_stage,
    const M31 *twiddles) {
    const uint32_t column_index = blockIdx.y;
    const uint32_t lane = threadIdx.x;
    const uint32_t warp_index = blockDim.y * blockIdx.x + threadIdx.y;
    constexpr uint32_t log_values_per_warp =
        LogValues + kN2bLogWarp;
    uint32_t warp_start =
        (warp_index << log_values_per_warp) + lane;
    M31 *column = columns.column(column_index);
    M31 values[1u << LogValues];
#pragma unroll
    for (uint32_t i = 0; i < 1u << LogValues; ++i) {
        values[i] = column[warp_start + (i << kN2bLogWarp)];
    }

    uint32_t layer_size = 1;
    uint32_t layer_offset = (1u << (log_n - 1u)) - 2u;
    for (uint32_t stage = 1; stage < min_stage; ++stage) {
        layer_size <<= 1;
        layer_offset -= layer_size;
    }
    uint32_t stage = min_stage;
#pragma unroll
    for (; stage < min_stage + LogValues; ++stage) {
        const uint32_t log_stride =
            LogValues - 1u - (stage - min_stage);
#pragma unroll
        for (uint32_t pair = 0; pair < 1u << (LogValues - 1u); ++pair) {
            const uint32_t group = pair & ((1u << log_stride) - 1u);
            const uint32_t inner_pair = pair >> log_stride;
            const uint32_t left = group + (inner_pair << (log_stride + 1u));
            const uint32_t right = left + (1u << log_stride);
            const uint32_t outer_pair =
                warp_start >> (1u + log_n - stage);
            const M31 product = m31_mul(
                twiddles[layer_offset + inner_pair + outer_pair],
                values[right]);
            const M31 left_value = values[left];
            values[left] = m31_add(left_value, product);
            values[right] = m31_sub(left_value, product);
        }
        layer_size <<= 1;
        layer_offset -= layer_size;
    }

#pragma unroll
    for (; stage <= log_n; ++stage) {
        const uint32_t log_stride = log_n - stage;
        n2b_shuffle<LogValues>(values, log_stride, lane);
        if constexpr (!IncludeCircle) {
            if (stage == log_n) continue;
        }
#pragma unroll
        for (uint32_t i = 0; i < 1u << (LogValues - 1u); ++i) {
            const uint32_t inner_pair =
                (lane >> log_stride) +
                (i << (kN2bLogWarp - log_stride));
            const uint32_t outer_pair =
                warp_index << (log_values_per_warp - 1u - log_stride);
            const M31 right = values[2u * i + 1u];
            const M31 product = stage == log_n
                ? m31_mul(
                      circle_twiddle(twiddles, inner_pair + outer_pair),
                      right)
                : m31_mul(
                      twiddles[layer_offset + inner_pair + outer_pair],
                      right);
            const M31 left = values[2u * i];
            values[2u * i] = m31_add(left, product);
            values[2u * i + 1u] = m31_sub(left, product);
        }
        layer_size <<= 1;
        layer_offset -= layer_size;
    }

    warp_start = (warp_index << log_values_per_warp) + 2u * lane;
#pragma unroll
    for (uint32_t i = 0; i < 1u << (LogValues - 1u); ++i) {
        const uint32_t output = warp_start + (i << 6u);
        column[output] = values[2u * i];
        column[output + 1u] = values[2u * i + 1u];
    }
}

template <uint32_t LogWarps, bool IncludeCircle>
__global__ void n2b_final_block(
    ColumnSlab<M31> columns,
    uint32_t log_n,
    uint32_t min_stage,
    const M31 *twiddles) {
    constexpr uint32_t log_values = 3;
    constexpr uint32_t log_values_per_warp =
        log_values + kN2bLogWarp;
    const uint32_t column_index = blockIdx.z;
    const uint32_t warp = threadIdx.y;
    const uint32_t lane = threadIdx.x;
    const uint32_t block_start =
        blockIdx.x << (log_values_per_warp + LogWarps);
    M31 *column = columns.column(column_index);
    M31 values[1u << log_values];
    uint32_t offset = (warp << kN2bLogWarp) + lane;
#pragma unroll
    for (uint32_t i = 0; i < 1u << log_values; ++i) {
        values[i] = column[
            block_start + (i << (kN2bLogWarp + LogWarps)) + offset];
    }

    uint32_t layer_size = 1;
    uint32_t layer_offset = (1u << (log_n - 1u)) - 2u;
    for (uint32_t stage = 1; stage < min_stage; ++stage) {
        layer_size <<= 1;
        layer_offset -= layer_size;
    }
    uint32_t stage = min_stage;
#pragma unroll
    for (; stage < min_stage + LogWarps; ++stage) {
        const uint32_t log_stride =
            log_values - 1u - (stage - min_stage);
#pragma unroll
        for (uint32_t pair = 0; pair < 1u << (log_values - 1u); ++pair) {
            const uint32_t group = pair & ((1u << log_stride) - 1u);
            const uint32_t inner_pair = pair >> log_stride;
            const uint32_t left = group + (inner_pair << (log_stride + 1u));
            const uint32_t right = left + (1u << log_stride);
            const uint32_t outer_pair =
                (block_start + offset) >> (1u + log_n - stage);
            const M31 product = m31_mul(
                twiddles[layer_offset + inner_pair + outer_pair],
                values[right]);
            const M31 left_value = values[left];
            values[left] = m31_add(left_value, product);
            values[right] = m31_sub(left_value, product);
        }
        layer_size <<= 1;
        layer_offset -= layer_size;
    }

    __shared__ M31 shared[
        32u << (LogWarps + log_values)];
#pragma unroll
    for (uint32_t i = 0; i < 1u << log_values; ++i) {
        shared[
            lane + (i << (kN2bLogWarp + LogWarps)) +
            (warp << kN2bLogWarp)] = values[i];
    }
    __syncthreads();
#pragma unroll
    for (uint32_t i = 0; i < 1u << log_values; ++i) {
        values[i] = shared[
            lane + (i << kN2bLogWarp) +
            (warp << (kN2bLogWarp + log_values))];
    }
    offset = (warp << (kN2bLogWarp + log_values)) + lane;

    const uint32_t warp_index = blockDim.y * blockIdx.x + warp;
    uint32_t warp_start =
        (warp_index << log_values_per_warp) + lane;
    const uint32_t next_stage = min_stage + LogWarps;
#pragma unroll
    for (stage = next_stage;
         stage < next_stage + log_values;
         ++stage) {
        const uint32_t log_stride =
            log_values - 1u - (stage - next_stage);
#pragma unroll
        for (uint32_t pair = 0; pair < 1u << (log_values - 1u); ++pair) {
            const uint32_t group = pair & ((1u << log_stride) - 1u);
            const uint32_t inner_pair = pair >> log_stride;
            const uint32_t left = group + (inner_pair << (log_stride + 1u));
            const uint32_t right = left + (1u << log_stride);
            const uint32_t outer_pair =
                warp_start >> (1u + log_n - stage);
            const M31 product = m31_mul(
                twiddles[layer_offset + inner_pair + outer_pair],
                values[right]);
            const M31 left_value = values[left];
            values[left] = m31_add(left_value, product);
            values[right] = m31_sub(left_value, product);
        }
        layer_size <<= 1;
        layer_offset -= layer_size;
    }

#pragma unroll
    for (; stage <= log_n; ++stage) {
        const uint32_t log_stride = log_n - stage;
        n2b_shuffle<log_values>(values, log_stride, lane);
        if constexpr (!IncludeCircle) {
            if (stage == log_n) continue;
        }
#pragma unroll
        for (uint32_t i = 0; i < 1u << (log_values - 1u); ++i) {
            const uint32_t inner_pair =
                (lane >> log_stride) +
                (i << (kN2bLogWarp - log_stride));
            const uint32_t outer_pair =
                warp_index << (log_values_per_warp - 1u - log_stride);
            const M31 right = values[2u * i + 1u];
            const M31 product = stage == log_n
                ? m31_mul(
                      circle_twiddle(twiddles, inner_pair + outer_pair),
                      right)
                : m31_mul(
                      twiddles[layer_offset + inner_pair + outer_pair],
                      right);
            const M31 left = values[2u * i];
            values[2u * i] = m31_add(left, product);
            values[2u * i + 1u] = m31_sub(left, product);
        }
        layer_size <<= 1;
        layer_offset -= layer_size;
    }

    warp_start = (warp_index << log_values_per_warp) + 2u * lane;
#pragma unroll
    for (uint32_t i = 0; i < 1u << (log_values - 1u); ++i) {
        const uint32_t output = warp_start + (i << 6u);
        column[output] = values[2u * i];
        column[output + 1u] = values[2u * i + 1u];
    }
}

inline cudaError_t launch_n2b_continue(
    ColumnSlab<M31> columns,
    uint32_t log_n,
    uint32_t column_count,
    uint32_t start_stage,
    uint32_t stages,
    const M31 *twiddles,
    cudaStream_t stream) {
    if (column_count == 0 || start_stage == 0 ||
        start_stage + stages - 1u >= log_n) {
        return cudaErrorInvalidConfiguration;
    }
    const uint32_t end_stage = start_stage + stages - 1u;
    const uint32_t min_stride = 1u << (log_n - end_stage);
    if (min_stride < 32u) return cudaErrorInvalidConfiguration;
    if (stages == 6) {
        const dim3 block{32, 8};
        const dim3 grid{
            min_stride / 32u,
            (1u << log_n) / (min_stride << 6u),
            column_count,
        };
        n2b_continue<3><<<grid, block, 0, stream>>>(
            {columns.base, columns.stride_words},
            nullptr,
            columns,
            log_n,
            start_stage,
            end_stage,
            twiddles);
    } else if (stages == 8) {
        const dim3 block{32, 16};
        const dim3 grid{
            min_stride / 32u,
            (1u << log_n) / (min_stride << 8u),
            column_count,
        };
        n2b_continue<4><<<grid, block, 0, stream>>>(
            {columns.base, columns.stride_words},
            nullptr,
            columns,
            log_n,
            start_stage,
            end_stage,
            twiddles);
    } else {
        return cudaErrorInvalidConfiguration;
    }
    return cudaPeekAtLastError();
}

inline cudaError_t launch_n2b_first_from_coefficients(
    ColumnSlab<const M31> coefficients,
    const uint32_t *coefficient_log_sizes,
    ColumnSlab<M31> evaluations,
    uint32_t log_n,
    uint32_t column_count,
    uint32_t stages,
    const M31 *twiddles,
    cudaStream_t stream) {
    if (column_count == 0 || coefficient_log_sizes == nullptr ||
        stages >= log_n) {
        return cudaErrorInvalidConfiguration;
    }
    const uint32_t min_stride = 1u << (log_n - stages);
    if (min_stride < 32u) return cudaErrorInvalidConfiguration;
    if (stages == 6) {
        const dim3 block{32, 8};
        const dim3 grid{
            min_stride / 32u,
            (1u << log_n) / (min_stride << 6u),
            column_count,
        };
        n2b_continue<3, 3, true><<<grid, block, 0, stream>>>(
            coefficients,
            coefficient_log_sizes,
            evaluations,
            log_n,
            1u,
            stages,
            twiddles);
    } else if (stages == 8) {
        const dim3 block{32, 16};
        const dim3 grid{
            min_stride / 32u,
            (1u << log_n) / (min_stride << 8u),
            column_count,
        };
        n2b_continue<4, 4, true><<<grid, block, 0, stream>>>(
            coefficients,
            coefficient_log_sizes,
            evaluations,
            log_n,
            1u,
            stages,
            twiddles);
    } else {
        return cudaErrorInvalidConfiguration;
    }
    return cudaPeekAtLastError();
}

template <bool IncludeCircle>
inline cudaError_t launch_n2b_final(
    ColumnSlab<M31> columns,
    uint32_t log_n,
    uint32_t column_count,
    uint32_t start_stage,
    uint32_t stages,
    const M31 *twiddles,
    cudaStream_t stream) {
    if (column_count == 0 || start_stage == 0 ||
        start_stage + stages - 1u != log_n) {
        return cudaErrorInvalidConfiguration;
    }
    if (stages == 7 || stages == 8) {
        const uint32_t log_values = stages - kN2bLogWarp;
        const uint32_t warps =
            1u << (log_n - kN2bLogWarp - log_values);
        const uint32_t block_warps = warps < 4u ? warps : 4u;
        const dim3 grid{warps / block_warps, column_count};
        const dim3 block{32, block_warps};
        if (stages == 7) {
            n2b_final_warp<2, IncludeCircle><<<
                grid, block, 0, stream>>>(
                    columns, log_n, start_stage, twiddles);
        } else {
            n2b_final_warp<3, IncludeCircle><<<
                grid, block, 0, stream>>>(
                    columns, log_n, start_stage, twiddles);
        }
    } else if (stages == 10) {
        n2b_final_block<2, IncludeCircle><<<
            dim3(1u << (log_n - 10u), 1, column_count),
            dim3(32, 4),
            0,
            stream>>>(columns, log_n, start_stage, twiddles);
    } else if (stages == 11) {
        n2b_final_block<3, IncludeCircle><<<
            dim3(1u << (log_n - 11u), 1, column_count),
            dim3(32, 8),
            0,
            stream>>>(columns, log_n, start_stage, twiddles);
    } else {
        return cudaErrorInvalidConfiguration;
    }
    return cudaPeekAtLastError();
}

}  // namespace stwo::cuda::transform

#endif
