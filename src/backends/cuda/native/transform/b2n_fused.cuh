#ifndef STWO_ZIG_CUDA_B2N_FUSED_CUH
#define STWO_ZIG_CUDA_B2N_FUSED_CUH

#include "../common/circle_twiddle.cuh"
#include "../common/provider_compat.cuh"
#include "transform_internal.cuh"

namespace stwo::cuda::transform {

constexpr uint32_t kLogWarp = 5;

template <uint32_t LogValues>
__device__ __forceinline__ void b2n_shuffle(
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

template <uint32_t LogValues>
__global__ void b2n_init_warp(
    ColumnSlab<const M31> inputs,
    ColumnSlab<M31> outputs,
    uint32_t log_n,
    uint32_t max_stage,
    const M31 *twiddles) {
    const uint32_t column_index = blockIdx.y;
    const uint32_t lane = threadIdx.x;
    const uint32_t warp_index = blockDim.y * blockIdx.x + threadIdx.y;
    constexpr uint32_t log_values_per_warp = LogValues + kLogWarp;
    const uint32_t warp_start = warp_index << log_values_per_warp;
    const M31 *input = inputs.column(column_index);
    M31 values[1u << LogValues];

#pragma unroll
    for (uint32_t i = 0; i < 1u << LogValues; ++i) {
        values[i] = input[warp_start + (lane << LogValues) + i];
    }

    uint32_t layer_size = 1u << (log_n - 1u);
    uint32_t layer_offset = 0;
    uint32_t stage = 1;
#pragma unroll
    for (; stage < 1u + LogValues; ++stage) {
        const uint32_t log_stride = stage - 1u;
#pragma unroll
        for (uint32_t pair = 0; pair < 1u << (LogValues - 1u); ++pair) {
            const uint32_t group = pair & ((1u << log_stride) - 1u);
            const uint32_t inner_pair = pair >> log_stride;
            const uint32_t left = group + (inner_pair << (log_stride + 1u));
            const uint32_t right = left + (1u << log_stride);
            const uint32_t outer_pair =
                (warp_start + (lane << LogValues)) >> (log_stride + 1u);
            const M31 twiddle = stage == 1
                ? circle_twiddle(twiddles, inner_pair + outer_pair)
                : twiddles[layer_offset + inner_pair + outer_pair];
            const M31 left_value = values[left];
            values[left] = m31_add(left_value, values[right]);
            values[right] =
                m31_mul(m31_sub(left_value, values[right]), twiddle);
        }
        if (stage >= 2) {
            layer_size >>= 1;
            layer_offset += layer_size;
        }
    }

#pragma unroll
    for (; stage <= max_stage; ++stage) {
        const uint32_t log_stride = stage - LogValues - 1u;
        b2n_shuffle<LogValues>(values, log_stride, lane);
#pragma unroll
        for (uint32_t i = 0; i < 1u << (LogValues - 1u); ++i) {
            const uint32_t outer_pair =
                (warp_start + (lane << LogValues)) >> stage;
            const M31 twiddle = twiddles[layer_offset + outer_pair];
            const M31 left = values[2u * i];
            values[2u * i] = m31_add(left, values[2u * i + 1u]);
            values[2u * i + 1u] =
                m31_mul(m31_sub(left, values[2u * i + 1u]), twiddle);
        }
        layer_size >>= 1;
        layer_offset += layer_size;
    }

    b2n_shuffle<LogValues>(values, 0, lane);
    M31 *output = outputs.column(column_index);
    const uint32_t lane_base =
        (lane >> 1u) << LogValues;
    const uint32_t lane_side = (lane & 1u)
        ? 1u << (log_values_per_warp - 1u)
        : 0;
#pragma unroll
    for (uint32_t i = 0; i < 1u << LogValues; ++i) {
        output[warp_start + lane_base + lane_side + i] = values[i];
    }
}

template <uint32_t LogWarps>
__global__ void b2n_init_block(
    ColumnSlab<const M31> inputs,
    ColumnSlab<M31> outputs,
    uint32_t log_n,
    uint32_t max_stage_exclusive,
    const M31 *twiddles) {
    constexpr uint32_t log_values = 3;
    constexpr uint32_t log_values_per_warp = log_values + kLogWarp;
    constexpr uint32_t log_values_per_block =
        log_values_per_warp + LogWarps;
    const uint32_t column_index = blockIdx.z;
    const uint32_t warp = threadIdx.y;
    const uint32_t lane = threadIdx.x;
    const uint32_t block_start = blockIdx.x << log_values_per_block;
    const uint32_t warp_index = blockDim.y * blockIdx.x + warp;
    const uint32_t warp_start = warp_index << log_values_per_warp;
    const M31 *input = inputs.column(column_index);
    M31 values[1u << log_values];

#pragma unroll
    for (uint32_t i = 0; i < 1u << log_values; ++i) {
        values[i] = input[warp_start + (lane << log_values) + i];
    }

    uint32_t layer_size = 1u << (log_n - 1u);
    uint32_t layer_offset = 0;
    uint32_t stage = 1;
#pragma unroll
    for (; stage < 1u + log_values; ++stage) {
        const uint32_t log_stride = stage - 1u;
#pragma unroll
        for (uint32_t pair = 0; pair < 1u << (log_values - 1u); ++pair) {
            const uint32_t group = pair & ((1u << log_stride) - 1u);
            const uint32_t inner_pair = pair >> log_stride;
            const uint32_t left = group + (inner_pair << (log_stride + 1u));
            const uint32_t right = left + (1u << log_stride);
            const uint32_t outer_pair =
                (warp_start + (lane << log_values)) >> (log_stride + 1u);
            const M31 twiddle = stage == 1
                ? circle_twiddle(twiddles, inner_pair + outer_pair)
                : twiddles[layer_offset + inner_pair + outer_pair];
            const M31 left_value = values[left];
            values[left] = m31_add(left_value, values[right]);
            values[right] =
                m31_mul(m31_sub(left_value, values[right]), twiddle);
        }
        if (stage >= 2) {
            layer_size >>= 1;
            layer_offset += layer_size;
        }
    }

#pragma unroll
    for (; stage < 1u + log_values + kLogWarp; ++stage) {
        const uint32_t log_stride = stage - log_values - 1u;
        b2n_shuffle<log_values>(values, log_stride, lane);
#pragma unroll
        for (uint32_t i = 0; i < 1u << (log_values - 1u); ++i) {
            const uint32_t outer_pair =
                (warp_start + (lane << log_values)) >> stage;
            const M31 twiddle = twiddles[layer_offset + outer_pair];
            const M31 left = values[2u * i];
            values[2u * i] = m31_add(left, values[2u * i + 1u]);
            values[2u * i + 1u] =
                m31_mul(m31_sub(left, values[2u * i + 1u]), twiddle);
        }
        layer_size >>= 1;
        layer_offset += layer_size;
    }
    b2n_shuffle<log_values>(values, 0, lane);

    __shared__ M31 shared[1u << log_values_per_block];
    const uint32_t lane_base = (lane >> 1u) << log_values;
    const uint32_t lane_side = (lane & 1u)
        ? 1u << (log_values_per_warp - 1u)
        : 0;
#pragma unroll
    for (uint32_t i = 0; i < 1u << log_values; ++i) {
        shared[warp_start - block_start + lane_base + lane_side + i] =
            values[i];
    }
    __syncthreads();
#pragma unroll
    for (uint32_t i = 0; i < 1u << log_values; ++i) {
        values[i] = shared[
            lane + (i << (kLogWarp + LogWarps)) + (warp << kLogWarp)];
    }

    const uint32_t next_stage = 1u + log_values + kLogWarp;
#pragma unroll
    for (stage = next_stage; stage < max_stage_exclusive; ++stage) {
        const uint32_t log_stride =
            stage - next_stage + log_values - LogWarps;
#pragma unroll
        for (uint32_t pair = 0; pair < 1u << (log_values - 1u); ++pair) {
            const uint32_t group = pair & ((1u << log_stride) - 1u);
            const uint32_t left =
                group + ((pair >> log_stride) << (log_stride + 1u));
            const uint32_t right = left + (1u << log_stride);
            const uint32_t pair_offset =
                blockIdx.x * blockDim.y *
                (1u << (log_values - 1u)) * (1u << kLogWarp);
            const uint32_t pair_index =
                (pair << (kLogWarp + LogWarps)) + lane +
                (warp << kLogWarp) + pair_offset;
            const M31 twiddle =
                twiddles[layer_offset + (pair_index >> (stage - 1u))];
            const M31 left_value = values[left];
            values[left] = m31_add(left_value, values[right]);
            values[right] =
                m31_mul(m31_sub(left_value, values[right]), twiddle);
        }
        layer_size >>= 1;
        layer_offset += layer_size;
    }

    M31 *output = outputs.column(column_index);
    const uint32_t value_stride = 1u << (kLogWarp + LogWarps);
#pragma unroll
    for (uint32_t i = 0; i < 1u << log_values; ++i) {
        output[block_start + lane + (warp << kLogWarp) + i * value_stride] =
            values[i];
    }
}

template <uint32_t LogValues, bool Duplicate, uint32_t CompactDepth>
__global__ void b2n_continue(
    ColumnSlab<M31> columns,
    ColumnSlab<M31> compact_outputs,
    uint32_t compact_column_offset,
    uint32_t log_n,
    uint32_t min_stage,
    uint32_t max_stage,
    const M31 *twiddles,
    M31 scale) {
    static_assert(
        !(Duplicate && CompactDepth != 0u),
        "a B2N continuation cannot duplicate and compact its output");
    static_assert(CompactDepth <= 2u, "unsupported compact split depth");
    constexpr uint32_t stage_count = 2u * LogValues;
    const uint32_t column_index = blockIdx.z;
    const uint32_t block_start =
        (blockIdx.x << kLogWarp) +
        (blockIdx.y << (min_stage + stage_count - 1u));
    const uint32_t warp = threadIdx.y;
    const uint32_t lane = threadIdx.x;
    const uint32_t min_stride = 1u << (min_stage - 1u);
    const uint32_t offset =
        warp * (min_stride << LogValues) + lane;
    M31 *column = columns.column(column_index);
    M31 values[1u << LogValues];

#pragma unroll
    for (uint32_t i = 0; i < 1u << LogValues; ++i) {
        values[i] = column[block_start + i * min_stride + offset];
    }

    uint32_t layer_size = 1u << (log_n - 1u);
    uint32_t layer_offset = 0;
    for (uint32_t stage = 2; stage < min_stage; ++stage) {
        layer_size >>= 1;
        layer_offset += layer_size;
    }
    uint32_t stage = min_stage;
#pragma unroll
    for (; stage < min_stage + LogValues; ++stage) {
        const uint32_t log_stride = stage - min_stage;
#pragma unroll
        for (uint32_t pair = 0; pair < 1u << (LogValues - 1u); ++pair) {
            const uint32_t group = pair & ((1u << log_stride) - 1u);
            const uint32_t inner_pair = pair >> log_stride;
            const uint32_t left = group + (inner_pair << (log_stride + 1u));
            const uint32_t right = left + (1u << log_stride);
            const uint32_t outer_pair = (block_start + offset) >> stage;
            const M31 twiddle =
                twiddles[layer_offset + inner_pair + outer_pair];
            const M31 left_value = values[left];
            values[left] = m31_add(left_value, values[right]);
            values[right] =
                m31_mul(m31_sub(left_value, values[right]), twiddle);
        }
        layer_size >>= 1;
        layer_offset += layer_size;
    }

    __shared__ M31 shared[
        (32u << (2u * LogValues)) + 32u];
#pragma unroll
    for (uint32_t i = 0; i < 1u << LogValues; ++i) {
        shared[(i * min_stride + warp * (min_stride << LogValues)) /
                   gridDim.x +
               lane] = values[i];
    }
    __syncthreads();
    const uint32_t next_stage = min_stage + LogValues;
    const uint32_t next_stride = 1u << (next_stage - 1u);
    const uint32_t next_offset =
        (warp * (min_stride << LogValues) >> LogValues) + lane;
#pragma unroll
    for (uint32_t i = 0; i < 1u << LogValues; ++i) {
        values[i] = shared[
            (i * next_stride +
             (warp * (min_stride << LogValues) >> LogValues)) /
                gridDim.x +
            lane];
    }

#pragma unroll
    for (stage = next_stage; stage <= max_stage; ++stage) {
        const uint32_t log_stride = stage - next_stage;
#pragma unroll
        for (uint32_t pair = 0; pair < 1u << (LogValues - 1u); ++pair) {
            const uint32_t group = pair & ((1u << log_stride) - 1u);
            const uint32_t inner_pair = pair >> log_stride;
            const uint32_t left = group + (inner_pair << (log_stride + 1u));
            const uint32_t right = left + (1u << log_stride);
            const uint32_t outer_pair =
                (block_start + next_offset) >> stage;
            const M31 twiddle =
                twiddles[layer_offset + inner_pair + outer_pair];
            const M31 left_value = values[left];
            values[left] = m31_add(left_value, values[right]);
            values[right] =
                m31_mul(m31_sub(left_value, values[right]), twiddle);
            if (stage == log_n) {
                values[left] = m31_mul(values[left], scale);
                values[right] = m31_mul(values[right], scale);
            }
        }
        layer_size >>= 1;
        layer_offset += layer_size;
    }

#pragma unroll
    for (uint32_t i = 0; i < 1u << LogValues; ++i) {
        const uint32_t output_index =
            block_start + i * next_stride + next_offset;
        if constexpr (CompactDepth != 0u) {
            // Chunk-major, coordinate-minor is the canonical Stwo
            // split-polynomial order. Depth two therefore writes
            // [LL c0..c3, LR c0..c3, RL c0..c3, RR c0..c3] directly.
            const uint32_t chunk_values = 1u << (log_n - CompactDepth);
            const uint32_t chunk = output_index >> (log_n - CompactDepth);
            compact_outputs
                .column(column_index + chunk * compact_column_offset)
                [output_index & (chunk_values - 1u)] = values[i];
        } else {
            column[output_index] = values[i];
            if constexpr (Duplicate) {
                column[output_index + (1u << log_n)] = values[i];
            }
        }
    }
}

inline cudaError_t launch_b2n_init(
    ColumnSlab<const M31> inputs,
    ColumnSlab<M31> outputs,
    uint32_t log_n,
    uint32_t columns,
    uint32_t stages,
    const M31 *twiddles,
    cudaStream_t stream) {
    if (log_n < stages || columns == 0)
        return STWO_CUDA_ERROR_INVALID_CONFIGURATION;
    switch (stages) {
        case 7: {
            const uint32_t warps = 1u << (log_n - 7u);
            const uint32_t block_warps = warps < 4u ? warps : 4u;
            b2n_init_warp<2><<<
                dim3(warps / block_warps, columns),
                dim3(32, block_warps),
                0,
                stream>>>(inputs, outputs, log_n, stages, twiddles);
            break;
        }
        case 8: {
            const uint32_t warps = 1u << (log_n - 8u);
            const uint32_t block_warps = warps < 4u ? warps : 4u;
            b2n_init_warp<3><<<
                dim3(warps / block_warps, columns),
                dim3(32, block_warps),
                0,
                stream>>>(inputs, outputs, log_n, stages, twiddles);
            break;
        }
        case 9:
            b2n_init_block<1><<<
                dim3(1u << (log_n - 9u), 1, columns),
                dim3(32, 2),
                0,
                stream>>>(inputs, outputs, log_n, 1u + stages, twiddles);
            break;
        case 10:
            b2n_init_block<2><<<
                dim3(1u << (log_n - 10u), 1, columns),
                dim3(32, 4),
                0,
                stream>>>(inputs, outputs, log_n, 1u + stages, twiddles);
            break;
        default:
            return STWO_CUDA_ERROR_INVALID_CONFIGURATION;
    }
    return cudaPeekAtLastError();
}

template <bool Duplicate>
inline cudaError_t launch_b2n_continue(
    ColumnSlab<M31> columns,
    uint32_t log_n,
    uint32_t column_count,
    uint32_t start_stage,
    uint32_t stages,
    const M31 *twiddles,
    cudaStream_t stream) {
    if (column_count == 0 || start_stage == 0 ||
        start_stage + stages - 1u > log_n ||
        (Duplicate && start_stage + stages - 1u != log_n)) {
        return STWO_CUDA_ERROR_INVALID_CONFIGURATION;
    }
    const uint32_t min_stride = 1u << (start_stage - 1u);
    if (min_stride < 32u) return STWO_CUDA_ERROR_INVALID_CONFIGURATION;
    const uint32_t end_stage = start_stage + stages - 1u;
    const dim3 grid{
        min_stride / 32u,
        (1u << log_n) / (1u << end_stage),
        column_count,
    };
    const M31 scale = m31_inverse_power_of_two(log_n);
    if (stages == 6) {
        b2n_continue<3, Duplicate, 0u><<<
            grid,
            dim3(32, 8),
            0,
            stream>>>(
                columns,
                ColumnSlab<M31>{nullptr, 0},
                0,
                log_n,
                start_stage,
                end_stage,
                twiddles,
                scale);
    } else if (stages == 8) {
        b2n_continue<4, Duplicate, 0u><<<
            grid,
            dim3(32, 16),
            0,
            stream>>>(
                columns,
                ColumnSlab<M31>{nullptr, 0},
                0,
                log_n,
                start_stage,
                end_stage,
                twiddles,
                scale);
    } else {
        return STWO_CUDA_ERROR_INVALID_CONFIGURATION;
    }
    return cudaPeekAtLastError();
}

template <uint32_t CompactDepth>
inline cudaError_t launch_b2n_continue_compact(
    ColumnSlab<M31> columns,
    ColumnSlab<M31> compact_outputs,
    uint32_t log_n,
    uint32_t column_count,
    uint32_t start_stage,
    uint32_t stages,
    const M31 *twiddles,
    cudaStream_t stream) {
    static_assert(
        CompactDepth == 1u || CompactDepth == 2u,
        "compact B2N supports depth one or two");
    if (columns.base == nullptr || compact_outputs.base == nullptr ||
        log_n < CompactDepth ||
        compact_outputs.stride_words != (1u << (log_n - CompactDepth)) ||
        column_count == 0 || start_stage == 0 ||
        start_stage + stages - 1u != log_n) {
        return STWO_CUDA_ERROR_INVALID_CONFIGURATION;
    }
    const uint32_t min_stride = 1u << (start_stage - 1u);
    if (min_stride < 32u) return STWO_CUDA_ERROR_INVALID_CONFIGURATION;
    const dim3 grid{
        min_stride / 32u,
        1u,
        column_count,
    };
    const M31 scale = m31_inverse_power_of_two(log_n);
    if (stages == 6) {
        b2n_continue<3, false, CompactDepth><<<
            grid,
            dim3(32, 8),
            0,
            stream>>>(
                columns,
                compact_outputs,
                column_count,
                log_n,
                start_stage,
                log_n,
                twiddles,
                scale);
    } else if (stages == 8) {
        b2n_continue<4, false, CompactDepth><<<
            grid,
            dim3(32, 16),
            0,
            stream>>>(
                columns,
                compact_outputs,
                column_count,
                log_n,
                start_stage,
                log_n,
                twiddles,
                scale);
    } else {
        return STWO_CUDA_ERROR_INVALID_CONFIGURATION;
    }
    return cudaPeekAtLastError();
}

}  // namespace stwo::cuda::transform

#endif
