#ifndef STWO_ZIG_CUDA_B2N_FUSED_CUH
#define STWO_ZIG_CUDA_B2N_FUSED_CUH

#include "../common/circle_twiddle.cuh"
#include "../common/provider_compat.cuh"
#include "transform_internal.cuh"
#include "wide_tile.cuh"

#include <cstdlib>

namespace stwo::cuda::transform {

constexpr uint32_t kLogWarp = 5;

template <uint32_t LogValues>
__device__ __forceinline__ void b2n_shuffle(
    M31 *values,
    uint32_t log_stride,
    uint32_t lane) {
    const uint32_t mask = 1u << log_stride;
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

    uint32_t layer_size = 1u << (log_n - min_stage + 1u);
    uint32_t layer_offset =
        (1u << (log_n - 1u)) - layer_size;
    // Compile-time trip counts keep values[] register-resident (a runtime
    // loop bound demotes it to a 64-byte local stack for LogValues == 4).
#pragma unroll
    for (uint32_t step = 0; step < LogValues; ++step) {
        const uint32_t stage = min_stage + step;
        const uint32_t log_stride = step;
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

    // max_stage == next_stage + LogValues - 1 for every launch (stages ==
    // 2 * LogValues in launch_b2n_continue*).
#pragma unroll
    for (uint32_t step = 0; step < LogValues; ++step) {
        const uint32_t stage = next_stage + step;
        const uint32_t log_stride = step;
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
        case 6: {
            const uint32_t warps = 1u << (log_n - 6u);
            const uint32_t block_warps = warps < 4u ? warps : 4u;
            b2n_init_warp<1><<<
                dim3(warps / block_warps, columns),
                dim3(32, block_warps), 0, stream>>>(
                    inputs, outputs, log_n, stages, twiddles);
            break;
        }
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

// ---------------------------------------------------------------------------
// Two-pass wide B2N for log_n in [STWO_B2N_WIDE_MIN_LOG, 24] (T4 FFT passes,
// M8 optimisation round 1). Mirrors the register-blocked two-pass N2B in
// n2b_smem.cuh with the stage order reversed (B2N pairs global bit s - 1 at
// stage s, low bits first):
//   Pass C (contiguous): 8192 consecutive words, stages 1..13 (the circle
//          stage included) in three register phases (5 + 5 + 3 stages)
//          joined by padded shared memory (idx = e + e/32, conflict-free).
//   Pass S (strided):    2^LaneLog contiguous words (the lane axis, never
//          permuted) x 2^High points of the high stride (global bits
//          13..log_n-1); stages 14..log_n in ceil(High/5) phases. The final
//          stage applies the 2^-log_n scale, and the final store writes the
//          plain, Duplicate (retained 2N) or CompactDepth layout of
//          b2n_continue.
// Stage s twiddle is circle_twiddle(tw, L >> 1) for s == 1 and
// tw[2^(log_n-1) - 2^(log_n-s+1) + (L >> s)] otherwise, exactly as b2n_stage.
// M31 arithmetic is canonical, so every schedule of the same butterflies is
// bit-identical (parity: bench/fft_passes_bench.cu).
// ---------------------------------------------------------------------------
constexpr uint32_t kB2nWideLowBits = 13;
constexpr uint32_t kB2nWideContiguousThreads = 256;
constexpr uint32_t kB2nWideContiguousWords = 1u << kB2nWideLowBits;

// Applies B2N stages first_stage .. first_stage + Stages - 1 to the k bits
// BottomBit .. BottomBit + Stages - 1 of the 32 register values; index(k) is
// the global (column) index of value k.
template <uint32_t Stages, uint32_t BottomBit, typename Index>
__device__ __forceinline__ void b2n_wide_stages(
    M31 (&v)[kWideValues], uint32_t first_stage, uint32_t log_n,
    const M31 *twiddles, M31 scale, Index index) {
#pragma unroll
    for (uint32_t i = 0; i < Stages; ++i) {
        const uint32_t stage = first_stage + i;
        const uint32_t kb = BottomBit + i;
        const uint32_t offset = stage == 1u
            ? 0u
            : (1u << (log_n - 1u)) - (1u << (log_n - stage + 1u));
#pragma unroll
        for (uint32_t q = 0; q < kWideValues / 2u; ++q) {
            const uint32_t kl =
                (q & ((1u << kb) - 1u)) | ((q >> kb) << (kb + 1u));
            const uint32_t kr = kl | (1u << kb);
            const uint32_t butterfly = index(kl) >> stage;
            const M31 twiddle = stage == 1u
                ? circle_twiddle(twiddles, butterfly)
                : twiddles[offset + butterfly];
            const M31 left = v[kl];
            const M31 right = v[kr];
            v[kl] = m31_add(left, right);
            v[kr] = m31_mul(m31_sub(left, right), twiddle);
            if (stage == log_n) {
                v[kl] = m31_mul(v[kl], scale);
                v[kr] = m31_mul(v[kr], scale);
            }
        }
    }
}

// A template (like every kernel in these headers) so that the instantiations
// in b2n_retained.cu and composition_split.cu merge at the -rdc device link.
template <uint32_t LowBits = kB2nWideLowBits>
__global__ __launch_bounds__(kB2nWideContiguousThreads) void b2n_wide_contiguous(
    ColumnSlab<const M31> inputs,
    ColumnSlab<M31> outputs,
    uint32_t log_n,
    const M31 *twiddles,
    uint32_t column_fastest) {
    static_assert(LowBits == kB2nWideLowBits, "the phases below are 5 + 5 + 3");
    __shared__ M31 tile_values[
        kB2nWideContiguousWords + kB2nWideContiguousWords / 32u];
    const uint32_t column_index = column_fastest ? blockIdx.x : blockIdx.y;
    const uint32_t tile = column_fastest ? blockIdx.y : blockIdx.x;
    const uint32_t base = tile << kB2nWideLowBits;
    const M31 *input = inputs.column(column_index) + base;
    M31 *output = outputs.column(column_index) + base;
    const uint32_t t = threadIdx.x;
    M31 v[kWideValues];
    // Coalesced load. Every read of the tile precedes every write of it, so
    // an exact input/output alias is safe.
    const auto e0 = [&](uint32_t k) { return t | (k << 8); };
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k) v[k] = input[e0(k)];
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        tile_values[wide_tile_pad(e0(k))] = v[k];
    __syncthreads();
    // Phase 1: bits 0..4 <- k0..k4 (stages 1..5, the circle stage first).
    const auto e1 = [&](uint32_t k) { return k | (t << 5); };
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        v[k] = tile_values[wide_tile_pad(e1(k))];
    b2n_wide_stages<5, 0>(v, 1, log_n, twiddles, 0u,
                          [&](uint32_t k) { return base | e1(k); });
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        tile_values[wide_tile_pad(e1(k))] = v[k];
    __syncthreads();
    // Phase 2: bits 5..9 <- k0..k4.
    const auto e2 = [&](uint32_t k) {
        return (t & 31u) | (k << 5) | ((t >> 5) << 10);
    };
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        v[k] = tile_values[wide_tile_pad(e2(k))];
    b2n_wide_stages<5, 0>(v, 6, log_n, twiddles, 0u,
                          [&](uint32_t k) { return base | e2(k); });
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        tile_values[wide_tile_pad(e2(k))] = v[k];
    __syncthreads();
    // Phase 3: bits 10..12 <- k2..k4 (stages 11..13), coalesced store.
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        v[k] = tile_values[wide_tile_pad(e0(k))];
    b2n_wide_stages<3, 2>(v, 11, log_n, twiddles, 0u,
                          [&](uint32_t k) { return base | e0(k); });
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k) output[e0(k)] = v[k];
}

template <uint32_t High, uint32_t LaneLog, uint32_t Phase, typename Store>
__device__ __forceinline__ void b2n_wide_strided_phase(
    M31 (&v)[kWideValues], M31 *tile_values, M31 *column,
    uint32_t j, uint32_t lane, uint32_t shift, uint32_t fixed,
    uint32_t log_n, const M31 *twiddles, M31 scale, Store store) {
    constexpr uint32_t phases = wide_phase_count(High);
    constexpr uint32_t first_bit = 5u * Phase;
    constexpr uint32_t count = wide_phase_bits(High, Phase);
    const uint32_t jh = wide_deposit<High>(Phase, first_bit, 0u, j);
    const auto h = [&](uint32_t k) {
        return wide_deposit<High>(Phase, first_bit, k, 0u) | jh;
    };
    const auto g = [&](uint32_t k) { return (h(k) << shift) | fixed; };
    if constexpr (Phase == 0) {
#pragma unroll
        for (uint32_t k = 0; k < kWideValues; ++k) v[k] = column[g(k)];
    } else {
#pragma unroll
        for (uint32_t k = 0; k < kWideValues; ++k)
            v[k] = tile_values[wide_tile_pad((h(k) << LaneLog) | lane)];
    }
    b2n_wide_stages<count, 0>(v, shift + first_bit + 1u, log_n, twiddles,
                              scale, g);
    if constexpr (Phase + 1u == phases) {
#pragma unroll
        for (uint32_t k = 0; k < kWideValues; ++k) store(g(k), v[k]);
    } else {
#pragma unroll
        for (uint32_t k = 0; k < kWideValues; ++k)
            tile_values[wide_tile_pad((h(k) << LaneLog) | lane)] = v[k];
        __syncthreads();
    }
}

template <uint32_t High, uint32_t LaneLog, bool Duplicate, uint32_t CompactDepth>
__global__ __launch_bounds__(WideStridedShape<High, LaneLog>::threads)
void b2n_wide_strided(
    ColumnSlab<M31> columns,
    ColumnSlab<M31> compact_outputs,
    uint32_t compact_column_offset,
    uint32_t log_n,
    const M31 *twiddles,
    M31 scale,
    uint32_t column_fastest) {
    static_assert(
        !(Duplicate && CompactDepth != 0u),
        "a B2N pass cannot duplicate and compact its output");
    static_assert(CompactDepth <= 2u, "unsupported compact split depth");
    extern __shared__ M31 tile_values[];
    const uint32_t column_index = column_fastest ? blockIdx.x : blockIdx.y;
    const uint32_t tile = column_fastest ? blockIdx.y : blockIdx.x;
    M31 *column = columns.column(column_index);
    const uint32_t t = threadIdx.x;
    const uint32_t lane = t & ((1u << LaneLog) - 1u);
    const uint32_t j = t >> LaneLog;
    const uint32_t shift = log_n - High;
    const uint32_t fixed = (tile << LaneLog) | lane;
    const auto store = [&](uint32_t index, M31 value) {
        if constexpr (CompactDepth != 0u) {
            const uint32_t chunk_values = 1u << (log_n - CompactDepth);
            const uint32_t chunk = index >> (log_n - CompactDepth);
            compact_outputs
                .column(column_index + chunk * compact_column_offset)
                [index & (chunk_values - 1u)] = value;
        } else {
            column[index] = value;
            if constexpr (Duplicate) column[index + (1u << log_n)] = value;
        }
    };
    M31 v[kWideValues];
    b2n_wide_strided_phase<High, LaneLog, 0>(
        v, tile_values, column, j, lane, shift, fixed, log_n, twiddles,
        scale, store);
    if constexpr (wide_phase_count(High) > 1u)
        b2n_wide_strided_phase<High, LaneLog, 1>(
            v, tile_values, column, j, lane, shift, fixed, log_n, twiddles,
            scale, store);
    if constexpr (wide_phase_count(High) > 2u)
        b2n_wide_strided_phase<High, LaneLog, 2>(
            v, tile_values, column, j, lane, shift, fixed, log_n, twiddles,
            scale, store);
}

// Strided-pass lane width: the tile holds 2^STWO_B2N_WIDE_TILE_LOG values
// (one CTA of 2^(TILE_LOG-5) threads), so smaller heights get wider rows
// (lane log >= 3; height 11 always uses 8-word rows, a 2^14 tile).
// [M] A/B, bench/fft_passes_bench.cu, 256 MiB per call, 7 reps, median ms,
// RTX 5090 (old = three-interval schedule):
//   log      19     20     21     22     23     24   (b2n_compact)
//   old    1.055  1.059  1.059  1.087  1.151  1.163
//   TILE 14 0.711  0.715  0.778  0.793  0.784  0.924
//   TILE 13 0.707  0.711  0.711  0.735  0.790  0.920   <- selected
//   TILE 12 0.707  0.705  0.713  0.786  0.793  0.920
//   b2n_to_retained (2N writes) TILE 14 -> 13: log 19 1.008 -> 0.911,
//   log 22 1.081 -> 0.954 (old 1.266 / 1.309).
#ifndef STWO_B2N_WIDE_TILE_LOG
#define STWO_B2N_WIDE_TILE_LOG 13
#endif
#ifndef STWO_B2N_WIDE_MIN_LOG
#define STWO_B2N_WIDE_MIN_LOG 19
#endif
#ifndef STWO_B2N_WIDE_MAX_LOG
#define STWO_B2N_WIDE_MAX_LOG 24
#endif

constexpr uint32_t b2n_wide_lane_log(uint32_t high) {
    return STWO_B2N_WIDE_TILE_LOG - high < 3u ? 3u
                                              : STWO_B2N_WIDE_TILE_LOG - high;
}

// Bench/A-B override: -1 follows STWO_RV64_M8_B2N_WIDE (default on; "0"
// restores the three-pass schedules, bit-identical either way).
inline int g_b2n_wide_override = -1;
inline bool b2n_wide_enabled() {
    if (g_b2n_wide_override >= 0) return g_b2n_wide_override != 0;
    static const bool enabled = [] {
        const char *value = std::getenv("STWO_RV64_M8_B2N_WIDE");
        return !(value && value[0] == '0');
    }();
    return enabled;
}

inline bool b2n_wide_supported(uint32_t log_n) {
    return log_n >= STWO_B2N_WIDE_MIN_LOG &&
        log_n <= STWO_B2N_WIDE_MAX_LOG &&
        log_n >= kB2nWideLowBits + 5u &&
        log_n <= kB2nWideLowBits + 11u;
}

// Full B2N of column_count columns in two HBM passes. inputs may exactly
// alias outputs. Duplicate writes the retained 2N image; CompactDepth writes
// the chunk-major compact split to compact_outputs (stride 2^(log_n-depth)).
template <bool Duplicate, uint32_t CompactDepth>
inline cudaError_t launch_b2n_wide(
    ColumnSlab<const M31> inputs,
    ColumnSlab<M31> outputs,
    ColumnSlab<M31> compact_outputs,
    uint32_t log_n,
    uint32_t column_count,
    const M31 *twiddles,
    cudaStream_t stream) {
    if (!b2n_wide_supported(log_n) || column_count == 0 ||
        (CompactDepth != 0u &&
         (compact_outputs.base == nullptr ||
          compact_outputs.stride_words != (1u << (log_n - CompactDepth)))))
        return STWO_CUDA_ERROR_INVALID_CONFIGURATION;
    const uint32_t contiguous_tiles = 1u << (log_n - kB2nWideLowBits);
    const uint32_t c_fast = column_count > 1u && contiguous_tiles <= 65535u;
    b2n_wide_contiguous<><<<
        c_fast ? dim3{column_count, contiguous_tiles}
               : dim3{contiguous_tiles, column_count},
        kB2nWideContiguousThreads, 0, stream>>>(
        inputs, outputs, log_n, twiddles, c_fast);
    cudaError_t status = cudaPeekAtLastError();
    if (status != cudaSuccess) return status;
    const M31 scale = m31_inverse_power_of_two(log_n);
    const auto launch = [&](auto kernel, uint32_t high, uint32_t lane_log,
                            uint32_t threads, size_t bytes) {
        const uint32_t tiles = 1u << (log_n - high - lane_log);
        const cudaError_t attribute = wide_allow_shared_bytes(kernel, bytes);
        if (attribute != cudaSuccess) return attribute;
        // Tile-fastest: the tiles sharing an L2 line stay in flight together
        // (as n2b_wide_strided); the high-stage twiddle layers are tiny.
        kernel<<<dim3{tiles, column_count}, threads, bytes, stream>>>(
            outputs, compact_outputs, column_count, log_n, twiddles, scale,
            0u);
        return cudaPeekAtLastError();
    };
#define STWO_B2N_WIDE_CASE(H)                                                \
    case H: {                                                                \
        constexpr uint32_t lane_log = b2n_wide_lane_log(H);                  \
        using Shape = WideStridedShape<H, lane_log>;                         \
        return launch(b2n_wide_strided<H, lane_log, Duplicate, CompactDepth>, \
                      H, lane_log, Shape::threads, Shape::bytes);            \
    }
    switch (log_n - kB2nWideLowBits) {
        STWO_B2N_WIDE_CASE(6)
        STWO_B2N_WIDE_CASE(7)
        STWO_B2N_WIDE_CASE(8)
        STWO_B2N_WIDE_CASE(9)
        STWO_B2N_WIDE_CASE(10)
        STWO_B2N_WIDE_CASE(11)
        default: return STWO_CUDA_ERROR_INVALID_CONFIGURATION;
    }
#undef STWO_B2N_WIDE_CASE
}

}  // namespace stwo::cuda::transform

#endif
