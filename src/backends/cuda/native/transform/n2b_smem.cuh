#ifndef STWO_ZIG_CUDA_N2B_SMEM_CUH
#define STWO_ZIG_CUDA_N2B_SMEM_CUH

// Two-pass N2B (kernels stream, M4 experiment). A pass loads one tile of
// 2^TileLog values into shared memory with coalesced rows, applies a run of
// radix-2 stages with one CTA barrier per stage, and stores the tile back.
//   Strided tile:    2^LaneLog contiguous words (the lane axis, never
//                    permuted) x 2^(TileLog-LaneLog) points of the high
//                    stride; it applies the high-bit stages 1..TileLog-LaneLog.
//   Contiguous tile: 2^TileLog consecutive words; it applies the last
//                    TileLog stages (including the circle stage).
// Stage s pairs global bit b = log_n - s. Its twiddle is
//   tw[2^(log_n-1) - 2^s + (L >> (b+1))]       for s < log_n,
//   circle_twiddle(tw, L >> 1)                 for s == log_n,
// exactly as n2b_stage, so every schedule computes bit-identical outputs.

#include "../common/circle_twiddle.cuh"
#include "../common/provider_compat.cuh"
#include "transform_internal.cuh"

namespace stwo::cuda::transform {

template <uint32_t TileLog, uint32_t LaneLog, bool Strided>
__device__ __forceinline__ uint32_t n2b_smem_index(
    uint32_t element, uint32_t tile, uint32_t log_n) {
    if constexpr (Strided) {
        constexpr uint32_t high_bits = TileLog - LaneLog;
        const uint32_t lane = element & ((1u << LaneLog) - 1u);
        const uint32_t high = element >> LaneLog;
        return (high << (log_n - high_bits)) | (tile << LaneLog) | lane;
    } else {
        return (tile << TileLog) | element;
    }
}

template <
    uint32_t TileLog,
    uint32_t LaneLog,
    bool Strided,
    bool LoadCoefficients,
    uint32_t Threads>
__global__ __launch_bounds__(Threads) void n2b_smem_pass(
    ColumnSlab<const M31> inputs,
    const uint32_t *input_log_sizes,
    ColumnSlab<M31> columns,
    uint32_t log_n,
    uint32_t first_stage,
    uint32_t last_stage,
    const M31 *twiddles,
    uint32_t column_fastest) {
    extern __shared__ M31 tile_values[];
    constexpr uint32_t tile_size = 1u << TileLog;
    const uint32_t column_index = column_fastest ? blockIdx.x : blockIdx.y;
    const uint32_t tile = column_fastest ? blockIdx.y : blockIdx.x;
    const M31 *input = inputs.column(column_index);
    M31 *column = columns.column(column_index);
    uint32_t input_count = 0;
    if constexpr (LoadCoefficients) {
        const uint32_t input_log_size = input_log_sizes[column_index];
        const uint32_t requested = input_log_size < 31u ? 1u << input_log_size : 0u;
        const uint32_t domain = 1u << (log_n - 1u);
        input_count = requested < domain ? requested : domain;
    }
#pragma unroll 4
    for (uint32_t e = threadIdx.x; e < tile_size; e += Threads) {
        const uint32_t g = n2b_smem_index<TileLog, LaneLog, Strided>(e, tile, log_n);
        if constexpr (LoadCoefficients) {
            tile_values[e] = g < input_count ? input[g] : 0u;
        } else {
            tile_values[e] = input[g];
        }
    }
    __syncthreads();
    for (uint32_t stage = first_stage; stage <= last_stage; ++stage) {
        const uint32_t bit = log_n - stage;
        const uint32_t tile_bit = Strided
            ? bit - (log_n - (TileLog - LaneLog)) + LaneLog
            : bit;
        const uint32_t offset = stage == log_n
            ? 0u
            : (1u << (log_n - 1u)) - (1u << stage);
        const uint32_t low_mask = (1u << tile_bit) - 1u;
#pragma unroll 4
        for (uint32_t p = threadIdx.x; p < tile_size / 2u; p += Threads) {
            const uint32_t left = ((p & ~low_mask) << 1) | (p & low_mask);
            const uint32_t right = left | (1u << tile_bit);
            const uint32_t global_left =
                n2b_smem_index<TileLog, LaneLog, Strided>(left, tile, log_n);
            const uint32_t butterfly = global_left >> (bit + 1u);
            const M31 twiddle = stage == log_n
                ? circle_twiddle(twiddles, butterfly)
                : twiddles[offset + butterfly];
            const M31 left_value = tile_values[left];
            const M31 product = m31_mul(twiddle, tile_values[right]);
            tile_values[left] = m31_add(left_value, product);
            tile_values[right] = m31_sub(left_value, product);
        }
        __syncthreads();
    }
#pragma unroll 4
    for (uint32_t e = threadIdx.x; e < tile_size; e += Threads) {
        column[n2b_smem_index<TileLog, LaneLog, Strided>(e, tile, log_n)] =
            tile_values[e];
    }
}

template <
    uint32_t TileLog,
    uint32_t LaneLog,
    bool Strided,
    bool LoadCoefficients,
    uint32_t Threads>
inline cudaError_t launch_n2b_smem_pass(
    ColumnSlab<const M31> inputs,
    const uint32_t *input_log_sizes,
    ColumnSlab<M31> columns,
    uint32_t log_n,
    uint32_t column_count,
    uint32_t first_stage,
    uint32_t last_stage,
    const M31 *twiddles,
    cudaStream_t stream) {
    constexpr size_t bytes = sizeof(M31) << TileLog;
    const uint32_t tiles = 1u << (log_n - TileLog);
    if (column_count == 0 || log_n <= TileLog || first_stage == 0 ||
        last_stage < first_stage || last_stage > log_n ||
        (Strided && last_stage > TileLog - LaneLog) ||
        (!Strided && first_stage + TileLog <= log_n)) {
        return STWO_CUDA_ERROR_INVALID_CONFIGURATION;
    }
    auto kernel = n2b_smem_pass<TileLog, LaneLog, Strided, LoadCoefficients, Threads>;
    if constexpr (bytes > 48u * 1024u) {
        // Per device; cheap and idempotent, so set it on every launch.
        const cudaError_t status = cudaFuncSetAttribute(
            kernel, cudaFuncAttributeMaxDynamicSharedMemorySize, int(bytes));
        if (status != cudaSuccess) return status;
    }
    const uint32_t column_fastest =
        column_count > 1u && tiles <= 65535u ? 1u : 0u;
    const dim3 grid = column_fastest ? dim3{column_count, tiles}
                                     : dim3{tiles, column_count};
    kernel<<<grid, Threads, bytes, stream>>>(
        inputs, input_log_sizes, columns, log_n, first_stage, last_stage,
        twiddles, column_fastest);
    return cudaPeekAtLastError();
}

}  // namespace stwo::cuda::transform

#endif
