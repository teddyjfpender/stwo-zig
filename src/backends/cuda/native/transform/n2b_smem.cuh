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
#include "wide_tile.cuh"

#include <cstdlib>

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


// ---------------------------------------------------------------------------
// Register-blocked two-pass N2B for log_n in [14, 24] (kernels stream, M4).
// Each thread holds 32 values; a phase applies up to five stages to the five
// "k" bits of its values in registers (compile-time pairs), and phases
// exchange through padded shared memory (idx = e + e/32: conflict-free for
// every phase mapping below). Pass W1 (strided) applies stages 1..11 on a
// tile of 8 contiguous words (one 32-byte sector, the lane axis is never
// permuted) x 2^11 high points; pass W2 (contiguous) applies the last 13
// stages on 8192 consecutive words. Twiddles follow n2b_stage exactly.
// ---------------------------------------------------------------------------
#ifndef STWO_N2B_WIDE_STRIDED_COLUMN_FASTEST
#define STWO_N2B_WIDE_STRIDED_COLUMN_FASTEST 0
#endif
constexpr uint32_t kWideValues = 32;
__device__ __forceinline__ uint32_t n2b_wide_pad(uint32_t e) {
    return e + (e >> 5);
}

template <uint32_t Stages, uint32_t TopBit, typename Index>
__device__ __forceinline__ void n2b_wide_stages(
    M31 (&v)[kWideValues], uint32_t first_stage, uint32_t last_stage,
    uint32_t log_n, const M31 *twiddles, Index index) {
#pragma unroll
    for (uint32_t i = 0; i < Stages; ++i) {
        const uint32_t stage = first_stage + i;
        if (stage <= last_stage) {
            const uint32_t kb = TopBit - i;
            const uint32_t bit = log_n - stage;
            const uint32_t offset = stage == log_n
                ? 0u
                : (1u << (log_n - 1u)) - (1u << stage);
#pragma unroll
            for (uint32_t q = 0; q < kWideValues / 2u; ++q) {
                const uint32_t kl =
                    (q & ((1u << kb) - 1u)) | ((q >> kb) << (kb + 1u));
                const uint32_t kr = kl | (1u << kb);
                const uint32_t butterfly = index(kl) >> (bit + 1u);
                const M31 twiddle = stage == log_n
                    ? circle_twiddle(twiddles, butterfly)
                    : twiddles[offset + butterfly];
                const M31 left = v[kl];
                const M31 product = m31_mul(twiddle, v[kr]);
                v[kl] = m31_add(left, product);
                v[kr] = m31_sub(left, product);
            }
        }
    }
}

constexpr uint32_t kWideHighBits = 11;
constexpr uint32_t kWideStridedThreads = 512;
constexpr uint32_t kWideStridedWords = 8u << kWideHighBits;
constexpr size_t kWideStridedBytes =
    sizeof(M31) * (kWideStridedWords + kWideStridedWords / 32u);

template <bool LoadCoefficients>
__global__ __launch_bounds__(kWideStridedThreads) void n2b_wide_strided(
    ColumnSlab<const M31> inputs,
    const uint32_t *input_log_sizes,
    ColumnSlab<M31> columns,
    uint32_t log_n,
    const M31 *twiddles,
    uint32_t column_fastest) {
    extern __shared__ M31 tile_values[];
    const uint32_t column_index = column_fastest ? blockIdx.x : blockIdx.y;
    const uint32_t tile = column_fastest ? blockIdx.y : blockIdx.x;
    const M31 *input = inputs.column(column_index);
    M31 *column = columns.column(column_index);
    const uint32_t t = threadIdx.x, lane = t & 7u, j = t >> 3;
    const uint32_t shift = log_n - kWideHighBits;
    const uint32_t fixed = (tile << 3) | lane;
    uint32_t input_count = 0;
    if constexpr (LoadCoefficients) {
        const uint32_t input_log_size = input_log_sizes[column_index];
        const uint32_t requested = input_log_size < 31u ? 1u << input_log_size : 0u;
        const uint32_t domain = 1u << (log_n - 1u);
        input_count = requested < domain ? requested : domain;
    }
    M31 v[kWideValues];
    // Phase 1: high bits 10..6 <- k4..k0.
    const auto h1 = [&](uint32_t k) { return j | (k << 6); };
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k) {
        const uint32_t g = (h1(k) << shift) | fixed;
        if constexpr (LoadCoefficients) {
            v[k] = g < input_count ? input[g] : 0u;
        } else {
            v[k] = input[g];
        }
    }
    n2b_wide_stages<5, 4>(v, 1, log_n, log_n, twiddles,
                          [&](uint32_t k) { return (h1(k) << shift) | fixed; });
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        tile_values[n2b_wide_pad(h1(k) * 8u + lane)] = v[k];
    __syncthreads();
    // Phase 2: high bits 5..1 <- k4..k0.
    const auto h2 = [&](uint32_t k) {
        return (j & 1u) | (k << 1) | ((j >> 1) << 6);
    };
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        v[k] = tile_values[n2b_wide_pad(h2(k) * 8u + lane)];
    n2b_wide_stages<5, 4>(v, 6, log_n, log_n, twiddles,
                          [&](uint32_t k) { return (h2(k) << shift) | fixed; });
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        tile_values[n2b_wide_pad(h2(k) * 8u + lane)] = v[k];
    __syncthreads();
    // Phase 3: high bit 0 <- k0, then store (4 rows x 8 words per warp).
    const auto h3 = [&](uint32_t k) { return k | (j << 5); };
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        v[k] = tile_values[n2b_wide_pad(h3(k) * 8u + lane)];
    n2b_wide_stages<1, 0>(v, 11, log_n, log_n, twiddles,
                          [&](uint32_t k) { return (h3(k) << shift) | fixed; });
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        column[(h3(k) << shift) | fixed] = v[k];
}

// Two-phase strided pass for High <= 10 (logs 21..23 with the 13-stage
// contiguous pass): phase 1 applies high bits High-1..J (J = High-5 thread
// bits), phase 2 bits J-1..0; same layout and padding as above.
template <uint32_t High, bool LoadCoefficients>
__global__ __launch_bounds__(8u << (High - 5u)) void n2b_wide_strided_short(
    ColumnSlab<const M31> inputs,
    const uint32_t *input_log_sizes,
    ColumnSlab<M31> columns,
    uint32_t log_n,
    const M31 *twiddles,
    uint32_t column_fastest) {
    static_assert(High >= 6 && High <= 10, "two-phase strided pass");
    constexpr uint32_t J = High - 5u;
    extern __shared__ M31 tile_values[];
    const uint32_t column_index = column_fastest ? blockIdx.x : blockIdx.y;
    const uint32_t tile = column_fastest ? blockIdx.y : blockIdx.x;
    const M31 *input = inputs.column(column_index);
    M31 *column = columns.column(column_index);
    const uint32_t t = threadIdx.x, lane = t & 7u, j = t >> 3;
    const uint32_t shift = log_n - High;
    const uint32_t fixed = (tile << 3) | lane;
    uint32_t input_count = 0;
    if constexpr (LoadCoefficients) {
        const uint32_t input_log_size = input_log_sizes[column_index];
        const uint32_t requested = input_log_size < 31u ? 1u << input_log_size : 0u;
        const uint32_t domain = 1u << (log_n - 1u);
        input_count = requested < domain ? requested : domain;
    }
    M31 v[kWideValues];
    const auto h1 = [&](uint32_t k) { return j | (k << J); };
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k) {
        const uint32_t g = (h1(k) << shift) | fixed;
        if constexpr (LoadCoefficients) {
            v[k] = g < input_count ? input[g] : 0u;
        } else {
            v[k] = input[g];
        }
    }
    n2b_wide_stages<5, 4>(v, 1, log_n, log_n, twiddles,
                          [&](uint32_t k) { return (h1(k) << shift) | fixed; });
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        tile_values[n2b_wide_pad(h1(k) * 8u + lane)] = v[k];
    __syncthreads();
    const auto h2 = [&](uint32_t k) { return k | (j << 5); };
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        v[k] = tile_values[n2b_wide_pad(h2(k) * 8u + lane)];
    n2b_wide_stages<J, J - 1u>(v, 6, log_n, log_n, twiddles,
                               [&](uint32_t k) { return (h2(k) << shift) | fixed; });
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        column[(h2(k) << shift) | fixed] = v[k];
}

constexpr uint32_t kWideLowBits = 13;
constexpr uint32_t kWideContiguousThreads = 256;
constexpr uint32_t kWideContiguousWords = 1u << kWideLowBits;

// A template (like every kernel in these headers) so that the instantiations
// in lde.cu and n2b.cu merge at the -rdc device link.
template <uint32_t LowBits = kWideLowBits>
__global__ __launch_bounds__(kWideContiguousThreads) void n2b_wide_contiguous(
    ColumnSlab<M31> columns,
    uint32_t log_n,
    uint32_t last_stage,
    const M31 *twiddles,
    uint32_t column_fastest) {
    __shared__ M31 tile_values[kWideContiguousWords + kWideContiguousWords / 32u];
    const uint32_t column_index = column_fastest ? blockIdx.x : blockIdx.y;
    const uint32_t tile = column_fastest ? blockIdx.y : blockIdx.x;
    M31 *column = columns.column(column_index) + (size_t(tile) << kWideLowBits);
    const uint32_t t = threadIdx.x;
    const uint32_t base = tile << kWideLowBits;
    const uint32_t first = log_n - (kWideLowBits - 1u);
    M31 v[kWideValues];
    // Phase 1: bits 12..8 <- k4..k0 (coalesced load).
    const auto e1 = [&](uint32_t k) { return t | (k << 8); };
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k) v[k] = column[e1(k)];
    n2b_wide_stages<5, 4>(v, first, last_stage, log_n, twiddles,
                          [&](uint32_t k) { return base | e1(k); });
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        tile_values[n2b_wide_pad(e1(k))] = v[k];
    __syncthreads();
    // Phase 2: bits 7..3 <- k4..k0.
    const auto e2 = [&](uint32_t k) {
        return (t & 7u) | (k << 3) | ((t >> 3) << 8);
    };
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        v[k] = tile_values[n2b_wide_pad(e2(k))];
    n2b_wide_stages<5, 4>(v, first + 5u, last_stage, log_n, twiddles,
                          [&](uint32_t k) { return base | e2(k); });
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        tile_values[n2b_wide_pad(e2(k))] = v[k];
    __syncthreads();
    // Phase 3: bits 2..0 <- k2..k0 (includes the circle stage).
    const auto e3 = [&](uint32_t k) { return k | (t << 5); };
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        v[k] = tile_values[n2b_wide_pad(e3(k))];
    n2b_wide_stages<3, 2>(v, first + 10u, last_stage, log_n, twiddles,
                          [&](uint32_t k) { return base | e3(k); });
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        tile_values[n2b_wide_pad(e3(k))] = v[k];
    __syncthreads();
    // Coalesced store.
#pragma unroll
    for (uint32_t k = 0; k < kWideValues; ++k)
        column[e1(k)] = tile_values[n2b_wide_pad(e1(k))];
}

// Strided pass with wide rows (T4 FFT passes, M8 round 1): the tile holds
// 2^STWO_N2B_WIDE_ROWS_TILE_LOG values in one CTA of 2^(TILE_LOG-5) threads,
// so a height-High pass reads rows of 2^(TILE_LOG-High) words instead of 8.
// It covers heights 6..7 (logs 19..20), which the 8-word kernels cannot run
// efficiently (a 16..32-thread CTA), and is faster at heights 8..9; see the
// A/B below. STWO_N2B_WIDE_ROWS_HIGHS selects the heights that use it (bit H
// set = height H).
template <uint32_t High, uint32_t LaneLog, uint32_t Phase, bool LoadCoefficients>
__device__ __forceinline__ void n2b_wide_rows_phase(
    M31 (&v)[kWideValues], M31 *tile_values, const M31 *input, M31 *column,
    uint32_t input_count, uint32_t j, uint32_t lane, uint32_t shift,
    uint32_t fixed, uint32_t log_n, const M31 *twiddles) {
    constexpr uint32_t phases = wide_phase_count(High);
    constexpr uint32_t count = wide_phase_bits(High, Phase);
    constexpr uint32_t first_bit = High - 5u * Phase - count;
    const uint32_t jh = wide_deposit<High>(Phase, first_bit, 0u, j);
    const auto h = [&](uint32_t k) {
        return wide_deposit<High>(Phase, first_bit, k, 0u) | jh;
    };
    const auto g = [&](uint32_t k) { return (h(k) << shift) | fixed; };
    if constexpr (Phase == 0) {
#pragma unroll
        for (uint32_t k = 0; k < kWideValues; ++k) {
            if constexpr (LoadCoefficients) {
                v[k] = g(k) < input_count ? input[g(k)] : 0u;
            } else {
                v[k] = input[g(k)];
            }
        }
    } else {
#pragma unroll
        for (uint32_t k = 0; k < kWideValues; ++k)
            v[k] = tile_values[wide_tile_pad((h(k) << LaneLog) | lane)];
    }
    n2b_wide_stages<count, count - 1u>(v, 5u * Phase + 1u, log_n, log_n,
                                       twiddles, g);
    if constexpr (Phase + 1u == phases) {
#pragma unroll
        for (uint32_t k = 0; k < kWideValues; ++k) column[g(k)] = v[k];
    } else {
#pragma unroll
        for (uint32_t k = 0; k < kWideValues; ++k)
            tile_values[wide_tile_pad((h(k) << LaneLog) | lane)] = v[k];
        __syncthreads();
    }
}

template <uint32_t High, uint32_t LaneLog, bool LoadCoefficients>
__global__ __launch_bounds__(WideStridedShape<High, LaneLog>::threads)
void n2b_wide_strided_rows(
    ColumnSlab<const M31> inputs,
    const uint32_t *input_log_sizes,
    ColumnSlab<M31> columns,
    uint32_t log_n,
    const M31 *twiddles,
    uint32_t column_fastest) {
    extern __shared__ M31 tile_values[];
    const uint32_t column_index = column_fastest ? blockIdx.x : blockIdx.y;
    const uint32_t tile = column_fastest ? blockIdx.y : blockIdx.x;
    const M31 *input = inputs.column(column_index);
    M31 *column = columns.column(column_index);
    const uint32_t t = threadIdx.x;
    const uint32_t lane = t & ((1u << LaneLog) - 1u);
    const uint32_t j = t >> LaneLog;
    const uint32_t shift = log_n - High;
    const uint32_t fixed = (tile << LaneLog) | lane;
    uint32_t input_count = 0;
    if constexpr (LoadCoefficients) {
        const uint32_t input_log_size = input_log_sizes[column_index];
        const uint32_t requested = input_log_size < 31u ? 1u << input_log_size : 0u;
        const uint32_t domain = 1u << (log_n - 1u);
        input_count = requested < domain ? requested : domain;
    }
    M31 v[kWideValues];
    n2b_wide_rows_phase<High, LaneLog, 0, LoadCoefficients>(
        v, tile_values, input, column, input_count, j, lane, shift, fixed,
        log_n, twiddles);
    if constexpr (wide_phase_count(High) > 1u)
        n2b_wide_rows_phase<High, LaneLog, 1, LoadCoefficients>(
            v, tile_values, input, column, input_count, j, lane, shift,
            fixed, log_n, twiddles);
    if constexpr (wide_phase_count(High) > 2u)
        n2b_wide_rows_phase<High, LaneLog, 2, LoadCoefficients>(
            v, tile_values, input, column, input_count, j, lane, shift,
            fixed, log_n, twiddles);
}

// [M] A/B, bench/fft_passes_bench.cu, 256 MiB per call, 7 reps, median ms
// (n2b in place; old = 3-pass 6,6,8 at log 20, 8-word strided kernels at
// 21..24):
//   log            20     21     22     23     24
//   old          1.053  0.715  0.733  0.762  0.891
//   rows TILE 14 0.715  0.727  0.752  0.754  0.926
//   rows TILE 13 0.700  0.703  0.719  0.762  0.928   <- TILE 13, heights 6..9
// Height 10 is neutral and height 11 is 4% slower than the hand-written
// 8-word kernels, which they keep. LDE (coefficient load) at log 20:
// 0.971 -> 0.619 ms. Height 6 (log 19) ties the fused 8,11 schedule (0.705
// vs 0.707), so STWO_N2B_WIDE_MIN_LOG stays 20.
#ifndef STWO_N2B_WIDE_ROWS_TILE_LOG
#define STWO_N2B_WIDE_ROWS_TILE_LOG 13
#endif
#ifndef STWO_N2B_WIDE_ROWS_HIGHS
#define STWO_N2B_WIDE_ROWS_HIGHS ((1u << 6) | (1u << 7) | (1u << 8) | (1u << 9))
#endif
constexpr uint32_t n2b_wide_rows_lane_log(uint32_t high) {
    return STWO_N2B_WIDE_ROWS_TILE_LOG - high < 3u
        ? 3u
        : STWO_N2B_WIDE_ROWS_TILE_LOG - high;
}

// Bench/A-B overrides (-1 = compiled default). They only pick between
// bit-identical schedules.
inline int g_n2b_wide_min_log_override = -1;
inline int g_n2b_wide_rows_highs_override = -1;
// STWO_RV64_M8_N2B_WIDE_ROWS=0 keeps the 8-word strided kernels at every
// height (with STWO_RV64_M8_N2B_WIDE_MIN_LOG=21: the previous kernel set).
inline uint32_t n2b_wide_rows_highs() {
    if (g_n2b_wide_rows_highs_override >= 0)
        return uint32_t(g_n2b_wide_rows_highs_override);
    static const uint32_t highs = [] {
        const char *value = std::getenv("STWO_RV64_M8_N2B_WIDE_ROWS");
        return value && value[0] == '0' ? 0u : uint32_t(STWO_N2B_WIDE_ROWS_HIGHS);
    }();
    return highs;
}

#ifndef STWO_N2B_WIDE_MIN_LOG
#define STWO_N2B_WIDE_MIN_LOG 20
#endif
// STWO_RV64_M8_N2B_WIDE_MIN_LOG overrides the first wide log (A/B only;
// every value selects bit-identical schedules).
inline uint32_t n2b_wide_min_log() {
    if (g_n2b_wide_min_log_override >= 0)
        return uint32_t(g_n2b_wide_min_log_override);
    static const uint32_t min_log = [] {
        const char *value = std::getenv("STWO_RV64_M8_N2B_WIDE_MIN_LOG");
        const unsigned long parsed = value ? std::strtoul(value, nullptr, 10) : 0ul;
        return parsed >= 19ul && parsed <= 25ul ? uint32_t(parsed)
                                                : uint32_t(STWO_N2B_WIDE_MIN_LOG);
    }();
    return min_log;
}
inline bool n2b_wide_supported(uint32_t log_n) {
    const uint32_t min_log = n2b_wide_min_log();
    const uint32_t high = log_n - kWideLowBits;
    return log_n >= min_log &&
        log_n <= kWideHighBits + kWideLowBits &&
        log_n >= 6u + kWideLowBits &&
        (high >= 8u || ((n2b_wide_rows_highs() >> high) & 1u) != 0u);
}

// Production switch: STWO_RV64_N2B_WIDE=0 restores the 3-pass schedule
// (bit-identical output either way; kept for A/B runs).
inline int g_n2b_wide_override = -1;
inline bool n2b_wide_enabled() {
    if (g_n2b_wide_override >= 0) return g_n2b_wide_override != 0;
    static const bool enabled = [] {
        const char *value = std::getenv("STWO_RV64_N2B_WIDE");
        return !(value && value[0] == '0');
    }();
    return enabled;
}

// Runs stages 1..log_n (or 1..log_n-1 without the circle stage) as two
// passes: inputs may alias columns (in-place N2B) or be a coefficient slab
// (LDE with zero extension), exactly like the fused first interval.
template <bool LoadCoefficients>
inline cudaError_t launch_n2b_wide(
    ColumnSlab<const M31> inputs,
    const uint32_t *input_log_sizes,
    ColumnSlab<M31> columns,
    uint32_t log_n,
    uint32_t column_count,
    bool include_circle,
    const M31 *twiddles,
    cudaStream_t stream) {
    if (!n2b_wide_supported(log_n) || column_count == 0)
        return STWO_CUDA_ERROR_INVALID_CONFIGURATION;
    const uint32_t high = log_n - kWideLowBits;
    const uint32_t strided_tiles = 1u << (log_n - high - 3u);
    const uint32_t contiguous_tiles = 1u << (log_n - kWideLowBits);
    // Pass W1 reads 32-byte rows: tile-fastest order keeps the four tiles
    // that share each 128-byte L2 line in flight together (its twiddle layers
    // are tiny, so column-fastest buys nothing there). Pass W2 reads whole
    // lines and its final layers are large, so it shares twiddles instead.
    const uint32_t a_fast = STWO_N2B_WIDE_STRIDED_COLUMN_FASTEST &&
        column_count > 1u && strided_tiles <= 65535u;
    const dim3 a_grid = a_fast ? dim3{column_count, strided_tiles}
                               : dim3{strided_tiles, column_count};
    const size_t a_bytes =
        sizeof(M31) * ((size_t(8) << high) + (size_t(8) << high) / 32u);
    cudaError_t status = cudaSuccess;
    const auto launch_short = [&](auto kernel, uint32_t threads) {
        if (a_bytes > 48u * 1024u) {
            const cudaError_t attribute = cudaFuncSetAttribute(
                kernel, cudaFuncAttributeMaxDynamicSharedMemorySize,
                int(a_bytes));
            if (attribute != cudaSuccess) return attribute;
        }
        kernel<<<a_grid, threads, a_bytes, stream>>>(
            inputs, input_log_sizes, columns, log_n, twiddles, a_fast);
        return cudaPeekAtLastError();
    };
    const auto launch_rows = [&](auto kernel, uint32_t lane_log,
                                 uint32_t threads, size_t bytes) {
        const uint32_t tiles = 1u << (log_n - high - lane_log);
        if (bytes > 48u * 1024u) {
            const cudaError_t attribute = cudaFuncSetAttribute(
                kernel, cudaFuncAttributeMaxDynamicSharedMemorySize,
                int(bytes));
            if (attribute != cudaSuccess) return attribute;
        }
        kernel<<<dim3{tiles, column_count}, threads, bytes, stream>>>(
            inputs, input_log_sizes, columns, log_n, twiddles, 0u);
        return cudaPeekAtLastError();
    };
#define STWO_N2B_ROWS_CASE(H)                                                 \
    {                                                                         \
        constexpr uint32_t lane_log = n2b_wide_rows_lane_log(H);              \
        using Shape = WideStridedShape<H, lane_log>;                          \
        status = launch_rows(                                                 \
            n2b_wide_strided_rows<H, lane_log, LoadCoefficients>, lane_log,   \
            Shape::threads, Shape::bytes);                                    \
    }
    const bool rows = ((n2b_wide_rows_highs() >> high) & 1u) != 0u;
    switch (rows ? high + 100u : high) {
        case 106: STWO_N2B_ROWS_CASE(6) break;
        case 107: STWO_N2B_ROWS_CASE(7) break;
        case 108: STWO_N2B_ROWS_CASE(8) break;
        case 109: STWO_N2B_ROWS_CASE(9) break;
        case 110: STWO_N2B_ROWS_CASE(10) break;
        case 111: STWO_N2B_ROWS_CASE(11) break;
        case 11: status = launch_short(n2b_wide_strided<LoadCoefficients>,
                                       kWideStridedThreads); break;
        case 10: status = launch_short(n2b_wide_strided_short<10, LoadCoefficients>, 8u << 5); break;
        case 9: status = launch_short(n2b_wide_strided_short<9, LoadCoefficients>, 8u << 4); break;
        case 8: status = launch_short(n2b_wide_strided_short<8, LoadCoefficients>, 8u << 3); break;
        default: return STWO_CUDA_ERROR_INVALID_CONFIGURATION;
    }
#undef STWO_N2B_ROWS_CASE
    if (status != cudaSuccess) return status;
    const uint32_t b_fast = column_count > 1u && contiguous_tiles <= 65535u;
    n2b_wide_contiguous<kWideLowBits><<<b_fast ? dim3{column_count, contiguous_tiles}
                                 : dim3{contiguous_tiles, column_count},
                          kWideContiguousThreads, 0, stream>>>(
        columns, log_n, include_circle ? log_n : log_n - 1u, twiddles, b_fast);
    return cudaPeekAtLastError();
}

}  // namespace stwo::cuda::transform

#endif
