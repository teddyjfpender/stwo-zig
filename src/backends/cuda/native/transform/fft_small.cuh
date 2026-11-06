#ifndef STWO_ZIG_CUDA_FFT_SMALL_CUH
#define STWO_ZIG_CUDA_FFT_SMALL_CUH

// Single-pass circle FFT for small columns (log_n <= 12; T4 FFT passes, M8
// optimisation round 1). The stagewise fallback launches one kernel per stage
// (log_n HBM round trips); here one CTA loads 2^kFftSmallTileLog words (one
// column, or 2^(tile-log_n) whole columns) into shared memory, applies every
// stage there with two stages (radix 4) per barrier, and stores once.
// Twiddles follow n2b_stage / b2n_stage exactly:
//   N2B stage s pairs bit b = log_n - s; twiddle
//       tw[2^(log_n-1) - 2^s + (L >> (b+1))]  (s < log_n),
//       circle_twiddle(tw, L >> 1)            (s == log_n).
//   B2N stage s pairs bit b = s - 1; twiddle
//       circle_twiddle(tw, L >> 1)            (s == 1),
//       tw[2^(log_n-1) - 2^(log_n-s+1) + (L >> s)]  (s > 1),
//   and the final stage scales both outputs by 2^-log_n.
// M31 arithmetic is canonical, so the outputs are bit-identical to the
// stagewise path (parity: bench/fft_passes_bench.cu).
// [M] A/B, bench/fft_passes_bench.cu, 256 MiB per call, 7 reps, median ms,
// stagewise -> this kernel:
//   log 10: b2n 3.535 -> 0.371, n2b 3.534 -> 0.369, retained 3.777 -> 0.571
//   log 11: b2n 3.861 -> 0.412, n2b 3.861 -> 0.406, retained 4.112 -> 0.567
//   log 12: b2n 4.217 -> 0.424, n2b 4.213 -> 0.404, retained 4.473 -> 0.573
//   (LDE log 12, whose staging kernel stays in lde.cu: 4.559 -> 0.748.)

#include "../common/circle_twiddle.cuh"
#include "../common/provider_compat.cuh"
#include "transform_internal.cuh"

#include <cstdlib>

namespace stwo::cuda::transform {

constexpr uint32_t kFftSmallMaxLogN = 12;
constexpr uint32_t kFftSmallTileLog = 12;
constexpr uint32_t kFftSmallThreads = 256;

template <bool B2n>
__device__ __forceinline__ M31 fft_small_twiddle(
    const M31 *twiddles, uint32_t log_n, uint32_t stage, uint32_t left) {
    if constexpr (B2n) {
        if (stage == 1u) return circle_twiddle(twiddles, left >> 1);
        return twiddles[(1u << (log_n - 1u)) - (1u << (log_n - stage + 1u)) +
                        (left >> stage)];
    } else {
        const uint32_t bit = log_n - stage;
        if (stage == log_n) return circle_twiddle(twiddles, left >> 1);
        return twiddles[(1u << (log_n - 1u)) - (1u << stage) +
                        (left >> (bit + 1u))];
    }
}

template <bool B2n>
__device__ __forceinline__ void fft_small_butterfly(
    M31 &left, M31 &right, M31 twiddle) {
    if constexpr (B2n) {
        const M31 l = left;
        left = m31_add(l, right);
        right = m31_mul(m31_sub(l, right), twiddle);
    } else {
        const M31 product = m31_mul(twiddle, right);
        const M31 l = left;
        left = m31_add(l, product);
        right = m31_sub(l, product);
    }
}

// in may exactly alias out (each CTA reads its whole columns before writing).
// Stages first_stage..last_stage; B2N scales at stage log_n; Duplicate also
// writes out[i + 2^log_n] (the retained 2N image).
template <bool B2n, bool Duplicate>
__global__ __launch_bounds__(kFftSmallThreads) void fft_small_columns(
    ColumnSlab<const M31> inputs,
    ColumnSlab<M31> outputs,
    uint32_t log_n,
    uint32_t column_count,
    uint32_t first_stage,
    uint32_t last_stage,
    const M31 *twiddles,
    M31 scale) {
    __shared__ M31 values[1u << kFftSmallTileLog];
    const uint32_t log_columns = kFftSmallTileLog - log_n;
    const uint32_t first_column = blockIdx.x << log_columns;
    const uint32_t remaining = column_count - first_column;
    const uint32_t columns =
        remaining < (1u << log_columns) ? remaining : (1u << log_columns);
    const uint32_t mask = (1u << log_n) - 1u;
    const uint32_t words = columns << log_n;
    const uint32_t t = threadIdx.x;
    for (uint32_t e = t; e < words; e += kFftSmallThreads)
        values[e] = inputs.column(first_column + (e >> log_n))[e & mask];
    __syncthreads();
    // Radix-4 steps: stages s and s+1 on the quad {L, L|b1, L|b2, L|b1|b2}
    // where b1, b2 are the two pair bits (b2n: b, b+1; n2b: b, b-1).
    const uint32_t quads = words >> 2;
    uint32_t stage = first_stage;
    for (; stage + 1u <= last_stage; stage += 2u) {
        const uint32_t bit1 = B2n ? stage - 1u : log_n - stage;
        const uint32_t bit2 = B2n ? stage : log_n - stage - 1u;
        const uint32_t low = bit1 < bit2 ? bit1 : bit2;
        for (uint32_t p = t; p < quads; p += kFftSmallThreads) {
            // Insert zeros at bits low and low+1.
            const uint32_t base =
                ((p >> low) << (low + 2u)) | (p & ((1u << low) - 1u));
            const uint32_t i0 = base;
            const uint32_t i1 = base | (1u << bit1);
            const uint32_t i2 = base | (1u << bit2);
            const uint32_t i3 = i1 | i2;
            M31 a = values[i0], b = values[i1], c = values[i2], d = values[i3];
            const uint32_t l0 = i0 & mask, l2 = i2 & mask;
            const M31 w0 = fft_small_twiddle<B2n>(twiddles, log_n, stage, l0);
            const M31 w2 = fft_small_twiddle<B2n>(twiddles, log_n, stage, l2);
            fft_small_butterfly<B2n>(a, b, w0);
            fft_small_butterfly<B2n>(c, d, w2);
            const uint32_t l1 = i1 & mask;
            const M31 v0 = fft_small_twiddle<B2n>(twiddles, log_n, stage + 1u, l0);
            const M31 v1 = fft_small_twiddle<B2n>(twiddles, log_n, stage + 1u, l1);
            fft_small_butterfly<B2n>(a, c, v0);
            fft_small_butterfly<B2n>(b, d, v1);
            if (B2n && stage + 1u == log_n) {
                a = m31_mul(a, scale);
                b = m31_mul(b, scale);
                c = m31_mul(c, scale);
                d = m31_mul(d, scale);
            }
            values[i0] = a;
            values[i1] = b;
            values[i2] = c;
            values[i3] = d;
        }
        __syncthreads();
    }
    if (stage <= last_stage) {
        const uint32_t bit = B2n ? stage - 1u : log_n - stage;
        for (uint32_t p = t; p < (words >> 1); p += kFftSmallThreads) {
            const uint32_t i0 =
                ((p >> bit) << (bit + 1u)) | (p & ((1u << bit) - 1u));
            const uint32_t i1 = i0 | (1u << bit);
            M31 a = values[i0], b = values[i1];
            fft_small_butterfly<B2n>(
                a, b, fft_small_twiddle<B2n>(twiddles, log_n, stage, i0 & mask));
            if (B2n && stage == log_n) {
                a = m31_mul(a, scale);
                b = m31_mul(b, scale);
            }
            values[i0] = a;
            values[i1] = b;
        }
        __syncthreads();
    }
    for (uint32_t e = t; e < words; e += kFftSmallThreads) {
        M31 *column = outputs.column(first_column + (e >> log_n));
        column[e & mask] = values[e];
        if constexpr (Duplicate) column[(e & mask) + (1u << log_n)] = values[e];
    }
}

// Bench/A-B override: -1 follows STWO_RV64_M8_FFT_SMALL (default on; "0"
// restores the stagewise kernels, bit-identical either way).
inline int g_fft_small_override = -1;
inline bool fft_small_enabled(uint32_t log_n) {
    if (log_n > kFftSmallMaxLogN || log_n < kMinLogN) return false;
    if (g_fft_small_override >= 0) return g_fft_small_override != 0;
    static const bool enabled = [] {
        const char *value = std::getenv("STWO_RV64_M8_FFT_SMALL");
        return !(value && value[0] == '0');
    }();
    return enabled;
}

template <bool B2n, bool Duplicate>
inline cudaError_t launch_fft_small(
    ColumnSlab<const M31> inputs,
    ColumnSlab<M31> outputs,
    uint32_t log_n,
    uint32_t column_count,
    uint32_t first_stage,
    uint32_t last_stage,
    const M31 *twiddles,
    cudaStream_t stream) {
    if (log_n > kFftSmallMaxLogN || log_n < kMinLogN || column_count == 0 ||
        first_stage == 0 || last_stage > log_n || first_stage > last_stage)
        return STWO_CUDA_ERROR_INVALID_CONFIGURATION;
    const uint32_t log_columns = kFftSmallTileLog - log_n;
    const uint32_t blocks =
        (column_count + (1u << log_columns) - 1u) >> log_columns;
    fft_small_columns<B2n, Duplicate><<<blocks, kFftSmallThreads, 0, stream>>>(
        inputs, outputs, log_n, column_count, first_stage, last_stage,
        twiddles, m31_inverse_power_of_two(log_n));
    return cudaPeekAtLastError();
}

}  // namespace stwo::cuda::transform

#endif
