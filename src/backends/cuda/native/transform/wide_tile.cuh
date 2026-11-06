#ifndef STWO_ZIG_CUDA_WIDE_TILE_CUH
#define STWO_ZIG_CUDA_WIDE_TILE_CUH

// Shared index helpers for the register-blocked strided FFT passes
// (b2n_wide_strided in b2n_fused.cuh, n2b_wide_strided_rows in
// n2b_smem.cuh). A strided tile is 2^LaneLog contiguous words (the lane axis,
// never permuted) x 2^High points of the high stride; each of its
// 2^(High+LaneLog-5) threads holds 32 values (5 "k" bits) and owns
// High - 5 "j" bits, and a phase applies up to five stages to the k bits.

#include "../common/provider_compat.cuh"

#include <stddef.h>
#include <stdint.h>

namespace stwo::cuda::transform {

// Padded shared-memory index: conflict-free for every phase mapping below.
__device__ __forceinline__ uint32_t wide_tile_pad(uint32_t e) {
    return e + (e >> 5);
}

// Bit deposit for strided phase P of a High-bit tile: c = wide_phase_bits
// h bits starting at first_bit (B2N: 5P upwards; N2B: High-5P-c, from the
// top) come from k bits [0, c); the remaining h bits, in increasing order, take
// the High - 5 thread bits j first (so a warp's j values are adjacent rows:
// conflict-free padded shared memory) and then k bits c..4.
__host__ __device__ constexpr uint32_t wide_phase_count(uint32_t high) {
    return (high + 4u) / 5u;
}
__host__ __device__ constexpr uint32_t wide_phase_bits(
    uint32_t high, uint32_t phase) {
    return high - 5u * phase < 5u ? high - 5u * phase : 5u;
}
template <uint32_t High>
__host__ __device__ __forceinline__ constexpr uint32_t wide_deposit(
    uint32_t phase, uint32_t first_bit, uint32_t k, uint32_t j) {
    const uint32_t count = wide_phase_bits(High, phase);
    uint32_t h = (k & ((1u << count) - 1u)) << first_bit;
    uint32_t source_j = 0;
    uint32_t source_k = count;
#pragma unroll
    for (uint32_t bit = 0; bit < High; ++bit) {
        if (bit >= first_bit && bit < first_bit + count) continue;
        if (source_j < High - 5u) {
            h |= ((j >> source_j) & 1u) << bit;
            ++source_j;
        } else {
            h |= ((k >> source_k) & 1u) << bit;
            ++source_k;
        }
    }
    return h;
}

template <uint32_t High, uint32_t LaneLog>
struct WideStridedShape {
    static_assert(High >= 5u && High <= 11u, "strided pass height");
    static constexpr uint32_t threads = 1u << (High + LaneLog - 5u);
    static constexpr uint32_t words = 1u << (High + LaneLog);
    static constexpr size_t bytes = sizeof(uint32_t) * (words + words / 32u);
};

}  // namespace stwo::cuda::transform

#endif
