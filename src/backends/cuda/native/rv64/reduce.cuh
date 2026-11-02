#pragma once
#include "om31.cuh"
namespace stwo::cuda::rv64 {
__device__ __forceinline__ OM31 warp_sum(OM31 v) {
    uint32_t words[8];
    for (uint32_t c = 0; c < 8; ++c) words[c] = coordinate(v, c);
    for (uint32_t delta = 16; delta; delta >>= 1) {
        for (uint32_t c = 0; c < 8; ++c)
            words[c] = q::add(words[c], __shfl_down_sync(0xffffffffu, words[c], delta));
    }
    return from_words(words);
}
// All threads enter. Only thread zero owns the returned sum; neutral tails
// participate in every full-warp shuffle and the inter-warp barrier.
template <uint32_t Threads>
__device__ __forceinline__ Pair block_pair_sum(Pair v) {
    static_assert(Threads >= 32 && Threads % 32 == 0 && Threads <= 1024, "full warps");
    __shared__ uint32_t partial[2][8][Threads / 32];
    v.at0 = warp_sum(v.at0);
    v.at2 = warp_sum(v.at2);
    const uint32_t lane = threadIdx.x & 31, warp = threadIdx.x >> 5;
    if (!lane)
        for (uint32_t c = 0; c < 8; ++c) {
            partial[0][c][warp] = coordinate(v.at0, c);
            partial[1][c][warp] = coordinate(v.at2, c);
        }
    __syncthreads();
    if (warp) return {zero(), zero()};
    uint32_t a[8]{}, b[8]{};
    if (lane < Threads / 32)
        for (uint32_t c = 0; c < 8; ++c) {
            a[c] = partial[0][c][lane];
            b[c] = partial[1][c][lane];
        }
    return {warp_sum(from_words(a)), warp_sum(from_words(b))};
}
}  // namespace stwo::cuda::rv64
