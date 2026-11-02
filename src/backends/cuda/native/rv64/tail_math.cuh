#pragma once
#include "gkr.h"
#include "round.cuh"
namespace stwo::cuda::rv64 {
// Shared rows use a bijective XOR swizzle. For adjacent pairs, a warp's
// even rows occupy even banks in its first half and odd banks in its second;
// this removes the linear layout's two-way bank conflict without padding.
__host__ __device__ __forceinline__ uint32_t tail_index(uint32_t row) {
    return row ^ (row >> 5);
}
__host__ __device__ __forceinline__ Pair tail_term(StwoRv64Plane n, StwoRv64Plane d,
                                                   uint32_t count, uint32_t i, StwoRv64Plane eq,
                                                   OM31 lambda) {
    const uint32_t terms = count / 4, j = tail_index(2 * i), k = tail_index(2 * (terms + i));
    const Fraction a{load(n.words, n.stride, j), load(d.words, d.stride, j)},
        b{load(n.words, n.stride, j ^ 1u), load(d.words, d.stride, j ^ 1u)},
        c{load(n.words, n.stride, k), load(d.words, d.stride, k)},
        f{load(n.words, n.stride, k ^ 1u), load(d.words, d.stride, k ^ 1u)};
    return sum_term(a, b, c, f, load(eq.words, eq.stride, i), lambda);
}
__host__ __device__ __forceinline__ void tail_fold_row(StwoRv64Plane n, StwoRv64Plane d,
                                                       uint32_t half, uint32_t i, OM31 x) {
    // The swizzle is bijective and preserves each power-of-two prefix.
    const uint32_t at = tail_index(i), other = tail_index(i + half);
    store(n.words, n.stride, at,
          fold(load(n.words, n.stride, at), load(n.words, n.stride, other), x));
    store(d.words, d.stride, at,
          fold(load(d.words, d.stride, at), load(d.words, d.stride, other), x));
}
}  // namespace stwo::cuda::rv64
