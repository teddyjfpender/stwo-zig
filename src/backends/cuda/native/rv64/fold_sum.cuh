#pragma once
#include "gkr.h"
#include "om31.cuh"
namespace stwo::cuda::rv64 {
// A tile owns four output rows and the corresponding eight input rows.
// Input and output planes must be disjoint; no block-to-block dependency.
__host__ __device__ __forceinline__ Fraction fold_store(StwoRv64Plane n, StwoRv64Plane d,
                                                        uint32_t half, uint32_t i, OM31 x,
                                                        StwoRv64Plane on, StwoRv64Plane od) {
    const OM31 a = n.coordinates == 1 ? base(n.words[i]) : load(n.words, n.stride, i);
    const OM31 b =
        n.coordinates == 1 ? base(n.words[i + half]) : load(n.words, n.stride, i + half);
    const Fraction v{fold(a, b, x),
                     fold(load(d.words, d.stride, i), load(d.words, d.stride, i + half), x)};
    store(on.words, on.stride, i, v.n);
    store(od.words, od.stride, i, v.d);
    return v;
}
__host__ __device__ __forceinline__ Pair fold_sum_tile(StwoRv64Plane n, StwoRv64Plane d,
                                                       uint32_t count, uint32_t i, OM31 x,
                                                       OM31 e, OM31 lambda, StwoRv64Plane on,
                                                       StwoRv64Plane od) {
    const uint32_t terms = count / 8, j = 2 * i, k = 2 * (terms + i);
    const auto a = fold_store(n, d, count / 2, j, x, on, od);
    const auto b = fold_store(n, d, count / 2, j + 1, x, on, od);
    const auto c = fold_store(n, d, count / 2, k, x, on, od);
    const auto f = fold_store(n, d, count / 2, k + 1, x, on, od);
    return sum_term(a, b, c, f, e, lambda);
}
}  // namespace stwo::cuda::rv64
