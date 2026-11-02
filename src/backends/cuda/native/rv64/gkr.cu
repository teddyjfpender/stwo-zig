#include "om31.cuh"
#include "eq_tile.cuh"
#include "fold_sum.cuh"
#include "custody.cuh"
#include "reduce.cuh"

namespace stwo::cuda::rv64 {
__device__ __forceinline__ OM31 read(StwoRv64Plane p, uint32_t i) {
    return p.coordinates == 1 ? base(p.words[i]) : load(p.words, p.stride, i);
}
__device__ __forceinline__ Fraction read_fraction(StwoRv64Plane n, StwoRv64Plane d,
                                                  uint32_t i) {
    return {read(n, i), load(d.words, d.stride, i)};
}
__global__ void project(StwoRv64Plane tuples, StwoRv64Plane weights, StwoRv64Plane active,
                        uint32_t count, uint32_t arity, const uint32_t* challenges,
                        StwoRv64Plane n, StwoRv64Plane d, uint32_t* status) {
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= count) return;
    if (active.words[i] != 1) {
        if (active.words[i] != 0) atomicOr(status, 1u);
        n.words[i] = 0;
        store(d.words, d.stride, i, one());
        return;
    }
    OM31 denominator = from_words(challenges);
    bool valid = canonical(denominator) && weights.words[i] < q::kPrime;
    for (uint32_t j = 0; j < arity; ++j) {
        const uint32_t t = tuples.words[j * tuples.stride + i];
        const OM31 coefficient = from_words(challenges + 8 * (j + 1));
        valid = valid && t < q::kPrime && canonical(coefficient);
        // Never run arithmetic on noncanonical words, even for a doomed job.
        if (valid) denominator = sub(denominator, scale(coefficient, t));
    }
    if (!valid || is_zero(denominator)) {
        atomicOr(status, !valid ? 1u : 2u);
        n.words[i] = 0;
        store(d.words, d.stride, i, one());
        return;
    }
    n.words[i] = weights.words[i];
    store(d.words, d.stride, i, denominator);
}
template <bool BaseNumerator, uint32_t Levels>
__global__ void layer(StwoRv64Plane n, StwoRv64Plane d, uint32_t out_count, StwoRv64Plane on,
                      StwoRv64Plane od) {
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= out_count) return;
    const uint32_t first = i << Levels;
    Fraction result;
    if constexpr (BaseNumerator) {
        result = combine_base(n.words[first], load(d.words, d.stride, first),
                              n.words[first + 1], load(d.words, d.stride, first + 1));
        if constexpr (Levels == 2)
            result = combine(
                result, combine_base(n.words[first + 2], load(d.words, d.stride, first + 2),
                                     n.words[first + 3], load(d.words, d.stride, first + 3)));
    } else {
        result = combine(read_fraction(n, d, first), read_fraction(n, d, first + 1));
        if constexpr (Levels == 2)
            result = combine(result, combine(read_fraction(n, d, first + 2),
                                             read_fraction(n, d, first + 3)));
    }
    store(on.words, on.stride, i, result.n);
    store(od.words, od.stride, i, result.d);
}
__global__ void fold_layer(StwoRv64Plane n, StwoRv64Plane d, uint32_t half, const uint32_t* x,
                           StwoRv64Plane on, StwoRv64Plane od) {
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= half) return;
    const auto a = read_fraction(n, d, i), b = read_fraction(n, d, i + half);
    const auto assignment = from_words(x);
    store(on.words, on.stride, i, fold(a.n, b.n, assignment));
    store(od.words, od.stride, i, fold(a.d, b.d, assignment));
}
__global__ void eq_seed(const uint32_t* y, uint32_t variables, StwoRv64Plane output) {
    store(output.words, output.stride, 0, variables ? sub(one(), from_words(y)) : one());
}
__global__ void eq_expand(const uint32_t* y, uint32_t coordinate_index, uint32_t half,
                          StwoRv64Plane output) {
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= half) return;
    const OM31 v = load(output.words, output.stride, i);
    const OM31 x = from_words(y + 8 * coordinate_index);
    // Each thread owns i and i+half; every input lies in the old prefix.
    store(output.words, output.stride, i, mul(v, sub(one(), x)));
    store(output.words, output.stride, i + half, mul(v, x));
}
template <uint32_t Levels>
__global__ void eq_tile_kernel(const uint32_t* point, uint32_t first, uint32_t half,
                               StwoRv64Plane output) {
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= half) return;
    expand_eq_tile<Levels>(load(output.words, output.stride, i), point, first, output.words,
                           output.stride, i, half);
}
// Eight coalesced coordinate reductions; no extension-field atomics, no
// global single-block bottleneck for the large input stage.
__device__ __forceinline__ void block_sum(Pair v, StwoRv64Plane output) {
    const auto result = block_pair_sum<threads>(v);
    if (!threadIdx.x) {
        store(output.words, output.stride, 2 * blockIdx.x, result.at0);
        store(output.words, output.stride, 2 * blockIdx.x + 1, result.at2);
    }
}
template <bool BaseNumerator>
__global__ void sum_first(StwoRv64Plane n, StwoRv64Plane d, uint32_t terms, StwoRv64Plane eq,
                          const uint32_t* lambda, StwoRv64Plane out) {
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    Pair result{zero(), zero()};
    if (i < terms) {
        const uint32_t j = 2 * i, k = 2 * (terms + i);
        const auto e = load(eq.words, eq.stride, i), l = from_words(lambda);
        if constexpr (BaseNumerator)
            result = sum_term_base(n.words[j], load(d.words, d.stride, j), n.words[j + 1],
                                   load(d.words, d.stride, j + 1), n.words[k],
                                   load(d.words, d.stride, k), n.words[k + 1],
                                   load(d.words, d.stride, k + 1), e, l);
        else
            result = sum_term(read_fraction(n, d, j), read_fraction(n, d, j + 1),
                              read_fraction(n, d, k), read_fraction(n, d, k + 1), e, l);
    }
    // Tail threads also participate in every shuffle and barrier.
    block_sum(result, out);
}
// Fold and form the NEXT round's raw terms before evicting values.
__global__ void fold_sum_first(StwoRv64Plane n, StwoRv64Plane d, uint32_t count,
                               const uint32_t* x, StwoRv64Plane on, StwoRv64Plane od,
                               StwoRv64Plane eq, const uint32_t* lambda, StwoRv64Plane out) {
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    Pair result{zero(), zero()};
    if (i < count / 8)
        result = fold_sum_tile(n, d, count, i, from_words(x), load(eq.words, eq.stride, i),
                               from_words(lambda), on, od);
    block_sum(result, out);
}
// Independent at0/at2 grids trade repeated first-half loads for shorter
// live ranges and more schedulable blocks. Keep the combined route available
// until real-device shape sweeps decide which strategy wins.
__device__ __forceinline__ Fraction extrapolated(StwoRv64Plane n, StwoRv64Plane d, uint32_t j,
                                                 uint32_t k) {
    const OM31 n0 = load(n.words, n.stride, j), n1 = load(n.words, n.stride, k);
    const OM31 d0 = load(d.words, d.stride, j), d1 = load(d.words, d.stride, k);
    return {sub(add(n1, n1), n0), sub(add(d1, d1), d0)};
}
__device__ __forceinline__ OM31 block_sum_one(OM31 value) {
    __shared__ uint32_t partial[8][threads / 32];
    value = warp_sum(value);
    const uint32_t lane = threadIdx.x & 31, warp = threadIdx.x >> 5;
    if (!lane)
        for (uint32_t c = 0; c < 8; ++c) partial[c][warp] = coordinate(value, c);
    __syncthreads();
    if (warp) return zero();
    uint32_t words[8]{};
    if (lane < threads / 32)
        for (uint32_t c = 0; c < 8; ++c) words[c] = partial[c][lane];
    return warp_sum(from_words(words));
}
__global__ void sum_secure_split(StwoRv64Plane n, StwoRv64Plane d, uint32_t terms,
                                 StwoRv64Plane eq, const uint32_t* lambda,
                                 StwoRv64Plane output) {
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    OM31 value = zero();
    if (i < terms) {
        const uint32_t j = 2 * i, k = 2 * (terms + i);
        Fraction pair;
        if (blockIdx.y == 0)
            pair = combine(read_fraction(n, d, j), read_fraction(n, d, j + 1));
        else
            pair = combine(extrapolated(n, d, j, k), extrapolated(n, d, j + 1, k + 1));
        value = mul(load(eq.words, eq.stride, i), add(pair.n, mul(from_words(lambda), pair.d)));
    }
    const OM31 result = block_sum_one(value);
    if (threadIdx.x == 0)
        store(output.words, output.stride, 2 * blockIdx.x + blockIdx.y, result);
}
__global__ void sum_reduce(StwoRv64Plane in, uint32_t pairs, StwoRv64Plane out) {
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    Pair result{zero(), zero()};
    if (i < pairs)
        result = {load(in.words, in.stride, 2 * i), load(in.words, in.stride, 2 * i + 1)};
    block_sum(result, out);
}
inline uint32_t blocks(uint32_t n) {
    return (n + threads - 1) / threads;
}
inline int launch_status() {
    return int(cudaPeekAtLastError());
}
}  // namespace stwo::cuda::rv64
using namespace stwo::cuda::rv64;
extern "C" int stwo_rv64_gkr_project_on(void* context, uint32_t lane, StwoRv64Plane tuples,
                                        StwoRv64Plane weights, StwoRv64Plane active,
                                        uint32_t count, uint32_t arity,
                                        const uint32_t* challenges, StwoRv64Plane n,
                                        StwoRv64Plane d, uint32_t* status) {
    if (!count || count > max_count || !arity || arity > 32) return int(cudaErrorInvalidValue);
    Custody c(context, lane);
    if (!c.plane(tuples, count, arity, false) || !c.plane(weights, count, 1, false) ||
        !c.plane(active, count, 1, false) || !c.range(challenges, 8ull * (arity + 1), false) ||
        !c.plane(n, count, 1, true) || !c.plane(d, count, 8, true) || !c.range(status, 1, true))
        return c.status;
    project<<<blocks(count), threads, 0, c.stream>>>(tuples, weights, active, count, arity,
                                                     challenges, n, d, status);
    return launch_status();
}
extern "C" int stwo_rv64_gkr_layer_on(void* context, uint32_t lane, StwoRv64Plane n,
                                      StwoRv64Plane d, uint32_t count, uint32_t levels,
                                      StwoRv64Plane on, StwoRv64Plane od) {
    if (!power2(count) || count > max_count || levels < 1 || levels > 2 ||
        count < (1u << levels))
        return int(cudaErrorInvalidValue);
    Custody c(context, lane);
    if (!c.numerator(n, count) || !c.plane(d, count, 8, false) ||
        !c.plane(on, count >> levels, 8, true) || !c.plane(od, count >> levels, 8, true))
        return c.status;
    const uint32_t grid = blocks(count >> levels);
    if (n.coordinates == 1) {
        if (levels == 1)
            layer<true, 1><<<grid, threads, 0, c.stream>>>(n, d, count >> levels, on, od);
        else
            layer<true, 2><<<grid, threads, 0, c.stream>>>(n, d, count >> levels, on, od);
    } else {
        if (levels == 1)
            layer<false, 1><<<grid, threads, 0, c.stream>>>(n, d, count >> levels, on, od);
        else
            layer<false, 2><<<grid, threads, 0, c.stream>>>(n, d, count >> levels, on, od);
    }
    return launch_status();
}
extern "C" int stwo_rv64_gkr_fold_on(void* context, uint32_t lane, StwoRv64Plane n,
                                     StwoRv64Plane d, uint32_t count, const uint32_t* x,
                                     StwoRv64Plane on, StwoRv64Plane od) {
    if (!power2(count) || count < 2 || count > max_count) return int(cudaErrorInvalidValue);
    Custody c(context, lane);
    if (!c.numerator(n, count) || !c.plane(d, count, 8, false) || !c.range(x, 8, false) ||
        !c.plane(on, count / 2, 8, true) || !c.plane(od, count / 2, 8, true))
        return c.status;
    fold_layer<<<blocks(count / 2), threads, 0, c.stream>>>(n, d, count / 2, x, on, od);
    return launch_status();
}
extern "C" int stwo_rv64_gkr_eq_on(void* context, uint32_t lane, const uint32_t* y,
                                   uint32_t variables, StwoRv64Plane output) {
    if (variables > 28) return int(cudaErrorInvalidValue);
    const uint32_t count = variables ? 1u << (variables - 1) : 1;
    Custody c(context, lane);
    if ((variables && !c.range(y, 8ull * variables, false)) || !c.plane(output, count, 8, true))
        return c.status;
    eq_seed<<<1, 1, 0, c.stream>>>(y, variables, output);
    int status = launch_status();
    for (uint32_t at = variables, half = 1; !status && at > 1; half <<= 1) {
        --at;
        eq_expand<<<blocks(half), threads, 0, c.stream>>>(y, at, half, output);
        status = launch_status();
    }
    return status;
}
extern "C" int stwo_rv64_gkr_eq_fused_on(void* context, uint32_t lane, const uint32_t* point,
                                         uint32_t variables, StwoRv64Plane output) {
    if (variables > 28) return int(cudaErrorInvalidValue);
    const uint32_t count = variables ? 1u << (variables - 1) : 1;
    Custody c(context, lane);
    if ((variables && !c.range(point, 8ull * variables, false)) ||
        !c.plane(output, count, 8, true))
        return c.status;
    eq_seed<<<1, 1, 0, c.stream>>>(point, variables, output);
    int status = launch_status();
    uint32_t remaining = variables ? variables - 1 : 0, half = 1;
    while (!status && remaining) {
        const uint32_t levels = remaining >= 4 ? 4 : remaining;
        const uint32_t first = remaining + 1 - levels;
        switch (levels) {
            case 4:
                eq_tile_kernel<4>
                    <<<blocks(half), threads, 0, c.stream>>>(point, first, half, output);
                break;
            case 3:
                eq_tile_kernel<3>
                    <<<blocks(half), threads, 0, c.stream>>>(point, first, half, output);
                break;
            case 2:
                eq_tile_kernel<2>
                    <<<blocks(half), threads, 0, c.stream>>>(point, first, half, output);
                break;
            default:
                eq_tile_kernel<1>
                    <<<blocks(half), threads, 0, c.stream>>>(point, first, half, output);
                break;
        }
        status = launch_status();
        remaining -= levels;
        half <<= levels;
    }
    return status;
}
static int finish_sum(cudaStream_t stream, uint32_t groups, StwoRv64Plane a, StwoRv64Plane b,
                      StwoRv64Plane out) {
    int status = launch_status();
    auto current = a, next = b;
    for (uint32_t pairs = groups; !status && pairs > 1;) {
        const uint32_t grid = blocks(pairs);
        sum_reduce<<<grid, threads, 0, stream>>>(current, pairs, grid == 1 ? out : next);
        status = launch_status();
        pairs = grid;
        const auto old = current;
        current = next;
        next = old;
    }
    return status;
}
extern "C" int stwo_rv64_gkr_fold_sum_on(void* context, uint32_t lane, StwoRv64Plane n,
                                         StwoRv64Plane d, uint32_t count, const uint32_t* x,
                                         StwoRv64Plane on, StwoRv64Plane od, StwoRv64Plane eq,
                                         const uint32_t* lambda, StwoRv64Plane a,
                                         StwoRv64Plane b, StwoRv64Plane out) {
    if (!power2(count) || count < 8 || count > max_count) return int(cudaErrorInvalidValue);
    const uint32_t groups = blocks(count / 8);
    Custody c(context, lane);
    if (!c.numerator(n, count) || !c.plane(d, count, 8, false) || !c.range(x, 8, false) ||
        !c.plane(on, count / 2, 8, true) || !c.plane(od, count / 2, 8, true) ||
        !c.plane(eq, count / 8, 8, false) || !c.range(lambda, 8, false) ||
        !c.plane(a, 2 * groups, 8, true) || !c.plane(b, 2 * groups, 8, true) ||
        !c.plane(out, 2, 8, true))
        return c.status;
    fold_sum_first<<<groups, threads, 0, c.stream>>>(n, d, count, x, on, od, eq, lambda,
                                                     groups == 1 ? out : a);
    return finish_sum(c.stream, groups, a, b, out);
}
static int sum_on_impl(bool split_secure, void* context, uint32_t lane, StwoRv64Plane n,
                       StwoRv64Plane d, uint32_t count, StwoRv64Plane eq,
                       const uint32_t* lambda, StwoRv64Plane a, StwoRv64Plane b,
                       StwoRv64Plane out) {
    if (!power2(count) || count < 4 || count > max_count) return int(cudaErrorInvalidValue);
    const uint32_t groups = blocks(count / 4);
    Custody c(context, lane);
    if (!c.numerator(n, count) || !c.plane(d, count, 8, false) ||
        !c.plane(eq, count / 4, 8, false) || !c.range(lambda, 8, false) ||
        !c.plane(a, 2 * groups, 8, true) || !c.plane(b, 2 * groups, 8, true) ||
        !c.plane(out, 2, 8, true))
        return c.status;
    if (n.coordinates == 1)
        sum_first<true><<<groups, threads, 0, c.stream>>>(n, d, count / 4, eq, lambda,
                                                          groups == 1 ? out : a);
    else if (split_secure)
        sum_secure_split<<<dim3(groups, 2), threads, 0, c.stream>>>(n, d, count / 4, eq, lambda,
                                                                    groups == 1 ? out : a);
    else
        sum_first<false><<<groups, threads, 0, c.stream>>>(n, d, count / 4, eq, lambda,
                                                           groups == 1 ? out : a);
    return finish_sum(c.stream, groups, a, b, out);
}

extern "C" int stwo_rv64_gkr_sum_on(void* context, uint32_t lane, StwoRv64Plane n,
                                    StwoRv64Plane d, uint32_t count, StwoRv64Plane eq,
                                    const uint32_t* lambda, StwoRv64Plane a, StwoRv64Plane b,
                                    StwoRv64Plane out) {
    return sum_on_impl(false, context, lane, n, d, count, eq, lambda, a, b, out);
}
extern "C" int stwo_rv64_gkr_sum_split_on(void* context, uint32_t lane, StwoRv64Plane n,
                                          StwoRv64Plane d, uint32_t count, StwoRv64Plane eq,
                                          const uint32_t* lambda, StwoRv64Plane a,
                                          StwoRv64Plane b, StwoRv64Plane out) {
    return sum_on_impl(true, context, lane, n, d, count, eq, lambda, a, b, out);
}
