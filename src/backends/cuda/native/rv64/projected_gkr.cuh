#pragma once
#include "custody.cuh"
#include "om31.cuh"
#include "reduce.cuh"

// Implicit, class-specific fractions for both product-tree ingress and the
// final GKR layer. Source is a small by-value descriptor with:
//   bool validate(Custody&, uint32_t count) const;    (host, all source ranges)
//   __device__ Fraction get(uint32_t index) const;   (includes padded 0/1 lanes)
// get() preserves every real pole; a source may atomically poison its own
// verdict but must never turn a real zero-weight 0/0 into a padding fraction.
namespace stwo::cuda::rv64::projected {
constexpr uint32_t block_threads = 128;
inline uint32_t blocks(uint32_t n) { return (n + block_threads - 1) / block_threads; }
inline bool geometry(uint32_t count) { return power2(count) && count >= 2 && count <= max_count; }

template<class Source>
__global__ void layer_kernel(Source source, uint32_t count, uint32_t levels,
                             StwoRv64Plane on, StwoRv64Plane od) {
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= (count >> levels)) return;
  const uint32_t first = i << levels;
  auto value = combine(source.get(first), source.get(first + 1));
  if (levels == 2) value = combine(value, combine(source.get(first + 2), source.get(first + 3)));
  store(on.words, on.stride, i, value.n); store(od.words, od.stride, i, value.d);
}
template<class Source>
__global__ void fold_kernel(Source source, uint32_t half, const uint32_t *x,
                            StwoRv64Plane on, StwoRv64Plane od) {
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= half) return;
  const auto a = source.get(i), b = source.get(i + half);
  const auto r = from_words(x);
  store(on.words, on.stride, i, fold(a.n, b.n, r));
  store(od.words, od.stride, i, fold(a.d, b.d, r));
}
__device__ __forceinline__ void store_sum(Pair v, StwoRv64Plane out) {
  const auto sum = block_pair_sum<block_threads>(v);
  if (!threadIdx.x) {
    store(out.words, out.stride, 2 * blockIdx.x, sum.at0);
    store(out.words, out.stride, 2 * blockIdx.x + 1, sum.at2);
  }
}
template<class Source>
__global__ void sum_kernel(Source source, uint32_t terms, StwoRv64Plane eq,
                           const uint32_t *lambda, StwoRv64Plane out) {
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  Pair value{zero(), zero()};
  if (i < terms) {
    const uint32_t j = 2 * i, k = 2 * (terms + i);
    value = sum_term(source.get(j), source.get(j + 1), source.get(k), source.get(k + 1),
                     load(eq.words, eq.stride, i), from_words(lambda));
  }
  store_sum(value, out);
}
static __global__ void reduce_kernel(StwoRv64Plane in, uint32_t pairs, StwoRv64Plane out) {
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  Pair value{zero(), zero()};
  if (i < pairs) value = {load(in.words, in.stride, 2 * i), load(in.words, in.stride, 2 * i + 1)};
  store_sum(value, out);
}
template<class Source>
__global__ void mask_kernel(Source source, uint32_t *out) {
  const uint32_t c = threadIdx.x;
  if (c >= 8) return;
  const auto a = source.get(0), b = source.get(1);
  out[c] = coordinate(a.n, c); out[8 + c] = coordinate(b.n, c);
  out[16 + c] = coordinate(a.d, c); out[24 + c] = coordinate(b.d, c);
}
template<class Source>
int validate_on(void *ctx, uint32_t lane, const void *raw, uint32_t count) {
  if (!raw || !geometry(count)) return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  const auto source = *static_cast<const Source *>(raw);
  if (!source.validate(c, count)) return c.status ? c.status : int(cudaErrorInvalidValue);
  return c.status;
}
template<class Source>
int layer_on(void *ctx, uint32_t lane, const void *raw, uint32_t count, uint32_t levels,
             StwoRv64Plane on, StwoRv64Plane od) {
  if (!raw || !geometry(count) || levels < 1 || levels > 2 || count < (1u << levels)) return int(cudaErrorInvalidValue);
  Custody c(ctx, lane); const auto source = *static_cast<const Source *>(raw);
  if (!source.validate(c, count) || !c.plane(on, count >> levels, 8, true) || !c.plane(od, count >> levels, 8, true))
    return c.status ? c.status : int(cudaErrorInvalidValue);
  layer_kernel<<<blocks(count >> levels), block_threads, 0, c.stream>>>(source, count, levels, on, od);
  return int(cudaPeekAtLastError());
}
template<class Source>
int fold_on(void *ctx, uint32_t lane, const void *raw, uint32_t count, const uint32_t *x,
            StwoRv64Plane on, StwoRv64Plane od) {
  if (!raw || !geometry(count)) return int(cudaErrorInvalidValue);
  Custody c(ctx, lane); const auto source = *static_cast<const Source *>(raw);
  if (!source.validate(c, count) || !c.range(x, 8, false) || !c.plane(on, count / 2, 8, true) || !c.plane(od, count / 2, 8, true))
    return c.status ? c.status : int(cudaErrorInvalidValue);
  fold_kernel<<<blocks(count / 2), block_threads, 0, c.stream>>>(source, count / 2, x, on, od);
  return int(cudaPeekAtLastError());
}
template<class Source>
int sum_on(void *ctx, uint32_t lane, const void *raw, uint32_t count, StwoRv64Plane eq,
           const uint32_t *lambda, StwoRv64Plane a, StwoRv64Plane b, StwoRv64Plane out) {
  if (!raw || !geometry(count) || count < 4) return int(cudaErrorInvalidValue);
  const uint32_t groups = blocks(count / 4);
  Custody c(ctx, lane); const auto source = *static_cast<const Source *>(raw);
  if (!source.validate(c, count) || !c.plane(eq, count / 4, 8, false) || !c.range(lambda, 8, false) ||
      !c.plane(a, 2 * groups, 8, true) || !c.plane(b, 2 * groups, 8, true) || !c.plane(out, 2, 8, true))
    return c.status ? c.status : int(cudaErrorInvalidValue);
  sum_kernel<<<groups, block_threads, 0, c.stream>>>(source, count / 4, eq, lambda, groups == 1 ? out : a);
  int status = int(cudaPeekAtLastError());
  auto current = a, next = b;
  for (uint32_t pairs = groups; !status && pairs > 1;) {
    const uint32_t grid = blocks(pairs);
    reduce_kernel<<<grid, block_threads, 0, c.stream>>>(current, pairs, grid == 1 ? out : next);
    status = int(cudaPeekAtLastError()); pairs = grid;
    const auto old = current; current = next; next = old;
  }
  return status;
}
template<class Source>
int mask_on(void *ctx, uint32_t lane, const void *raw, uint32_t *out) {
  if (!raw) return int(cudaErrorInvalidValue);
  Custody c(ctx, lane); const auto source = *static_cast<const Source *>(raw);
  if (!source.validate(c, 2) || !c.range(out, 32, true)) return c.status ? c.status : int(cudaErrorInvalidValue);
  mask_kernel<<<1, 32, 0, c.stream>>>(source, out);
  return int(cudaPeekAtLastError());
}
} // namespace stwo::cuda::rv64::projected
