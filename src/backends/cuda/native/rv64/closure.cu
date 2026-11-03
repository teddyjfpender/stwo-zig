#include "closure.h"
#include "custody.cuh"
#include "om31.cuh"
namespace stwo::cuda::rv64 {
__global__ void close_local(const uint32_t *roots, uint32_t count,
                            uint32_t *status) {
  OM31 numerator = zero(), denominator = one();
  for (uint32_t i = 0; i < count; ++i) {
    const OM31 n = from_words(roots + 16 * i),
               d = from_words(roots + 16 * i + 8);
    if (!canonical(n) || !canonical(d)) {
      atomicOr(status, 2u);
      return;
    }
    if (is_zero(d)) {
      atomicOr(status, 4u);
      return;
    }
    numerator = add(mul(numerator, d), mul(n, denominator));
    denominator = mul(denominator, d);
  }
  if (!is_zero(numerator))
    atomicOr(status, 8u);
}
__global__ void close_global(const uint32_t *claims, const uint32_t *relations,
                             uint32_t count, uint32_t *status) {
  const uint32_t relation = blockIdx.x, bit = 1u << relation;
  OM31 sum = zero();
  for (uint32_t i = threadIdx.x; i < count; i += blockDim.x) {
    const uint32_t mask = relations[i];
    if (mask & ~7u)
      atomicOr(status, 256u);
    OM31 value = from_words(claims + uint64_t(i) * 24 + 8 * relation);
    if (!canonical(value)) {
      atomicOr(status, 2u);
      value = zero();
    }
    if (!(mask & bit) && !is_zero(value))
      atomicOr(status, 128u);
    sum = add(sum, value);
  }
  __shared__ OM31 partial[128];
  partial[threadIdx.x] = sum;
  __syncthreads();
  for (uint32_t step = 64; step; step >>= 1) {
    if (threadIdx.x < step)
      partial[threadIdx.x] =
          add(partial[threadIdx.x], partial[threadIdx.x + step]);
    __syncthreads();
  }
  if (threadIdx.x == 0 && !is_zero(partial[0]))
    atomicOr(status, 16u << relation);
}
} // namespace stwo::cuda::rv64
extern "C" int stwo_rv64_local_close_on(void *ctx, uint32_t lane,
                                        const uint32_t *roots, uint32_t count,
                                        uint32_t *status) {
  using namespace stwo::cuda::rv64;
  if (!count || count > 64)
    return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if (!c.range(roots, uint64_t(count) * 16, false) || !c.range(status, 1, true))
    return c.status;
  close_local<<<1, 1, 0, c.stream>>>(roots, count, status);
  return int(cudaPeekAtLastError());
}
extern "C" int stwo_rv64_global_close_on(void *ctx, uint32_t lane,
                                         const uint32_t *claims,
                                         const uint32_t *relations,
                                         uint32_t count, uint32_t *status) {
  using namespace stwo::cuda::rv64;
  if (!count || count > 65535)
    return int(cudaErrorInvalidValue);
  Custody c(ctx, lane);
  if (!c.range(claims, uint64_t(count) * 24, false) ||
      !c.range(relations, count, false) || !c.range(status, 1, true))
    return c.status;
  close_global<<<3, 128, 0, c.stream>>>(claims, relations, count, status);
  return int(cudaPeekAtLastError());
}
