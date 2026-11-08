// M8 native composition (addon, enqueue only): the composition coefficient
// powers alpha^0 .. alpha^(count-1) from the DEVICE-drawn coefficient.
//
// Legacy resident_composition.zig draws alpha on the host and uploads the
// power table built by repeated multiplication (power = power * alpha). Field
// multiplication is exact, so alpha^i by square-and-multiply is the same OM31
// value word for word. The table is consumed from the top (each role takes
// its `constraint_count` powers ending at the running `next`), exactly as the
// host table. A noncanonical alpha latches bit 0 of `status` and writes no
// powers (the job's finish fails on the status word).
#include <cstdint>
#include "rv64/custody.cuh"
#include "rv64/om31.cuh"

namespace stwo::cuda::rv64 {
__global__ void job_native_powers(const uint32_t *alpha_words, uint32_t count, uint32_t *powers,
                                  uint32_t *status) {
  const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= count) return;
  OM31 base = from_words(alpha_words);
  if (!canonical(base)) {
    if (i == 0) atomicOr(status, 1u);
    return;
  }
  uint64_t exponent = i;
  OM31 result = one();
  while (exponent) {
    if (exponent & 1u) result = mul(result, base);
    exponent >>= 1;
    if (exponent) base = mul(base, base);
  }
  store(powers + uint64_t(i) * 8, 1, 0, result);
}
} // namespace stwo::cuda::rv64

extern "C" int stwo_rv64_jobs_native_powers_v1_on(void *context, uint32_t lane, const uint32_t *alpha,
                                                  uint32_t count, uint32_t *powers, uint32_t *status) {
  using namespace stwo::cuda::rv64;
  if (!count || count > (1u << 24)) return int(cudaErrorInvalidValue);
  RangeCustody<4> custody(context, lane);
  if (!custody.range(alpha, 8, false) || !custody.range(powers, uint64_t(count) * 8, true) ||
      !custody.range(status, 1, true))
    return custody.status;
  job_native_powers<<<(count + 127) / 128, 128, 0, custody.stream>>>(alpha, count, powers, status);
  return int(cudaPeekAtLastError());
}
