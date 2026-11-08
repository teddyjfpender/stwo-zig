#ifndef STWO_CUDA_RV64_PROJECTION_CUH
#define STWO_CUDA_RV64_PROJECTION_CUH
#include "composition.cuh"
namespace stwo::cuda::rv64 {
// An invalid input must not leave uninitialized holes for queued consumers.
// The owner checks this sticky verdict before publishing any proof.
__device__ __forceinline__ void
invalid_projection_row(uint32_t *n, uint32_t *d, uint32_t row, uint32_t lanes,
                       uint64_t stride, uint32_t *status) {
  for (uint32_t lane = 0; lane < lanes; ++lane) {
    const uint64_t at = uint64_t(row) * lanes + lane;
    n[at] = 0;
    store(d, stride, at, one());
  }
  atomicOr(status, 1u);
}
} // namespace stwo::cuda::rv64
#endif
