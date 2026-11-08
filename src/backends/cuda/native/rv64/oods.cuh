#ifndef STWO_CUDA_RV64_OODS_CUH
#define STWO_CUDA_RV64_OODS_CUH
#include "composition.cuh"
namespace stwo::cuda::rv64 {
// OODS is a single extension-field point, unlike the bulk domain evaluator.
// Share the multiply body to keep AOT compilation and instruction footprint
// bounded across hundreds of residuals. The field arithmetic is unchanged.
static __device__ __noinline__ OM31 oods_mul(OM31 a, OM31 b) {
  return mul(a, b);
}
} // namespace stwo::cuda::rv64
#endif
