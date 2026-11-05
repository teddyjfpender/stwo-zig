#ifndef STWO_CUDA_RV64_COMPOSITION_CUH
#define STWO_CUDA_RV64_COMPOSITION_CUH
#include "om31.cuh"
namespace stwo::cuda::rv64 {
__device__ __forceinline__ uint32_t reverse_index(uint32_t i, uint32_t bits) {
  return bits ? __brev(i) >> (32 - bits) : i;
}
// Matches core.utils.offsetBitReversedCircleDomainIndex, on the GLOBAL lifted
// domain. A trace-row offset is not an adjacent storage-row offset.
__device__ __forceinline__ uint32_t composition_mask_row(uint32_t row,
                                                         uint32_t trace_log,
                                                         uint32_t eval_log,
                                                         int offset) {
  if (!offset)
    return row;
  const uint32_t size = 1u << eval_log;
  uint32_t i = reverse_index(row, eval_log);
  if (trace_log == eval_log) {
    const uint32_t coset = i < size / 2 ? 2 * i : 2 * (size - 1 - i) + 1;
    const uint32_t shifted = (coset + uint32_t(offset)) & (size - 1);
    i = (shifted & 1) ? size - 1 - shifted / 2 : shifted / 2;
  } else {
    const uint32_t half = size / 2;
    const uint32_t shift = uint32_t(offset) << (eval_log - trace_log - 1);
    i = i < half ? (i + shift) & (half - 1) : ((i - shift) & (half - 1)) + half;
  }
  return reverse_index(i, eval_log);
}
} // namespace stwo::cuda::rv64
#endif
