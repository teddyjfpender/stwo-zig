#ifndef STWO_CUDA_RV64_PCS_FRAMING_H
#define STWO_CUDA_RV64_PCS_FRAMING_H
#include <cstdint>
#include <cstddef>
namespace stwo::cuda::rv64 {
struct PcsAggregateCounts { uint64_t coefficients, evaluations, combined_coefficients, combined_evaluations; };
inline bool decodePcsCounts(const uint32_t *h, size_t size, PcsAggregateCounts *out) {
  if (!h || !out || (size != 24 && size != 28) || h[0] != 0x52564d53 ||
      !((h[1] == 2 && size == 24) || (h[1] == 3 && size == 28)) ||
      h[2] || h[21] > 1 || h[22] > 32 || h[23]) return false;
  uint64_t counts[4];
  for (unsigned i = 0; i < 4; ++i) {
    counts[i] = uint64_t(h[15+i]) | (h[1] == 3 ? uint64_t(h[24+i]) << 32 : 0);
    // Every valid bounded source inventory is below this. Keep subsequent
    // sums/byte sizes overflow-free before invoking the owner's byte cap.
    if (counts[i] > (uint64_t(1) << 48)) return false;
  }
  *out = {counts[0], counts[1], counts[2], counts[3]};
  return true;
}
} // namespace stwo::cuda::rv64
#endif
