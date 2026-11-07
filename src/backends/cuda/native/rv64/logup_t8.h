#ifndef STWO_CUDA_RV64_LOGUP_T8_H
#define STWO_CUDA_RV64_LOGUP_T8_H
// M8 optimisation T8 (LogUp batch inverse): host-side switch and the
// mode-explicit launchers behind the unchanged extern "C" entry points.
//
// STWO_RV64_M8_LOGUP_BLOCK_INVERSE
//   unset, empty or "0": original kernels (default);
//   "1": norm-descent inverse with per-thread batched M31 inversion, fused
//        row sum for wide row grids, coalesced level-0 prefix scan;
//   anything else: the entry points fail closed (cudaErrorInvalidValue).
// Every mode writes bit-identical outputs, claims and status bits: inverses
// and n * inverse are unique canonical field elements, and modular sums are
// order independent.
#include "binding.h"
#include "global.h"
#include <cstdlib>
#include <cstring>
namespace stwo::cuda::rv64::t8 {
inline int mode() {
  static const int value = [] {
    const char *v = std::getenv("STWO_RV64_M8_LOGUP_BLOCK_INVERSE");
    // Unset/empty or 1 = T8 kernels, 0 = original kernels.
    // Default ON since M8 opt-combined (vectors/reports/rv64-m8-20261106/opt-combined/): kernel-parity bit-exact, rv64_gate PASS on 26235156+24628607 flags on, and in the qualified 3+3 (24628607 warm, nsys CUPTI, both GPUs) global_inverse_contribute 0.391 -> inverse_contribute(_sum) 0.180 GPU-s, level-0 scan tiled [M].
    if (!v || !*v || !std::strcmp(v, "1"))
      return 1;
    return std::strcmp(v, "0") ? -1 : 0;
  }();
  return value;
}
// mode 0 = original kernels, 1 = T8 kernels. Hidden: test/bench entry only.
__attribute__((visibility("hidden"))) int
global_pairs(void *ctx, uint32_t lane, const StwoRv64GlobalPairs *input,
             int mode);
__attribute__((visibility("hidden"))) int
prefix_scan(void *ctx, uint32_t lane, const StwoRv64PrefixScan *input,
            int mode);
} // namespace stwo::cuda::rv64::t8
#endif
