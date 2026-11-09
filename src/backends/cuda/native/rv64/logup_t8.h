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
  return 1;
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
