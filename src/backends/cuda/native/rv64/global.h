#ifndef STWO_CUDA_RV64_GLOBAL_H
#define STWO_CUDA_RV64_GLOBAL_H
#include "binding.h"
struct StwoRv64GlobalPairs {
  // output initially holds paired denominators, then inverse columns and one
  // centered prefix. contributions initially holds paired numerators and is
  // overwritten with their contributions. Both are coordinate-major per pair.
  uint32_t *output, *contributions, *scan_scratch, *claim, *status;
  uint64_t stride, scan_words;
  uint32_t row_log, pairs, reserved[2];
};
static_assert(sizeof(StwoRv64GlobalPairs) == 72, "global pairs ABI");
// One relation per call. RAM, KIO and Wire must never share a cancellation
// claim. Paired values must come from the authenticated MAIN query authority.
// This primitive publishes a witness/claim, not execution acceptance.
extern "C" int stwo_rv64_global_pairs_on(void *, uint32_t,
                                         const StwoRv64GlobalPairs *);
#endif
