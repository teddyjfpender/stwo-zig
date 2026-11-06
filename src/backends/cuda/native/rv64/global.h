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
// Circuit-only contribution sum/scan. contributions must equal output
// exactly; the one validated output spans pair planes plus their prefix.
// No inversion is performed and no old overlap contract is relaxed.
extern "C" int stwo_rv64_global_contributions_scan_v1_on(void*,uint32_t,const StwoRv64GlobalPairs*);

// Convert the temporary inverse columns to the native cumulative-per-batch
// encoding in place. The helper's final centered prefix remains scratch.
struct StwoRv64GlobalCumulative {
  uint32_t *output;
  const uint32_t *contributions;
  uint64_t stride;
  uint32_t row_log, pairs;
};
static_assert(sizeof(StwoRv64GlobalCumulative)==32,"global cumulative ABI");
extern "C" int stwo_rv64_global_cumulative_on(void*,uint32_t,const StwoRv64GlobalCumulative*);

#endif
