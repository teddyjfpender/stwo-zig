#ifndef STWO_CUDA_RV64_BINDING_H
#define STWO_CUDA_RV64_BINDING_H
#include "gkr.h"
struct StwoRv64BindingProjection {
  StwoRv64Plane n, d, eq, prefix;
  const uint32_t *metadata;
  uint32_t *status;
  uint32_t row_log, lane_log, reserved[2];
};
// Deferred ownership retains the unweighted P=N+eta*D projection only.
struct StwoRv64BindingDeferred {
  StwoRv64Plane n, d, output;
  const uint32_t *metadata;
  uint32_t *status;
  uint32_t row_log, lane_log, reserved[2];
};
struct StwoRv64BindingFinalize {
  StwoRv64Plane projection, eq, output;
  const uint32_t *metadata;
  uint32_t *status;
  uint32_t row_log, reserved[3];
};
static_assert(sizeof(StwoRv64BindingDeferred) == 104 &&
              sizeof(StwoRv64BindingFinalize) == 104, "deferred binding ABI");
extern "C" int stwo_rv64_binding_deferred_on(void *, uint32_t,
                                            const StwoRv64BindingDeferred *);
extern "C" int stwo_rv64_binding_finalize_on(void *, uint32_t,
                                            const StwoRv64BindingFinalize *);
struct StwoRv64PrefixScan {
  StwoRv64Plane data;
  uint32_t *scratch;
  uint64_t scratch_words;
  uint32_t *claim, *status;
  uint32_t row_log, center, reserved[2];
};
static_assert(sizeof(StwoRv64BindingProjection) == 128 &&
                  sizeof(StwoRv64PrefixScan) == 72,
              "binding witness ABI");
// Full binding Eq table; the GKR sumcheck half-table is not interchangeable.
extern "C" int stwo_rv64_binding_eq_on(void *, uint32_t, const uint32_t *,
                                       uint32_t, StwoRv64Plane, uint32_t *);
// Eq and fractions must already be generated on the same lane. Numerical
// verdict is sticky; successful enqueue is never proof or witness acceptance.
extern "C" int stwo_rv64_binding_project_on(void *, uint32_t,
                                            const StwoRv64BindingProjection *);
// In-place inclusive scan in logical coset order, stored in circle order.
// center=0 rejects nonzero final debt; center=1 subtracts the emitted claim.
extern "C" int stwo_rv64_prefix_scan_on(void *, uint32_t,
                                        const StwoRv64PrefixScan *);
#endif
