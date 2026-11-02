#ifndef STWO_CUDA_RV64_BATCH_H
#define STWO_CUDA_RV64_BATCH_H
#include "gkr.h"
#include <stddef.h>
constexpr uint32_t STWO_RV64_BATCH_MAX_ORACLES = 64;
constexpr uint32_t STWO_RV64_BATCH_STATE_WORDS = 1644;
// For a zero-variable oracle, raw is null and raw_stride is zero. Otherwise it
// names a two-row, eight-coordinate scalar sum; no full matrix is uploaded
// here.
struct StwoRv64BatchOracle {
  const uint32_t *raw;
  uint64_t raw_stride;
  uint32_t variables, reserved;
};
static_assert(sizeof(StwoRv64BatchOracle) == 24, "batch oracle ABI");
extern "C" int stwo_rv64_batch_init_on(void *, uint32_t, uint32_t *,
                                       const uint32_t *, const uint32_t *,
                                       const uint32_t *,
                                       const StwoRv64BatchOracle *, uint32_t,
                                       uint32_t);
extern "C" int stwo_rv64_batch_round_on(void *, uint32_t, uint32_t *,
                                        const StwoRv64BatchOracle *, uint32_t,
                                        uint32_t, uint32_t, const uint32_t *,
                                        uint32_t *);
extern "C" int stwo_rv64_batch_mask_on(void *, uint32_t, StwoRv64Plane,
                                       StwoRv64Plane, uint32_t *);
#endif
