#ifndef STWO_CUDA_RV64_BATCH_H
#define STWO_CUDA_RV64_BATCH_H
#include "gkr.h"
#include <stddef.h>
constexpr uint32_t STWO_RV64_BATCH_MAX_ORACLES = 64;
constexpr uint32_t STWO_RV64_BATCH_STATE_WORDS = 2173;
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
// Active oracles have one common remaining height. Each CTA row owns one
// oracle, so batching adds no mixed-height padding or numerical interaction.
struct StwoRv64BatchSumJob { StwoRv64Plane n, d, a, b, out; };
struct StwoRv64BatchFoldJob { StwoRv64Plane n, d, out_n, out_d; };
static_assert(sizeof(StwoRv64BatchSumJob) == 120 && sizeof(StwoRv64BatchFoldJob) == 96,
              "batched oracle job ABI");
extern "C" int stwo_rv64_batch_sum_on(void *, uint32_t,
    const StwoRv64BatchSumJob *, uint32_t jobs, uint32_t count, StwoRv64Plane eq,
    const uint32_t *lambda, uint32_t *launches);
extern "C" int stwo_rv64_batch_fold_on(void *, uint32_t,
    const StwoRv64BatchFoldJob *, uint32_t jobs, uint32_t count,
    const uint32_t *challenge, uint32_t *launches);

#endif
