#ifndef STWO_CUDA_RV64_PARAMETERS_H
#define STWO_CUDA_RV64_PARAMETERS_H
#include "gkr.h"
constexpr uint32_t STWO_RV64_RELATION_COUNT = 10;
constexpr uint32_t STWO_RV64_RELATION_SLOT_STRIDE = 31;
// Immutable HOST slot metadata consumed by this call. Draw values and output
// are borrowed device allocations; no numerical feedback or allocation occurs.
extern "C" int stwo_rv64_parameter_gather_on(void *, uint32_t, const uint32_t *,
                                             uint32_t *, const uint32_t *,
                                             uint32_t, uint32_t, uint32_t *);
#endif
