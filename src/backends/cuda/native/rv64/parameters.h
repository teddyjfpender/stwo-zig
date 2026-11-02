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
constexpr uint32_t STWO_RV64_JOINED_PARAMETER_COUNT = 942;
constexpr uint32_t STWO_RV64_JOINED_NAMESPACE_COUNT = 5;
constexpr uint32_t STWO_RV64_JOINED_NAMESPACE_COUNTS[5] = {306, 310, 260, 63,
                                                           3};
struct StwoRv64JoinedParameters {
  const uint32_t *sources[5];
  const uint32_t *addresses;
  uint32_t *output;
  uint32_t *status;
  uint32_t count, reserved;
};
static_assert(sizeof(StwoRv64JoinedParameters) == 72 &&
                  offsetof(StwoRv64JoinedParameters, count) == 64,
              "joined parameter ABI");
// Addresses are immutable admitted device setup, two words per parameter:
// namespace/index. Public inputs are base words; other sources are AoS OM31.
extern "C" int
stwo_rv64_joined_parameter_gather_on(void *, uint32_t,
                                     const StwoRv64JoinedParameters *);
#endif
