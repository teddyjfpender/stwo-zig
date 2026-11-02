#ifndef STWO_CUDA_RV64_GKR_LOOP_H
#define STWO_CUDA_RV64_GKR_LOOP_H
#include "gkr.h"
constexpr uint32_t STWO_RV64_GKR_STATE_WORDS = 1428;
constexpr uint32_t STWO_RV64_GKR_ALPHA_WORD = 152;
constexpr uint32_t STWO_RV64_GKR_LAMBDA_WORD = 160;
constexpr uint32_t STWO_RV64_GKR_SEED_WORD = 168;
constexpr uint32_t STWO_RV64_GKR_CLAIMS_WORD = 180;
constexpr uint32_t STWO_RV64_GKR_POINT_WORD = 1204;
struct StwoRv64Root {
  StwoRv64Plane n, d;
};
extern "C" int stwo_rv64_gkr_pack_roots_on(void *, uint32_t,
                                           const StwoRv64Root *, uint32_t,
                                           uint32_t *);
extern "C" int stwo_rv64_gkr_init_on(void *, uint32_t, uint32_t *,
                                     const uint32_t *, const uint32_t *,
                                     uint32_t, uint32_t, uint64_t);
extern "C" int stwo_rv64_gkr_begin_on(void *, uint32_t, uint32_t *, uint32_t,
                                      uint32_t, uint32_t, const uint32_t *,
                                      uint32_t *);
extern "C" int stwo_rv64_gkr_close_on(void *, uint32_t, uint32_t *,
                                      const uint32_t *, const uint32_t *,
                                      const uint32_t *, uint32_t, uint32_t,
                                      uint32_t);
// Derive one physical role's Eq-point metadata from a completed parent.
// State remains immutable. Reservoir is 256 lane weights, eta, target, eq0,
// eq1.
struct StwoRv64BindingMetadata {
  const uint32_t *state;
  uint32_t *reservoir, *row_point, *carry, *seed, *status;
  uint64_t chain;
  uint32_t instance, row_log, lane_log, count, layers, reserved;
};
static_assert(sizeof(StwoRv64BindingMetadata) == 80 &&
                  offsetof(StwoRv64BindingMetadata, chain) == 48,
              "binding metadata ABI");
extern "C" int
stwo_rv64_gkr_binding_metadata_on(void *, uint32_t,
                                  const StwoRv64BindingMetadata *);
#endif
