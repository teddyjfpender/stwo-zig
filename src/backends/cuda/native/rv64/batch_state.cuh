#ifndef STWO_CUDA_RV64_BATCH_STATE_CUH
#define STWO_CUDA_RV64_BATCH_STATE_CUH
#include "batch.h"
#include "round.cuh"
namespace stwo::cuda::rv64 {
constexpr uint32_t max_oracles = STWO_RV64_BATCH_MAX_ORACLES;
struct BatchState {
  RoundState round;
  uint32_t count, reserved[3];
  OM31 weights[max_oracles], corrections[max_oracles],
      sleeping_claims[max_oracles];
  uint32_t initial_variables[max_oracles];
  uint32_t initial_seed[9];
  OM31 initial_alpha, initial_claims[max_oracles];
};
static_assert(sizeof(BatchState) == STWO_RV64_BATCH_STATE_WORDS * 4,
              "batch state ABI");
} // namespace stwo::cuda::rv64
#endif
