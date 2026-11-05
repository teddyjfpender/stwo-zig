#ifndef STWO_CUDA_RV64_ARITHMETIC_WITNESS_H
#define STWO_CUDA_RV64_ARITHMETIC_WITNESS_H
#include <cstdint>
// Compact request8: family-local opcode ordinal, reserved0, A64, B64, result64.
struct StwoRv64ArithmeticWitness {
  const uint32_t *requests;
  uint32_t *main, *range16, *range8, *pairs, *status, *mul_support;
  uint32_t count, log, division, fused_pairs;
};
static_assert(sizeof(StwoRv64ArithmeticWitness) == 72, "arithmetic witness ABI");
extern "C" int stwo_rv64_arithmetic_witness_on(void *, uint32_t,
                                               const StwoRv64ArithmeticWitness *);
#endif
