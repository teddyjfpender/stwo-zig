#ifndef STWO_CUDA_RV64_FAMILY_WITNESS_H
#define STWO_CUDA_RV64_FAMILY_WITNESS_H
#include <cstdint>
// Compact logical facts: op, multiplicity, A(lo,hi), B(lo,hi), C(lo,hi).
// All outputs are column-major in the native bit-reversed circle ordering.
struct StwoRv64FamilyWitness {
  const uint32_t *facts;
  uint32_t *main, *range16_counts, *and_counts, *shift_counts, *status;
  uint32_t count, log, kind, reserved;
};
static_assert(sizeof(StwoRv64FamilyWitness) == 64, "family witness ABI");
// kind0 ALU47, kind1 BINARY29, kind2 SHIFT52, kind3 Zbb BINARY32, kind4 JALR17. Histograms are additive device
// ledgers, zeroed once by their scoped owner before any family contributes.
extern "C" int stwo_rv64_family_witness_on(void *, uint32_t,
                                           const StwoRv64FamilyWitness *);
#endif
