#ifndef STWO_CUDA_RV64_MEMORY_WITNESS_H
#define STWO_CUDA_RV64_MEMORY_WITNESS_H
#include <cstdint>
// Event16: A64, immediate64, B64, C64, before-value64, before-epoch,
// epoch, before-tick, tick, rights, native load/store flag ordinal.
struct StwoRv64MemoryWitness {
  const uint32_t *events;
  uint32_t *main, *range16, *range8, *pairs, *selection, *status;
  uint32_t count, log, dword, fused_pairs;
};
static_assert(sizeof(StwoRv64MemoryWitness) == 72, "memory witness ABI");
// Cell8: address64, value64, epoch, tick, rights, reserved0.
extern "C" int stwo_rv64_memory_witness_on(void *, uint32_t,
                                           const StwoRv64MemoryWitness *);
extern "C" int stwo_rv64_boundary_witness_on(void *, uint32_t,
                                             const uint32_t *, uint32_t,
                                             uint32_t, uint32_t *, uint32_t *);
// kind0 U16,1 U8,2 AND,3 AND+pair,4 packed SHIFT16,5 selection,6 ROM.
extern "C" int stwo_rv64_multiplicity_witness_on(void *, uint32_t,
                                                 const uint32_t *,
                                                 const uint32_t *, uint32_t,
                                                 uint32_t, uint32_t *, uint32_t *);
#endif
