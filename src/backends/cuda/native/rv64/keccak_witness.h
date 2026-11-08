#pragma once
#include <stdint.h>
// Compact call inputs -> native throughput-r27 / compact pair29 MAIN and table multiplicities.
// All pointers are borrowed leases in the supplied proof owner. No output is
// host-visible; callers must reject nonzero status before committing a tree.
struct StwoRv64KeccakWitness {
  const uint32_t *inputs;
  uint32_t *main, *chi, *xor5, *status;
  uint64_t input_words, main_words;
  // policy: 0=throughput_r27_v1 (pair27), 1=triple_v2 (pair29).
  uint32_t calls, first_id, log, policy;
};
static_assert(sizeof(StwoRv64KeccakWitness)==72,"Keccak witness ABI");
extern "C" int stwo_rv64_keccak_witness_on(void *,uint32_t,const StwoRv64KeccakWitness *);
