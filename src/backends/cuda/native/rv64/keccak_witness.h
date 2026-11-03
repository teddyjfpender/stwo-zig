#pragma once
#include <stdint.h>
// Compact call inputs -> native throughput-r27 MAIN and table multiplicities.
// All pointers are borrowed leases in the supplied proof owner. No output is
// host-visible; callers must reject nonzero status before committing a tree.
struct StwoRv64KeccakWitness {
  const uint32_t *inputs;
  uint32_t *main, *chi, *xor5, *status;
  uint64_t input_words, main_words;
  uint32_t calls, first_id, log, reserved;
};
static_assert(sizeof(StwoRv64KeccakWitness)==72,"Keccak witness ABI");
extern "C" int stwo_rv64_keccak_witness_on(void *,uint32_t,const StwoRv64KeccakWitness *);
