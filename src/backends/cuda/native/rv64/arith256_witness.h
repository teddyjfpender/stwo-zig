#ifndef STWO_CUDA_RV64_ARITH256_WITNESS_H
#define STWO_CUDA_RV64_ARITH256_WITNESS_H
#include <cstdint>
// Forty little-endian u32 per call: A,B,C,M,R_before, eight words each.
struct StwoRv64Arith256Witness {
  const uint32_t *inputs;
  uint32_t *main,*byte_counts,*status;
  uint64_t input_words,main_words;
  uint32_t calls,first_id,log,reserved;
};
static_assert(sizeof(StwoRv64Arith256Witness)==64,"arith256 witness ABI");
extern "C" int stwo_rv64_arith256_witness_on(void*,uint32_t,const StwoRv64Arith256Witness*);
#endif
