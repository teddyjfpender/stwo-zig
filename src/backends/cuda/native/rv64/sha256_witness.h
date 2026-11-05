#ifndef STWO_CUDA_RV64_SHA256_WITNESS_H
#define STWO_CUDA_RV64_SHA256_WITNESS_H
#include <cstdint>
// Each compact record has24 little-endian u32 words: eight state words followed
// by64 stream-order bytes packed in16 words. No expanded bits/carries enter.
struct StwoRv64Sha256Witness {
  const uint32_t *inputs;
  uint32_t *main, *status;
  uint64_t input_words, main_words;
  uint32_t calls, first_id, log, reserved;
};
static_assert(sizeof(StwoRv64Sha256Witness)==56,"SHA256 witness ABI");
extern "C" int stwo_rv64_sha256_witness_on(void*,uint32_t,const StwoRv64Sha256Witness*);
#endif
