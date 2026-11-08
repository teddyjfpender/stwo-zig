#ifndef STWO_CUDA_RV64_CHANNEL_H
#define STWO_CUDA_RV64_CHANNEL_H
#include <stdint.h>
// State is the existing 16-word transcript::State (8-byte aligned). The
// checkpoint is digest[8], draws. Initialization does not add a profile tag:
// the caller imports an independently bound native OM31 channel checkpoint.
extern "C" int stwo_rv64_channel_init_on(void *, uint32_t, uint32_t *,
                                         const uint32_t *, uint64_t);
extern "C" int stwo_rv64_channel_mix_on(void *, uint32_t, uint32_t *, uint32_t,
                                        uint64_t, uint64_t, const uint32_t *,
                                        uint32_t, uint32_t, uint32_t *);
extern "C" int stwo_rv64_channel_draw_on(void *, uint32_t, uint32_t *, uint32_t,
                                         uint64_t, uint64_t, uint32_t,
                                         uint32_t *, uint32_t *);
// Native drawQueries: eight RAW words per hash, masked to the domain.
// These must not pass through the modulo-M31 secure-field draw.
extern "C" int stwo_rv64_channel_queries_on(void *, uint32_t, uint32_t *,
                                            uint32_t, uint64_t, uint64_t,
                                            uint32_t, uint32_t, uint32_t *,
                                            uint32_t *);
#endif
