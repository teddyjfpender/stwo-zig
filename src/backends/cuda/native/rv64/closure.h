#ifndef STWO_CUDA_RV64_CLOSURE_H
#define STWO_CUDA_RV64_CLOSURE_H
#include "gkr.h"
// Roots are AoS (N,D) OM31 pairs from the authenticated GKR instances. This
// checks poles and the projective sum, without changing the native transcript.
extern "C" int stwo_rv64_local_close_on(void *, uint32_t, const uint32_t *,
                                        uint32_t, uint32_t *);
// Claims are AoS (RAM,KIO,Wire) OM31 triples, one per manifest worker. The
// immutable relation masks must come from the complete receiver-owned roster.
// This is arithmetic closure only: physical-root/statement authentication and
// exact roster coverage remain obligations of the execution controller.
extern "C" int stwo_rv64_global_close_on(void *, uint32_t, const uint32_t *,
                                         const uint32_t *, uint32_t,
                                         uint32_t *);
#endif
