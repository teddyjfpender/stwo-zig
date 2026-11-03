#ifndef STWO_CUDA_RV64_SAMPLE_ORDER_H
#define STWO_CUDA_RV64_SAMPLE_ORDER_H
#include <stdint.h>
// Secure AoS gather from grouped evaluation slots into native transcript order.
// The map is immutable receiver-derived geometry. Repeated indices are valid
// (e.g. periodicity shares a physical sample); output cannot alias any input.
extern "C" int stwo_rv64_sample_order_on(void *, uint32_t, const uint32_t *,
                                         uint32_t, const uint32_t *, uint32_t,
                                         uint32_t *, uint32_t *);
#endif
