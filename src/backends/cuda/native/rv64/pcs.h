#ifndef STWO_CUDA_RV64_PCS_H
#define STWO_CUDA_RV64_PCS_H
#include "gkr.h"
#include <stddef.h>
// Metadata is copied by value to the launch. Numeric arrays remain borrowed
// until joined completion, under the same context/lane custody as GKR.
struct StwoRv64FriFold {
    StwoRv64Plane input, output;
    const uint32_t *twiddles;
    uint64_t twiddle_words;
    const uint32_t *alpha;
    uint32_t offsets[4];
    uint32_t count, steps, first_is_circle, accumulate_circle;
};
static_assert(sizeof(StwoRv64FriFold) == 104 && offsetof(StwoRv64FriFold, count) == 88,
              "OM31 FRI ABI");
extern "C" int stwo_rv64_fri_fold_on(void *, uint32_t, const StwoRv64FriFold *);
// Hash storage is row-major 8-word digests; secure input is coordinate-major.
extern "C" int stwo_rv64_fri_leaves_on(void *, uint32_t, StwoRv64Plane, uint32_t, uint32_t,
                                       uint32_t, uint32_t *, uint64_t);
#endif
