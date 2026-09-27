#ifndef STWO_CUDA_CONTEXT_OPTIONS_H
#define STWO_CUDA_CONTEXT_OPTIONS_H

#include <stdint.h>
#include <stddef.h>

#define STWO_CUDA_CONTEXT_OPTIONS_VERSION 1u
#define STWO_CUDA_CONTEXT_MAX_LANES 4u
#define STWO_CUDA_CONTEXT_MAX_DEPENDENCIES 64u

// Lane 0 is the existing coordination stream. UINT32_MAX selects the caller's
// current device only for the legacy constructor; explicit options may also
// name it without claiming multi-device scheduling.
struct StwoCudaContextOptions {
    uint32_t version;
    uint32_t device_ordinal;
    uint32_t lane_count;
    uint32_t dependency_capacity;
};

struct StwoCudaDependency {
    uint64_t context_identity;
    uint64_t generation;
    uint32_t slot;
    uint32_t producer_lane;
};

static_assert(sizeof(StwoCudaContextOptions) == 16, "context options ABI");
static_assert(sizeof(StwoCudaDependency) == 24, "dependency token ABI");
static_assert(offsetof(StwoCudaContextOptions, version) == 0 &&
              offsetof(StwoCudaContextOptions, device_ordinal) == 4 &&
              offsetof(StwoCudaContextOptions, lane_count) == 8 &&
              offsetof(StwoCudaContextOptions, dependency_capacity) == 12,
              "context options field offsets");
static_assert(offsetof(StwoCudaDependency, context_identity) == 0 &&
              offsetof(StwoCudaDependency, generation) == 8 &&
              offsetof(StwoCudaDependency, slot) == 16 &&
              offsetof(StwoCudaDependency, producer_lane) == 20,
              "dependency token field offsets");

#endif
