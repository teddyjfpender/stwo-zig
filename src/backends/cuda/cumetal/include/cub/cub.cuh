#ifndef STWO_ZIG_CUMETAL_CUB_COMPAT_CUH
#define STWO_ZIG_CUMETAL_CUB_COMPAT_CUH

// CuMetal publishes its supported CUB surface from cub/cub.h.  NVIDIA's CUB
// umbrella spelling is cub/cub.cuh, so keep that source-level difference at
// the provider boundary instead of modifying the pinned kernel authority.
#include <cub/cub.h>

#endif
