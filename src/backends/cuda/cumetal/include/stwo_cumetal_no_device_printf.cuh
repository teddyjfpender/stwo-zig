#ifndef STWO_ZIG_CUMETAL_NO_DEVICE_PRINTF_CUH
#define STWO_ZIG_CUMETAL_NO_DEVICE_PRINTF_CUH

#include "stwo_cumetal_cuda_compat.cuh"

// The authority functions affected by this overlay are diagnostic printers
// only. CuMetal does not implement device printf, so erase those calls in the
// provider build without changing the authenticated source projection.
#define printf(...) ((void)0)

#endif
