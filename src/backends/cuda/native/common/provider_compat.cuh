#ifndef STWO_ZIG_CUDA_PROVIDER_COMPAT_CUH
#define STWO_ZIG_CUDA_PROVIDER_COMPAT_CUH

// Narrow source-compatibility vocabulary for the two resident execution
// providers. Keep provider differences explicit here instead of teaching the
// proof pipeline to depend on CuMetal or NVIDIA-only enum spellings.

#include <cuda_runtime_api.h>

#if defined(STWO_CUMETAL)
#define STWO_CUDA_ERROR_INVALID_CONFIGURATION cudaErrorInvalidValue
#define STWO_CUDA_ERROR_INVALID_DEVICE cudaErrorInvalidValue
#define STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE cudaErrorInvalidValue
#define STWO_CUDA_ERROR_NO_DEVICE cudaErrorDevicesUnavailable
#else
#define STWO_CUDA_ERROR_INVALID_CONFIGURATION cudaErrorInvalidConfiguration
#define STWO_CUDA_ERROR_INVALID_DEVICE cudaErrorInvalidDevice
#define STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE cudaErrorInvalidResourceHandle
#define STWO_CUDA_ERROR_NO_DEVICE cudaErrorNoDevice
#endif

#define STWO_CUDA_EXECUTION_PROVIDER_NVIDIA 1u
#define STWO_CUDA_EXECUTION_PROVIDER_CUMETAL 2u

#endif
