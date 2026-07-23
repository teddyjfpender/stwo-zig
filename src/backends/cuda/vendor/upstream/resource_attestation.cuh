#ifndef STWO_RESOURCE_ATTESTATION_H
#define STWO_RESOURCE_ATTESTATION_H

#include <cuda_runtime_api.h>
#include <cstddef>
#include <cstdint>

// Fixed-width host ABI for the attributes CUDA reports for the function loaded
// on the current device. This is execution qualification, not a build estimate.
struct alignas(8) StwoCudaFunctionAttributes {
    uint32_t abi_version;
    uint32_t max_threads_per_block;
    uint32_t registers_per_thread;
    uint32_t binary_version;
    uint32_t ptx_version;
    uint32_t reserved;
    uint64_t local_bytes;
    uint64_t static_shared_bytes;
};

static_assert(sizeof(StwoCudaFunctionAttributes) == 40);
static_assert(alignof(StwoCudaFunctionAttributes) == 8);
static_assert(offsetof(StwoCudaFunctionAttributes, local_bytes) == 24);
static_assert(offsetof(StwoCudaFunctionAttributes, static_shared_bytes) == 32);
static_assert(sizeof(size_t) <= sizeof(uint64_t));

template <typename Kernel>
inline cudaError_t stwo_cuda_function_attributes(
        Kernel kernel,
        StwoCudaFunctionAttributes *out
) {
    if (out == nullptr) return cudaErrorInvalidValue;
    *out = {};

    cudaFuncAttributes attributes = {};
    const cudaError_t error = cudaFuncGetAttributes(&attributes, kernel);
    if (error != cudaSuccess) return error;
    if (attributes.maxThreadsPerBlock < 0 || attributes.numRegs < 0 ||
        attributes.binaryVersion < 0 || attributes.ptxVersion < 0) {
        return cudaErrorInvalidValue;
    }

    out->abi_version = 1;
    out->max_threads_per_block =
            static_cast<uint32_t>(attributes.maxThreadsPerBlock);
    out->registers_per_thread = static_cast<uint32_t>(attributes.numRegs);
    out->binary_version = static_cast<uint32_t>(attributes.binaryVersion);
    out->ptx_version = static_cast<uint32_t>(attributes.ptxVersion);
    out->local_bytes = static_cast<uint64_t>(attributes.localSizeBytes);
    out->static_shared_bytes = static_cast<uint64_t>(attributes.sharedSizeBytes);
    return cudaSuccess;
}

#endif
