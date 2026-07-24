// Minimal proof-owned CUDA execution context. Every operation is bound to one
// nonblocking stream and one isolated async pool; there is no global state or
// allocation fallback.

#include <cuda_runtime_api.h>

#include <stddef.h>
#include <stdint.h>

#include <limits>
#include <new>

namespace {

struct StwoNativeCudaContext {
    int device;
    cudaStream_t stream;
    cudaMemPool_t pool;
};

cudaError_t require_context(
    void *handle,
    StwoNativeCudaContext **out_context) {
    if (handle == nullptr || out_context == nullptr) {
        return cudaErrorInvalidValue;
    }
    auto *context = static_cast<StwoNativeCudaContext *>(handle);
    int current = -1;
    cudaError_t status = cudaGetDevice(&current);
    if (status != cudaSuccess) return status;
    if (current != context->device) return cudaErrorInvalidDevice;
    *out_context = context;
    return cudaSuccess;
}

__global__ void fill_u32_kernel(
    uint32_t *destination,
    uint32_t value,
    size_t count) {
    const size_t index =
        static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (index < count) destination[index] = value;
}

}  // namespace

extern "C" int stwo_cuda_device_snapshot(
    uint32_t *out_count,
    uint32_t *out_current,
    uint32_t *out_sm_major,
    uint32_t *out_sm_minor) {
    if (out_count == nullptr || out_current == nullptr ||
        out_sm_major == nullptr || out_sm_minor == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    int count = 0;
    int current = -1;
    cudaDeviceProp properties{};
    cudaError_t status = cudaGetDeviceCount(&count);
    if (status == cudaSuccess && count <= 0) status = cudaErrorNoDevice;
    if (status == cudaSuccess) status = cudaGetDevice(&current);
    if (status == cudaSuccess) {
        status = cudaGetDeviceProperties(&properties, current);
    }
    if (status != cudaSuccess) return static_cast<int>(status);
    *out_count = static_cast<uint32_t>(count);
    *out_current = static_cast<uint32_t>(current);
    *out_sm_major = static_cast<uint32_t>(properties.major);
    *out_sm_minor = static_cast<uint32_t>(properties.minor);
    return 0;
}

extern "C" int stwo_exec_context_create(void **out_handle) {
    if (out_handle == nullptr) return static_cast<int>(cudaErrorInvalidValue);
    *out_handle = nullptr;

    auto *context = new (std::nothrow) StwoNativeCudaContext{
        -1,
        nullptr,
        nullptr,
    };
    if (context == nullptr) {
        return static_cast<int>(cudaErrorMemoryAllocation);
    }

    cudaError_t status = cudaGetDevice(&context->device);
    cudaMemPoolProps properties{};
    properties.allocType = cudaMemAllocationTypePinned;
    properties.handleTypes = cudaMemHandleTypeNone;
    properties.location.type = cudaMemLocationTypeDevice;
    properties.location.id = context->device;
    if (status == cudaSuccess) {
        status = cudaMemPoolCreate(&context->pool, &properties);
    }
    uint64_t release_threshold = std::numeric_limits<uint64_t>::max();
    if (status == cudaSuccess) {
        status = cudaMemPoolSetAttribute(
            context->pool,
            cudaMemPoolAttrReleaseThreshold,
            &release_threshold);
    }
    if (status == cudaSuccess) {
        status = cudaStreamCreateWithFlags(
            &context->stream,
            cudaStreamNonBlocking);
    }
    if (status != cudaSuccess) {
        if (context->stream != nullptr) cudaStreamDestroy(context->stream);
        if (context->pool != nullptr) cudaMemPoolDestroy(context->pool);
        delete context;
        return static_cast<int>(status);
    }
    *out_handle = context;
    return 0;
}

extern "C" int stwo_exec_context_destroy(void *handle) {
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    status = cudaStreamSynchronize(context->stream);
    const cudaError_t stream_status = cudaStreamDestroy(context->stream);
    const cudaError_t pool_status = cudaMemPoolDestroy(context->pool);
    delete context;
    if (status != cudaSuccess) return static_cast<int>(status);
    if (stream_status != cudaSuccess) return static_cast<int>(stream_status);
    return static_cast<int>(pool_status);
}

extern "C" int stwo_exec_context_sync(void *handle) {
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    return static_cast<int>(cudaStreamSynchronize(context->stream));
}

extern "C" int stwo_exec_context_pool_current(
    void *handle,
    size_t *used_current,
    size_t *reserved_current) {
    if (used_current == nullptr || reserved_current == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    uint64_t used = 0;
    uint64_t reserved = 0;
    if (status == cudaSuccess) {
        status = cudaMemPoolGetAttribute(
            context->pool,
            cudaMemPoolAttrUsedMemCurrent,
            &used);
    }
    if (status == cudaSuccess) {
        status = cudaMemPoolGetAttribute(
            context->pool,
            cudaMemPoolAttrReservedMemCurrent,
            &reserved);
    }
    if (status != cudaSuccess) return static_cast<int>(status);
    if (used > std::numeric_limits<size_t>::max() ||
        reserved > std::numeric_limits<size_t>::max()) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    *used_current = static_cast<size_t>(used);
    *reserved_current = static_cast<size_t>(reserved);
    return 0;
}

extern "C" int stwo_exec_context_stream(
    void *handle,
    void **out_stream) {
    if (out_stream == nullptr) return static_cast<int>(cudaErrorInvalidValue);
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    *out_stream = context->stream;
    return 0;
}

extern "C" int stwo_exec_context_device(
    void *handle,
    int *out_device) {
    if (out_device == nullptr) return static_cast<int>(cudaErrorInvalidValue);
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    *out_device = context->device;
    return 0;
}

extern "C" int stwo_exec_context_lane_count(
    void *handle,
    uint32_t *out_count) {
    if (out_count == nullptr) return static_cast<int>(cudaErrorInvalidValue);
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    *out_count = 0;
    return 0;
}

extern "C" int stwo_exec_context_join_all_lanes(void *handle) {
    StwoNativeCudaContext *context = nullptr;
    return static_cast<int>(require_context(handle, &context));
}

extern "C" int stwo_exec_context_alloc_u32(
    void *handle,
    size_t count,
    uint32_t **out_pointer) {
    if (count == 0 || out_pointer == nullptr ||
        count > std::numeric_limits<size_t>::max() / sizeof(uint32_t)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    *out_pointer = nullptr;
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status == cudaSuccess) {
        status = cudaMallocFromPoolAsync(
            reinterpret_cast<void **>(out_pointer),
            count * sizeof(uint32_t),
            context->pool,
            context->stream);
    }
    return static_cast<int>(status);
}

extern "C" int stwo_exec_context_free_u32(
    void *handle,
    uint32_t *pointer) {
    if (pointer == nullptr) return static_cast<int>(cudaErrorInvalidValue);
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status == cudaSuccess) {
        status = cudaFreeAsync(pointer, context->stream);
    }
    return static_cast<int>(status);
}

extern "C" int stwo_exec_context_memset_async(
    void *handle,
    void *destination,
    int value,
    size_t bytes) {
    if (destination == nullptr || bytes == 0) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status == cudaSuccess) {
        status = cudaMemsetAsync(
            destination,
            value,
            bytes,
            context->stream);
    }
    return static_cast<int>(status);
}

extern "C" int stwo_exec_context_fill_u32_async(
    void *handle,
    uint32_t *destination,
    uint32_t value,
    size_t count) {
    if (destination == nullptr || count == 0) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    constexpr uint32_t kThreads = 256;
    const size_t blocks = (count + kThreads - 1) / kThreads;
    if (blocks > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    fill_u32_kernel<<<
        static_cast<uint32_t>(blocks),
        kThreads,
        0,
        context->stream>>>(destination, value, count);
    return static_cast<int>(cudaPeekAtLastError());
}

extern "C" int stwo_exec_context_memcpy_d2d_async(
    void *handle,
    void *destination,
    const void *source,
    size_t bytes) {
    if (destination == nullptr || source == nullptr || bytes == 0) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status == cudaSuccess) {
        status = cudaMemcpyAsync(
            destination,
            source,
            bytes,
            cudaMemcpyDeviceToDevice,
            context->stream);
    }
    return static_cast<int>(status);
}

extern "C" int stwo_exec_context_memcpy_h2d_async(
    void *handle,
    void *destination,
    const void *source,
    size_t bytes) {
    if (destination == nullptr || source == nullptr || bytes == 0) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status == cudaSuccess) {
        status = cudaMemcpyAsync(
            destination,
            source,
            bytes,
            cudaMemcpyHostToDevice,
            context->stream);
    }
    return static_cast<int>(status);
}

extern "C" int stwo_exec_context_memcpy_d2h_async(
    void *handle,
    void *destination,
    const void *source,
    size_t bytes) {
    if (destination == nullptr || source == nullptr || bytes == 0) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status == cudaSuccess) {
        status = cudaMemcpyAsync(
            destination,
            source,
            bytes,
            cudaMemcpyDeviceToHost,
            context->stream);
    }
    return static_cast<int>(status);
}
