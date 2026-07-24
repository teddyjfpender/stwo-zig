// Minimal proof-owned CUDA execution context. Every operation is bound to one
// nonblocking stream and one isolated async pool; there is no global state or
// allocation fallback.

#include <cuda_runtime_api.h>

#include <stddef.h>
#include <stdint.h>

#include <limits>
#include <cstring>
#include <new>

extern "C" int nvtxRangePushA(const char *) __attribute__((weak));
extern "C" int nvtxRangePop() __attribute__((weak));

namespace {

constexpr uint32_t kProofStageCount = 10;
constexpr uint32_t kTimingMarkerCount = kProofStageCount + 1;

struct StwoNativeCudaContext {
    int device;
    cudaStream_t stream;
    cudaMemPool_t pool;
    cudaEvent_t timing_events[kTimingMarkerCount];
    uint32_t timing_marker_count;
    uint32_t nvtx_depth;
};

struct alignas(8) StwoCudaPlatformSnapshot {
    uint8_t uuid[16];
    uint32_t driver_version;
    uint32_t runtime_version;
    uint32_t toolkit_version;
    uint32_t device_ordinal;
    uint64_t total_global_memory;
    uint32_t multiprocessor_count;
    uint32_t warp_size;
    uint32_t max_threads_per_block;
    uint32_t reserved;
};

static_assert(sizeof(StwoCudaPlatformSnapshot) == 56,
              "CUDA platform snapshot ABI must be 56 bytes");
static_assert(offsetof(StwoCudaPlatformSnapshot, total_global_memory) == 32,
              "invalid CUDA platform snapshot memory offset");

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

extern "C" int stwo_cuda_platform_snapshot(
    StwoCudaPlatformSnapshot *out) {
    if (out == nullptr) return static_cast<int>(cudaErrorInvalidValue);
    *out = {};

    int device = -1;
    int driver_version = 0;
    int runtime_version = 0;
    cudaDeviceProp properties{};
    cudaError_t status = cudaGetDevice(&device);
    if (status == cudaSuccess) {
        status = cudaGetDeviceProperties(&properties, device);
    }
    if (status == cudaSuccess) status = cudaDriverGetVersion(&driver_version);
    if (status == cudaSuccess) status = cudaRuntimeGetVersion(&runtime_version);
    if (status != cudaSuccess) return static_cast<int>(status);
    if (device < 0 || driver_version <= 0 || runtime_version <= 0 ||
        properties.totalGlobalMem == 0 ||
        properties.multiProcessorCount <= 0 || properties.warpSize <= 0 ||
        properties.maxThreadsPerBlock <= 0) {
        return static_cast<int>(cudaErrorInvalidDevice);
    }

    std::memcpy(out->uuid, properties.uuid.bytes, sizeof(out->uuid));
    out->driver_version = static_cast<uint32_t>(driver_version);
    out->runtime_version = static_cast<uint32_t>(runtime_version);
    out->toolkit_version = CUDART_VERSION;
    out->device_ordinal = static_cast<uint32_t>(device);
    out->total_global_memory = properties.totalGlobalMem;
    out->multiprocessor_count =
        static_cast<uint32_t>(properties.multiProcessorCount);
    out->warp_size = static_cast<uint32_t>(properties.warpSize);
    out->max_threads_per_block =
        static_cast<uint32_t>(properties.maxThreadsPerBlock);
    return 0;
}

extern "C" int stwo_exec_context_create(void **out_handle) {
    if (out_handle == nullptr) return static_cast<int>(cudaErrorInvalidValue);
    *out_handle = nullptr;

    auto *context = new (std::nothrow) StwoNativeCudaContext{
        -1,
        nullptr,
        nullptr,
        {},
        0,
        0,
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
    cudaError_t event_status = cudaSuccess;
    if (context->nvtx_depth != 0 && nvtxRangePop != nullptr) nvtxRangePop();
    for (uint32_t marker = 0; marker < kTimingMarkerCount; ++marker) {
        if (context->timing_events[marker] == nullptr) continue;
        const cudaError_t status =
            cudaEventDestroy(context->timing_events[marker]);
        if (event_status == cudaSuccess) event_status = status;
    }
    const cudaError_t stream_status = cudaStreamDestroy(context->stream);
    const cudaError_t pool_status = cudaMemPoolDestroy(context->pool);
    delete context;
    if (event_status != cudaSuccess) return static_cast<int>(event_status);
    if (stream_status != cudaSuccess) return static_cast<int>(stream_status);
    return static_cast<int>(pool_status);
}

extern "C" int stwo_exec_context_sync(void *handle) {
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    return static_cast<int>(cudaStreamSynchronize(context->stream));
}

extern "C" int stwo_exec_context_memory_info(
    void *handle,
    size_t *free_bytes,
    size_t *total_bytes) {
    if (free_bytes == nullptr || total_bytes == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    return static_cast<int>(cudaMemGetInfo(free_bytes, total_bytes));
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
    // The native product currently owns exactly one proof stream. Exposing it
    // as one lane keeps admission and telemetry aligned with actual execution.
    *out_count = 1;
    return 0;
}

extern "C" int stwo_exec_context_join_all_lanes(void *handle) {
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    return static_cast<int>(cudaStreamSynchronize(context->stream));
}

// CUDA events are recorded at stage boundaries and resolved only after the
// proof's existing terminal stream fence. Profiling therefore adds no stage
// synchronization and the events are reusable by a process-owned context.
extern "C" int stwo_exec_context_timing_begin(
    void *handle,
    uint32_t *out_interval_capacity) {
    if (out_interval_capacity == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    *out_interval_capacity = 0;
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    if (context->timing_events[0] == nullptr) {
        for (uint32_t marker = 0; marker < kTimingMarkerCount; ++marker) {
            status = cudaEventCreate(&context->timing_events[marker]);
            if (status == cudaSuccess) continue;
            for (uint32_t cleanup = 0; cleanup <= marker; ++cleanup) {
                if (context->timing_events[cleanup] != nullptr) {
                    cudaEventDestroy(context->timing_events[cleanup]);
                    context->timing_events[cleanup] = nullptr;
                }
            }
            context->timing_marker_count = 0;
            return static_cast<int>(status);
        }
    }
    context->timing_marker_count = 0;
    status = cudaEventRecord(context->timing_events[0], context->stream);
    if (status != cudaSuccess) return static_cast<int>(status);
    context->timing_marker_count = 1;
    *out_interval_capacity = kProofStageCount;
    return 0;
}

extern "C" int stwo_exec_context_timing_mark(void *handle) {
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    if (context->timing_marker_count == 0 ||
        context->timing_marker_count >= kTimingMarkerCount) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    status = cudaEventRecord(
        context->timing_events[context->timing_marker_count],
        context->stream);
    if (status == cudaSuccess) ++context->timing_marker_count;
    return static_cast<int>(status);
}

extern "C" int stwo_exec_context_timing_elapsed(
    void *handle,
    float *out_elapsed_ms,
    uint32_t capacity,
    uint32_t *out_count) {
    if (out_elapsed_ms == nullptr || out_count == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    *out_count = 0;
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    if (context->timing_marker_count != kTimingMarkerCount ||
        capacity < kProofStageCount) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    for (uint32_t interval = 0; interval < kProofStageCount; ++interval) {
        status = cudaEventElapsedTime(
            &out_elapsed_ms[interval],
            context->timing_events[interval],
            context->timing_events[interval + 1]);
        if (status != cudaSuccess) return static_cast<int>(status);
    }
    *out_count = kProofStageCount;
    return 0;
}

extern "C" int stwo_exec_context_nvtx_push(
    void *handle,
    const char *label) {
    if (label == nullptr) return static_cast<int>(cudaErrorInvalidValue);
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    if (context->nvtx_depth != 0) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    if (nvtxRangePushA != nullptr) nvtxRangePushA(label);
    context->nvtx_depth = 1;
    return 0;
}

extern "C" int stwo_exec_context_nvtx_pop(void *handle) {
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    if (context->nvtx_depth != 1) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    if (nvtxRangePop != nullptr) nvtxRangePop();
    context->nvtx_depth = 0;
    return 0;
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
