// Minimal proof-owned CUDA execution context. Every operation is bound to one
// coordination stream, bounded additional streams and one isolated async pool.
// There is no allocation fallback; extra lanes do not enable proof dispatch.

#include <cuda_runtime_api.h>
#include <nvtx3/nvToolsExt.h>

#include "common/provider_compat.cuh"
#include "context_options.h"

#include <stddef.h>
#include <stdint.h>

#include <limits>
#include <cstring>
#include <new>
#include <atomic>
#include <thread>

namespace {

constexpr uint32_t kProofStageCount = 10;
constexpr uint32_t kTimingMarkerCount = kProofStageCount + 1;
constexpr size_t kInitialAllocationCapacity = 256;

struct StwoNativeCudaAllocation {
    uintptr_t address;
    size_t bytes;
    bool managed;
};

struct StwoNativeCudaDependency {
    cudaEvent_t event;
    uint64_t generation;
    uint32_t producer_lane;
    bool active;
};

struct StwoNativeCudaContext {
    int device;
    cudaStream_t stream;
    cudaStream_t lanes[STWO_CUDA_CONTEXT_MAX_LANES];
    uint32_t lane_count;
    uint32_t dependency_capacity;
    StwoNativeCudaDependency dependencies[STWO_CUDA_CONTEXT_MAX_DEPENDENCIES];
    uint64_t identity;
    std::thread::id owner_thread;
    bool capture_active;
    bool closing;
    cudaMemPool_t pool;
    cudaEvent_t timing_events[kTimingMarkerCount];
    uint32_t timing_marker_count;
    uint32_t nvtx_depth;
    StwoNativeCudaAllocation *allocations;
    size_t allocation_count;
    size_t allocation_capacity;
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
    StwoNativeCudaContext **out_context,
    bool allow_closing = false) {
    if (handle == nullptr || out_context == nullptr) {
        return cudaErrorInvalidValue;
    }
    auto *context = static_cast<StwoNativeCudaContext *>(handle);
    if (context->owner_thread != std::this_thread::get_id() ||
        (context->closing && !allow_closing)) {
        return STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE;
    }
    int current = -1;
    cudaError_t status = cudaGetDevice(&current);
    if (status != cudaSuccess) return status;
    if (current != context->device) return STWO_CUDA_ERROR_INVALID_DEVICE;
    *out_context = context;
    return cudaSuccess;
}

// A token survives reuse of a native control-node address only when its
// independently owned context identity and monotonic slot generation agree.
std::atomic<uint64_t> next_context_identity{1};

uint64_t acquire_context_identity() {
    uint64_t identity = next_context_identity.load(std::memory_order_relaxed);
    while (identity != std::numeric_limits<uint64_t>::max()) {
        if (next_context_identity.compare_exchange_weak(
                identity, identity + 1, std::memory_order_relaxed)) return identity;
    }
    return 0;
}

cudaError_t join_lanes(StwoNativeCudaContext *context) {
    if (context->capture_active) return STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE;
    cudaError_t first = cudaSuccess;
    for (uint32_t lane = 0; lane < context->lane_count; ++lane) {
        if (context->lanes[lane] == nullptr) continue;
        const cudaError_t status = cudaStreamSynchronize(context->lanes[lane]);
        if (first == cudaSuccess) first = status;
    }
    return first;
}

cudaError_t require_dependency(
    StwoNativeCudaContext *context,
    const StwoCudaDependency *token,
    StwoNativeCudaDependency **out) {
    if (token == nullptr || out == nullptr || context->capture_active ||
        token->context_identity != context->identity || token->generation == 0 ||
        token->slot >= context->dependency_capacity ||
        token->producer_lane >= context->lane_count) {
        return STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE;
    }
    auto *dependency = &context->dependencies[token->slot];
    if (!dependency->active || dependency->generation != token->generation ||
        dependency->producer_lane != token->producer_lane) {
        return STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE;
    }
    *out = dependency;
    return cudaSuccess;
}

cudaError_t ensure_allocation_capacity(StwoNativeCudaContext *context) {
    if (context->allocation_count < context->allocation_capacity) {
        return cudaSuccess;
    }
    const size_t next_capacity = context->allocation_capacity == 0
        ? kInitialAllocationCapacity
        : context->allocation_capacity * 2;
    if (next_capacity < context->allocation_capacity ||
        next_capacity > std::numeric_limits<size_t>::max() /
            sizeof(StwoNativeCudaAllocation)) {
        return cudaErrorMemoryAllocation;
    }
    auto *next = new (std::nothrow)
        StwoNativeCudaAllocation[next_capacity];
    if (next == nullptr) return cudaErrorMemoryAllocation;
    if (context->allocation_count != 0) {
        std::memcpy(
            next,
            context->allocations,
            context->allocation_count * sizeof(StwoNativeCudaAllocation));
    }
    delete[] context->allocations;
    context->allocations = next;
    context->allocation_capacity = next_capacity;
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

extern "C" uint32_t stwo_cuda_execution_provider() {
#if defined(STWO_CUMETAL)
    return STWO_CUDA_EXECUTION_PROVIDER_CUMETAL;
#else
    return STWO_CUDA_EXECUTION_PROVIDER_NVIDIA;
#endif
}

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
    if (status == cudaSuccess && count <= 0) status = STWO_CUDA_ERROR_NO_DEVICE;
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
        return static_cast<int>(STWO_CUDA_ERROR_INVALID_DEVICE);
    }

#if defined(STWO_CUMETAL)
    // CuMetal has no PCI/IOKit UUID in its CUDA-compatible device structure.
    // Derive a stable, explicitly synthetic provider-local identity from the
    // immutable device description rather than publishing an all-zero UUID.
    uint64_t low = 1469598103934665603ull;
    for (size_t index = 0;
         index < sizeof(properties.name) && properties.name[index] != '\0';
         ++index) {
        low ^= static_cast<uint8_t>(properties.name[index]);
        low *= 1099511628211ull;
    }
    low ^= static_cast<uint64_t>(properties.totalGlobalMem);
    low *= 1099511628211ull;
    low ^= static_cast<uint64_t>(properties.multiProcessorCount);
    const uint64_t high = low ^ 0x43554d4554414c32ull;
    std::memcpy(out->uuid, &low, sizeof(low));
    std::memcpy(out->uuid + sizeof(low), &high, sizeof(high));
#else
    std::memcpy(out->uuid, properties.uuid.bytes, sizeof(out->uuid));
#endif
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

extern "C" int stwo_exec_context_destroy(void *handle);

extern "C" int stwo_exec_context_create_options(
    const StwoCudaContextOptions *options,
    void **out_handle) {
    if (out_handle == nullptr) return static_cast<int>(cudaErrorInvalidValue);
    *out_handle = nullptr;
    if (options == nullptr || options->version != STWO_CUDA_CONTEXT_OPTIONS_VERSION ||
        options->lane_count == 0 || options->lane_count > STWO_CUDA_CONTEXT_MAX_LANES ||
        options->dependency_capacity > STWO_CUDA_CONTEXT_MAX_DEPENDENCIES) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
#if defined(STWO_CUMETAL)
    // No compatibility emulation of NVIDIA dependency routing.
    if (options->lane_count != 1 || options->dependency_capacity != 0)
        return static_cast<int>(STWO_CUDA_ERROR_INVALID_CONFIGURATION);
#endif
    int previous_device = -1;
    int device_count = 0;
    cudaError_t status = cudaGetDevice(&previous_device);
    if (status == cudaSuccess) status = cudaGetDeviceCount(&device_count);
    const uint32_t selected = options->device_ordinal == UINT32_MAX
        ? static_cast<uint32_t>(previous_device) : options->device_ordinal;
    if (status != cudaSuccess) return static_cast<int>(status);
    if (device_count <= 0 || selected >= static_cast<uint32_t>(device_count))
        return static_cast<int>(STWO_CUDA_ERROR_INVALID_DEVICE);
#if defined(STWO_CUMETAL)
    if (selected != static_cast<uint32_t>(previous_device))
        return static_cast<int>(STWO_CUDA_ERROR_INVALID_DEVICE);
#else
    status = cudaSetDevice(static_cast<int>(selected));
    if (status != cudaSuccess) return static_cast<int>(status);
#endif
    auto *context = new (std::nothrow) StwoNativeCudaContext{};
    if (context == nullptr) {
#if !defined(STWO_CUMETAL)
        cudaSetDevice(previous_device);
#endif
        return static_cast<int>(cudaErrorMemoryAllocation);
    }
    context->device = static_cast<int>(selected);
    context->owner_thread = std::this_thread::get_id();
    context->identity = acquire_context_identity();
    context->lane_count = options->lane_count;
    context->dependency_capacity = options->dependency_capacity;
    if (context->identity == 0) status = STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE;
    cudaMemPoolProps properties{};
#if defined(STWO_CUMETAL)
    properties.location_type = 0;
    properties.location_id = context->device;
#else
    properties.allocType = cudaMemAllocationTypePinned;
    properties.handleTypes = cudaMemHandleTypeNone;
    properties.location.type = cudaMemLocationTypeDevice;
    properties.location.id = context->device;
#endif
    if (status == cudaSuccess) status = cudaMemPoolCreate(&context->pool, &properties);
    uint64_t release_threshold = std::numeric_limits<uint64_t>::max();
    if (status == cudaSuccess) status = cudaMemPoolSetAttribute(
        context->pool, cudaMemPoolAttrReleaseThreshold, &release_threshold);
    for (uint32_t lane = 0; status == cudaSuccess && lane < context->lane_count; ++lane) {
        status = cudaStreamCreateWithFlags(&context->lanes[lane], cudaStreamNonBlocking);
    }
    context->stream = context->lanes[0];
#if !defined(STWO_CUMETAL)
    for (uint32_t slot = 0; status == cudaSuccess && slot < context->dependency_capacity; ++slot) {
        status = cudaEventCreateWithFlags(&context->dependencies[slot].event, cudaEventDisableTiming);
    }
#endif
    if (status != cudaSuccess) {
        const cudaError_t create_status = status;
        const cudaError_t cleanup_status = static_cast<cudaError_t>(
            stwo_exec_context_destroy(context));
        if (cleanup_status != cudaSuccess) {
            // The options ABI explicitly transfers a teardown-only owner on
            // cleanup failure. The typed Zig construction result retains it.
            context->closing = true;
            *out_handle = context;
            return static_cast<int>(cleanup_status);
        }
#if !defined(STWO_CUMETAL)
        cudaSetDevice(previous_device);
#endif
        return static_cast<int>(create_status);
    }
    *out_handle = context;
    return 0;
}

extern "C" int stwo_exec_context_create(void **out_handle) {
    const StwoCudaContextOptions options{
        STWO_CUDA_CONTEXT_OPTIONS_VERSION, UINT32_MAX, 1, 0};
    return stwo_exec_context_create_options(&options, out_handle);
}

extern "C" int stwo_exec_context_destroy(void *handle) {
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context, true);
    if (status != cudaSuccess) return static_cast<int>(status);
    if (context->allocation_count != 0 || context->capture_active)
        return static_cast<int>(STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE);
    status = join_lanes(context);
    if (status != cudaSuccess) return static_cast<int>(status);
    context->closing = true;
    if (context->nvtx_depth != 0) { nvtxRangePop(); context->nvtx_depth = 0; }
    // A failed destroy retains the control owner with remaining handles for
    // retry; ordinary operations reject a partially closed context.
    for (uint32_t slot = 0; slot < context->dependency_capacity; ++slot) {
        auto *dependency = &context->dependencies[slot];
        if (dependency->event == nullptr) continue;
        status = cudaEventDestroy(dependency->event);
        if (status != cudaSuccess) return static_cast<int>(status);
        dependency->event = nullptr;
        dependency->active = false;
    }
    for (uint32_t marker = 0; marker < kTimingMarkerCount; ++marker) {
        if (context->timing_events[marker] == nullptr) continue;
        status = cudaEventDestroy(context->timing_events[marker]);
        if (status != cudaSuccess) return static_cast<int>(status);
        context->timing_events[marker] = nullptr;
    }
    for (uint32_t lane = 0; lane < context->lane_count; ++lane) {
        if (context->lanes[lane] == nullptr) continue;
        status = cudaStreamDestroy(context->lanes[lane]);
        if (status != cudaSuccess) return static_cast<int>(status);
        context->lanes[lane] = nullptr;
    }
    if (context->pool != nullptr) {
        status = cudaMemPoolDestroy(context->pool);
        if (status != cudaSuccess) return static_cast<int>(status);
        context->pool = nullptr;
    }
    delete[] context->allocations;
    delete context;
    return 0;
}

extern "C" int stwo_exec_context_sync(void *handle) {
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    return static_cast<int>(join_lanes(context));
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
    *out_count = context->lane_count;
    return 0;
}

extern "C" int stwo_exec_context_join_all_lanes(void *handle) {
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    return static_cast<int>(join_lanes(context));
}

extern "C" int stwo_exec_context_identity(void *handle, uint64_t *out_identity) {
    if (out_identity == nullptr) return static_cast<int>(cudaErrorInvalidValue);
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    *out_identity = context->identity;
    return 0;
}

extern "C" int stwo_exec_context_lane_stream(void *handle, uint32_t lane, void **out_stream) {
    if (out_stream == nullptr) return static_cast<int>(cudaErrorInvalidValue);
    *out_stream = nullptr;
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    if (lane >= context->lane_count || context->capture_active)
        return static_cast<int>(STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE);
    *out_stream = context->lanes[lane];
    return 0;
}

extern "C" int stwo_exec_context_dependency_record(
    void *handle, uint32_t lane, uint32_t slot, StwoCudaDependency *out_token) {
    if (out_token == nullptr) return static_cast<int>(cudaErrorInvalidValue);
    *out_token = {};
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    if (context->capture_active || lane >= context->lane_count ||
        slot >= context->dependency_capacity) return static_cast<int>(cudaErrorInvalidValue);
    auto *dependency = &context->dependencies[slot];
    if (dependency->active || dependency->generation == std::numeric_limits<uint64_t>::max())
        return static_cast<int>(STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE);
#if defined(STWO_CUMETAL)
    return static_cast<int>(STWO_CUDA_ERROR_INVALID_CONFIGURATION);
#else
    status = cudaEventRecord(dependency->event, context->lanes[lane]);
    if (status != cudaSuccess) return static_cast<int>(status);
    ++dependency->generation;
    dependency->producer_lane = lane;
    dependency->active = true;
    *out_token = {context->identity, dependency->generation, slot, lane};
    return 0;
#endif
}

extern "C" int stwo_exec_context_dependency_wait(
    void *handle, uint32_t lane, const StwoCudaDependency *token) {
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    StwoNativeCudaDependency *dependency = nullptr;
    status = require_dependency(context, token, &dependency);
    if (status != cudaSuccess) return static_cast<int>(status);
    if (lane >= context->lane_count) return static_cast<int>(cudaErrorInvalidValue);
#if defined(STWO_CUMETAL)
    return static_cast<int>(STWO_CUDA_ERROR_INVALID_CONFIGURATION);
#else
    return static_cast<int>(cudaStreamWaitEvent(context->lanes[lane], dependency->event, 0));
#endif
}

extern "C" int stwo_exec_context_dependency_release(void *handle, const StwoCudaDependency *token) {
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    StwoNativeCudaDependency *dependency = nullptr;
    status = require_dependency(context, token, &dependency);
    if (status != cudaSuccess) return static_cast<int>(status);
    // Explicit terminal retirement: all producer and waiter work completes
    // before a slot can be recorded again. This is not nonblocking reclamation.
    status = join_lanes(context);
    if (status == cudaSuccess) dependency->active = false;
    return static_cast<int>(status);
}

extern "C" int stwo_exec_context_dependencies_reset(void *handle) {
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status == cudaSuccess) status = join_lanes(context);
    if (status != cudaSuccess) return static_cast<int>(status);
    for (uint32_t slot = 0; slot < context->dependency_capacity; ++slot)
        context->dependencies[slot].active = false;
    return 0;
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
    nvtxRangePushA(label);
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
    nvtxRangePop();
    context->nvtx_depth = 0;
    return 0;
}

extern "C" int stwo_graph_capture_begin(void *handle) {
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    if (context->capture_active) return static_cast<int>(STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE);
    for (uint32_t slot = 0; slot < context->dependency_capacity; ++slot)
        if (context->dependencies[slot].active)
            return static_cast<int>(STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE);
    // Cross-lane graph/event routing is deliberately not admitted yet.
    if (context->lane_count != 1) return static_cast<int>(STWO_CUDA_ERROR_INVALID_CONFIGURATION);
    status = cudaStreamBeginCapture(context->stream, cudaStreamCaptureModeThreadLocal);
    if (status == cudaSuccess) context->capture_active = true;
    return static_cast<int>(status);
}

extern "C" int stwo_graph_capture_end(
    void *handle,
    void **out_exec,
    uint64_t *out_kernel_nodes) {
    if (out_exec == nullptr || out_kernel_nodes == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    *out_exec = nullptr;
    *out_kernel_nodes = 0;
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);

    if (!context->capture_active) return static_cast<int>(STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE);
    cudaGraph_t graph = nullptr;
    status = cudaStreamEndCapture(context->stream, &graph);
    context->capture_active = false;
    if (status != cudaSuccess) {
        if (graph != nullptr) cudaGraphDestroy(graph);
        return static_cast<int>(status);
    }
    if (graph == nullptr) {
        return static_cast<int>(STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE);
    }

    size_t node_count = 0;
    status = cudaGraphGetNodes(graph, nullptr, &node_count);
    if (status != cudaSuccess) {
        cudaGraphDestroy(graph);
        return static_cast<int>(status);
    }
    cudaGraphNode_t *nodes = node_count == 0
        ? nullptr
        : new (std::nothrow) cudaGraphNode_t[node_count];
    if (node_count != 0 && nodes == nullptr) {
        cudaGraphDestroy(graph);
        return static_cast<int>(cudaErrorMemoryAllocation);
    }
    if (node_count != 0) {
        status = cudaGraphGetNodes(graph, nodes, &node_count);
    }
    uint64_t kernel_nodes = 0;
    for (size_t index = 0; status == cudaSuccess && index < node_count; ++index) {
        cudaGraphNodeType type{};
        status = cudaGraphNodeGetType(nodes[index], &type);
        kernel_nodes += type == cudaGraphNodeTypeKernel;
    }
    delete[] nodes;
    if (status != cudaSuccess || kernel_nodes == 0) {
        cudaGraphDestroy(graph);
        return static_cast<int>(
            status == cudaSuccess ? STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE : status);
    }

    cudaGraphExec_t exec = nullptr;
    status = cudaGraphInstantiate(&exec, graph, nullptr, nullptr, 0);
    const cudaError_t destroy_status = cudaGraphDestroy(graph);
    if (status != cudaSuccess) return static_cast<int>(status);
    if (destroy_status != cudaSuccess) {
        cudaGraphExecDestroy(exec);
        return static_cast<int>(destroy_status);
    }
    if (exec == nullptr) {
        return static_cast<int>(STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE);
    }
    *out_exec = reinterpret_cast<void *>(exec);
    *out_kernel_nodes = kernel_nodes;
    return 0;
}

extern "C" int stwo_graph_capture_abort(void *handle) {
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    if (!context->capture_active) return static_cast<int>(STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE);
    cudaGraph_t graph = nullptr;
    status = cudaStreamEndCapture(context->stream, &graph);
    context->capture_active = false;
    if (graph != nullptr) {
        const cudaError_t destroy_status = cudaGraphDestroy(graph);
        if (status == cudaSuccess) status = destroy_status;
    }
    return static_cast<int>(status);
}

extern "C" int stwo_graph_launch(
    void *exec_handle,
    void *context_handle) {
    if (exec_handle == nullptr) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(context_handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    if (context->capture_active || context->lane_count != 1)
        return static_cast<int>(STWO_CUDA_ERROR_INVALID_CONFIGURATION);
    return static_cast<int>(cudaGraphLaunch(
        reinterpret_cast<cudaGraphExec_t>(exec_handle),
        context->stream));
}

extern "C" int stwo_graph_destroy(void *exec_handle) {
    if (exec_handle == nullptr) return 0;
    return static_cast<int>(cudaGraphExecDestroy(
        reinterpret_cast<cudaGraphExec_t>(exec_handle)));
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
    if (status == cudaSuccess) status = ensure_allocation_capacity(context);
    if (status == cudaSuccess) {
        status = cudaMallocFromPoolAsync(
            reinterpret_cast<void **>(out_pointer),
            count * sizeof(uint32_t),
            context->pool,
            context->stream);
    }
    if (status == cudaSuccess) {
        context->allocations[context->allocation_count++] = {
            reinterpret_cast<uintptr_t>(*out_pointer),
            count * sizeof(uint32_t),
            false,
        };
    }
    return static_cast<int>(status);
}

// Opt-in out-of-core request arena. The ordinary device allocation remains
// the default. Managed memory is admitted only on devices that support
// concurrent managed access (and therefore GPU-memory oversubscription).
extern "C" int stwo_exec_context_alloc_managed_u32(
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
    int concurrent_access = 0;
    if (status == cudaSuccess) status = cudaDeviceGetAttribute(
        &concurrent_access, cudaDevAttrConcurrentManagedAccess, context->device);
    if (status == cudaSuccess && concurrent_access == 0)
        return static_cast<int>(cudaErrorNotSupported);
    if (status == cudaSuccess) status = ensure_allocation_capacity(context);
    if (status == cudaSuccess) status = cudaMallocManaged(
        reinterpret_cast<void **>(out_pointer),
        count * sizeof(uint32_t), cudaMemAttachGlobal);
    if (status == cudaSuccess) {
        context->allocations[context->allocation_count++] = {
            reinterpret_cast<uintptr_t>(*out_pointer),
            count * sizeof(uint32_t),
            true,
        };
    }
    return static_cast<int>(status);
}

extern "C" int stwo_exec_context_prefetch_managed(
    void *handle,
    const void *pointer,
    size_t bytes,
    int to_device) {
    if (pointer == nullptr || bytes == 0 || (to_device != 0 && to_device != 1))
        return static_cast<int>(cudaErrorInvalidValue);
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    const uintptr_t address = reinterpret_cast<uintptr_t>(pointer);
    for (size_t index = 0; index < context->allocation_count; ++index) {
        const StwoNativeCudaAllocation allocation = context->allocations[index];
        if (!allocation.managed || address < allocation.address) continue;
        const size_t offset = static_cast<size_t>(address - allocation.address);
        if (offset <= allocation.bytes && bytes <= allocation.bytes - offset) {
#if CUDART_VERSION >= 13000
            const cudaMemLocation location = to_device
                ? cudaMemLocation{cudaMemLocationTypeDevice, context->device}
                : cudaMemLocation{cudaMemLocationTypeHost, 0};
            return static_cast<int>(cudaMemPrefetchAsync(
                pointer, bytes, location, 0, context->stream));
#else
            return static_cast<int>(cudaMemPrefetchAsync(
                pointer, bytes,
                to_device ? context->device : cudaCpuDeviceId,
                context->stream));
#endif
        }
    }
    return static_cast<int>(cudaErrorInvalidDevicePointer);
}

extern "C" int stwo_exec_context_advise_managed_host(
    void *handle,
    const void *pointer,
    size_t bytes,
    int prefer_host) {
    if (pointer == nullptr || bytes == 0 ||
        (prefer_host != 0 && prefer_host != 1))
        return static_cast<int>(cudaErrorInvalidValue);
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    const uintptr_t address = reinterpret_cast<uintptr_t>(pointer);
    for (size_t index = 0; index < context->allocation_count; ++index) {
        const StwoNativeCudaAllocation allocation = context->allocations[index];
        if (!allocation.managed || address < allocation.address) continue;
        const size_t offset = static_cast<size_t>(address - allocation.address);
        if (offset > allocation.bytes || bytes > allocation.bytes - offset)
            continue;
#if CUDART_VERSION >= 13000
        const cudaMemLocation host_location{cudaMemLocationTypeHost, 0};
        const cudaMemLocation device_location{
            cudaMemLocationTypeDevice, context->device};
        if (prefer_host) {
            status = cudaMemAdvise(pointer, bytes,
                cudaMemAdviseSetPreferredLocation, host_location);
            if (status == cudaSuccess) status = cudaMemAdvise(pointer, bytes,
                cudaMemAdviseSetAccessedBy, device_location);
        } else {
            status = cudaMemAdvise(pointer, bytes,
                cudaMemAdviseUnsetAccessedBy, device_location);
            if (status == cudaSuccess) status = cudaMemAdvise(pointer, bytes,
                cudaMemAdviseUnsetPreferredLocation, host_location);
        }
#else
        if (prefer_host) {
            status = cudaMemAdvise(pointer, bytes,
                cudaMemAdviseSetPreferredLocation, cudaCpuDeviceId);
            if (status == cudaSuccess) status = cudaMemAdvise(pointer, bytes,
                cudaMemAdviseSetAccessedBy, context->device);
        } else {
            status = cudaMemAdvise(pointer, bytes,
                cudaMemAdviseUnsetAccessedBy, context->device);
            if (status == cudaSuccess) status = cudaMemAdvise(pointer, bytes,
                cudaMemAdviseUnsetPreferredLocation, cudaCpuDeviceId);
        }
#endif
        return static_cast<int>(status);
    }
    return static_cast<int>(cudaErrorInvalidDevicePointer);
}

extern "C" int stwo_exec_context_free_u32(
    void *handle,
    uint32_t *pointer) {
    if (pointer == nullptr) return static_cast<int>(cudaErrorInvalidValue);
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    size_t allocation_index = 0;
    if (status == cudaSuccess) {
        const uintptr_t address = reinterpret_cast<uintptr_t>(pointer);
        while (allocation_index < context->allocation_count &&
               context->allocations[allocation_index].address != address) {
            ++allocation_index;
        }
        if (allocation_index == context->allocation_count) {
            status = cudaErrorInvalidDevicePointer;
        }
    }
    if (status == cudaSuccess && context->lane_count > 1) status = join_lanes(context);
    if (status == cudaSuccess && context->allocations[allocation_index].managed) {
        status = cudaStreamSynchronize(context->stream);
        if (status == cudaSuccess) status = cudaFree(pointer);
    } else if (status == cudaSuccess) {
        status = cudaFreeAsync(pointer, context->stream);
    }
    if (status == cudaSuccess) {
        --context->allocation_count;
        context->allocations[allocation_index] =
            context->allocations[context->allocation_count];
        context->allocations[context->allocation_count] = {};
    }
    return static_cast<int>(status);
}

// Authenticate one exact resident range against this proof context's own
// allocation ledger. CUDA pointer-context metadata is not an ownership proof
// for cudaMallocFromPoolAsync allocations and differs across driver/runtime
// allocation classes on real hardware.
extern "C" int stwo_exec_context_validate_allocation(
    void *handle,
    const void *pointer,
    size_t required_bytes) {
    if (pointer == nullptr || required_bytes == 0) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    const uintptr_t address = reinterpret_cast<uintptr_t>(pointer);
    for (size_t index = 0; index < context->allocation_count; ++index) {
        const StwoNativeCudaAllocation allocation =
            context->allocations[index];
        if (address < allocation.address) continue;
        const size_t offset = static_cast<size_t>(
            address - allocation.address);
        if (offset <= allocation.bytes &&
            required_bytes <= allocation.bytes - offset) {
            return 0;
        }
    }
    return static_cast<int>(cudaErrorInvalidDevicePointer);
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
