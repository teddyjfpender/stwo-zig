// Minimal proof-owned CUDA execution context. Every operation is bound to one
// coordination stream, bounded additional streams and one isolated async pool.
// There is no allocation fallback; extra lanes do not enable proof dispatch.

#include <cuda_runtime_api.h>
#include <nvtx3/nvToolsExt.h>

#include "common/provider_compat.cuh"
#include "context_options.h"
#include "admission_v2.h"
#include "pool_trim_policy.h"
#include "allocation_observer.h"
#if !defined(STWO_CUMETAL)
#include "device_arena_runtime.cuh"
#define STWO_DEVICE_ARENA_HOOK 1
#else
#define STWO_DEVICE_ARENA_HOOK 0
#endif

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
    bool read_only = false;
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
    // M5 platform: one reusable event per lane for device-side lane
    // convergence (frees) instead of host joins.
    cudaEvent_t lane_events[STWO_CUDA_CONTEXT_MAX_LANES];
    uint32_t lane_count;
    uint32_t dependency_capacity;
    StwoNativeCudaDependency dependencies[STWO_CUDA_CONTEXT_MAX_DEPENDENCIES];
    uint64_t identity;
    std::thread::id owner_thread;
    bool capture_active;
    bool closing;
    cudaMemPool_t pool;
    // Lifetime segregation: immutable setup/domain planes outlive every
    // request; keeping them out of the per-request pool means a reservation
    // trim of the scratch pool is never pinned by long-lived pages.
    cudaMemPool_t long_pool;
    cudaEvent_t timing_events[kTimingMarkerCount];
    uint32_t timing_marker_count;
    uint32_t nvtx_depth;
    StwoNativeCudaAllocation *allocations;
    size_t allocation_count;
    size_t allocation_capacity;
};

#if STWO_DEVICE_ARENA_HOOK
cudaError_t admission_v2_context_closing(StwoNativeCudaContext *context);
#endif

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

// Host join of every lane. M5 platform: a lane whose work has already
// completed (cudaStreamQuery == cudaSuccess) is not synchronized; that is the
// same host-visible state a cudaStreamSynchronize would return, without a
// blocking driver call. Most joins in a request are on idle lanes.
cudaError_t join_lanes(StwoNativeCudaContext *context) {
    if (context->capture_active) return STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE;
    cudaError_t first = cudaSuccess;
#if STWO_DEVICE_ARENA_HOOK
    auto &counters = stwo::cuda::runtime::arena::counters();
    counters.join_calls.fetch_add(1, std::memory_order_relaxed);
#endif
    for (uint32_t lane = 0; lane < context->lane_count; ++lane) {
        if (context->lanes[lane] == nullptr) continue;
#if STWO_DEVICE_ARENA_HOOK
        const cudaError_t pending = cudaPeekAtLastError();
        cudaError_t status = cudaStreamQuery(context->lanes[lane]);
        if (status == cudaErrorNotReady) {
            // NotReady is a poll result, not an error: never leave it behind
            // for a later cudaPeekAtLastError launch check.
            if (pending == cudaSuccess && cudaPeekAtLastError() == cudaErrorNotReady)
                (void)cudaGetLastError();
            status = cudaStreamSynchronize(context->lanes[lane]);
            counters.lane_syncs.fetch_add(1, std::memory_order_relaxed);
        } else {
            counters.lane_syncs_skipped.fetch_add(1, std::memory_order_relaxed);
        }
#else
        const cudaError_t status = cudaStreamSynchronize(context->lanes[lane]);
#endif
        if (first == cudaSuccess) first = status;
    }
    return first;
}

#if STWO_DEVICE_ARENA_HOOK
// STWO_RV64_EXEC_SYNC=host|device (M5 platform; default host).
// device: stwo_exec_context_sync / join_all_lanes become a device-side
// all-lane barrier (every lane waits for every other lane's submitted work)
// instead of a host join. Every host<->device copy already has a host-visible
// contract of its own (H2D source consumed on return; D2H data present on
// return, pinned or pageable), so the host join only ordered device work
// across lanes, which the barrier preserves. Proof bytes cannot change.
bool device_sync_mode() {
    return false;
}

cudaError_t barrier_lanes(StwoNativeCudaContext *context) {
    if (context->capture_active) return STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE;
    stwo::cuda::runtime::arena::counters().device_barriers.fetch_add(1, std::memory_order_relaxed);
    if (context->lane_count < 2) return cudaSuccess;
    for (uint32_t lane = 0; lane < context->lane_count; ++lane) {
        const cudaError_t status = cudaEventRecord(context->lane_events[lane], context->lanes[lane]);
        if (status != cudaSuccess) return status;
    }
    for (uint32_t lane = 0; lane < context->lane_count; ++lane)
        for (uint32_t other = 0; other < context->lane_count; ++other) {
            if (other == lane) continue;
            const cudaError_t status =
                cudaStreamWaitEvent(context->lanes[lane], context->lane_events[other], 0);
            if (status != cudaSuccess) return status;
        }
    return cudaSuccess;
}

// Device-side convergence: the coordination stream waits for every other
// lane's submitted work. Work enqueued on lane 0 afterwards (and an event
// recorded there) is ordered after all lanes; the host does not block.
cudaError_t converge_lanes(StwoNativeCudaContext *context) {
    if (context->capture_active) return STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE;
    for (uint32_t lane = 1; lane < context->lane_count; ++lane) {
        cudaError_t status = cudaEventRecord(context->lane_events[lane], context->lanes[lane]);
        if (status == cudaSuccess)
            status = cudaStreamWaitEvent(context->stream, context->lane_events[lane], 0);
        if (status != cudaSuccess) return status;
    }
    return cudaSuccess;
}
#endif

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
    if (status == cudaSuccess) status = cudaMemPoolCreate(&context->long_pool, &properties);
    if (status == cudaSuccess) status = cudaMemPoolSetAttribute(
        context->long_pool, cudaMemPoolAttrReleaseThreshold, &release_threshold);
    for (uint32_t lane = 0; status == cudaSuccess && lane < context->lane_count; ++lane) {
        status = cudaStreamCreateWithFlags(&context->lanes[lane], cudaStreamNonBlocking);
    }
    context->stream = context->lanes[0];
#if STWO_DEVICE_ARENA_HOOK
    for (uint32_t lane = 0; status == cudaSuccess && lane < context->lane_count; ++lane)
        status = cudaEventCreateWithFlags(&context->lane_events[lane], cudaEventDisableTiming);
    // M5 platform: carve the static arena when the first context of a device
    // is created (service start), so request 1 pays no cuMemCreate/map.
    if (status == cudaSuccess && stwo::cuda::runtime::arena::config().enabled &&
        stwo::cuda::runtime::arena::config().valid) {
        cudaError_t carve = cudaSuccess;
        auto *arena_device=stwo::cuda::runtime::arena::device(context->device, &carve);
        status = carve;
        if(status==cudaSuccess && stwo::cuda::runtime::arena::observer_enabled()) {
            std::lock_guard<std::mutex> lock(arena_device->mutex);
            for(uint32_t lane=0;lane<context->lane_count;++lane)
                arena_device->observer_stream_owners[context->lanes[lane]]=context->identity;
        }
    }
#endif
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
#if STWO_DEVICE_ARENA_HOOK
    status = admission_v2_context_closing(context);
    if (status != cudaSuccess) return static_cast<int>(status);
#endif
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
        if (context->lane_events[lane] != nullptr) {
            status = cudaEventDestroy(context->lane_events[lane]);
            if (status != cudaSuccess) return static_cast<int>(status);
            context->lane_events[lane] = nullptr;
        }
        if (context->lanes[lane] == nullptr) continue;
#if STWO_DEVICE_ARENA_HOOK
        stwo::cuda::runtime::arena::release_ring(context->lanes[lane]);
        if(stwo::cuda::runtime::arena::observer_enabled() && stwo::cuda::runtime::arena::config().enabled) {
            cudaError_t observer_status=cudaSuccess;
            auto *d=stwo::cuda::runtime::arena::device(context->device,&observer_status);
            if(d) { std::lock_guard<std::mutex> lock(d->mutex); d->observer_stream_owners.erase(context->lanes[lane]); }
        }
#endif
        status = cudaStreamDestroy(context->lanes[lane]);
        if (status != cudaSuccess) return static_cast<int>(status);
        context->lanes[lane] = nullptr;
    }
    if (context->pool != nullptr) {
        status = cudaMemPoolDestroy(context->pool);
        if (status != cudaSuccess) return static_cast<int>(status);
        context->pool = nullptr;
    }
    if (context->long_pool != nullptr) {
        status = cudaMemPoolDestroy(context->long_pool);
        if (status != cudaSuccess) return static_cast<int>(status);
        context->long_pool = nullptr;
    }
    delete[] context->allocations;
    delete context;
#if STWO_DEVICE_ARENA_HOOK
    stwo::cuda::runtime::arena::print_summaries();
#endif
    return 0;
}

extern "C" int stwo_exec_context_sync(void *handle) {
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
#if STWO_DEVICE_ARENA_HOOK
    if (device_sync_mode()) return static_cast<int>(barrier_lanes(context));
#endif
    return static_cast<int>(join_lanes(context));
}

extern "C" int stwo_exec_context_pool_trim(void *handle) {
    StwoNativeCudaContext *context = nullptr;
    return stwo::cuda::runtime::trim_pool(
        [&]() { return static_cast<int>(require_context(handle, &context)); },
        [&]() { return context->capture_active; },
        [&]() { return static_cast<int>(join_lanes(context)); },
        [&]() {
#if STWO_DEVICE_ARENA_HOOK
            if (stwo::cuda::runtime::arena::config().enabled) return 0;
            stwo::cuda::runtime::arena::counters().pool_trims.fetch_add(1);
#endif
            // Both lifetime pools: freed long-lived pages (retired setup,
            // evicted domains) must not stay pinned in the long pool's
            // reservation after an explicit phase trim.
            cudaError_t trimmed = cudaMemPoolTrimTo(context->pool, 0);
            if (trimmed == cudaSuccess && context->long_pool != nullptr)
                trimmed = cudaMemPoolTrimTo(context->long_pool, 0);
            return static_cast<int>(trimmed);
        },
        static_cast<int>(STWO_CUDA_ERROR_INVALID_RESOURCE_HANDLE));
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
#if STWO_DEVICE_ARENA_HOOK
    if (status == cudaSuccess) {
        size_t split_used[2], split_reserved[2];
        if (stwo::cuda::runtime::arena::usage(context->device, split_used, split_reserved)) {
            *used_current = split_used[0] + split_used[1];
            *reserved_current = split_reserved[0] + split_reserved[1];
            return 0;
        }
    }
#endif
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
    uint64_t long_used = 0, long_reserved = 0;
    if (status == cudaSuccess)
        status = cudaMemPoolGetAttribute(context->long_pool, cudaMemPoolAttrUsedMemCurrent, &long_used);
    if (status == cudaSuccess)
        status = cudaMemPoolGetAttribute(context->long_pool, cudaMemPoolAttrReservedMemCurrent, &long_reserved);
    used += long_used;
    reserved += long_reserved;
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
#if STWO_DEVICE_ARENA_HOOK
    if (device_sync_mode()) return static_cast<int>(barrier_lanes(context));
#endif
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
    // Device-mode joins do not complete the terminal marker on the host.
    status = cudaEventSynchronize(context->timing_events[kProofStageCount]);
    if (status != cudaSuccess) return static_cast<int>(status);
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

static int alloc_u32_from(void *handle, size_t count, uint32_t **out_pointer, bool long_lived);
extern "C" int stwo_exec_context_alloc_u32(
    void *handle,
    size_t count,
    uint32_t **out_pointer) {
    return alloc_u32_from(handle, count, out_pointer, false);
}
// Long-lived class (immutable setup, cached domains). Same custody ledger and
// stream-ordered free; only the backing pool differs.
extern "C" int stwo_exec_context_alloc_u32_long(
    void *handle,
    size_t count,
    uint32_t **out_pointer) {
    return alloc_u32_from(handle, count, out_pointer, true);
}
extern "C" int stwo_exec_context_pool_split(
    void *handle, size_t used[2], size_t reserved[2]) {
    if (!used || !reserved) return static_cast<int>(cudaErrorInvalidValue);
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
#if STWO_DEVICE_ARENA_HOOK
    if (status == cudaSuccess && stwo::cuda::runtime::arena::usage(context->device, used, reserved))
        return 0;
#endif
    cudaMemPool_t pools[2] = {context ? context->pool : nullptr,
                              context ? context->long_pool : nullptr};
    for (int i = 0; status == cudaSuccess && i < 2; ++i) {
        uint64_t u = 0, r = 0;
        status = cudaMemPoolGetAttribute(pools[i], cudaMemPoolAttrUsedMemCurrent, &u);
        if (status == cudaSuccess)
            status = cudaMemPoolGetAttribute(pools[i], cudaMemPoolAttrReservedMemCurrent, &r);
        used[i] = static_cast<size_t>(u);
        reserved[i] = static_cast<size_t>(r);
    }
    return static_cast<int>(status);
}
static int alloc_u32_from(void *handle, size_t count, uint32_t **out_pointer, bool long_lived) {
    if (count == 0 || out_pointer == nullptr ||
        count > std::numeric_limits<size_t>::max() / sizeof(uint32_t)) {
        return static_cast<int>(cudaErrorInvalidValue);
    }
    *out_pointer = nullptr;
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(handle, &context);
    if (status == cudaSuccess) status = ensure_allocation_capacity(context);
    cudaMemPool_t pool = context == nullptr ? nullptr
        : (long_lived ? context->long_pool : context->pool);
#if STWO_DEVICE_ARENA_HOOK
    // Static arena: no driver call in steady state; overrun is returned to the
    // caller as cudaErrorMemoryAllocation (never a pool fallback). Graph
    // capture keeps the pool path so captured graphs own their memory nodes.
    const bool use_arena = status == cudaSuccess &&
        stwo::cuda::runtime::arena::config().enabled && !context->capture_active;
    if(status==cudaSuccess && !use_arena && stwo::cuda::runtime::arena::observer_enabled())
        ::fprintf(stderr,"GPU_NODE_ALLOC_COVERAGE_GAP context=%llu reason=non_arena_pool_path requested_bytes=%llu capture_active=%u\n",
            (unsigned long long)context->identity,(unsigned long long)(count*sizeof(uint32_t)),unsigned(context->capture_active));
    if (!use_arena && status == cudaSuccess && context->capture_active &&
        stwo::cuda::runtime::arena::admission_enforced(context->device)) return int(cudaErrorNotSupported);
    if (use_arena) {
        status = stwo::cuda::runtime::arena::allocate(
            context->device, context->stream, context->lanes, context->lane_count,
            count * sizeof(uint32_t), long_lived,
            reinterpret_cast<void **>(out_pointer), context->identity);
    } else if (status == cudaSuccess) {
        stwo::cuda::runtime::arena::counters().pool_mallocs.fetch_add(1, std::memory_order_relaxed);
#else
    if (status == cudaSuccess) {
#endif
        status = cudaMallocFromPoolAsync(
            reinterpret_cast<void **>(out_pointer),
            count * sizeof(uint32_t),
            pool,
            context->stream);
        // Freed async-pool pages can remain physically resident and fragmented
        // despite a small live allocation set. Reclaim only unused backing,
        // after every lane has finished using it, then retry this allocation
        // once. Live witnesses and allocation custody remain unchanged.
        if (status == cudaErrorMemoryAllocation && !context->capture_active) {
#if STWO_DEVICE_ARENA_HOOK
            stwo::cuda::runtime::arena::counters().pool_oom_recoveries.fetch_add(1, std::memory_order_relaxed);
            stwo::cuda::runtime::arena::counters().pool_trims.fetch_add(2, std::memory_order_relaxed);
#endif
            *out_pointer = nullptr;
            // A recovered allocation error must not poison later kernel
            // launch checks using cudaPeekAtLastError on this owner thread.
            (void)cudaGetLastError();
            status = join_lanes(context);
            if (status == cudaSuccess) status = cudaMemPoolTrimTo(context->pool, 0);
            if (status == cudaSuccess) status = cudaMemPoolTrimTo(context->long_pool, 0);
            if (status == cudaSuccess) {
                status = cudaMallocFromPoolAsync(
                    reinterpret_cast<void **>(out_pointer),
                    count * sizeof(uint32_t),
                    pool,
                    context->stream);
            }
        }
    }
    if (status == cudaSuccess) {
        context->allocations[context->allocation_count++] = {
            reinterpret_cast<uintptr_t>(*out_pointer),
            count * sizeof(uint32_t),
        };
    } else {
        *out_pointer = nullptr;
    }
    return static_cast<int>(status);
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
#if STWO_DEVICE_ARENA_HOOK
    // M5 platform: an arena range freed by a multi-lane context is fenced on
    // the device instead of host-joining every lane. Lane 0 waits for all
    // lanes, the release fence is recorded on lane 0 after that wait, and any
    // reuse (any lane of any context) waits on the fence on the device.
    const bool arena_owned = status == cudaSuccess &&
        stwo::cuda::runtime::arena::owns(context->device, pointer);
    if (status == cudaSuccess && context->lane_count > 1 && !arena_owned) status = join_lanes(context);
    if (arena_owned) {
        if (context->capture_active) {
            status = STWO_CUDA_ERROR_INVALID_CONFIGURATION;
        } else {
            if (context->lane_count > 1) {
                status = converge_lanes(context);
                stwo::cuda::runtime::arena::counters().free_fences.fetch_add(1, std::memory_order_relaxed);
            }
            if (status == cudaSuccess)
                status = stwo::cuda::runtime::arena::release(
                    context->device, context->stream, pointer, false);
        }
    } else
#else
    if (status == cudaSuccess && context->lane_count > 1) status = join_lanes(context);
#endif
    if (status == cudaSuccess) {
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

// Native constant images become read-only only after their owner joins writes.
// This guards command-API destinations; custom CUDA kernels remain trusted code.
static cudaError_t reject_read_only(StwoNativeCudaContext *context, const void *ptr, size_t bytes) {
    const uintptr_t begin = reinterpret_cast<uintptr_t>(ptr);
    if (bytes > UINTPTR_MAX - begin) return cudaErrorInvalidValue;
    const uintptr_t end = begin + bytes;
    for (size_t i = 0; i < context->allocation_count; ++i) {
        const auto &allocation = context->allocations[i];
        if (allocation.read_only && begin < allocation.address + allocation.bytes && allocation.address < end)
            return cudaErrorInvalidValue;
    }
    return cudaSuccess;
}
extern "C" int stwo_exec_context_seal_read_only(void *handle, const void *ptr, size_t bytes) {
    StwoNativeCudaContext *context = nullptr;
    const auto status = require_context(handle, &context);
    if (status != cudaSuccess) return static_cast<int>(status);
    for (size_t i = 0; i < context->allocation_count; ++i) {
        auto &allocation = context->allocations[i];
        if (allocation.address == reinterpret_cast<uintptr_t>(ptr) && allocation.bytes == bytes) {
            allocation.read_only = true;
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
    if (status == cudaSuccess) status = reject_read_only(context, destination, bytes);
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
    if (status == cudaSuccess) status = reject_read_only(context, destination, count * sizeof(uint32_t));
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
    if (status == cudaSuccess) status = reject_read_only(context, destination, bytes);
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
    if (status == cudaSuccess) status = reject_read_only(context, destination, bytes);
    if (status == cudaSuccess) {
#if STWO_DEVICE_ARENA_HOOK
        status = stwo::cuda::runtime::arena::copy_async(
            context->stream, destination, source, bytes,
            cudaMemcpyHostToDevice, context->capture_active);
#else
        status = cudaMemcpyAsync(
            destination,
            source,
            bytes,
            cudaMemcpyHostToDevice,
            context->stream);
#endif
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
#if STWO_DEVICE_ARENA_HOOK
        status = stwo::cuda::runtime::arena::copy_async(
            context->stream, destination, source, bytes,
            cudaMemcpyDeviceToHost, context->capture_active);
#else
        status = cudaMemcpyAsync(
            destination,
            source,
            bytes,
            cudaMemcpyDeviceToHost,
            context->stream);
#endif
    }
    return static_cast<int>(status);
}

// M5 platform: stream-ordered scratch from the static arena for library code
// that previously called cudaMallocAsync directly (rv64/trace.cu prefix
// seeds), so no device allocation bypasses the carve. Returns
// cudaErrorNotSupported when the arena is disabled; callers then keep their
// original allocator.
extern "C" int stwo_exec_arena_scratch_alloc(void *stream, size_t bytes, void **out) {
    if (out == nullptr || bytes == 0) return static_cast<int>(cudaErrorInvalidValue);
    *out = nullptr;
#if STWO_DEVICE_ARENA_HOOK
    if (!stwo::cuda::runtime::arena::config().enabled) return static_cast<int>(cudaErrorNotSupported);
    int device = -1;
    cudaError_t status = cudaGetDevice(&device);
    cudaStream_t s = static_cast<cudaStream_t>(stream);
    if (status == cudaSuccess)
        status = stwo::cuda::runtime::arena::allocate(device, s, &s, 1, bytes, false, out);
    return static_cast<int>(status);
#else
    (void)stream;
    return static_cast<int>(cudaErrorNotSupported);
#endif
}

extern "C" int stwo_exec_arena_scratch_free(void *stream, void *pointer) {
#if STWO_DEVICE_ARENA_HOOK
    int device = -1;
    cudaError_t status = cudaGetDevice(&device);
    if (status == cudaSuccess)
        status = stwo::cuda::runtime::arena::release(
            device, static_cast<cudaStream_t>(stream), pointer, false);
    return static_cast<int>(status);
#else
    (void)stream;
    (void)pointer;
    return static_cast<int>(cudaErrorNotSupported);
#endif
}

// 1 when device allocations come from the static arena (the PCS physical
// admission must then count only the carve, never cudaMemGetInfo free bytes,
// which the arena cannot use).
extern "C" int stwo_exec_arena_enabled(void) {
#if STWO_DEVICE_ARENA_HOOK
    return stwo::cuda::runtime::arena::config().enabled && stwo::cuda::runtime::arena::config().valid ? 1 : 0;
#else
    return 0;
#endif
}

struct alignas(8) StwoCudaArenaSnapshotV1 {
    uint32_t version, device;
    uint64_t capacity, chunk, small_slab, live_large, live_small, largest_virtual_free;
    uint64_t free_device, total_device;
};
static_assert(sizeof(StwoCudaArenaSnapshotV1) == 72, "arena snapshot ABI");
#if STWO_DEVICE_ARENA_HOOK
namespace {
void arena_snapshot_locked(stwo::cuda::runtime::arena::Device *d, int device, StwoCudaArenaSnapshotV1 *out) {
    *out = {}; out->version=1; out->device=uint32_t(device);
    out->capacity=d->capacity(); out->chunk=d->chunk; out->small_slab=d->small_bytes;
    out->live_large=d->live-d->live_small; out->live_small=d->live_small;
    d->arena->for_each_free([&](uint64_t, uint64_t bytes){ out->largest_virtual_free=std::max(out->largest_virtual_free,bytes); });
}
}
#endif
extern "C" int stwo_exec_context_arena_snapshot_v1(void *raw, StwoCudaArenaSnapshotV1 *out) {
#if STWO_DEVICE_ARENA_HOOK
    if (!out) return int(cudaErrorInvalidValue);
    StwoNativeCudaContext *context=nullptr;
    cudaError_t status=require_context(raw,&context); if(status!=cudaSuccess) return int(status);
    auto *d=stwo::cuda::runtime::arena::device(context->device,&status);
    if(!d) return int(status);
    { std::lock_guard<std::mutex> lock(d->mutex); arena_snapshot_locked(d,context->device,out); }
    size_t free=0,total=0; status=cudaSetDevice(context->device);
    if(status==cudaSuccess) status=cudaMemGetInfo(&free,&total);
    out->free_device=free; out->total_device=total; return int(status);
#else
    return int(cudaErrorNotSupported);
#endif
}
extern "C" int stwo_exec_context_admission_configure_v1(void *raw, uint64_t capacity) {
#if STWO_DEVICE_ARENA_HOOK
    StwoNativeCudaContext *context=nullptr;
    cudaError_t status=require_context(raw,&context); if(status!=cudaSuccess) return int(status);
    const auto &c=stwo::cuda::runtime::arena::config();
    if(!c.valid || !c.enabled || !capacity || c.bytes!=capacity || c.chunk!=(32ull<<20) || c.small_chunks!=16)
        return int(cudaErrorInvalidValue);
    auto *d=stwo::cuda::runtime::arena::device(context->device,&status); if(!d) return int(status);
    std::lock_guard<std::mutex> lock(d->mutex);
    if(d->admission_version==2 || d->capacity()!=capacity || d->admission_ticket || (!d->admission_required && d->live)) return int(cudaErrorInvalidValue);
    d->admission_required=true; d->admission_version=1; return 0;
#else
    return int(cudaErrorNotSupported);
#endif
}
extern "C" int stwo_exec_context_admission_begin_v1(void *raw, uint64_t ticket,
    uint64_t expected_large, uint64_t expected_small, uint64_t add_large, uint64_t add_small, const char *label) {
#if STWO_DEVICE_ARENA_HOOK
    StwoNativeCudaContext *context=nullptr;
    cudaError_t status=require_context(raw,&context); if(status!=cudaSuccess) return int(status);
    if(!ticket || !label || context->capture_active || context->nvtx_depth) return int(cudaErrorInvalidValue);
    auto *d=stwo::cuda::runtime::arena::device(context->device,&status); if(!d) return int(status);
    std::lock_guard<std::mutex> lock(d->mutex);
    const uint64_t large=d->live-d->live_small, small=d->live_small;
    if(!d->admission_required || d->admission_version!=1 || d->admission_ticket || large>expected_large || small>expected_small ||
       add_large>d->capacity()-d->small_bytes || large>d->capacity()-d->small_bytes-add_large ||
       add_small>d->small_bytes || small>d->small_bytes-add_small) return int(cudaErrorInvalidValue);
    d->admission_ticket=ticket; d->admission_owner=context->identity;
    d->admission_large_ceiling=large+add_large; d->admission_small_ceiling=small+add_small;
    nvtxRangePushA(label); context->nvtx_depth=1; return 0;
#else
    return int(cudaErrorNotSupported);
#endif
}
extern "C" int stwo_exec_context_admission_end_v1(void *raw, uint64_t ticket, StwoCudaArenaSnapshotV1 *out) {
#if STWO_DEVICE_ARENA_HOOK
    if(!out) return int(cudaErrorInvalidValue);
    StwoNativeCudaContext *context=nullptr;
    cudaError_t status=require_context(raw,&context); if(status!=cudaSuccess) return int(status);
    auto *d=stwo::cuda::runtime::arena::device(context->device,&status); if(!d) return int(status);
    { std::lock_guard<std::mutex> lock(d->mutex);
      if(!ticket || d->admission_ticket!=ticket || d->admission_owner!=context->identity || context->nvtx_depth!=1) return int(cudaErrorInvalidValue);
      d->admission_ticket=0; d->admission_owner=0;
      arena_snapshot_locked(d,context->device,out);
    }
    nvtxRangePop(); context->nvtx_depth=0;
    size_t free=0,total=0; status=cudaMemGetInfo(&free,&total);
    out->free_device=free;out->total_device=total; return int(status);
#else
    return int(cudaErrorNotSupported);
#endif
}

#if STWO_DEVICE_ARENA_HOOK
namespace {
namespace Arena = stwo::cuda::runtime::arena;
struct AdmissionHostContext { uint64_t identity; int device; };
std::mutex admission_host_mutex;
std::unordered_map<void *, AdmissionHostContext> admission_host_contexts;

bool add_checked(uint64_t a, uint64_t b, uint64_t *out) {
    if (a > UINT64_MAX - b) return false;
    *out = a + b; return true;
}
bool unused_locked(Arena::Device *d, uint64_t *large, uint64_t *small) {
    *large = 0; *small = 0;
    for (const auto &entry : d->owner_windows) {
        const auto live = d->owner_live.find(entry.first);
        const uint64_t budget_large = entry.second.ceiling_large - entry.second.baseline_large;
        const uint64_t budget_small = entry.second.ceiling_small - entry.second.baseline_small;
        if (live == d->owner_live.end() || entry.second.new_large > budget_large || entry.second.new_small > budget_small) return false;
        if (!add_checked(*large, budget_large - entry.second.new_large, large) ||
            !add_checked(*small, budget_small - entry.second.new_small, small)) return false;
    }
    return true;
}
// Caller holds admission_host_mutex. Lookup does not dereference a stale raw
// pointer or query CUDA; teardown removes the identity before deleting it.
Arena::Device *host_device_locked(void *raw, uint64_t identity) {
    const auto registered = admission_host_contexts.find(raw);
    if (!identity || registered == admission_host_contexts.end() || registered->second.identity != identity) return nullptr;
    std::lock_guard<std::mutex> lock(Arena::registry_mutex());
    const int device = registered->second.device;
    return device >= 0 && device < Arena::kMaxDevices ? Arena::registry()[device] : nullptr;
}
bool owner_snapshot_locked(Arena::Device *d, uint64_t identity, StwoCudaOwnerSnapshotV2 *out) {
    const auto live = d->owner_live.find(identity);
    if (!out || d->admission_version != 2 || live == d->owner_live.end()) return false;
    *out = {}; out->version = 2; out->device = uint32_t(d->ordinal);
    out->context_identity = identity; out->capacity = d->capacity();
    out->chunk = d->chunk; out->small_slab = d->small_bytes;
    out->global_live_large = d->live - d->live_small; out->global_live_small = d->live_small;
    if (!unused_locked(d, &out->reserved_unused_large, &out->reserved_unused_small)) return false;
    out->owner_live_large = live->second.large; out->owner_live_small = live->second.small;
    out->stable_live_large = out->global_live_large; out->stable_live_small = out->global_live_small;
    out->active_reservations = d->owner_windows.size();
    for (const auto &entry : d->owner_windows) {
        if (entry.second.new_large > out->stable_live_large || entry.second.new_small > out->stable_live_small) return false;
        out->stable_live_large -= entry.second.new_large; out->stable_live_small -= entry.second.new_small;
    }
    const auto window = d->owner_windows.find(identity);
    if (window != d->owner_windows.end()) {
        out->ticket = window->second.ticket;
        out->baseline_large = window->second.baseline_large; out->baseline_small = window->second.baseline_small;
        out->ceiling_large = window->second.ceiling_large; out->ceiling_small = window->second.ceiling_small;
        out->owner_new_live_large = window->second.new_large; out->owner_new_live_small = window->second.new_small;
        out->entered = window->second.entered; out->ended = window->second.ended;
    }
    return true;
}
cudaError_t admission_v2_context_closing(StwoNativeCudaContext *context) {
    std::lock_guard<std::mutex> host(admission_host_mutex);
    const auto registered = admission_host_contexts.find(context);
    if (registered == admission_host_contexts.end()) return cudaSuccess;
    auto *d = host_device_locked(context, context->identity);
    if (!d) return cudaErrorInvalidValue;
    std::lock_guard<std::mutex> lock(d->mutex);
    const auto live = d->owner_live.find(context->identity);
    if (live == d->owner_live.end() || live->second.large || live->second.small) return cudaErrorInvalidValue;
    // The destructor has already joined every lane and verified zero live
    // context allocations. Only its own terminal reservation may be canceled.
    d->owner_windows.erase(context->identity);
    d->owner_live.erase(live);
    admission_host_contexts.erase(registered);
    return cudaSuccess;
}
}
#endif

extern "C" int stwo_exec_context_admission_configure_v2(void *raw, uint64_t capacity) {
#if STWO_DEVICE_ARENA_HOOK
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(raw, &context); if (status != cudaSuccess) return int(status);
    const auto &c = Arena::config();
    if (!c.valid || !c.enabled || !capacity || c.bytes != capacity || c.chunk != (32ull << 20) || c.small_chunks != 16) return int(cudaErrorInvalidValue);
    auto *d = Arena::device(context->device, &status); if (!d) return int(status);
    std::lock_guard<std::mutex> host(admission_host_mutex);
    std::lock_guard<std::mutex> lock(d->mutex);
    if (d->capacity() != capacity || d->admission_version == 1 || d->admission_ticket || (!d->admission_required && d->live)) return int(cudaErrorInvalidValue);
    bool inserted = false;
    try {
        const auto registered = admission_host_contexts.find(raw);
        if (registered != admission_host_contexts.end() && registered->second.identity != context->identity) return int(cudaErrorInvalidValue);
        inserted = d->owner_live.emplace(context->identity, Arena::OwnerLive{}).second;
        admission_host_contexts[raw] = {context->identity, context->device};
    } catch (const std::bad_alloc &) {
        if (inserted) d->owner_live.erase(context->identity);
        return int(cudaErrorMemoryAllocation);
    }
    d->admission_required = true; d->admission_version = 2; return 0;
#else
    return int(cudaErrorNotSupported);
#endif
}
extern "C" int stwo_exec_context_admission_snapshot_v2(void *raw, uint64_t identity, StwoCudaOwnerSnapshotV2 *out) {
#if STWO_DEVICE_ARENA_HOOK
    if (!out) return int(cudaErrorInvalidValue);
    std::lock_guard<std::mutex> host(admission_host_mutex);
    auto *d = host_device_locked(raw, identity); if (!d) return int(cudaErrorInvalidValue);
    std::lock_guard<std::mutex> lock(d->mutex);
    return owner_snapshot_locked(d, identity, out) ? 0 : int(cudaErrorInvalidValue);
#else
    return int(cudaErrorNotSupported);
#endif
}
extern "C" int stwo_exec_context_admission_reserve_v2(void *raw, uint64_t identity, uint64_t ticket,
    uint64_t add_large, uint64_t add_small, StwoCudaOwnerSnapshotV2 *out) {
#if STWO_DEVICE_ARENA_HOOK
    if (!out || !ticket) return int(cudaErrorInvalidValue);
    std::lock_guard<std::mutex> host(admission_host_mutex);
    auto *d = host_device_locked(raw, identity); if (!d) return int(cudaErrorInvalidValue);
    std::lock_guard<std::mutex> lock(d->mutex);
    if (d->admission_version != 2 || d->owner_windows.count(identity) || add_large % d->chunk || add_small % 512) return int(cudaErrorInvalidValue);
    for (const auto &w : d->owner_windows) if (w.second.ticket == ticket) return int(cudaErrorInvalidValue);
    const auto creator = d->owner_live.find(identity); if (creator == d->owner_live.end()) return int(cudaErrorInvalidValue);
    uint64_t unused_large = 0, unused_small = 0, total_large = 0, total_small = 0;
    if (!unused_locked(d, &unused_large, &unused_small) ||
        !add_checked(d->live - d->live_small, unused_large, &total_large) || !add_checked(total_large, add_large, &total_large) ||
        !add_checked(d->live_small, unused_small, &total_small) || !add_checked(total_small, add_small, &total_small) ||
        total_large > d->capacity() - d->small_bytes || total_small > d->small_bytes) return int(cudaErrorMemoryAllocation);
    Arena::OwnerWindow window;
    window.ticket = ticket; window.baseline_large = creator->second.large; window.baseline_small = creator->second.small;
    if (!add_checked(window.baseline_large, add_large, &window.ceiling_large) || !add_checked(window.baseline_small, add_small, &window.ceiling_small)) return int(cudaErrorInvalidValue);
    try { d->owner_windows.emplace(identity, window); } catch (const std::bad_alloc &) { return int(cudaErrorMemoryAllocation); }
    if (!owner_snapshot_locked(d, identity, out)) { d->owner_windows.erase(identity); return int(cudaErrorInvalidValue); }
    return 0;
#else
    return int(cudaErrorNotSupported);
#endif
}
extern "C" int stwo_exec_context_admission_enter_v2(void *raw, uint64_t ticket, const char *label) {
#if STWO_DEVICE_ARENA_HOOK
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(raw, &context); if (status != cudaSuccess) return int(status);
    if (!ticket || !label || context->capture_active || context->nvtx_depth) return int(cudaErrorInvalidValue);
    auto *d = Arena::device(context->device, &status); if (!d) return int(status);
    std::lock_guard<std::mutex> lock(d->mutex);
    const auto window = d->owner_windows.find(context->identity);
    if (d->admission_version != 2 || window == d->owner_windows.end() || window->second.ticket != ticket || window->second.entered || window->second.ended) return int(cudaErrorInvalidValue);
    window->second.entered = true; nvtxRangePushA(label); context->nvtx_depth = 1; return 0;
#else
    return int(cudaErrorNotSupported);
#endif
}
extern "C" int stwo_exec_context_admission_end_v2(void *raw, uint64_t ticket, StwoCudaOwnerSnapshotV2 *out) {
#if STWO_DEVICE_ARENA_HOOK
    if (!out) return int(cudaErrorInvalidValue);
    StwoNativeCudaContext *context = nullptr;
    cudaError_t status = require_context(raw, &context); if (status != cudaSuccess) return int(status);
    auto *d = Arena::device(context->device, &status); if (!d) return int(status);
    std::lock_guard<std::mutex> lock(d->mutex);
    const auto window = d->owner_windows.find(context->identity);
    if (d->admission_version != 2 || window == d->owner_windows.end() || window->second.ticket != ticket || !window->second.entered || window->second.ended || context->nvtx_depth != 1) return int(cudaErrorInvalidValue);
    // The owner has joined its lanes. Keep the reservation until host finish;
    // new allocations from this ended window are forbidden immediately.
    window->second.ended = true; nvtxRangePop(); context->nvtx_depth = 0;
    return owner_snapshot_locked(d, context->identity, out) ? 0 : int(cudaErrorInvalidValue);
#else
    return int(cudaErrorNotSupported);
#endif
}
namespace {
int admission_close_v2(void *raw, uint64_t identity, uint64_t ticket, StwoCudaOwnerSnapshotV2 *out, bool entered) {
#if STWO_DEVICE_ARENA_HOOK
    if (!out || !ticket) return int(cudaErrorInvalidValue);
    std::lock_guard<std::mutex> host(admission_host_mutex);
    auto *d = host_device_locked(raw, identity); if (!d) return int(cudaErrorInvalidValue);
    std::lock_guard<std::mutex> lock(d->mutex);
    const auto window = d->owner_windows.find(identity);
    if (window == d->owner_windows.end() || window->second.ticket != ticket || window->second.entered != entered || (entered && !window->second.ended) || (!entered && (window->second.new_large || window->second.new_small))) return int(cudaErrorInvalidValue);
    d->owner_windows.erase(window);
    return owner_snapshot_locked(d, identity, out) ? 0 : int(cudaErrorInvalidValue);
#else
    return int(cudaErrorNotSupported);
#endif
}
}
extern "C" int stwo_exec_context_admission_cancel_v2(void *raw, uint64_t identity, uint64_t ticket, StwoCudaOwnerSnapshotV2 *out) {
    return admission_close_v2(raw, identity, ticket, out, false);
}
extern "C" int stwo_exec_context_admission_finish_v2(void *raw, uint64_t identity, uint64_t ticket, StwoCudaOwnerSnapshotV2 *out) {
    return admission_close_v2(raw, identity, ticket, out, true);
}

// Observer APIs are scheduling diagnostics. Their host joins are deliberate;
// the resulting request walls are NEVER qualified latency measurements.
extern "C" int stwo_exec_context_allocation_observer_capability_v1() { return 1; }
extern "C" int stwo_exec_context_allocation_observer_begin_v1(void *raw,
    const uint32_t key[8], uint32_t ordinal, uint32_t domain, uint32_t stage, uint32_t lane) {
#if STWO_DEVICE_ARENA_HOOK
    namespace A=stwo::cuda::runtime::arena;
    if(!A::observer_enabled()) return 0;
    StwoNativeCudaContext *context=nullptr;
    auto status=require_context(raw,&context); if(status!=cudaSuccess) return int(status);
    if(!key || !stage || stage>21 || lane>=context->lane_count || !A::config().enabled) return int(cudaErrorInvalidValue);
    status=join_lanes(context); if(status!=cudaSuccess) return int(status);
    auto *d=A::device(context->device,&status); if(!d) return int(status);
    std::lock_guard<std::mutex> lock(d->mutex);
    status=A::purge(d); if(status!=cudaSuccess) return int(status);
    if(d->observer_stages.count(context->identity)) return int(cudaErrorInvalidValue);
    std::array<uint32_t,8> stable; std::copy(key,key+8,stable.begin());
    size_t node=0;
    for(;node<d->observer_nodes.size();++node) {
        const auto &n=d->observer_nodes[node];
        if(n.key==stable && n.ordinal==ordinal && n.domain==domain) break;
    }
    if(node==d->observer_nodes.size()) {
        A::ObserverNode n; n.key=stable;n.ordinal=ordinal;n.domain=domain;
        d->observer_nodes.push_back(n);
    }
    auto &n=d->observer_nodes[node];
    if(stage==1) {
        // A repeat request reuses the semantic node key. Never reset while
        // prior-request reservations or retirement fences remain attributed.
        if(n.live.rounded || n.live.pending_rounded) return int(cudaErrorInvalidValue);
        ++n.epoch;n.peak={};n.including_pending_upper=0;
    } else if(!n.epoch) n.epoch=1;
    A::ObserverStage s; s.node=node+1;s.stage=stage;s.lane=lane;s.gaps_before=d->observer_gaps;
    s.baseline=n.live;s.peak=s.baseline;
    uint64_t attributed=0;for(const auto &entry:d->observer_nodes)attributed+=entry.live.rounded;
    s.shared_baseline=d->live-attributed;
    d->observer_stages.emplace(context->identity,s);A::observer_sample(d);
    return 0;
#else
    (void)raw;(void)key;(void)ordinal;(void)domain;(void)stage;(void)lane;return int(cudaErrorNotSupported);
#endif
}
extern "C" int stwo_exec_context_allocation_observer_next_v1(void *raw,uint32_t stage,uint32_t lane) {
#if STWO_DEVICE_ARENA_HOOK
    namespace A=stwo::cuda::runtime::arena;
    if(!A::observer_enabled()) return 0;
    StwoNativeCudaContext *context=nullptr;auto status=require_context(raw,&context);
    if(status!=cudaSuccess) return int(status);
    if(!stage || stage>21 || lane>=context->lane_count) return int(cudaErrorInvalidValue);
    status=join_lanes(context);if(status!=cudaSuccess)return int(status);
    auto *d=A::device(context->device,&status);if(!d)return int(status);
    std::lock_guard<std::mutex> lock(d->mutex);status=A::purge(d);if(status!=cudaSuccess)return int(status);
    auto found=d->observer_stages.find(context->identity);
    if(found==d->observer_stages.end()) {++d->observer_gaps;return 0;}
    A::observer_sample(d);A::observer_print(d,context->identity,found->second);
    auto &s=found->second;s.stage=stage;s.lane=lane;s.baseline=d->observer_nodes[s.node-1].live;
    s.peak=s.baseline;s.including_pending_upper=s.baseline.rounded+s.baseline.pending_rounded;
    s.global_rounded_peak=d->live;s.gaps_before=d->observer_gaps;
    uint64_t attributed=0;for(const auto &entry:d->observer_nodes)attributed+=entry.live.rounded;
    s.shared_baseline=d->live-attributed;s.shared_rounded_peak=s.shared_baseline;
    return 0;
#else
    (void)raw;(void)stage;(void)lane;return int(cudaErrorNotSupported);
#endif
}
extern "C" int stwo_exec_context_allocation_observer_end_v1(void *raw) {
#if STWO_DEVICE_ARENA_HOOK
    namespace A=stwo::cuda::runtime::arena;
    if(!A::observer_enabled())return 0;
    StwoNativeCudaContext *context=nullptr;auto status=require_context(raw,&context);if(status!=cudaSuccess)return int(status);
    status=join_lanes(context);if(status!=cudaSuccess)return int(status);
    auto *d=A::device(context->device,&status);if(!d)return int(status);
    std::lock_guard<std::mutex> lock(d->mutex);status=A::purge(d);if(status!=cudaSuccess)return int(status);
    auto found=d->observer_stages.find(context->identity);if(found==d->observer_stages.end())return int(cudaErrorInvalidValue);
    A::observer_sample(d);A::observer_print(d,context->identity,found->second);d->observer_stages.erase(found);return 0;
#else
    (void)raw;return int(cudaErrorNotSupported);
#endif
}
extern "C" int stwo_exec_context_allocation_observer_bind_v1(void *raw,const void *pointer,uint64_t active_bytes) {
#if STWO_DEVICE_ARENA_HOOK
    namespace A=stwo::cuda::runtime::arena;
    if(!A::observer_enabled())return 0;
    StwoNativeCudaContext *context=nullptr;auto status=require_context(raw,&context);if(status!=cudaSuccess)return int(status);
    // An idle-cache transition is a diagnostic retirement boundary. In the
    // device-sync preset the normal sync may only enqueue a barrier, so join
    // before removing the node's tag from still-executing cached storage.
    if(!active_bytes) {status=join_lanes(context);if(status!=cudaSuccess)return int(status);}
    auto *d=A::device(context->device,&status);if(!d)return int(status);
    std::lock_guard<std::mutex> lock(d->mutex);
    const auto address=reinterpret_cast<uintptr_t>(pointer),base=reinterpret_cast<uintptr_t>(d->base);
    if(address<base)return int(cudaErrorInvalidValue);
    auto found=d->live_bytes_by_offset.find(address-base);
    if(found==d->live_bytes_by_offset.end() || found->second.creator!=context->identity || active_bytes>found->second.observer_requested)
        return int(cudaErrorInvalidValue);
    auto &a=found->second;
    auto stage=d->observer_stages.find(context->identity);
    if(active_bytes && stage==d->observer_stages.end()) ++d->observer_gaps;
    a.observer_node=active_bytes && stage!=d->observer_stages.end() ? stage->second.node : 0;
    a.observer_active=active_bytes;a.observer_idle=!active_bytes;
    A::observer_sample(d);return 0;
#else
    (void)raw;(void)pointer;(void)active_bytes;return int(cudaErrorNotSupported);
#endif
}
