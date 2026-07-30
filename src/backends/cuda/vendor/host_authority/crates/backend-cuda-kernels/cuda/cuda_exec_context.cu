#include <cuda.h>
#include <cuda_runtime.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <new>
#include <vector>

// ---------------------------------------------------------------------------
// Resource-owning execution context for ONE resident proof (design §19).
//
// The core prove path is stream-0-centric: every kernel + every pool alloc/free
// is ordered on the legacy default stream (see cuda_mem_pool.cuh). To run two
// proofs concurrently, each must own an independent CUDA stream AND its own
// stream-ordered memory pool: two contexts allocating from DISJOINT pools have no
// cross-stream reuse hazard, whereas two streams sharing the single global default
// pool have no ordering guarantee between one's cudaFreeAsync and the other's
// kernels (the central concurrency hazard in the recon).
//
// A context is NOT just a stream pointer — it owns the stream and the pool, and all
// alloc / free / kernel work for the proof's streamful island routes through its
// stream, so buffers free stream-ordered AFTER their last use on that stream. No
// stream-0 free ever races another stream's kernels (the resource-lifetime bug).
//
// Handles are opaque `void*` (StwoExecContext*), matching the FFI style of the rest
// of this crate. Pool creation fails closed: a live context is always isolated.
// ---------------------------------------------------------------------------

namespace {
constexpr uint32_t STWO_EXEC_LANE_COUNT = 8;
constexpr uint32_t STWO_EXEC_TIMING_EVENT_COUNT = 32;

struct StwoExecContext {
    cudaStream_t stream;
    cudaStream_t lanes[STWO_EXEC_LANE_COUNT];
    cudaEvent_t lane_forks[STWO_EXEC_LANE_COUNT];
    cudaEvent_t lane_joins[STWO_EXEC_LANE_COUNT];
    cudaEvent_t timing_events[STWO_EXEC_TIMING_EVENT_COUNT];
    uint32_t timing_marker_count;
    cudaMemPool_t pool;
    int device_id;
};

StwoExecContext *context_from(void *handle) {
    return static_cast<StwoExecContext *>(handle);
}

cudaError_t first_error(cudaError_t current, cudaError_t candidate) {
    return current == cudaSuccess ? candidate : current;
}

void report_graph_kernel_node(
    const char *role,
    size_t index,
    cudaGraphNode_t node
) {
    CUDA_KERNEL_NODE_PARAMS params{};
    CUresult params_err = cuGraphKernelNodeGetParams(
        reinterpret_cast<CUgraphNode>(node),
        &params);
    if (params_err != CUDA_SUCCESS) {
        std::fprintf(
            stderr,
            "stwo graph: %s kernel_node=%zu params_status=%d\n",
            role,
            index,
            static_cast<int>(params_err));
        return;
    }

    int registers = 0;
    int static_shared_bytes = 0;
    int local_bytes = 0;
    int max_threads = 0;
    CUresult registers_err = cuFuncGetAttribute(
        &registers,
        CU_FUNC_ATTRIBUTE_NUM_REGS,
        params.func);
    CUresult shared_err = cuFuncGetAttribute(
        &static_shared_bytes,
        CU_FUNC_ATTRIBUTE_SHARED_SIZE_BYTES,
        params.func);
    CUresult local_err = cuFuncGetAttribute(
        &local_bytes,
        CU_FUNC_ATTRIBUTE_LOCAL_SIZE_BYTES,
        params.func);
    CUresult threads_err = cuFuncGetAttribute(
        &max_threads,
        CU_FUNC_ATTRIBUTE_MAX_THREADS_PER_BLOCK,
        params.func);
    if (registers_err != CUDA_SUCCESS || shared_err != CUDA_SUCCESS ||
        local_err != CUDA_SUCCESS || threads_err != CUDA_SUCCESS) {
        std::fprintf(
            stderr,
            "stwo graph: %s kernel_node=%zu grid=%ux%ux%u block=%ux%ux%u "
            "dynamic_smem=%u attribute_statuses=%d,%d,%d,%d func=%p\n",
            role,
            index,
            params.gridDimX,
            params.gridDimY,
            params.gridDimZ,
            params.blockDimX,
            params.blockDimY,
            params.blockDimZ,
            params.sharedMemBytes,
            static_cast<int>(registers_err),
            static_cast<int>(shared_err),
            static_cast<int>(local_err),
            static_cast<int>(threads_err),
            reinterpret_cast<void *>(params.func));
        return;
    }

    std::fprintf(
        stderr,
        "stwo graph: %s kernel_node=%zu grid=%ux%ux%u block=%ux%ux%u "
        "dynamic_smem=%u regs=%d static_smem=%d local_bytes=%d "
        "max_threads=%d func=%p\n",
        role,
        index,
        params.gridDimX,
        params.gridDimY,
        params.gridDimZ,
        params.blockDimX,
        params.blockDimY,
        params.blockDimZ,
        params.sharedMemBytes,
        registers,
        static_shared_bytes,
        local_bytes,
        max_threads,
        reinterpret_cast<void *>(params.func));
}

__global__ void fill_u32_kernel(uint32_t *dst, uint32_t value, size_t count) {
    size_t index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (index < count) {
        dst[index] = value;
    }
}
}  // namespace

// Snapshot the runtime device selected for subsequent context construction.
// Replacement-v1 uses this before creating any stream, pool, module, or device
// table so its current single-visible-device containment fails closed.
extern "C" int stwo_cuda_device_snapshot(
    uint32_t *out_count,
    uint32_t *out_current,
    uint32_t *out_sm_major,
    uint32_t *out_sm_minor
) {
    if (out_count == nullptr || out_current == nullptr || out_sm_major == nullptr ||
        out_sm_minor == nullptr) {
        return cudaErrorInvalidValue;
    }
    *out_count = 0;
    *out_current = 0;
    *out_sm_major = 0;
    *out_sm_minor = 0;

    int count = 0;
    cudaError_t err = cudaGetDeviceCount(&count);
    if (err != cudaSuccess) {
        return err;
    }
    if (count <= 0) {
        return cudaErrorNoDevice;
    }

    int current = 0;
    err = cudaGetDevice(&current);
    if (err != cudaSuccess) {
        return err;
    }
    if (current < 0 || current >= count) {
        return cudaErrorInvalidDevice;
    }

    cudaDeviceProp properties = {};
    err = cudaGetDeviceProperties(&properties, current);
    if (err != cudaSuccess) {
        return err;
    }
    *out_count = static_cast<uint32_t>(count);
    *out_current = static_cast<uint32_t>(current);
    *out_sm_major = static_cast<uint32_t>(properties.major);
    *out_sm_minor = static_cast<uint32_t>(properties.minor);
    return cudaSuccess;
}

// Create a context: a non-blocking stream + its own never-release memory pool on
// the current device. Isolation is part of the contract, so pool creation fails
// closed instead of silently falling back to the process-wide default pool.
extern "C" int stwo_exec_context_create(void **out_handle) {
    if (out_handle == nullptr) {
        return cudaErrorInvalidValue;
    }
    *out_handle = nullptr;

    StwoExecContext *ctx = new (std::nothrow) StwoExecContext();
    if (ctx == nullptr) {
        return cudaErrorMemoryAllocation;
    }
    ctx->stream = nullptr;
    for (uint32_t lane = 0; lane < STWO_EXEC_LANE_COUNT; ++lane) {
        ctx->lanes[lane] = nullptr;
        ctx->lane_forks[lane] = nullptr;
        ctx->lane_joins[lane] = nullptr;
    }
    for (uint32_t marker = 0; marker < STWO_EXEC_TIMING_EVENT_COUNT; ++marker) {
        ctx->timing_events[marker] = nullptr;
    }
    ctx->timing_marker_count = 0;
    ctx->pool = nullptr;
    ctx->device_id = -1;

    cudaError_t err = cudaStreamCreateWithFlags(&ctx->stream, cudaStreamNonBlocking);
    if (err != cudaSuccess) {
        delete ctx;
        return err;
    }

    for (uint32_t lane = 0; lane < STWO_EXEC_LANE_COUNT; ++lane) {
        err = cudaStreamCreateWithFlags(&ctx->lanes[lane], cudaStreamNonBlocking);
        if (err == cudaSuccess) {
            err = cudaEventCreateWithFlags(&ctx->lane_forks[lane], cudaEventDisableTiming);
        }
        if (err == cudaSuccess) {
            err = cudaEventCreateWithFlags(&ctx->lane_joins[lane], cudaEventDisableTiming);
        }
        if (err != cudaSuccess) {
            for (uint32_t cleanup = 0; cleanup <= lane; ++cleanup) {
                if (ctx->lane_joins[cleanup] != nullptr) {
                    cudaEventDestroy(ctx->lane_joins[cleanup]);
                }
                if (ctx->lane_forks[cleanup] != nullptr) {
                    cudaEventDestroy(ctx->lane_forks[cleanup]);
                }
                if (ctx->lanes[cleanup] != nullptr) {
                    cudaStreamDestroy(ctx->lanes[cleanup]);
                }
            }
            cudaStreamDestroy(ctx->stream);
            delete ctx;
            return err;
        }
    }

    int device_id = 0;
    err = cudaGetDevice(&device_id);
    if (err != cudaSuccess) {
        for (uint32_t lane = 0; lane < STWO_EXEC_LANE_COUNT; ++lane) {
            cudaEventDestroy(ctx->lane_joins[lane]);
            cudaEventDestroy(ctx->lane_forks[lane]);
            cudaStreamDestroy(ctx->lanes[lane]);
        }
        cudaStreamDestroy(ctx->stream);
        delete ctx;
        return err;
    }
    ctx->device_id = device_id;

    cudaMemPoolProps props = {};
    props.allocType = cudaMemAllocationTypePinned;
    props.handleTypes = cudaMemHandleTypeNone;
    props.location.type = cudaMemLocationTypeDevice;
    props.location.id = device_id;
    err = cudaMemPoolCreate(&ctx->pool, &props);
    if (err != cudaSuccess || ctx->pool == nullptr) {
        for (uint32_t lane = 0; lane < STWO_EXEC_LANE_COUNT; ++lane) {
            cudaEventDestroy(ctx->lane_joins[lane]);
            cudaEventDestroy(ctx->lane_forks[lane]);
            cudaStreamDestroy(ctx->lanes[lane]);
        }
        cudaStreamDestroy(ctx->stream);
        delete ctx;
        return err == cudaSuccess ? cudaErrorMemoryAllocation : err;
    }

    // Never release back to the OS between warm proves, so a workspace can retain
    // its slab for the full capture epoch without allocator churn.
    uint64_t threshold = UINT64_MAX;
    err = cudaMemPoolSetAttribute(ctx->pool, cudaMemPoolAttrReleaseThreshold, &threshold);
    if (err != cudaSuccess) {
        cudaMemPoolDestroy(ctx->pool);
        for (uint32_t lane = 0; lane < STWO_EXEC_LANE_COUNT; ++lane) {
            cudaEventDestroy(ctx->lane_joins[lane]);
            cudaEventDestroy(ctx->lane_forks[lane]);
            cudaStreamDestroy(ctx->lanes[lane]);
        }
        cudaStreamDestroy(ctx->stream);
        delete ctx;
        return err;
    }

    *out_handle = ctx;
    return cudaSuccess;
}

// Sync + tear down. Every component lane and the main stream are drained before
// their events, streams, and shared proof pool are destroyed.
extern "C" int stwo_exec_context_destroy(void *handle) {
    if (handle == nullptr) {
        return cudaSuccess;
    }
    StwoExecContext *ctx = context_from(handle);
    cudaError_t err = cudaSuccess;
    for (uint32_t lane = 0; lane < STWO_EXEC_LANE_COUNT; ++lane) {
        if (ctx->lanes[lane] != nullptr) {
            err = first_error(err, cudaStreamSynchronize(ctx->lanes[lane]));
        }
    }
    if (ctx->stream != nullptr) {
        err = first_error(err, cudaStreamSynchronize(ctx->stream));
    }
    for (uint32_t marker = 0; marker < STWO_EXEC_TIMING_EVENT_COUNT; ++marker) {
        if (ctx->timing_events[marker] != nullptr) {
            err = first_error(err, cudaEventDestroy(ctx->timing_events[marker]));
        }
    }
    for (uint32_t lane = 0; lane < STWO_EXEC_LANE_COUNT; ++lane) {
        if (ctx->lane_joins[lane] != nullptr) {
            err = first_error(err, cudaEventDestroy(ctx->lane_joins[lane]));
        }
        if (ctx->lane_forks[lane] != nullptr) {
            err = first_error(err, cudaEventDestroy(ctx->lane_forks[lane]));
        }
        if (ctx->lanes[lane] != nullptr) {
            err = first_error(err, cudaStreamDestroy(ctx->lanes[lane]));
        }
    }
    if (ctx->stream != nullptr) {
        err = first_error(err, cudaStreamDestroy(ctx->stream));
    }
    if (ctx->pool != nullptr) {
        err = first_error(err, cudaMemPoolDestroy(ctx->pool));
    }
    delete ctx;
    return err;
}

// Block the host until all work enqueued on the context's stream has completed.
extern "C" int stwo_exec_context_sync(void *handle) {
    if (handle == nullptr) {
        return cudaErrorInvalidResourceHandle;
    }
    return cudaStreamSynchronize(context_from(handle)->stream);
}

// Checked current footprint of this context's isolated pool. This intentionally
// does not synchronize: callers that need a post-free snapshot must first fence
// the context, while resident-ledger callers can inspect the live arena without
// perturbing execution.
extern "C" int stwo_exec_context_pool_current(
    void *handle, size_t *used_current, size_t *reserved_current
) {
    if (handle == nullptr || used_current == nullptr || reserved_current == nullptr) {
        return cudaErrorInvalidValue;
    }
    *used_current = 0;
    *reserved_current = 0;
    StwoExecContext *ctx = context_from(handle);
    if (ctx->pool == nullptr) {
        return cudaErrorInvalidResourceHandle;
    }

    uint64_t used = 0;
    uint64_t reserved = 0;
    cudaError_t err =
        cudaMemPoolGetAttribute(ctx->pool, cudaMemPoolAttrUsedMemCurrent, &used);
    if (err != cudaSuccess) {
        return err;
    }
    err = cudaMemPoolGetAttribute(ctx->pool, cudaMemPoolAttrReservedMemCurrent, &reserved);
    if (err != cudaSuccess) {
        return err;
    }
    *used_current = static_cast<size_t>(used);
    *reserved_current = static_cast<size_t>(reserved);
    return cudaSuccess;
}

// Fence exactly one borrowed launch stream. The ownership check prevents a
// stale or foreign stream handle from being synchronized through this context.
extern "C" int stwo_exec_context_stream_sync(void *handle, void *stream) {
    if (handle == nullptr || stream == nullptr) {
        return cudaErrorInvalidResourceHandle;
    }
    StwoExecContext *ctx = context_from(handle);
    cudaStream_t target = reinterpret_cast<cudaStream_t>(stream);
    bool owned = target == ctx->stream;
    for (uint32_t lane = 0; lane < STWO_EXEC_LANE_COUNT && !owned; ++lane) {
        owned = target == ctx->lanes[lane];
    }
    if (!owned) {
        return cudaErrorInvalidResourceHandle;
    }
    return cudaStreamSynchronize(target);
}

// The context's stream as an opaque handle, to pass to `_on(stream)` kernel variants.
extern "C" int stwo_exec_context_stream(void *handle, void **out_stream) {
    if (handle == nullptr || out_stream == nullptr) {
        return cudaErrorInvalidValue;
    }
    *out_stream = reinterpret_cast<void *>(context_from(handle)->stream);
    return *out_stream == nullptr ? cudaErrorInvalidResourceHandle : cudaSuccess;
}

// Device identity captured when the context was created. VMM allocations use
// this instead of process-global current-device state for fail-closed ownership.
extern "C" int stwo_exec_context_device(void *handle, int *out_device) {
    if (handle == nullptr || out_device == nullptr) {
        return cudaErrorInvalidValue;
    }
    const int device = context_from(handle)->device_id;
    if (device < 0) {
        return cudaErrorInvalidDevice;
    }
    *out_device = device;
    return cudaSuccess;
}

// Diagnostic-only device timeline. Events are created on first use, before the
// first recorded marker, and then reused across warm proofs. Recording a marker
// is asynchronous; elapsed time is queried only after the proof's existing
// stream fence, so instrumentation adds no synchronization to the hot path.
extern "C" int stwo_exec_context_timing_begin(
    void *handle, uint32_t *out_interval_capacity
) {
    if (handle == nullptr || out_interval_capacity == nullptr) {
        return cudaErrorInvalidValue;
    }
    *out_interval_capacity = 0;
    StwoExecContext *ctx = context_from(handle);
    if (ctx->timing_events[0] == nullptr) {
        for (uint32_t marker = 0; marker < STWO_EXEC_TIMING_EVENT_COUNT; ++marker) {
            cudaError_t err = cudaEventCreate(&ctx->timing_events[marker]);
            if (err != cudaSuccess) {
                for (uint32_t cleanup = 0; cleanup <= marker; ++cleanup) {
                    if (ctx->timing_events[cleanup] != nullptr) {
                        cudaEventDestroy(ctx->timing_events[cleanup]);
                        ctx->timing_events[cleanup] = nullptr;
                    }
                }
                ctx->timing_marker_count = 0;
                return err;
            }
        }
    }
    ctx->timing_marker_count = 0;
    cudaError_t err = cudaEventRecord(ctx->timing_events[0], ctx->stream);
    if (err != cudaSuccess) {
        return err;
    }
    ctx->timing_marker_count = 1;
    *out_interval_capacity = STWO_EXEC_TIMING_EVENT_COUNT - 1;
    return cudaSuccess;
}

extern "C" int stwo_exec_context_timing_mark(void *handle) {
    if (handle == nullptr) {
        return cudaErrorInvalidValue;
    }
    StwoExecContext *ctx = context_from(handle);
    if (ctx->timing_marker_count == 0 ||
        ctx->timing_marker_count >= STWO_EXEC_TIMING_EVENT_COUNT) {
        return cudaErrorInvalidValue;
    }
    cudaError_t err = cudaEventRecord(
        ctx->timing_events[ctx->timing_marker_count], ctx->stream);
    if (err == cudaSuccess) {
        ++ctx->timing_marker_count;
    }
    return err;
}

extern "C" int stwo_exec_context_timing_elapsed(
    void *handle,
    float *out_elapsed_ms,
    uint32_t capacity,
    uint32_t *out_count
) {
    if (handle == nullptr || out_elapsed_ms == nullptr || out_count == nullptr) {
        return cudaErrorInvalidValue;
    }
    *out_count = 0;
    StwoExecContext *ctx = context_from(handle);
    if (ctx->timing_marker_count < 2) {
        return cudaErrorInvalidValue;
    }
    const uint32_t count = ctx->timing_marker_count - 1;
    if (capacity < count) {
        return cudaErrorInvalidValue;
    }
    for (uint32_t interval = 0; interval < count; ++interval) {
        cudaError_t err = cudaEventElapsedTime(
            &out_elapsed_ms[interval],
            ctx->timing_events[interval],
            ctx->timing_events[interval + 1]);
        if (err != cudaSuccess) {
            return err;
        }
    }
    *out_count = count;
    return cudaSuccess;
}

// Capture-safe component lanes owned by the proof context. Streams and events
// are created once with the context; fork/join only enqueue dependency nodes,
// so no resource creation or host synchronization occurs during graph capture.
extern "C" int stwo_exec_context_lane_count(void *handle, uint32_t *out_count) {
    if (handle == nullptr || out_count == nullptr) {
        return cudaErrorInvalidValue;
    }
    *out_count = STWO_EXEC_LANE_COUNT;
    return cudaSuccess;
}

extern "C" int stwo_exec_context_lane_stream(
    void *handle, uint32_t lane, void **out_stream
) {
    if (handle == nullptr || out_stream == nullptr || lane >= STWO_EXEC_LANE_COUNT) {
        return cudaErrorInvalidValue;
    }
    *out_stream = reinterpret_cast<void *>(context_from(handle)->lanes[lane]);
    return *out_stream == nullptr ? cudaErrorInvalidResourceHandle : cudaSuccess;
}

extern "C" int stwo_exec_context_lane_fork(void *handle, uint32_t lane) {
    if (handle == nullptr || lane >= STWO_EXEC_LANE_COUNT) {
        return cudaErrorInvalidValue;
    }
    StwoExecContext *ctx = context_from(handle);
    cudaError_t err = cudaEventRecord(ctx->lane_forks[lane], ctx->stream);
    if (err != cudaSuccess) {
        return err;
    }
    return cudaStreamWaitEvent(ctx->lanes[lane], ctx->lane_forks[lane], 0);
}

extern "C" int stwo_exec_context_lane_join(void *handle, uint32_t lane) {
    if (handle == nullptr || lane >= STWO_EXEC_LANE_COUNT) {
        return cudaErrorInvalidValue;
    }
    StwoExecContext *ctx = context_from(handle);
    cudaError_t err = cudaEventRecord(ctx->lane_joins[lane], ctx->lanes[lane]);
    if (err != cudaSuccess) {
        return err;
    }
    return cudaStreamWaitEvent(ctx->stream, ctx->lane_joins[lane], 0);
}

// Enqueue a join from every owned component lane back to the main stream. This
// is deliberately rejected during graph capture: host-side VMM unmapping is a
// transcript-boundary operation and must never become part of a graph epoch.
extern "C" int stwo_exec_context_join_all_lanes(void *handle) {
    if (handle == nullptr) {
        return cudaErrorInvalidResourceHandle;
    }
    StwoExecContext *ctx = context_from(handle);
    cudaStreamCaptureStatus capture_status = cudaStreamCaptureStatusNone;
    cudaError_t err = cudaStreamIsCapturing(ctx->stream, &capture_status);
    if (err != cudaSuccess) {
        return err;
    }
    if (capture_status != cudaStreamCaptureStatusNone) {
        return cudaErrorStreamCaptureUnsupported;
    }
    for (uint32_t lane = 0; lane < STWO_EXEC_LANE_COUNT; ++lane) {
        err = cudaEventRecord(ctx->lane_joins[lane], ctx->lanes[lane]);
        if (err != cudaSuccess) {
            return err;
        }
        err = cudaStreamWaitEvent(ctx->stream, ctx->lane_joins[lane], 0);
        if (err != cudaSuccess) {
            return err;
        }
    }
    return cudaSuccess;
}

// Allocate `count` u32 from the context's pool, ordered on its stream. The returned
// pointer is usable by later work on the SAME stream (stream-ordered allocation
// guarantees the memory is backed before any later same-stream consumer runs).
// Returns a checked CUDA status and writes a non-null pointer on success.
extern "C" int stwo_exec_context_alloc_u32(
    void *handle, size_t count, uint32_t **out_ptr
) {
    if (handle == nullptr || out_ptr == nullptr || count == 0 ||
        count > SIZE_MAX / sizeof(uint32_t)) {
        return cudaErrorInvalidValue;
    }
    *out_ptr = nullptr;
    StwoExecContext *ctx = context_from(handle);
    uint32_t *ptr = nullptr;
    size_t bytes = count * sizeof(uint32_t);
    cudaError_t err =
        cudaMallocFromPoolAsync(reinterpret_cast<void **>(&ptr), bytes, ctx->pool, ctx->stream);
    if (err != cudaSuccess) {
        return err;
    }
    if (ptr == nullptr) {
        return cudaErrorMemoryAllocation;
    }
    *out_ptr = ptr;
    return cudaSuccess;
}

// Free a buffer on the context's stream: ordered AFTER all prior same-stream users,
// so no use-after-free for same-stream work and no cross-stream reuse hazard.
extern "C" int stwo_exec_context_free_u32(void *handle, uint32_t *ptr) {
    if (handle == nullptr || ptr == nullptr) {
        return cudaErrorInvalidValue;
    }
    return cudaFreeAsync(ptr, context_from(handle)->stream);
}

// Stream-explicit memory operations used to seed/read stable arena slots around
// graph launches. They enqueue only; callers fence with stwo_exec_context_sync.
extern "C" int stwo_exec_context_memset_async(
    void *handle, void *dst, int value, size_t bytes
) {
    if (handle == nullptr || (dst == nullptr && bytes != 0)) {
        return cudaErrorInvalidValue;
    }
    if (bytes == 0) {
        return cudaSuccess;
    }
    return cudaMemsetAsync(dst, value, bytes, context_from(handle)->stream);
}

extern "C" int stwo_exec_context_fill_u32_async(
    void *handle, uint32_t *dst, uint32_t value, size_t count
) {
    if (handle == nullptr || (dst == nullptr && count != 0)) {
        return cudaErrorInvalidValue;
    }
    if (count == 0) {
        return cudaSuccess;
    }
    constexpr uint32_t block = 256;
    size_t blocks = (count + block - 1u) / block;
    if (blocks > static_cast<size_t>(UINT32_MAX)) {
        return cudaErrorInvalidValue;
    }
    fill_u32_kernel<<<static_cast<uint32_t>(blocks), block, 0,
                      context_from(handle)->stream>>>(dst, value, count);
    return cudaGetLastError();
}

extern "C" int stwo_exec_context_memcpy_d2d_async(
    void *handle, void *dst, const void *src, size_t bytes
) {
    if (handle == nullptr || ((dst == nullptr || src == nullptr) && bytes != 0)) {
        return cudaErrorInvalidValue;
    }
    if (bytes == 0) {
        return cudaSuccess;
    }
    return cudaMemcpyAsync(
        dst, src, bytes, cudaMemcpyDeviceToDevice, context_from(handle)->stream);
}

extern "C" int stwo_exec_context_memcpy_h2d_async(
    void *handle, void *dst, const void *src, size_t bytes
) {
    if (handle == nullptr || ((dst == nullptr || src == nullptr) && bytes != 0)) {
        return cudaErrorInvalidValue;
    }
    if (bytes == 0) {
        return cudaSuccess;
    }
    return cudaMemcpyAsync(
        dst, src, bytes, cudaMemcpyHostToDevice, context_from(handle)->stream);
}

extern "C" int stwo_exec_context_memcpy_d2h_async(
    void *handle, void *dst, const void *src, size_t bytes
) {
    if (handle == nullptr || ((dst == nullptr || src == nullptr) && bytes != 0)) {
        return cudaErrorInvalidValue;
    }
    if (bytes == 0) {
        return cudaSuccess;
    }
    return cudaMemcpyAsync(
        dst, src, bytes, cudaMemcpyDeviceToHost, context_from(handle)->stream);
}

// ---------------------------------------------------------------------------
// CUDA graph lifecycle rooted on the context's main stream. Auxiliary streams
// become part of the same graph only through the explicit lane fork/join edges
// above; transcript boundaries and host reads remain outside.
// ---------------------------------------------------------------------------

extern "C" int stwo_graph_capture_begin(void *handle) {
    if (handle == nullptr) {
        return cudaErrorInvalidResourceHandle;
    }
    return cudaStreamBeginCapture(
        context_from(handle)->stream, cudaStreamCaptureModeThreadLocal);
}

extern "C" int stwo_graph_capture_end(void *handle, void **out_exec,
                                        uint64_t *out_kernel_nodes) {
    if (handle == nullptr || out_exec == nullptr || out_kernel_nodes == nullptr) {
        return cudaErrorInvalidValue;
    }
    *out_exec = nullptr;
    *out_kernel_nodes = 0;

    cudaGraph_t graph = nullptr;
    cudaError_t err = cudaStreamEndCapture(context_from(handle)->stream, &graph);
    if (err != cudaSuccess) {
        std::fprintf(
            stderr,
            "stwo graph: cudaStreamEndCapture failed status=%d graph=%p\n",
            static_cast<int>(err),
            static_cast<void *>(graph));
        if (graph != nullptr) {
            cudaGraphDestroy(graph);
        }
        return err;
    }
    if (graph == nullptr) {
        std::fprintf(stderr, "stwo graph: cudaStreamEndCapture returned a null graph\n");
        return cudaErrorInvalidResourceHandle;
    }

    size_t node_count = 0;
    err = cudaGraphGetNodes(graph, nullptr, &node_count);
    if (err != cudaSuccess) {
        std::fprintf(
            stderr,
            "stwo graph: cudaGraphGetNodes(count) failed status=%d\n",
            static_cast<int>(err));
        cudaGraphDestroy(graph);
        return err;
    }
    std::vector<cudaGraphNode_t> nodes(node_count);
    if (node_count != 0) {
        err = cudaGraphGetNodes(graph, nodes.data(), &node_count);
        if (err != cudaSuccess) {
            std::fprintf(
                stderr,
                "stwo graph: cudaGraphGetNodes(nodes) failed status=%d\n",
                static_cast<int>(err));
            cudaGraphDestroy(graph);
            return err;
        }
    }
    uint64_t kernel_nodes = 0;
    for (size_t index = 0; index < node_count; ++index) {
        cudaGraphNode_t node = nodes[index];
        cudaGraphNodeType type;
        err = cudaGraphNodeGetType(node, &type);
        if (err != cudaSuccess) {
            std::fprintf(
                stderr,
                "stwo graph: cudaGraphNodeGetType failed status=%d node=%zu\n",
                static_cast<int>(err),
                index);
            cudaGraphDestroy(graph);
            return err;
        }
        kernel_nodes += type == cudaGraphNodeTypeKernel;
    }

    cudaGraphExec_t exec = nullptr;
    cudaGraphNode_t error_node = nullptr;
    char instantiate_log[4096] = {};
    err = cudaGraphInstantiate(
        &exec,
        graph,
        &error_node,
        instantiate_log,
        sizeof(instantiate_log));
    instantiate_log[sizeof(instantiate_log) - 1] = '\0';
    if (err != cudaSuccess) {
        size_t error_index = node_count;
        for (size_t index = 0; index < node_count; ++index) {
            if (nodes[index] == error_node) {
                error_index = index;
                break;
            }
        }
        std::fprintf(
            stderr,
            "stwo graph: cudaGraphInstantiate failed status=%d nodes=%zu "
            "error_node=%p error_index=%zu log=%s\n",
            static_cast<int>(err),
            node_count,
            static_cast<void *>(error_node),
            error_index,
            instantiate_log[0] == '\0' ? "<empty>" : instantiate_log);
        if (error_index < node_count) {
            cudaGraphNodeType type;
            cudaError_t type_err = cudaGraphNodeGetType(error_node, &type);
            std::fprintf(
                stderr,
                "stwo graph: instantiate error_node_type_status=%d type=%d\n",
                static_cast<int>(type_err),
                type_err == cudaSuccess ? static_cast<int>(type) : -1);
            if (type_err == cudaSuccess && type == cudaGraphNodeTypeKernel) {
                report_graph_kernel_node("instantiate_error", error_index, error_node);
            }
        } else {
            for (size_t index = 0; index < node_count; ++index) {
                cudaGraphNodeType type;
                if (cudaGraphNodeGetType(nodes[index], &type) == cudaSuccess &&
                    type == cudaGraphNodeTypeKernel) {
                    report_graph_kernel_node("instantiate_candidate", index, nodes[index]);
                }
            }
        }
    }
    cudaError_t destroy_err = cudaGraphDestroy(graph);
    if (err != cudaSuccess) {
        return err;
    }
    if (destroy_err != cudaSuccess) {
        std::fprintf(
            stderr,
            "stwo graph: cudaGraphDestroy failed status=%d\n",
            static_cast<int>(destroy_err));
        cudaGraphExecDestroy(exec);
        return destroy_err;
    }
    if (exec == nullptr) {
        std::fprintf(stderr, "stwo graph: cudaGraphInstantiate returned a null executable\n");
        return cudaErrorInvalidResourceHandle;
    }
    *out_exec = reinterpret_cast<void *>(exec);
    *out_kernel_nodes = kernel_nodes;
    return cudaSuccess;
}

// CUDA has no separate abort primitive. Ending capture exits capture mode; any
// successfully produced graph is immediately discarded. On an invalidated
// capture cudaStreamEndCapture returns that status after restoring the stream.
extern "C" int stwo_graph_capture_abort(void *handle) {
    if (handle == nullptr) {
        return cudaErrorInvalidResourceHandle;
    }
    cudaGraph_t graph = nullptr;
    cudaError_t err = cudaStreamEndCapture(context_from(handle)->stream, &graph);
    if (graph != nullptr) {
        cudaError_t destroy_err = cudaGraphDestroy(graph);
        err = first_error(err, destroy_err);
    }
    return err;
}

extern "C" int stwo_graph_launch(void *exec_handle, void *context_handle) {
    if (exec_handle == nullptr || context_handle == nullptr) {
        return cudaErrorInvalidValue;
    }
    return cudaGraphLaunch(
        reinterpret_cast<cudaGraphExec_t>(exec_handle), context_from(context_handle)->stream);
}

extern "C" int stwo_graph_destroy(void *exec_handle) {
    if (exec_handle == nullptr) {
        return cudaSuccess;
    }
    return cudaGraphExecDestroy(reinterpret_cast<cudaGraphExec_t>(exec_handle));
}
