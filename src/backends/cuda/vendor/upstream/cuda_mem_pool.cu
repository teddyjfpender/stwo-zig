#include "cuda_mem_pool.cuh"
#include <cuda_runtime.h>
#include <atomic>
#include <cstdint>
#include <mutex>

namespace {

struct DefaultPoolState {
    std::mutex mutex;
    std::atomic<cudaMemPool_t> pool{nullptr};
    int device_id = -1;
};

DefaultPoolState& default_pool_state() {
    static DefaultPoolState state;
    return state;
}

cudaError_t validate_cached_pool(
    const DefaultPoolState& state,
    cudaMemPool_t pool,
    bool validate_current_device,
    cudaMemPool_t* out_pool
) {
    if (validate_current_device) {
        int current_device = -1;
        cudaError_t err = cudaGetDevice(&current_device);
        if (err != cudaSuccess) {
            return err;
        }
        if (current_device != state.device_id) {
            return cudaErrorInvalidDevice;
        }
    }
    *out_pool = pool;
    return cudaSuccess;
}

// Resolve the current device's default pool and publish it only after every
// setup operation succeeds. A failed attempt leaves the state empty, allowing
// a later formal admission check to retry instead of inheriting a cached null.
cudaError_t resolve_default_pool(cudaMemPool_t* out_pool, bool validate_current_device) {
    if (out_pool == nullptr) {
        return cudaErrorInvalidValue;
    }
    *out_pool = nullptr;

    DefaultPoolState& state = default_pool_state();
    cudaMemPool_t cached = state.pool.load(std::memory_order_acquire);
    if (cached != nullptr) {
        return validate_cached_pool(state, cached, validate_current_device, out_pool);
    }

    std::lock_guard<std::mutex> guard(state.mutex);
    cached = state.pool.load(std::memory_order_relaxed);
    if (cached != nullptr) {
        return validate_cached_pool(state, cached, validate_current_device, out_pool);
    }

    int device_id = -1;
    cudaError_t err = cudaGetDevice(&device_id);
    if (err != cudaSuccess) {
        return err;
    }
    cudaMemPool_t candidate = nullptr;
    err = cudaDeviceGetDefaultMemPool(&candidate, device_id);
    if (err != cudaSuccess) {
        return err;
    }
    if (candidate == nullptr) {
        return cudaErrorNotSupported;
    }
    uint64_t threshold = UINT64_MAX;
    err = cudaMemPoolSetAttribute(candidate, cudaMemPoolAttrReleaseThreshold, &threshold);
    if (err != cudaSuccess) {
        return err;
    }

    state.device_id = device_id;
    state.pool.store(candidate, std::memory_order_release);
    *out_pool = candidate;
    return cudaSuccess;
}

}  // namespace

cudaMemPool_t stwo_default_mem_pool() {
    cudaMemPool_t pool = nullptr;
    // Legacy allocators retain their cudaMalloc fallback. Unlike the checked
    // APIs below, this compatibility path deliberately does not re-query the
    // current device after a successful single-device initialization.
    (void)resolve_default_pool(&pool, false);
    return pool;
}

namespace {

cudaError_t default_pool_current(
    cudaMemPool_t pool,
    size_t* used_current,
    size_t* reserved_current
) {
    if (used_current == nullptr || reserved_current == nullptr) {
        return cudaErrorInvalidValue;
    }
    *used_current = 0;
    *reserved_current = 0;
    if (pool == nullptr) {
        return cudaErrorNotSupported;
    }

    uint64_t used = 0;
    uint64_t reserved = 0;
    cudaError_t err = cudaMemPoolGetAttribute(pool, cudaMemPoolAttrUsedMemCurrent, &used);
    if (err != cudaSuccess) {
        return err;
    }
    err = cudaMemPoolGetAttribute(pool, cudaMemPoolAttrReservedMemCurrent, &reserved);
    if (err != cudaSuccess) {
        return err;
    }
    *used_current = static_cast<size_t>(used);
    *reserved_current = static_cast<size_t>(reserved);
    return cudaSuccess;
}

}  // namespace

extern "C" cudaError_t cuda_mem_pool_init() {
    cudaMemPool_t pool = nullptr;
    return resolve_default_pool(&pool, true);
}

extern "C" cudaError_t cuda_default_pool_alloc_checked(
    size_t byte_count,
    void** output
) {
    if (output == nullptr || byte_count == 0) {
        return cudaErrorInvalidValue;
    }
    *output = nullptr;
    cudaMemPool_t pool = nullptr;
    cudaError_t err = resolve_default_pool(&pool, true);
    if (err != cudaSuccess) {
        return err;
    }
    return cudaMallocFromPoolAsync(output, byte_count, pool, 0);
}

extern "C" cudaError_t cuda_default_pool_copy_h2d_checked(
    const void* host,
    void* device,
    size_t byte_count
) {
    if (host == nullptr || device == nullptr || byte_count == 0) {
        return cudaErrorInvalidValue;
    }
    cudaMemPool_t pool = nullptr;
    cudaError_t err = resolve_default_pool(&pool, true);
    if (err != cudaSuccess) {
        return err;
    }
    return cudaMemcpy(device, host, byte_count, cudaMemcpyHostToDevice);
}

extern "C" cudaError_t cuda_default_pool_free_checked(void* device) {
    if (device == nullptr) {
        return cudaErrorInvalidValue;
    }
    cudaMemPool_t pool = nullptr;
    cudaError_t err = resolve_default_pool(&pool, true);
    if (err != cudaSuccess) {
        return err;
    }
    return cudaFreeAsync(device, 0);
}

extern "C" cudaError_t cuda_default_pool_stream_sync_checked() {
    cudaMemPool_t pool = nullptr;
    cudaError_t err = resolve_default_pool(&pool, true);
    if (err != cudaSuccess) {
        return err;
    }
    return cudaStreamSynchronize(0);
}

extern "C" cudaError_t cuda_default_pool_current(
    size_t* used_current,
    size_t* reserved_current
) {
    if (used_current == nullptr || reserved_current == nullptr) {
        return cudaErrorInvalidValue;
    }
    *used_current = 0;
    *reserved_current = 0;
    cudaMemPool_t pool = nullptr;
    cudaError_t err = resolve_default_pool(&pool, true);
    if (err != cudaSuccess) {
        return err;
    }
    return default_pool_current(pool, used_current, reserved_current);
}

extern "C" cudaError_t cuda_default_pool_trim(
    size_t min_bytes_to_keep,
    size_t* used_current,
    size_t* reserved_current
) {
    if (used_current == nullptr || reserved_current == nullptr) {
        return cudaErrorInvalidValue;
    }
    *used_current = 0;
    *reserved_current = 0;
    cudaMemPool_t pool = nullptr;
    cudaError_t err = resolve_default_pool(&pool, true);
    if (err != cudaSuccess) {
        return err;
    }
    err = cudaStreamSynchronize(0);
    if (err != cudaSuccess) {
        return err;
    }
    err = cudaMemPoolTrimTo(pool, min_bytes_to_keep);
    if (err != cudaSuccess) {
        return err;
    }
    return default_pool_current(pool, used_current, reserved_current);
}

extern "C" cudaError_t cuda_mem_pool_destroy() {
    return cudaSuccess;
}

namespace {
struct StreamPool {
    cudaStream_t streams[STWO_N_POOL_STREAMS];
    cudaEvent_t events[STWO_N_POOL_STREAMS];
};
StreamPool &stream_pool() {
    static StreamPool pool = [] {
        StreamPool p{};
        for (int i = 0; i < STWO_N_POOL_STREAMS; ++i) {
            cudaStreamCreateWithFlags(&p.streams[i], cudaStreamNonBlocking);
            cudaEventCreateWithFlags(&p.events[i], cudaEventDisableTiming);
        }
        return p;
    }();
    return pool;
}
}  // namespace

cudaStream_t stwo_pool_stream(int i) { return stream_pool().streams[i % STWO_N_POOL_STREAMS]; }

void stwo_stream_wait_legacy(int i) {
    StreamPool &p = stream_pool();
    int k = i % STWO_N_POOL_STREAMS;
    // Record the legacy stream's current frontier and make stream k wait on it.
    cudaEventRecord(p.events[k], (cudaStream_t)0);
    cudaStreamWaitEvent(p.streams[k], p.events[k], 0);
}

void stwo_legacy_wait_stream(int i) {
    StreamPool &p = stream_pool();
    int k = i % STWO_N_POOL_STREAMS;
    cudaEventRecord(p.events[k], p.streams[k]);
    cudaStreamWaitEvent((cudaStream_t)0, p.events[k], 0);
}

// ---------------------------------------------------------------------------
// Stage B′ fan-out primitives (STWO_CUDA_STREAM_FANOUT). The per-slot bridges
// above share ONE event per slot: if two host threads bridge the same slot
// concurrently (which the multi-threaded witness fan-out does — rayon workers
// each driving a lane), their `cudaEventRecord` calls race on the same event
// object (undefined behaviour) and silently corrupt the ordering edge. These
// use a FRESH event per call, so concurrent forks/joins from different workers
// never touch a shared event. The event is created timing-disabled and
// destroyed right after the wait is enqueued — CUDA defers the real teardown
// until no pending work references it, so this is safe and cheap (~tens of
// create/destroy pairs per prove).
// ---------------------------------------------------------------------------

// Pool stream `i` (round-robin) as an opaque handle for the Rust stream scope.
extern "C" void *stwo_fanout_stream(int i) {
    return (void *)stream_pool().streams[i % STWO_N_POOL_STREAMS];
}

// FORK: `stream` waits for everything enqueued on the legacy stream so far — its
// inputs (pool allocations stay legacy-ordered, plus any shared read-only tables
// uploaded on legacy). MUST be called before launching the lane's kernel on it.
extern "C" void stwo_fanout_fork(void *stream) {
    cudaEvent_t ev;
    cudaEventCreateWithFlags(&ev, cudaEventDisableTiming);
    cudaEventRecord(ev, (cudaStream_t)0);
    cudaStreamWaitEvent((cudaStream_t)stream, ev, 0);
    cudaEventDestroy(ev);
}

// JOIN: the legacy stream waits for `stream`'s work. MUST be called before any
// legacy-stream or host consumer reads the lane's outputs (the closing bridge).
extern "C" void stwo_fanout_join(void *stream) {
    cudaEvent_t ev;
    cudaEventCreateWithFlags(&ev, cudaEventDisableTiming);
    cudaEventRecord(ev, (cudaStream_t)stream);
    cudaStreamWaitEvent((cudaStream_t)0, ev, 0);
    cudaEventDestroy(ev);
}

extern "C" uint32_t* cuda_mem_pool_allocate_uint32(size_t count) {
    return cuda_mem_pool_allocate<uint32_t>(count);
}

extern "C" uint32_t* cuda_mem_pool_allocate_zeroes_uint32(size_t count) {
    return cuda_mem_pool_allocate_zeroes<uint32_t>(count);
}

extern "C" void cuda_mem_pool_free_uint32(uint32_t* ptr) {
    cuda_mem_pool_free(ptr);
}
