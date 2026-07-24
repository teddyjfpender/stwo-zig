#ifndef CUDA_MEM_POOL_H
#define CUDA_MEM_POOL_H

#include <cuda_runtime.h>
#include <cstdint>
#include <cstdio>

// ---------------------------------------------------------------------------
// Stream-ordered allocator (see docs/gpu-architecture-analysis.md, item 1).
//
// Every allocation, zero-fill, and free is enqueued on the LEGACY DEFAULT STREAM
// with no host synchronization:
//
//   - cudaMallocFromPoolAsync(stream 0): the returned pointer is usable
//     immediately by later default-stream work — stream ordering guarantees the
//     memory is backed before any consumer runs.
//   - cudaMemsetAsync(stream 0): ordered before any later default-stream reader.
//   - cudaFreeAsync(stream 0): ordered after all prior default-stream users of
//     the buffer, so no use-after-free is possible for default-stream work.
//
// The previous implementation created, synchronized, and destroyed a PRIVATE
// stream around every single alloc/free (4-6k stream lifecycle events plus full
// host stalls per prove). With a never-release pool (threshold = UINT64_MAX, the
// NitrooZK setup) the steady-state cost of an allocation is now a single stream-
// ordered pool op.
//
// Host code must never dereference these pointers directly; all host reads in
// this crate go through synchronous cudaMemcpy, which orders after the default
// stream and blocks until complete (the fence).
// ---------------------------------------------------------------------------

// Initialize the CUDA memory pool (idempotent; sets the never-release threshold).
// Only a successful initialization is cached; failures retain their exact CUDA
// status and a later call retries.
extern "C" cudaError_t cuda_mem_pool_init();

// Formal default-pool-only primitives. Every call validates the current device
// against the admitted pool, returns the exact CUDA status, and never falls
// back to cudaMalloc/cudaFree. `byte_count` must be non-zero.
extern "C" cudaError_t cuda_default_pool_alloc_checked(
    size_t byte_count,
    void** output
);
extern "C" cudaError_t cuda_default_pool_copy_h2d_checked(
    const void* host,
    void* device,
    size_t byte_count
);
extern "C" cudaError_t cuda_default_pool_free_checked(void* device);
extern "C" cudaError_t cuda_default_pool_stream_sync_checked();

// Checked current footprint of the process-wide default pool. Unlike the
// historical high-water telemetry, these values describe memory held now.
extern "C" cudaError_t cuda_default_pool_current(
    size_t* used_current,
    size_t* reserved_current
);

// Drain stream 0, explicitly trim unused default-pool backing memory, and
// return the checked post-trim footprint. The fence is part of this API so an
// enqueued cudaFreeAsync cannot be mistaken for reclaimable memory.
extern "C" cudaError_t cuda_default_pool_trim(
    size_t min_bytes_to_keep,
    size_t* used_current,
    size_t* reserved_current
);

// Destroy the CUDA memory pool
extern "C" cudaError_t cuda_mem_pool_destroy();

// Successfully initialized default-mem-pool handle for the admitted device.
// Failed resolutions are not cached. nullptr means this attempt failed, in
// which case legacy callers fall back to plain cudaMalloc/cudaFree.
cudaMemPool_t stwo_default_mem_pool();

template<typename T>
T* cuda_allocator_allocate_for_proving(size_t count) {
    T* ptr = nullptr;
    size_t size = sizeof(T) * count;

    cudaMemPool_t pool = stwo_default_mem_pool();
    if (pool != nullptr) {
        cudaError_t err = cudaMallocFromPoolAsync((void**)&ptr, size, pool, 0);
        if (err == cudaSuccess) {
            return ptr;
        }
        printf("Failed to allocate %zu bytes from pool: %s\n", size, cudaGetErrorString(err));
    }

    cudaError_t fallback_err = cudaMalloc((void**)&ptr, size);
    if (fallback_err != cudaSuccess) {
        printf("Failed to fallback cudaMalloc(%zu): %s\n", size, cudaGetErrorString(fallback_err));
        return nullptr;
    }
    return ptr;
}

template<typename T>
T* cuda_allocator_allocate_zeroes_for_proving(size_t count) {
    T* ptr = cuda_allocator_allocate_for_proving<T>(count);
    if (ptr != nullptr && count > 0) {
        cudaError_t err = cudaMemsetAsync(ptr, 0, sizeof(T) * count, 0);
        if (err != cudaSuccess) {
            printf("Failed to zero %zu bytes: %s\n", sizeof(T) * count, cudaGetErrorString(err));
            cudaFreeAsync(ptr, 0);
            return nullptr;
        }
    }
    return ptr;
}

template<typename T>
void cuda_allocator_free_for_proving(T* ptr) {
    if (ptr == nullptr) {
        return;
    }
    // cudaFreeAsync handles both pool allocations and plain cudaMalloc memory
    // (CUDA >= 11.2); ordering on stream 0 guarantees all prior default-stream
    // users of the buffer have finished before the memory is recycled.
    cudaError_t err = cudaFreeAsync(const_cast<void*>(reinterpret_cast<const void*>(ptr)), 0);
    if (err != cudaSuccess) {
        printf("Failed stream-ordered free, falling back: %s\n", cudaGetErrorString(err));
        cudaFree(const_cast<void*>(reinterpret_cast<const void*>(ptr)));
    }
}

// Legacy aliases (same stream-ordered behavior).
template<typename T>
T* cuda_mem_pool_allocate(size_t count) {
    return cuda_allocator_allocate_for_proving<T>(count);
}

template<typename T>
T* cuda_mem_pool_allocate_zeroes(size_t count) {
    return cuda_allocator_allocate_zeroes_for_proving<T>(count);
}

template<typename T>
void cuda_mem_pool_free(T* ptr) {
    cuda_allocator_free_for_proving(ptr);
}

// ---------------------------------------------------------------------------
// P3 stream pool (multi-stream overlap; see ROAD_TO_10MHZ.md program P3).
//
// CONTRACT: work on a pool stream is only correct between a pair of bridges:
//   stwo_stream_wait_legacy(i)  — pool stream i waits for everything enqueued on
//                                 the legacy stream so far (its inputs);
//   stwo_legacy_wait_stream(i)  — the legacy stream waits for stream i's work
//                                 (before any consumer or host read).
// Never read pool-stream results from the host or from the legacy stream
// without the closing bridge. Allocations remain legacy-stream-ordered, so pool
// streams must not free buffers they used until after the closing bridge.
// ---------------------------------------------------------------------------
constexpr int STWO_N_POOL_STREAMS = 4;
cudaStream_t stwo_pool_stream(int i);
void stwo_stream_wait_legacy(int i);
void stwo_legacy_wait_stream(int i);

// C-style wrappers for specific types
extern "C" uint32_t* cuda_mem_pool_allocate_uint32(size_t count);
extern "C" uint32_t* cuda_mem_pool_allocate_zeroes_uint32(size_t count);
extern "C" void cuda_mem_pool_free_uint32(uint32_t* ptr);

#endif // CUDA_MEM_POOL_H
