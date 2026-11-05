// Compile the real context with allocation failure injection confined to this
// test translation unit. No production switch or exported test hook is needed.
#include <cuda_runtime_api.h>
#include <cassert>
#include <cstdio>
static unsigned failures = 0, attempts = 0, trims = 0;
static cudaError_t failure = cudaErrorMemoryAllocation;
static cudaError_t test_pool_malloc(void** out, size_t bytes, cudaMemPool_t pool,
                                    cudaStream_t stream) {
    ++attempts;
    if (failures) {
        --failures;
        if (failure == cudaErrorMemoryAllocation) {
            // Populate CUDA's real per-thread last-error state as well as
            // returning the injected status; later launch checks must be clean.
            size_t free_bytes = 0, total_bytes = 0;
            assert(cudaMemGetInfo(&free_bytes, &total_bytes) == cudaSuccess);
            void* impossible = nullptr;
            assert(cudaMalloc(&impossible, total_bytes * 2) == cudaErrorMemoryAllocation);
        }
        return failure;
    }
    return cudaMallocFromPoolAsync(out, bytes, pool, stream);
}
static cudaError_t test_pool_trim(cudaMemPool_t pool, size_t bytes) {
    ++trims;
    return cudaMemPoolTrimTo(pool, bytes);
}
#define cudaMallocFromPoolAsync test_pool_malloc
#define cudaMemPoolTrimTo test_pool_trim
#include "../../../src/backends/cuda/native/runtime/context.cu"
#undef cudaMallocFromPoolAsync
#undef cudaMemPoolTrimTo

int main() {
    void* ctx = nullptr;
    StwoCudaContextOptions options{1, 0, 2, 8};
    assert(stwo_exec_context_create_options(&options, &ctx) == 0);
    uint32_t* live = nullptr;
    assert(stwo_exec_context_alloc_u32(ctx, 1024, &live) == 0);
    uint32_t expected[1024];
    for (unsigned i = 0; i < 1024; ++i) expected[i] = 0x12345678u ^ i;
    void* lane = nullptr;
    assert(stwo_exec_context_lane_stream(ctx, 1, &lane) == 0);
    assert(cudaMemcpyAsync(live, expected, sizeof(expected), cudaMemcpyHostToDevice,
                           static_cast<cudaStream_t>(lane)) == cudaSuccess);
    uint32_t* cached = nullptr;
    assert(stwo_exec_context_alloc_u32(ctx, 4 * 1024 * 1024, &cached) == 0);
    assert(stwo_exec_context_free_u32(ctx, cached) == 0);
    const unsigned before = attempts;
    failures = 1;
    uint32_t* retried = nullptr;
    assert(stwo_exec_context_alloc_u32(ctx, 16 * 1024 * 1024, &retried) == 0);
    assert(attempts == before + 2 && trims == 1 && retried != nullptr);
    assert(cudaPeekAtLastError() == cudaSuccess);
    uint32_t* successful_retry = retried;
    assert(stwo_exec_context_sync(ctx) == 0);
    uint32_t actual[1024];
    assert(cudaMemcpy(actual, live, sizeof(actual), cudaMemcpyDeviceToHost) == cudaSuccess);
    for (unsigned i = 0; i < 1024; ++i) assert(actual[i] == expected[i]);
    auto* internal = static_cast<StwoNativeCudaContext*>(ctx);
    const size_t registered = internal->allocation_count;
    failures = 2;
    retried = reinterpret_cast<uint32_t*>(1);
    assert(stwo_exec_context_alloc_u32(ctx, 1024, &retried) == cudaErrorMemoryAllocation);
    assert(retried == nullptr && failures == 0 && trims == 2);
    assert(internal->allocation_count == registered);
    failure = cudaErrorInvalidValue;
    failures = 1;
    const unsigned non_oom_before = attempts;
    assert(stwo_exec_context_alloc_u32(ctx, 1024, &retried) == cudaErrorInvalidValue);
    assert(attempts == non_oom_before + 1 && trims == 2 && retried == nullptr);
    assert(internal->allocation_count == registered);
    assert(stwo_exec_context_free_u32(ctx, successful_retry) == 0);
    assert(stwo_exec_context_free_u32(ctx, live) == 0);
    assert(stwo_exec_context_destroy(ctx) == 0);
    std::puts("PASS pool OOM retry, live two-lane contents, bounded retry, failure custody, non-OOM passthrough");
}
