#include <cuda_runtime_api.h>
#include <cassert>
#include <cstdio>
#include <cstdint>
extern "C" int stwo_exec_context_alloc_u32(void*, size_t, uint32_t**);
static unsigned failures = 0, attempts = 0;
extern "C" int injected_context_alloc(void* context, size_t words, uint32_t** out) {
    ++attempts;
    if (failures) {
        --failures;
        *out = nullptr;
        size_t available = 0, total = 0;
        assert(cudaMemGetInfo(&available, &total) == cudaSuccess);
        void* impossible = nullptr;
        assert(cudaMalloc(&impossible, total * 2) == cudaErrorMemoryAllocation);
        return int(cudaErrorMemoryAllocation);
    }
    return stwo_exec_context_alloc_u32(context, words, out);
}
#define stwo_exec_context_alloc_u32 injected_context_alloc
#include "../../../src/backends/cuda/native/rv64/pcs_native.cu"
#undef stwo_exec_context_alloc_u32
int main() {
    ResidentOwner owner(0, 256 * 1024 * 1024);
    Scope scope{}; scope[0] = 1;
    auto live = owner.lease(1024, 2, scope);
    const auto idle = owner.plane(4 * 1024 * 1024, 1);
    owner.reset();
    const auto active = owner.plane(8 * 1024 * 1024, 1);
    assert(owner.blocks.size() == 2);
    assert(!owner.blocks[0].used && owner.blocks[1].used);
    const uint32_t pattern = 0x12345678;
    assert(cudaMemset(live.words, 0x5a, live.count * 4) == cudaSuccess);
    assert(cudaMemcpy(active.words, &pattern, 4, cudaMemcpyHostToDevice) == cudaSuccess);
    const unsigned before = attempts;
    failures = 1;
    auto result = owner.lease(16 * 1024 * 1024, 0, scope);
    assert(attempts == before + 2 && failures == 0);
    assert(cudaPeekAtLastError() == cudaSuccess);
    assert(owner.blocks.size() == 1 && owner.blocks[0].ptr == active.words);
    assert(owner.blocks[0].used);
    assert(owner.leases.size() == 2);
    assert(owner.retained == (1024ull + 8 * 1024 * 1024 + 16 * 1024 * 1024) * 4);
    uint32_t actual = 0;
    assert(cudaMemcpy(&actual, live.words, 4, cudaMemcpyDeviceToHost) == cudaSuccess);
    assert(actual == 0x5a5a5a5a);
    assert(cudaMemcpy(&actual, active.words, 4, cudaMemcpyDeviceToHost) == cudaSuccess);
    assert(actual == pattern);
    const auto retained = owner.retained;
    failures = 2;
    bool rejected = false;
    try { (void)owner.lease(1024, 0, scope); }
    catch (const std::exception&) { rejected = true; }
    assert(rejected && failures == 0 && owner.retained == retained && owner.leases.size() == 2);
    (void)cudaGetLastError();
    owner.release(result);
    owner.release(live);
    owner.reset();
    (void)idle;
    std::puts("PASS idle PCS eviction, active cache/live leases preserved, exact accounting, bounded failure custody");
}
