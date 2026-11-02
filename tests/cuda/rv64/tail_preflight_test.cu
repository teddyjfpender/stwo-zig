// Exercise actual native launch preflight with a fake allocation registry.
// Every call must fail BEFORE launch; no NVIDIA device/driver is required.
#include "rv64/gkr.h"
#include <cuda_runtime.h>
#include <array>
#include <cassert>
static std::array<uint32_t, 4096> arena;
static size_t cursor, validated;
extern "C" int stwo_exec_context_lane_stream(void* ctx, uint32_t lane, void** stream) {
    if (ctx != reinterpret_cast<void*>(1) || lane != 1)
        return int(cudaErrorInvalidResourceHandle);
    *stream = reinterpret_cast<void*>(2);
    return 0;
}
extern "C" int stwo_exec_context_validate_allocation(void*, const void* p, size_t bytes) {
    const auto start = reinterpret_cast<uintptr_t>(arena.data()),
               at = reinterpret_cast<uintptr_t>(p);
    ++validated;
    return at >= start && at <= start + sizeof(arena) && bytes <= start + sizeof(arena) - at
               ? 0
               : int(cudaErrorInvalidDevicePointer);
}
static uint32_t* words(size_t n) {
    auto* result = arena.data() + cursor;
    cursor += n;
    assert(cursor <= arena.size());
    return result;
}
static StwoRv64Plane plane(uint32_t n, uint32_t c) {
    return {words(n * c), n, c, 0};
}
static std::array<StwoRv64TailJob, 8> jobs() {
    cursor = validated = 0;
    arena.fill(0xdeadbeef);
    std::array<StwoRv64TailJob, 8> result{};
    for (auto& j : result) {
        j.n = plane(4, 8);
        j.d = plane(4, 8);
        j.out_n = plane(2, 8);
        j.out_d = plane(2, 8);
        j.eq = plane(1, 8);
        j.point = words(8);
        j.lambda = words(8);
        j.state = words(40);
        j.records = words(44);
        j.mask = words(32);
        j.count = 4;
        j.variables = 1;
    }
    return result;
}
static int run(std::array<StwoRv64TailJob, 8>& j) {
    const auto before = arena;
    const int rc =
        stwo_rv64_sumcheck_tail_on(reinterpret_cast<void*>(1), 1, j.data(), j.size());
    assert(before == arena);  // no prefix mutation on a rejected packet
    return rc;
}
int main() {
    auto j = jobs();
    j[7].mask = j[0].state;  // cross-job alias at the final (80th) range
    assert(run(j) == int(cudaErrorInvalidValue));
    assert(validated == 79);
    j = jobs();
    j[7].mask = arena.data() + arena.size();
    assert(run(j) == int(cudaErrorInvalidDevicePointer));
    assert(validated == 80);
    j = jobs();
    j[7].first = 1;
    assert(run(j) == int(cudaErrorInvalidValue));
    j = jobs();
    j[7].reserved = 1;
    assert(run(j) == int(cudaErrorInvalidValue));
    j = jobs();
    j[7].eq.stride = 0;
    assert(run(j) == int(cudaErrorInvalidValue));
    j = jobs();
    j[7].variables = 2;  // in-range cursor but inconsistent remaining geometry
    assert(run(j) == int(cudaErrorInvalidValue));
    j = jobs();
    for (uint32_t i = 1; i < 8; ++i) {
        j[i].n = j[0].n;
        j[i].d = j[0].d;
        j[i].eq = j[0].eq;
        j[i].point = j[0].point;
        j[i].lambda = j[0].lambda;
    }
    j[7].mask = arena.data() + arena.size();  // shared READS survive to final bounds check
    assert(run(j) == int(cudaErrorInvalidDevicePointer));
    assert(validated == 80);
    assert(stwo_rv64_sumcheck_tail_on(nullptr, 1, nullptr, 0) == int(cudaErrorInvalidValue));
    assert(stwo_rv64_sumcheck_tail_on(nullptr, 1, j.data(), 9) == int(cudaErrorInvalidValue));
    assert(stwo_rv64_sumcheck_tail_on(nullptr, 1, j.data(), 1) ==
           int(cudaErrorInvalidResourceHandle));
}
