#pragma once
#include "rv64/gkr.h"
#include "runtime/context_options.h"
#include <cuda_runtime.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstdint>
extern "C" int stwo_exec_context_create_options(const StwoCudaContextOptions*, void**);
extern "C" int stwo_exec_context_destroy(void*);
extern "C" int stwo_exec_context_sync(void*);
extern "C" int stwo_exec_context_alloc_u32(void*, size_t, uint32_t**);
extern "C" int stwo_exec_context_free_u32(void*, uint32_t*);
extern "C" int stwo_exec_context_memcpy_h2d_async(void*, void*, const void*, size_t);
extern "C" int stwo_exec_context_memcpy_d2h_async(void*, void*, const void*, size_t);
extern "C" int stwo_exec_context_dependency_record(void*, uint32_t, uint32_t,
                                                   StwoCudaDependency*);
extern "C" int stwo_exec_context_dependency_wait(void*, uint32_t, const StwoCudaDependency*);
extern "C" int stwo_exec_context_dependency_release(void*, const StwoCudaDependency*);
extern "C" int stwo_exec_context_lane_stream(void*, uint32_t, void**);
static void check(int status, const char* operation) {
    if (status)
        throw std::runtime_error(std::string(operation) + ": " +
                                 cudaGetErrorString(cudaError_t(status)));
}
#define CHECK(expr) check((expr), #expr)
struct Owner {
    void* ctx = nullptr;
    std::vector<uint32_t*> allocations;
    std::vector<cudaEvent_t> events;
    uint64_t allocated_bytes = 0;
    explicit Owner(int device) {
        StwoCudaContextOptions options{1, uint32_t(device), 2, 8};
        const int status = stwo_exec_context_create_options(&options, &ctx);
        if (status) {
            if (ctx) {
                const int cleanup = stwo_exec_context_destroy(ctx);
                (void)cleanup;
                ctx = nullptr;
            }
            check(status, "context create");
        }
    }
    StwoRv64Plane plane(uint32_t count, uint32_t coordinates) {
        uint32_t* p = nullptr;
        CHECK(stwo_exec_context_alloc_u32(ctx, size_t(count) * coordinates, &p));
        allocations.push_back(p);
        allocated_bytes += uint64_t(count) * coordinates * 4;
        return {p, count, coordinates, 0};
    }
    cudaEvent_t event() {
        cudaEvent_t e;
        CHECK(cudaEventCreate(&e));
        events.push_back(e);
        return e;
    }
    void upload(StwoRv64Plane p, const std::vector<uint32_t>& v) {
        CHECK(stwo_exec_context_memcpy_h2d_async(ctx, p.words, v.data(), v.size() * 4));
    }
    std::vector<uint32_t> read(StwoRv64Plane p) {
        std::vector<uint32_t> out(size_t(p.stride) * p.coordinates);
        CHECK(stwo_exec_context_memcpy_d2h_async(ctx, out.data(), p.words, out.size() * 4));
        CHECK(stwo_exec_context_sync(ctx));
        return out;
    }
    void close() {
        CHECK(stwo_exec_context_sync(ctx));
        for (auto p : allocations) CHECK(stwo_exec_context_free_u32(ctx, p));
        allocations.clear();
        for (auto e : events) CHECK(cudaEventDestroy(e));
        events.clear();
        CHECK(stwo_exec_context_destroy(ctx));
        ctx = nullptr;
    }
    ~Owner() {
        if (!ctx) return;
        // An earlier failure already makes the run fail. Join before teardown;
        // never publish data from this destructor's best-effort cleanup.
        if (stwo_exec_context_sync(ctx)) return;
        for (auto p : allocations)
            if (stwo_exec_context_free_u32(ctx, p)) return;
        for (auto e : events)
            if (cudaEventDestroy(e)) return;
        (void)stwo_exec_context_destroy(ctx);
    }
};
