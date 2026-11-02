#ifndef STWO_CUDA_RV64_CUSTODY_CUH
#define STWO_CUDA_RV64_CUSTODY_CUH
#include "gkr.h"
#include <cuda_runtime_api.h>
#include <stddef.h>
#include <limits>
extern "C" int stwo_exec_context_lane_stream(void*, uint32_t, void**);
extern "C" int stwo_exec_context_validate_allocation(void*, const void*, size_t);
namespace stwo::cuda::rv64 {
constexpr uint32_t threads = 128, max_count = 1u << 28;
inline bool power2(uint32_t n) {
    return n && !(n & (n - 1));
}
// All source/output allocation and overlap checks happen before any enqueue.
// The registry check also rejects host, cross-context and retired pointers.
struct Custody {
    void* context;
    cudaStream_t stream = nullptr;
    struct Range {
        uintptr_t begin, end;
        bool write;
    } ranges[12]{};
    uint32_t used = 0;
    int status = 0;
    Custody(void* ctx, uint32_t lane) : context(ctx) {
        void* raw = nullptr;
        status = stwo_exec_context_lane_stream(context, lane, &raw);
        if (!status && !raw) status = int(cudaErrorInvalidResourceHandle);
        stream = reinterpret_cast<cudaStream_t>(raw);
    }
    bool range(const uint32_t* p, uint64_t words, bool write) {
        if (status) return false;
        const uintptr_t b = reinterpret_cast<uintptr_t>(p);
        if (!p || !words || b % alignof(uint32_t) || used == 12 ||
            words > SIZE_MAX / sizeof(uint32_t) ||
            words > (UINTPTR_MAX - b) / sizeof(uint32_t)) {
            status = int(cudaErrorInvalidValue);
            return false;
        }
        const uintptr_t end = b + words * sizeof(uint32_t);
        for (uint32_t i = 0; i < used; ++i) {
            if ((write || ranges[i].write) && b < ranges[i].end && ranges[i].begin < end) {
                status = int(cudaErrorInvalidValue);
                return false;
            }
        }
        status =
            stwo_exec_context_validate_allocation(context, p, size_t(words) * sizeof(uint32_t));
        if (status) return false;
        ranges[used++] = {b, end, write};
        return true;
    }
    bool plane(StwoRv64Plane p, uint32_t count, uint32_t coordinates, bool write) {
        if (status) return false;
        if (p.reserved || p.coordinates != coordinates || !count || p.stride < count ||
            p.stride > SIZE_MAX / coordinates) {
            status = int(cudaErrorInvalidValue);
            return false;
        }
        return range(p.words, p.stride * coordinates, write);
    }
    bool numerator(StwoRv64Plane p, uint32_t count) {
        if (p.coordinates != 1 && p.coordinates != 8) {
            status = int(cudaErrorInvalidValue);
            return false;
        }
        return plane(p, count, p.coordinates, false);
    }
};
}  // namespace stwo::cuda::rv64
#endif
