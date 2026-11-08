// A physical ceiling, not a sampled peak measurement. Run under gpu.lock and
// keep stdin open for the complete prover lifetime. Unmapped PINNED handles
// occupy device physical memory; the rest of the device is <= the requested
// budget, including every prover context, module, stack and driver reservation.
#include <cuda.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>

static void check(CUresult status, const char* operation) {
    if (status == CUDA_SUCCESS) return;
    const char* name = nullptr;
    cuGetErrorName(status, &name);
    std::fprintf(stderr, "budget_guard %s: %s (%d)\n", operation,
                 name ? name : "unknown", int(status));
    std::exit(1);
}

int main(int argc, char** argv) {
    uint64_t limit = 28000000000ULL;
    std::string selected = "0,1";
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--limit-bytes") && i + 1 < argc)
            limit = std::strtoull(argv[++i], nullptr, 10);
        else if (!std::strcmp(argv[i], "--devices") && i + 1 < argc)
            selected = argv[++i];
        else return 2;
    }
    if (!limit) return 2;
    check(cuInit(0), "cuInit");
    struct Held { CUmemGenericAllocationHandle handle; int device; size_t total, bytes, granularity; };
    std::vector<Held> held;
    size_t cursor = 0;
    while (cursor < selected.size()) {
        const size_t end = selected.find(',', cursor);
        const std::string token = selected.substr(cursor, end - cursor);
        char* rest = nullptr;
        const long index = std::strtol(token.c_str(), &rest, 10);
        if (token.empty() || *rest || index < 0) return 2;
        for (const auto& old : held) if (old.device == index) return 2;
        CUdevice device;
        check(cuDeviceGet(&device, int(index)), "cuDeviceGet");
        size_t total = 0;
        check(cuDeviceTotalMem(&total, device), "cuDeviceTotalMem");
        if (total <= limit) return 2;
        CUmemAllocationProp prop{};
        prop.type = CU_MEM_ALLOCATION_TYPE_PINNED;
        prop.location.type = CU_MEM_LOCATION_TYPE_DEVICE;
        prop.location.id = device;
        size_t granularity = 0;
        check(cuMemGetAllocationGranularity(&granularity, &prop,
                  CU_MEM_ALLOC_GRANULARITY_MINIMUM), "cuMemGetAllocationGranularity");
        if (!granularity) return 2;
        const size_t bytes = ((total - limit + granularity - 1) / granularity) * granularity;
        CUmemGenericAllocationHandle handle;
        check(cuMemCreate(&handle, bytes, &prop, 0), "cuMemCreate");
        held.push_back({handle, int(index), total, bytes, granularity});
        if (end == std::string::npos) break;
        cursor = end + 1;
        if (cursor == selected.size()) return 2;
    }
    if (held.empty()) return 2;
    std::printf("{\"schema\":\"rv64-physical-budget-guard/v1\",\"ready\":true,\"requested_limit_bytes\":%llu,\"devices\":[",
                (unsigned long long)limit);
    for (size_t i = 0; i < held.size(); ++i) {
        const auto& h = held[i];
        std::printf("%s{\"device\":%d,\"total_bytes\":%zu,\"held_physical_bytes\":%zu,\"granularity_bytes\":%zu,\"prover_physical_ceiling_bytes\":%zu}",
                    i ? "," : "", h.device, h.total, h.bytes, h.granularity, h.total - h.bytes);
    }
    std::printf("]}\n");
    std::fflush(stdout);
    (void)std::getchar();
    for (auto it = held.rbegin(); it != held.rend(); ++it)
        check(cuMemRelease(it->handle), "cuMemRelease");
    return 0;
}
