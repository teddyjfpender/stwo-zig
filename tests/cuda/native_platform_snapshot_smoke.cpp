#include <cuda_runtime_api.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>

struct alignas(8) PlatformSnapshot {
    std::uint8_t uuid[16];
    std::uint32_t driver_version;
    std::uint32_t runtime_version;
    std::uint32_t toolkit_version;
    std::uint32_t device_ordinal;
    std::uint64_t total_global_memory;
    std::uint32_t multiprocessor_count;
    std::uint32_t warp_size;
    std::uint32_t max_threads_per_block;
    std::uint32_t reserved;
};

static_assert(sizeof(PlatformSnapshot) == 56);
static_assert(offsetof(PlatformSnapshot, total_global_memory) == 32);

extern "C" int stwo_cuda_platform_snapshot(PlatformSnapshot *out);

int main() {
    PlatformSnapshot snapshot{};
    const int status = stwo_cuda_platform_snapshot(&snapshot);
    if (status != 0) {
        std::fprintf(
            stderr,
            "platform snapshot: %s\n",
            cudaGetErrorString(static_cast<cudaError_t>(status)));
        return 1;
    }
    bool uuid_nonzero = false;
    for (std::uint8_t byte : snapshot.uuid) uuid_nonzero |= byte != 0;
    if (!uuid_nonzero || snapshot.driver_version == 0 ||
        snapshot.runtime_version == 0 || snapshot.toolkit_version == 0 ||
        snapshot.total_global_memory == 0 ||
        snapshot.multiprocessor_count == 0 || snapshot.warp_size == 0 ||
        snapshot.max_threads_per_block == 0 || snapshot.reserved != 0) {
        std::fprintf(stderr, "incomplete CUDA platform provenance\n");
        return 1;
    }
    std::printf(
        "native CUDA platform snapshot passed: device=%u driver=%u "
        "runtime=%u toolkit=%u memory=%llu SMs=%u\n",
        snapshot.device_ordinal,
        snapshot.driver_version,
        snapshot.runtime_version,
        snapshot.toolkit_version,
        static_cast<unsigned long long>(snapshot.total_global_memory),
        snapshot.multiprocessor_count);
    return 0;
}
