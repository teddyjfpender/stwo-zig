#include "rv64/custody.cuh"
#include <cassert>
#include <vector>
static uint32_t data[1024];
static size_t last_bytes = 0;
extern "C" int stwo_exec_context_lane_stream(void* ctx, uint32_t lane, void** stream) {
    if (ctx != reinterpret_cast<void*>(1) || lane > 1)
        return int(cudaErrorInvalidResourceHandle);
    *stream = reinterpret_cast<void*>(2);
    return 0;
}
extern "C" int stwo_exec_context_validate_allocation(void*, const void* pointer, size_t bytes) {
    last_bytes = bytes;
    const auto p = reinterpret_cast<uintptr_t>(pointer), b = reinterpret_cast<uintptr_t>(data);
    return p >= b && p <= b + sizeof(data) && bytes <= b + sizeof(data) - p
               ? 0
               : int(cudaErrorInvalidDevicePointer);
}
int main() {
    using stwo::cuda::rv64::Custody;
    Custody good(reinterpret_cast<void*>(1), 1);
    assert(good.plane({data, 8, 8, 0}, 8, 8, false));
    assert(last_bytes == 256);  // registry API takes BYTES, not words.
    assert(good.plane({data + 64, 8, 8, 0}, 8, 8, true));
    assert(!good.range(data + 63, 2, true));
    Custody short_plane(reinterpret_cast<void*>(1), 1);
    assert(!short_plane.plane({data, 4, 8, 0}, 8, 8, false));
    Custody foreign(reinterpret_cast<void*>(3), 1);
    assert(!foreign.range(data, 1, false));
    Custody invalid_lane(reinterpret_cast<void*>(1), 2);
    assert(!invalid_lane.range(data, 1, false));
    Custody overflow(reinterpret_cast<void*>(1), 0);
    assert(!overflow.range(data, UINT64_MAX, true));
    Custody bad_coord(reinterpret_cast<void*>(1), 0);
    assert(!bad_coord.numerator({data, 8, 4, 0}, 8));
    Custody misaligned(reinterpret_cast<void*>(1), 0);
    assert(!misaligned.range(reinterpret_cast<uint32_t*>(reinterpret_cast<uintptr_t>(data) + 1),
                             1, false));
    Custody read_alias(reinterpret_cast<void*>(1), 0);
    assert(read_alias.range(data, 64, false));
    assert(read_alias.range(data + 1, 32, false));
    assert(!read_alias.range(data + 32, 64, true));
    Custody out_of_range(reinterpret_cast<void*>(1), 0);
    assert(!out_of_range.range(data + 1023, 2, true));
}
