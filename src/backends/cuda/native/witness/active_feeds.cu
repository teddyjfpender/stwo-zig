// Current Cairo feeds distinguish the source's padded stride from its active
// row extent. The legacy feed entry point cannot represent that distinction.
#include <cuda_runtime.h>
#include <cstdint>

namespace stwo::cuda::witness_active {
constexpr unsigned kDescriptorWords = 14;
constexpr unsigned kNoLut = 0xffffffffu;

__device__ __forceinline__ void increment(unsigned* counter) {
#if __CUDA_ARCH__ >= 700 && !defined(STWO_CUMETAL)
    const unsigned peers = __match_any_sync(__activemask(),
        reinterpret_cast<unsigned long long>(counter));
    if ((threadIdx.x & 31u) == static_cast<unsigned>(__ffs(peers) - 1))
        atomicAdd(counter, static_cast<unsigned>(__popc(peers)));
#else
    atomicAdd(counter, 1u);
#endif
}

__global__ void count_active(const unsigned* source, unsigned stride,
    unsigned active_rows, const unsigned* descriptors, unsigned n_descriptors,
    const unsigned* const* luts, unsigned* const* counts) {
    const unsigned row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= active_rows) return;
    for (unsigned d = 0; d < n_descriptors; ++d) {
        const unsigned* e = descriptors + static_cast<size_t>(d) * kDescriptorWords;
        const unsigned first = source[static_cast<size_t>(e[0]) * stride + row];
        unsigned key = 0, relation = e[7];
        if (e[11] == 1u) {
            if (first == 0x3fffffffu) continue;
            const unsigned tag = first >> 30, value = first & 0x3fffffffu;
            if (tag == 1u && value < e[8]) increment(&counts[e[10]][static_cast<size_t>(relation) * e[8] + value]);
            else if (tag == 0u && value < e[12]) increment(&counts[e[13]][static_cast<size_t>(relation) * e[12] + value]);
            continue;
        }
        if (e[11] == 2u || e[11] == 3u) {
            const unsigned bits = e[11] == 3u ? 12u : e[2];
            const unsigned b = source[static_cast<size_t>(e[0] + 1u) * stride + row];
            const unsigned c = source[static_cast<size_t>(e[0] + 2u) * stride + row];
            if (bits == 0u || bits >= 16u || (first | b | c) >= (1u << bits) || c != (first ^ b)) continue;
            if (e[11] == 3u) {
                relation = ((first >> 10u) << 2u) | (b >> 10u);
                key = ((first & 1023u) << 10u) | (b & 1023u);
            } else key = (first << bits) | b;
        } else {
            if (e[1] == 0u || e[1] > 5u) continue;
            bool valid = true;
            for (unsigned i = 0; i < e[1]; ++i) {
                if (e[2 + i] >= 32u) { valid = false; break; }
                const unsigned word = source[static_cast<size_t>(e[0] + i) * stride + row];
                if (e[2 + i] != 0u && word >= (1u << e[2 + i])) { valid = false; break; }
                key = (key << e[2 + i]) | word;
            }
            if (!valid) continue;
            // All keys are u32. Apply the signed address offset with checked
            // u32 arithmetic, avoiding a widening add on every range tuple.
            if (static_cast<int32_t>(e[12]) < 0) {
                const unsigned adjustment = 0u - e[12];
                if (key < adjustment) continue;
                key -= adjustment;
            } else {
                if (key > 0xffffffffu - e[12]) continue;
                key += e[12];
            }
        }
        if (key >= e[8]) continue;
        const unsigned index = e[9] == kNoLut ? key : luts[e[9]][key];
        if (index < e[8]) increment(&counts[e[10]][static_cast<size_t>(relation) * e[8] + index]);
    }
}
}

extern "C" int stwo_witness_feed_counts_active_on(
    const unsigned* source, unsigned padded_rows, unsigned active_rows,
    const unsigned* descriptors, unsigned descriptor_count,
    const unsigned* const* luts, unsigned* const* destinations, void* raw_stream) {
    if (!source || !descriptors || !destinations || !raw_stream ||
        padded_rows == 0 || active_rows > padded_rows || descriptor_count == 0) return 1;
    if (active_rows == 0) return 0;
    const unsigned blocks = active_rows / 256u + (active_rows % 256u != 0);
    stwo::cuda::witness_active::count_active<<<blocks, 256, 0, static_cast<cudaStream_t>(raw_stream)>>>(
        source, padded_rows, active_rows, descriptors, descriptor_count, luts, destinations);
    return static_cast<int>(cudaGetLastError());
}
