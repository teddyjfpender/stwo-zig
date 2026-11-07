#ifndef STWO_ZIG_CUDA_BLAKE2S_MERKLE_FUSED_CUH
#define STWO_ZIG_CUDA_BLAKE2S_MERKLE_FUSED_CUH

// T6 (M8 round 2) Merkle tree kernels behind STWO_RV64_M8_MERKLE_FUSED, used by
// stwo_blake2s_merkle_layers_on (merkle.cu). Existing entry points, kernels
// and buffer layouts are unchanged. Every kernel hashes exactly the same Blake2s messages
// as the established kernels (same byte counters, same final-block rule), so
// leaves, nodes, prefix states and roots are bit-identical.

#include "blake2s_protocol.cuh"
#include "progressive_scalar.cuh"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

namespace stwo::cuda::blake2s {

// 0 = established kernels, 1 = T6 kernels, -1 = invalid value (fail closed).
// A process-wide test override (stwo_blake2s_m8_merkle_fused_override) wins
// over the environment so one binary can A/B both arms.
inline int &merkle_fused_override_slot() {
    static int value = -2;  // -2: no override
    return value;
}

inline int merkle_fused_mode() {
    const int forced = __atomic_load_n(&merkle_fused_override_slot(), __ATOMIC_RELAXED);
    if (forced != -2) return forced;
    static const int from_env = [] {
        const char *value = getenv("STWO_RV64_M8_MERKLE_FUSED");
        if (value == nullptr || *value == 0 || strcmp(value, "0") == 0) return 0;
        if (strcmp(value, "1") == 0) return 1;
        return -1;
    }();
    return from_env;
}

// Compression over an array state with compile-time indices only, so ptxas
// keeps both arrays in registers (0 bytes stack frame, ptxas -v).
__device__ __forceinline__ void fused_compress(
    uint32_t (&h)[8], const uint32_t (&m)[16], uint64_t byte_count, uint32_t last) {
    progressive_compress(h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
                         m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7],
                         m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15],
                         byte_count, last);
}

__device__ __forceinline__ Hash fused_children(
    const uint32_t (&init)[8], const Hash &left, const Hash &right, uint64_t bytes) {
    uint32_t h[8];
    uint32_t m[16];
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        h[i] = init[i];
        m[i] = left.words[i];
        m[i + 8] = right.words[i];
    }
    fused_compress(h, m, bytes, 0xffffffffu);
    Hash out;
#pragma unroll
    for (int i = 0; i < 8; ++i) out.words[i] = h[i];
    return out;
}

template <bool Prefixed>
__device__ __forceinline__ void node_init(uint32_t (&init)[8]) {
    if constexpr (Prefixed) {
        initialize_node(init);
    } else {
        initialize(init);
    }
}

template <bool Prefixed>
__host__ __device__ constexpr uint64_t node_bytes() {
    return Prefixed ? 128u : 64u;
}

__device__ __forceinline__ Hash load_hash(const Hash *p) {
    const uint4 *v = reinterpret_cast<const uint4 *>(p);
    const uint4 a = v[0];
    const uint4 b = v[1];
    return {{a.x, a.y, a.z, a.w, b.x, b.y, b.z, b.w}};
}

__device__ __forceinline__ void store_hash(Hash *p, const Hash &h) {
    uint4 *v = reinterpret_cast<uint4 *>(p);
    v[0] = make_uint4(h.words[0], h.words[1], h.words[2], h.words[3]);
    v[1] = make_uint4(h.words[4], h.words[5], h.words[6], h.words[7]);
}

// One thread owns 2^Levels consecutive nodes of the input layer and writes
// the Levels layers above them (2^(Levels-1), ..., 1 nodes) from registers:
// every compression slot is used (no idle lanes), the input layer is read
// once instead of once per layer, and the per-thread compressions are
// independent (ILP). out[j] is the start of layer j+1 above `input`.
#ifndef STWO_T6_SUBTREE_BLOCK
#define STWO_T6_SUBTREE_BLOCK 128
#endif
template <bool Prefixed, uint32_t Levels>
__global__ void __launch_bounds__(STWO_T6_SUBTREE_BLOCK) subtree_levels_kernel(
    const Hash *input, uint32_t outputs_top, Hash *layer1, Hash *layer2,
    Hash *layer3) {
    static_assert(Levels >= 1 && Levels <= 3, "subtree levels");
    const uint32_t t = blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= outputs_top) return;
    uint32_t init[8];
    node_init<Prefixed>(init);
    constexpr uint64_t bytes = node_bytes<Prefixed>();
    constexpr uint32_t width = 1u << Levels;
    Hash level[width];
#pragma unroll
    for (uint32_t i = 0; i < width; ++i)
        level[i] = load_hash(input + size_t(t) * width + i);
    Hash *outs[3] = {layer1, layer2, layer3};
#pragma unroll
    for (uint32_t l = 0; l < Levels; ++l) {
        const uint32_t count = width >> (l + 1);
#pragma unroll
        for (uint32_t i = 0; i < count; ++i) {
            level[i] = fused_children(init, level[2 * i], level[2 * i + 1], bytes);
            store_hash(outs[l] + size_t(t) * count + i, level[i]);
        }
    }
}

// All remaining layers of a small subtree in one CTA: layer sizes halve and
// every layer is separated by a block barrier (global writes of the block are
// visible to the block after __syncthreads). `outputs` is the contiguous run
// of layers that follows `previous`.
template <bool Prefixed>
__global__ void __launch_bounds__(1024) fused_tail_kernel(
    const Hash *previous, uint32_t previous_size, Hash *outputs) {
    uint32_t init[8];
    node_init<Prefixed>(init);
    constexpr uint64_t bytes = node_bytes<Prefixed>();
    Hash *next = outputs;
    for (uint32_t size = previous_size; size > 1; size >>= 1) {
        const uint32_t next_size = size >> 1;
        for (uint32_t i = threadIdx.x; i < next_size; i += blockDim.x)
            store_hash(next + i, fused_children(init, load_hash(previous + 2 * i),
                                                load_hash(previous + 2 * i + 1), bytes));
        __syncthreads();
        previous = next;
        next += next_size;
    }
}

}  // namespace stwo::cuda::blake2s

#endif
