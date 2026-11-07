#ifndef STWO_ZIG_CUDA_BLAKE2S_MERKLE_FUSED_CUH
#define STWO_ZIG_CUDA_BLAKE2S_MERKLE_FUSED_CUH

// T6 (M8 round 2) Merkle tree kernels behind STWO_RV64_M8_MERKLE_FUSED, used by
// stwo_blake2s_merkle_layers_on (merkle.cu). Existing entry points, kernels
// and buffer layouts are unchanged. Both kernels hash every node with the
// established hash_children_for, so all nodes and the root are bit-identical
// to the callers' layer loop.

#include "blake2s_protocol.cuh"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Schedule constants; their measured A/Bs are in the comment above
// fused_tree_layers (merkle.cu). The -D overrides exist only for those
// tuning builds of the receipt's bench.
#ifndef STWO_T6_TAIL_NODES
#define STWO_T6_TAIL_NODES 2048
#endif
#ifndef STWO_T6_SUBTREE_BLOCK
#define STWO_T6_SUBTREE_BLOCK 128
#endif
#ifndef STWO_T6_TAIL_BLOCK
#define STWO_T6_TAIL_BLOCK 1024
#endif

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

// Explicit 2x128-bit loads/stores. [M review-r3] Indexing the global Hash
// arrays directly (hash_children_for(previous[2 * i], ...)) costs the tail CTA
// ~2 us per tree (2^10 0.0136 -> 0.0157 ms, 2^20 0.0724 -> 0.0765), the same
// gap that makes upper_tail_kernel the slower tail.
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
template <bool Prefixed, uint32_t Levels>
__global__ void __launch_bounds__(STWO_T6_SUBTREE_BLOCK) subtree_levels_kernel(
    const Hash *input, uint32_t outputs_top, Hash *layer1, Hash *layer2,
    Hash *layer3) {
    static_assert(Levels >= 2 && Levels <= 3, "subtree levels");
    const uint32_t t = blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= outputs_top) return;
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
            level[i] = hash_children_for<Prefixed>(level[2 * i], level[2 * i + 1]);
            store_hash(outs[l] + size_t(t) * count + i, level[i]);
        }
    }
}

// All remaining layers of a small subtree in one CTA: layer sizes halve and
// every layer is separated by a block barrier (global writes of the block are
// visible to the block after __syncthreads). `outputs` is the contiguous run
// of layers that follows `previous`.
template <bool Prefixed>
__global__ void __launch_bounds__(STWO_T6_TAIL_BLOCK) fused_tail_kernel(
    const Hash *previous, uint32_t previous_size, Hash *outputs) {
    Hash *next = outputs;
    for (uint32_t size = previous_size; size > 1; size >>= 1) {
        const uint32_t next_size = size >> 1;
        for (uint32_t i = threadIdx.x; i < next_size; i += blockDim.x)
            store_hash(next + i, hash_children_for<Prefixed>(load_hash(previous + 2 * i),
                                                             load_hash(previous + 2 * i + 1)));
        __syncthreads();
        previous = next;
        next += next_size;
    }
}

}  // namespace stwo::cuda::blake2s

#endif
