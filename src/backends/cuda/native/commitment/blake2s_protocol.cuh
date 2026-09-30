#ifndef STWO_ZIG_CUDA_BLAKE2S_PROTOCOL_CUH
#define STWO_ZIG_CUDA_BLAKE2S_PROTOCOL_CUH

#include "blake2s_core.cuh"

// Commitment protocol selection stays outside the shared transcript core.
// Both formats retain the standard BLAKE2s compression and 32-byte digest.
namespace stwo::cuda::blake2s {

template <bool Prefixed>
__device__ __forceinline__ void initialize_leaf_for(uint32_t hash[8]) {
    if constexpr (Prefixed) initialize_leaf(hash);
    else initialize(hash);
}

template <bool Prefixed>
__device__ __forceinline__ Hash hash_children_for(
    const Hash &left, const Hash &right) {
    if constexpr (Prefixed) return hash_children(left, right);
    uint32_t hash[8];
    uint32_t message[16];
    initialize(hash);
#pragma unroll
    for (int index = 0; index < 8; ++index) {
        message[index] = left.words[index];
        message[index + 8] = right.words[index];
    }
    compress(hash, message, 64, 0xffffffffu);
    Hash result;
#pragma unroll
    for (int index = 0; index < 8; ++index) result.words[index] = hash[index];
    return result;
}

}  // namespace stwo::cuda::blake2s
#endif
