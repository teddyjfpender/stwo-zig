#ifndef STWO_ZIG_CUDA_BLAKE2S_DOMAIN_STATES_H
#define STWO_ZIG_CUDA_BLAKE2S_DOMAIN_STATES_H

#include <stdint.h>

namespace stwo::cuda::blake2s {

struct DomainState {
    uint32_t words[8];
};

#if defined(__CUDACC__)
#define STWO_BLAKE2S_DOMAIN_STATE_STORAGE static __device__ __constant__
#else
#define STWO_BLAKE2S_DOMAIN_STATE_STORAGE inline constexpr
#endif

STWO_BLAKE2S_DOMAIN_STATE_STORAGE DomainState kLeafInitialState = {{
    0x6510b1f7u, 0xfd531f42u, 0xcff75ec3u, 0x382935d0u,
    0xab15dbf2u, 0x950eb564u, 0xe8e92866u, 0x28047acau,
}};

STWO_BLAKE2S_DOMAIN_STATE_STORAGE DomainState kNodeInitialState = {{
    0xe5cf8926u, 0x841cea30u, 0x7b4acadau, 0xfc5d8d28u,
    0xfc6ef857u, 0xb29da528u, 0xc0d319c7u, 0x8ae795c8u,
}};

#undef STWO_BLAKE2S_DOMAIN_STATE_STORAGE

}  // namespace stwo::cuda::blake2s

#endif
