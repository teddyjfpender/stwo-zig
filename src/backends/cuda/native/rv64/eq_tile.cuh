#ifndef STWO_CUDA_RV64_EQ_TILE_CUH
#define STWO_CUDA_RV64_EQ_TILE_CUH
#include "om31.cuh"
namespace stwo::cuda::rv64 {
// One thread owns one old prefix value and every descendant it emits. No
// intermediate level enters global memory. The earliest new variable is the
// highest new index bit, exactly matching native EqEvals generation.
template <uint32_t Levels>
__host__ __device__ __forceinline__ void expand_eq_tile(OM31 value, const uint32_t* point,
                                                        uint32_t first, uint32_t* output,
                                                        uint64_t stride, uint32_t index,
                                                        uint32_t half, uint32_t group = 0) {
    if constexpr (Levels == 0)
        store(output, stride, index + uint64_t(group) * half, value);
    else {
        const OM31 y = from_words(point + 8 * first);
        expand_eq_tile<Levels - 1>(mul(value, sub(one(), y)), point, first + 1, output, stride,
                                   index, half, group);
        expand_eq_tile<Levels - 1>(mul(value, y), point, first + 1, output, stride, index, half,
                                   group + (1u << (Levels - 1)));
    }
}
}  // namespace stwo::cuda::rv64
#endif
