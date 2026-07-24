#ifndef STWO_ZIG_CUDA_COMMON_CIRCLE_TWIDDLE_CUH
#define STWO_ZIG_CUDA_COMMON_CIRCLE_TWIDDLE_CUH

#include "m31.cuh"

namespace stwo::cuda {

__device__ __forceinline__ M31 circle_twiddle(
    const M31 *twiddles,
    uint32_t index) {
    const uint32_t pair = index >> 2;
    switch (index & 3u) {
        case 0:
            return twiddles[2u * pair + 1u];
        case 1:
            return m31_neg(twiddles[2u * pair + 1u]);
        case 2:
            return m31_neg(twiddles[2u * pair]);
        default:
            return twiddles[2u * pair];
    }
}

}  // namespace stwo::cuda

#endif
