#ifndef STWO_ZIG_CUDA_FRI_SAFETY_CUH
#define STWO_ZIG_CUDA_FRI_SAFETY_CUH

#include <stddef.h>
#include <stdint.h>

namespace stwo::cuda::fri {

__host__ __device__ constexpr bool is_power_of_two(uint32_t value) {
    return value != 0 && (value & (value - 1u)) == 0;
}

__host__ __device__ __forceinline__ uint32_t bit_reverse(
    uint32_t value,
    uint32_t bits) {
#if defined(__CUDA_ARCH__)
    return bits == 0 ? 0 : __brev(value) >> (32u - bits);
#else
    uint32_t result = 0;
    for (uint32_t bit = 0; bit < bits; ++bit) {
        result = (result << 1u) | ((value >> bit) & 1u);
    }
    return result;
#endif
}

inline bool checked_bytes(size_t count, size_t width, size_t *result) {
    if (result == nullptr || width != 0 && count > SIZE_MAX / width) {
        return false;
    }
    *result = count * width;
    return true;
}

inline bool ranges_overlap(
    const void *left,
    size_t left_bytes,
    const void *right,
    size_t right_bytes) {
    const uintptr_t left_begin = reinterpret_cast<uintptr_t>(left);
    const uintptr_t right_begin = reinterpret_cast<uintptr_t>(right);
    if (left_bytes > UINTPTR_MAX - left_begin ||
        right_bytes > UINTPTR_MAX - right_begin) {
        return true;
    }
    return left_begin < right_begin + right_bytes &&
        right_begin < left_begin + left_bytes;
}

}  // namespace stwo::cuda::fri

#endif
