#ifndef STWO_ZIG_CUDA_POW_SAFETY_CUH
#define STWO_ZIG_CUDA_POW_SAFETY_CUH

#include <stddef.h>
#include <stdint.h>

namespace stwo::cuda::pow {

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

template <size_t count>
inline bool all_disjoint(
    const void *const (&pointers)[count],
    const size_t (&sizes)[count]) {
    for (size_t left = 0; left < count; ++left) {
        for (size_t right = left + 1; right < count; ++right) {
            if (ranges_overlap(
                    pointers[left], sizes[left],
                    pointers[right], sizes[right])) {
                return false;
            }
        }
    }
    return true;
}

}  // namespace stwo::cuda::pow

#endif
