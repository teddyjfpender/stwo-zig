#ifndef STWO_ZIG_CUDA_COMMITMENT_RESIDENT_LAYOUT_CUH
#define STWO_ZIG_CUDA_COMMITMENT_RESIDENT_LAYOUT_CUH

#include <stddef.h>
#include <stdint.h>

namespace stwo::cuda::blake2s {

struct DeviceRange {
    uintptr_t start;
    uintptr_t end;
};

inline bool byte_range(
    const void *base,
    size_t bytes,
    size_t alignment,
    DeviceRange *result) {
    if (base == nullptr || bytes == 0 || alignment == 0 || result == nullptr) {
        return false;
    }
    const uintptr_t start = reinterpret_cast<uintptr_t>(base);
    if (start % alignment != 0 || bytes > UINTPTR_MAX - start) return false;
    *result = {start, start + bytes};
    return true;
}

template <typename T>
inline bool element_range(
    const T *base,
    size_t count,
    DeviceRange *result) {
    if (count == 0 || count > SIZE_MAX / sizeof(T)) return false;
    return byte_range(base, count * sizeof(T), alignof(T), result);
}

inline bool exact_word_slab_range(
    const uint32_t *base,
    size_t capacity_words,
    size_t column_stride_words,
    uint32_t words_per_column,
    uint32_t *column_count,
    DeviceRange *result) {
    if (capacity_words == 0 || words_per_column == 0 ||
        column_stride_words < words_per_column || column_count == nullptr ||
        capacity_words % column_stride_words != 0 ||
        capacity_words / column_stride_words > UINT32_MAX) {
        return false;
    }
    const uint32_t count =
        static_cast<uint32_t>(capacity_words / column_stride_words);
    if (count == 0 ||
        static_cast<size_t>(count - 1u) >
            SIZE_MAX / column_stride_words) {
        return false;
    }
    const size_t final_offset =
        static_cast<size_t>(count - 1u) * column_stride_words;
    if (words_per_column > SIZE_MAX - final_offset) return false;
    const size_t required_words = final_offset + words_per_column;
    if (capacity_words < required_words) return false;
    if (!element_range(base, capacity_words, result)) return false;
    *column_count = count;
    return true;
}

inline bool ranges_overlap(DeviceRange left, DeviceRange right) {
    return left.start < right.end && right.start < left.end;
}

}  // namespace stwo::cuda::blake2s

#endif
