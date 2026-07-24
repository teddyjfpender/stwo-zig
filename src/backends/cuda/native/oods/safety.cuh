#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>

namespace stwo::cuda::oods {

struct ByteRange {
    std::uintptr_t first;
    std::uintptr_t last;
};

inline bool checked_product(
    std::size_t left,
    std::size_t right,
    std::size_t *result) {
    if (result == nullptr ||
        (left != 0 && right > std::numeric_limits<std::size_t>::max() / left)) {
        return false;
    }
    *result = left * right;
    return true;
}

inline bool checked_sum(
    std::size_t left,
    std::size_t right,
    std::size_t *result) {
    if (result == nullptr ||
        right > std::numeric_limits<std::size_t>::max() - left) {
        return false;
    }
    *result = left + right;
    return true;
}

inline bool matrix_elements(
    std::size_t rows,
    std::size_t stride,
    std::size_t width,
    std::size_t *result) {
    if (rows == 0 || stride < width || width == 0) return false;
    std::size_t last_row;
    return checked_product(rows - 1, stride, &last_row) &&
           checked_sum(last_row, width, result);
}

inline bool byte_range(
    const void *pointer,
    std::size_t bytes,
    ByteRange *result) {
    if (pointer == nullptr || bytes == 0 || result == nullptr) return false;
    const std::uintptr_t first = reinterpret_cast<std::uintptr_t>(pointer);
    if (bytes > std::numeric_limits<std::uintptr_t>::max() - first) {
        return false;
    }
    *result = {first, first + bytes};
    return true;
}

template <typename Element>
inline bool element_range(
    const Element *pointer,
    std::size_t count,
    ByteRange *result) {
    std::size_t bytes;
    return checked_product(count, sizeof(Element), &bytes) &&
           byte_range(pointer, bytes, result);
}

inline bool ranges_overlap(ByteRange left, ByteRange right) {
    return left.first < right.last && right.first < left.last;
}

}  // namespace stwo::cuda::oods
