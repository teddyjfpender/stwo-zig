#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>

namespace stwo::cuda::cairo {

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

template <typename Element>
inline bool element_range(
    const Element *pointer,
    std::size_t count,
    ByteRange *result) {
    std::size_t bytes;
    if (pointer == nullptr || count == 0 || result == nullptr ||
        !checked_product(count, sizeof(Element), &bytes)) {
        return false;
    }
    const std::uintptr_t first = reinterpret_cast<std::uintptr_t>(pointer);
    if (first % alignof(Element) != 0 ||
        bytes > std::numeric_limits<std::uintptr_t>::max() - first) {
        return false;
    }
    *result = {first, first + bytes};
    return true;
}

inline bool overlaps(ByteRange left, ByteRange right) {
    return left.first < right.last && right.first < left.last;
}

}  // namespace stwo::cuda::cairo
