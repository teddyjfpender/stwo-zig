#pragma once

#include "../oods/safety.cuh"

#include <cstddef>
#include <cstdint>

namespace stwo::cuda::quotient {

using ByteRange = oods::ByteRange;
using oods::checked_product;
using oods::element_range;
using oods::matrix_elements;
using oods::ranges_overlap;

template <typename Element>
inline bool matrix_range(
    const Element *base,
    std::size_t row_count,
    std::size_t row_stride,
    std::size_t touched_width,
    ByteRange *result) {
    std::size_t count;
    return matrix_elements(
               row_count,
               row_stride,
               touched_width,
               &count) &&
           element_range(base, count, result);
}

inline bool ranges_disjoint(
    const ByteRange *writes,
    std::size_t write_count,
    const ByteRange *reads,
    std::size_t read_count) {
    for (std::size_t left = 0; left < write_count; ++left) {
        for (std::size_t right = left + 1; right < write_count; ++right) {
            if (ranges_overlap(writes[left], writes[right])) return false;
        }
        for (std::size_t read = 0; read < read_count; ++read) {
            if (ranges_overlap(writes[left], reads[read])) return false;
        }
    }
    return true;
}

__host__ __device__ constexpr bool is_power_of_two(std::uint32_t value) {
    return value != 0 && (value & (value - 1u)) == 0;
}

}  // namespace stwo::cuda::quotient
