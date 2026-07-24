#ifndef STWO_ZIG_CUDA_TRANSFORM_INTERNAL_CUH
#define STWO_ZIG_CUDA_TRANSFORM_INTERNAL_CUH

#include <cuda_runtime_api.h>

#include <stddef.h>
#include <stdint.h>

namespace stwo::cuda::transform {

constexpr uint32_t kThreadsPerBlock = 256;
constexpr uint32_t kMaxColumnsPerLaunch = 65535;
constexpr uint32_t kMinLogN = 3;
constexpr uint32_t kMaxLogN = 30;

struct DeviceRange {
    uintptr_t start;
    uintptr_t end;
};

inline bool valid_shape(
    uint32_t log_n,
    uint32_t polynomial_count,
    uint32_t twiddle_words,
    uint32_t evaluation_domain_size) {
    return log_n >= kMinLogN &&
        log_n <= kMaxLogN &&
        polynomial_count != 0 &&
        evaluation_domain_size == (1u << (log_n - 1u)) &&
        evaluation_domain_size <= twiddle_words;
}

inline bool word_range(
    const void *base,
    size_t words,
    DeviceRange *result) {
    if (base == nullptr || words == 0 || result == nullptr ||
        words > SIZE_MAX / sizeof(uint32_t)) {
        return false;
    }
    const uintptr_t start = reinterpret_cast<uintptr_t>(base);
    if (start % alignof(uint32_t) != 0) return false;
    const size_t bytes = words * sizeof(uint32_t);
    if (bytes > UINTPTR_MAX - start) return false;
    *result = {start, start + bytes};
    return true;
}

inline bool column_range(
    const void *base,
    size_t column_stride_words,
    uint32_t column_count,
    size_t words_per_column,
    DeviceRange *result) {
    if (column_count == 0 ||
        column_stride_words < words_per_column ||
        static_cast<size_t>(column_count - 1u) >
            SIZE_MAX / column_stride_words) {
        return false;
    }
    const size_t final_offset =
        static_cast<size_t>(column_count - 1u) * column_stride_words;
    if (words_per_column > SIZE_MAX - final_offset) return false;
    return word_range(base, final_offset + words_per_column, result);
}

inline bool ranges_overlap(DeviceRange left, DeviceRange right) {
    return left.start < right.end && right.start < left.end;
}

cudaError_t n2b_columns_on(
    uint32_t *columns,
    size_t column_stride_words,
    uint32_t log_n,
    uint32_t polynomial_count,
    const uint32_t *twiddles,
    uint32_t twiddle_words,
    uint32_t evaluation_domain_size,
    cudaStream_t stream,
    bool include_circle);

}  // namespace stwo::cuda::transform

#endif
