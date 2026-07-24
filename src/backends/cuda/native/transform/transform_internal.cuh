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
constexpr uint32_t kFirstFusedLogN = 13;
constexpr uint32_t kLastFusedLogN = 23;

template <typename T>
struct ColumnSlab {
    T *base;
    size_t stride_words;

    __device__ __forceinline__ T *column(uint32_t index) const {
        return base + static_cast<size_t>(index) * stride_words;
    }
};

struct TransformSchedule {
    uint8_t interval_count;
    uint8_t intervals[3];
};

constexpr TransformSchedule kB2nSchedules[] = {
    {2, {7, 6, 0}},
    {2, {8, 6, 0}},
    {2, {9, 6, 0}},
    {2, {10, 6, 0}},
    {2, {9, 8, 0}},
    {2, {10, 8, 0}},
    {3, {7, 6, 6}},
    {3, {8, 6, 6}},
    {3, {9, 6, 6}},
    {3, {10, 6, 6}},
    {3, {7, 8, 8}},
};

constexpr TransformSchedule kN2bSchedules[] = {
    {2, {6, 7, 0}},
    {2, {6, 8, 0}},
    {2, {8, 7, 0}},
    {2, {8, 8, 0}},
    {2, {6, 11, 0}},
    {2, {8, 10, 0}},
    {2, {8, 11, 0}},
    {3, {6, 6, 8}},
    {3, {6, 8, 7}},
    {3, {6, 6, 10}},
    {3, {6, 6, 11}},
};

constexpr bool valid_schedule(
    const TransformSchedule &schedule,
    uint32_t log_n) {
    uint32_t covered = 0;
    for (uint32_t i = 0; i < schedule.interval_count; ++i) {
        if (schedule.intervals[i] == 0) return false;
        covered += schedule.intervals[i];
    }
    return covered == log_n;
}

constexpr bool schedules_are_exact() {
    for (uint32_t i = 0; i <= kLastFusedLogN - kFirstFusedLogN; ++i) {
        const uint32_t log_n = kFirstFusedLogN + i;
        if (!valid_schedule(kB2nSchedules[i], log_n) ||
            !valid_schedule(kN2bSchedules[i], log_n)) {
            return false;
        }
    }
    return true;
}

constexpr bool schedule_tail_is_stack_free(
    const TransformSchedule &schedule,
    uint32_t first_interval) {
    for (uint32_t i = first_interval; i < schedule.interval_count; ++i) {
        if (schedule.intervals[i] != 6) return false;
    }
    return true;
}

constexpr bool selected_schedule_resource_contracts_hold() {
    // These rows replace the 8-stage continuation, whose sixteen dynamic
    // values require a local stack on the supported AOT toolchain. The
    // selected 6-stage continuation holds eight values in registers.
    constexpr uint32_t b2n_indices[] = {2u, 3u, 8u, 9u};
    for (uint32_t index : b2n_indices) {
        if (!schedule_tail_is_stack_free(kB2nSchedules[index], 1)) {
            return false;
        }
    }
    constexpr uint32_t n2b_indices[] = {9u, 10u};
    for (uint32_t index : n2b_indices) {
        const TransformSchedule &schedule = kN2bSchedules[index];
        for (uint32_t i = 0; i + 1u < schedule.interval_count; ++i) {
            if (schedule.intervals[i] != 6) return false;
        }
    }
    return true;
}

static_assert(
    schedules_are_exact(),
    "fused transform schedules must partition every admitted stage exactly");
static_assert(
    selected_schedule_resource_contracts_hold(),
    "qualified transform rows must retain their stack-free continuations");

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
    bool include_circle,
    uint32_t *launches_out);

}  // namespace stwo::cuda::transform

#endif
