// Generic indexed order-two M31 recurrence trace generation.
//
// The frontend supplies the scalar recipe and two resident four-column
// destinations. This program owns no statement policy, allocation, transfer,
// synchronization, or fallback.

typedef unsigned long long u64;

#define STWO_M31_P 2147483647ull
#define STWO_TRACE_COLUMNS 4ull

__device__ __forceinline__ unsigned stwo_m31_from_u64(u64 value) {
    u64 reduced = (value & STWO_M31_P) + (value >> 31u);
    reduced = (reduced & STWO_M31_P) + (reduced >> 31u);
    return reduced >= STWO_M31_P
        ? (unsigned)(reduced - STWO_M31_P)
        : (unsigned)reduced;
}

__device__ __forceinline__ unsigned stwo_m31_add(
    unsigned lhs,
    unsigned rhs) {
    const u64 sum = (u64)lhs + rhs;
    return (unsigned)(sum >= STWO_M31_P ? sum - STWO_M31_P : sum);
}

__device__ __forceinline__ unsigned stwo_m31_sub(
    unsigned lhs,
    unsigned rhs) {
    return lhs >= rhs
        ? lhs - rhs
        : (unsigned)((u64)lhs + STWO_M31_P - rhs);
}

__device__ __forceinline__ unsigned stwo_m31_mul(
    unsigned lhs,
    unsigned rhs) {
    return stwo_m31_from_u64((u64)lhs * rhs);
}

struct StwoM31Pair {
    unsigned current;
    unsigned next;
};

__device__ __forceinline__ StwoM31Pair stwo_m31_fibonacci_pair(
    unsigned index) {
    unsigned current = 0u;
    unsigned next = 1u;
    for (unsigned bit_count = 31u; bit_count > 0u; --bit_count) {
        const unsigned bit = bit_count - 1u;
        const unsigned twice_next = stwo_m31_add(next, next);
        const unsigned doubled = stwo_m31_mul(
            current,
            stwo_m31_sub(twice_next, current));
        const unsigned advanced = stwo_m31_add(
            stwo_m31_mul(current, current),
            stwo_m31_mul(next, next));
        if (((index >> bit) & 1u) == 0u) {
            current = doubled;
            next = advanced;
        } else {
            current = advanced;
            next = stwo_m31_add(doubled, advanced);
        }
    }
    return {current, next};
}

extern "C" __global__ void __launch_bounds__(256)
stwo_native_trace_indexed_recurrence_slabs_v1_ad484862f20d700c(
    unsigned *preprocessed_slab,
    u64 preprocessed_slab_words,
    u64 preprocessed_stride_words,
    unsigned *main_slab,
    u64 main_slab_words,
    u64 main_stride_words,
    unsigned row_count,
    unsigned log_n_rows,
    u64 index_base,
    u64 index_step,
    u64 preprocessed_constant,
    u64 recurrence_seed0,
    u64 recurrence_seed1,
    u64 selector_default,
    u64 selector_last,
    u64 selector_penultimate) {
    const unsigned row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= row_count) return;

    const u64 expected_rows =
        log_n_rows < 31u ? 1ull << log_n_rows : 0ull;
    if (preprocessed_slab == nullptr || main_slab == nullptr ||
        preprocessed_slab == main_slab ||
        log_n_rows == 0u || log_n_rows >= 31u ||
        (u64)row_count != expected_rows ||
        preprocessed_stride_words < expected_rows ||
        main_stride_words < expected_rows ||
        preprocessed_stride_words > (~0ull) / STWO_TRACE_COLUMNS ||
        main_stride_words > (~0ull) / STWO_TRACE_COLUMNS ||
        preprocessed_slab_words !=
            preprocessed_stride_words * STWO_TRACE_COLUMNS ||
        main_slab_words != main_stride_words * STWO_TRACE_COLUMNS ||
        index_step == 0ull ||
        expected_rows + 1ull > (~0ull - index_base) / index_step) {
        return;
    }

    const u64 index = index_base + (u64)row * index_step;
    preprocessed_slab[row] = stwo_m31_from_u64(index);
    preprocessed_slab[preprocessed_stride_words + row] =
        stwo_m31_from_u64(index + index_step);
    preprocessed_slab[2ull * preprocessed_stride_words + row] =
        stwo_m31_from_u64(index + 2ull * index_step);
    preprocessed_slab[3ull * preprocessed_stride_words + row] =
        stwo_m31_from_u64(preprocessed_constant);

    const unsigned seed0 = stwo_m31_from_u64(recurrence_seed0);
    const unsigned seed1 = stwo_m31_from_u64(recurrence_seed1);
    const StwoM31Pair fib = stwo_m31_fibonacci_pair(row);
    const unsigned delta = stwo_m31_sub(seed1, seed0);
    const unsigned value0 = stwo_m31_add(
        stwo_m31_mul(seed0, fib.next),
        stwo_m31_mul(delta, fib.current));
    const unsigned value1 = stwo_m31_add(
        stwo_m31_mul(seed0, fib.current),
        stwo_m31_mul(seed1, fib.next));
    const unsigned value2 = stwo_m31_add(value0, value1);

    u64 selector = selector_default;
    if (row + 1u == row_count) {
        selector = selector_last;
    } else if (row + 2u == row_count) {
        selector = selector_penultimate;
    }
    main_slab[row] = stwo_m31_from_u64(selector);
    main_slab[main_stride_words + row] = value0;
    main_slab[2ull * main_stride_words + row] = value1;
    main_slab[3ull * main_stride_words + row] = value2;
}
