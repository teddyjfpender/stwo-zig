// Native wide-Fibonacci constraint evaluation over one column-major trace slab.
//
// The ABI is intentionally product-owned: no device pointer table, allocation,
// transfer, synchronization, or fallback is hidden behind this kernel.

typedef unsigned long long u64;

#define STWO_M31_P 2147483647u

#ifndef STWO_M31_FAST32_GLOBAL
#define STWO_M31_FAST32_GLOBAL 0
#endif
#if STWO_M31_FAST32_GLOBAL != 0 && STWO_M31_FAST32_GLOBAL != 1
#error "STWO_M31_FAST32_GLOBAL must be 0 or 1"
#endif

__device__ __forceinline__ unsigned stwo_m31_add(unsigned lhs, unsigned rhs) {
    unsigned sum = lhs + rhs;
    return sum >= STWO_M31_P ? sum - STWO_M31_P : sum;
}

__device__ __forceinline__ unsigned stwo_m31_sub(unsigned lhs, unsigned rhs) {
    return lhs >= rhs ? lhs - rhs : lhs + STWO_M31_P - rhs;
}

__device__ __forceinline__ unsigned stwo_m31_mul(unsigned lhs, unsigned rhs) {
#if STWO_M31_FAST32_GLOBAL
    unsigned lo = lhs * rhs;
    unsigned hi = __umulhi(lhs, rhs);
    unsigned quotient = (hi << 1) | (lo >> 31);
    unsigned reduced = (lo & STWO_M31_P) + quotient;
    reduced = (reduced & STWO_M31_P) + (reduced >> 31);
    return reduced == STWO_M31_P ? 0u : reduced;
#else
    u64 product = (u64)lhs * (u64)rhs;
    u64 reduced =
        (((((product >> 31) + product + 1u) >> 31) + product) &
         (u64)STWO_M31_P);
    return (unsigned)reduced;
#endif
}

struct StwoCudaQm31 {
    unsigned a, b, c, d;
};

__device__ __forceinline__ StwoCudaQm31 stwo_qm31_add(
    StwoCudaQm31 lhs,
    StwoCudaQm31 rhs) {
    return StwoCudaQm31{
        stwo_m31_add(lhs.a, rhs.a),
        stwo_m31_add(lhs.b, rhs.b),
        stwo_m31_add(lhs.c, rhs.c),
        stwo_m31_add(lhs.d, rhs.d)};
}

__device__ __forceinline__ StwoCudaQm31 stwo_qm31_mul_base(
    StwoCudaQm31 value,
    unsigned scalar) {
    return StwoCudaQm31{
        stwo_m31_mul(value.a, scalar),
        stwo_m31_mul(value.b, scalar),
        stwo_m31_mul(value.c, scalar),
        stwo_m31_mul(value.d, scalar)};
}

__device__ __forceinline__ StwoCudaQm31 stwo_load_qm31(
    const unsigned *values,
    u64 index) {
    const u64 base = index * 4ull;
    return StwoCudaQm31{
        values[base],
        values[base + 1u],
        values[base + 2u],
        values[base + 3u]};
}

extern "C" __global__ void __launch_bounds__(128)
stwo_native_constraint_wide_fibonacci_slab_v1_6f60dbf6e15716eb(
    const unsigned *trace_slab,
    u64 trace_slab_words,
    u64 trace_column_stride_words,
    unsigned sequence_len,
    const unsigned *random_coeff_powers,
    u64 random_coeff_words,
    const unsigned *denom_inv,
    u64 denominator_words,
    unsigned *coordinate_slab,
    u64 coordinate_slab_words,
    u64 coordinate_stride_words,
    unsigned row_count,
    unsigned log_n_rows,
    unsigned rc_base) {
    const unsigned row_index = blockIdx.x * blockDim.x + threadIdx.x;
    if (row_index >= row_count) return;

    if (sequence_len < 3u || sequence_len > 512u || log_n_rows >= 31u) return;
    const u64 expected_rows = 1ull << (log_n_rows + 1u);
    if (trace_column_stride_words >
        (~0ull - expected_rows) / (sequence_len - 1u)) {
        return;
    }
    const u64 required_trace_words =
        (u64)(sequence_len - 1u) * trace_column_stride_words + expected_rows;
    const u64 required_random_words =
        4ull * ((u64)rc_base + sequence_len - 2u);
    if (coordinate_stride_words >
        (~0ull - expected_rows) / 3ull) {
        return;
    }
    const u64 required_coordinate_words =
        3ull * coordinate_stride_words + expected_rows;
    if ((u64)row_count != expected_rows ||
        trace_column_stride_words < expected_rows ||
        required_trace_words > trace_slab_words ||
        required_random_words > random_coeff_words ||
        denominator_words < 2ull ||
        coordinate_stride_words < expected_rows ||
        required_coordinate_words > coordinate_slab_words) {
        return;
    }

    unsigned a = trace_slab[row_index];
    unsigned b = trace_slab[trace_column_stride_words + row_index];
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};

    for (unsigned column = 2u; column < sequence_len; ++column) {
        const unsigned c =
            trace_slab[(u64)column * trace_column_stride_words + row_index];
        const unsigned expected = stwo_m31_add(
            stwo_m31_mul(a, a),
            stwo_m31_mul(b, b));
        const unsigned constraint = stwo_m31_sub(c, expected);
        acc = stwo_qm31_add(
            acc,
            stwo_qm31_mul_base(
                stwo_load_qm31(
                    random_coeff_powers,
                    (u64)rc_base + sequence_len - 1u - column),
                constraint));
        a = b;
        b = c;
    }

    const unsigned denominator_index = row_index >> log_n_rows;
    const StwoCudaQm31 result =
        stwo_qm31_mul_base(acc, denom_inv[denominator_index]);
    coordinate_slab[row_index] =
        stwo_m31_add(coordinate_slab[row_index], result.a);
    coordinate_slab[coordinate_stride_words + row_index] = stwo_m31_add(
        coordinate_slab[coordinate_stride_words + row_index], result.b);
    coordinate_slab[2ull * coordinate_stride_words + row_index] = stwo_m31_add(
        coordinate_slab[2ull * coordinate_stride_words + row_index], result.c);
    coordinate_slab[3ull * coordinate_stride_words + row_index] = stwo_m31_add(
        coordinate_slab[3ull * coordinate_stride_words + row_index], result.d);
}
