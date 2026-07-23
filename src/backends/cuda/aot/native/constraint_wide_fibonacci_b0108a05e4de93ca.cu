// Native wide-Fibonacci constraint evaluation using the copied upstream
// ordinary_constraint_v1 ABI. Field formulas match the pinned CUDA emitter.

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
    unsigned index) {
    const unsigned base = index * 4u;
    return StwoCudaQm31{
        values[base],
        values[base + 1u],
        values[base + 2u],
        values[base + 3u]};
}

extern "C" __global__ void __launch_bounds__(128)
stwo_jit_fused_4a5dad552ce2c7ae(
    const unsigned *const *trace_cols,
    const unsigned *interaction_offsets,
    const unsigned *base_params,
    const unsigned *ext_params,
    const unsigned *random_coeff_powers,
    const unsigned *denom_inv,
    unsigned *coord_0,
    unsigned *coord_1,
    unsigned *coord_2,
    unsigned *coord_3,
    unsigned row_count,
    unsigned log_n_rows,
    unsigned rc_base) {
    const unsigned row_index = blockIdx.x * blockDim.x + threadIdx.x;
    if (row_index >= row_count) return;

    // The statement-owned column count is a launch parameter so one immutable
    // AOT module covers every admitted Native wide-Fibonacci width.
    const unsigned sequence_len = base_params[0];
    if (sequence_len < 3u) return;
    const unsigned main_offset = interaction_offsets[1];
    unsigned a = trace_cols[main_offset][row_index];
    unsigned b = trace_cols[main_offset + 1u][row_index];
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};

    for (unsigned column = 2u; column < sequence_len; ++column) {
        const unsigned c = trace_cols[main_offset + column][row_index];
        const unsigned expected = stwo_m31_add(
            stwo_m31_mul(a, a),
            stwo_m31_mul(b, b));
        const unsigned constraint = stwo_m31_sub(c, expected);
        acc = stwo_qm31_add(
            acc,
            stwo_qm31_mul_base(
                stwo_load_qm31(
                    random_coeff_powers,
                    rc_base + column - 2u),
                constraint));
        a = b;
        b = c;
    }

    // ext_params remains present to preserve ordinary_constraint_v1 exactly.
    (void)ext_params;
    const unsigned denominator_index = row_index >> log_n_rows;
    const StwoCudaQm31 result =
        stwo_qm31_mul_base(acc, denom_inv[denominator_index]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
