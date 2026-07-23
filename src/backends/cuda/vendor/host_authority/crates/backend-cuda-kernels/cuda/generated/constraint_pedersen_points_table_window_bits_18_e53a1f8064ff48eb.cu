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

__device__ __forceinline__ unsigned stwo_m31_neg(unsigned value) {
    unsigned negated = STWO_M31_P - value;
    return negated == STWO_M31_P ? 0u : negated;
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
    u64 reduced = (((((product >> 31) + product + 1u) >> 31) + product) & (u64)STWO_M31_P);
    return (unsigned)reduced;
#endif
}

__device__ __forceinline__ unsigned stwo_m31_square(unsigned value) {
    return stwo_m31_mul(value, value);
}

__device__ __forceinline__ unsigned stwo_m31_pow2k(unsigned squarings, unsigned value) {
    unsigned result = value;
    for (unsigned i = 0; i < squarings; ++i) { result = stwo_m31_square(result); }
    return result;
}

__device__ __forceinline__ unsigned stwo_m31_inv(unsigned value) {
    unsigned t0 = stwo_m31_mul(stwo_m31_pow2k(2u, value), value);
    unsigned t1 = stwo_m31_mul(stwo_m31_pow2k(1u, t0), t0);
    unsigned t2 = stwo_m31_mul(stwo_m31_pow2k(3u, t1), t0);
    unsigned t3 = stwo_m31_mul(stwo_m31_pow2k(1u, t2), t0);
    unsigned t4 = stwo_m31_mul(stwo_m31_pow2k(8u, t3), t3);
    unsigned t5 = stwo_m31_mul(stwo_m31_pow2k(8u, t4), t3);
    return stwo_m31_mul(stwo_m31_pow2k(7u, t5), t2);
}

struct StwoCudaQm31 { unsigned a, b, c, d; };

__device__ __forceinline__ StwoCudaQm31 stwo_qm31_add(StwoCudaQm31 l, StwoCudaQm31 r) {
    return StwoCudaQm31{stwo_m31_add(l.a, r.a), stwo_m31_add(l.b, r.b),
                        stwo_m31_add(l.c, r.c), stwo_m31_add(l.d, r.d)};
}

__device__ __forceinline__ StwoCudaQm31 stwo_qm31_sub(StwoCudaQm31 l, StwoCudaQm31 r) {
    return StwoCudaQm31{stwo_m31_sub(l.a, r.a), stwo_m31_sub(l.b, r.b),
                        stwo_m31_sub(l.c, r.c), stwo_m31_sub(l.d, r.d)};
}

__device__ __forceinline__ StwoCudaQm31 stwo_qm31_mul_base(StwoCudaQm31 v, unsigned s) {
    return StwoCudaQm31{stwo_m31_mul(v.a, s), stwo_m31_mul(v.b, s),
                        stwo_m31_mul(v.c, s), stwo_m31_mul(v.d, s)};
}

__device__ __forceinline__ StwoCudaQm31 stwo_qm31_mul(StwoCudaQm31 l, StwoCudaQm31 r) {
    unsigned a0 = l.a, a1 = l.b, a2 = l.c, a3 = l.d;
    unsigned b0 = r.a, b1 = r.b, b2 = r.c, b3 = r.d;
    unsigned x0 = stwo_m31_sub(stwo_m31_mul(a0, b0), stwo_m31_mul(a1, b1));
    unsigned x1 = stwo_m31_add(stwo_m31_mul(a0, b1), stwo_m31_mul(a1, b0));
    unsigned y0 = stwo_m31_sub(stwo_m31_mul(a2, b2), stwo_m31_mul(a3, b3));
    unsigned y1 = stwo_m31_add(stwo_m31_mul(a2, b3), stwo_m31_mul(a3, b2));
    unsigned c0 = stwo_m31_sub(stwo_m31_mul(a0, b2), stwo_m31_mul(a1, b3));
    unsigned c1 = stwo_m31_add(stwo_m31_mul(a0, b3), stwo_m31_mul(a1, b2));
    unsigned c2 = stwo_m31_sub(stwo_m31_mul(a2, b0), stwo_m31_mul(a3, b1));
    unsigned c3 = stwo_m31_add(stwo_m31_mul(a2, b1), stwo_m31_mul(a3, b0));
    unsigned ry0 = stwo_m31_sub(stwo_m31_mul(2u, y0), y1);
    unsigned ry1 = stwo_m31_add(y0, stwo_m31_mul(2u, y1));
    return StwoCudaQm31{stwo_m31_add(x0, ry0), stwo_m31_add(x1, ry1),
                        stwo_m31_add(c0, c2), stwo_m31_add(c1, c3)};
}

__device__ __forceinline__ StwoCudaQm31 stwo_load_qm31(const unsigned *values, unsigned index) {
    unsigned base = index * 4u;
    return StwoCudaQm31{values[base], values[base + 1u], values[base + 2u], values[base + 3u]};
}

__device__ __forceinline__ unsigned stwo_bit_reverse(unsigned index, unsigned bits) {
    return __brev(index) >> (32u - bits);
}

__device__ __forceinline__ unsigned stwo_offset_bit_reversed_circle_domain_index(
    unsigned i, unsigned domain_log_size, unsigned eval_log_size, int offset
) {
    unsigned prev = stwo_bit_reverse(i, eval_log_size);
    unsigned half_size = 1u << (eval_log_size - 1u);
    int step = offset * (int)(1u << (eval_log_size - domain_log_size - 1u));
    if (prev < half_size) {
        int p = ((int)prev + step) % (int)half_size;
        if (p < 0) p += (int)half_size;
        prev = (unsigned)p;
    } else {
        int p = (int)prev - step;
        p = p % (int)half_size;
        if (p < 0) p += (int)half_size;
        prev = (unsigned)p + half_size;
    }
    return stwo_bit_reverse(prev, eval_log_size);
}

__device__ __forceinline__ unsigned stwo_trace_value(
    const unsigned *const *trace_cols, const unsigned *interaction_offsets, unsigned row_count,
    unsigned log_n_rows, unsigned interaction, unsigned column, unsigned row_index, int offset
) {
    unsigned target_row;
    if (offset == 0) {
        target_row = row_index;
    } else {
        unsigned eval_log_size = 0u;
        unsigned tmp = row_count;
        while (tmp > 1u) { tmp >>= 1u; eval_log_size++; }
        target_row = stwo_offset_bit_reversed_circle_domain_index(
            row_index, log_n_rows, eval_log_size, offset);
    }
    unsigned global_column = interaction_offsets[interaction] + column;
    return trace_cols[global_column][target_row];
}

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_1c62c0df44ad2348(
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
    unsigned rc_base
) {
    unsigned row_index = blockIdx.x * blockDim.x + threadIdx.x;
    if (row_index >= row_count) { return; }

    // Canonical ext stream with demand-driven, versioned base cones.
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b58 = base_params[0u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b57, b58, b58, b58 };
    StwoCudaQm31 e1 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e0);
    e0 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    StwoCudaQm31 e2 = StwoCudaQm31{ b0, b58, b58, b58 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e0, e2);
    e2 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(ext_params, 2u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 1u, row_index, 0);
    e3 = StwoCudaQm31{ b1, b58, b58, b58 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 3u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 2u, row_index, 0);
    e0 = StwoCudaQm31{ b2, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 4u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 3u, row_index, 0);
    e3 = StwoCudaQm31{ b3, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 5u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 4u, row_index, 0);
    e0 = StwoCudaQm31{ b4, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 6u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 5u, row_index, 0);
    e3 = StwoCudaQm31{ b5, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 7u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 6u, row_index, 0);
    e0 = StwoCudaQm31{ b6, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 8u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 7u, row_index, 0);
    e3 = StwoCudaQm31{ b7, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 9u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 8u, row_index, 0);
    e0 = StwoCudaQm31{ b8, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 10u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 9u, row_index, 0);
    e3 = StwoCudaQm31{ b9, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 11u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 10u, row_index, 0);
    e0 = StwoCudaQm31{ b10, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 12u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 11u, row_index, 0);
    e3 = StwoCudaQm31{ b11, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 13u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 12u, row_index, 0);
    e0 = StwoCudaQm31{ b12, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 14u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 13u, row_index, 0);
    e3 = StwoCudaQm31{ b13, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 15u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 14u, row_index, 0);
    e0 = StwoCudaQm31{ b14, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 16u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 15u, row_index, 0);
    e3 = StwoCudaQm31{ b15, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 17u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 16u, row_index, 0);
    e0 = StwoCudaQm31{ b16, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 18u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 17u, row_index, 0);
    e3 = StwoCudaQm31{ b17, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 19u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 18u, row_index, 0);
    e0 = StwoCudaQm31{ b18, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 20u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 19u, row_index, 0);
    e3 = StwoCudaQm31{ b19, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 21u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 20u, row_index, 0);
    e0 = StwoCudaQm31{ b20, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 22u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 21u, row_index, 0);
    e3 = StwoCudaQm31{ b21, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 23u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 22u, row_index, 0);
    e0 = StwoCudaQm31{ b22, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 24u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 23u, row_index, 0);
    e3 = StwoCudaQm31{ b23, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 25u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 24u, row_index, 0);
    e0 = StwoCudaQm31{ b24, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 26u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 25u, row_index, 0);
    e3 = StwoCudaQm31{ b25, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 27u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 26u, row_index, 0);
    e0 = StwoCudaQm31{ b26, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 28u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 27u, row_index, 0);
    e3 = StwoCudaQm31{ b27, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 29u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 28u, row_index, 0);
    e0 = StwoCudaQm31{ b28, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 30u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 29u, row_index, 0);
    e3 = StwoCudaQm31{ b29, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 31u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 30u, row_index, 0);
    e0 = StwoCudaQm31{ b30, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 32u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 31u, row_index, 0);
    e3 = StwoCudaQm31{ b31, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 33u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 32u, row_index, 0);
    e0 = StwoCudaQm31{ b32, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 34u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 33u, row_index, 0);
    e3 = StwoCudaQm31{ b33, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 35u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 34u, row_index, 0);
    e0 = StwoCudaQm31{ b34, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 36u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 35u, row_index, 0);
    e3 = StwoCudaQm31{ b35, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 37u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 36u, row_index, 0);
    e0 = StwoCudaQm31{ b36, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 38u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 37u, row_index, 0);
    e3 = StwoCudaQm31{ b37, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 39u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 38u, row_index, 0);
    e0 = StwoCudaQm31{ b38, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 40u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 39u, row_index, 0);
    e3 = StwoCudaQm31{ b39, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 41u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 40u, row_index, 0);
    e0 = StwoCudaQm31{ b40, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 42u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 41u, row_index, 0);
    e3 = StwoCudaQm31{ b41, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 43u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 42u, row_index, 0);
    e0 = StwoCudaQm31{ b42, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 44u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 43u, row_index, 0);
    e3 = StwoCudaQm31{ b43, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 45u);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 44u, row_index, 0);
    e0 = StwoCudaQm31{ b44, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 46u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 45u, row_index, 0);
    e3 = StwoCudaQm31{ b45, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 47u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 46u, row_index, 0);
    e0 = StwoCudaQm31{ b46, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 48u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 47u, row_index, 0);
    e3 = StwoCudaQm31{ b47, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 49u);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 48u, row_index, 0);
    e0 = StwoCudaQm31{ b48, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 50u);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 49u, row_index, 0);
    e3 = StwoCudaQm31{ b49, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 51u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 50u, row_index, 0);
    e0 = StwoCudaQm31{ b50, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 52u);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 51u, row_index, 0);
    e3 = StwoCudaQm31{ b51, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 53u);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 52u, row_index, 0);
    e0 = StwoCudaQm31{ b52, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 54u);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 53u, row_index, 0);
    e3 = StwoCudaQm31{ b53, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 55u);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 54u, row_index, 0);
    e0 = StwoCudaQm31{ b54, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 56u);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 55u, row_index, 0);
    e3 = StwoCudaQm31{ b55, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 57u);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 56u, row_index, 0);
    e0 = StwoCudaQm31{ b56, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 58u);
    e3 = stwo_qm31_sub(e0, e2);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, -1);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, -1);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, -1);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, -1);
    e2 = StwoCudaQm31{ b59, b61, b63, b65 };
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e0 = StwoCudaQm31{ b60, b62, b64, b66 };
    e4 = stwo_qm31_sub(e0, e2);
    e0 = stwo_load_qm31(ext_params, 59u);
    e2 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e2, e3);
    e2 = stwo_qm31_sub(e0, e1);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
