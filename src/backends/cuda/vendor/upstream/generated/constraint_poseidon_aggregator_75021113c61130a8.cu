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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_0a98255da07f85f6(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b120 = base_params[0u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b0, b120, b120, b120 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 2u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    e2 = StwoCudaQm31{ b2, b120, b120, b120 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 3u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    e0 = StwoCudaQm31{ b3, b120, b120, b120 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 4u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    e2 = StwoCudaQm31{ b4, b120, b120, b120 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 5u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    e0 = StwoCudaQm31{ b5, b120, b120, b120 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 6u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    e2 = StwoCudaQm31{ b6, b120, b120, b120 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 7u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    e0 = StwoCudaQm31{ b7, b120, b120, b120 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 8u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    e2 = StwoCudaQm31{ b8, b120, b120, b120 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 9u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    e0 = StwoCudaQm31{ b9, b120, b120, b120 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 10u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    e2 = StwoCudaQm31{ b10, b120, b120, b120 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 11u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    e0 = StwoCudaQm31{ b11, b120, b120, b120 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 12u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    e2 = StwoCudaQm31{ b12, b120, b120, b120 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 13u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    e0 = StwoCudaQm31{ b13, b120, b120, b120 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 14u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    e2 = StwoCudaQm31{ b14, b120, b120, b120 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 15u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    e0 = StwoCudaQm31{ b15, b120, b120, b120 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 16u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    e2 = StwoCudaQm31{ b16, b120, b120, b120 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 17u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    e0 = StwoCudaQm31{ b17, b120, b120, b120 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 18u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    e2 = StwoCudaQm31{ b18, b120, b120, b120 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 19u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    e0 = StwoCudaQm31{ b19, b120, b120, b120 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 20u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    e2 = StwoCudaQm31{ b20, b120, b120, b120 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 21u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    e0 = StwoCudaQm31{ b21, b120, b120, b120 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 22u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    e2 = StwoCudaQm31{ b22, b120, b120, b120 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 23u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    e0 = StwoCudaQm31{ b23, b120, b120, b120 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 24u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    e2 = StwoCudaQm31{ b24, b120, b120, b120 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 25u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    e0 = StwoCudaQm31{ b25, b120, b120, b120 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 26u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    e2 = StwoCudaQm31{ b26, b120, b120, b120 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 27u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    e0 = StwoCudaQm31{ b27, b120, b120, b120 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 28u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    e2 = StwoCudaQm31{ b28, b120, b120, b120 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 29u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    e0 = StwoCudaQm31{ b29, b120, b120, b120 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 30u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 31u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e0 = StwoCudaQm31{ b1, b120, b120, b120 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 32u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 33u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    e3 = StwoCudaQm31{ b30, b120, b120, b120 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 34u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    e1 = StwoCudaQm31{ b31, b120, b120, b120 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 35u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    e3 = StwoCudaQm31{ b32, b120, b120, b120 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 36u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    e1 = StwoCudaQm31{ b33, b120, b120, b120 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 37u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    e3 = StwoCudaQm31{ b34, b120, b120, b120 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 38u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    e1 = StwoCudaQm31{ b35, b120, b120, b120 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 39u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    e3 = StwoCudaQm31{ b36, b120, b120, b120 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 40u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    e1 = StwoCudaQm31{ b37, b120, b120, b120 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 41u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    e3 = StwoCudaQm31{ b38, b120, b120, b120 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 42u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    e1 = StwoCudaQm31{ b39, b120, b120, b120 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 43u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    e3 = StwoCudaQm31{ b40, b120, b120, b120 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 44u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    e1 = StwoCudaQm31{ b41, b120, b120, b120 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 45u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    e3 = StwoCudaQm31{ b42, b120, b120, b120 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 46u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    e1 = StwoCudaQm31{ b43, b120, b120, b120 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 47u);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    e3 = StwoCudaQm31{ b44, b120, b120, b120 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 48u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    e1 = StwoCudaQm31{ b45, b120, b120, b120 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 49u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    e3 = StwoCudaQm31{ b46, b120, b120, b120 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 50u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    e1 = StwoCudaQm31{ b47, b120, b120, b120 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 51u);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    e3 = StwoCudaQm31{ b48, b120, b120, b120 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 52u);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    e1 = StwoCudaQm31{ b49, b120, b120, b120 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 53u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 54u, row_index, 0);
    e3 = StwoCudaQm31{ b50, b120, b120, b120 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 54u);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 55u, row_index, 0);
    e1 = StwoCudaQm31{ b51, b120, b120, b120 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 55u);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    e3 = StwoCudaQm31{ b52, b120, b120, b120 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 56u);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    e1 = StwoCudaQm31{ b53, b120, b120, b120 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 57u);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    e3 = StwoCudaQm31{ b54, b120, b120, b120 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 58u);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    e1 = StwoCudaQm31{ b55, b120, b120, b120 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 59u);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 60u, row_index, 0);
    e3 = StwoCudaQm31{ b56, b120, b120, b120 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 60u);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 61u, row_index, 0);
    e1 = StwoCudaQm31{ b57, b120, b120, b120 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 61u);
    e3 = stwo_qm31_sub(e1, e0);
    unsigned b121 = base_params[221u];
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 195u, row_index, 0);
    unsigned b122 = stwo_m31_mul(b121, b58);
    unsigned b123 = base_params[222u];
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 205u, row_index, 0);
    unsigned b124 = stwo_m31_mul(b123, b68);
    unsigned b125 = stwo_m31_add(b122, b124);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 215u, row_index, 0);
    unsigned b126 = stwo_m31_add(b125, b78);
    unsigned b127 = base_params[223u];
    unsigned b128 = stwo_m31_add(b126, b127);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 235u, row_index, 0);
    unsigned b129 = stwo_m31_sub(b128, b98);
    unsigned b108 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 245u, row_index, 0);
    unsigned b130 = stwo_m31_sub(b129, b108);
    unsigned b131 = base_params[224u];
    unsigned b132 = stwo_m31_mul(b130, b131);
    unsigned b133 = base_params[225u];
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 196u, row_index, 0);
    unsigned b134 = stwo_m31_mul(b133, b59);
    unsigned b135 = stwo_m31_add(b132, b134);
    unsigned b136 = base_params[226u];
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 206u, row_index, 0);
    unsigned b137 = stwo_m31_mul(b136, b69);
    unsigned b138 = stwo_m31_add(b135, b137);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 216u, row_index, 0);
    unsigned b139 = stwo_m31_add(b138, b79);
    unsigned b140 = base_params[227u];
    unsigned b141 = stwo_m31_add(b139, b140);
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 236u, row_index, 0);
    unsigned b142 = stwo_m31_sub(b141, b99);
    unsigned b143 = base_params[228u];
    unsigned b144 = stwo_m31_mul(b142, b143);
    unsigned b145 = base_params[229u];
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 197u, row_index, 0);
    unsigned b146 = stwo_m31_mul(b145, b60);
    unsigned b147 = stwo_m31_add(b144, b146);
    unsigned b148 = base_params[230u];
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 207u, row_index, 0);
    unsigned b149 = stwo_m31_mul(b148, b70);
    unsigned b150 = stwo_m31_add(b147, b149);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 217u, row_index, 0);
    unsigned b151 = stwo_m31_add(b150, b80);
    unsigned b152 = base_params[231u];
    unsigned b153 = stwo_m31_add(b151, b152);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 237u, row_index, 0);
    unsigned b154 = stwo_m31_sub(b153, b100);
    unsigned b155 = base_params[232u];
    unsigned b156 = stwo_m31_mul(b154, b155);
    unsigned b157 = base_params[233u];
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 198u, row_index, 0);
    unsigned b158 = stwo_m31_mul(b157, b61);
    unsigned b159 = stwo_m31_add(b156, b158);
    unsigned b160 = base_params[234u];
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 208u, row_index, 0);
    unsigned b161 = stwo_m31_mul(b160, b71);
    unsigned b162 = stwo_m31_add(b159, b161);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 218u, row_index, 0);
    unsigned b163 = stwo_m31_add(b162, b81);
    unsigned b164 = base_params[235u];
    unsigned b165 = stwo_m31_add(b163, b164);
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 238u, row_index, 0);
    unsigned b166 = stwo_m31_sub(b165, b101);
    unsigned b167 = base_params[236u];
    unsigned b168 = stwo_m31_mul(b166, b167);
    unsigned b169 = base_params[237u];
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 199u, row_index, 0);
    unsigned b170 = stwo_m31_mul(b169, b62);
    unsigned b171 = stwo_m31_add(b168, b170);
    unsigned b172 = base_params[238u];
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 209u, row_index, 0);
    unsigned b173 = stwo_m31_mul(b172, b72);
    unsigned b174 = stwo_m31_add(b171, b173);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 219u, row_index, 0);
    unsigned b175 = stwo_m31_add(b174, b82);
    unsigned b176 = base_params[239u];
    unsigned b177 = stwo_m31_add(b175, b176);
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 239u, row_index, 0);
    unsigned b178 = stwo_m31_sub(b177, b102);
    unsigned b179 = base_params[240u];
    unsigned b180 = stwo_m31_mul(b178, b179);
    unsigned b181 = base_params[241u];
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 200u, row_index, 0);
    unsigned b182 = stwo_m31_mul(b181, b63);
    unsigned b183 = stwo_m31_add(b180, b182);
    unsigned b184 = base_params[242u];
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 210u, row_index, 0);
    unsigned b185 = stwo_m31_mul(b184, b73);
    unsigned b186 = stwo_m31_add(b183, b185);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 220u, row_index, 0);
    unsigned b187 = stwo_m31_add(b186, b83);
    unsigned b188 = base_params[243u];
    unsigned b189 = stwo_m31_add(b187, b188);
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 240u, row_index, 0);
    unsigned b190 = stwo_m31_sub(b189, b103);
    unsigned b191 = base_params[244u];
    unsigned b192 = stwo_m31_mul(b190, b191);
    unsigned b193 = base_params[245u];
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 201u, row_index, 0);
    unsigned b194 = stwo_m31_mul(b193, b64);
    unsigned b195 = stwo_m31_add(b192, b194);
    unsigned b196 = base_params[246u];
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 211u, row_index, 0);
    unsigned b197 = stwo_m31_mul(b196, b74);
    unsigned b198 = stwo_m31_add(b195, b197);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 221u, row_index, 0);
    unsigned b199 = stwo_m31_add(b198, b84);
    unsigned b200 = base_params[247u];
    unsigned b201 = stwo_m31_add(b199, b200);
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 241u, row_index, 0);
    unsigned b202 = stwo_m31_sub(b201, b104);
    unsigned b203 = base_params[248u];
    unsigned b204 = stwo_m31_mul(b202, b203);
    unsigned b205 = base_params[249u];
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 202u, row_index, 0);
    unsigned b206 = stwo_m31_mul(b205, b65);
    unsigned b207 = stwo_m31_add(b204, b206);
    unsigned b208 = base_params[250u];
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 212u, row_index, 0);
    unsigned b209 = stwo_m31_mul(b208, b75);
    unsigned b210 = stwo_m31_add(b207, b209);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 222u, row_index, 0);
    unsigned b211 = stwo_m31_add(b210, b85);
    unsigned b212 = base_params[251u];
    unsigned b213 = stwo_m31_add(b211, b212);
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 242u, row_index, 0);
    unsigned b214 = stwo_m31_sub(b213, b105);
    unsigned b215 = base_params[252u];
    unsigned b216 = stwo_m31_mul(b108, b215);
    unsigned b217 = stwo_m31_sub(b214, b216);
    unsigned b218 = base_params[253u];
    unsigned b219 = stwo_m31_mul(b217, b218);
    unsigned b220 = base_params[254u];
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 203u, row_index, 0);
    unsigned b221 = stwo_m31_mul(b220, b66);
    unsigned b222 = stwo_m31_add(b219, b221);
    unsigned b223 = base_params[255u];
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 213u, row_index, 0);
    unsigned b224 = stwo_m31_mul(b223, b76);
    unsigned b225 = stwo_m31_add(b222, b224);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 223u, row_index, 0);
    unsigned b226 = stwo_m31_add(b225, b86);
    unsigned b227 = base_params[256u];
    unsigned b228 = stwo_m31_add(b226, b227);
    unsigned b106 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 243u, row_index, 0);
    unsigned b229 = stwo_m31_sub(b228, b106);
    unsigned b230 = base_params[257u];
    unsigned b231 = stwo_m31_mul(b229, b230);
    unsigned b232 = base_params[258u];
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 204u, row_index, 0);
    unsigned b233 = stwo_m31_mul(b232, b67);
    unsigned b234 = stwo_m31_add(b231, b233);
    unsigned b235 = base_params[259u];
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 214u, row_index, 0);
    unsigned b236 = stwo_m31_mul(b235, b77);
    unsigned b237 = stwo_m31_add(b234, b236);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 224u, row_index, 0);
    unsigned b238 = stwo_m31_add(b237, b87);
    unsigned b239 = base_params[260u];
    unsigned b240 = stwo_m31_add(b238, b239);
    unsigned b107 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 244u, row_index, 0);
    unsigned b241 = stwo_m31_sub(b240, b107);
    unsigned b242 = base_params[261u];
    unsigned b243 = stwo_m31_mul(b108, b242);
    unsigned b244 = stwo_m31_sub(b241, b243);
    e0 = StwoCudaQm31{ b244, b120, b120, b120 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b245 = base_params[272u];
    unsigned b246 = stwo_m31_mul(b245, b78);
    unsigned b247 = base_params[273u];
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 225u, row_index, 0);
    unsigned b248 = stwo_m31_mul(b247, b88);
    unsigned b249 = stwo_m31_add(b246, b248);
    unsigned b250 = stwo_m31_add(b249, b98);
    unsigned b251 = base_params[274u];
    unsigned b252 = stwo_m31_add(b250, b251);
    unsigned b109 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 246u, row_index, 0);
    unsigned b253 = stwo_m31_sub(b252, b109);
    unsigned b119 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 256u, row_index, 0);
    unsigned b254 = stwo_m31_sub(b253, b119);
    unsigned b255 = base_params[275u];
    unsigned b256 = stwo_m31_mul(b254, b255);
    unsigned b257 = base_params[276u];
    unsigned b258 = stwo_m31_mul(b257, b79);
    unsigned b259 = stwo_m31_add(b256, b258);
    unsigned b260 = base_params[277u];
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 226u, row_index, 0);
    unsigned b261 = stwo_m31_mul(b260, b89);
    unsigned b262 = stwo_m31_add(b259, b261);
    unsigned b263 = stwo_m31_add(b262, b99);
    unsigned b264 = base_params[278u];
    unsigned b265 = stwo_m31_add(b263, b264);
    unsigned b110 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 247u, row_index, 0);
    unsigned b266 = stwo_m31_sub(b265, b110);
    unsigned b267 = base_params[279u];
    unsigned b268 = stwo_m31_mul(b266, b267);
    unsigned b269 = base_params[280u];
    unsigned b270 = stwo_m31_mul(b269, b80);
    unsigned b271 = stwo_m31_add(b268, b270);
    unsigned b272 = base_params[281u];
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 227u, row_index, 0);
    unsigned b273 = stwo_m31_mul(b272, b90);
    unsigned b274 = stwo_m31_add(b271, b273);
    unsigned b275 = stwo_m31_add(b274, b100);
    unsigned b276 = base_params[282u];
    unsigned b277 = stwo_m31_add(b275, b276);
    unsigned b111 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 248u, row_index, 0);
    unsigned b278 = stwo_m31_sub(b277, b111);
    unsigned b279 = base_params[283u];
    unsigned b280 = stwo_m31_mul(b278, b279);
    unsigned b281 = base_params[284u];
    unsigned b282 = stwo_m31_mul(b281, b81);
    unsigned b283 = stwo_m31_add(b280, b282);
    unsigned b284 = base_params[285u];
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 228u, row_index, 0);
    unsigned b285 = stwo_m31_mul(b284, b91);
    unsigned b286 = stwo_m31_add(b283, b285);
    unsigned b287 = stwo_m31_add(b286, b101);
    unsigned b288 = base_params[286u];
    unsigned b289 = stwo_m31_add(b287, b288);
    unsigned b112 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 249u, row_index, 0);
    unsigned b290 = stwo_m31_sub(b289, b112);
    unsigned b291 = base_params[287u];
    unsigned b292 = stwo_m31_mul(b290, b291);
    unsigned b293 = base_params[288u];
    unsigned b294 = stwo_m31_mul(b293, b82);
    unsigned b295 = stwo_m31_add(b292, b294);
    unsigned b296 = base_params[289u];
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 229u, row_index, 0);
    unsigned b297 = stwo_m31_mul(b296, b92);
    unsigned b298 = stwo_m31_add(b295, b297);
    unsigned b299 = stwo_m31_add(b298, b102);
    unsigned b300 = base_params[290u];
    unsigned b301 = stwo_m31_add(b299, b300);
    unsigned b113 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 250u, row_index, 0);
    unsigned b302 = stwo_m31_sub(b301, b113);
    unsigned b303 = base_params[291u];
    unsigned b304 = stwo_m31_mul(b302, b303);
    unsigned b305 = base_params[292u];
    unsigned b306 = stwo_m31_mul(b305, b83);
    unsigned b307 = stwo_m31_add(b304, b306);
    unsigned b308 = base_params[293u];
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 230u, row_index, 0);
    unsigned b309 = stwo_m31_mul(b308, b93);
    unsigned b310 = stwo_m31_add(b307, b309);
    unsigned b311 = stwo_m31_add(b310, b103);
    unsigned b312 = base_params[294u];
    unsigned b313 = stwo_m31_add(b311, b312);
    unsigned b114 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 251u, row_index, 0);
    unsigned b314 = stwo_m31_sub(b313, b114);
    unsigned b315 = base_params[295u];
    unsigned b316 = stwo_m31_mul(b314, b315);
    unsigned b317 = base_params[296u];
    unsigned b318 = stwo_m31_mul(b317, b84);
    unsigned b319 = stwo_m31_add(b316, b318);
    unsigned b320 = base_params[297u];
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 231u, row_index, 0);
    unsigned b321 = stwo_m31_mul(b320, b94);
    unsigned b322 = stwo_m31_add(b319, b321);
    unsigned b323 = stwo_m31_add(b322, b104);
    unsigned b324 = base_params[298u];
    unsigned b325 = stwo_m31_add(b323, b324);
    unsigned b115 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 252u, row_index, 0);
    unsigned b326 = stwo_m31_sub(b325, b115);
    unsigned b327 = base_params[299u];
    unsigned b328 = stwo_m31_mul(b326, b327);
    unsigned b329 = base_params[300u];
    unsigned b330 = stwo_m31_mul(b329, b85);
    unsigned b331 = stwo_m31_add(b328, b330);
    unsigned b332 = base_params[301u];
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 232u, row_index, 0);
    unsigned b333 = stwo_m31_mul(b332, b95);
    unsigned b334 = stwo_m31_add(b331, b333);
    unsigned b335 = stwo_m31_add(b334, b105);
    unsigned b336 = base_params[302u];
    unsigned b337 = stwo_m31_add(b335, b336);
    unsigned b116 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 253u, row_index, 0);
    unsigned b338 = stwo_m31_sub(b337, b116);
    unsigned b339 = base_params[303u];
    unsigned b340 = stwo_m31_mul(b119, b339);
    unsigned b341 = stwo_m31_sub(b338, b340);
    unsigned b342 = base_params[304u];
    unsigned b343 = stwo_m31_mul(b341, b342);
    unsigned b344 = base_params[305u];
    unsigned b345 = stwo_m31_mul(b344, b86);
    unsigned b346 = stwo_m31_add(b343, b345);
    unsigned b347 = base_params[306u];
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 233u, row_index, 0);
    unsigned b348 = stwo_m31_mul(b347, b96);
    unsigned b349 = stwo_m31_add(b346, b348);
    unsigned b350 = stwo_m31_add(b349, b106);
    unsigned b351 = base_params[307u];
    unsigned b352 = stwo_m31_add(b350, b351);
    unsigned b117 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 254u, row_index, 0);
    unsigned b353 = stwo_m31_sub(b352, b117);
    unsigned b354 = base_params[308u];
    unsigned b355 = stwo_m31_mul(b353, b354);
    unsigned b356 = base_params[309u];
    unsigned b357 = stwo_m31_mul(b356, b87);
    unsigned b358 = stwo_m31_add(b355, b357);
    unsigned b359 = base_params[310u];
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 234u, row_index, 0);
    unsigned b360 = stwo_m31_mul(b359, b97);
    unsigned b361 = stwo_m31_add(b358, b360);
    unsigned b362 = stwo_m31_add(b361, b107);
    unsigned b363 = base_params[311u];
    unsigned b364 = stwo_m31_add(b362, b363);
    unsigned b118 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 255u, row_index, 0);
    unsigned b365 = stwo_m31_sub(b364, b118);
    unsigned b366 = base_params[312u];
    unsigned b367 = stwo_m31_mul(b119, b366);
    unsigned b368 = stwo_m31_sub(b365, b367);
    e1 = StwoCudaQm31{ b368, b120, b120, b120 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    e4 = stwo_load_qm31(ext_params, 548u);
    StwoCudaQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_load_qm31(ext_params, 549u);
    StwoCudaQm31 e6 = stwo_qm31_mul(e2, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_qm31_mul(e2, e3);
    unsigned b369 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b370 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b371 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b372 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e3 = StwoCudaQm31{ b369, b370, b371, b372 };
    e2 = stwo_qm31_mul(e3, e6);
    e3 = stwo_qm31_sub(e2, e4);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
