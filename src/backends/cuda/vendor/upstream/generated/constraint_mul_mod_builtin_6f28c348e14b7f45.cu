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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_9e873fe0862ae09b(
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
    unsigned b97 = base_params[4u];
    unsigned b95 = base_params[3u];
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    unsigned b96 = stwo_m31_mul(b95, b0);
    unsigned b98 = stwo_m31_add(b97, b96);
    unsigned b94 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b98, b94, b94, b94 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 2u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e2 = StwoCudaQm31{ b1, b94, b94, b94 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 3u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 4u);
    e2 = StwoCudaQm31{ b1, b94, b94, b94 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 5u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 6u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    e1 = StwoCudaQm31{ b2, b94, b94, b94 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 7u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e3 = StwoCudaQm31{ b3, b94, b94, b94 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 8u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e1 = StwoCudaQm31{ b4, b94, b94, b94 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 9u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e3 = StwoCudaQm31{ b5, b94, b94, b94 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 10u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    e1 = StwoCudaQm31{ b6, b94, b94, b94 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 11u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    e3 = StwoCudaQm31{ b7, b94, b94, b94 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 12u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    e1 = StwoCudaQm31{ b8, b94, b94, b94 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 13u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    e3 = StwoCudaQm31{ b9, b94, b94, b94 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 14u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    e1 = StwoCudaQm31{ b10, b94, b94, b94 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 15u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    e3 = StwoCudaQm31{ b11, b94, b94, b94 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 16u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    e1 = StwoCudaQm31{ b12, b94, b94, b94 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 17u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 18u);
    unsigned b99 = base_params[6u];
    unsigned b100 = stwo_m31_add(b98, b99);
    e1 = StwoCudaQm31{ b100, b94, b94, b94 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 19u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 20u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    e2 = StwoCudaQm31{ b13, b94, b94, b94 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 21u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(ext_params, 22u);
    e2 = StwoCudaQm31{ b13, b94, b94, b94 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(ext_params, 23u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 24u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    e1 = StwoCudaQm31{ b14, b94, b94, b94 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 25u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    e5 = StwoCudaQm31{ b15, b94, b94, b94 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 26u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    e1 = StwoCudaQm31{ b16, b94, b94, b94 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 27u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    e5 = StwoCudaQm31{ b17, b94, b94, b94 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 28u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    e1 = StwoCudaQm31{ b18, b94, b94, b94 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 29u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    e5 = StwoCudaQm31{ b19, b94, b94, b94 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 30u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    e1 = StwoCudaQm31{ b20, b94, b94, b94 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 31u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    e5 = StwoCudaQm31{ b21, b94, b94, b94 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 32u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    e1 = StwoCudaQm31{ b22, b94, b94, b94 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 33u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    e5 = StwoCudaQm31{ b23, b94, b94, b94 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 34u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    e1 = StwoCudaQm31{ b24, b94, b94, b94 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 35u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(ext_params, 36u);
    unsigned b101 = base_params[7u];
    unsigned b102 = stwo_m31_add(b98, b101);
    e1 = StwoCudaQm31{ b102, b94, b94, b94 };
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(ext_params, 37u);
    e6 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 38u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    e2 = StwoCudaQm31{ b25, b94, b94, b94 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 39u);
    e6 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(ext_params, 40u);
    e2 = StwoCudaQm31{ b25, b94, b94, b94 };
    e1 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(ext_params, 41u);
    e7 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 42u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    e1 = StwoCudaQm31{ b26, b94, b94, b94 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 43u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    e7 = StwoCudaQm31{ b27, b94, b94, b94 };
    e2 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 44u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    e1 = StwoCudaQm31{ b28, b94, b94, b94 };
    e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 45u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    e7 = StwoCudaQm31{ b29, b94, b94, b94 };
    e2 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 46u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    e1 = StwoCudaQm31{ b30, b94, b94, b94 };
    e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 47u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    e7 = StwoCudaQm31{ b31, b94, b94, b94 };
    e2 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 48u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    e1 = StwoCudaQm31{ b32, b94, b94, b94 };
    e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 49u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    e7 = StwoCudaQm31{ b33, b94, b94, b94 };
    e2 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 50u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    e1 = StwoCudaQm31{ b34, b94, b94, b94 };
    e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 51u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    e7 = StwoCudaQm31{ b35, b94, b94, b94 };
    e2 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 52u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    e1 = StwoCudaQm31{ b36, b94, b94, b94 };
    e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 53u);
    e7 = stwo_qm31_sub(e1, e8);
    e8 = stwo_load_qm31(ext_params, 54u);
    unsigned b103 = base_params[8u];
    unsigned b104 = stwo_m31_add(b98, b103);
    e1 = StwoCudaQm31{ b104, b94, b94, b94 };
    e2 = stwo_qm31_mul(e8, e1);
    e1 = stwo_load_qm31(ext_params, 55u);
    e8 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 56u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    e2 = StwoCudaQm31{ b37, b94, b94, b94 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 57u);
    e8 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(ext_params, 58u);
    e2 = StwoCudaQm31{ b37, b94, b94, b94 };
    e1 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(ext_params, 59u);
    e9 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 60u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    e1 = StwoCudaQm31{ b38, b94, b94, b94 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 61u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    e9 = StwoCudaQm31{ b39, b94, b94, b94 };
    e2 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 62u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    e1 = StwoCudaQm31{ b40, b94, b94, b94 };
    e10 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 63u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    e9 = StwoCudaQm31{ b41, b94, b94, b94 };
    e2 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 64u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    e1 = StwoCudaQm31{ b42, b94, b94, b94 };
    e10 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 65u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    e9 = StwoCudaQm31{ b43, b94, b94, b94 };
    e2 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 66u);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    e1 = StwoCudaQm31{ b44, b94, b94, b94 };
    e10 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 67u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    e9 = StwoCudaQm31{ b45, b94, b94, b94 };
    e2 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 68u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    e1 = StwoCudaQm31{ b46, b94, b94, b94 };
    e10 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 69u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    e9 = StwoCudaQm31{ b47, b94, b94, b94 };
    e2 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 70u);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    e1 = StwoCudaQm31{ b48, b94, b94, b94 };
    e10 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 71u);
    e9 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(ext_params, 72u);
    unsigned b105 = base_params[9u];
    unsigned b106 = stwo_m31_add(b98, b105);
    e1 = StwoCudaQm31{ b106, b94, b94, b94 };
    e2 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(ext_params, 73u);
    e10 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 74u);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    e2 = StwoCudaQm31{ b49, b94, b94, b94 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 75u);
    e10 = stwo_qm31_sub(e2, e11);
    e11 = stwo_load_qm31(ext_params, 76u);
    e2 = StwoCudaQm31{ b49, b94, b94, b94 };
    e1 = stwo_qm31_mul(e11, e2);
    e2 = stwo_load_qm31(ext_params, 77u);
    e11 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 78u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    e1 = StwoCudaQm31{ b50, b94, b94, b94 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 79u);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    e11 = StwoCudaQm31{ b51, b94, b94, b94 };
    e2 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 80u);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    e1 = StwoCudaQm31{ b52, b94, b94, b94 };
    e12 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 81u);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    e11 = StwoCudaQm31{ b53, b94, b94, b94 };
    e2 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 82u);
    e1 = stwo_qm31_sub(e11, e2);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 421u, row_index, 0);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 420u, row_index, 0);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 320u, row_index, 0);
    unsigned b143 = base_params[217u];
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 148u, row_index, 0);
    unsigned b144 = stwo_m31_mul(b143, b54);
    unsigned b145 = stwo_m31_add(b80, b144);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 343u, row_index, 0);
    unsigned b185 = base_params[274u];
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 203u, row_index, 0);
    unsigned b186 = stwo_m31_mul(b185, b69);
    unsigned b187 = stwo_m31_add(b87, b186);
    unsigned b188 = stwo_m31_mul(b145, b187);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 149u, row_index, 0);
    unsigned b146 = base_params[218u];
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 150u, row_index, 0);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 321u, row_index, 0);
    unsigned b134 = base_params[204u];
    unsigned b135 = stwo_m31_mul(b81, b134);
    unsigned b136 = stwo_m31_sub(b56, b135);
    unsigned b147 = stwo_m31_mul(b146, b136);
    unsigned b148 = stwo_m31_add(b55, b147);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 201u, row_index, 0);
    unsigned b182 = base_params[273u];
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 202u, row_index, 0);
    unsigned b167 = base_params[258u];
    unsigned b168 = stwo_m31_mul(b87, b167);
    unsigned b169 = stwo_m31_sub(b68, b168);
    unsigned b183 = stwo_m31_mul(b182, b169);
    unsigned b184 = stwo_m31_add(b67, b183);
    unsigned b189 = stwo_m31_mul(b148, b184);
    unsigned b190 = stwo_m31_add(b188, b189);
    unsigned b149 = base_params[219u];
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 151u, row_index, 0);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 322u, row_index, 0);
    unsigned b137 = base_params[205u];
    unsigned b138 = stwo_m31_mul(b82, b137);
    unsigned b139 = stwo_m31_sub(b57, b138);
    unsigned b150 = stwo_m31_mul(b149, b139);
    unsigned b151 = stwo_m31_add(b81, b150);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 342u, row_index, 0);
    unsigned b179 = base_params[272u];
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 200u, row_index, 0);
    unsigned b180 = stwo_m31_mul(b179, b66);
    unsigned b181 = stwo_m31_add(b86, b180);
    unsigned b191 = stwo_m31_mul(b151, b181);
    unsigned b192 = stwo_m31_add(b190, b191);
    unsigned b152 = base_params[220u];
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 152u, row_index, 0);
    unsigned b153 = stwo_m31_mul(b152, b58);
    unsigned b154 = stwo_m31_add(b82, b153);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 341u, row_index, 0);
    unsigned b176 = base_params[271u];
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 199u, row_index, 0);
    unsigned b164 = base_params[257u];
    unsigned b165 = stwo_m31_mul(b86, b164);
    unsigned b166 = stwo_m31_sub(b65, b165);
    unsigned b177 = stwo_m31_mul(b176, b166);
    unsigned b178 = stwo_m31_add(b85, b177);
    unsigned b193 = stwo_m31_mul(b154, b178);
    unsigned b194 = stwo_m31_add(b192, b193);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 153u, row_index, 0);
    unsigned b155 = base_params[221u];
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 154u, row_index, 0);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 323u, row_index, 0);
    unsigned b140 = base_params[206u];
    unsigned b141 = stwo_m31_mul(b83, b140);
    unsigned b142 = stwo_m31_sub(b60, b141);
    unsigned b156 = stwo_m31_mul(b155, b142);
    unsigned b157 = stwo_m31_add(b59, b156);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 197u, row_index, 0);
    unsigned b173 = base_params[270u];
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 198u, row_index, 0);
    unsigned b161 = base_params[256u];
    unsigned b162 = stwo_m31_mul(b85, b161);
    unsigned b163 = stwo_m31_sub(b64, b162);
    unsigned b174 = stwo_m31_mul(b173, b163);
    unsigned b175 = stwo_m31_add(b63, b174);
    unsigned b195 = stwo_m31_mul(b157, b175);
    unsigned b196 = stwo_m31_add(b194, b195);
    unsigned b158 = base_params[222u];
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 155u, row_index, 0);
    unsigned b159 = stwo_m31_mul(b158, b61);
    unsigned b160 = stwo_m31_add(b83, b159);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 340u, row_index, 0);
    unsigned b170 = base_params[269u];
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 196u, row_index, 0);
    unsigned b171 = stwo_m31_mul(b170, b62);
    unsigned b172 = stwo_m31_add(b84, b171);
    unsigned b197 = stwo_m31_mul(b160, b172);
    unsigned b198 = stwo_m31_add(b196, b197);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 278u, row_index, 0);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 303u, row_index, 0);
    unsigned b131 = base_params[170u];
    unsigned b132 = stwo_m31_mul(b131, b48);
    unsigned b133 = stwo_m31_add(b79, b132);
    unsigned b224 = stwo_m31_mul(b70, b133);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 279u, row_index, 0);
    unsigned b128 = base_params[169u];
    unsigned b113 = base_params[154u];
    unsigned b114 = stwo_m31_mul(b79, b113);
    unsigned b115 = stwo_m31_sub(b47, b114);
    unsigned b129 = stwo_m31_mul(b128, b115);
    unsigned b130 = stwo_m31_add(b46, b129);
    unsigned b225 = stwo_m31_mul(b71, b130);
    unsigned b226 = stwo_m31_add(b224, b225);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 280u, row_index, 0);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 302u, row_index, 0);
    unsigned b125 = base_params[168u];
    unsigned b126 = stwo_m31_mul(b125, b45);
    unsigned b127 = stwo_m31_add(b78, b126);
    unsigned b227 = stwo_m31_mul(b72, b127);
    unsigned b228 = stwo_m31_add(b226, b227);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 281u, row_index, 0);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 301u, row_index, 0);
    unsigned b122 = base_params[167u];
    unsigned b110 = base_params[153u];
    unsigned b111 = stwo_m31_mul(b78, b110);
    unsigned b112 = stwo_m31_sub(b44, b111);
    unsigned b123 = stwo_m31_mul(b122, b112);
    unsigned b124 = stwo_m31_add(b77, b123);
    unsigned b229 = stwo_m31_mul(b73, b124);
    unsigned b230 = stwo_m31_add(b228, b229);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 282u, row_index, 0);
    unsigned b119 = base_params[166u];
    unsigned b107 = base_params[152u];
    unsigned b108 = stwo_m31_mul(b77, b107);
    unsigned b109 = stwo_m31_sub(b43, b108);
    unsigned b120 = stwo_m31_mul(b119, b109);
    unsigned b121 = stwo_m31_add(b42, b120);
    unsigned b231 = stwo_m31_mul(b74, b121);
    unsigned b232 = stwo_m31_add(b230, b231);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 283u, row_index, 0);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 300u, row_index, 0);
    unsigned b116 = base_params[165u];
    unsigned b117 = stwo_m31_mul(b116, b41);
    unsigned b118 = stwo_m31_add(b76, b117);
    unsigned b233 = stwo_m31_mul(b75, b118);
    unsigned b234 = stwo_m31_add(b232, b233);
    unsigned b260 = stwo_m31_sub(b198, b234);
    unsigned b261 = stwo_m31_add(b88, b260);
    unsigned b262 = base_params[442u];
    unsigned b263 = stwo_m31_mul(b261, b262);
    unsigned b264 = stwo_m31_sub(b89, b263);
    e2 = StwoCudaQm31{ b264, b94, b94, b94 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 422u, row_index, 0);
    unsigned b199 = stwo_m31_mul(b148, b187);
    unsigned b200 = stwo_m31_mul(b151, b184);
    unsigned b201 = stwo_m31_add(b199, b200);
    unsigned b202 = stwo_m31_mul(b154, b181);
    unsigned b203 = stwo_m31_add(b201, b202);
    unsigned b204 = stwo_m31_mul(b157, b178);
    unsigned b205 = stwo_m31_add(b203, b204);
    unsigned b206 = stwo_m31_mul(b160, b175);
    unsigned b207 = stwo_m31_add(b205, b206);
    unsigned b235 = stwo_m31_mul(b71, b133);
    unsigned b236 = stwo_m31_mul(b72, b130);
    unsigned b237 = stwo_m31_add(b235, b236);
    unsigned b238 = stwo_m31_mul(b73, b127);
    unsigned b239 = stwo_m31_add(b237, b238);
    unsigned b240 = stwo_m31_mul(b74, b124);
    unsigned b241 = stwo_m31_add(b239, b240);
    unsigned b242 = stwo_m31_mul(b75, b121);
    unsigned b243 = stwo_m31_add(b241, b242);
    unsigned b265 = stwo_m31_sub(b207, b243);
    unsigned b266 = stwo_m31_add(b89, b265);
    unsigned b267 = base_params[444u];
    unsigned b268 = stwo_m31_mul(b266, b267);
    unsigned b269 = stwo_m31_sub(b90, b268);
    e11 = StwoCudaQm31{ b269, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 423u, row_index, 0);
    unsigned b208 = stwo_m31_mul(b151, b187);
    unsigned b209 = stwo_m31_mul(b154, b184);
    unsigned b210 = stwo_m31_add(b208, b209);
    unsigned b211 = stwo_m31_mul(b157, b181);
    unsigned b212 = stwo_m31_add(b210, b211);
    unsigned b213 = stwo_m31_mul(b160, b178);
    unsigned b214 = stwo_m31_add(b212, b213);
    unsigned b244 = stwo_m31_mul(b72, b133);
    unsigned b245 = stwo_m31_mul(b73, b130);
    unsigned b246 = stwo_m31_add(b244, b245);
    unsigned b247 = stwo_m31_mul(b74, b127);
    unsigned b248 = stwo_m31_add(b246, b247);
    unsigned b249 = stwo_m31_mul(b75, b124);
    unsigned b250 = stwo_m31_add(b248, b249);
    unsigned b270 = stwo_m31_sub(b214, b250);
    unsigned b271 = stwo_m31_add(b90, b270);
    unsigned b272 = base_params[446u];
    unsigned b273 = stwo_m31_mul(b271, b272);
    unsigned b274 = stwo_m31_sub(b91, b273);
    e12 = StwoCudaQm31{ b274, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 424u, row_index, 0);
    unsigned b215 = stwo_m31_mul(b154, b187);
    unsigned b216 = stwo_m31_mul(b157, b184);
    unsigned b217 = stwo_m31_add(b215, b216);
    unsigned b218 = stwo_m31_mul(b160, b181);
    unsigned b219 = stwo_m31_add(b217, b218);
    unsigned b251 = stwo_m31_mul(b73, b133);
    unsigned b252 = stwo_m31_mul(b74, b130);
    unsigned b253 = stwo_m31_add(b251, b252);
    unsigned b254 = stwo_m31_mul(b75, b127);
    unsigned b255 = stwo_m31_add(b253, b254);
    unsigned b275 = stwo_m31_sub(b219, b255);
    unsigned b276 = stwo_m31_add(b91, b275);
    unsigned b277 = base_params[448u];
    unsigned b278 = stwo_m31_mul(b276, b277);
    unsigned b279 = stwo_m31_sub(b92, b278);
    StwoCudaQm31 e13 = StwoCudaQm31{ b279, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 425u, row_index, 0);
    unsigned b220 = stwo_m31_mul(b157, b187);
    unsigned b221 = stwo_m31_mul(b160, b184);
    unsigned b222 = stwo_m31_add(b220, b221);
    unsigned b256 = stwo_m31_mul(b74, b133);
    unsigned b257 = stwo_m31_mul(b75, b130);
    unsigned b258 = stwo_m31_add(b256, b257);
    unsigned b280 = stwo_m31_sub(b222, b258);
    unsigned b281 = stwo_m31_add(b92, b280);
    unsigned b282 = base_params[450u];
    unsigned b283 = stwo_m31_mul(b281, b282);
    unsigned b284 = stwo_m31_sub(b93, b283);
    StwoCudaQm31 e14 = StwoCudaQm31{ b284, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b223 = stwo_m31_mul(b160, b187);
    unsigned b285 = stwo_m31_add(b223, b93);
    unsigned b259 = stwo_m31_mul(b75, b133);
    unsigned b286 = stwo_m31_sub(b285, b259);
    StwoCudaQm31 e15 = StwoCudaQm31{ b286, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    StwoCudaQm31 e16 = stwo_load_qm31(ext_params, 990u);
    StwoCudaQm31 e17 = stwo_qm31_mul(e3, e16);
    e16 = stwo_load_qm31(ext_params, 991u);
    StwoCudaQm31 e18 = stwo_qm31_mul(e0, e16);
    e16 = stwo_qm31_add(e17, e18);
    e18 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(ext_params, 992u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 993u);
    e17 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e17);
    e17 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 994u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 995u);
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 996u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(ext_params, 997u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 998u);
    e8 = stwo_qm31_mul(e1, e9);
    e9 = stwo_load_qm31(ext_params, 999u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e1);
    unsigned b287 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b288 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b289 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b290 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e1 = StwoCudaQm31{ b287, b288, b289, b290 };
    e10 = stwo_qm31_mul(e1, e18);
    e18 = stwo_qm31_sub(e10, e16);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b291 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b292 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b293 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b294 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e10 = StwoCudaQm31{ b291, b292, b293, b294 };
    e16 = stwo_qm31_sub(e10, e1);
    e1 = stwo_qm31_mul(e16, e17);
    e16 = stwo_qm31_sub(e1, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b295 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b296 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b297 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b298 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e1 = StwoCudaQm31{ b295, b296, b297, b298 };
    e3 = stwo_qm31_sub(e1, e10);
    e10 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e10, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b299 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b300 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b301 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b302 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e10 = StwoCudaQm31{ b299, b300, b301, b302 };
    e5 = stwo_qm31_sub(e10, e1);
    e1 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e1, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b303 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, 0);
    unsigned b304 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, 0);
    unsigned b305 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, 0);
    unsigned b306 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, 0);
    e1 = StwoCudaQm31{ b303, b304, b305, b306 };
    e7 = stwo_qm31_sub(e1, e10);
    e1 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e1, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
