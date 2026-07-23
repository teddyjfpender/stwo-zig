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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_08d658a9bfd43f4a(
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
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b21 = base_params[0u];
    unsigned b22 = stwo_m31_mul(b6, b21);
    unsigned b23 = stwo_m31_sub(b0, b22);
    unsigned b39 = base_params[6u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b23, b39, b39, b39 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 2u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b27 = base_params[2u];
    unsigned b28 = stwo_m31_mul(b8, b27);
    unsigned b29 = stwo_m31_sub(b2, b28);
    e2 = StwoCudaQm31{ b29, b39, b39, b39 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 3u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    e0 = StwoCudaQm31{ b12, b39, b39, b39 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 5u);
    e0 = StwoCudaQm31{ b12, b39, b39, b39 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 6u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 7u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b33 = base_params[4u];
    unsigned b34 = stwo_m31_mul(b10, b33);
    unsigned b35 = stwo_m31_sub(b4, b34);
    e3 = StwoCudaQm31{ b35, b39, b39, b39 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 8u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    e1 = StwoCudaQm31{ b13, b39, b39, b39 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 9u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 10u);
    e1 = StwoCudaQm31{ b6, b39, b39, b39 };
    e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 11u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(ext_params, 12u);
    e4 = StwoCudaQm31{ b8, b39, b39, b39 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 13u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    e0 = StwoCudaQm31{ b14, b39, b39, b39 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(ext_params, 14u);
    e4 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 15u);
    e0 = StwoCudaQm31{ b14, b39, b39, b39 };
    e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 16u);
    e1 = stwo_qm31_add(e0, e5);
    e0 = stwo_load_qm31(ext_params, 17u);
    e5 = StwoCudaQm31{ b10, b39, b39, b39 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e0, e5);
    e5 = stwo_qm31_add(e1, e6);
    e6 = stwo_load_qm31(ext_params, 18u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    e1 = StwoCudaQm31{ b15, b39, b39, b39 };
    e0 = stwo_qm31_mul(e6, e1);
    e1 = stwo_qm31_add(e5, e0);
    e0 = stwo_load_qm31(ext_params, 19u);
    e5 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 20u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b24 = base_params[1u];
    unsigned b25 = stwo_m31_mul(b7, b24);
    unsigned b26 = stwo_m31_sub(b1, b25);
    e1 = StwoCudaQm31{ b26, b39, b39, b39 };
    e6 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 21u);
    e0 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(ext_params, 22u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b30 = base_params[3u];
    unsigned b31 = stwo_m31_mul(b9, b30);
    unsigned b32 = stwo_m31_sub(b3, b31);
    e6 = StwoCudaQm31{ b32, b39, b39, b39 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e0, e7);
    e7 = stwo_load_qm31(ext_params, 23u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    e0 = StwoCudaQm31{ b16, b39, b39, b39 };
    e1 = stwo_qm31_mul(e7, e0);
    e0 = stwo_qm31_add(e6, e1);
    e1 = stwo_load_qm31(ext_params, 24u);
    e6 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 25u);
    e0 = StwoCudaQm31{ b16, b39, b39, b39 };
    e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 26u);
    e1 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(ext_params, 27u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b36 = base_params[5u];
    unsigned b37 = stwo_m31_mul(b11, b36);
    unsigned b38 = stwo_m31_sub(b5, b37);
    e7 = StwoCudaQm31{ b38, b39, b39, b39 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e0, e7);
    e7 = stwo_qm31_add(e1, e8);
    e8 = stwo_load_qm31(ext_params, 28u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    e1 = StwoCudaQm31{ b17, b39, b39, b39 };
    e0 = stwo_qm31_mul(e8, e1);
    e1 = stwo_qm31_add(e7, e0);
    e0 = stwo_load_qm31(ext_params, 29u);
    e7 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 30u);
    e1 = StwoCudaQm31{ b7, b39, b39, b39 };
    e8 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 31u);
    e0 = stwo_qm31_add(e1, e8);
    e1 = stwo_load_qm31(ext_params, 32u);
    e8 = StwoCudaQm31{ b9, b39, b39, b39 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e1, e8);
    e8 = stwo_qm31_add(e0, e9);
    e9 = stwo_load_qm31(ext_params, 33u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    e0 = StwoCudaQm31{ b18, b39, b39, b39 };
    e1 = stwo_qm31_mul(e9, e0);
    e0 = stwo_qm31_add(e8, e1);
    e1 = stwo_load_qm31(ext_params, 34u);
    e8 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 35u);
    e0 = StwoCudaQm31{ b18, b39, b39, b39 };
    e9 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 36u);
    e1 = stwo_qm31_add(e0, e9);
    e0 = stwo_load_qm31(ext_params, 37u);
    e9 = StwoCudaQm31{ b11, b39, b39, b39 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(ext_params, 38u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    e1 = StwoCudaQm31{ b19, b39, b39, b39 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(ext_params, 39u);
    e9 = stwo_qm31_sub(e1, e0);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    unsigned b46 = stwo_m31_mul(b20, b20);
    unsigned b47 = stwo_m31_sub(b46, b20);
    e0 = StwoCudaQm31{ b47, b39, b39, b39 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    e1 = StwoCudaQm31{ b20, b39, b39, b39 };
    e10 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e1);
    e1 = stwo_load_qm31(ext_params, 40u);
    StwoCudaQm31 e11 = StwoCudaQm31{ b0, b39, b39, b39 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e1, e11);
    e11 = stwo_load_qm31(ext_params, 41u);
    e1 = stwo_qm31_add(e11, e12);
    e11 = stwo_load_qm31(ext_params, 42u);
    e12 = StwoCudaQm31{ b1, b39, b39, b39 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e11, e12);
    e12 = stwo_qm31_add(e1, e13);
    e13 = stwo_load_qm31(ext_params, 43u);
    e1 = StwoCudaQm31{ b2, b39, b39, b39 };
    e11 = stwo_qm31_mul(e13, e1);
    e1 = stwo_qm31_add(e12, e11);
    e11 = stwo_load_qm31(ext_params, 44u);
    e12 = StwoCudaQm31{ b3, b39, b39, b39 };
    e13 = stwo_qm31_mul(e11, e12);
    e12 = stwo_qm31_add(e1, e13);
    e13 = stwo_load_qm31(ext_params, 45u);
    e1 = StwoCudaQm31{ b4, b39, b39, b39 };
    e11 = stwo_qm31_mul(e13, e1);
    e1 = stwo_qm31_add(e12, e11);
    e11 = stwo_load_qm31(ext_params, 46u);
    e12 = StwoCudaQm31{ b5, b39, b39, b39 };
    e13 = stwo_qm31_mul(e11, e12);
    e12 = stwo_qm31_add(e1, e13);
    e13 = stwo_load_qm31(ext_params, 47u);
    unsigned b40 = base_params[7u];
    unsigned b41 = stwo_m31_mul(b15, b40);
    unsigned b42 = stwo_m31_add(b13, b41);
    e1 = StwoCudaQm31{ b42, b39, b39, b39 };
    e11 = stwo_qm31_mul(e13, e1);
    e1 = stwo_qm31_add(e12, e11);
    e11 = stwo_load_qm31(ext_params, 48u);
    unsigned b43 = base_params[8u];
    unsigned b44 = stwo_m31_mul(b19, b43);
    unsigned b45 = stwo_m31_add(b17, b44);
    e12 = StwoCudaQm31{ b45, b39, b39, b39 };
    e13 = stwo_qm31_mul(e11, e12);
    e12 = stwo_qm31_add(e1, e13);
    e13 = stwo_load_qm31(ext_params, 49u);
    e1 = stwo_qm31_sub(e12, e13);
    e13 = stwo_load_qm31(ext_params, 50u);
    e12 = stwo_qm31_mul(e3, e13);
    e13 = stwo_load_qm31(ext_params, 51u);
    e11 = stwo_qm31_mul(e2, e13);
    e13 = stwo_qm31_add(e12, e11);
    e11 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 52u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 53u);
    e12 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e12);
    e12 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 54u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 55u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 56u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(ext_params, 57u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e9 = StwoCudaQm31{ b48, b49, b50, b51 };
    e8 = stwo_qm31_mul(e9, e11);
    e11 = stwo_qm31_sub(e8, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e8 = StwoCudaQm31{ b52, b53, b54, b55 };
    e13 = stwo_qm31_sub(e8, e9);
    e9 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e9, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e9 = StwoCudaQm31{ b56, b57, b58, b59 };
    e3 = stwo_qm31_sub(e9, e8);
    e8 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e8, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e8 = StwoCudaQm31{ b60, b61, b62, b63 };
    e5 = stwo_qm31_sub(e8, e9);
    e9 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e9, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, -1);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, -1);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, -1);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, -1);
    e9 = StwoCudaQm31{ b64, b66, b68, b70 };
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, 0);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, 0);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, 0);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, 0);
    e7 = StwoCudaQm31{ b65, b67, b69, b71 };
    e4 = stwo_qm31_sub(e7, e9);
    e7 = stwo_qm31_sub(e4, e8);
    e4 = stwo_load_qm31(ext_params, 58u);
    e8 = stwo_qm31_add(e7, e4);
    e4 = stwo_qm31_mul(e8, e1);
    e8 = stwo_qm31_sub(e4, e10);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
