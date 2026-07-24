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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_5d3813928a10f9d6(
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
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    unsigned b13 = base_params[0u];
    unsigned b14 = stwo_m31_sub(b13, b3);
    unsigned b15 = stwo_m31_mul(b3, b14);
    unsigned b16 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b15, b16, b16, b16 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    StwoCudaQm31 e1 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    StwoCudaQm31 e2 = StwoCudaQm31{ b0, b16, b16, b16 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_load_qm31(ext_params, 1u);
    e1 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(ext_params, 2u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 3u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 5u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 6u);
    unsigned b19 = base_params[3u];
    unsigned b17 = base_params[2u];
    unsigned b18 = stwo_m31_mul(b3, b17);
    unsigned b20 = stwo_m31_add(b19, b18);
    e3 = StwoCudaQm31{ b20, b16, b16, b16 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 7u);
    e1 = stwo_qm31_sub(e3, e4);
    e4 = stwo_load_qm31(ext_params, 8u);
    unsigned b21 = base_params[4u];
    unsigned b22 = stwo_m31_add(b0, b21);
    e3 = StwoCudaQm31{ b22, b16, b16, b16 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(ext_params, 9u);
    e4 = stwo_qm31_add(e3, e2);
    e3 = stwo_load_qm31(ext_params, 10u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e2 = StwoCudaQm31{ b4, b16, b16, b16 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 11u);
    e4 = stwo_qm31_sub(e2, e5);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    unsigned b23 = base_params[5u];
    unsigned b24 = stwo_m31_sub(b5, b23);
    unsigned b25 = stwo_m31_mul(b5, b24);
    e5 = StwoCudaQm31{ b25, b16, b16, b16 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b26 = base_params[6u];
    unsigned b27 = stwo_m31_sub(b6, b26);
    unsigned b28 = stwo_m31_mul(b6, b27);
    e2 = StwoCudaQm31{ b28, b16, b16, b16 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b29 = base_params[7u];
    unsigned b30 = stwo_m31_sub(b5, b29);
    unsigned b31 = stwo_m31_mul(b6, b30);
    e3 = StwoCudaQm31{ b31, b16, b16, b16 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b41 = base_params[12u];
    unsigned b42 = stwo_m31_sub(b41, b11);
    unsigned b43 = stwo_m31_mul(b11, b42);
    unsigned b44 = base_params[13u];
    unsigned b45 = stwo_m31_mul(b43, b44);
    StwoCudaQm31 e6 = StwoCudaQm31{ b45, b16, b16, b16 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b46 = base_params[14u];
    unsigned b47 = stwo_m31_mul(b11, b46);
    unsigned b48 = stwo_m31_sub(b10, b47);
    unsigned b49 = base_params[15u];
    unsigned b50 = stwo_m31_sub(b49, b48);
    unsigned b51 = stwo_m31_mul(b48, b50);
    unsigned b52 = base_params[16u];
    unsigned b53 = stwo_m31_mul(b51, b52);
    StwoCudaQm31 e7 = StwoCudaQm31{ b53, b16, b16, b16 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    StwoCudaQm31 e8 = stwo_load_qm31(ext_params, 12u);
    StwoCudaQm31 e9 = StwoCudaQm31{ b4, b16, b16, b16 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 13u);
    e8 = stwo_qm31_add(e9, e10);
    e9 = stwo_load_qm31(ext_params, 14u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    e10 = StwoCudaQm31{ b7, b16, b16, b16 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 15u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    e8 = StwoCudaQm31{ b8, b16, b16, b16 };
    e9 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 16u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    e10 = StwoCudaQm31{ b9, b16, b16, b16 };
    e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 17u);
    unsigned b32 = base_params[8u];
    unsigned b33 = stwo_m31_mul(b6, b32);
    unsigned b54 = stwo_m31_add(b10, b33);
    e8 = StwoCudaQm31{ b54, b16, b16, b16 };
    e9 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 18u);
    unsigned b34 = base_params[9u];
    unsigned b35 = stwo_m31_mul(b6, b34);
    e10 = StwoCudaQm31{ b35, b16, b16, b16 };
    e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 19u);
    e8 = StwoCudaQm31{ b35, b16, b16, b16 };
    e9 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 20u);
    e10 = StwoCudaQm31{ b35, b16, b16, b16 };
    e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 21u);
    e8 = StwoCudaQm31{ b35, b16, b16, b16 };
    e9 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 22u);
    e10 = StwoCudaQm31{ b35, b16, b16, b16 };
    e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 23u);
    e8 = StwoCudaQm31{ b35, b16, b16, b16 };
    e9 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 24u);
    e10 = StwoCudaQm31{ b35, b16, b16, b16 };
    e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 25u);
    e8 = StwoCudaQm31{ b35, b16, b16, b16 };
    e9 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 26u);
    e10 = StwoCudaQm31{ b35, b16, b16, b16 };
    e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 27u);
    e8 = StwoCudaQm31{ b35, b16, b16, b16 };
    e9 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 28u);
    e10 = StwoCudaQm31{ b35, b16, b16, b16 };
    e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 29u);
    e8 = StwoCudaQm31{ b35, b16, b16, b16 };
    e9 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 30u);
    e10 = StwoCudaQm31{ b35, b16, b16, b16 };
    e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 31u);
    e8 = StwoCudaQm31{ b35, b16, b16, b16 };
    e9 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 32u);
    e10 = StwoCudaQm31{ b35, b16, b16, b16 };
    e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 33u);
    e8 = StwoCudaQm31{ b35, b16, b16, b16 };
    e9 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 34u);
    e10 = StwoCudaQm31{ b35, b16, b16, b16 };
    e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 35u);
    unsigned b36 = base_params[10u];
    unsigned b37 = stwo_m31_mul(b5, b36);
    unsigned b38 = stwo_m31_sub(b37, b6);
    e8 = StwoCudaQm31{ b38, b16, b16, b16 };
    e9 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 36u);
    e10 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 37u);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 38u);
    e10 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 39u);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 40u);
    e10 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 41u);
    unsigned b39 = base_params[11u];
    unsigned b40 = stwo_m31_mul(b5, b39);
    e8 = StwoCudaQm31{ b40, b16, b16, b16 };
    e11 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 42u);
    e10 = stwo_qm31_sub(e8, e11);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b68 = stwo_m31_mul(b12, b12);
    unsigned b69 = stwo_m31_sub(b68, b12);
    e11 = StwoCudaQm31{ b69, b16, b16, b16 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    e8 = stwo_load_qm31(ext_params, 43u);
    e9 = StwoCudaQm31{ b0, b16, b16, b16 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 44u);
    e8 = stwo_qm31_add(e9, e12);
    e9 = stwo_load_qm31(ext_params, 45u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e12 = StwoCudaQm31{ b1, b16, b16, b16 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e9, e12);
    e12 = stwo_qm31_add(e8, e13);
    e13 = stwo_load_qm31(ext_params, 46u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    e8 = StwoCudaQm31{ b2, b16, b16, b16 };
    e9 = stwo_qm31_mul(e13, e8);
    e8 = stwo_qm31_add(e12, e9);
    e9 = stwo_load_qm31(ext_params, 47u);
    e12 = stwo_qm31_sub(e8, e9);
    e9 = StwoCudaQm31{ b12, b16, b16, b16 };
    e8 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e9);
    e9 = stwo_load_qm31(ext_params, 48u);
    unsigned b55 = base_params[17u];
    unsigned b56 = stwo_m31_mul(b8, b55);
    unsigned b57 = stwo_m31_add(b7, b56);
    unsigned b58 = base_params[18u];
    unsigned b59 = stwo_m31_mul(b9, b58);
    unsigned b60 = stwo_m31_add(b57, b59);
    unsigned b61 = base_params[19u];
    unsigned b62 = stwo_m31_mul(b10, b61);
    unsigned b63 = stwo_m31_add(b60, b62);
    unsigned b64 = stwo_m31_sub(b63, b5);
    unsigned b65 = base_params[20u];
    unsigned b66 = stwo_m31_mul(b65, b6);
    unsigned b67 = stwo_m31_sub(b64, b66);
    unsigned b70 = stwo_m31_add(b0, b67);
    e13 = StwoCudaQm31{ b70, b16, b16, b16 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e9, e13);
    e13 = stwo_load_qm31(ext_params, 49u);
    e9 = stwo_qm31_add(e13, e14);
    e13 = stwo_load_qm31(ext_params, 50u);
    unsigned b71 = stwo_m31_add(b1, b3);
    e14 = StwoCudaQm31{ b71, b16, b16, b16 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e13, e14);
    e14 = stwo_qm31_add(e9, e15);
    e15 = stwo_load_qm31(ext_params, 51u);
    e9 = StwoCudaQm31{ b2, b16, b16, b16 };
    e13 = stwo_qm31_mul(e15, e9);
    e9 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 52u);
    e14 = stwo_qm31_sub(e9, e13);
    e13 = stwo_load_qm31(ext_params, 53u);
    e9 = stwo_qm31_mul(e4, e13);
    e13 = stwo_load_qm31(ext_params, 54u);
    e15 = stwo_qm31_mul(e1, e13);
    e13 = stwo_qm31_add(e9, e15);
    e15 = stwo_qm31_mul(e1, e4);
    e4 = stwo_load_qm31(ext_params, 55u);
    e1 = stwo_qm31_mul(e12, e4);
    e4 = StwoCudaQm31{ b12, b16, b16, b16 };
    e9 = stwo_qm31_mul(e10, e4);
    e4 = stwo_qm31_add(e1, e9);
    e9 = stwo_qm31_mul(e10, e12);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e12 = StwoCudaQm31{ b72, b73, b74, b75 };
    e10 = stwo_qm31_mul(e12, e15);
    e15 = stwo_qm31_sub(e10, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e10 = StwoCudaQm31{ b76, b77, b78, b79 };
    e13 = stwo_qm31_sub(e10, e12);
    e12 = stwo_qm31_mul(e13, e9);
    e13 = stwo_qm31_sub(e12, e4);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, -1);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, -1);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, -1);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, -1);
    e12 = StwoCudaQm31{ b80, b82, b84, b86 };
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e4 = StwoCudaQm31{ b81, b83, b85, b87 };
    e9 = stwo_qm31_sub(e4, e12);
    e4 = stwo_qm31_sub(e9, e10);
    e9 = stwo_load_qm31(ext_params, 56u);
    e10 = stwo_qm31_add(e4, e9);
    e9 = stwo_qm31_mul(e10, e14);
    e10 = stwo_qm31_sub(e9, e8);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
