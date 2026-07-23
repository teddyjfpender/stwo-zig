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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_904ccde444828506(
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
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b98 = base_params[18u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b10, b98, b98, b98 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 2u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    e2 = StwoCudaQm31{ b11, b98, b98, b98 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 3u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 4u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b44 = stwo_m31_sub(b0, b10);
    unsigned b45 = base_params[0u];
    unsigned b46 = stwo_m31_mul(b11, b45);
    unsigned b47 = stwo_m31_sub(b44, b46);
    unsigned b48 = base_params[1u];
    unsigned b49 = stwo_m31_mul(b47, b48);
    e2 = StwoCudaQm31{ b49, b98, b98, b98 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 5u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 6u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    e1 = StwoCudaQm31{ b12, b98, b98, b98 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 7u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 8u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    e1 = StwoCudaQm31{ b13, b98, b98, b98 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 9u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 10u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    unsigned b50 = stwo_m31_sub(b1, b12);
    unsigned b51 = base_params[2u];
    unsigned b52 = stwo_m31_mul(b13, b51);
    unsigned b53 = stwo_m31_sub(b50, b52);
    unsigned b54 = base_params[3u];
    unsigned b55 = stwo_m31_mul(b53, b54);
    e2 = StwoCudaQm31{ b55, b98, b98, b98 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 11u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(ext_params, 12u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    e2 = StwoCudaQm31{ b14, b98, b98, b98 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(ext_params, 13u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 14u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    e1 = StwoCudaQm31{ b15, b98, b98, b98 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 15u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(ext_params, 16u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b56 = stwo_m31_sub(b2, b14);
    unsigned b57 = base_params[4u];
    unsigned b58 = stwo_m31_mul(b15, b57);
    unsigned b59 = stwo_m31_sub(b56, b58);
    unsigned b60 = base_params[5u];
    unsigned b61 = stwo_m31_mul(b59, b60);
    e1 = StwoCudaQm31{ b61, b98, b98, b98 };
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(ext_params, 17u);
    e6 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 18u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    e2 = StwoCudaQm31{ b16, b98, b98, b98 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 19u);
    e6 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(ext_params, 20u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    e2 = StwoCudaQm31{ b17, b98, b98, b98 };
    e1 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(ext_params, 21u);
    e7 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 22u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    unsigned b62 = stwo_m31_sub(b3, b16);
    unsigned b63 = base_params[6u];
    unsigned b64 = stwo_m31_mul(b17, b63);
    unsigned b65 = stwo_m31_sub(b62, b64);
    unsigned b66 = base_params[7u];
    unsigned b67 = stwo_m31_mul(b65, b66);
    e1 = StwoCudaQm31{ b67, b98, b98, b98 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 23u);
    e7 = stwo_qm31_sub(e1, e8);
    e8 = stwo_load_qm31(ext_params, 24u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    e1 = StwoCudaQm31{ b18, b98, b98, b98 };
    e2 = stwo_qm31_mul(e8, e1);
    e1 = stwo_load_qm31(ext_params, 25u);
    e8 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 26u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    e2 = StwoCudaQm31{ b19, b98, b98, b98 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 27u);
    e8 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(ext_params, 28u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    unsigned b68 = stwo_m31_sub(b4, b18);
    unsigned b69 = base_params[8u];
    unsigned b70 = stwo_m31_mul(b19, b69);
    unsigned b71 = stwo_m31_sub(b68, b70);
    unsigned b72 = base_params[9u];
    unsigned b73 = stwo_m31_mul(b71, b72);
    e2 = StwoCudaQm31{ b73, b98, b98, b98 };
    e1 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(ext_params, 29u);
    e9 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 30u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    e1 = StwoCudaQm31{ b20, b98, b98, b98 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 31u);
    e9 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(ext_params, 32u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    e1 = StwoCudaQm31{ b21, b98, b98, b98 };
    e2 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(ext_params, 33u);
    e10 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 34u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    unsigned b74 = stwo_m31_sub(b5, b20);
    unsigned b75 = base_params[10u];
    unsigned b76 = stwo_m31_mul(b21, b75);
    unsigned b77 = stwo_m31_sub(b74, b76);
    unsigned b78 = base_params[11u];
    unsigned b79 = stwo_m31_mul(b77, b78);
    e2 = StwoCudaQm31{ b79, b98, b98, b98 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 35u);
    e10 = stwo_qm31_sub(e2, e11);
    e11 = stwo_load_qm31(ext_params, 36u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    e2 = StwoCudaQm31{ b22, b98, b98, b98 };
    e1 = stwo_qm31_mul(e11, e2);
    e2 = stwo_load_qm31(ext_params, 37u);
    e11 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 38u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    e1 = StwoCudaQm31{ b23, b98, b98, b98 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 39u);
    e11 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(ext_params, 40u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b80 = stwo_m31_sub(b6, b22);
    unsigned b81 = base_params[12u];
    unsigned b82 = stwo_m31_mul(b23, b81);
    unsigned b83 = stwo_m31_sub(b80, b82);
    unsigned b84 = base_params[13u];
    unsigned b85 = stwo_m31_mul(b83, b84);
    e1 = StwoCudaQm31{ b85, b98, b98, b98 };
    e2 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(ext_params, 41u);
    e12 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 42u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    e2 = StwoCudaQm31{ b24, b98, b98, b98 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 43u);
    e12 = stwo_qm31_sub(e2, e13);
    e13 = stwo_load_qm31(ext_params, 44u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    e2 = StwoCudaQm31{ b25, b98, b98, b98 };
    e1 = stwo_qm31_mul(e13, e2);
    e2 = stwo_load_qm31(ext_params, 45u);
    e13 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 46u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b86 = stwo_m31_sub(b7, b24);
    unsigned b87 = base_params[14u];
    unsigned b88 = stwo_m31_mul(b25, b87);
    unsigned b89 = stwo_m31_sub(b86, b88);
    unsigned b90 = base_params[15u];
    unsigned b91 = stwo_m31_mul(b89, b90);
    e1 = StwoCudaQm31{ b91, b98, b98, b98 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(ext_params, 47u);
    e13 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(ext_params, 48u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    e1 = StwoCudaQm31{ b26, b98, b98, b98 };
    e2 = stwo_qm31_mul(e14, e1);
    e1 = stwo_load_qm31(ext_params, 49u);
    e14 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 50u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    e2 = StwoCudaQm31{ b27, b98, b98, b98 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 51u);
    e14 = stwo_qm31_sub(e2, e15);
    e15 = stwo_load_qm31(ext_params, 52u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b92 = stwo_m31_sub(b8, b26);
    unsigned b93 = base_params[16u];
    unsigned b94 = stwo_m31_mul(b27, b93);
    unsigned b95 = stwo_m31_sub(b92, b94);
    unsigned b96 = base_params[17u];
    unsigned b97 = stwo_m31_mul(b95, b96);
    e2 = StwoCudaQm31{ b97, b98, b98, b98 };
    e1 = stwo_qm31_mul(e15, e2);
    e2 = stwo_load_qm31(ext_params, 53u);
    e15 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 54u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    e1 = StwoCudaQm31{ b9, b98, b98, b98 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e15, e16);
    e16 = stwo_load_qm31(ext_params, 55u);
    e15 = stwo_qm31_sub(e1, e16);
    e16 = stwo_load_qm31(ext_params, 56u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    e1 = StwoCudaQm31{ b28, b98, b98, b98 };
    e2 = stwo_qm31_mul(e16, e1);
    e1 = stwo_load_qm31(ext_params, 57u);
    e16 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 58u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    e2 = StwoCudaQm31{ b29, b98, b98, b98 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 59u);
    e16 = stwo_qm31_sub(e2, e17);
    e17 = stwo_load_qm31(ext_params, 60u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    e2 = StwoCudaQm31{ b30, b98, b98, b98 };
    e1 = stwo_qm31_mul(e17, e2);
    e2 = stwo_load_qm31(ext_params, 61u);
    e17 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 62u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    e1 = StwoCudaQm31{ b31, b98, b98, b98 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(ext_params, 63u);
    e17 = stwo_qm31_sub(e1, e18);
    e18 = stwo_load_qm31(ext_params, 64u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    e1 = StwoCudaQm31{ b32, b98, b98, b98 };
    e2 = stwo_qm31_mul(e18, e1);
    e1 = stwo_load_qm31(ext_params, 65u);
    e18 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 66u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    e2 = StwoCudaQm31{ b33, b98, b98, b98 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(ext_params, 67u);
    e18 = stwo_qm31_sub(e2, e19);
    e19 = stwo_load_qm31(ext_params, 68u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    e2 = StwoCudaQm31{ b34, b98, b98, b98 };
    e1 = stwo_qm31_mul(e19, e2);
    e2 = stwo_load_qm31(ext_params, 69u);
    e19 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 70u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    e1 = StwoCudaQm31{ b35, b98, b98, b98 };
    StwoCudaQm31 e20 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e19, e20);
    e20 = stwo_load_qm31(ext_params, 71u);
    e19 = stwo_qm31_sub(e1, e20);
    e20 = stwo_load_qm31(ext_params, 72u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    e1 = StwoCudaQm31{ b36, b98, b98, b98 };
    e2 = stwo_qm31_mul(e20, e1);
    e1 = stwo_load_qm31(ext_params, 73u);
    e20 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 74u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    e2 = StwoCudaQm31{ b37, b98, b98, b98 };
    StwoCudaQm31 e21 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e20, e21);
    e21 = stwo_load_qm31(ext_params, 75u);
    e20 = stwo_qm31_sub(e2, e21);
    e21 = stwo_load_qm31(ext_params, 76u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    e2 = StwoCudaQm31{ b38, b98, b98, b98 };
    e1 = stwo_qm31_mul(e21, e2);
    e2 = stwo_load_qm31(ext_params, 77u);
    e21 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 78u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    e1 = StwoCudaQm31{ b39, b98, b98, b98 };
    StwoCudaQm31 e22 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e21, e22);
    e22 = stwo_load_qm31(ext_params, 79u);
    e21 = stwo_qm31_sub(e1, e22);
    e22 = stwo_load_qm31(ext_params, 80u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    e1 = StwoCudaQm31{ b40, b98, b98, b98 };
    e2 = stwo_qm31_mul(e22, e1);
    e1 = stwo_load_qm31(ext_params, 81u);
    e22 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 82u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    e2 = StwoCudaQm31{ b41, b98, b98, b98 };
    StwoCudaQm31 e23 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e22, e23);
    e23 = stwo_load_qm31(ext_params, 83u);
    e22 = stwo_qm31_sub(e2, e23);
    e23 = stwo_load_qm31(ext_params, 84u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    e2 = StwoCudaQm31{ b42, b98, b98, b98 };
    e1 = stwo_qm31_mul(e23, e2);
    e2 = stwo_load_qm31(ext_params, 85u);
    e23 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 86u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    e1 = StwoCudaQm31{ b43, b98, b98, b98 };
    StwoCudaQm31 e24 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e23, e24);
    e24 = stwo_load_qm31(ext_params, 87u);
    e23 = stwo_qm31_sub(e1, e24);
    e24 = stwo_load_qm31(ext_params, 358u);
    e1 = stwo_qm31_mul(e3, e24);
    e24 = stwo_load_qm31(ext_params, 359u);
    e2 = stwo_qm31_mul(e0, e24);
    e24 = stwo_qm31_add(e1, e2);
    e2 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(ext_params, 360u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 361u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 362u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 363u);
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 364u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(ext_params, 365u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 366u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(ext_params, 367u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(ext_params, 368u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(ext_params, 369u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(ext_params, 370u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(ext_params, 371u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 372u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(ext_params, 373u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(ext_params, 374u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(ext_params, 375u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(ext_params, 376u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(ext_params, 377u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e20, e21);
    e21 = stwo_load_qm31(ext_params, 378u);
    e20 = stwo_qm31_mul(e23, e21);
    e21 = stwo_load_qm31(ext_params, 379u);
    e18 = stwo_qm31_mul(e22, e21);
    e21 = stwo_qm31_add(e20, e18);
    e18 = stwo_qm31_mul(e22, e23);
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e23 = StwoCudaQm31{ b99, b100, b101, b102 };
    e22 = stwo_qm31_mul(e23, e2);
    e2 = stwo_qm31_sub(e22, e24);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b106 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e22 = StwoCudaQm31{ b103, b104, b105, b106 };
    e24 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e24, e1);
    e24 = stwo_qm31_sub(e23, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e24, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b107 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b108 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b109 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b110 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e23 = StwoCudaQm31{ b107, b108, b109, b110 };
    e3 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e22, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b111 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b112 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b113 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b114 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e22 = StwoCudaQm31{ b111, b112, b113, b114 };
    e5 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e23, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b115 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, 0);
    unsigned b116 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, 0);
    unsigned b117 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, 0);
    unsigned b118 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, 0);
    e23 = StwoCudaQm31{ b115, b116, b117, b118 };
    e7 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e22, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b119 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 20u, row_index, 0);
    unsigned b120 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 21u, row_index, 0);
    unsigned b121 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 22u, row_index, 0);
    unsigned b122 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 23u, row_index, 0);
    e22 = StwoCudaQm31{ b119, b120, b121, b122 };
    e9 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e23, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b123 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 24u, row_index, 0);
    unsigned b124 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 25u, row_index, 0);
    unsigned b125 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 26u, row_index, 0);
    unsigned b126 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 27u, row_index, 0);
    e23 = StwoCudaQm31{ b123, b124, b125, b126 };
    e11 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e22, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b127 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 28u, row_index, 0);
    unsigned b128 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 29u, row_index, 0);
    unsigned b129 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 30u, row_index, 0);
    unsigned b130 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 31u, row_index, 0);
    e22 = StwoCudaQm31{ b127, b128, b129, b130 };
    e13 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e23, e15);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b131 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 32u, row_index, 0);
    unsigned b132 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 33u, row_index, 0);
    unsigned b133 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 34u, row_index, 0);
    unsigned b134 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 35u, row_index, 0);
    e23 = StwoCudaQm31{ b131, b132, b133, b134 };
    e15 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e22, e17);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b135 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 36u, row_index, 0);
    unsigned b136 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 37u, row_index, 0);
    unsigned b137 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 38u, row_index, 0);
    unsigned b138 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 39u, row_index, 0);
    e22 = StwoCudaQm31{ b135, b136, b137, b138 };
    e17 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e23, e19);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b139 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 40u, row_index, 0);
    unsigned b140 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 41u, row_index, 0);
    unsigned b141 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 42u, row_index, 0);
    unsigned b142 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 43u, row_index, 0);
    e23 = StwoCudaQm31{ b139, b140, b141, b142 };
    e19 = stwo_qm31_sub(e23, e22);
    e23 = stwo_qm31_mul(e19, e18);
    e19 = stwo_qm31_sub(e23, e21);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e19, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
