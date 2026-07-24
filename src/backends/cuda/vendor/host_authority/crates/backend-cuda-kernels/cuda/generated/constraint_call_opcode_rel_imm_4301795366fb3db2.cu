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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_3ca3b8d291cfd8f9(
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
    unsigned b24 = base_params[0u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b0, b24, b24, b24 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 2u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 3u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 5u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 6u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 7u);
    e0 = stwo_qm31_sub(e2, e1);
    e1 = stwo_load_qm31(ext_params, 8u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e2 = StwoCudaQm31{ b1, b24, b24, b24 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_load_qm31(ext_params, 9u);
    e1 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(ext_params, 10u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e3 = StwoCudaQm31{ b3, b24, b24, b24 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 11u);
    e1 = stwo_qm31_sub(e3, e4);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b25 = base_params[1u];
    unsigned b26 = stwo_m31_sub(b25, b8);
    unsigned b27 = stwo_m31_mul(b8, b26);
    unsigned b28 = base_params[2u];
    unsigned b29 = stwo_m31_mul(b27, b28);
    e4 = StwoCudaQm31{ b29, b24, b24, b24 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b30 = base_params[3u];
    unsigned b31 = stwo_m31_mul(b8, b30);
    unsigned b32 = stwo_m31_sub(b7, b31);
    unsigned b33 = base_params[4u];
    unsigned b34 = stwo_m31_sub(b33, b32);
    unsigned b35 = stwo_m31_mul(b32, b34);
    unsigned b36 = base_params[5u];
    unsigned b37 = stwo_m31_mul(b35, b36);
    e3 = StwoCudaQm31{ b37, b24, b24, b24 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    e2 = stwo_load_qm31(ext_params, 12u);
    StwoCudaQm31 e5 = StwoCudaQm31{ b3, b24, b24, b24 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e2, e5);
    e5 = stwo_load_qm31(ext_params, 13u);
    e2 = stwo_qm31_add(e5, e6);
    e5 = stwo_load_qm31(ext_params, 14u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e6 = StwoCudaQm31{ b4, b24, b24, b24 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_qm31_add(e2, e7);
    e7 = stwo_load_qm31(ext_params, 15u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e2 = StwoCudaQm31{ b5, b24, b24, b24 };
    e5 = stwo_qm31_mul(e7, e2);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(ext_params, 16u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    e6 = StwoCudaQm31{ b6, b24, b24, b24 };
    e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_qm31_add(e2, e7);
    e7 = stwo_load_qm31(ext_params, 17u);
    e2 = StwoCudaQm31{ b7, b24, b24, b24 };
    e5 = stwo_qm31_mul(e7, e2);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(ext_params, 18u);
    e6 = stwo_qm31_sub(e2, e5);
    unsigned b38 = base_params[6u];
    unsigned b39 = stwo_m31_mul(b5, b38);
    unsigned b40 = stwo_m31_add(b4, b39);
    unsigned b41 = base_params[7u];
    unsigned b42 = stwo_m31_mul(b6, b41);
    unsigned b43 = stwo_m31_add(b40, b42);
    unsigned b44 = base_params[8u];
    unsigned b45 = stwo_m31_mul(b7, b44);
    unsigned b46 = stwo_m31_add(b43, b45);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b47 = stwo_m31_sub(b46, b2);
    e5 = StwoCudaQm31{ b47, b24, b24, b24 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    e2 = stwo_load_qm31(ext_params, 19u);
    unsigned b48 = base_params[9u];
    unsigned b49 = stwo_m31_add(b1, b48);
    e7 = StwoCudaQm31{ b49, b24, b24, b24 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e2, e7);
    e7 = stwo_load_qm31(ext_params, 20u);
    e2 = stwo_qm31_add(e7, e8);
    e7 = stwo_load_qm31(ext_params, 21u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    e8 = StwoCudaQm31{ b9, b24, b24, b24 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e2, e9);
    e9 = stwo_load_qm31(ext_params, 22u);
    e2 = stwo_qm31_sub(e8, e9);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    unsigned b50 = base_params[10u];
    unsigned b51 = stwo_m31_sub(b50, b14);
    unsigned b52 = stwo_m31_mul(b14, b51);
    unsigned b53 = base_params[11u];
    unsigned b54 = stwo_m31_mul(b52, b53);
    e9 = StwoCudaQm31{ b54, b24, b24, b24 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    unsigned b55 = base_params[12u];
    unsigned b56 = stwo_m31_mul(b14, b55);
    unsigned b57 = stwo_m31_sub(b13, b56);
    unsigned b58 = base_params[13u];
    unsigned b59 = stwo_m31_sub(b58, b57);
    unsigned b60 = stwo_m31_mul(b57, b59);
    unsigned b61 = base_params[14u];
    unsigned b62 = stwo_m31_mul(b60, b61);
    e8 = StwoCudaQm31{ b62, b24, b24, b24 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    e7 = stwo_load_qm31(ext_params, 23u);
    StwoCudaQm31 e10 = StwoCudaQm31{ b9, b24, b24, b24 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e7, e10);
    e10 = stwo_load_qm31(ext_params, 24u);
    e7 = stwo_qm31_add(e10, e11);
    e10 = stwo_load_qm31(ext_params, 25u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    e11 = StwoCudaQm31{ b10, b24, b24, b24 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e10, e11);
    e11 = stwo_qm31_add(e7, e12);
    e12 = stwo_load_qm31(ext_params, 26u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    e7 = StwoCudaQm31{ b11, b24, b24, b24 };
    e10 = stwo_qm31_mul(e12, e7);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 27u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    e11 = StwoCudaQm31{ b12, b24, b24, b24 };
    e12 = stwo_qm31_mul(e10, e11);
    e11 = stwo_qm31_add(e7, e12);
    e12 = stwo_load_qm31(ext_params, 28u);
    e7 = StwoCudaQm31{ b13, b24, b24, b24 };
    e10 = stwo_qm31_mul(e12, e7);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 29u);
    e11 = stwo_qm31_sub(e7, e10);
    unsigned b63 = base_params[15u];
    unsigned b64 = stwo_m31_mul(b11, b63);
    unsigned b65 = stwo_m31_add(b10, b64);
    unsigned b66 = base_params[16u];
    unsigned b67 = stwo_m31_mul(b12, b66);
    unsigned b68 = stwo_m31_add(b65, b67);
    unsigned b69 = base_params[17u];
    unsigned b70 = stwo_m31_mul(b13, b69);
    unsigned b71 = stwo_m31_add(b68, b70);
    unsigned b72 = base_params[18u];
    unsigned b73 = stwo_m31_add(b0, b72);
    unsigned b74 = stwo_m31_sub(b71, b73);
    e10 = StwoCudaQm31{ b74, b24, b24, b24 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    e7 = stwo_load_qm31(ext_params, 30u);
    unsigned b75 = base_params[19u];
    unsigned b76 = stwo_m31_add(b0, b75);
    e12 = StwoCudaQm31{ b76, b24, b24, b24 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e7, e12);
    e12 = stwo_load_qm31(ext_params, 31u);
    e7 = stwo_qm31_add(e12, e13);
    e12 = stwo_load_qm31(ext_params, 32u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    e13 = StwoCudaQm31{ b15, b24, b24, b24 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e12, e13);
    e13 = stwo_qm31_add(e7, e14);
    e14 = stwo_load_qm31(ext_params, 33u);
    e7 = stwo_qm31_sub(e13, e14);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b77 = base_params[20u];
    unsigned b78 = stwo_m31_sub(b16, b77);
    unsigned b79 = stwo_m31_mul(b16, b78);
    e14 = StwoCudaQm31{ b79, b24, b24, b24 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    unsigned b80 = base_params[21u];
    unsigned b81 = stwo_m31_sub(b17, b80);
    unsigned b82 = stwo_m31_mul(b17, b81);
    e13 = StwoCudaQm31{ b82, b24, b24, b24 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b83 = base_params[22u];
    unsigned b84 = stwo_m31_sub(b16, b83);
    unsigned b85 = stwo_m31_mul(b17, b84);
    e12 = StwoCudaQm31{ b85, b24, b24, b24 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    unsigned b95 = base_params[27u];
    unsigned b96 = stwo_m31_sub(b95, b22);
    unsigned b97 = stwo_m31_mul(b22, b96);
    unsigned b98 = base_params[28u];
    unsigned b99 = stwo_m31_mul(b97, b98);
    StwoCudaQm31 e15 = StwoCudaQm31{ b99, b24, b24, b24 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    unsigned b100 = base_params[29u];
    unsigned b101 = stwo_m31_mul(b22, b100);
    unsigned b102 = stwo_m31_sub(b21, b101);
    unsigned b103 = base_params[30u];
    unsigned b104 = stwo_m31_sub(b103, b102);
    unsigned b105 = stwo_m31_mul(b102, b104);
    unsigned b106 = base_params[31u];
    unsigned b107 = stwo_m31_mul(b105, b106);
    StwoCudaQm31 e16 = StwoCudaQm31{ b107, b24, b24, b24 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    StwoCudaQm31 e17 = stwo_load_qm31(ext_params, 34u);
    StwoCudaQm31 e18 = StwoCudaQm31{ b15, b24, b24, b24 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e17, e18);
    e18 = stwo_load_qm31(ext_params, 35u);
    e17 = stwo_qm31_add(e18, e19);
    e18 = stwo_load_qm31(ext_params, 36u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    e19 = StwoCudaQm31{ b18, b24, b24, b24 };
    StwoCudaQm31 e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 37u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    e17 = StwoCudaQm31{ b19, b24, b24, b24 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 38u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    e19 = StwoCudaQm31{ b20, b24, b24, b24 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 39u);
    unsigned b86 = base_params[23u];
    unsigned b87 = stwo_m31_mul(b17, b86);
    unsigned b108 = stwo_m31_add(b21, b87);
    e17 = StwoCudaQm31{ b108, b24, b24, b24 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 40u);
    unsigned b88 = base_params[24u];
    unsigned b89 = stwo_m31_mul(b17, b88);
    e19 = StwoCudaQm31{ b89, b24, b24, b24 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 41u);
    e17 = StwoCudaQm31{ b89, b24, b24, b24 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 42u);
    e19 = StwoCudaQm31{ b89, b24, b24, b24 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 43u);
    e17 = StwoCudaQm31{ b89, b24, b24, b24 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 44u);
    e19 = StwoCudaQm31{ b89, b24, b24, b24 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 45u);
    e17 = StwoCudaQm31{ b89, b24, b24, b24 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 46u);
    e19 = StwoCudaQm31{ b89, b24, b24, b24 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 47u);
    e17 = StwoCudaQm31{ b89, b24, b24, b24 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 48u);
    e19 = StwoCudaQm31{ b89, b24, b24, b24 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 49u);
    e17 = StwoCudaQm31{ b89, b24, b24, b24 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 50u);
    e19 = StwoCudaQm31{ b89, b24, b24, b24 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 51u);
    e17 = StwoCudaQm31{ b89, b24, b24, b24 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 52u);
    e19 = StwoCudaQm31{ b89, b24, b24, b24 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 53u);
    e17 = StwoCudaQm31{ b89, b24, b24, b24 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 54u);
    e19 = StwoCudaQm31{ b89, b24, b24, b24 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 55u);
    e17 = StwoCudaQm31{ b89, b24, b24, b24 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 56u);
    e19 = StwoCudaQm31{ b89, b24, b24, b24 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 57u);
    unsigned b90 = base_params[25u];
    unsigned b91 = stwo_m31_mul(b16, b90);
    unsigned b92 = stwo_m31_sub(b91, b17);
    e17 = StwoCudaQm31{ b92, b24, b24, b24 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 58u);
    e19 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(ext_params, 59u);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 60u);
    e19 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(ext_params, 61u);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 62u);
    e19 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(ext_params, 63u);
    unsigned b93 = base_params[26u];
    unsigned b94 = stwo_m31_mul(b16, b93);
    e17 = StwoCudaQm31{ b94, b24, b24, b24 };
    e20 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e19, e20);
    e20 = stwo_load_qm31(ext_params, 64u);
    e19 = stwo_qm31_sub(e17, e20);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    unsigned b122 = stwo_m31_mul(b23, b23);
    unsigned b123 = stwo_m31_sub(b122, b23);
    e20 = StwoCudaQm31{ b123, b24, b24, b24 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e20, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    e17 = stwo_load_qm31(ext_params, 65u);
    e18 = StwoCudaQm31{ b0, b24, b24, b24 };
    StwoCudaQm31 e21 = stwo_qm31_mul(e17, e18);
    e18 = stwo_load_qm31(ext_params, 66u);
    e17 = stwo_qm31_add(e18, e21);
    e18 = stwo_load_qm31(ext_params, 67u);
    e21 = StwoCudaQm31{ b1, b24, b24, b24 };
    StwoCudaQm31 e22 = stwo_qm31_mul(e18, e21);
    e21 = stwo_qm31_add(e17, e22);
    e22 = stwo_load_qm31(ext_params, 68u);
    e17 = StwoCudaQm31{ b2, b24, b24, b24 };
    e18 = stwo_qm31_mul(e22, e17);
    e17 = stwo_qm31_add(e21, e18);
    e18 = stwo_load_qm31(ext_params, 69u);
    e21 = stwo_qm31_sub(e17, e18);
    e18 = StwoCudaQm31{ b23, b24, b24, b24 };
    e17 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e18);
    e18 = stwo_load_qm31(ext_params, 70u);
    unsigned b109 = base_params[32u];
    unsigned b110 = stwo_m31_mul(b19, b109);
    unsigned b111 = stwo_m31_add(b18, b110);
    unsigned b112 = base_params[33u];
    unsigned b113 = stwo_m31_mul(b20, b112);
    unsigned b114 = stwo_m31_add(b111, b113);
    unsigned b115 = base_params[34u];
    unsigned b116 = stwo_m31_mul(b21, b115);
    unsigned b117 = stwo_m31_add(b114, b116);
    unsigned b118 = stwo_m31_sub(b117, b16);
    unsigned b119 = base_params[35u];
    unsigned b120 = stwo_m31_mul(b119, b17);
    unsigned b121 = stwo_m31_sub(b118, b120);
    unsigned b124 = stwo_m31_add(b0, b121);
    e22 = StwoCudaQm31{ b124, b24, b24, b24 };
    StwoCudaQm31 e23 = stwo_qm31_mul(e18, e22);
    e22 = stwo_load_qm31(ext_params, 71u);
    e18 = stwo_qm31_add(e22, e23);
    e22 = stwo_load_qm31(ext_params, 72u);
    unsigned b125 = base_params[36u];
    unsigned b126 = stwo_m31_add(b1, b125);
    e23 = StwoCudaQm31{ b126, b24, b24, b24 };
    StwoCudaQm31 e24 = stwo_qm31_mul(e22, e23);
    e23 = stwo_qm31_add(e18, e24);
    e24 = stwo_load_qm31(ext_params, 73u);
    unsigned b127 = base_params[37u];
    unsigned b128 = stwo_m31_add(b1, b127);
    e18 = StwoCudaQm31{ b128, b24, b24, b24 };
    e22 = stwo_qm31_mul(e24, e18);
    e18 = stwo_qm31_add(e23, e22);
    e22 = stwo_load_qm31(ext_params, 74u);
    e23 = stwo_qm31_sub(e18, e22);
    e22 = stwo_load_qm31(ext_params, 75u);
    e18 = stwo_qm31_mul(e1, e22);
    e22 = stwo_load_qm31(ext_params, 76u);
    e24 = stwo_qm31_mul(e0, e22);
    e22 = stwo_qm31_add(e18, e24);
    e24 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 77u);
    e0 = stwo_qm31_mul(e2, e1);
    e1 = stwo_load_qm31(ext_params, 78u);
    e18 = stwo_qm31_mul(e6, e1);
    e1 = stwo_qm31_add(e0, e18);
    e18 = stwo_qm31_mul(e6, e2);
    e2 = stwo_load_qm31(ext_params, 79u);
    e6 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(ext_params, 80u);
    e0 = stwo_qm31_mul(e11, e2);
    e2 = stwo_qm31_add(e6, e0);
    e0 = stwo_qm31_mul(e11, e7);
    e7 = stwo_load_qm31(ext_params, 81u);
    e11 = stwo_qm31_mul(e21, e7);
    e7 = StwoCudaQm31{ b23, b24, b24, b24 };
    e6 = stwo_qm31_mul(e19, e7);
    e7 = stwo_qm31_add(e11, e6);
    e6 = stwo_qm31_mul(e19, e21);
    unsigned b129 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b130 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b131 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b132 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e21 = StwoCudaQm31{ b129, b130, b131, b132 };
    e19 = stwo_qm31_mul(e21, e24);
    e24 = stwo_qm31_sub(e19, e22);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e24, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b133 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b134 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b135 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b136 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e19 = StwoCudaQm31{ b133, b134, b135, b136 };
    e22 = stwo_qm31_sub(e19, e21);
    e21 = stwo_qm31_mul(e22, e18);
    e22 = stwo_qm31_sub(e21, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e22, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b137 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b138 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b139 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b140 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e21 = StwoCudaQm31{ b137, b138, b139, b140 };
    e1 = stwo_qm31_sub(e21, e19);
    e19 = stwo_qm31_mul(e1, e0);
    e1 = stwo_qm31_sub(e19, e2);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));
    unsigned b141 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b142 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b143 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b144 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e19 = StwoCudaQm31{ b141, b142, b143, b144 };
    e2 = stwo_qm31_sub(e19, e21);
    e21 = stwo_qm31_mul(e2, e6);
    e2 = stwo_qm31_sub(e21, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 15u)));
    unsigned b145 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, -1);
    unsigned b147 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, -1);
    unsigned b149 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, -1);
    unsigned b151 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, -1);
    e21 = StwoCudaQm31{ b145, b147, b149, b151 };
    unsigned b146 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, 0);
    unsigned b148 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, 0);
    unsigned b150 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, 0);
    unsigned b152 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, 0);
    e7 = StwoCudaQm31{ b146, b148, b150, b152 };
    e6 = stwo_qm31_sub(e7, e21);
    e7 = stwo_qm31_sub(e6, e19);
    e6 = stwo_load_qm31(ext_params, 82u);
    e19 = stwo_qm31_add(e7, e6);
    e6 = stwo_qm31_mul(e19, e23);
    e19 = stwo_qm31_sub(e6, e17);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e19, stwo_load_qm31(random_coeff_powers, rc_base + 16u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
