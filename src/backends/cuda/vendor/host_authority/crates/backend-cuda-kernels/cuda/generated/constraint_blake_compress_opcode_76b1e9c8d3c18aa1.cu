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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_6490191123d136eb(
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
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b39 = base_params[0u];
    unsigned b40 = stwo_m31_sub(b39, b6);
    unsigned b41 = stwo_m31_mul(b6, b40);
    unsigned b42 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b41, b42, b42, b42 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b43 = base_params[2u];
    unsigned b44 = stwo_m31_sub(b43, b7);
    unsigned b45 = stwo_m31_mul(b7, b44);
    StwoCudaQm31 e1 = StwoCudaQm31{ b45, b42, b42, b42 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b46 = base_params[3u];
    unsigned b47 = stwo_m31_sub(b46, b8);
    unsigned b48 = stwo_m31_mul(b8, b47);
    StwoCudaQm31 e2 = StwoCudaQm31{ b48, b42, b42, b42 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b49 = base_params[4u];
    unsigned b50 = stwo_m31_sub(b49, b9);
    unsigned b51 = stwo_m31_mul(b9, b50);
    StwoCudaQm31 e3 = StwoCudaQm31{ b51, b42, b42, b42 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    StwoCudaQm31 e4 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    StwoCudaQm31 e5 = StwoCudaQm31{ b0, b42, b42, b42 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 1u);
    e4 = stwo_qm31_add(e5, e6);
    e5 = stwo_load_qm31(ext_params, 2u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e6 = StwoCudaQm31{ b3, b42, b42, b42 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 3u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e4 = StwoCudaQm31{ b4, b42, b42, b42 };
    e5 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(ext_params, 4u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e6 = StwoCudaQm31{ b5, b42, b42, b42 };
    e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 5u);
    unsigned b52 = base_params[5u];
    unsigned b53 = stwo_m31_mul(b6, b52);
    unsigned b54 = base_params[6u];
    unsigned b55 = stwo_m31_mul(b7, b54);
    unsigned b56 = stwo_m31_add(b53, b55);
    unsigned b57 = base_params[7u];
    unsigned b58 = stwo_m31_mul(b8, b57);
    unsigned b59 = stwo_m31_add(b56, b58);
    unsigned b60 = base_params[8u];
    unsigned b61 = stwo_m31_sub(b60, b8);
    unsigned b62 = base_params[9u];
    unsigned b63 = stwo_m31_mul(b61, b62);
    unsigned b64 = stwo_m31_add(b59, b63);
    e4 = StwoCudaQm31{ b64, b42, b42, b42 };
    e5 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(ext_params, 6u);
    unsigned b65 = base_params[10u];
    unsigned b66 = stwo_m31_mul(b9, b65);
    e6 = StwoCudaQm31{ b66, b42, b42, b42 };
    e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 7u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    e4 = StwoCudaQm31{ b10, b42, b42, b42 };
    e5 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(ext_params, 8u);
    e6 = stwo_qm31_sub(e4, e5);
    unsigned b75 = base_params[15u];
    unsigned b76 = stwo_m31_sub(b10, b75);
    unsigned b77 = base_params[16u];
    unsigned b78 = stwo_m31_sub(b10, b77);
    unsigned b79 = stwo_m31_mul(b76, b78);
    e5 = StwoCudaQm31{ b79, b42, b42, b42 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b80 = stwo_m31_mul(b7, b2);
    unsigned b81 = base_params[17u];
    unsigned b82 = stwo_m31_sub(b81, b7);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    unsigned b83 = stwo_m31_mul(b82, b1);
    unsigned b84 = stwo_m31_add(b80, b83);
    unsigned b85 = stwo_m31_sub(b11, b84);
    e4 = StwoCudaQm31{ b85, b42, b42, b42 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    e7 = stwo_load_qm31(ext_params, 9u);
    unsigned b69 = base_params[12u];
    unsigned b70 = stwo_m31_sub(b4, b69);
    unsigned b86 = stwo_m31_add(b11, b70);
    StwoCudaQm31 e8 = StwoCudaQm31{ b86, b42, b42, b42 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_load_qm31(ext_params, 10u);
    e7 = stwo_qm31_add(e8, e9);
    e8 = stwo_load_qm31(ext_params, 11u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    e9 = StwoCudaQm31{ b12, b42, b42, b42 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 12u);
    e7 = stwo_qm31_sub(e9, e10);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    unsigned b87 = base_params[18u];
    unsigned b88 = stwo_m31_sub(b87, b17);
    unsigned b89 = stwo_m31_mul(b17, b88);
    unsigned b90 = base_params[19u];
    unsigned b91 = stwo_m31_mul(b89, b90);
    e10 = StwoCudaQm31{ b91, b42, b42, b42 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b92 = base_params[20u];
    unsigned b93 = stwo_m31_mul(b17, b92);
    unsigned b94 = stwo_m31_sub(b16, b93);
    unsigned b95 = base_params[21u];
    unsigned b96 = stwo_m31_sub(b95, b94);
    unsigned b97 = stwo_m31_mul(b94, b96);
    unsigned b98 = base_params[22u];
    unsigned b99 = stwo_m31_mul(b97, b98);
    e9 = StwoCudaQm31{ b99, b42, b42, b42 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    e8 = stwo_load_qm31(ext_params, 13u);
    StwoCudaQm31 e11 = StwoCudaQm31{ b12, b42, b42, b42 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e8, e11);
    e11 = stwo_load_qm31(ext_params, 14u);
    e8 = stwo_qm31_add(e11, e12);
    e11 = stwo_load_qm31(ext_params, 15u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    e12 = StwoCudaQm31{ b13, b42, b42, b42 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e11, e12);
    e12 = stwo_qm31_add(e8, e13);
    e13 = stwo_load_qm31(ext_params, 16u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    e8 = StwoCudaQm31{ b14, b42, b42, b42 };
    e11 = stwo_qm31_mul(e13, e8);
    e8 = stwo_qm31_add(e12, e11);
    e11 = stwo_load_qm31(ext_params, 17u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    e12 = StwoCudaQm31{ b15, b42, b42, b42 };
    e13 = stwo_qm31_mul(e11, e12);
    e12 = stwo_qm31_add(e8, e13);
    e13 = stwo_load_qm31(ext_params, 18u);
    e8 = StwoCudaQm31{ b16, b42, b42, b42 };
    e11 = stwo_qm31_mul(e13, e8);
    e8 = stwo_qm31_add(e12, e11);
    e11 = stwo_load_qm31(ext_params, 19u);
    e12 = stwo_qm31_sub(e8, e11);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    unsigned b100 = stwo_m31_mul(b8, b2);
    unsigned b73 = base_params[14u];
    unsigned b74 = stwo_m31_sub(b73, b8);
    unsigned b101 = stwo_m31_mul(b74, b1);
    unsigned b102 = stwo_m31_add(b100, b101);
    unsigned b103 = stwo_m31_sub(b18, b102);
    e11 = StwoCudaQm31{ b103, b42, b42, b42 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    e8 = stwo_load_qm31(ext_params, 20u);
    unsigned b71 = base_params[13u];
    unsigned b72 = stwo_m31_sub(b5, b71);
    unsigned b104 = stwo_m31_add(b18, b72);
    e13 = StwoCudaQm31{ b104, b42, b42, b42 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e8, e13);
    e13 = stwo_load_qm31(ext_params, 21u);
    e8 = stwo_qm31_add(e13, e14);
    e13 = stwo_load_qm31(ext_params, 22u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    e14 = StwoCudaQm31{ b19, b42, b42, b42 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e13, e14);
    e14 = stwo_qm31_add(e8, e15);
    e15 = stwo_load_qm31(ext_params, 23u);
    e8 = stwo_qm31_sub(e14, e15);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    unsigned b105 = base_params[23u];
    unsigned b106 = stwo_m31_sub(b105, b24);
    unsigned b107 = stwo_m31_mul(b24, b106);
    unsigned b108 = base_params[24u];
    unsigned b109 = stwo_m31_mul(b107, b108);
    e15 = StwoCudaQm31{ b109, b42, b42, b42 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    unsigned b110 = base_params[25u];
    unsigned b111 = stwo_m31_mul(b24, b110);
    unsigned b112 = stwo_m31_sub(b23, b111);
    unsigned b113 = base_params[26u];
    unsigned b114 = stwo_m31_sub(b113, b112);
    unsigned b115 = stwo_m31_mul(b112, b114);
    unsigned b116 = base_params[27u];
    unsigned b117 = stwo_m31_mul(b115, b116);
    e14 = StwoCudaQm31{ b117, b42, b42, b42 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    e13 = stwo_load_qm31(ext_params, 24u);
    StwoCudaQm31 e16 = StwoCudaQm31{ b19, b42, b42, b42 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e13, e16);
    e16 = stwo_load_qm31(ext_params, 25u);
    e13 = stwo_qm31_add(e16, e17);
    e16 = stwo_load_qm31(ext_params, 26u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    e17 = StwoCudaQm31{ b20, b42, b42, b42 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e16, e17);
    e17 = stwo_qm31_add(e13, e18);
    e18 = stwo_load_qm31(ext_params, 27u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    e13 = StwoCudaQm31{ b21, b42, b42, b42 };
    e16 = stwo_qm31_mul(e18, e13);
    e13 = stwo_qm31_add(e17, e16);
    e16 = stwo_load_qm31(ext_params, 28u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    e17 = StwoCudaQm31{ b22, b42, b42, b42 };
    e18 = stwo_qm31_mul(e16, e17);
    e17 = stwo_qm31_add(e13, e18);
    e18 = stwo_load_qm31(ext_params, 29u);
    e13 = StwoCudaQm31{ b23, b42, b42, b42 };
    e16 = stwo_qm31_mul(e18, e13);
    e13 = stwo_qm31_add(e17, e16);
    e16 = stwo_load_qm31(ext_params, 30u);
    e17 = stwo_qm31_sub(e13, e16);
    e16 = stwo_load_qm31(ext_params, 31u);
    e13 = StwoCudaQm31{ b1, b42, b42, b42 };
    e18 = stwo_qm31_mul(e16, e13);
    e13 = stwo_load_qm31(ext_params, 32u);
    e16 = stwo_qm31_add(e13, e18);
    e13 = stwo_load_qm31(ext_params, 33u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    e18 = StwoCudaQm31{ b25, b42, b42, b42 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e13, e18);
    e18 = stwo_qm31_add(e16, e19);
    e19 = stwo_load_qm31(ext_params, 34u);
    e16 = stwo_qm31_sub(e18, e19);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    unsigned b118 = base_params[28u];
    unsigned b119 = stwo_m31_sub(b118, b30);
    unsigned b120 = stwo_m31_mul(b30, b119);
    unsigned b121 = base_params[29u];
    unsigned b122 = stwo_m31_mul(b120, b121);
    e19 = StwoCudaQm31{ b122, b42, b42, b42 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e19, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    unsigned b123 = base_params[30u];
    unsigned b124 = stwo_m31_mul(b30, b123);
    unsigned b125 = stwo_m31_sub(b29, b124);
    unsigned b126 = base_params[31u];
    unsigned b127 = stwo_m31_sub(b126, b125);
    unsigned b128 = stwo_m31_mul(b125, b127);
    unsigned b129 = base_params[32u];
    unsigned b130 = stwo_m31_mul(b128, b129);
    e18 = StwoCudaQm31{ b130, b42, b42, b42 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    e13 = stwo_load_qm31(ext_params, 35u);
    StwoCudaQm31 e20 = StwoCudaQm31{ b25, b42, b42, b42 };
    StwoCudaQm31 e21 = stwo_qm31_mul(e13, e20);
    e20 = stwo_load_qm31(ext_params, 36u);
    e13 = stwo_qm31_add(e20, e21);
    e20 = stwo_load_qm31(ext_params, 37u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    e21 = StwoCudaQm31{ b26, b42, b42, b42 };
    StwoCudaQm31 e22 = stwo_qm31_mul(e20, e21);
    e21 = stwo_qm31_add(e13, e22);
    e22 = stwo_load_qm31(ext_params, 38u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    e13 = StwoCudaQm31{ b27, b42, b42, b42 };
    e20 = stwo_qm31_mul(e22, e13);
    e13 = stwo_qm31_add(e21, e20);
    e20 = stwo_load_qm31(ext_params, 39u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    e21 = StwoCudaQm31{ b28, b42, b42, b42 };
    e22 = stwo_qm31_mul(e20, e21);
    e21 = stwo_qm31_add(e13, e22);
    e22 = stwo_load_qm31(ext_params, 40u);
    e13 = StwoCudaQm31{ b29, b42, b42, b42 };
    e20 = stwo_qm31_mul(e22, e13);
    e13 = stwo_qm31_add(e21, e20);
    e20 = stwo_load_qm31(ext_params, 41u);
    e21 = stwo_qm31_sub(e13, e20);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    unsigned b131 = stwo_m31_mul(b6, b2);
    unsigned b132 = base_params[33u];
    unsigned b133 = stwo_m31_sub(b132, b6);
    unsigned b134 = stwo_m31_mul(b133, b1);
    unsigned b135 = stwo_m31_add(b131, b134);
    unsigned b136 = stwo_m31_sub(b31, b135);
    e20 = StwoCudaQm31{ b136, b42, b42, b42 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e20, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    e13 = stwo_load_qm31(ext_params, 42u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    e22 = StwoCudaQm31{ b34, b42, b42, b42 };
    StwoCudaQm31 e23 = stwo_qm31_mul(e13, e22);
    e22 = stwo_load_qm31(ext_params, 43u);
    e13 = stwo_qm31_add(e22, e23);
    e22 = stwo_load_qm31(ext_params, 44u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    unsigned b138 = base_params[34u];
    unsigned b139 = stwo_m31_mul(b35, b138);
    unsigned b140 = stwo_m31_sub(b33, b139);
    e23 = StwoCudaQm31{ b140, b42, b42, b42 };
    StwoCudaQm31 e24 = stwo_qm31_mul(e22, e23);
    e23 = stwo_qm31_add(e13, e24);
    e24 = stwo_load_qm31(ext_params, 45u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    e13 = StwoCudaQm31{ b36, b42, b42, b42 };
    e22 = stwo_qm31_mul(e24, e13);
    e13 = stwo_qm31_add(e23, e22);
    e22 = stwo_load_qm31(ext_params, 46u);
    e23 = stwo_qm31_sub(e13, e22);
    e22 = stwo_load_qm31(ext_params, 47u);
    unsigned b67 = base_params[11u];
    unsigned b68 = stwo_m31_sub(b3, b67);
    unsigned b137 = stwo_m31_add(b31, b68);
    e13 = StwoCudaQm31{ b137, b42, b42, b42 };
    e24 = stwo_qm31_mul(e22, e13);
    e13 = stwo_load_qm31(ext_params, 48u);
    e22 = stwo_qm31_add(e13, e24);
    e13 = stwo_load_qm31(ext_params, 49u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    e24 = StwoCudaQm31{ b37, b42, b42, b42 };
    StwoCudaQm31 e25 = stwo_qm31_mul(e13, e24);
    e24 = stwo_qm31_add(e22, e25);
    e25 = stwo_load_qm31(ext_params, 50u);
    e22 = stwo_qm31_sub(e24, e25);
    e25 = stwo_load_qm31(ext_params, 51u);
    e24 = StwoCudaQm31{ b37, b42, b42, b42 };
    e13 = stwo_qm31_mul(e25, e24);
    e24 = stwo_load_qm31(ext_params, 52u);
    e25 = stwo_qm31_add(e24, e13);
    e24 = stwo_load_qm31(ext_params, 53u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    unsigned b141 = base_params[35u];
    unsigned b142 = stwo_m31_mul(b34, b141);
    unsigned b143 = stwo_m31_sub(b32, b142);
    e13 = StwoCudaQm31{ b143, b42, b42, b42 };
    StwoCudaQm31 e26 = stwo_qm31_mul(e24, e13);
    e13 = stwo_qm31_add(e25, e26);
    e26 = stwo_load_qm31(ext_params, 54u);
    unsigned b144 = base_params[36u];
    unsigned b145 = stwo_m31_mul(b140, b144);
    unsigned b146 = stwo_m31_add(b34, b145);
    e25 = StwoCudaQm31{ b146, b42, b42, b42 };
    e24 = stwo_qm31_mul(e26, e25);
    e25 = stwo_qm31_add(e13, e24);
    e24 = stwo_load_qm31(ext_params, 55u);
    unsigned b147 = base_params[37u];
    unsigned b148 = stwo_m31_mul(b36, b147);
    unsigned b149 = stwo_m31_sub(b35, b148);
    e13 = StwoCudaQm31{ b149, b42, b42, b42 };
    e26 = stwo_qm31_mul(e24, e13);
    e13 = stwo_qm31_add(e25, e26);
    e26 = stwo_load_qm31(ext_params, 56u);
    e25 = StwoCudaQm31{ b36, b42, b42, b42 };
    e24 = stwo_qm31_mul(e26, e25);
    e25 = stwo_qm31_add(e13, e24);
    e24 = stwo_load_qm31(ext_params, 57u);
    e13 = stwo_qm31_add(e25, e24);
    e24 = stwo_load_qm31(ext_params, 58u);
    e25 = stwo_qm31_add(e13, e24);
    e24 = stwo_load_qm31(ext_params, 59u);
    e13 = stwo_qm31_add(e25, e24);
    e24 = stwo_load_qm31(ext_params, 60u);
    e25 = stwo_qm31_add(e13, e24);
    e24 = stwo_load_qm31(ext_params, 61u);
    e13 = stwo_qm31_add(e25, e24);
    e24 = stwo_load_qm31(ext_params, 62u);
    e25 = stwo_qm31_add(e13, e24);
    e24 = stwo_load_qm31(ext_params, 63u);
    e13 = stwo_qm31_add(e25, e24);
    e24 = stwo_load_qm31(ext_params, 64u);
    e25 = stwo_qm31_add(e13, e24);
    e24 = stwo_load_qm31(ext_params, 65u);
    e13 = stwo_qm31_add(e25, e24);
    e24 = stwo_load_qm31(ext_params, 66u);
    e25 = stwo_qm31_add(e13, e24);
    e24 = stwo_load_qm31(ext_params, 67u);
    e13 = stwo_qm31_add(e25, e24);
    e24 = stwo_load_qm31(ext_params, 68u);
    e25 = stwo_qm31_add(e13, e24);
    e24 = stwo_load_qm31(ext_params, 69u);
    e13 = stwo_qm31_add(e25, e24);
    e24 = stwo_load_qm31(ext_params, 70u);
    e25 = stwo_qm31_add(e13, e24);
    e24 = stwo_load_qm31(ext_params, 71u);
    e13 = stwo_qm31_add(e25, e24);
    e24 = stwo_load_qm31(ext_params, 72u);
    e25 = stwo_qm31_add(e13, e24);
    e24 = stwo_load_qm31(ext_params, 73u);
    e13 = stwo_qm31_add(e25, e24);
    e24 = stwo_load_qm31(ext_params, 74u);
    e25 = stwo_qm31_add(e13, e24);
    e24 = stwo_load_qm31(ext_params, 75u);
    e13 = stwo_qm31_add(e25, e24);
    e24 = stwo_load_qm31(ext_params, 76u);
    e25 = stwo_qm31_add(e13, e24);
    e24 = stwo_load_qm31(ext_params, 77u);
    e13 = stwo_qm31_add(e25, e24);
    e24 = stwo_load_qm31(ext_params, 78u);
    e25 = stwo_qm31_add(e13, e24);
    e24 = stwo_load_qm31(ext_params, 79u);
    e13 = stwo_qm31_add(e25, e24);
    e24 = stwo_load_qm31(ext_params, 80u);
    e25 = stwo_qm31_add(e13, e24);
    e24 = stwo_load_qm31(ext_params, 81u);
    e13 = stwo_qm31_sub(e25, e24);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 173u, row_index, 0);
    unsigned b150 = stwo_m31_mul(b38, b38);
    unsigned b151 = stwo_m31_sub(b150, b38);
    e24 = StwoCudaQm31{ b151, b42, b42, b42 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e24, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));
    e25 = stwo_load_qm31(ext_params, 906u);
    e26 = stwo_qm31_mul(e7, e25);
    e25 = stwo_load_qm31(ext_params, 907u);
    StwoCudaQm31 e27 = stwo_qm31_mul(e6, e25);
    e25 = stwo_qm31_add(e26, e27);
    e27 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 908u);
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_load_qm31(ext_params, 909u);
    e26 = stwo_qm31_mul(e12, e7);
    e7 = stwo_qm31_add(e6, e26);
    e26 = stwo_qm31_mul(e12, e8);
    e8 = stwo_load_qm31(ext_params, 910u);
    e12 = stwo_qm31_mul(e16, e8);
    e8 = stwo_load_qm31(ext_params, 911u);
    e6 = stwo_qm31_mul(e17, e8);
    e8 = stwo_qm31_add(e12, e6);
    e6 = stwo_qm31_mul(e17, e16);
    e16 = stwo_load_qm31(ext_params, 912u);
    e17 = stwo_qm31_mul(e23, e16);
    e16 = stwo_load_qm31(ext_params, 913u);
    e12 = stwo_qm31_mul(e21, e16);
    e16 = stwo_qm31_add(e17, e12);
    e12 = stwo_qm31_mul(e21, e23);
    e23 = stwo_load_qm31(ext_params, 914u);
    e21 = stwo_qm31_mul(e13, e23);
    e23 = stwo_load_qm31(ext_params, 915u);
    e17 = stwo_qm31_mul(e22, e23);
    e23 = stwo_qm31_add(e21, e17);
    e17 = stwo_qm31_mul(e22, e13);
    unsigned b152 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b153 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b154 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b155 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e13 = StwoCudaQm31{ b152, b153, b154, b155 };
    e22 = stwo_qm31_mul(e13, e27);
    e27 = stwo_qm31_sub(e22, e25);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e27, stwo_load_qm31(random_coeff_powers, rc_base + 15u)));
    unsigned b156 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b157 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b158 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b159 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e22 = StwoCudaQm31{ b156, b157, b158, b159 };
    e25 = stwo_qm31_sub(e22, e13);
    e13 = stwo_qm31_mul(e25, e26);
    e25 = stwo_qm31_sub(e13, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e25, stwo_load_qm31(random_coeff_powers, rc_base + 16u)));
    unsigned b160 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b161 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b162 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b163 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e13 = StwoCudaQm31{ b160, b161, b162, b163 };
    e7 = stwo_qm31_sub(e13, e22);
    e22 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e22, e8);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 17u)));
    unsigned b164 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b165 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b166 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b167 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e22 = StwoCudaQm31{ b164, b165, b166, b167 };
    e8 = stwo_qm31_sub(e22, e13);
    e13 = stwo_qm31_mul(e8, e12);
    e8 = stwo_qm31_sub(e13, e16);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 18u)));
    unsigned b168 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, 0);
    unsigned b169 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, 0);
    unsigned b170 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, 0);
    unsigned b171 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, 0);
    e13 = StwoCudaQm31{ b168, b169, b170, b171 };
    e16 = stwo_qm31_sub(e13, e22);
    e13 = stwo_qm31_mul(e16, e17);
    e16 = stwo_qm31_sub(e13, e23);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 19u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
