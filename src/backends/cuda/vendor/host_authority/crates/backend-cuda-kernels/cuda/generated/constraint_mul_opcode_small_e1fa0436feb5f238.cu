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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_cd39bbe85e628f10(
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
    unsigned b37 = base_params[0u];
    unsigned b38 = stwo_m31_sub(b37, b6);
    unsigned b39 = stwo_m31_mul(b6, b38);
    unsigned b40 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b39, b40, b40, b40 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b41 = base_params[2u];
    unsigned b42 = stwo_m31_sub(b41, b7);
    unsigned b43 = stwo_m31_mul(b7, b42);
    StwoCudaQm31 e1 = StwoCudaQm31{ b43, b40, b40, b40 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b44 = base_params[3u];
    unsigned b45 = stwo_m31_sub(b44, b8);
    unsigned b46 = stwo_m31_mul(b8, b45);
    StwoCudaQm31 e2 = StwoCudaQm31{ b46, b40, b40, b40 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b47 = base_params[4u];
    unsigned b48 = stwo_m31_sub(b47, b9);
    unsigned b49 = stwo_m31_mul(b9, b48);
    StwoCudaQm31 e3 = StwoCudaQm31{ b49, b40, b40, b40 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b50 = base_params[5u];
    unsigned b51 = stwo_m31_sub(b50, b8);
    unsigned b52 = stwo_m31_sub(b51, b9);
    unsigned b53 = base_params[6u];
    unsigned b54 = stwo_m31_sub(b53, b52);
    unsigned b55 = stwo_m31_mul(b52, b54);
    StwoCudaQm31 e4 = StwoCudaQm31{ b55, b40, b40, b40 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b56 = base_params[7u];
    unsigned b57 = stwo_m31_sub(b56, b10);
    unsigned b58 = stwo_m31_mul(b10, b57);
    StwoCudaQm31 e5 = StwoCudaQm31{ b58, b40, b40, b40 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    StwoCudaQm31 e6 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    StwoCudaQm31 e7 = StwoCudaQm31{ b0, b40, b40, b40 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 1u);
    e6 = stwo_qm31_add(e7, e8);
    e7 = stwo_load_qm31(ext_params, 2u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e8 = StwoCudaQm31{ b3, b40, b40, b40 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 3u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e6 = StwoCudaQm31{ b4, b40, b40, b40 };
    e7 = stwo_qm31_mul(e9, e6);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 4u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e8 = StwoCudaQm31{ b5, b40, b40, b40 };
    e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 5u);
    unsigned b59 = base_params[8u];
    unsigned b60 = stwo_m31_mul(b6, b59);
    unsigned b61 = base_params[9u];
    unsigned b62 = stwo_m31_mul(b7, b61);
    unsigned b63 = stwo_m31_add(b60, b62);
    unsigned b64 = base_params[10u];
    unsigned b65 = stwo_m31_mul(b8, b64);
    unsigned b66 = stwo_m31_add(b63, b65);
    unsigned b67 = base_params[11u];
    unsigned b68 = stwo_m31_mul(b9, b67);
    unsigned b69 = stwo_m31_add(b66, b68);
    unsigned b70 = base_params[12u];
    unsigned b71 = stwo_m31_mul(b52, b70);
    unsigned b72 = stwo_m31_add(b69, b71);
    e6 = StwoCudaQm31{ b72, b40, b40, b40 };
    e7 = stwo_qm31_mul(e9, e6);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 6u);
    unsigned b75 = base_params[14u];
    unsigned b73 = base_params[13u];
    unsigned b74 = stwo_m31_mul(b10, b73);
    unsigned b76 = stwo_m31_add(b75, b74);
    unsigned b77 = base_params[15u];
    unsigned b78 = stwo_m31_add(b76, b77);
    e8 = StwoCudaQm31{ b78, b40, b40, b40 };
    e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 7u);
    e6 = stwo_qm31_sub(e8, e9);
    unsigned b85 = base_params[19u];
    unsigned b83 = base_params[18u];
    unsigned b84 = stwo_m31_sub(b5, b83);
    unsigned b86 = stwo_m31_sub(b85, b84);
    unsigned b87 = stwo_m31_mul(b8, b86);
    e9 = StwoCudaQm31{ b87, b40, b40, b40 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b88 = stwo_m31_mul(b6, b2);
    unsigned b89 = base_params[20u];
    unsigned b90 = stwo_m31_sub(b89, b6);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    unsigned b91 = stwo_m31_mul(b90, b1);
    unsigned b92 = stwo_m31_add(b88, b91);
    unsigned b93 = stwo_m31_sub(b11, b92);
    e8 = StwoCudaQm31{ b93, b40, b40, b40 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b94 = stwo_m31_mul(b7, b2);
    unsigned b95 = base_params[21u];
    unsigned b96 = stwo_m31_sub(b95, b7);
    unsigned b97 = stwo_m31_mul(b96, b1);
    unsigned b98 = stwo_m31_add(b94, b97);
    unsigned b99 = stwo_m31_sub(b12, b98);
    e7 = StwoCudaQm31{ b99, b40, b40, b40 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    unsigned b100 = stwo_m31_mul(b8, b0);
    unsigned b101 = stwo_m31_mul(b9, b2);
    unsigned b102 = stwo_m31_add(b100, b101);
    unsigned b103 = stwo_m31_mul(b52, b1);
    unsigned b104 = stwo_m31_add(b102, b103);
    unsigned b105 = stwo_m31_sub(b13, b104);
    StwoCudaQm31 e10 = StwoCudaQm31{ b105, b40, b40, b40 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    StwoCudaQm31 e11 = stwo_load_qm31(ext_params, 8u);
    unsigned b79 = base_params[16u];
    unsigned b80 = stwo_m31_sub(b3, b79);
    unsigned b106 = stwo_m31_add(b11, b80);
    StwoCudaQm31 e12 = StwoCudaQm31{ b106, b40, b40, b40 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e11, e12);
    e12 = stwo_load_qm31(ext_params, 9u);
    e11 = stwo_qm31_add(e12, e13);
    e12 = stwo_load_qm31(ext_params, 10u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    e13 = StwoCudaQm31{ b14, b40, b40, b40 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e12, e13);
    e13 = stwo_qm31_add(e11, e14);
    e14 = stwo_load_qm31(ext_params, 11u);
    e11 = stwo_qm31_sub(e13, e14);
    e14 = stwo_load_qm31(ext_params, 12u);
    e13 = StwoCudaQm31{ b14, b40, b40, b40 };
    e12 = stwo_qm31_mul(e14, e13);
    e13 = stwo_load_qm31(ext_params, 13u);
    e14 = stwo_qm31_add(e13, e12);
    e13 = stwo_load_qm31(ext_params, 14u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    e12 = StwoCudaQm31{ b15, b40, b40, b40 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 15u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    e14 = StwoCudaQm31{ b16, b40, b40, b40 };
    e13 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 16u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    e12 = StwoCudaQm31{ b17, b40, b40, b40 };
    e15 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 17u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    e14 = StwoCudaQm31{ b18, b40, b40, b40 };
    e13 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 18u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    e12 = StwoCudaQm31{ b19, b40, b40, b40 };
    e15 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 19u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    e14 = StwoCudaQm31{ b20, b40, b40, b40 };
    e13 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 20u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    e12 = StwoCudaQm31{ b21, b40, b40, b40 };
    e15 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 21u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    e14 = StwoCudaQm31{ b22, b40, b40, b40 };
    e13 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 22u);
    e12 = stwo_qm31_sub(e14, e13);
    e13 = stwo_load_qm31(ext_params, 23u);
    unsigned b81 = base_params[17u];
    unsigned b82 = stwo_m31_sub(b4, b81);
    unsigned b107 = stwo_m31_add(b12, b82);
    e14 = StwoCudaQm31{ b107, b40, b40, b40 };
    e15 = stwo_qm31_mul(e13, e14);
    e14 = stwo_load_qm31(ext_params, 24u);
    e13 = stwo_qm31_add(e14, e15);
    e14 = stwo_load_qm31(ext_params, 25u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    e15 = StwoCudaQm31{ b23, b40, b40, b40 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 26u);
    e13 = stwo_qm31_sub(e15, e16);
    e16 = stwo_load_qm31(ext_params, 27u);
    e15 = StwoCudaQm31{ b23, b40, b40, b40 };
    e14 = stwo_qm31_mul(e16, e15);
    e15 = stwo_load_qm31(ext_params, 28u);
    e16 = stwo_qm31_add(e15, e14);
    e15 = stwo_load_qm31(ext_params, 29u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    e14 = StwoCudaQm31{ b24, b40, b40, b40 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 30u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    e16 = StwoCudaQm31{ b25, b40, b40, b40 };
    e15 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 31u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    e14 = StwoCudaQm31{ b26, b40, b40, b40 };
    e17 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 32u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    e16 = StwoCudaQm31{ b27, b40, b40, b40 };
    e15 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 33u);
    e14 = stwo_qm31_sub(e16, e15);
    e15 = stwo_load_qm31(ext_params, 34u);
    unsigned b108 = stwo_m31_add(b13, b84);
    e16 = StwoCudaQm31{ b108, b40, b40, b40 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_load_qm31(ext_params, 35u);
    e15 = stwo_qm31_add(e16, e17);
    e16 = stwo_load_qm31(ext_params, 36u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    e17 = StwoCudaQm31{ b28, b40, b40, b40 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e16, e17);
    e17 = stwo_qm31_add(e15, e18);
    e18 = stwo_load_qm31(ext_params, 37u);
    e15 = stwo_qm31_sub(e17, e18);
    e18 = stwo_load_qm31(ext_params, 38u);
    e17 = StwoCudaQm31{ b28, b40, b40, b40 };
    e16 = stwo_qm31_mul(e18, e17);
    e17 = stwo_load_qm31(ext_params, 39u);
    e18 = stwo_qm31_add(e17, e16);
    e17 = stwo_load_qm31(ext_params, 40u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    e16 = StwoCudaQm31{ b29, b40, b40, b40 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(ext_params, 41u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    e18 = StwoCudaQm31{ b30, b40, b40, b40 };
    e17 = stwo_qm31_mul(e19, e18);
    e18 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 42u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    e16 = StwoCudaQm31{ b31, b40, b40, b40 };
    e19 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(ext_params, 43u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    e18 = StwoCudaQm31{ b32, b40, b40, b40 };
    e17 = stwo_qm31_mul(e19, e18);
    e18 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 44u);
    e16 = stwo_qm31_sub(e18, e17);
    e17 = stwo_load_qm31(ext_params, 45u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    e18 = StwoCudaQm31{ b33, b40, b40, b40 };
    e19 = stwo_qm31_mul(e17, e18);
    e18 = stwo_load_qm31(ext_params, 46u);
    e17 = stwo_qm31_add(e18, e19);
    e18 = stwo_load_qm31(ext_params, 47u);
    e19 = stwo_qm31_sub(e17, e18);
    unsigned b109 = base_params[22u];
    unsigned b110 = stwo_m31_mul(b33, b109);
    unsigned b111 = stwo_m31_mul(b24, b29);
    unsigned b112 = stwo_m31_sub(b111, b15);
    unsigned b113 = stwo_m31_mul(b24, b30);
    unsigned b114 = stwo_m31_mul(b25, b29);
    unsigned b115 = stwo_m31_add(b113, b114);
    unsigned b116 = stwo_m31_sub(b115, b16);
    unsigned b117 = base_params[23u];
    unsigned b118 = stwo_m31_mul(b116, b117);
    unsigned b119 = stwo_m31_add(b112, b118);
    unsigned b120 = stwo_m31_sub(b110, b119);
    e18 = StwoCudaQm31{ b120, b40, b40, b40 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    e17 = stwo_load_qm31(ext_params, 48u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    StwoCudaQm31 e20 = StwoCudaQm31{ b34, b40, b40, b40 };
    StwoCudaQm31 e21 = stwo_qm31_mul(e17, e20);
    e20 = stwo_load_qm31(ext_params, 49u);
    e17 = stwo_qm31_add(e20, e21);
    e20 = stwo_load_qm31(ext_params, 50u);
    e21 = stwo_qm31_sub(e17, e20);
    unsigned b121 = base_params[24u];
    unsigned b122 = stwo_m31_mul(b34, b121);
    unsigned b123 = stwo_m31_mul(b24, b31);
    unsigned b124 = stwo_m31_mul(b25, b30);
    unsigned b125 = stwo_m31_add(b123, b124);
    unsigned b126 = stwo_m31_mul(b26, b29);
    unsigned b127 = stwo_m31_add(b125, b126);
    unsigned b128 = stwo_m31_sub(b127, b17);
    unsigned b129 = stwo_m31_add(b33, b128);
    unsigned b130 = stwo_m31_mul(b24, b32);
    unsigned b131 = stwo_m31_mul(b25, b31);
    unsigned b132 = stwo_m31_add(b130, b131);
    unsigned b133 = stwo_m31_mul(b26, b30);
    unsigned b134 = stwo_m31_add(b132, b133);
    unsigned b135 = stwo_m31_mul(b27, b29);
    unsigned b136 = stwo_m31_add(b134, b135);
    unsigned b137 = stwo_m31_sub(b136, b18);
    unsigned b138 = base_params[25u];
    unsigned b139 = stwo_m31_mul(b137, b138);
    unsigned b140 = stwo_m31_add(b129, b139);
    unsigned b141 = stwo_m31_sub(b122, b140);
    e20 = StwoCudaQm31{ b141, b40, b40, b40 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e20, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    e17 = stwo_load_qm31(ext_params, 51u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    StwoCudaQm31 e22 = StwoCudaQm31{ b35, b40, b40, b40 };
    StwoCudaQm31 e23 = stwo_qm31_mul(e17, e22);
    e22 = stwo_load_qm31(ext_params, 52u);
    e17 = stwo_qm31_add(e22, e23);
    e22 = stwo_load_qm31(ext_params, 53u);
    e23 = stwo_qm31_sub(e17, e22);
    unsigned b142 = base_params[26u];
    unsigned b143 = stwo_m31_mul(b35, b142);
    unsigned b144 = stwo_m31_mul(b25, b32);
    unsigned b145 = stwo_m31_mul(b26, b31);
    unsigned b146 = stwo_m31_add(b144, b145);
    unsigned b147 = stwo_m31_mul(b27, b30);
    unsigned b148 = stwo_m31_add(b146, b147);
    unsigned b149 = stwo_m31_sub(b148, b19);
    unsigned b150 = stwo_m31_add(b34, b149);
    unsigned b151 = stwo_m31_mul(b26, b32);
    unsigned b152 = stwo_m31_mul(b27, b31);
    unsigned b153 = stwo_m31_add(b151, b152);
    unsigned b154 = stwo_m31_sub(b153, b20);
    unsigned b155 = base_params[27u];
    unsigned b156 = stwo_m31_mul(b154, b155);
    unsigned b157 = stwo_m31_add(b150, b156);
    unsigned b158 = stwo_m31_sub(b143, b157);
    e22 = StwoCudaQm31{ b158, b40, b40, b40 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e22, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b159 = stwo_m31_mul(b27, b32);
    unsigned b160 = stwo_m31_add(b35, b159);
    unsigned b161 = base_params[28u];
    unsigned b162 = stwo_m31_mul(b22, b161);
    unsigned b163 = stwo_m31_sub(b160, b162);
    unsigned b164 = stwo_m31_sub(b163, b21);
    e17 = StwoCudaQm31{ b164, b40, b40, b40 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    unsigned b165 = stwo_m31_mul(b36, b36);
    unsigned b166 = stwo_m31_sub(b165, b36);
    StwoCudaQm31 e24 = StwoCudaQm31{ b166, b40, b40, b40 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e24, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));
    StwoCudaQm31 e25 = stwo_load_qm31(ext_params, 64u);
    StwoCudaQm31 e26 = stwo_qm31_mul(e11, e25);
    e25 = stwo_load_qm31(ext_params, 65u);
    StwoCudaQm31 e27 = stwo_qm31_mul(e6, e25);
    e25 = stwo_qm31_add(e26, e27);
    e27 = stwo_qm31_mul(e6, e11);
    e11 = stwo_load_qm31(ext_params, 66u);
    e6 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(ext_params, 67u);
    e26 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e6, e26);
    e26 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(ext_params, 68u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(ext_params, 69u);
    e6 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e6);
    e6 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 70u);
    e14 = stwo_qm31_mul(e19, e15);
    e15 = stwo_load_qm31(ext_params, 71u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e19);
    e19 = stwo_load_qm31(ext_params, 72u);
    e16 = stwo_qm31_mul(e23, e19);
    e19 = stwo_load_qm31(ext_params, 73u);
    e14 = stwo_qm31_mul(e21, e19);
    e19 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e21, e23);
    unsigned b167 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b168 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b169 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b170 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e23 = StwoCudaQm31{ b167, b168, b169, b170 };
    e21 = stwo_qm31_mul(e23, e27);
    e27 = stwo_qm31_sub(e21, e25);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e27, stwo_load_qm31(random_coeff_powers, rc_base + 15u)));
    unsigned b171 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b172 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b173 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b174 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e21 = StwoCudaQm31{ b171, b172, b173, b174 };
    e25 = stwo_qm31_sub(e21, e23);
    e23 = stwo_qm31_mul(e25, e26);
    e25 = stwo_qm31_sub(e23, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e25, stwo_load_qm31(random_coeff_powers, rc_base + 16u)));
    unsigned b175 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b176 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b177 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b178 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e23 = StwoCudaQm31{ b175, b176, b177, b178 };
    e11 = stwo_qm31_sub(e23, e21);
    e21 = stwo_qm31_mul(e11, e6);
    e11 = stwo_qm31_sub(e21, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 17u)));
    unsigned b179 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b180 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b181 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b182 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e21 = StwoCudaQm31{ b179, b180, b181, b182 };
    e13 = stwo_qm31_sub(e21, e23);
    e23 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e23, e15);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 18u)));
    unsigned b183 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, 0);
    unsigned b184 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, 0);
    unsigned b185 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, 0);
    unsigned b186 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, 0);
    e23 = StwoCudaQm31{ b183, b184, b185, b186 };
    e15 = stwo_qm31_sub(e23, e21);
    e23 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e23, e19);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 19u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
