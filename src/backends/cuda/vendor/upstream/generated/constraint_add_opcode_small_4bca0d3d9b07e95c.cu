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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_1a63cf0f7d9ca3f7(
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
    unsigned b38 = base_params[0u];
    unsigned b39 = stwo_m31_sub(b38, b6);
    unsigned b40 = stwo_m31_mul(b6, b39);
    unsigned b41 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b40, b41, b41, b41 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b42 = base_params[2u];
    unsigned b43 = stwo_m31_sub(b42, b7);
    unsigned b44 = stwo_m31_mul(b7, b43);
    StwoCudaQm31 e1 = StwoCudaQm31{ b44, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b45 = base_params[3u];
    unsigned b46 = stwo_m31_sub(b45, b8);
    unsigned b47 = stwo_m31_mul(b8, b46);
    StwoCudaQm31 e2 = StwoCudaQm31{ b47, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b48 = base_params[4u];
    unsigned b49 = stwo_m31_sub(b48, b9);
    unsigned b50 = stwo_m31_mul(b9, b49);
    StwoCudaQm31 e3 = StwoCudaQm31{ b50, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b51 = base_params[5u];
    unsigned b52 = stwo_m31_sub(b51, b8);
    unsigned b53 = stwo_m31_sub(b52, b9);
    unsigned b54 = base_params[6u];
    unsigned b55 = stwo_m31_sub(b54, b53);
    unsigned b56 = stwo_m31_mul(b53, b55);
    StwoCudaQm31 e4 = StwoCudaQm31{ b56, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b57 = base_params[7u];
    unsigned b58 = stwo_m31_sub(b57, b10);
    unsigned b59 = stwo_m31_mul(b10, b58);
    StwoCudaQm31 e5 = StwoCudaQm31{ b59, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    StwoCudaQm31 e6 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    StwoCudaQm31 e7 = StwoCudaQm31{ b0, b41, b41, b41 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 1u);
    e6 = stwo_qm31_add(e7, e8);
    e7 = stwo_load_qm31(ext_params, 2u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e8 = StwoCudaQm31{ b3, b41, b41, b41 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 3u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e6 = StwoCudaQm31{ b4, b41, b41, b41 };
    e7 = stwo_qm31_mul(e9, e6);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 4u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e8 = StwoCudaQm31{ b5, b41, b41, b41 };
    e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 5u);
    unsigned b60 = base_params[8u];
    unsigned b61 = stwo_m31_mul(b6, b60);
    unsigned b62 = base_params[9u];
    unsigned b63 = stwo_m31_mul(b7, b62);
    unsigned b64 = stwo_m31_add(b61, b63);
    unsigned b65 = base_params[10u];
    unsigned b66 = stwo_m31_mul(b8, b65);
    unsigned b67 = stwo_m31_add(b64, b66);
    unsigned b68 = base_params[11u];
    unsigned b69 = stwo_m31_mul(b9, b68);
    unsigned b70 = stwo_m31_add(b67, b69);
    unsigned b71 = base_params[12u];
    unsigned b72 = stwo_m31_mul(b53, b71);
    unsigned b73 = stwo_m31_add(b70, b72);
    unsigned b74 = base_params[13u];
    unsigned b75 = stwo_m31_add(b73, b74);
    e6 = StwoCudaQm31{ b75, b41, b41, b41 };
    e7 = stwo_qm31_mul(e9, e6);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 6u);
    unsigned b76 = base_params[14u];
    unsigned b77 = stwo_m31_mul(b10, b76);
    unsigned b78 = base_params[15u];
    unsigned b79 = stwo_m31_add(b77, b78);
    e8 = StwoCudaQm31{ b79, b41, b41, b41 };
    e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 7u);
    e6 = stwo_qm31_sub(e8, e9);
    unsigned b86 = base_params[19u];
    unsigned b84 = base_params[18u];
    unsigned b85 = stwo_m31_sub(b5, b84);
    unsigned b87 = stwo_m31_sub(b86, b85);
    unsigned b88 = stwo_m31_mul(b8, b87);
    e9 = StwoCudaQm31{ b88, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b89 = stwo_m31_mul(b6, b2);
    unsigned b90 = base_params[20u];
    unsigned b91 = stwo_m31_sub(b90, b6);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    unsigned b92 = stwo_m31_mul(b91, b1);
    unsigned b93 = stwo_m31_add(b89, b92);
    unsigned b94 = stwo_m31_sub(b11, b93);
    e8 = StwoCudaQm31{ b94, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b95 = stwo_m31_mul(b7, b2);
    unsigned b96 = base_params[21u];
    unsigned b97 = stwo_m31_sub(b96, b7);
    unsigned b98 = stwo_m31_mul(b97, b1);
    unsigned b99 = stwo_m31_add(b95, b98);
    unsigned b100 = stwo_m31_sub(b12, b99);
    e7 = StwoCudaQm31{ b100, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    unsigned b101 = stwo_m31_mul(b8, b0);
    unsigned b102 = stwo_m31_mul(b9, b2);
    unsigned b103 = stwo_m31_add(b101, b102);
    unsigned b104 = stwo_m31_mul(b53, b1);
    unsigned b105 = stwo_m31_add(b103, b104);
    unsigned b106 = stwo_m31_sub(b13, b105);
    StwoCudaQm31 e10 = StwoCudaQm31{ b106, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    StwoCudaQm31 e11 = stwo_load_qm31(ext_params, 8u);
    unsigned b80 = base_params[16u];
    unsigned b81 = stwo_m31_sub(b3, b80);
    unsigned b107 = stwo_m31_add(b11, b81);
    StwoCudaQm31 e12 = StwoCudaQm31{ b107, b41, b41, b41 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e11, e12);
    e12 = stwo_load_qm31(ext_params, 9u);
    e11 = stwo_qm31_add(e12, e13);
    e12 = stwo_load_qm31(ext_params, 10u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    e13 = StwoCudaQm31{ b14, b41, b41, b41 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e12, e13);
    e13 = stwo_qm31_add(e11, e14);
    e14 = stwo_load_qm31(ext_params, 11u);
    e11 = stwo_qm31_sub(e13, e14);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b108 = base_params[22u];
    unsigned b109 = stwo_m31_sub(b15, b108);
    unsigned b110 = stwo_m31_mul(b15, b109);
    e14 = StwoCudaQm31{ b110, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b111 = base_params[23u];
    unsigned b112 = stwo_m31_sub(b16, b111);
    unsigned b113 = stwo_m31_mul(b16, b112);
    e13 = StwoCudaQm31{ b113, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b114 = base_params[24u];
    unsigned b115 = stwo_m31_sub(b15, b114);
    unsigned b116 = stwo_m31_mul(b16, b115);
    e12 = StwoCudaQm31{ b116, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    unsigned b126 = base_params[29u];
    unsigned b127 = stwo_m31_sub(b126, b21);
    unsigned b128 = stwo_m31_mul(b21, b127);
    unsigned b129 = base_params[30u];
    unsigned b130 = stwo_m31_mul(b128, b129);
    StwoCudaQm31 e15 = StwoCudaQm31{ b130, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    unsigned b131 = base_params[31u];
    unsigned b132 = stwo_m31_mul(b21, b131);
    unsigned b133 = stwo_m31_sub(b20, b132);
    unsigned b134 = base_params[32u];
    unsigned b135 = stwo_m31_sub(b134, b133);
    unsigned b136 = stwo_m31_mul(b133, b135);
    unsigned b137 = base_params[33u];
    unsigned b138 = stwo_m31_mul(b136, b137);
    StwoCudaQm31 e16 = StwoCudaQm31{ b138, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));
    StwoCudaQm31 e17 = stwo_load_qm31(ext_params, 12u);
    StwoCudaQm31 e18 = StwoCudaQm31{ b14, b41, b41, b41 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e17, e18);
    e18 = stwo_load_qm31(ext_params, 13u);
    e17 = stwo_qm31_add(e18, e19);
    e18 = stwo_load_qm31(ext_params, 14u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    e19 = StwoCudaQm31{ b17, b41, b41, b41 };
    StwoCudaQm31 e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 15u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    e17 = StwoCudaQm31{ b18, b41, b41, b41 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 16u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    e19 = StwoCudaQm31{ b19, b41, b41, b41 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 17u);
    unsigned b117 = base_params[25u];
    unsigned b118 = stwo_m31_mul(b16, b117);
    unsigned b139 = stwo_m31_add(b20, b118);
    e17 = StwoCudaQm31{ b139, b41, b41, b41 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 18u);
    unsigned b119 = base_params[26u];
    unsigned b120 = stwo_m31_mul(b16, b119);
    e19 = StwoCudaQm31{ b120, b41, b41, b41 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 19u);
    e17 = StwoCudaQm31{ b120, b41, b41, b41 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 20u);
    e19 = StwoCudaQm31{ b120, b41, b41, b41 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 21u);
    e17 = StwoCudaQm31{ b120, b41, b41, b41 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 22u);
    e19 = StwoCudaQm31{ b120, b41, b41, b41 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 23u);
    e17 = StwoCudaQm31{ b120, b41, b41, b41 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 24u);
    e19 = StwoCudaQm31{ b120, b41, b41, b41 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 25u);
    e17 = StwoCudaQm31{ b120, b41, b41, b41 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 26u);
    e19 = StwoCudaQm31{ b120, b41, b41, b41 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 27u);
    e17 = StwoCudaQm31{ b120, b41, b41, b41 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 28u);
    e19 = StwoCudaQm31{ b120, b41, b41, b41 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 29u);
    e17 = StwoCudaQm31{ b120, b41, b41, b41 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 30u);
    e19 = StwoCudaQm31{ b120, b41, b41, b41 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 31u);
    e17 = StwoCudaQm31{ b120, b41, b41, b41 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 32u);
    e19 = StwoCudaQm31{ b120, b41, b41, b41 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 33u);
    e17 = StwoCudaQm31{ b120, b41, b41, b41 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 34u);
    e19 = StwoCudaQm31{ b120, b41, b41, b41 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(ext_params, 35u);
    unsigned b121 = base_params[27u];
    unsigned b122 = stwo_m31_mul(b15, b121);
    unsigned b123 = stwo_m31_sub(b122, b16);
    e17 = StwoCudaQm31{ b123, b41, b41, b41 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 36u);
    e19 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(ext_params, 37u);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 38u);
    e19 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(ext_params, 39u);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 40u);
    e19 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(ext_params, 41u);
    unsigned b124 = base_params[28u];
    unsigned b125 = stwo_m31_mul(b15, b124);
    e17 = StwoCudaQm31{ b125, b41, b41, b41 };
    e20 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e19, e20);
    e20 = stwo_load_qm31(ext_params, 42u);
    e19 = stwo_qm31_sub(e17, e20);
    e20 = stwo_load_qm31(ext_params, 43u);
    unsigned b82 = base_params[17u];
    unsigned b83 = stwo_m31_sub(b4, b82);
    unsigned b153 = stwo_m31_add(b12, b83);
    e17 = StwoCudaQm31{ b153, b41, b41, b41 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_load_qm31(ext_params, 44u);
    e20 = stwo_qm31_add(e17, e18);
    e17 = stwo_load_qm31(ext_params, 45u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    e18 = StwoCudaQm31{ b22, b41, b41, b41 };
    StwoCudaQm31 e21 = stwo_qm31_mul(e17, e18);
    e18 = stwo_qm31_add(e20, e21);
    e21 = stwo_load_qm31(ext_params, 46u);
    e20 = stwo_qm31_sub(e18, e21);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    unsigned b154 = base_params[38u];
    unsigned b155 = stwo_m31_sub(b23, b154);
    unsigned b156 = stwo_m31_mul(b23, b155);
    e21 = StwoCudaQm31{ b156, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e21, stwo_load_qm31(random_coeff_powers, rc_base + 15u)));
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    unsigned b157 = base_params[39u];
    unsigned b158 = stwo_m31_sub(b24, b157);
    unsigned b159 = stwo_m31_mul(b24, b158);
    e18 = StwoCudaQm31{ b159, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 16u)));
    unsigned b160 = base_params[40u];
    unsigned b161 = stwo_m31_sub(b23, b160);
    unsigned b162 = stwo_m31_mul(b24, b161);
    e17 = StwoCudaQm31{ b162, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 17u)));
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    unsigned b163 = base_params[45u];
    unsigned b164 = stwo_m31_sub(b163, b29);
    unsigned b165 = stwo_m31_mul(b29, b164);
    unsigned b166 = base_params[46u];
    unsigned b167 = stwo_m31_mul(b165, b166);
    StwoCudaQm31 e22 = StwoCudaQm31{ b167, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e22, stwo_load_qm31(random_coeff_powers, rc_base + 18u)));
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    unsigned b168 = base_params[47u];
    unsigned b169 = stwo_m31_mul(b29, b168);
    unsigned b170 = stwo_m31_sub(b28, b169);
    unsigned b171 = base_params[48u];
    unsigned b172 = stwo_m31_sub(b171, b170);
    unsigned b173 = stwo_m31_mul(b170, b172);
    unsigned b174 = base_params[49u];
    unsigned b175 = stwo_m31_mul(b173, b174);
    StwoCudaQm31 e23 = StwoCudaQm31{ b175, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e23, stwo_load_qm31(random_coeff_powers, rc_base + 19u)));
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    unsigned b189 = base_params[54u];
    unsigned b190 = stwo_m31_sub(b30, b189);
    unsigned b191 = stwo_m31_mul(b30, b190);
    StwoCudaQm31 e24 = StwoCudaQm31{ b191, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e24, stwo_load_qm31(random_coeff_powers, rc_base + 20u)));
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    unsigned b192 = base_params[55u];
    unsigned b193 = stwo_m31_sub(b31, b192);
    unsigned b194 = stwo_m31_mul(b31, b193);
    StwoCudaQm31 e25 = StwoCudaQm31{ b194, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e25, stwo_load_qm31(random_coeff_powers, rc_base + 21u)));
    unsigned b195 = base_params[56u];
    unsigned b196 = stwo_m31_sub(b30, b195);
    unsigned b197 = stwo_m31_mul(b31, b196);
    StwoCudaQm31 e26 = StwoCudaQm31{ b197, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e26, stwo_load_qm31(random_coeff_powers, rc_base + 22u)));
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    unsigned b198 = base_params[61u];
    unsigned b199 = stwo_m31_sub(b198, b36);
    unsigned b200 = stwo_m31_mul(b36, b199);
    unsigned b201 = base_params[62u];
    unsigned b202 = stwo_m31_mul(b200, b201);
    StwoCudaQm31 e27 = StwoCudaQm31{ b202, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e27, stwo_load_qm31(random_coeff_powers, rc_base + 23u)));
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    unsigned b203 = base_params[63u];
    unsigned b204 = stwo_m31_mul(b36, b203);
    unsigned b205 = stwo_m31_sub(b35, b204);
    unsigned b206 = base_params[64u];
    unsigned b207 = stwo_m31_sub(b206, b205);
    unsigned b208 = stwo_m31_mul(b205, b207);
    unsigned b209 = base_params[65u];
    unsigned b210 = stwo_m31_mul(b208, b209);
    StwoCudaQm31 e28 = StwoCudaQm31{ b210, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e28, stwo_load_qm31(random_coeff_powers, rc_base + 24u)));
    unsigned b140 = base_params[34u];
    unsigned b141 = stwo_m31_mul(b18, b140);
    unsigned b142 = stwo_m31_add(b17, b141);
    unsigned b143 = base_params[35u];
    unsigned b144 = stwo_m31_mul(b19, b143);
    unsigned b145 = stwo_m31_add(b142, b144);
    unsigned b146 = base_params[36u];
    unsigned b147 = stwo_m31_mul(b20, b146);
    unsigned b148 = stwo_m31_add(b145, b147);
    unsigned b149 = stwo_m31_sub(b148, b15);
    unsigned b150 = base_params[37u];
    unsigned b151 = stwo_m31_mul(b150, b16);
    unsigned b152 = stwo_m31_sub(b149, b151);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    unsigned b176 = base_params[50u];
    unsigned b177 = stwo_m31_mul(b26, b176);
    unsigned b178 = stwo_m31_add(b25, b177);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    unsigned b179 = base_params[51u];
    unsigned b180 = stwo_m31_mul(b27, b179);
    unsigned b181 = stwo_m31_add(b178, b180);
    unsigned b182 = base_params[52u];
    unsigned b183 = stwo_m31_mul(b28, b182);
    unsigned b184 = stwo_m31_add(b181, b183);
    unsigned b185 = stwo_m31_sub(b184, b23);
    unsigned b186 = base_params[53u];
    unsigned b187 = stwo_m31_mul(b186, b24);
    unsigned b188 = stwo_m31_sub(b185, b187);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    unsigned b211 = base_params[66u];
    unsigned b212 = stwo_m31_mul(b33, b211);
    unsigned b213 = stwo_m31_add(b32, b212);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    unsigned b214 = base_params[67u];
    unsigned b215 = stwo_m31_mul(b34, b214);
    unsigned b216 = stwo_m31_add(b213, b215);
    unsigned b217 = base_params[68u];
    unsigned b218 = stwo_m31_mul(b35, b217);
    unsigned b219 = stwo_m31_add(b216, b218);
    unsigned b220 = stwo_m31_sub(b219, b30);
    unsigned b221 = base_params[69u];
    unsigned b222 = stwo_m31_mul(b221, b31);
    unsigned b223 = stwo_m31_sub(b220, b222);
    unsigned b224 = stwo_m31_add(b188, b223);
    unsigned b225 = stwo_m31_sub(b152, b224);
    StwoCudaQm31 e29 = StwoCudaQm31{ b225, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e29, stwo_load_qm31(random_coeff_powers, rc_base + 25u)));
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    unsigned b226 = stwo_m31_mul(b37, b37);
    unsigned b227 = stwo_m31_sub(b226, b37);
    StwoCudaQm31 e30 = StwoCudaQm31{ b227, b41, b41, b41 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e30, stwo_load_qm31(random_coeff_powers, rc_base + 26u)));
    StwoCudaQm31 e31 = stwo_load_qm31(ext_params, 123u);
    StwoCudaQm31 e32 = stwo_qm31_mul(e11, e31);
    e31 = stwo_load_qm31(ext_params, 124u);
    StwoCudaQm31 e33 = stwo_qm31_mul(e6, e31);
    e31 = stwo_qm31_add(e32, e33);
    e33 = stwo_qm31_mul(e6, e11);
    e11 = stwo_load_qm31(ext_params, 125u);
    e6 = stwo_qm31_mul(e20, e11);
    e11 = stwo_load_qm31(ext_params, 126u);
    e32 = stwo_qm31_mul(e19, e11);
    e11 = stwo_qm31_add(e6, e32);
    e32 = stwo_qm31_mul(e19, e20);
    unsigned b228 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b229 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b230 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b231 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e20 = StwoCudaQm31{ b228, b229, b230, b231 };
    e19 = stwo_qm31_mul(e20, e33);
    e33 = stwo_qm31_sub(e19, e31);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e33, stwo_load_qm31(random_coeff_powers, rc_base + 27u)));
    unsigned b232 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b233 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b234 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b235 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e19 = StwoCudaQm31{ b232, b233, b234, b235 };
    e31 = stwo_qm31_sub(e19, e20);
    e19 = stwo_qm31_mul(e31, e32);
    e31 = stwo_qm31_sub(e19, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e31, stwo_load_qm31(random_coeff_powers, rc_base + 28u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
