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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_30d7745cb2938e96(
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
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b46 = base_params[0u];
    unsigned b47 = stwo_m31_sub(b1, b46);
    unsigned b48 = stwo_m31_mul(b1, b47);
    unsigned b49 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b48, b49, b49, b49 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    unsigned b50 = stwo_m31_mul(b1, b0);
    StwoCudaQm31 e1 = StwoCudaQm31{ b50, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 54u, row_index, 0);
    unsigned b53 = base_params[10u];
    unsigned b54 = stwo_m31_sub(b53, b8);
    unsigned b55 = stwo_m31_mul(b8, b54);
    unsigned b56 = base_params[11u];
    unsigned b57 = stwo_m31_mul(b55, b56);
    StwoCudaQm31 e2 = StwoCudaQm31{ b57, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    unsigned b58 = base_params[12u];
    unsigned b59 = stwo_m31_mul(b8, b58);
    unsigned b60 = stwo_m31_sub(b7, b59);
    unsigned b61 = base_params[13u];
    unsigned b62 = stwo_m31_sub(b61, b60);
    unsigned b63 = stwo_m31_mul(b60, b62);
    unsigned b64 = base_params[14u];
    unsigned b65 = stwo_m31_mul(b63, b64);
    StwoCudaQm31 e3 = StwoCudaQm31{ b65, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 60u, row_index, 0);
    unsigned b66 = base_params[16u];
    unsigned b67 = stwo_m31_sub(b66, b13);
    unsigned b68 = stwo_m31_mul(b13, b67);
    unsigned b69 = base_params[17u];
    unsigned b70 = stwo_m31_mul(b68, b69);
    StwoCudaQm31 e4 = StwoCudaQm31{ b70, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    unsigned b71 = base_params[18u];
    unsigned b72 = stwo_m31_mul(b13, b71);
    unsigned b73 = stwo_m31_sub(b12, b72);
    unsigned b74 = base_params[19u];
    unsigned b75 = stwo_m31_sub(b74, b73);
    unsigned b76 = stwo_m31_mul(b73, b75);
    unsigned b77 = base_params[20u];
    unsigned b78 = stwo_m31_mul(b76, b77);
    StwoCudaQm31 e5 = StwoCudaQm31{ b78, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 66u, row_index, 0);
    unsigned b79 = base_params[22u];
    unsigned b80 = stwo_m31_sub(b79, b18);
    unsigned b81 = stwo_m31_mul(b18, b80);
    unsigned b82 = base_params[23u];
    unsigned b83 = stwo_m31_mul(b81, b82);
    StwoCudaQm31 e6 = StwoCudaQm31{ b83, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 65u, row_index, 0);
    unsigned b84 = base_params[24u];
    unsigned b85 = stwo_m31_mul(b18, b84);
    unsigned b86 = stwo_m31_sub(b17, b85);
    unsigned b87 = base_params[25u];
    unsigned b88 = stwo_m31_sub(b87, b86);
    unsigned b89 = stwo_m31_mul(b86, b88);
    unsigned b90 = base_params[26u];
    unsigned b91 = stwo_m31_mul(b89, b90);
    StwoCudaQm31 e7 = StwoCudaQm31{ b91, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 72u, row_index, 0);
    unsigned b92 = base_params[28u];
    unsigned b93 = stwo_m31_sub(b92, b23);
    unsigned b94 = stwo_m31_mul(b23, b93);
    unsigned b95 = base_params[29u];
    unsigned b96 = stwo_m31_mul(b94, b95);
    StwoCudaQm31 e8 = StwoCudaQm31{ b96, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 71u, row_index, 0);
    unsigned b97 = base_params[30u];
    unsigned b98 = stwo_m31_mul(b23, b97);
    unsigned b99 = stwo_m31_sub(b22, b98);
    unsigned b100 = base_params[31u];
    unsigned b101 = stwo_m31_sub(b100, b99);
    unsigned b102 = stwo_m31_mul(b99, b101);
    unsigned b103 = base_params[32u];
    unsigned b104 = stwo_m31_mul(b102, b103);
    StwoCudaQm31 e9 = StwoCudaQm31{ b104, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 78u, row_index, 0);
    unsigned b105 = base_params[34u];
    unsigned b106 = stwo_m31_sub(b105, b28);
    unsigned b107 = stwo_m31_mul(b28, b106);
    unsigned b108 = base_params[35u];
    unsigned b109 = stwo_m31_mul(b107, b108);
    StwoCudaQm31 e10 = StwoCudaQm31{ b109, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 77u, row_index, 0);
    unsigned b110 = base_params[36u];
    unsigned b111 = stwo_m31_mul(b28, b110);
    unsigned b112 = stwo_m31_sub(b27, b111);
    unsigned b113 = base_params[37u];
    unsigned b114 = stwo_m31_sub(b113, b112);
    unsigned b115 = stwo_m31_mul(b112, b114);
    unsigned b116 = base_params[38u];
    unsigned b117 = stwo_m31_mul(b115, b116);
    StwoCudaQm31 e11 = StwoCudaQm31{ b117, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 74u, row_index, 0);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 75u, row_index, 0);
    unsigned b118 = base_params[39u];
    unsigned b119 = stwo_m31_mul(b25, b118);
    unsigned b120 = stwo_m31_add(b24, b119);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 76u, row_index, 0);
    unsigned b121 = base_params[40u];
    unsigned b122 = stwo_m31_mul(b26, b121);
    unsigned b123 = stwo_m31_add(b120, b122);
    unsigned b124 = base_params[41u];
    unsigned b125 = stwo_m31_mul(b27, b124);
    unsigned b126 = stwo_m31_add(b123, b125);
    unsigned b127 = base_params[42u];
    unsigned b128 = stwo_m31_sub(b126, b127);
    unsigned b51 = base_params[2u];
    unsigned b52 = stwo_m31_sub(b1, b51);
    unsigned b138 = stwo_m31_mul(b128, b52);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 68u, row_index, 0);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 69u, row_index, 0);
    unsigned b139 = base_params[46u];
    unsigned b140 = stwo_m31_mul(b20, b139);
    unsigned b141 = stwo_m31_add(b19, b140);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 70u, row_index, 0);
    unsigned b142 = base_params[47u];
    unsigned b143 = stwo_m31_mul(b21, b142);
    unsigned b144 = stwo_m31_add(b141, b143);
    unsigned b145 = base_params[48u];
    unsigned b146 = stwo_m31_mul(b22, b145);
    unsigned b147 = stwo_m31_add(b144, b146);
    unsigned b148 = stwo_m31_sub(b128, b147);
    unsigned b149 = stwo_m31_mul(b138, b148);
    StwoCudaQm31 e12 = StwoCudaQm31{ b149, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    unsigned b129 = base_params[43u];
    unsigned b130 = stwo_m31_mul(b10, b129);
    unsigned b131 = stwo_m31_add(b9, b130);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    unsigned b132 = base_params[44u];
    unsigned b133 = stwo_m31_mul(b11, b132);
    unsigned b134 = stwo_m31_add(b131, b133);
    unsigned b135 = base_params[45u];
    unsigned b136 = stwo_m31_mul(b12, b135);
    unsigned b137 = stwo_m31_add(b134, b136);
    unsigned b150 = base_params[49u];
    unsigned b151 = stwo_m31_sub(b137, b150);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 62u, row_index, 0);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 63u, row_index, 0);
    unsigned b152 = base_params[50u];
    unsigned b153 = stwo_m31_mul(b15, b152);
    unsigned b154 = stwo_m31_add(b14, b153);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 64u, row_index, 0);
    unsigned b155 = base_params[51u];
    unsigned b156 = stwo_m31_mul(b16, b155);
    unsigned b157 = stwo_m31_add(b154, b156);
    unsigned b158 = base_params[52u];
    unsigned b159 = stwo_m31_mul(b17, b158);
    unsigned b160 = stwo_m31_add(b157, b159);
    unsigned b161 = stwo_m31_sub(b151, b160);
    unsigned b162 = stwo_m31_mul(b138, b161);
    StwoCudaQm31 e13 = StwoCudaQm31{ b162, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 79u, row_index, 0);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    unsigned b163 = stwo_m31_sub(b29, b6);
    unsigned b164 = stwo_m31_mul(b163, b138);
    StwoCudaQm31 e14 = StwoCudaQm31{ b164, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 80u, row_index, 0);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    unsigned b165 = stwo_m31_sub(b30, b2);
    unsigned b166 = stwo_m31_mul(b165, b138);
    StwoCudaQm31 e15 = StwoCudaQm31{ b166, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 15u)));
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 81u, row_index, 0);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    unsigned b167 = stwo_m31_sub(b31, b3);
    unsigned b168 = stwo_m31_mul(b167, b138);
    StwoCudaQm31 e16 = StwoCudaQm31{ b168, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 16u)));
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 82u, row_index, 0);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    unsigned b169 = stwo_m31_sub(b32, b4);
    unsigned b170 = stwo_m31_mul(b169, b138);
    StwoCudaQm31 e17 = StwoCudaQm31{ b170, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 17u)));
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 83u, row_index, 0);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    unsigned b171 = stwo_m31_sub(b33, b5);
    unsigned b172 = stwo_m31_mul(b171, b138);
    StwoCudaQm31 e18 = StwoCudaQm31{ b172, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 18u)));
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 85u, row_index, 0);
    unsigned b173 = base_params[57u];
    unsigned b174 = stwo_m31_sub(b34, b173);
    unsigned b175 = stwo_m31_mul(b34, b174);
    StwoCudaQm31 e19 = StwoCudaQm31{ b175, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e19, stwo_load_qm31(random_coeff_powers, rc_base + 19u)));
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 86u, row_index, 0);
    unsigned b176 = base_params[58u];
    unsigned b177 = stwo_m31_sub(b35, b176);
    unsigned b178 = stwo_m31_mul(b35, b177);
    StwoCudaQm31 e20 = StwoCudaQm31{ b178, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e20, stwo_load_qm31(random_coeff_powers, rc_base + 20u)));
    unsigned b179 = base_params[59u];
    unsigned b180 = stwo_m31_sub(b34, b179);
    unsigned b181 = stwo_m31_mul(b35, b180);
    StwoCudaQm31 e21 = StwoCudaQm31{ b181, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e21, stwo_load_qm31(random_coeff_powers, rc_base + 21u)));
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 91u, row_index, 0);
    unsigned b182 = base_params[64u];
    unsigned b183 = stwo_m31_sub(b182, b37);
    unsigned b184 = stwo_m31_mul(b37, b183);
    unsigned b185 = base_params[65u];
    unsigned b186 = stwo_m31_mul(b184, b185);
    StwoCudaQm31 e22 = StwoCudaQm31{ b186, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e22, stwo_load_qm31(random_coeff_powers, rc_base + 22u)));
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 90u, row_index, 0);
    unsigned b187 = base_params[66u];
    unsigned b188 = stwo_m31_mul(b37, b187);
    unsigned b189 = stwo_m31_sub(b36, b188);
    unsigned b190 = base_params[67u];
    unsigned b191 = stwo_m31_sub(b190, b189);
    unsigned b192 = stwo_m31_mul(b189, b191);
    unsigned b193 = base_params[68u];
    unsigned b194 = stwo_m31_mul(b192, b193);
    StwoCudaQm31 e23 = StwoCudaQm31{ b194, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e23, stwo_load_qm31(random_coeff_powers, rc_base + 23u)));
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 93u, row_index, 0);
    unsigned b195 = base_params[74u];
    unsigned b196 = stwo_m31_sub(b38, b195);
    unsigned b197 = stwo_m31_mul(b38, b196);
    StwoCudaQm31 e24 = StwoCudaQm31{ b197, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e24, stwo_load_qm31(random_coeff_powers, rc_base + 24u)));
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 94u, row_index, 0);
    unsigned b198 = base_params[75u];
    unsigned b199 = stwo_m31_sub(b39, b198);
    unsigned b200 = stwo_m31_mul(b39, b199);
    StwoCudaQm31 e25 = StwoCudaQm31{ b200, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e25, stwo_load_qm31(random_coeff_powers, rc_base + 25u)));
    unsigned b201 = base_params[76u];
    unsigned b202 = stwo_m31_sub(b38, b201);
    unsigned b203 = stwo_m31_mul(b39, b202);
    StwoCudaQm31 e26 = StwoCudaQm31{ b203, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e26, stwo_load_qm31(random_coeff_powers, rc_base + 26u)));
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 99u, row_index, 0);
    unsigned b204 = base_params[81u];
    unsigned b205 = stwo_m31_sub(b204, b41);
    unsigned b206 = stwo_m31_mul(b41, b205);
    unsigned b207 = base_params[82u];
    unsigned b208 = stwo_m31_mul(b206, b207);
    StwoCudaQm31 e27 = StwoCudaQm31{ b208, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e27, stwo_load_qm31(random_coeff_powers, rc_base + 27u)));
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 98u, row_index, 0);
    unsigned b209 = base_params[83u];
    unsigned b210 = stwo_m31_mul(b41, b209);
    unsigned b211 = stwo_m31_sub(b40, b210);
    unsigned b212 = base_params[84u];
    unsigned b213 = stwo_m31_sub(b212, b211);
    unsigned b214 = stwo_m31_mul(b211, b213);
    unsigned b215 = base_params[85u];
    unsigned b216 = stwo_m31_mul(b214, b215);
    StwoCudaQm31 e28 = StwoCudaQm31{ b216, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e28, stwo_load_qm31(random_coeff_powers, rc_base + 28u)));
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 101u, row_index, 0);
    unsigned b217 = base_params[91u];
    unsigned b218 = stwo_m31_sub(b42, b217);
    unsigned b219 = stwo_m31_mul(b42, b218);
    StwoCudaQm31 e29 = StwoCudaQm31{ b219, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e29, stwo_load_qm31(random_coeff_powers, rc_base + 29u)));
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 102u, row_index, 0);
    unsigned b220 = base_params[92u];
    unsigned b221 = stwo_m31_sub(b43, b220);
    unsigned b222 = stwo_m31_mul(b43, b221);
    StwoCudaQm31 e30 = StwoCudaQm31{ b222, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e30, stwo_load_qm31(random_coeff_powers, rc_base + 30u)));
    unsigned b223 = base_params[93u];
    unsigned b224 = stwo_m31_sub(b42, b223);
    unsigned b225 = stwo_m31_mul(b43, b224);
    StwoCudaQm31 e31 = StwoCudaQm31{ b225, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e31, stwo_load_qm31(random_coeff_powers, rc_base + 31u)));
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 107u, row_index, 0);
    unsigned b226 = base_params[98u];
    unsigned b227 = stwo_m31_sub(b226, b45);
    unsigned b228 = stwo_m31_mul(b45, b227);
    unsigned b229 = base_params[99u];
    unsigned b230 = stwo_m31_mul(b228, b229);
    StwoCudaQm31 e32 = StwoCudaQm31{ b230, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e32, stwo_load_qm31(random_coeff_powers, rc_base + 32u)));
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 106u, row_index, 0);
    unsigned b231 = base_params[100u];
    unsigned b232 = stwo_m31_mul(b45, b231);
    unsigned b233 = stwo_m31_sub(b44, b232);
    unsigned b234 = base_params[101u];
    unsigned b235 = stwo_m31_sub(b234, b233);
    unsigned b236 = stwo_m31_mul(b233, b235);
    unsigned b237 = base_params[102u];
    unsigned b238 = stwo_m31_mul(b236, b237);
    StwoCudaQm31 e33 = StwoCudaQm31{ b238, b49, b49, b49 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e33, stwo_load_qm31(random_coeff_powers, rc_base + 33u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
