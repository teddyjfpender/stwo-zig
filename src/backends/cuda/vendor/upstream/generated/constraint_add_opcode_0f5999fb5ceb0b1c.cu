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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_f3c610596e55cf46(
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
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b97 = base_params[0u];
    unsigned b98 = stwo_m31_sub(b97, b4);
    unsigned b99 = stwo_m31_mul(b4, b98);
    unsigned b100 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b99, b100, b100, b100 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b101 = base_params[2u];
    unsigned b102 = stwo_m31_sub(b101, b5);
    unsigned b103 = stwo_m31_mul(b5, b102);
    StwoCudaQm31 e1 = StwoCudaQm31{ b103, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b104 = base_params[3u];
    unsigned b105 = stwo_m31_sub(b104, b6);
    unsigned b106 = stwo_m31_mul(b6, b105);
    StwoCudaQm31 e2 = StwoCudaQm31{ b106, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b107 = base_params[4u];
    unsigned b108 = stwo_m31_sub(b107, b7);
    unsigned b109 = stwo_m31_mul(b7, b108);
    StwoCudaQm31 e3 = StwoCudaQm31{ b109, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b110 = base_params[5u];
    unsigned b111 = stwo_m31_sub(b110, b6);
    unsigned b112 = stwo_m31_sub(b111, b7);
    unsigned b113 = base_params[6u];
    unsigned b114 = stwo_m31_sub(b113, b112);
    unsigned b115 = stwo_m31_mul(b112, b114);
    StwoCudaQm31 e4 = StwoCudaQm31{ b115, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b116 = base_params[7u];
    unsigned b117 = stwo_m31_sub(b116, b8);
    unsigned b118 = stwo_m31_mul(b8, b117);
    StwoCudaQm31 e5 = StwoCudaQm31{ b118, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b121 = base_params[19u];
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    unsigned b119 = base_params[18u];
    unsigned b120 = stwo_m31_sub(b3, b119);
    unsigned b122 = stwo_m31_sub(b121, b120);
    unsigned b123 = stwo_m31_mul(b6, b122);
    StwoCudaQm31 e6 = StwoCudaQm31{ b123, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b124 = stwo_m31_mul(b4, b2);
    unsigned b125 = base_params[20u];
    unsigned b126 = stwo_m31_sub(b125, b4);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    unsigned b127 = stwo_m31_mul(b126, b1);
    unsigned b128 = stwo_m31_add(b124, b127);
    unsigned b129 = stwo_m31_sub(b9, b128);
    StwoCudaQm31 e7 = StwoCudaQm31{ b129, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b130 = stwo_m31_mul(b5, b2);
    unsigned b131 = base_params[21u];
    unsigned b132 = stwo_m31_sub(b131, b5);
    unsigned b133 = stwo_m31_mul(b132, b1);
    unsigned b134 = stwo_m31_add(b130, b133);
    unsigned b135 = stwo_m31_sub(b10, b134);
    StwoCudaQm31 e8 = StwoCudaQm31{ b135, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b136 = stwo_m31_mul(b6, b0);
    unsigned b137 = stwo_m31_mul(b7, b2);
    unsigned b138 = stwo_m31_add(b136, b137);
    unsigned b139 = stwo_m31_mul(b112, b1);
    unsigned b140 = stwo_m31_add(b138, b139);
    unsigned b141 = stwo_m31_sub(b11, b140);
    StwoCudaQm31 e9 = StwoCudaQm31{ b141, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 101u, row_index, 0);
    unsigned b142 = base_params[22u];
    unsigned b143 = stwo_m31_sub(b96, b142);
    unsigned b144 = stwo_m31_mul(b96, b143);
    StwoCudaQm31 e10 = StwoCudaQm31{ b144, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 75u, row_index, 0);
    unsigned b145 = stwo_m31_add(b42, b70);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 74u, row_index, 0);
    unsigned b146 = stwo_m31_add(b41, b69);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 73u, row_index, 0);
    unsigned b147 = stwo_m31_add(b40, b68);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b148 = stwo_m31_sub(b147, b12);
    unsigned b149 = stwo_m31_sub(b148, b96);
    unsigned b150 = base_params[23u];
    unsigned b151 = stwo_m31_mul(b149, b150);
    unsigned b152 = stwo_m31_add(b146, b151);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b153 = stwo_m31_sub(b152, b13);
    unsigned b154 = base_params[24u];
    unsigned b155 = stwo_m31_mul(b153, b154);
    unsigned b156 = stwo_m31_add(b145, b155);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    unsigned b157 = stwo_m31_sub(b156, b14);
    unsigned b158 = base_params[25u];
    unsigned b159 = stwo_m31_mul(b157, b158);
    unsigned b160 = stwo_m31_mul(b159, b159);
    unsigned b161 = base_params[26u];
    unsigned b162 = stwo_m31_sub(b160, b161);
    unsigned b163 = stwo_m31_mul(b159, b162);
    StwoCudaQm31 e11 = StwoCudaQm31{ b163, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 78u, row_index, 0);
    unsigned b164 = stwo_m31_add(b45, b73);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 77u, row_index, 0);
    unsigned b165 = stwo_m31_add(b44, b72);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 76u, row_index, 0);
    unsigned b166 = stwo_m31_add(b43, b71);
    unsigned b167 = stwo_m31_add(b166, b159);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    unsigned b168 = stwo_m31_sub(b167, b15);
    unsigned b169 = base_params[27u];
    unsigned b170 = stwo_m31_mul(b168, b169);
    unsigned b171 = stwo_m31_add(b165, b170);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    unsigned b172 = stwo_m31_sub(b171, b16);
    unsigned b173 = base_params[28u];
    unsigned b174 = stwo_m31_mul(b172, b173);
    unsigned b175 = stwo_m31_add(b164, b174);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    unsigned b176 = stwo_m31_sub(b175, b17);
    unsigned b177 = base_params[29u];
    unsigned b178 = stwo_m31_mul(b176, b177);
    unsigned b179 = stwo_m31_mul(b178, b178);
    unsigned b180 = base_params[30u];
    unsigned b181 = stwo_m31_sub(b179, b180);
    unsigned b182 = stwo_m31_mul(b178, b181);
    StwoCudaQm31 e12 = StwoCudaQm31{ b182, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 81u, row_index, 0);
    unsigned b183 = stwo_m31_add(b48, b76);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 80u, row_index, 0);
    unsigned b184 = stwo_m31_add(b47, b75);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 79u, row_index, 0);
    unsigned b185 = stwo_m31_add(b46, b74);
    unsigned b186 = stwo_m31_add(b185, b178);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    unsigned b187 = stwo_m31_sub(b186, b18);
    unsigned b188 = base_params[31u];
    unsigned b189 = stwo_m31_mul(b187, b188);
    unsigned b190 = stwo_m31_add(b184, b189);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    unsigned b191 = stwo_m31_sub(b190, b19);
    unsigned b192 = base_params[32u];
    unsigned b193 = stwo_m31_mul(b191, b192);
    unsigned b194 = stwo_m31_add(b183, b193);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    unsigned b195 = stwo_m31_sub(b194, b20);
    unsigned b196 = base_params[33u];
    unsigned b197 = stwo_m31_mul(b195, b196);
    unsigned b198 = stwo_m31_mul(b197, b197);
    unsigned b199 = base_params[34u];
    unsigned b200 = stwo_m31_sub(b198, b199);
    unsigned b201 = stwo_m31_mul(b197, b200);
    StwoCudaQm31 e13 = StwoCudaQm31{ b201, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 55u, row_index, 0);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 84u, row_index, 0);
    unsigned b202 = stwo_m31_add(b51, b79);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 54u, row_index, 0);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 83u, row_index, 0);
    unsigned b203 = stwo_m31_add(b50, b78);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 82u, row_index, 0);
    unsigned b204 = stwo_m31_add(b49, b77);
    unsigned b205 = stwo_m31_add(b204, b197);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    unsigned b206 = stwo_m31_sub(b205, b21);
    unsigned b207 = base_params[35u];
    unsigned b208 = stwo_m31_mul(b206, b207);
    unsigned b209 = stwo_m31_add(b203, b208);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    unsigned b210 = stwo_m31_sub(b209, b22);
    unsigned b211 = base_params[36u];
    unsigned b212 = stwo_m31_mul(b210, b211);
    unsigned b213 = stwo_m31_add(b202, b212);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    unsigned b214 = stwo_m31_sub(b213, b23);
    unsigned b215 = base_params[37u];
    unsigned b216 = stwo_m31_mul(b214, b215);
    unsigned b217 = stwo_m31_mul(b216, b216);
    unsigned b218 = base_params[38u];
    unsigned b219 = stwo_m31_sub(b217, b218);
    unsigned b220 = stwo_m31_mul(b216, b219);
    StwoCudaQm31 e14 = StwoCudaQm31{ b220, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 87u, row_index, 0);
    unsigned b221 = stwo_m31_add(b54, b82);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 86u, row_index, 0);
    unsigned b222 = stwo_m31_add(b53, b81);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 85u, row_index, 0);
    unsigned b223 = stwo_m31_add(b52, b80);
    unsigned b224 = stwo_m31_add(b223, b216);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    unsigned b225 = stwo_m31_sub(b224, b24);
    unsigned b226 = base_params[39u];
    unsigned b227 = stwo_m31_mul(b225, b226);
    unsigned b228 = stwo_m31_add(b222, b227);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    unsigned b229 = stwo_m31_sub(b228, b25);
    unsigned b230 = base_params[40u];
    unsigned b231 = stwo_m31_mul(b229, b230);
    unsigned b232 = stwo_m31_add(b221, b231);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    unsigned b233 = stwo_m31_sub(b232, b26);
    unsigned b234 = base_params[41u];
    unsigned b235 = stwo_m31_mul(b233, b234);
    unsigned b236 = stwo_m31_mul(b235, b235);
    unsigned b237 = base_params[42u];
    unsigned b238 = stwo_m31_sub(b236, b237);
    unsigned b239 = stwo_m31_mul(b235, b238);
    StwoCudaQm31 e15 = StwoCudaQm31{ b239, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 15u)));
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 61u, row_index, 0);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 90u, row_index, 0);
    unsigned b240 = stwo_m31_add(b57, b85);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 60u, row_index, 0);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 89u, row_index, 0);
    unsigned b241 = stwo_m31_add(b56, b84);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 88u, row_index, 0);
    unsigned b242 = stwo_m31_add(b55, b83);
    unsigned b243 = stwo_m31_add(b242, b235);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    unsigned b244 = stwo_m31_sub(b243, b27);
    unsigned b245 = base_params[43u];
    unsigned b246 = stwo_m31_mul(b244, b245);
    unsigned b247 = stwo_m31_add(b241, b246);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    unsigned b248 = stwo_m31_sub(b247, b28);
    unsigned b249 = base_params[44u];
    unsigned b250 = stwo_m31_mul(b248, b249);
    unsigned b251 = stwo_m31_add(b240, b250);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    unsigned b252 = stwo_m31_sub(b251, b29);
    unsigned b253 = base_params[45u];
    unsigned b254 = stwo_m31_mul(b252, b253);
    unsigned b255 = stwo_m31_mul(b254, b254);
    unsigned b256 = base_params[46u];
    unsigned b257 = stwo_m31_sub(b255, b256);
    unsigned b258 = stwo_m31_mul(b254, b257);
    StwoCudaQm31 e16 = StwoCudaQm31{ b258, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 16u)));
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 64u, row_index, 0);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 93u, row_index, 0);
    unsigned b259 = stwo_m31_add(b60, b88);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 63u, row_index, 0);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 92u, row_index, 0);
    unsigned b260 = stwo_m31_add(b59, b87);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 62u, row_index, 0);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 91u, row_index, 0);
    unsigned b261 = stwo_m31_add(b58, b86);
    unsigned b262 = stwo_m31_add(b261, b254);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    unsigned b263 = stwo_m31_sub(b262, b30);
    unsigned b264 = base_params[47u];
    unsigned b265 = stwo_m31_mul(b263, b264);
    unsigned b266 = stwo_m31_add(b260, b265);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    unsigned b267 = stwo_m31_sub(b266, b31);
    unsigned b268 = base_params[48u];
    unsigned b269 = stwo_m31_mul(b267, b268);
    unsigned b270 = stwo_m31_add(b259, b269);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    unsigned b271 = stwo_m31_sub(b270, b32);
    unsigned b272 = base_params[49u];
    unsigned b273 = stwo_m31_mul(b271, b272);
    unsigned b274 = stwo_m31_mul(b273, b273);
    unsigned b275 = base_params[50u];
    unsigned b276 = stwo_m31_sub(b274, b275);
    unsigned b277 = stwo_m31_mul(b273, b276);
    StwoCudaQm31 e17 = StwoCudaQm31{ b277, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 17u)));
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 67u, row_index, 0);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 96u, row_index, 0);
    unsigned b278 = stwo_m31_add(b63, b91);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 66u, row_index, 0);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 95u, row_index, 0);
    unsigned b279 = stwo_m31_add(b62, b90);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 65u, row_index, 0);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 94u, row_index, 0);
    unsigned b280 = stwo_m31_add(b61, b89);
    unsigned b281 = stwo_m31_add(b280, b273);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    unsigned b282 = stwo_m31_sub(b281, b33);
    unsigned b283 = base_params[51u];
    unsigned b284 = stwo_m31_mul(b283, b96);
    unsigned b285 = stwo_m31_sub(b282, b284);
    unsigned b286 = base_params[52u];
    unsigned b287 = stwo_m31_mul(b285, b286);
    unsigned b288 = stwo_m31_add(b279, b287);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    unsigned b289 = stwo_m31_sub(b288, b34);
    unsigned b290 = base_params[53u];
    unsigned b291 = stwo_m31_mul(b289, b290);
    unsigned b292 = stwo_m31_add(b278, b291);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    unsigned b293 = stwo_m31_sub(b292, b35);
    unsigned b294 = base_params[54u];
    unsigned b295 = stwo_m31_mul(b293, b294);
    unsigned b296 = stwo_m31_mul(b295, b295);
    unsigned b297 = base_params[55u];
    unsigned b298 = stwo_m31_sub(b296, b297);
    unsigned b299 = stwo_m31_mul(b295, b298);
    StwoCudaQm31 e18 = StwoCudaQm31{ b299, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 18u)));
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 70u, row_index, 0);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 99u, row_index, 0);
    unsigned b300 = stwo_m31_add(b66, b94);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 69u, row_index, 0);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 98u, row_index, 0);
    unsigned b301 = stwo_m31_add(b65, b93);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 68u, row_index, 0);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 97u, row_index, 0);
    unsigned b302 = stwo_m31_add(b64, b92);
    unsigned b303 = stwo_m31_add(b302, b295);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    unsigned b304 = stwo_m31_sub(b303, b36);
    unsigned b305 = base_params[56u];
    unsigned b306 = stwo_m31_mul(b304, b305);
    unsigned b307 = stwo_m31_add(b301, b306);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    unsigned b308 = stwo_m31_sub(b307, b37);
    unsigned b309 = base_params[57u];
    unsigned b310 = stwo_m31_mul(b308, b309);
    unsigned b311 = stwo_m31_add(b300, b310);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    unsigned b312 = stwo_m31_sub(b311, b38);
    unsigned b313 = base_params[58u];
    unsigned b314 = stwo_m31_mul(b312, b313);
    unsigned b315 = stwo_m31_mul(b314, b314);
    unsigned b316 = base_params[59u];
    unsigned b317 = stwo_m31_sub(b315, b316);
    unsigned b318 = stwo_m31_mul(b314, b317);
    StwoCudaQm31 e19 = StwoCudaQm31{ b318, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e19, stwo_load_qm31(random_coeff_powers, rc_base + 19u)));
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 71u, row_index, 0);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 100u, row_index, 0);
    unsigned b319 = stwo_m31_add(b67, b95);
    unsigned b320 = stwo_m31_add(b319, b314);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    unsigned b321 = stwo_m31_sub(b320, b39);
    unsigned b322 = base_params[60u];
    unsigned b323 = stwo_m31_mul(b322, b96);
    unsigned b324 = stwo_m31_sub(b321, b323);
    StwoCudaQm31 e20 = StwoCudaQm31{ b324, b100, b100, b100 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e20, stwo_load_qm31(random_coeff_powers, rc_base + 20u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
