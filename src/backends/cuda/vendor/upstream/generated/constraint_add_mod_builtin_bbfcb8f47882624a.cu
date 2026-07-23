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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_54d265e11f775c56(
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
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 252u, row_index, 0);
    unsigned b106 = base_params[119u];
    unsigned b107 = stwo_m31_sub(b96, b106);
    unsigned b108 = stwo_m31_mul(b107, b96);
    unsigned b105 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b108, b105, b105, b105 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 253u, row_index, 0);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 109u, row_index, 0);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 157u, row_index, 0);
    unsigned b109 = stwo_m31_add(b24, b48);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 205u, row_index, 0);
    unsigned b110 = stwo_m31_sub(b109, b72);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b111 = stwo_m31_mul(b0, b96);
    unsigned b112 = stwo_m31_sub(b110, b111);
    unsigned b117 = base_params[120u];
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 110u, row_index, 0);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 158u, row_index, 0);
    unsigned b113 = stwo_m31_add(b25, b49);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 206u, row_index, 0);
    unsigned b114 = stwo_m31_sub(b113, b73);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    unsigned b115 = stwo_m31_mul(b1, b96);
    unsigned b116 = stwo_m31_sub(b114, b115);
    unsigned b118 = stwo_m31_mul(b117, b116);
    unsigned b119 = stwo_m31_add(b112, b118);
    unsigned b124 = base_params[121u];
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 111u, row_index, 0);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 159u, row_index, 0);
    unsigned b120 = stwo_m31_add(b26, b50);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 207u, row_index, 0);
    unsigned b121 = stwo_m31_sub(b120, b74);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    unsigned b122 = stwo_m31_mul(b2, b96);
    unsigned b123 = stwo_m31_sub(b121, b122);
    unsigned b125 = stwo_m31_mul(b124, b123);
    unsigned b126 = stwo_m31_add(b119, b125);
    unsigned b127 = base_params[122u];
    unsigned b128 = stwo_m31_mul(b126, b127);
    unsigned b129 = stwo_m31_sub(b97, b128);
    StwoCudaQm31 e1 = StwoCudaQm31{ b129, b105, b105, b105 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b130 = stwo_m31_mul(b97, b97);
    unsigned b131 = base_params[123u];
    unsigned b132 = stwo_m31_sub(b130, b131);
    unsigned b133 = stwo_m31_mul(b97, b132);
    StwoCudaQm31 e2 = StwoCudaQm31{ b133, b105, b105, b105 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 254u, row_index, 0);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 112u, row_index, 0);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 160u, row_index, 0);
    unsigned b134 = stwo_m31_add(b27, b51);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 208u, row_index, 0);
    unsigned b135 = stwo_m31_sub(b134, b75);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    unsigned b136 = stwo_m31_mul(b3, b96);
    unsigned b137 = stwo_m31_sub(b135, b136);
    unsigned b138 = stwo_m31_add(b97, b137);
    unsigned b143 = base_params[124u];
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 113u, row_index, 0);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 161u, row_index, 0);
    unsigned b139 = stwo_m31_add(b28, b52);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 209u, row_index, 0);
    unsigned b140 = stwo_m31_sub(b139, b76);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b141 = stwo_m31_mul(b4, b96);
    unsigned b142 = stwo_m31_sub(b140, b141);
    unsigned b144 = stwo_m31_mul(b143, b142);
    unsigned b145 = stwo_m31_add(b138, b144);
    unsigned b150 = base_params[125u];
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 114u, row_index, 0);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 162u, row_index, 0);
    unsigned b146 = stwo_m31_add(b29, b53);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 210u, row_index, 0);
    unsigned b147 = stwo_m31_sub(b146, b77);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b148 = stwo_m31_mul(b5, b96);
    unsigned b149 = stwo_m31_sub(b147, b148);
    unsigned b151 = stwo_m31_mul(b150, b149);
    unsigned b152 = stwo_m31_add(b145, b151);
    unsigned b153 = base_params[126u];
    unsigned b154 = stwo_m31_mul(b152, b153);
    unsigned b155 = stwo_m31_sub(b98, b154);
    StwoCudaQm31 e3 = StwoCudaQm31{ b155, b105, b105, b105 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b156 = stwo_m31_mul(b98, b98);
    unsigned b157 = base_params[127u];
    unsigned b158 = stwo_m31_sub(b156, b157);
    unsigned b159 = stwo_m31_mul(b98, b158);
    StwoCudaQm31 e4 = StwoCudaQm31{ b159, b105, b105, b105 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 255u, row_index, 0);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 115u, row_index, 0);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 163u, row_index, 0);
    unsigned b160 = stwo_m31_add(b30, b54);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 211u, row_index, 0);
    unsigned b161 = stwo_m31_sub(b160, b78);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b162 = stwo_m31_mul(b6, b96);
    unsigned b163 = stwo_m31_sub(b161, b162);
    unsigned b164 = stwo_m31_add(b98, b163);
    unsigned b169 = base_params[128u];
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 116u, row_index, 0);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 164u, row_index, 0);
    unsigned b165 = stwo_m31_add(b31, b55);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 212u, row_index, 0);
    unsigned b166 = stwo_m31_sub(b165, b79);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b167 = stwo_m31_mul(b7, b96);
    unsigned b168 = stwo_m31_sub(b166, b167);
    unsigned b170 = stwo_m31_mul(b169, b168);
    unsigned b171 = stwo_m31_add(b164, b170);
    unsigned b176 = base_params[129u];
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 117u, row_index, 0);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 165u, row_index, 0);
    unsigned b172 = stwo_m31_add(b32, b56);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 213u, row_index, 0);
    unsigned b173 = stwo_m31_sub(b172, b80);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b174 = stwo_m31_mul(b8, b96);
    unsigned b175 = stwo_m31_sub(b173, b174);
    unsigned b177 = stwo_m31_mul(b176, b175);
    unsigned b178 = stwo_m31_add(b171, b177);
    unsigned b179 = base_params[130u];
    unsigned b180 = stwo_m31_mul(b178, b179);
    unsigned b181 = stwo_m31_sub(b99, b180);
    StwoCudaQm31 e5 = StwoCudaQm31{ b181, b105, b105, b105 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b182 = stwo_m31_mul(b99, b99);
    unsigned b183 = base_params[131u];
    unsigned b184 = stwo_m31_sub(b182, b183);
    unsigned b185 = stwo_m31_mul(b99, b184);
    StwoCudaQm31 e6 = StwoCudaQm31{ b185, b105, b105, b105 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 256u, row_index, 0);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 118u, row_index, 0);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 166u, row_index, 0);
    unsigned b186 = stwo_m31_add(b33, b57);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 214u, row_index, 0);
    unsigned b187 = stwo_m31_sub(b186, b81);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b188 = stwo_m31_mul(b9, b96);
    unsigned b189 = stwo_m31_sub(b187, b188);
    unsigned b190 = stwo_m31_add(b99, b189);
    unsigned b195 = base_params[132u];
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 119u, row_index, 0);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 167u, row_index, 0);
    unsigned b191 = stwo_m31_add(b34, b58);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 215u, row_index, 0);
    unsigned b192 = stwo_m31_sub(b191, b82);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b193 = stwo_m31_mul(b10, b96);
    unsigned b194 = stwo_m31_sub(b192, b193);
    unsigned b196 = stwo_m31_mul(b195, b194);
    unsigned b197 = stwo_m31_add(b190, b196);
    unsigned b202 = base_params[133u];
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 121u, row_index, 0);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 169u, row_index, 0);
    unsigned b198 = stwo_m31_add(b35, b59);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 217u, row_index, 0);
    unsigned b199 = stwo_m31_sub(b198, b83);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    unsigned b200 = stwo_m31_mul(b11, b96);
    unsigned b201 = stwo_m31_sub(b199, b200);
    unsigned b203 = stwo_m31_mul(b202, b201);
    unsigned b204 = stwo_m31_add(b197, b203);
    unsigned b205 = base_params[134u];
    unsigned b206 = stwo_m31_mul(b204, b205);
    unsigned b207 = stwo_m31_sub(b100, b206);
    StwoCudaQm31 e7 = StwoCudaQm31{ b207, b105, b105, b105 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b208 = stwo_m31_mul(b100, b100);
    unsigned b209 = base_params[135u];
    unsigned b210 = stwo_m31_sub(b208, b209);
    unsigned b211 = stwo_m31_mul(b100, b210);
    StwoCudaQm31 e8 = StwoCudaQm31{ b211, b105, b105, b105 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 257u, row_index, 0);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 122u, row_index, 0);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 170u, row_index, 0);
    unsigned b212 = stwo_m31_add(b36, b60);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 218u, row_index, 0);
    unsigned b213 = stwo_m31_sub(b212, b84);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b214 = stwo_m31_mul(b12, b96);
    unsigned b215 = stwo_m31_sub(b213, b214);
    unsigned b216 = stwo_m31_add(b100, b215);
    unsigned b221 = base_params[136u];
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 123u, row_index, 0);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 171u, row_index, 0);
    unsigned b217 = stwo_m31_add(b37, b61);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 219u, row_index, 0);
    unsigned b218 = stwo_m31_sub(b217, b85);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b219 = stwo_m31_mul(b13, b96);
    unsigned b220 = stwo_m31_sub(b218, b219);
    unsigned b222 = stwo_m31_mul(b221, b220);
    unsigned b223 = stwo_m31_add(b216, b222);
    unsigned b228 = base_params[137u];
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 124u, row_index, 0);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 172u, row_index, 0);
    unsigned b224 = stwo_m31_add(b38, b62);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 220u, row_index, 0);
    unsigned b225 = stwo_m31_sub(b224, b86);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    unsigned b226 = stwo_m31_mul(b14, b96);
    unsigned b227 = stwo_m31_sub(b225, b226);
    unsigned b229 = stwo_m31_mul(b228, b227);
    unsigned b230 = stwo_m31_add(b223, b229);
    unsigned b231 = base_params[138u];
    unsigned b232 = stwo_m31_mul(b230, b231);
    unsigned b233 = stwo_m31_sub(b101, b232);
    StwoCudaQm31 e9 = StwoCudaQm31{ b233, b105, b105, b105 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b234 = stwo_m31_mul(b101, b101);
    unsigned b235 = base_params[139u];
    unsigned b236 = stwo_m31_sub(b234, b235);
    unsigned b237 = stwo_m31_mul(b101, b236);
    StwoCudaQm31 e10 = StwoCudaQm31{ b237, b105, b105, b105 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 258u, row_index, 0);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 125u, row_index, 0);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 173u, row_index, 0);
    unsigned b238 = stwo_m31_add(b39, b63);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 221u, row_index, 0);
    unsigned b239 = stwo_m31_sub(b238, b87);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    unsigned b240 = stwo_m31_mul(b15, b96);
    unsigned b241 = stwo_m31_sub(b239, b240);
    unsigned b242 = stwo_m31_add(b101, b241);
    unsigned b247 = base_params[140u];
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 126u, row_index, 0);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 174u, row_index, 0);
    unsigned b243 = stwo_m31_add(b40, b64);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 222u, row_index, 0);
    unsigned b244 = stwo_m31_sub(b243, b88);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    unsigned b245 = stwo_m31_mul(b16, b96);
    unsigned b246 = stwo_m31_sub(b244, b245);
    unsigned b248 = stwo_m31_mul(b247, b246);
    unsigned b249 = stwo_m31_add(b242, b248);
    unsigned b254 = base_params[141u];
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 127u, row_index, 0);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 175u, row_index, 0);
    unsigned b250 = stwo_m31_add(b41, b65);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 223u, row_index, 0);
    unsigned b251 = stwo_m31_sub(b250, b89);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    unsigned b252 = stwo_m31_mul(b17, b96);
    unsigned b253 = stwo_m31_sub(b251, b252);
    unsigned b255 = stwo_m31_mul(b254, b253);
    unsigned b256 = stwo_m31_add(b249, b255);
    unsigned b257 = base_params[142u];
    unsigned b258 = stwo_m31_mul(b256, b257);
    unsigned b259 = stwo_m31_sub(b102, b258);
    StwoCudaQm31 e11 = StwoCudaQm31{ b259, b105, b105, b105 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b260 = stwo_m31_mul(b102, b102);
    unsigned b261 = base_params[143u];
    unsigned b262 = stwo_m31_sub(b260, b261);
    unsigned b263 = stwo_m31_mul(b102, b262);
    StwoCudaQm31 e12 = StwoCudaQm31{ b263, b105, b105, b105 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 259u, row_index, 0);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 128u, row_index, 0);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 176u, row_index, 0);
    unsigned b264 = stwo_m31_add(b42, b66);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 224u, row_index, 0);
    unsigned b265 = stwo_m31_sub(b264, b90);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    unsigned b266 = stwo_m31_mul(b18, b96);
    unsigned b267 = stwo_m31_sub(b265, b266);
    unsigned b268 = stwo_m31_add(b102, b267);
    unsigned b273 = base_params[144u];
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 129u, row_index, 0);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 177u, row_index, 0);
    unsigned b269 = stwo_m31_add(b43, b67);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 225u, row_index, 0);
    unsigned b270 = stwo_m31_sub(b269, b91);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    unsigned b271 = stwo_m31_mul(b19, b96);
    unsigned b272 = stwo_m31_sub(b270, b271);
    unsigned b274 = stwo_m31_mul(b273, b272);
    unsigned b275 = stwo_m31_add(b268, b274);
    unsigned b280 = base_params[145u];
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 130u, row_index, 0);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 178u, row_index, 0);
    unsigned b276 = stwo_m31_add(b44, b68);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 226u, row_index, 0);
    unsigned b277 = stwo_m31_sub(b276, b92);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    unsigned b278 = stwo_m31_mul(b20, b96);
    unsigned b279 = stwo_m31_sub(b277, b278);
    unsigned b281 = stwo_m31_mul(b280, b279);
    unsigned b282 = stwo_m31_add(b275, b281);
    unsigned b283 = base_params[146u];
    unsigned b284 = stwo_m31_mul(b282, b283);
    unsigned b285 = stwo_m31_sub(b103, b284);
    StwoCudaQm31 e13 = StwoCudaQm31{ b285, b105, b105, b105 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b286 = stwo_m31_mul(b103, b103);
    unsigned b287 = base_params[147u];
    unsigned b288 = stwo_m31_sub(b286, b287);
    unsigned b289 = stwo_m31_mul(b103, b288);
    StwoCudaQm31 e14 = StwoCudaQm31{ b289, b105, b105, b105 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 260u, row_index, 0);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 131u, row_index, 0);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 179u, row_index, 0);
    unsigned b290 = stwo_m31_add(b45, b69);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 227u, row_index, 0);
    unsigned b291 = stwo_m31_sub(b290, b93);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    unsigned b292 = stwo_m31_mul(b21, b96);
    unsigned b293 = stwo_m31_sub(b291, b292);
    unsigned b294 = stwo_m31_add(b103, b293);
    unsigned b299 = base_params[148u];
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 133u, row_index, 0);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 181u, row_index, 0);
    unsigned b295 = stwo_m31_add(b46, b70);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 229u, row_index, 0);
    unsigned b296 = stwo_m31_sub(b295, b94);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    unsigned b297 = stwo_m31_mul(b22, b96);
    unsigned b298 = stwo_m31_sub(b296, b297);
    unsigned b300 = stwo_m31_mul(b299, b298);
    unsigned b301 = stwo_m31_add(b294, b300);
    unsigned b306 = base_params[149u];
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 134u, row_index, 0);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 182u, row_index, 0);
    unsigned b302 = stwo_m31_add(b47, b71);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 230u, row_index, 0);
    unsigned b303 = stwo_m31_sub(b302, b95);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    unsigned b304 = stwo_m31_mul(b23, b96);
    unsigned b305 = stwo_m31_sub(b303, b304);
    unsigned b307 = stwo_m31_mul(b306, b305);
    unsigned b308 = stwo_m31_add(b301, b307);
    unsigned b309 = base_params[150u];
    unsigned b310 = stwo_m31_mul(b308, b309);
    unsigned b311 = stwo_m31_sub(b104, b310);
    StwoCudaQm31 e15 = StwoCudaQm31{ b311, b105, b105, b105 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 15u)));
    unsigned b312 = stwo_m31_mul(b104, b104);
    unsigned b313 = base_params[151u];
    unsigned b314 = stwo_m31_sub(b312, b313);
    unsigned b315 = stwo_m31_mul(b104, b314);
    StwoCudaQm31 e16 = StwoCudaQm31{ b315, b105, b105, b105 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 16u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
