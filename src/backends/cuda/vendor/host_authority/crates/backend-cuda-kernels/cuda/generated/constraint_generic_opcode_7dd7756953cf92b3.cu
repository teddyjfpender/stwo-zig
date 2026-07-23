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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_b126c8a2dc32d272(
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
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 196u, row_index, 0);
    unsigned b297 = base_params[233u];
    unsigned b298 = stwo_m31_mul(b95, b297);
    unsigned b278 = base_params[172u];
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 60u, row_index, 0);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 96u, row_index, 0);
    unsigned b142 = stwo_m31_mul(b10, b43);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 61u, row_index, 0);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 95u, row_index, 0);
    unsigned b143 = stwo_m31_mul(b11, b42);
    unsigned b144 = stwo_m31_add(b142, b143);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 62u, row_index, 0);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 94u, row_index, 0);
    unsigned b145 = stwo_m31_mul(b12, b41);
    unsigned b146 = stwo_m31_add(b144, b145);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 63u, row_index, 0);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 93u, row_index, 0);
    unsigned b147 = stwo_m31_mul(b13, b40);
    unsigned b148 = stwo_m31_add(b146, b147);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 64u, row_index, 0);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 92u, row_index, 0);
    unsigned b149 = stwo_m31_mul(b14, b39);
    unsigned b150 = stwo_m31_add(b148, b149);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 65u, row_index, 0);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 91u, row_index, 0);
    unsigned b151 = stwo_m31_mul(b15, b38);
    unsigned b152 = stwo_m31_add(b150, b151);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 66u, row_index, 0);
    unsigned b167 = stwo_m31_add(b9, b16);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 90u, row_index, 0);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 97u, row_index, 0);
    unsigned b168 = stwo_m31_add(b37, b44);
    unsigned b169 = stwo_m31_mul(b167, b168);
    unsigned b141 = stwo_m31_mul(b9, b37);
    unsigned b170 = stwo_m31_sub(b169, b141);
    unsigned b166 = stwo_m31_mul(b16, b44);
    unsigned b171 = stwo_m31_sub(b170, b166);
    unsigned b172 = stwo_m31_add(b152, b171);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 67u, row_index, 0);
    unsigned b232 = stwo_m31_add(b3, b17);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 89u, row_index, 0);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 103u, row_index, 0);
    unsigned b244 = stwo_m31_add(b36, b50);
    unsigned b246 = stwo_m31_mul(b232, b244);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 54u, row_index, 0);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 68u, row_index, 0);
    unsigned b233 = stwo_m31_add(b4, b18);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 88u, row_index, 0);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 102u, row_index, 0);
    unsigned b243 = stwo_m31_add(b35, b49);
    unsigned b247 = stwo_m31_mul(b233, b243);
    unsigned b248 = stwo_m31_add(b246, b247);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 55u, row_index, 0);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 69u, row_index, 0);
    unsigned b234 = stwo_m31_add(b5, b19);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 87u, row_index, 0);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 101u, row_index, 0);
    unsigned b242 = stwo_m31_add(b34, b48);
    unsigned b249 = stwo_m31_mul(b234, b242);
    unsigned b250 = stwo_m31_add(b248, b249);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 70u, row_index, 0);
    unsigned b235 = stwo_m31_add(b6, b20);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 86u, row_index, 0);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 100u, row_index, 0);
    unsigned b241 = stwo_m31_add(b33, b47);
    unsigned b251 = stwo_m31_mul(b235, b241);
    unsigned b252 = stwo_m31_add(b250, b251);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 71u, row_index, 0);
    unsigned b236 = stwo_m31_add(b7, b21);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 85u, row_index, 0);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 99u, row_index, 0);
    unsigned b240 = stwo_m31_add(b32, b46);
    unsigned b253 = stwo_m31_mul(b236, b240);
    unsigned b254 = stwo_m31_add(b252, b253);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 72u, row_index, 0);
    unsigned b237 = stwo_m31_add(b8, b22);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 84u, row_index, 0);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 98u, row_index, 0);
    unsigned b239 = stwo_m31_add(b31, b45);
    unsigned b255 = stwo_m31_mul(b237, b239);
    unsigned b256 = stwo_m31_add(b254, b255);
    unsigned b117 = stwo_m31_mul(b3, b36);
    unsigned b118 = stwo_m31_mul(b4, b35);
    unsigned b119 = stwo_m31_add(b117, b118);
    unsigned b120 = stwo_m31_mul(b5, b34);
    unsigned b121 = stwo_m31_add(b119, b120);
    unsigned b122 = stwo_m31_mul(b6, b33);
    unsigned b123 = stwo_m31_add(b121, b122);
    unsigned b124 = stwo_m31_mul(b7, b32);
    unsigned b125 = stwo_m31_add(b123, b124);
    unsigned b126 = stwo_m31_mul(b8, b31);
    unsigned b127 = stwo_m31_add(b125, b126);
    unsigned b270 = stwo_m31_sub(b256, b127);
    unsigned b173 = stwo_m31_mul(b17, b50);
    unsigned b174 = stwo_m31_mul(b18, b49);
    unsigned b175 = stwo_m31_add(b173, b174);
    unsigned b176 = stwo_m31_mul(b19, b48);
    unsigned b177 = stwo_m31_add(b175, b176);
    unsigned b178 = stwo_m31_mul(b20, b47);
    unsigned b179 = stwo_m31_add(b177, b178);
    unsigned b180 = stwo_m31_mul(b21, b46);
    unsigned b181 = stwo_m31_add(b179, b180);
    unsigned b182 = stwo_m31_mul(b22, b45);
    unsigned b183 = stwo_m31_add(b181, b182);
    unsigned b271 = stwo_m31_sub(b270, b183);
    unsigned b272 = stwo_m31_add(b172, b271);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 160u, row_index, 0);
    unsigned b276 = stwo_m31_sub(b272, b91);
    unsigned b279 = stwo_m31_mul(b278, b276);
    unsigned b280 = base_params[173u];
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 74u, row_index, 0);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 110u, row_index, 0);
    unsigned b198 = stwo_m31_mul(b24, b57);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 75u, row_index, 0);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 109u, row_index, 0);
    unsigned b199 = stwo_m31_mul(b25, b56);
    unsigned b200 = stwo_m31_add(b198, b199);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 76u, row_index, 0);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 108u, row_index, 0);
    unsigned b201 = stwo_m31_mul(b26, b55);
    unsigned b202 = stwo_m31_add(b200, b201);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 77u, row_index, 0);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 107u, row_index, 0);
    unsigned b203 = stwo_m31_mul(b27, b54);
    unsigned b204 = stwo_m31_add(b202, b203);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 78u, row_index, 0);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 106u, row_index, 0);
    unsigned b205 = stwo_m31_mul(b28, b53);
    unsigned b206 = stwo_m31_add(b204, b205);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 79u, row_index, 0);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 105u, row_index, 0);
    unsigned b207 = stwo_m31_mul(b29, b52);
    unsigned b208 = stwo_m31_add(b206, b207);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 73u, row_index, 0);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 80u, row_index, 0);
    unsigned b226 = stwo_m31_add(b23, b30);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 104u, row_index, 0);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 111u, row_index, 0);
    unsigned b227 = stwo_m31_add(b51, b58);
    unsigned b228 = stwo_m31_mul(b226, b227);
    unsigned b197 = stwo_m31_mul(b23, b51);
    unsigned b229 = stwo_m31_sub(b228, b197);
    unsigned b225 = stwo_m31_mul(b30, b58);
    unsigned b230 = stwo_m31_sub(b229, b225);
    unsigned b231 = stwo_m31_add(b208, b230);
    unsigned b281 = stwo_m31_mul(b280, b231);
    unsigned b282 = stwo_m31_sub(b279, b281);
    unsigned b283 = base_params[174u];
    unsigned b222 = stwo_m31_mul(b29, b58);
    unsigned b223 = stwo_m31_mul(b30, b57);
    unsigned b224 = stwo_m31_add(b222, b223);
    unsigned b284 = stwo_m31_mul(b283, b224);
    unsigned b285 = stwo_m31_add(b282, b284);
    unsigned b286 = base_params[175u];
    unsigned b287 = stwo_m31_mul(b286, b225);
    unsigned b288 = stwo_m31_add(b285, b287);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 195u, row_index, 0);
    unsigned b299 = stwo_m31_add(b288, b94);
    unsigned b300 = stwo_m31_sub(b298, b299);
    unsigned b112 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b300, b112, b112, b112 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b289 = base_params[176u];
    unsigned b153 = stwo_m31_mul(b10, b44);
    unsigned b154 = stwo_m31_mul(b11, b43);
    unsigned b155 = stwo_m31_add(b153, b154);
    unsigned b156 = stwo_m31_mul(b12, b42);
    unsigned b157 = stwo_m31_add(b155, b156);
    unsigned b158 = stwo_m31_mul(b13, b41);
    unsigned b159 = stwo_m31_add(b157, b158);
    unsigned b160 = stwo_m31_mul(b14, b40);
    unsigned b161 = stwo_m31_add(b159, b160);
    unsigned b162 = stwo_m31_mul(b15, b39);
    unsigned b163 = stwo_m31_add(b161, b162);
    unsigned b164 = stwo_m31_mul(b16, b38);
    unsigned b165 = stwo_m31_add(b163, b164);
    unsigned b245 = stwo_m31_add(b37, b51);
    unsigned b257 = stwo_m31_mul(b232, b245);
    unsigned b258 = stwo_m31_mul(b233, b244);
    unsigned b259 = stwo_m31_add(b257, b258);
    unsigned b260 = stwo_m31_mul(b234, b243);
    unsigned b261 = stwo_m31_add(b259, b260);
    unsigned b262 = stwo_m31_mul(b235, b242);
    unsigned b263 = stwo_m31_add(b261, b262);
    unsigned b264 = stwo_m31_mul(b236, b241);
    unsigned b265 = stwo_m31_add(b263, b264);
    unsigned b266 = stwo_m31_mul(b237, b240);
    unsigned b267 = stwo_m31_add(b265, b266);
    unsigned b238 = stwo_m31_add(b9, b23);
    unsigned b268 = stwo_m31_mul(b238, b239);
    unsigned b269 = stwo_m31_add(b267, b268);
    unsigned b128 = stwo_m31_mul(b3, b37);
    unsigned b129 = stwo_m31_mul(b4, b36);
    unsigned b130 = stwo_m31_add(b128, b129);
    unsigned b131 = stwo_m31_mul(b5, b35);
    unsigned b132 = stwo_m31_add(b130, b131);
    unsigned b133 = stwo_m31_mul(b6, b34);
    unsigned b134 = stwo_m31_add(b132, b133);
    unsigned b135 = stwo_m31_mul(b7, b33);
    unsigned b136 = stwo_m31_add(b134, b135);
    unsigned b137 = stwo_m31_mul(b8, b32);
    unsigned b138 = stwo_m31_add(b136, b137);
    unsigned b139 = stwo_m31_mul(b9, b31);
    unsigned b140 = stwo_m31_add(b138, b139);
    unsigned b273 = stwo_m31_sub(b269, b140);
    unsigned b184 = stwo_m31_mul(b17, b51);
    unsigned b185 = stwo_m31_mul(b18, b50);
    unsigned b186 = stwo_m31_add(b184, b185);
    unsigned b187 = stwo_m31_mul(b19, b49);
    unsigned b188 = stwo_m31_add(b186, b187);
    unsigned b189 = stwo_m31_mul(b20, b48);
    unsigned b190 = stwo_m31_add(b188, b189);
    unsigned b191 = stwo_m31_mul(b21, b47);
    unsigned b192 = stwo_m31_add(b190, b191);
    unsigned b193 = stwo_m31_mul(b22, b46);
    unsigned b194 = stwo_m31_add(b192, b193);
    unsigned b195 = stwo_m31_mul(b23, b45);
    unsigned b196 = stwo_m31_add(b194, b195);
    unsigned b274 = stwo_m31_sub(b273, b196);
    unsigned b275 = stwo_m31_add(b165, b274);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 161u, row_index, 0);
    unsigned b277 = stwo_m31_sub(b275, b92);
    unsigned b290 = stwo_m31_mul(b289, b277);
    unsigned b291 = base_params[177u];
    unsigned b209 = stwo_m31_mul(b24, b58);
    unsigned b210 = stwo_m31_mul(b25, b57);
    unsigned b211 = stwo_m31_add(b209, b210);
    unsigned b212 = stwo_m31_mul(b26, b56);
    unsigned b213 = stwo_m31_add(b211, b212);
    unsigned b214 = stwo_m31_mul(b27, b55);
    unsigned b215 = stwo_m31_add(b213, b214);
    unsigned b216 = stwo_m31_mul(b28, b54);
    unsigned b217 = stwo_m31_add(b215, b216);
    unsigned b218 = stwo_m31_mul(b29, b53);
    unsigned b219 = stwo_m31_add(b217, b218);
    unsigned b220 = stwo_m31_mul(b30, b52);
    unsigned b221 = stwo_m31_add(b219, b220);
    unsigned b292 = stwo_m31_mul(b291, b221);
    unsigned b293 = stwo_m31_sub(b290, b292);
    unsigned b294 = base_params[178u];
    unsigned b295 = stwo_m31_mul(b294, b225);
    unsigned b296 = stwo_m31_add(b293, b295);
    unsigned b301 = base_params[235u];
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 169u, row_index, 0);
    unsigned b302 = stwo_m31_mul(b301, b93);
    unsigned b303 = stwo_m31_sub(b296, b302);
    unsigned b304 = stwo_m31_add(b303, b95);
    StwoCudaQm31 e1 = StwoCudaQm31{ b304, b112, b112, b112 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 112u, row_index, 0);
    unsigned b307 = stwo_m31_mul(b0, b59);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 141u, row_index, 0);
    unsigned b308 = stwo_m31_mul(b1, b75);
    unsigned b309 = stwo_m31_add(b307, b308);
    unsigned b113 = base_params[35u];
    unsigned b114 = stwo_m31_sub(b113, b0);
    unsigned b115 = stwo_m31_sub(b114, b1);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b116 = stwo_m31_sub(b115, b2);
    unsigned b310 = stwo_m31_mul(b116, b31);
    unsigned b311 = stwo_m31_add(b309, b310);
    unsigned b305 = base_params[236u];
    unsigned b306 = stwo_m31_sub(b305, b2);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 197u, row_index, 0);
    unsigned b312 = stwo_m31_mul(b306, b96);
    unsigned b313 = stwo_m31_sub(b311, b312);
    StwoCudaQm31 e2 = StwoCudaQm31{ b313, b112, b112, b112 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 113u, row_index, 0);
    unsigned b314 = stwo_m31_mul(b0, b60);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 142u, row_index, 0);
    unsigned b315 = stwo_m31_mul(b1, b76);
    unsigned b316 = stwo_m31_add(b314, b315);
    unsigned b317 = stwo_m31_mul(b116, b32);
    unsigned b318 = stwo_m31_add(b316, b317);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 198u, row_index, 0);
    unsigned b319 = stwo_m31_mul(b306, b97);
    unsigned b320 = stwo_m31_sub(b318, b319);
    StwoCudaQm31 e3 = StwoCudaQm31{ b320, b112, b112, b112 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 114u, row_index, 0);
    unsigned b321 = stwo_m31_mul(b0, b61);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 143u, row_index, 0);
    unsigned b322 = stwo_m31_mul(b1, b77);
    unsigned b323 = stwo_m31_add(b321, b322);
    unsigned b324 = stwo_m31_mul(b116, b33);
    unsigned b325 = stwo_m31_add(b323, b324);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 199u, row_index, 0);
    unsigned b326 = stwo_m31_mul(b306, b98);
    unsigned b327 = stwo_m31_sub(b325, b326);
    StwoCudaQm31 e4 = StwoCudaQm31{ b327, b112, b112, b112 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 115u, row_index, 0);
    unsigned b328 = stwo_m31_mul(b0, b62);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 144u, row_index, 0);
    unsigned b329 = stwo_m31_mul(b1, b78);
    unsigned b330 = stwo_m31_add(b328, b329);
    unsigned b331 = stwo_m31_mul(b116, b34);
    unsigned b332 = stwo_m31_add(b330, b331);
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 200u, row_index, 0);
    unsigned b333 = stwo_m31_mul(b306, b99);
    unsigned b334 = stwo_m31_sub(b332, b333);
    StwoCudaQm31 e5 = StwoCudaQm31{ b334, b112, b112, b112 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 116u, row_index, 0);
    unsigned b335 = stwo_m31_mul(b0, b63);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 145u, row_index, 0);
    unsigned b336 = stwo_m31_mul(b1, b79);
    unsigned b337 = stwo_m31_add(b335, b336);
    unsigned b338 = stwo_m31_mul(b116, b35);
    unsigned b339 = stwo_m31_add(b337, b338);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 201u, row_index, 0);
    unsigned b340 = stwo_m31_mul(b306, b100);
    unsigned b341 = stwo_m31_sub(b339, b340);
    StwoCudaQm31 e6 = StwoCudaQm31{ b341, b112, b112, b112 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 117u, row_index, 0);
    unsigned b342 = stwo_m31_mul(b0, b64);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 146u, row_index, 0);
    unsigned b343 = stwo_m31_mul(b1, b80);
    unsigned b344 = stwo_m31_add(b342, b343);
    unsigned b345 = stwo_m31_mul(b116, b36);
    unsigned b346 = stwo_m31_add(b344, b345);
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 202u, row_index, 0);
    unsigned b347 = stwo_m31_mul(b306, b101);
    unsigned b348 = stwo_m31_sub(b346, b347);
    StwoCudaQm31 e7 = StwoCudaQm31{ b348, b112, b112, b112 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 118u, row_index, 0);
    unsigned b349 = stwo_m31_mul(b0, b65);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 147u, row_index, 0);
    unsigned b350 = stwo_m31_mul(b1, b81);
    unsigned b351 = stwo_m31_add(b349, b350);
    unsigned b352 = stwo_m31_mul(b116, b37);
    unsigned b353 = stwo_m31_add(b351, b352);
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 203u, row_index, 0);
    unsigned b354 = stwo_m31_mul(b306, b102);
    unsigned b355 = stwo_m31_sub(b353, b354);
    StwoCudaQm31 e8 = StwoCudaQm31{ b355, b112, b112, b112 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 119u, row_index, 0);
    unsigned b356 = stwo_m31_mul(b0, b66);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 148u, row_index, 0);
    unsigned b357 = stwo_m31_mul(b1, b82);
    unsigned b358 = stwo_m31_add(b356, b357);
    unsigned b359 = stwo_m31_mul(b116, b38);
    unsigned b360 = stwo_m31_add(b358, b359);
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 204u, row_index, 0);
    unsigned b361 = stwo_m31_mul(b306, b103);
    unsigned b362 = stwo_m31_sub(b360, b361);
    StwoCudaQm31 e9 = StwoCudaQm31{ b362, b112, b112, b112 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 120u, row_index, 0);
    unsigned b363 = stwo_m31_mul(b0, b67);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 149u, row_index, 0);
    unsigned b364 = stwo_m31_mul(b1, b83);
    unsigned b365 = stwo_m31_add(b363, b364);
    unsigned b366 = stwo_m31_mul(b116, b39);
    unsigned b367 = stwo_m31_add(b365, b366);
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 205u, row_index, 0);
    unsigned b368 = stwo_m31_mul(b306, b104);
    unsigned b369 = stwo_m31_sub(b367, b368);
    StwoCudaQm31 e10 = StwoCudaQm31{ b369, b112, b112, b112 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 121u, row_index, 0);
    unsigned b370 = stwo_m31_mul(b0, b68);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 150u, row_index, 0);
    unsigned b371 = stwo_m31_mul(b1, b84);
    unsigned b372 = stwo_m31_add(b370, b371);
    unsigned b373 = stwo_m31_mul(b116, b40);
    unsigned b374 = stwo_m31_add(b372, b373);
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 206u, row_index, 0);
    unsigned b375 = stwo_m31_mul(b306, b105);
    unsigned b376 = stwo_m31_sub(b374, b375);
    StwoCudaQm31 e11 = StwoCudaQm31{ b376, b112, b112, b112 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 122u, row_index, 0);
    unsigned b377 = stwo_m31_mul(b0, b69);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 151u, row_index, 0);
    unsigned b378 = stwo_m31_mul(b1, b85);
    unsigned b379 = stwo_m31_add(b377, b378);
    unsigned b380 = stwo_m31_mul(b116, b41);
    unsigned b381 = stwo_m31_add(b379, b380);
    unsigned b106 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 207u, row_index, 0);
    unsigned b382 = stwo_m31_mul(b306, b106);
    unsigned b383 = stwo_m31_sub(b381, b382);
    StwoCudaQm31 e12 = StwoCudaQm31{ b383, b112, b112, b112 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 123u, row_index, 0);
    unsigned b384 = stwo_m31_mul(b0, b70);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 152u, row_index, 0);
    unsigned b385 = stwo_m31_mul(b1, b86);
    unsigned b386 = stwo_m31_add(b384, b385);
    unsigned b387 = stwo_m31_mul(b116, b42);
    unsigned b388 = stwo_m31_add(b386, b387);
    unsigned b107 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 208u, row_index, 0);
    unsigned b389 = stwo_m31_mul(b306, b107);
    unsigned b390 = stwo_m31_sub(b388, b389);
    StwoCudaQm31 e13 = StwoCudaQm31{ b390, b112, b112, b112 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 124u, row_index, 0);
    unsigned b391 = stwo_m31_mul(b0, b71);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 153u, row_index, 0);
    unsigned b392 = stwo_m31_mul(b1, b87);
    unsigned b393 = stwo_m31_add(b391, b392);
    unsigned b394 = stwo_m31_mul(b116, b43);
    unsigned b395 = stwo_m31_add(b393, b394);
    unsigned b108 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 209u, row_index, 0);
    unsigned b396 = stwo_m31_mul(b306, b108);
    unsigned b397 = stwo_m31_sub(b395, b396);
    StwoCudaQm31 e14 = StwoCudaQm31{ b397, b112, b112, b112 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 125u, row_index, 0);
    unsigned b398 = stwo_m31_mul(b0, b72);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 154u, row_index, 0);
    unsigned b399 = stwo_m31_mul(b1, b88);
    unsigned b400 = stwo_m31_add(b398, b399);
    unsigned b401 = stwo_m31_mul(b116, b44);
    unsigned b402 = stwo_m31_add(b400, b401);
    unsigned b109 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 210u, row_index, 0);
    unsigned b403 = stwo_m31_mul(b306, b109);
    unsigned b404 = stwo_m31_sub(b402, b403);
    StwoCudaQm31 e15 = StwoCudaQm31{ b404, b112, b112, b112 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 15u)));
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 126u, row_index, 0);
    unsigned b405 = stwo_m31_mul(b0, b73);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 155u, row_index, 0);
    unsigned b406 = stwo_m31_mul(b1, b89);
    unsigned b407 = stwo_m31_add(b405, b406);
    unsigned b408 = stwo_m31_mul(b116, b45);
    unsigned b409 = stwo_m31_add(b407, b408);
    unsigned b110 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 211u, row_index, 0);
    unsigned b410 = stwo_m31_mul(b306, b110);
    unsigned b411 = stwo_m31_sub(b409, b410);
    StwoCudaQm31 e16 = StwoCudaQm31{ b411, b112, b112, b112 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 16u)));
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 127u, row_index, 0);
    unsigned b412 = stwo_m31_mul(b0, b74);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 156u, row_index, 0);
    unsigned b413 = stwo_m31_mul(b1, b90);
    unsigned b414 = stwo_m31_add(b412, b413);
    unsigned b415 = stwo_m31_mul(b116, b46);
    unsigned b416 = stwo_m31_add(b414, b415);
    unsigned b111 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 212u, row_index, 0);
    unsigned b417 = stwo_m31_mul(b306, b111);
    unsigned b418 = stwo_m31_sub(b416, b417);
    StwoCudaQm31 e17 = StwoCudaQm31{ b418, b112, b112, b112 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 17u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
