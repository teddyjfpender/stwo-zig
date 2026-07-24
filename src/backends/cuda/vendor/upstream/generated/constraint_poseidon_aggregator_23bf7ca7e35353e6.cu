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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_d7b70290734238e7(
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
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b79 = base_params[1u];
    unsigned b80 = stwo_m31_mul(b1, b79);
    unsigned b81 = stwo_m31_add(b0, b80);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b82 = base_params[2u];
    unsigned b83 = stwo_m31_mul(b2, b82);
    unsigned b84 = stwo_m31_add(b81, b83);
    unsigned b187 = base_params[55u];
    unsigned b188 = stwo_m31_add(b84, b187);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 90u, row_index, 0);
    unsigned b189 = stwo_m31_sub(b188, b56);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 100u, row_index, 0);
    unsigned b190 = stwo_m31_sub(b189, b66);
    unsigned b191 = base_params[56u];
    unsigned b192 = stwo_m31_mul(b190, b191);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b85 = base_params[3u];
    unsigned b86 = stwo_m31_mul(b4, b85);
    unsigned b87 = stwo_m31_add(b3, b86);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b88 = base_params[4u];
    unsigned b89 = stwo_m31_mul(b5, b88);
    unsigned b90 = stwo_m31_add(b87, b89);
    unsigned b193 = stwo_m31_add(b192, b90);
    unsigned b194 = base_params[57u];
    unsigned b195 = stwo_m31_add(b193, b194);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 91u, row_index, 0);
    unsigned b196 = stwo_m31_sub(b195, b57);
    unsigned b197 = base_params[58u];
    unsigned b198 = stwo_m31_mul(b196, b197);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    unsigned b91 = base_params[5u];
    unsigned b92 = stwo_m31_mul(b7, b91);
    unsigned b93 = stwo_m31_add(b6, b92);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    unsigned b94 = base_params[6u];
    unsigned b95 = stwo_m31_mul(b8, b94);
    unsigned b96 = stwo_m31_add(b93, b95);
    unsigned b199 = stwo_m31_add(b198, b96);
    unsigned b200 = base_params[59u];
    unsigned b201 = stwo_m31_add(b199, b200);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 92u, row_index, 0);
    unsigned b202 = stwo_m31_sub(b201, b58);
    unsigned b203 = base_params[60u];
    unsigned b204 = stwo_m31_mul(b202, b203);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b97 = base_params[7u];
    unsigned b98 = stwo_m31_mul(b10, b97);
    unsigned b99 = stwo_m31_add(b9, b98);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    unsigned b100 = base_params[8u];
    unsigned b101 = stwo_m31_mul(b11, b100);
    unsigned b102 = stwo_m31_add(b99, b101);
    unsigned b205 = stwo_m31_add(b204, b102);
    unsigned b206 = base_params[61u];
    unsigned b207 = stwo_m31_add(b205, b206);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 93u, row_index, 0);
    unsigned b208 = stwo_m31_sub(b207, b59);
    unsigned b209 = base_params[62u];
    unsigned b210 = stwo_m31_mul(b208, b209);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    unsigned b103 = base_params[9u];
    unsigned b104 = stwo_m31_mul(b13, b103);
    unsigned b105 = stwo_m31_add(b12, b104);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    unsigned b106 = base_params[10u];
    unsigned b107 = stwo_m31_mul(b14, b106);
    unsigned b108 = stwo_m31_add(b105, b107);
    unsigned b211 = stwo_m31_add(b210, b108);
    unsigned b212 = base_params[63u];
    unsigned b213 = stwo_m31_add(b211, b212);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 94u, row_index, 0);
    unsigned b214 = stwo_m31_sub(b213, b60);
    unsigned b215 = base_params[64u];
    unsigned b216 = stwo_m31_mul(b214, b215);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    unsigned b109 = base_params[11u];
    unsigned b110 = stwo_m31_mul(b16, b109);
    unsigned b111 = stwo_m31_add(b15, b110);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    unsigned b112 = base_params[12u];
    unsigned b113 = stwo_m31_mul(b17, b112);
    unsigned b114 = stwo_m31_add(b111, b113);
    unsigned b217 = stwo_m31_add(b216, b114);
    unsigned b218 = base_params[65u];
    unsigned b219 = stwo_m31_add(b217, b218);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 95u, row_index, 0);
    unsigned b220 = stwo_m31_sub(b219, b61);
    unsigned b221 = base_params[66u];
    unsigned b222 = stwo_m31_mul(b220, b221);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    unsigned b115 = base_params[13u];
    unsigned b116 = stwo_m31_mul(b19, b115);
    unsigned b117 = stwo_m31_add(b18, b116);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    unsigned b118 = base_params[14u];
    unsigned b119 = stwo_m31_mul(b20, b118);
    unsigned b120 = stwo_m31_add(b117, b119);
    unsigned b223 = stwo_m31_add(b222, b120);
    unsigned b224 = base_params[67u];
    unsigned b225 = stwo_m31_add(b223, b224);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 96u, row_index, 0);
    unsigned b226 = stwo_m31_sub(b225, b62);
    unsigned b227 = base_params[68u];
    unsigned b228 = stwo_m31_mul(b226, b227);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    unsigned b121 = base_params[15u];
    unsigned b122 = stwo_m31_mul(b22, b121);
    unsigned b123 = stwo_m31_add(b21, b122);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    unsigned b124 = base_params[16u];
    unsigned b125 = stwo_m31_mul(b23, b124);
    unsigned b126 = stwo_m31_add(b123, b125);
    unsigned b229 = stwo_m31_add(b228, b126);
    unsigned b230 = base_params[69u];
    unsigned b231 = stwo_m31_add(b229, b230);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 97u, row_index, 0);
    unsigned b232 = stwo_m31_sub(b231, b63);
    unsigned b233 = base_params[70u];
    unsigned b234 = stwo_m31_mul(b66, b233);
    unsigned b235 = stwo_m31_sub(b232, b234);
    unsigned b236 = base_params[71u];
    unsigned b237 = stwo_m31_mul(b235, b236);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    unsigned b127 = base_params[17u];
    unsigned b128 = stwo_m31_mul(b25, b127);
    unsigned b129 = stwo_m31_add(b24, b128);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    unsigned b130 = base_params[18u];
    unsigned b131 = stwo_m31_mul(b26, b130);
    unsigned b132 = stwo_m31_add(b129, b131);
    unsigned b238 = stwo_m31_add(b237, b132);
    unsigned b239 = base_params[72u];
    unsigned b240 = stwo_m31_add(b238, b239);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 98u, row_index, 0);
    unsigned b241 = stwo_m31_sub(b240, b64);
    unsigned b242 = base_params[73u];
    unsigned b243 = stwo_m31_mul(b241, b242);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    unsigned b244 = stwo_m31_add(b243, b27);
    unsigned b245 = base_params[74u];
    unsigned b246 = stwo_m31_add(b244, b245);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 99u, row_index, 0);
    unsigned b247 = stwo_m31_sub(b246, b65);
    unsigned b248 = base_params[75u];
    unsigned b249 = stwo_m31_mul(b66, b248);
    unsigned b250 = stwo_m31_sub(b247, b249);
    unsigned b78 = base_params[0u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b250, b78, b78, b78 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b251 = stwo_m31_mul(b66, b66);
    unsigned b252 = stwo_m31_mul(b251, b66);
    unsigned b253 = stwo_m31_sub(b252, b66);
    StwoCudaQm31 e1 = StwoCudaQm31{ b253, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b254 = stwo_m31_mul(b192, b192);
    unsigned b255 = stwo_m31_mul(b254, b192);
    unsigned b256 = stwo_m31_sub(b255, b192);
    StwoCudaQm31 e2 = StwoCudaQm31{ b256, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b257 = stwo_m31_mul(b198, b198);
    unsigned b258 = stwo_m31_mul(b257, b198);
    unsigned b259 = stwo_m31_sub(b258, b198);
    StwoCudaQm31 e3 = StwoCudaQm31{ b259, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b260 = stwo_m31_mul(b204, b204);
    unsigned b261 = stwo_m31_mul(b260, b204);
    unsigned b262 = stwo_m31_sub(b261, b204);
    StwoCudaQm31 e4 = StwoCudaQm31{ b262, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b263 = stwo_m31_mul(b210, b210);
    unsigned b264 = stwo_m31_mul(b263, b210);
    unsigned b265 = stwo_m31_sub(b264, b210);
    StwoCudaQm31 e5 = StwoCudaQm31{ b265, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b266 = stwo_m31_mul(b216, b216);
    unsigned b267 = stwo_m31_mul(b266, b216);
    unsigned b268 = stwo_m31_sub(b267, b216);
    StwoCudaQm31 e6 = StwoCudaQm31{ b268, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b269 = stwo_m31_mul(b222, b222);
    unsigned b270 = stwo_m31_mul(b269, b222);
    unsigned b271 = stwo_m31_sub(b270, b222);
    StwoCudaQm31 e7 = StwoCudaQm31{ b271, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b272 = stwo_m31_mul(b228, b228);
    unsigned b273 = stwo_m31_mul(b272, b228);
    unsigned b274 = stwo_m31_sub(b273, b228);
    StwoCudaQm31 e8 = StwoCudaQm31{ b274, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b275 = stwo_m31_mul(b237, b237);
    unsigned b276 = stwo_m31_mul(b275, b237);
    unsigned b277 = stwo_m31_sub(b276, b237);
    StwoCudaQm31 e9 = StwoCudaQm31{ b277, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b278 = stwo_m31_mul(b243, b243);
    unsigned b279 = stwo_m31_mul(b278, b243);
    unsigned b280 = stwo_m31_sub(b279, b243);
    StwoCudaQm31 e10 = StwoCudaQm31{ b280, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    unsigned b133 = base_params[19u];
    unsigned b134 = stwo_m31_mul(b29, b133);
    unsigned b135 = stwo_m31_add(b28, b134);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    unsigned b136 = base_params[20u];
    unsigned b137 = stwo_m31_mul(b30, b136);
    unsigned b138 = stwo_m31_add(b135, b137);
    unsigned b281 = base_params[76u];
    unsigned b282 = stwo_m31_add(b138, b281);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 101u, row_index, 0);
    unsigned b283 = stwo_m31_sub(b282, b67);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 111u, row_index, 0);
    unsigned b284 = stwo_m31_sub(b283, b77);
    unsigned b285 = base_params[77u];
    unsigned b286 = stwo_m31_mul(b284, b285);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    unsigned b139 = base_params[21u];
    unsigned b140 = stwo_m31_mul(b32, b139);
    unsigned b141 = stwo_m31_add(b31, b140);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    unsigned b142 = base_params[22u];
    unsigned b143 = stwo_m31_mul(b33, b142);
    unsigned b144 = stwo_m31_add(b141, b143);
    unsigned b287 = stwo_m31_add(b286, b144);
    unsigned b288 = base_params[78u];
    unsigned b289 = stwo_m31_add(b287, b288);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 102u, row_index, 0);
    unsigned b290 = stwo_m31_sub(b289, b68);
    unsigned b291 = base_params[79u];
    unsigned b292 = stwo_m31_mul(b290, b291);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    unsigned b145 = base_params[23u];
    unsigned b146 = stwo_m31_mul(b35, b145);
    unsigned b147 = stwo_m31_add(b34, b146);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    unsigned b148 = base_params[24u];
    unsigned b149 = stwo_m31_mul(b36, b148);
    unsigned b150 = stwo_m31_add(b147, b149);
    unsigned b293 = stwo_m31_add(b292, b150);
    unsigned b294 = base_params[80u];
    unsigned b295 = stwo_m31_add(b293, b294);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 103u, row_index, 0);
    unsigned b296 = stwo_m31_sub(b295, b69);
    unsigned b297 = base_params[81u];
    unsigned b298 = stwo_m31_mul(b296, b297);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    unsigned b151 = base_params[25u];
    unsigned b152 = stwo_m31_mul(b38, b151);
    unsigned b153 = stwo_m31_add(b37, b152);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    unsigned b154 = base_params[26u];
    unsigned b155 = stwo_m31_mul(b39, b154);
    unsigned b156 = stwo_m31_add(b153, b155);
    unsigned b299 = stwo_m31_add(b298, b156);
    unsigned b300 = base_params[82u];
    unsigned b301 = stwo_m31_add(b299, b300);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 104u, row_index, 0);
    unsigned b302 = stwo_m31_sub(b301, b70);
    unsigned b303 = base_params[83u];
    unsigned b304 = stwo_m31_mul(b302, b303);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    unsigned b157 = base_params[27u];
    unsigned b158 = stwo_m31_mul(b41, b157);
    unsigned b159 = stwo_m31_add(b40, b158);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    unsigned b160 = base_params[28u];
    unsigned b161 = stwo_m31_mul(b42, b160);
    unsigned b162 = stwo_m31_add(b159, b161);
    unsigned b305 = stwo_m31_add(b304, b162);
    unsigned b306 = base_params[84u];
    unsigned b307 = stwo_m31_add(b305, b306);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 105u, row_index, 0);
    unsigned b308 = stwo_m31_sub(b307, b71);
    unsigned b309 = base_params[85u];
    unsigned b310 = stwo_m31_mul(b308, b309);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    unsigned b163 = base_params[29u];
    unsigned b164 = stwo_m31_mul(b44, b163);
    unsigned b165 = stwo_m31_add(b43, b164);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    unsigned b166 = base_params[30u];
    unsigned b167 = stwo_m31_mul(b45, b166);
    unsigned b168 = stwo_m31_add(b165, b167);
    unsigned b311 = stwo_m31_add(b310, b168);
    unsigned b312 = base_params[86u];
    unsigned b313 = stwo_m31_add(b311, b312);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 106u, row_index, 0);
    unsigned b314 = stwo_m31_sub(b313, b72);
    unsigned b315 = base_params[87u];
    unsigned b316 = stwo_m31_mul(b314, b315);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    unsigned b169 = base_params[31u];
    unsigned b170 = stwo_m31_mul(b47, b169);
    unsigned b171 = stwo_m31_add(b46, b170);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 54u, row_index, 0);
    unsigned b172 = base_params[32u];
    unsigned b173 = stwo_m31_mul(b48, b172);
    unsigned b174 = stwo_m31_add(b171, b173);
    unsigned b317 = stwo_m31_add(b316, b174);
    unsigned b318 = base_params[88u];
    unsigned b319 = stwo_m31_add(b317, b318);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 107u, row_index, 0);
    unsigned b320 = stwo_m31_sub(b319, b73);
    unsigned b321 = base_params[89u];
    unsigned b322 = stwo_m31_mul(b320, b321);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 55u, row_index, 0);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    unsigned b175 = base_params[33u];
    unsigned b176 = stwo_m31_mul(b50, b175);
    unsigned b177 = stwo_m31_add(b49, b176);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    unsigned b178 = base_params[34u];
    unsigned b179 = stwo_m31_mul(b51, b178);
    unsigned b180 = stwo_m31_add(b177, b179);
    unsigned b323 = stwo_m31_add(b322, b180);
    unsigned b324 = base_params[90u];
    unsigned b325 = stwo_m31_add(b323, b324);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 108u, row_index, 0);
    unsigned b326 = stwo_m31_sub(b325, b74);
    unsigned b327 = base_params[91u];
    unsigned b328 = stwo_m31_mul(b77, b327);
    unsigned b329 = stwo_m31_sub(b326, b328);
    unsigned b330 = base_params[92u];
    unsigned b331 = stwo_m31_mul(b329, b330);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    unsigned b181 = base_params[35u];
    unsigned b182 = stwo_m31_mul(b53, b181);
    unsigned b183 = stwo_m31_add(b52, b182);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 60u, row_index, 0);
    unsigned b184 = base_params[36u];
    unsigned b185 = stwo_m31_mul(b54, b184);
    unsigned b186 = stwo_m31_add(b183, b185);
    unsigned b332 = stwo_m31_add(b331, b186);
    unsigned b333 = base_params[93u];
    unsigned b334 = stwo_m31_add(b332, b333);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 109u, row_index, 0);
    unsigned b335 = stwo_m31_sub(b334, b75);
    unsigned b336 = base_params[94u];
    unsigned b337 = stwo_m31_mul(b335, b336);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 61u, row_index, 0);
    unsigned b338 = stwo_m31_add(b337, b55);
    unsigned b339 = base_params[95u];
    unsigned b340 = stwo_m31_add(b338, b339);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 110u, row_index, 0);
    unsigned b341 = stwo_m31_sub(b340, b76);
    unsigned b342 = base_params[96u];
    unsigned b343 = stwo_m31_mul(b77, b342);
    unsigned b344 = stwo_m31_sub(b341, b343);
    StwoCudaQm31 e11 = StwoCudaQm31{ b344, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b345 = stwo_m31_mul(b77, b77);
    unsigned b346 = stwo_m31_mul(b345, b77);
    unsigned b347 = stwo_m31_sub(b346, b77);
    StwoCudaQm31 e12 = StwoCudaQm31{ b347, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b348 = stwo_m31_mul(b286, b286);
    unsigned b349 = stwo_m31_mul(b348, b286);
    unsigned b350 = stwo_m31_sub(b349, b286);
    StwoCudaQm31 e13 = StwoCudaQm31{ b350, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b351 = stwo_m31_mul(b292, b292);
    unsigned b352 = stwo_m31_mul(b351, b292);
    unsigned b353 = stwo_m31_sub(b352, b292);
    StwoCudaQm31 e14 = StwoCudaQm31{ b353, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));
    unsigned b354 = stwo_m31_mul(b298, b298);
    unsigned b355 = stwo_m31_mul(b354, b298);
    unsigned b356 = stwo_m31_sub(b355, b298);
    StwoCudaQm31 e15 = StwoCudaQm31{ b356, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 15u)));
    unsigned b357 = stwo_m31_mul(b304, b304);
    unsigned b358 = stwo_m31_mul(b357, b304);
    unsigned b359 = stwo_m31_sub(b358, b304);
    StwoCudaQm31 e16 = StwoCudaQm31{ b359, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 16u)));
    unsigned b360 = stwo_m31_mul(b310, b310);
    unsigned b361 = stwo_m31_mul(b360, b310);
    unsigned b362 = stwo_m31_sub(b361, b310);
    StwoCudaQm31 e17 = StwoCudaQm31{ b362, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 17u)));
    unsigned b363 = stwo_m31_mul(b316, b316);
    unsigned b364 = stwo_m31_mul(b363, b316);
    unsigned b365 = stwo_m31_sub(b364, b316);
    StwoCudaQm31 e18 = StwoCudaQm31{ b365, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 18u)));
    unsigned b366 = stwo_m31_mul(b322, b322);
    unsigned b367 = stwo_m31_mul(b366, b322);
    unsigned b368 = stwo_m31_sub(b367, b322);
    StwoCudaQm31 e19 = StwoCudaQm31{ b368, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e19, stwo_load_qm31(random_coeff_powers, rc_base + 19u)));
    unsigned b369 = stwo_m31_mul(b331, b331);
    unsigned b370 = stwo_m31_mul(b369, b331);
    unsigned b371 = stwo_m31_sub(b370, b331);
    StwoCudaQm31 e20 = StwoCudaQm31{ b371, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e20, stwo_load_qm31(random_coeff_powers, rc_base + 20u)));
    unsigned b372 = stwo_m31_mul(b337, b337);
    unsigned b373 = stwo_m31_mul(b372, b337);
    unsigned b374 = stwo_m31_sub(b373, b337);
    StwoCudaQm31 e21 = StwoCudaQm31{ b374, b78, b78, b78 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e21, stwo_load_qm31(random_coeff_powers, rc_base + 21u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
