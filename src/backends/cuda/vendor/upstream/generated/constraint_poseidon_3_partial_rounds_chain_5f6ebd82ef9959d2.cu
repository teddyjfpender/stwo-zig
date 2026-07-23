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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_c17b9b19eddf4bf9(
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
    unsigned b125 = base_params[1u];
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b126 = stwo_m31_mul(b125, b0);
    unsigned b127 = base_params[2u];
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b128 = stwo_m31_mul(b127, b10);
    unsigned b129 = stwo_m31_add(b126, b128);
    unsigned b130 = base_params[3u];
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    unsigned b131 = stwo_m31_mul(b130, b20);
    unsigned b132 = stwo_m31_add(b129, b131);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    unsigned b133 = stwo_m31_add(b132, b30);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 72u, row_index, 0);
    unsigned b134 = stwo_m31_sub(b133, b60);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    unsigned b135 = stwo_m31_add(b134, b40);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 82u, row_index, 0);
    unsigned b136 = stwo_m31_sub(b135, b70);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 92u, row_index, 0);
    unsigned b137 = stwo_m31_sub(b136, b80);
    unsigned b138 = base_params[4u];
    unsigned b139 = stwo_m31_mul(b137, b138);
    unsigned b140 = base_params[5u];
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    unsigned b141 = stwo_m31_mul(b140, b1);
    unsigned b142 = stwo_m31_add(b139, b141);
    unsigned b143 = base_params[6u];
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    unsigned b144 = stwo_m31_mul(b143, b11);
    unsigned b145 = stwo_m31_add(b142, b144);
    unsigned b146 = base_params[7u];
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    unsigned b147 = stwo_m31_mul(b146, b21);
    unsigned b148 = stwo_m31_add(b145, b147);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    unsigned b149 = stwo_m31_add(b148, b31);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 73u, row_index, 0);
    unsigned b150 = stwo_m31_sub(b149, b61);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    unsigned b151 = stwo_m31_add(b150, b41);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 83u, row_index, 0);
    unsigned b152 = stwo_m31_sub(b151, b71);
    unsigned b153 = base_params[8u];
    unsigned b154 = stwo_m31_mul(b152, b153);
    unsigned b155 = base_params[9u];
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    unsigned b156 = stwo_m31_mul(b155, b2);
    unsigned b157 = stwo_m31_add(b154, b156);
    unsigned b158 = base_params[10u];
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    unsigned b159 = stwo_m31_mul(b158, b12);
    unsigned b160 = stwo_m31_add(b157, b159);
    unsigned b161 = base_params[11u];
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    unsigned b162 = stwo_m31_mul(b161, b22);
    unsigned b163 = stwo_m31_add(b160, b162);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    unsigned b164 = stwo_m31_add(b163, b32);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 74u, row_index, 0);
    unsigned b165 = stwo_m31_sub(b164, b62);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    unsigned b166 = stwo_m31_add(b165, b42);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 84u, row_index, 0);
    unsigned b167 = stwo_m31_sub(b166, b72);
    unsigned b168 = base_params[12u];
    unsigned b169 = stwo_m31_mul(b167, b168);
    unsigned b170 = base_params[13u];
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    unsigned b171 = stwo_m31_mul(b170, b3);
    unsigned b172 = stwo_m31_add(b169, b171);
    unsigned b173 = base_params[14u];
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b174 = stwo_m31_mul(b173, b13);
    unsigned b175 = stwo_m31_add(b172, b174);
    unsigned b176 = base_params[15u];
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    unsigned b177 = stwo_m31_mul(b176, b23);
    unsigned b178 = stwo_m31_add(b175, b177);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    unsigned b179 = stwo_m31_add(b178, b33);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 75u, row_index, 0);
    unsigned b180 = stwo_m31_sub(b179, b63);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    unsigned b181 = stwo_m31_add(b180, b43);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 85u, row_index, 0);
    unsigned b182 = stwo_m31_sub(b181, b73);
    unsigned b183 = base_params[16u];
    unsigned b184 = stwo_m31_mul(b182, b183);
    unsigned b185 = base_params[17u];
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b186 = stwo_m31_mul(b185, b4);
    unsigned b187 = stwo_m31_add(b184, b186);
    unsigned b188 = base_params[18u];
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b189 = stwo_m31_mul(b188, b14);
    unsigned b190 = stwo_m31_add(b187, b189);
    unsigned b191 = base_params[19u];
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    unsigned b192 = stwo_m31_mul(b191, b24);
    unsigned b193 = stwo_m31_add(b190, b192);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    unsigned b194 = stwo_m31_add(b193, b34);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 76u, row_index, 0);
    unsigned b195 = stwo_m31_sub(b194, b64);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    unsigned b196 = stwo_m31_add(b195, b44);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 86u, row_index, 0);
    unsigned b197 = stwo_m31_sub(b196, b74);
    unsigned b198 = base_params[20u];
    unsigned b199 = stwo_m31_mul(b197, b198);
    unsigned b200 = base_params[21u];
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b201 = stwo_m31_mul(b200, b5);
    unsigned b202 = stwo_m31_add(b199, b201);
    unsigned b203 = base_params[22u];
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    unsigned b204 = stwo_m31_mul(b203, b15);
    unsigned b205 = stwo_m31_add(b202, b204);
    unsigned b206 = base_params[23u];
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    unsigned b207 = stwo_m31_mul(b206, b25);
    unsigned b208 = stwo_m31_add(b205, b207);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    unsigned b209 = stwo_m31_add(b208, b35);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 77u, row_index, 0);
    unsigned b210 = stwo_m31_sub(b209, b65);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    unsigned b211 = stwo_m31_add(b210, b45);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 87u, row_index, 0);
    unsigned b212 = stwo_m31_sub(b211, b75);
    unsigned b213 = base_params[24u];
    unsigned b214 = stwo_m31_mul(b212, b213);
    unsigned b215 = base_params[25u];
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b216 = stwo_m31_mul(b215, b6);
    unsigned b217 = stwo_m31_add(b214, b216);
    unsigned b218 = base_params[26u];
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    unsigned b219 = stwo_m31_mul(b218, b16);
    unsigned b220 = stwo_m31_add(b217, b219);
    unsigned b221 = base_params[27u];
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    unsigned b222 = stwo_m31_mul(b221, b26);
    unsigned b223 = stwo_m31_add(b220, b222);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    unsigned b224 = stwo_m31_add(b223, b36);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 78u, row_index, 0);
    unsigned b225 = stwo_m31_sub(b224, b66);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    unsigned b226 = stwo_m31_add(b225, b46);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 88u, row_index, 0);
    unsigned b227 = stwo_m31_sub(b226, b76);
    unsigned b228 = base_params[28u];
    unsigned b229 = stwo_m31_mul(b227, b228);
    unsigned b230 = base_params[29u];
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b231 = stwo_m31_mul(b230, b7);
    unsigned b232 = stwo_m31_add(b229, b231);
    unsigned b233 = base_params[30u];
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    unsigned b234 = stwo_m31_mul(b233, b17);
    unsigned b235 = stwo_m31_add(b232, b234);
    unsigned b236 = base_params[31u];
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    unsigned b237 = stwo_m31_mul(b236, b27);
    unsigned b238 = stwo_m31_add(b235, b237);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    unsigned b239 = stwo_m31_add(b238, b37);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 79u, row_index, 0);
    unsigned b240 = stwo_m31_sub(b239, b67);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    unsigned b241 = stwo_m31_add(b240, b47);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 89u, row_index, 0);
    unsigned b242 = stwo_m31_sub(b241, b77);
    unsigned b243 = base_params[32u];
    unsigned b244 = stwo_m31_mul(b80, b243);
    unsigned b245 = stwo_m31_sub(b242, b244);
    unsigned b246 = base_params[33u];
    unsigned b247 = stwo_m31_mul(b245, b246);
    unsigned b248 = base_params[34u];
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b249 = stwo_m31_mul(b248, b8);
    unsigned b250 = stwo_m31_add(b247, b249);
    unsigned b251 = base_params[35u];
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    unsigned b252 = stwo_m31_mul(b251, b18);
    unsigned b253 = stwo_m31_add(b250, b252);
    unsigned b254 = base_params[36u];
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    unsigned b255 = stwo_m31_mul(b254, b28);
    unsigned b256 = stwo_m31_add(b253, b255);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    unsigned b257 = stwo_m31_add(b256, b38);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 80u, row_index, 0);
    unsigned b258 = stwo_m31_sub(b257, b68);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    unsigned b259 = stwo_m31_add(b258, b48);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 90u, row_index, 0);
    unsigned b260 = stwo_m31_sub(b259, b78);
    unsigned b261 = base_params[37u];
    unsigned b262 = stwo_m31_mul(b260, b261);
    unsigned b263 = base_params[38u];
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b264 = stwo_m31_mul(b263, b9);
    unsigned b265 = stwo_m31_add(b262, b264);
    unsigned b266 = base_params[39u];
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    unsigned b267 = stwo_m31_mul(b266, b19);
    unsigned b268 = stwo_m31_add(b265, b267);
    unsigned b269 = base_params[40u];
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    unsigned b270 = stwo_m31_mul(b269, b29);
    unsigned b271 = stwo_m31_add(b268, b270);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    unsigned b272 = stwo_m31_add(b271, b39);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 81u, row_index, 0);
    unsigned b273 = stwo_m31_sub(b272, b69);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    unsigned b274 = stwo_m31_add(b273, b49);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 91u, row_index, 0);
    unsigned b275 = stwo_m31_sub(b274, b79);
    unsigned b276 = base_params[41u];
    unsigned b277 = stwo_m31_mul(b80, b276);
    unsigned b278 = stwo_m31_sub(b275, b277);
    unsigned b124 = base_params[0u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b278, b124, b124, b124 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b279 = base_params[52u];
    unsigned b280 = stwo_m31_mul(b279, b70);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 93u, row_index, 0);
    unsigned b281 = stwo_m31_sub(b280, b81);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 103u, row_index, 0);
    unsigned b282 = stwo_m31_sub(b281, b91);
    unsigned b283 = base_params[53u];
    unsigned b284 = stwo_m31_mul(b282, b283);
    unsigned b285 = base_params[54u];
    unsigned b286 = stwo_m31_mul(b285, b71);
    unsigned b287 = stwo_m31_add(b284, b286);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 94u, row_index, 0);
    unsigned b288 = stwo_m31_sub(b287, b82);
    unsigned b289 = base_params[55u];
    unsigned b290 = stwo_m31_mul(b288, b289);
    unsigned b291 = base_params[56u];
    unsigned b292 = stwo_m31_mul(b291, b72);
    unsigned b293 = stwo_m31_add(b290, b292);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 95u, row_index, 0);
    unsigned b294 = stwo_m31_sub(b293, b83);
    unsigned b295 = base_params[57u];
    unsigned b296 = stwo_m31_mul(b294, b295);
    unsigned b297 = base_params[58u];
    unsigned b298 = stwo_m31_mul(b297, b73);
    unsigned b299 = stwo_m31_add(b296, b298);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 96u, row_index, 0);
    unsigned b300 = stwo_m31_sub(b299, b84);
    unsigned b301 = base_params[59u];
    unsigned b302 = stwo_m31_mul(b300, b301);
    unsigned b303 = base_params[60u];
    unsigned b304 = stwo_m31_mul(b303, b74);
    unsigned b305 = stwo_m31_add(b302, b304);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 97u, row_index, 0);
    unsigned b306 = stwo_m31_sub(b305, b85);
    unsigned b307 = base_params[61u];
    unsigned b308 = stwo_m31_mul(b306, b307);
    unsigned b309 = base_params[62u];
    unsigned b310 = stwo_m31_mul(b309, b75);
    unsigned b311 = stwo_m31_add(b308, b310);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 98u, row_index, 0);
    unsigned b312 = stwo_m31_sub(b311, b86);
    unsigned b313 = base_params[63u];
    unsigned b314 = stwo_m31_mul(b312, b313);
    unsigned b315 = base_params[64u];
    unsigned b316 = stwo_m31_mul(b315, b76);
    unsigned b317 = stwo_m31_add(b314, b316);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 99u, row_index, 0);
    unsigned b318 = stwo_m31_sub(b317, b87);
    unsigned b319 = base_params[65u];
    unsigned b320 = stwo_m31_mul(b318, b319);
    unsigned b321 = base_params[66u];
    unsigned b322 = stwo_m31_mul(b321, b77);
    unsigned b323 = stwo_m31_add(b320, b322);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 100u, row_index, 0);
    unsigned b324 = stwo_m31_sub(b323, b88);
    unsigned b325 = base_params[67u];
    unsigned b326 = stwo_m31_mul(b91, b325);
    unsigned b327 = stwo_m31_sub(b324, b326);
    unsigned b328 = base_params[68u];
    unsigned b329 = stwo_m31_mul(b327, b328);
    unsigned b330 = base_params[69u];
    unsigned b331 = stwo_m31_mul(b330, b78);
    unsigned b332 = stwo_m31_add(b329, b331);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 101u, row_index, 0);
    unsigned b333 = stwo_m31_sub(b332, b89);
    unsigned b334 = base_params[70u];
    unsigned b335 = stwo_m31_mul(b333, b334);
    unsigned b336 = base_params[71u];
    unsigned b337 = stwo_m31_mul(b336, b79);
    unsigned b338 = stwo_m31_add(b335, b337);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 102u, row_index, 0);
    unsigned b339 = stwo_m31_sub(b338, b90);
    unsigned b340 = base_params[72u];
    unsigned b341 = stwo_m31_mul(b91, b340);
    unsigned b342 = stwo_m31_sub(b339, b341);
    StwoCudaQm31 e1 = StwoCudaQm31{ b342, b124, b124, b124 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b343 = stwo_m31_mul(b91, b91);
    unsigned b344 = stwo_m31_mul(b343, b91);
    unsigned b345 = stwo_m31_sub(b344, b91);
    StwoCudaQm31 e2 = StwoCudaQm31{ b345, b124, b124, b124 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b346 = stwo_m31_mul(b284, b284);
    unsigned b347 = stwo_m31_mul(b346, b284);
    unsigned b348 = stwo_m31_sub(b347, b284);
    StwoCudaQm31 e3 = StwoCudaQm31{ b348, b124, b124, b124 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b349 = stwo_m31_mul(b290, b290);
    unsigned b350 = stwo_m31_mul(b349, b290);
    unsigned b351 = stwo_m31_sub(b350, b290);
    StwoCudaQm31 e4 = StwoCudaQm31{ b351, b124, b124, b124 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b352 = stwo_m31_mul(b296, b296);
    unsigned b353 = stwo_m31_mul(b352, b296);
    unsigned b354 = stwo_m31_sub(b353, b296);
    StwoCudaQm31 e5 = StwoCudaQm31{ b354, b124, b124, b124 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b355 = stwo_m31_mul(b302, b302);
    unsigned b356 = stwo_m31_mul(b355, b302);
    unsigned b357 = stwo_m31_sub(b356, b302);
    StwoCudaQm31 e6 = StwoCudaQm31{ b357, b124, b124, b124 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b358 = stwo_m31_mul(b308, b308);
    unsigned b359 = stwo_m31_mul(b358, b308);
    unsigned b360 = stwo_m31_sub(b359, b308);
    StwoCudaQm31 e7 = StwoCudaQm31{ b360, b124, b124, b124 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b361 = stwo_m31_mul(b314, b314);
    unsigned b362 = stwo_m31_mul(b361, b314);
    unsigned b363 = stwo_m31_sub(b362, b314);
    StwoCudaQm31 e8 = StwoCudaQm31{ b363, b124, b124, b124 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b364 = stwo_m31_mul(b320, b320);
    unsigned b365 = stwo_m31_mul(b364, b320);
    unsigned b366 = stwo_m31_sub(b365, b320);
    StwoCudaQm31 e9 = StwoCudaQm31{ b366, b124, b124, b124 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b367 = stwo_m31_mul(b329, b329);
    unsigned b368 = stwo_m31_mul(b367, b329);
    unsigned b369 = stwo_m31_sub(b368, b329);
    StwoCudaQm31 e10 = StwoCudaQm31{ b369, b124, b124, b124 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b370 = stwo_m31_mul(b335, b335);
    unsigned b371 = stwo_m31_mul(b370, b335);
    unsigned b372 = stwo_m31_sub(b371, b335);
    StwoCudaQm31 e11 = StwoCudaQm31{ b372, b124, b124, b124 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b373 = base_params[73u];
    unsigned b374 = stwo_m31_mul(b373, b20);
    unsigned b375 = base_params[74u];
    unsigned b376 = stwo_m31_mul(b375, b30);
    unsigned b377 = stwo_m31_add(b374, b376);
    unsigned b378 = base_params[75u];
    unsigned b379 = stwo_m31_mul(b378, b60);
    unsigned b380 = stwo_m31_add(b377, b379);
    unsigned b381 = stwo_m31_add(b380, b81);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 104u, row_index, 0);
    unsigned b382 = stwo_m31_sub(b381, b92);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    unsigned b383 = stwo_m31_add(b382, b50);
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 114u, row_index, 0);
    unsigned b384 = stwo_m31_sub(b383, b102);
    unsigned b112 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 124u, row_index, 0);
    unsigned b385 = stwo_m31_sub(b384, b112);
    unsigned b386 = base_params[76u];
    unsigned b387 = stwo_m31_mul(b385, b386);
    unsigned b388 = base_params[77u];
    unsigned b389 = stwo_m31_mul(b388, b21);
    unsigned b390 = stwo_m31_add(b387, b389);
    unsigned b391 = base_params[78u];
    unsigned b392 = stwo_m31_mul(b391, b31);
    unsigned b393 = stwo_m31_add(b390, b392);
    unsigned b394 = base_params[79u];
    unsigned b395 = stwo_m31_mul(b394, b61);
    unsigned b396 = stwo_m31_add(b393, b395);
    unsigned b397 = stwo_m31_add(b396, b82);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 105u, row_index, 0);
    unsigned b398 = stwo_m31_sub(b397, b93);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    unsigned b399 = stwo_m31_add(b398, b51);
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 115u, row_index, 0);
    unsigned b400 = stwo_m31_sub(b399, b103);
    unsigned b401 = base_params[80u];
    unsigned b402 = stwo_m31_mul(b400, b401);
    unsigned b403 = base_params[81u];
    unsigned b404 = stwo_m31_mul(b403, b22);
    unsigned b405 = stwo_m31_add(b402, b404);
    unsigned b406 = base_params[82u];
    unsigned b407 = stwo_m31_mul(b406, b32);
    unsigned b408 = stwo_m31_add(b405, b407);
    unsigned b409 = base_params[83u];
    unsigned b410 = stwo_m31_mul(b409, b62);
    unsigned b411 = stwo_m31_add(b408, b410);
    unsigned b412 = stwo_m31_add(b411, b83);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 106u, row_index, 0);
    unsigned b413 = stwo_m31_sub(b412, b94);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 54u, row_index, 0);
    unsigned b414 = stwo_m31_add(b413, b52);
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 116u, row_index, 0);
    unsigned b415 = stwo_m31_sub(b414, b104);
    unsigned b416 = base_params[84u];
    unsigned b417 = stwo_m31_mul(b415, b416);
    unsigned b418 = base_params[85u];
    unsigned b419 = stwo_m31_mul(b418, b23);
    unsigned b420 = stwo_m31_add(b417, b419);
    unsigned b421 = base_params[86u];
    unsigned b422 = stwo_m31_mul(b421, b33);
    unsigned b423 = stwo_m31_add(b420, b422);
    unsigned b424 = base_params[87u];
    unsigned b425 = stwo_m31_mul(b424, b63);
    unsigned b426 = stwo_m31_add(b423, b425);
    unsigned b427 = stwo_m31_add(b426, b84);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 107u, row_index, 0);
    unsigned b428 = stwo_m31_sub(b427, b95);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 55u, row_index, 0);
    unsigned b429 = stwo_m31_add(b428, b53);
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 117u, row_index, 0);
    unsigned b430 = stwo_m31_sub(b429, b105);
    unsigned b431 = base_params[88u];
    unsigned b432 = stwo_m31_mul(b430, b431);
    unsigned b433 = base_params[89u];
    unsigned b434 = stwo_m31_mul(b433, b24);
    unsigned b435 = stwo_m31_add(b432, b434);
    unsigned b436 = base_params[90u];
    unsigned b437 = stwo_m31_mul(b436, b34);
    unsigned b438 = stwo_m31_add(b435, b437);
    unsigned b439 = base_params[91u];
    unsigned b440 = stwo_m31_mul(b439, b64);
    unsigned b441 = stwo_m31_add(b438, b440);
    unsigned b442 = stwo_m31_add(b441, b85);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 108u, row_index, 0);
    unsigned b443 = stwo_m31_sub(b442, b96);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    unsigned b444 = stwo_m31_add(b443, b54);
    unsigned b106 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 118u, row_index, 0);
    unsigned b445 = stwo_m31_sub(b444, b106);
    unsigned b446 = base_params[92u];
    unsigned b447 = stwo_m31_mul(b445, b446);
    unsigned b448 = base_params[93u];
    unsigned b449 = stwo_m31_mul(b448, b25);
    unsigned b450 = stwo_m31_add(b447, b449);
    unsigned b451 = base_params[94u];
    unsigned b452 = stwo_m31_mul(b451, b35);
    unsigned b453 = stwo_m31_add(b450, b452);
    unsigned b454 = base_params[95u];
    unsigned b455 = stwo_m31_mul(b454, b65);
    unsigned b456 = stwo_m31_add(b453, b455);
    unsigned b457 = stwo_m31_add(b456, b86);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 109u, row_index, 0);
    unsigned b458 = stwo_m31_sub(b457, b97);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    unsigned b459 = stwo_m31_add(b458, b55);
    unsigned b107 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 119u, row_index, 0);
    unsigned b460 = stwo_m31_sub(b459, b107);
    unsigned b461 = base_params[96u];
    unsigned b462 = stwo_m31_mul(b460, b461);
    unsigned b463 = base_params[97u];
    unsigned b464 = stwo_m31_mul(b463, b26);
    unsigned b465 = stwo_m31_add(b462, b464);
    unsigned b466 = base_params[98u];
    unsigned b467 = stwo_m31_mul(b466, b36);
    unsigned b468 = stwo_m31_add(b465, b467);
    unsigned b469 = base_params[99u];
    unsigned b470 = stwo_m31_mul(b469, b66);
    unsigned b471 = stwo_m31_add(b468, b470);
    unsigned b472 = stwo_m31_add(b471, b87);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 110u, row_index, 0);
    unsigned b473 = stwo_m31_sub(b472, b98);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    unsigned b474 = stwo_m31_add(b473, b56);
    unsigned b108 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 120u, row_index, 0);
    unsigned b475 = stwo_m31_sub(b474, b108);
    unsigned b476 = base_params[100u];
    unsigned b477 = stwo_m31_mul(b475, b476);
    unsigned b478 = base_params[101u];
    unsigned b479 = stwo_m31_mul(b478, b27);
    unsigned b480 = stwo_m31_add(b477, b479);
    unsigned b481 = base_params[102u];
    unsigned b482 = stwo_m31_mul(b481, b37);
    unsigned b483 = stwo_m31_add(b480, b482);
    unsigned b484 = base_params[103u];
    unsigned b485 = stwo_m31_mul(b484, b67);
    unsigned b486 = stwo_m31_add(b483, b485);
    unsigned b487 = stwo_m31_add(b486, b88);
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 111u, row_index, 0);
    unsigned b488 = stwo_m31_sub(b487, b99);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    unsigned b489 = stwo_m31_add(b488, b57);
    unsigned b109 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 121u, row_index, 0);
    unsigned b490 = stwo_m31_sub(b489, b109);
    unsigned b491 = base_params[104u];
    unsigned b492 = stwo_m31_mul(b112, b491);
    unsigned b493 = stwo_m31_sub(b490, b492);
    unsigned b494 = base_params[105u];
    unsigned b495 = stwo_m31_mul(b493, b494);
    unsigned b496 = base_params[106u];
    unsigned b497 = stwo_m31_mul(b496, b28);
    unsigned b498 = stwo_m31_add(b495, b497);
    unsigned b499 = base_params[107u];
    unsigned b500 = stwo_m31_mul(b499, b38);
    unsigned b501 = stwo_m31_add(b498, b500);
    unsigned b502 = base_params[108u];
    unsigned b503 = stwo_m31_mul(b502, b68);
    unsigned b504 = stwo_m31_add(b501, b503);
    unsigned b505 = stwo_m31_add(b504, b89);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 112u, row_index, 0);
    unsigned b506 = stwo_m31_sub(b505, b100);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 60u, row_index, 0);
    unsigned b507 = stwo_m31_add(b506, b58);
    unsigned b110 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 122u, row_index, 0);
    unsigned b508 = stwo_m31_sub(b507, b110);
    unsigned b509 = base_params[109u];
    unsigned b510 = stwo_m31_mul(b508, b509);
    unsigned b511 = base_params[110u];
    unsigned b512 = stwo_m31_mul(b511, b29);
    unsigned b513 = stwo_m31_add(b510, b512);
    unsigned b514 = base_params[111u];
    unsigned b515 = stwo_m31_mul(b514, b39);
    unsigned b516 = stwo_m31_add(b513, b515);
    unsigned b517 = base_params[112u];
    unsigned b518 = stwo_m31_mul(b517, b69);
    unsigned b519 = stwo_m31_add(b516, b518);
    unsigned b520 = stwo_m31_add(b519, b90);
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 113u, row_index, 0);
    unsigned b521 = stwo_m31_sub(b520, b101);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 61u, row_index, 0);
    unsigned b522 = stwo_m31_add(b521, b59);
    unsigned b111 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 123u, row_index, 0);
    unsigned b523 = stwo_m31_sub(b522, b111);
    unsigned b524 = base_params[113u];
    unsigned b525 = stwo_m31_mul(b112, b524);
    unsigned b526 = stwo_m31_sub(b523, b525);
    StwoCudaQm31 e12 = StwoCudaQm31{ b526, b124, b124, b124 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b527 = base_params[124u];
    unsigned b528 = stwo_m31_mul(b527, b102);
    unsigned b113 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 125u, row_index, 0);
    unsigned b529 = stwo_m31_sub(b528, b113);
    unsigned b123 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 135u, row_index, 0);
    unsigned b530 = stwo_m31_sub(b529, b123);
    unsigned b531 = base_params[125u];
    unsigned b532 = stwo_m31_mul(b530, b531);
    unsigned b533 = base_params[126u];
    unsigned b534 = stwo_m31_mul(b533, b103);
    unsigned b535 = stwo_m31_add(b532, b534);
    unsigned b114 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 126u, row_index, 0);
    unsigned b536 = stwo_m31_sub(b535, b114);
    unsigned b537 = base_params[127u];
    unsigned b538 = stwo_m31_mul(b536, b537);
    unsigned b539 = base_params[128u];
    unsigned b540 = stwo_m31_mul(b539, b104);
    unsigned b541 = stwo_m31_add(b538, b540);
    unsigned b115 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 127u, row_index, 0);
    unsigned b542 = stwo_m31_sub(b541, b115);
    unsigned b543 = base_params[129u];
    unsigned b544 = stwo_m31_mul(b542, b543);
    unsigned b545 = base_params[130u];
    unsigned b546 = stwo_m31_mul(b545, b105);
    unsigned b547 = stwo_m31_add(b544, b546);
    unsigned b116 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 128u, row_index, 0);
    unsigned b548 = stwo_m31_sub(b547, b116);
    unsigned b549 = base_params[131u];
    unsigned b550 = stwo_m31_mul(b548, b549);
    unsigned b551 = base_params[132u];
    unsigned b552 = stwo_m31_mul(b551, b106);
    unsigned b553 = stwo_m31_add(b550, b552);
    unsigned b117 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 129u, row_index, 0);
    unsigned b554 = stwo_m31_sub(b553, b117);
    unsigned b555 = base_params[133u];
    unsigned b556 = stwo_m31_mul(b554, b555);
    unsigned b557 = base_params[134u];
    unsigned b558 = stwo_m31_mul(b557, b107);
    unsigned b559 = stwo_m31_add(b556, b558);
    unsigned b118 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 130u, row_index, 0);
    unsigned b560 = stwo_m31_sub(b559, b118);
    unsigned b561 = base_params[135u];
    unsigned b562 = stwo_m31_mul(b560, b561);
    unsigned b563 = base_params[136u];
    unsigned b564 = stwo_m31_mul(b563, b108);
    unsigned b565 = stwo_m31_add(b562, b564);
    unsigned b119 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 131u, row_index, 0);
    unsigned b566 = stwo_m31_sub(b565, b119);
    unsigned b567 = base_params[137u];
    unsigned b568 = stwo_m31_mul(b566, b567);
    unsigned b569 = base_params[138u];
    unsigned b570 = stwo_m31_mul(b569, b109);
    unsigned b571 = stwo_m31_add(b568, b570);
    unsigned b120 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 132u, row_index, 0);
    unsigned b572 = stwo_m31_sub(b571, b120);
    unsigned b573 = base_params[139u];
    unsigned b574 = stwo_m31_mul(b123, b573);
    unsigned b575 = stwo_m31_sub(b572, b574);
    unsigned b576 = base_params[140u];
    unsigned b577 = stwo_m31_mul(b575, b576);
    unsigned b578 = base_params[141u];
    unsigned b579 = stwo_m31_mul(b578, b110);
    unsigned b580 = stwo_m31_add(b577, b579);
    unsigned b121 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 133u, row_index, 0);
    unsigned b581 = stwo_m31_sub(b580, b121);
    unsigned b582 = base_params[142u];
    unsigned b583 = stwo_m31_mul(b581, b582);
    unsigned b584 = base_params[143u];
    unsigned b585 = stwo_m31_mul(b584, b111);
    unsigned b586 = stwo_m31_add(b583, b585);
    unsigned b122 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 134u, row_index, 0);
    unsigned b587 = stwo_m31_sub(b586, b122);
    unsigned b588 = base_params[144u];
    unsigned b589 = stwo_m31_mul(b123, b588);
    unsigned b590 = stwo_m31_sub(b587, b589);
    StwoCudaQm31 e13 = StwoCudaQm31{ b590, b124, b124, b124 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b591 = stwo_m31_mul(b123, b123);
    unsigned b592 = stwo_m31_mul(b591, b123);
    unsigned b593 = stwo_m31_sub(b592, b123);
    StwoCudaQm31 e14 = StwoCudaQm31{ b593, b124, b124, b124 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));
    unsigned b594 = stwo_m31_mul(b532, b532);
    unsigned b595 = stwo_m31_mul(b594, b532);
    unsigned b596 = stwo_m31_sub(b595, b532);
    StwoCudaQm31 e15 = StwoCudaQm31{ b596, b124, b124, b124 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 15u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
