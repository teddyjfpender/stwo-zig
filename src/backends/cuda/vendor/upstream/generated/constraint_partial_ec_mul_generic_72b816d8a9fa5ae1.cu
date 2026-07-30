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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_10b842b68ba9a504(
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
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 423u, row_index, 0);
    unsigned b457 = base_params[588u];
    unsigned b458 = stwo_m31_mul(b62, b457);
    unsigned b416 = base_params[523u];
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    unsigned b144 = stwo_m31_mul(b7, b10);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    unsigned b145 = stwo_m31_mul(b8, b9);
    unsigned b146 = stwo_m31_add(b144, b145);
    unsigned b147 = stwo_m31_mul(b9, b8);
    unsigned b148 = stwo_m31_add(b146, b147);
    unsigned b149 = stwo_m31_mul(b10, b7);
    unsigned b150 = stwo_m31_add(b148, b149);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    unsigned b193 = stwo_m31_add(b4, b11);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    unsigned b198 = stwo_m31_add(b6, b13);
    unsigned b199 = stwo_m31_mul(b193, b198);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    unsigned b194 = stwo_m31_add(b5, b12);
    unsigned b197 = stwo_m31_add(b5, b12);
    unsigned b200 = stwo_m31_mul(b194, b197);
    unsigned b201 = stwo_m31_add(b199, b200);
    unsigned b195 = stwo_m31_add(b6, b13);
    unsigned b196 = stwo_m31_add(b4, b11);
    unsigned b202 = stwo_m31_mul(b195, b196);
    unsigned b203 = stwo_m31_add(b201, b202);
    unsigned b135 = stwo_m31_mul(b4, b6);
    unsigned b136 = stwo_m31_mul(b5, b5);
    unsigned b137 = stwo_m31_add(b135, b136);
    unsigned b138 = stwo_m31_mul(b6, b4);
    unsigned b139 = stwo_m31_add(b137, b138);
    unsigned b204 = stwo_m31_sub(b203, b139);
    unsigned b184 = stwo_m31_mul(b11, b13);
    unsigned b185 = stwo_m31_mul(b12, b12);
    unsigned b186 = stwo_m31_add(b184, b185);
    unsigned b187 = stwo_m31_mul(b13, b11);
    unsigned b188 = stwo_m31_add(b186, b187);
    unsigned b205 = stwo_m31_sub(b204, b188);
    unsigned b206 = stwo_m31_add(b150, b205);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    unsigned b346 = stwo_m31_add(b0, b14);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    unsigned b356 = stwo_m31_add(b3, b17);
    unsigned b360 = stwo_m31_mul(b346, b356);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    unsigned b347 = stwo_m31_add(b1, b15);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    unsigned b355 = stwo_m31_add(b2, b16);
    unsigned b361 = stwo_m31_mul(b347, b355);
    unsigned b362 = stwo_m31_add(b360, b361);
    unsigned b348 = stwo_m31_add(b2, b16);
    unsigned b354 = stwo_m31_add(b1, b15);
    unsigned b363 = stwo_m31_mul(b348, b354);
    unsigned b364 = stwo_m31_add(b362, b363);
    unsigned b349 = stwo_m31_add(b3, b17);
    unsigned b353 = stwo_m31_add(b0, b14);
    unsigned b365 = stwo_m31_mul(b349, b353);
    unsigned b366 = stwo_m31_add(b364, b365);
    unsigned b95 = stwo_m31_mul(b0, b3);
    unsigned b96 = stwo_m31_mul(b1, b2);
    unsigned b97 = stwo_m31_add(b95, b96);
    unsigned b98 = stwo_m31_mul(b2, b1);
    unsigned b99 = stwo_m31_add(b97, b98);
    unsigned b100 = stwo_m31_mul(b3, b0);
    unsigned b101 = stwo_m31_add(b99, b100);
    unsigned b400 = stwo_m31_sub(b366, b101);
    unsigned b217 = stwo_m31_mul(b14, b17);
    unsigned b218 = stwo_m31_mul(b15, b16);
    unsigned b219 = stwo_m31_add(b217, b218);
    unsigned b220 = stwo_m31_mul(b16, b15);
    unsigned b221 = stwo_m31_add(b219, b220);
    unsigned b222 = stwo_m31_mul(b17, b14);
    unsigned b223 = stwo_m31_add(b221, b222);
    unsigned b401 = stwo_m31_sub(b400, b223);
    unsigned b402 = stwo_m31_add(b206, b401);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 387u, row_index, 0);
    unsigned b412 = stwo_m31_sub(b402, b56);
    unsigned b417 = stwo_m31_mul(b416, b412);
    unsigned b418 = base_params[524u];
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    unsigned b266 = stwo_m31_mul(b21, b24);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    unsigned b267 = stwo_m31_mul(b22, b23);
    unsigned b268 = stwo_m31_add(b266, b267);
    unsigned b269 = stwo_m31_mul(b23, b22);
    unsigned b270 = stwo_m31_add(b268, b269);
    unsigned b271 = stwo_m31_mul(b24, b21);
    unsigned b272 = stwo_m31_add(b270, b271);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    unsigned b322 = stwo_m31_add(b18, b25);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    unsigned b327 = stwo_m31_add(b20, b27);
    unsigned b328 = stwo_m31_mul(b322, b327);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    unsigned b323 = stwo_m31_add(b19, b26);
    unsigned b326 = stwo_m31_add(b19, b26);
    unsigned b329 = stwo_m31_mul(b323, b326);
    unsigned b330 = stwo_m31_add(b328, b329);
    unsigned b324 = stwo_m31_add(b20, b27);
    unsigned b325 = stwo_m31_add(b18, b25);
    unsigned b331 = stwo_m31_mul(b324, b325);
    unsigned b332 = stwo_m31_add(b330, b331);
    unsigned b257 = stwo_m31_mul(b18, b20);
    unsigned b258 = stwo_m31_mul(b19, b19);
    unsigned b259 = stwo_m31_add(b257, b258);
    unsigned b260 = stwo_m31_mul(b20, b18);
    unsigned b261 = stwo_m31_add(b259, b260);
    unsigned b333 = stwo_m31_sub(b332, b261);
    unsigned b313 = stwo_m31_mul(b25, b27);
    unsigned b314 = stwo_m31_mul(b26, b26);
    unsigned b315 = stwo_m31_add(b313, b314);
    unsigned b316 = stwo_m31_mul(b27, b25);
    unsigned b317 = stwo_m31_add(b315, b316);
    unsigned b334 = stwo_m31_sub(b333, b317);
    unsigned b335 = stwo_m31_add(b272, b334);
    unsigned b419 = stwo_m31_mul(b418, b335);
    unsigned b420 = stwo_m31_sub(b417, b419);
    unsigned b421 = base_params[525u];
    unsigned b306 = stwo_m31_mul(b24, b27);
    unsigned b307 = stwo_m31_mul(b25, b26);
    unsigned b308 = stwo_m31_add(b306, b307);
    unsigned b309 = stwo_m31_mul(b26, b25);
    unsigned b310 = stwo_m31_add(b308, b309);
    unsigned b311 = stwo_m31_mul(b27, b24);
    unsigned b312 = stwo_m31_add(b310, b311);
    unsigned b422 = stwo_m31_mul(b421, b312);
    unsigned b423 = stwo_m31_add(b420, b422);
    unsigned b424 = base_params[526u];
    unsigned b425 = stwo_m31_mul(b424, b317);
    unsigned b426 = stwo_m31_add(b423, b425);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 422u, row_index, 0);
    unsigned b459 = stwo_m31_add(b426, b61);
    unsigned b460 = stwo_m31_sub(b458, b459);
    unsigned b94 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b460, b94, b94, b94 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 424u, row_index, 0);
    unsigned b461 = base_params[590u];
    unsigned b462 = stwo_m31_mul(b63, b461);
    unsigned b427 = base_params[527u];
    unsigned b151 = stwo_m31_mul(b7, b11);
    unsigned b152 = stwo_m31_mul(b8, b10);
    unsigned b153 = stwo_m31_add(b151, b152);
    unsigned b154 = stwo_m31_mul(b9, b9);
    unsigned b155 = stwo_m31_add(b153, b154);
    unsigned b156 = stwo_m31_mul(b10, b8);
    unsigned b157 = stwo_m31_add(b155, b156);
    unsigned b158 = stwo_m31_mul(b11, b7);
    unsigned b159 = stwo_m31_add(b157, b158);
    unsigned b207 = stwo_m31_mul(b194, b198);
    unsigned b208 = stwo_m31_mul(b195, b197);
    unsigned b209 = stwo_m31_add(b207, b208);
    unsigned b140 = stwo_m31_mul(b5, b6);
    unsigned b141 = stwo_m31_mul(b6, b5);
    unsigned b142 = stwo_m31_add(b140, b141);
    unsigned b210 = stwo_m31_sub(b209, b142);
    unsigned b189 = stwo_m31_mul(b12, b13);
    unsigned b190 = stwo_m31_mul(b13, b12);
    unsigned b191 = stwo_m31_add(b189, b190);
    unsigned b211 = stwo_m31_sub(b210, b191);
    unsigned b212 = stwo_m31_add(b159, b211);
    unsigned b357 = stwo_m31_add(b4, b18);
    unsigned b367 = stwo_m31_mul(b346, b357);
    unsigned b368 = stwo_m31_mul(b347, b356);
    unsigned b369 = stwo_m31_add(b367, b368);
    unsigned b370 = stwo_m31_mul(b348, b355);
    unsigned b371 = stwo_m31_add(b369, b370);
    unsigned b372 = stwo_m31_mul(b349, b354);
    unsigned b373 = stwo_m31_add(b371, b372);
    unsigned b350 = stwo_m31_add(b4, b18);
    unsigned b374 = stwo_m31_mul(b350, b353);
    unsigned b375 = stwo_m31_add(b373, b374);
    unsigned b102 = stwo_m31_mul(b0, b4);
    unsigned b103 = stwo_m31_mul(b1, b3);
    unsigned b104 = stwo_m31_add(b102, b103);
    unsigned b105 = stwo_m31_mul(b2, b2);
    unsigned b106 = stwo_m31_add(b104, b105);
    unsigned b107 = stwo_m31_mul(b3, b1);
    unsigned b108 = stwo_m31_add(b106, b107);
    unsigned b109 = stwo_m31_mul(b4, b0);
    unsigned b110 = stwo_m31_add(b108, b109);
    unsigned b403 = stwo_m31_sub(b375, b110);
    unsigned b224 = stwo_m31_mul(b14, b18);
    unsigned b225 = stwo_m31_mul(b15, b17);
    unsigned b226 = stwo_m31_add(b224, b225);
    unsigned b227 = stwo_m31_mul(b16, b16);
    unsigned b228 = stwo_m31_add(b226, b227);
    unsigned b229 = stwo_m31_mul(b17, b15);
    unsigned b230 = stwo_m31_add(b228, b229);
    unsigned b231 = stwo_m31_mul(b18, b14);
    unsigned b232 = stwo_m31_add(b230, b231);
    unsigned b404 = stwo_m31_sub(b403, b232);
    unsigned b405 = stwo_m31_add(b212, b404);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 388u, row_index, 0);
    unsigned b413 = stwo_m31_sub(b405, b57);
    unsigned b428 = stwo_m31_mul(b427, b413);
    unsigned b429 = base_params[528u];
    unsigned b273 = stwo_m31_mul(b21, b25);
    unsigned b274 = stwo_m31_mul(b22, b24);
    unsigned b275 = stwo_m31_add(b273, b274);
    unsigned b276 = stwo_m31_mul(b23, b23);
    unsigned b277 = stwo_m31_add(b275, b276);
    unsigned b278 = stwo_m31_mul(b24, b22);
    unsigned b279 = stwo_m31_add(b277, b278);
    unsigned b280 = stwo_m31_mul(b25, b21);
    unsigned b281 = stwo_m31_add(b279, b280);
    unsigned b336 = stwo_m31_mul(b323, b327);
    unsigned b337 = stwo_m31_mul(b324, b326);
    unsigned b338 = stwo_m31_add(b336, b337);
    unsigned b262 = stwo_m31_mul(b19, b20);
    unsigned b263 = stwo_m31_mul(b20, b19);
    unsigned b264 = stwo_m31_add(b262, b263);
    unsigned b339 = stwo_m31_sub(b338, b264);
    unsigned b318 = stwo_m31_mul(b26, b27);
    unsigned b319 = stwo_m31_mul(b27, b26);
    unsigned b320 = stwo_m31_add(b318, b319);
    unsigned b340 = stwo_m31_sub(b339, b320);
    unsigned b341 = stwo_m31_add(b281, b340);
    unsigned b430 = stwo_m31_mul(b429, b341);
    unsigned b431 = stwo_m31_sub(b428, b430);
    unsigned b432 = base_params[529u];
    unsigned b433 = stwo_m31_mul(b432, b317);
    unsigned b434 = stwo_m31_add(b431, b433);
    unsigned b435 = base_params[530u];
    unsigned b436 = stwo_m31_mul(b435, b320);
    unsigned b437 = stwo_m31_add(b434, b436);
    unsigned b463 = stwo_m31_add(b437, b62);
    unsigned b464 = stwo_m31_sub(b462, b463);
    StwoCudaQm31 e1 = StwoCudaQm31{ b464, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 425u, row_index, 0);
    unsigned b465 = base_params[592u];
    unsigned b466 = stwo_m31_mul(b64, b465);
    unsigned b438 = base_params[531u];
    unsigned b160 = stwo_m31_mul(b7, b12);
    unsigned b161 = stwo_m31_mul(b8, b11);
    unsigned b162 = stwo_m31_add(b160, b161);
    unsigned b163 = stwo_m31_mul(b9, b10);
    unsigned b164 = stwo_m31_add(b162, b163);
    unsigned b165 = stwo_m31_mul(b10, b9);
    unsigned b166 = stwo_m31_add(b164, b165);
    unsigned b167 = stwo_m31_mul(b11, b8);
    unsigned b168 = stwo_m31_add(b166, b167);
    unsigned b169 = stwo_m31_mul(b12, b7);
    unsigned b170 = stwo_m31_add(b168, b169);
    unsigned b213 = stwo_m31_mul(b195, b198);
    unsigned b143 = stwo_m31_mul(b6, b6);
    unsigned b214 = stwo_m31_sub(b213, b143);
    unsigned b192 = stwo_m31_mul(b13, b13);
    unsigned b215 = stwo_m31_sub(b214, b192);
    unsigned b216 = stwo_m31_add(b170, b215);
    unsigned b358 = stwo_m31_add(b5, b19);
    unsigned b376 = stwo_m31_mul(b346, b358);
    unsigned b377 = stwo_m31_mul(b347, b357);
    unsigned b378 = stwo_m31_add(b376, b377);
    unsigned b379 = stwo_m31_mul(b348, b356);
    unsigned b380 = stwo_m31_add(b378, b379);
    unsigned b381 = stwo_m31_mul(b349, b355);
    unsigned b382 = stwo_m31_add(b380, b381);
    unsigned b383 = stwo_m31_mul(b350, b354);
    unsigned b384 = stwo_m31_add(b382, b383);
    unsigned b351 = stwo_m31_add(b5, b19);
    unsigned b385 = stwo_m31_mul(b351, b353);
    unsigned b386 = stwo_m31_add(b384, b385);
    unsigned b111 = stwo_m31_mul(b0, b5);
    unsigned b112 = stwo_m31_mul(b1, b4);
    unsigned b113 = stwo_m31_add(b111, b112);
    unsigned b114 = stwo_m31_mul(b2, b3);
    unsigned b115 = stwo_m31_add(b113, b114);
    unsigned b116 = stwo_m31_mul(b3, b2);
    unsigned b117 = stwo_m31_add(b115, b116);
    unsigned b118 = stwo_m31_mul(b4, b1);
    unsigned b119 = stwo_m31_add(b117, b118);
    unsigned b120 = stwo_m31_mul(b5, b0);
    unsigned b121 = stwo_m31_add(b119, b120);
    unsigned b406 = stwo_m31_sub(b386, b121);
    unsigned b233 = stwo_m31_mul(b14, b19);
    unsigned b234 = stwo_m31_mul(b15, b18);
    unsigned b235 = stwo_m31_add(b233, b234);
    unsigned b236 = stwo_m31_mul(b16, b17);
    unsigned b237 = stwo_m31_add(b235, b236);
    unsigned b238 = stwo_m31_mul(b17, b16);
    unsigned b239 = stwo_m31_add(b237, b238);
    unsigned b240 = stwo_m31_mul(b18, b15);
    unsigned b241 = stwo_m31_add(b239, b240);
    unsigned b242 = stwo_m31_mul(b19, b14);
    unsigned b243 = stwo_m31_add(b241, b242);
    unsigned b407 = stwo_m31_sub(b406, b243);
    unsigned b408 = stwo_m31_add(b216, b407);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 389u, row_index, 0);
    unsigned b414 = stwo_m31_sub(b408, b58);
    unsigned b439 = stwo_m31_mul(b438, b414);
    unsigned b440 = base_params[532u];
    unsigned b282 = stwo_m31_mul(b21, b26);
    unsigned b283 = stwo_m31_mul(b22, b25);
    unsigned b284 = stwo_m31_add(b282, b283);
    unsigned b285 = stwo_m31_mul(b23, b24);
    unsigned b286 = stwo_m31_add(b284, b285);
    unsigned b287 = stwo_m31_mul(b24, b23);
    unsigned b288 = stwo_m31_add(b286, b287);
    unsigned b289 = stwo_m31_mul(b25, b22);
    unsigned b290 = stwo_m31_add(b288, b289);
    unsigned b291 = stwo_m31_mul(b26, b21);
    unsigned b292 = stwo_m31_add(b290, b291);
    unsigned b342 = stwo_m31_mul(b324, b327);
    unsigned b265 = stwo_m31_mul(b20, b20);
    unsigned b343 = stwo_m31_sub(b342, b265);
    unsigned b321 = stwo_m31_mul(b27, b27);
    unsigned b344 = stwo_m31_sub(b343, b321);
    unsigned b345 = stwo_m31_add(b292, b344);
    unsigned b441 = stwo_m31_mul(b440, b345);
    unsigned b442 = stwo_m31_sub(b439, b441);
    unsigned b443 = base_params[533u];
    unsigned b444 = stwo_m31_mul(b443, b320);
    unsigned b445 = stwo_m31_add(b442, b444);
    unsigned b446 = base_params[534u];
    unsigned b447 = stwo_m31_mul(b446, b321);
    unsigned b448 = stwo_m31_add(b445, b447);
    unsigned b467 = stwo_m31_add(b448, b63);
    unsigned b468 = stwo_m31_sub(b466, b467);
    StwoCudaQm31 e2 = StwoCudaQm31{ b468, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b449 = base_params[535u];
    unsigned b171 = stwo_m31_mul(b7, b13);
    unsigned b172 = stwo_m31_mul(b8, b12);
    unsigned b173 = stwo_m31_add(b171, b172);
    unsigned b174 = stwo_m31_mul(b9, b11);
    unsigned b175 = stwo_m31_add(b173, b174);
    unsigned b176 = stwo_m31_mul(b10, b10);
    unsigned b177 = stwo_m31_add(b175, b176);
    unsigned b178 = stwo_m31_mul(b11, b9);
    unsigned b179 = stwo_m31_add(b177, b178);
    unsigned b180 = stwo_m31_mul(b12, b8);
    unsigned b181 = stwo_m31_add(b179, b180);
    unsigned b182 = stwo_m31_mul(b13, b7);
    unsigned b183 = stwo_m31_add(b181, b182);
    unsigned b359 = stwo_m31_add(b6, b20);
    unsigned b387 = stwo_m31_mul(b346, b359);
    unsigned b388 = stwo_m31_mul(b347, b358);
    unsigned b389 = stwo_m31_add(b387, b388);
    unsigned b390 = stwo_m31_mul(b348, b357);
    unsigned b391 = stwo_m31_add(b389, b390);
    unsigned b392 = stwo_m31_mul(b349, b356);
    unsigned b393 = stwo_m31_add(b391, b392);
    unsigned b394 = stwo_m31_mul(b350, b355);
    unsigned b395 = stwo_m31_add(b393, b394);
    unsigned b396 = stwo_m31_mul(b351, b354);
    unsigned b397 = stwo_m31_add(b395, b396);
    unsigned b352 = stwo_m31_add(b6, b20);
    unsigned b398 = stwo_m31_mul(b352, b353);
    unsigned b399 = stwo_m31_add(b397, b398);
    unsigned b122 = stwo_m31_mul(b0, b6);
    unsigned b123 = stwo_m31_mul(b1, b5);
    unsigned b124 = stwo_m31_add(b122, b123);
    unsigned b125 = stwo_m31_mul(b2, b4);
    unsigned b126 = stwo_m31_add(b124, b125);
    unsigned b127 = stwo_m31_mul(b3, b3);
    unsigned b128 = stwo_m31_add(b126, b127);
    unsigned b129 = stwo_m31_mul(b4, b2);
    unsigned b130 = stwo_m31_add(b128, b129);
    unsigned b131 = stwo_m31_mul(b5, b1);
    unsigned b132 = stwo_m31_add(b130, b131);
    unsigned b133 = stwo_m31_mul(b6, b0);
    unsigned b134 = stwo_m31_add(b132, b133);
    unsigned b409 = stwo_m31_sub(b399, b134);
    unsigned b244 = stwo_m31_mul(b14, b20);
    unsigned b245 = stwo_m31_mul(b15, b19);
    unsigned b246 = stwo_m31_add(b244, b245);
    unsigned b247 = stwo_m31_mul(b16, b18);
    unsigned b248 = stwo_m31_add(b246, b247);
    unsigned b249 = stwo_m31_mul(b17, b17);
    unsigned b250 = stwo_m31_add(b248, b249);
    unsigned b251 = stwo_m31_mul(b18, b16);
    unsigned b252 = stwo_m31_add(b250, b251);
    unsigned b253 = stwo_m31_mul(b19, b15);
    unsigned b254 = stwo_m31_add(b252, b253);
    unsigned b255 = stwo_m31_mul(b20, b14);
    unsigned b256 = stwo_m31_add(b254, b255);
    unsigned b410 = stwo_m31_sub(b409, b256);
    unsigned b411 = stwo_m31_add(b183, b410);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 390u, row_index, 0);
    unsigned b415 = stwo_m31_sub(b411, b59);
    unsigned b450 = stwo_m31_mul(b449, b415);
    unsigned b451 = base_params[536u];
    unsigned b293 = stwo_m31_mul(b21, b27);
    unsigned b294 = stwo_m31_mul(b22, b26);
    unsigned b295 = stwo_m31_add(b293, b294);
    unsigned b296 = stwo_m31_mul(b23, b25);
    unsigned b297 = stwo_m31_add(b295, b296);
    unsigned b298 = stwo_m31_mul(b24, b24);
    unsigned b299 = stwo_m31_add(b297, b298);
    unsigned b300 = stwo_m31_mul(b25, b23);
    unsigned b301 = stwo_m31_add(b299, b300);
    unsigned b302 = stwo_m31_mul(b26, b22);
    unsigned b303 = stwo_m31_add(b301, b302);
    unsigned b304 = stwo_m31_mul(b27, b21);
    unsigned b305 = stwo_m31_add(b303, b304);
    unsigned b452 = stwo_m31_mul(b451, b305);
    unsigned b453 = stwo_m31_sub(b450, b452);
    unsigned b454 = base_params[537u];
    unsigned b455 = stwo_m31_mul(b454, b321);
    unsigned b456 = stwo_m31_add(b453, b455);
    unsigned b469 = base_params[594u];
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 398u, row_index, 0);
    unsigned b470 = stwo_m31_mul(b469, b60);
    unsigned b471 = stwo_m31_sub(b456, b470);
    unsigned b472 = stwo_m31_add(b471, b64);
    StwoCudaQm31 e3 = StwoCudaQm31{ b472, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 454u, row_index, 0);
    unsigned b473 = base_params[595u];
    unsigned b474 = stwo_m31_sub(b93, b473);
    unsigned b475 = stwo_m31_mul(b93, b474);
    StwoCudaQm31 e4 = StwoCudaQm31{ b475, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    unsigned b476 = stwo_m31_add(b30, b30);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    unsigned b477 = stwo_m31_add(b29, b29);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    unsigned b478 = stwo_m31_add(b28, b28);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 426u, row_index, 0);
    unsigned b479 = stwo_m31_sub(b478, b65);
    unsigned b480 = stwo_m31_sub(b479, b93);
    unsigned b481 = base_params[596u];
    unsigned b482 = stwo_m31_mul(b480, b481);
    unsigned b483 = stwo_m31_add(b477, b482);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 427u, row_index, 0);
    unsigned b484 = stwo_m31_sub(b483, b66);
    unsigned b485 = base_params[597u];
    unsigned b486 = stwo_m31_mul(b484, b485);
    unsigned b487 = stwo_m31_add(b476, b486);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 428u, row_index, 0);
    unsigned b488 = stwo_m31_sub(b487, b67);
    unsigned b489 = base_params[598u];
    unsigned b490 = stwo_m31_mul(b488, b489);
    unsigned b491 = stwo_m31_mul(b490, b490);
    unsigned b492 = base_params[599u];
    unsigned b493 = stwo_m31_sub(b491, b492);
    unsigned b494 = stwo_m31_mul(b490, b493);
    StwoCudaQm31 e5 = StwoCudaQm31{ b494, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    unsigned b495 = stwo_m31_add(b33, b33);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    unsigned b496 = stwo_m31_add(b32, b32);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    unsigned b497 = stwo_m31_add(b31, b31);
    unsigned b498 = stwo_m31_add(b497, b490);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 429u, row_index, 0);
    unsigned b499 = stwo_m31_sub(b498, b68);
    unsigned b500 = base_params[600u];
    unsigned b501 = stwo_m31_mul(b499, b500);
    unsigned b502 = stwo_m31_add(b496, b501);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 430u, row_index, 0);
    unsigned b503 = stwo_m31_sub(b502, b69);
    unsigned b504 = base_params[601u];
    unsigned b505 = stwo_m31_mul(b503, b504);
    unsigned b506 = stwo_m31_add(b495, b505);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 431u, row_index, 0);
    unsigned b507 = stwo_m31_sub(b506, b70);
    unsigned b508 = base_params[602u];
    unsigned b509 = stwo_m31_mul(b507, b508);
    unsigned b510 = stwo_m31_mul(b509, b509);
    unsigned b511 = base_params[603u];
    unsigned b512 = stwo_m31_sub(b510, b511);
    unsigned b513 = stwo_m31_mul(b509, b512);
    StwoCudaQm31 e6 = StwoCudaQm31{ b513, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    unsigned b514 = stwo_m31_add(b36, b36);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    unsigned b515 = stwo_m31_add(b35, b35);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    unsigned b516 = stwo_m31_add(b34, b34);
    unsigned b517 = stwo_m31_add(b516, b509);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 432u, row_index, 0);
    unsigned b518 = stwo_m31_sub(b517, b71);
    unsigned b519 = base_params[604u];
    unsigned b520 = stwo_m31_mul(b518, b519);
    unsigned b521 = stwo_m31_add(b515, b520);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 433u, row_index, 0);
    unsigned b522 = stwo_m31_sub(b521, b72);
    unsigned b523 = base_params[605u];
    unsigned b524 = stwo_m31_mul(b522, b523);
    unsigned b525 = stwo_m31_add(b514, b524);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 434u, row_index, 0);
    unsigned b526 = stwo_m31_sub(b525, b73);
    unsigned b527 = base_params[606u];
    unsigned b528 = stwo_m31_mul(b526, b527);
    unsigned b529 = stwo_m31_mul(b528, b528);
    unsigned b530 = base_params[607u];
    unsigned b531 = stwo_m31_sub(b529, b530);
    unsigned b532 = stwo_m31_mul(b528, b531);
    StwoCudaQm31 e7 = StwoCudaQm31{ b532, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    unsigned b533 = stwo_m31_add(b39, b39);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    unsigned b534 = stwo_m31_add(b38, b38);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    unsigned b535 = stwo_m31_add(b37, b37);
    unsigned b536 = stwo_m31_add(b535, b528);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 435u, row_index, 0);
    unsigned b537 = stwo_m31_sub(b536, b74);
    unsigned b538 = base_params[608u];
    unsigned b539 = stwo_m31_mul(b537, b538);
    unsigned b540 = stwo_m31_add(b534, b539);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 436u, row_index, 0);
    unsigned b541 = stwo_m31_sub(b540, b75);
    unsigned b542 = base_params[609u];
    unsigned b543 = stwo_m31_mul(b541, b542);
    unsigned b544 = stwo_m31_add(b533, b543);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 437u, row_index, 0);
    unsigned b545 = stwo_m31_sub(b544, b76);
    unsigned b546 = base_params[610u];
    unsigned b547 = stwo_m31_mul(b545, b546);
    unsigned b548 = stwo_m31_mul(b547, b547);
    unsigned b549 = base_params[611u];
    unsigned b550 = stwo_m31_sub(b548, b549);
    unsigned b551 = stwo_m31_mul(b547, b550);
    StwoCudaQm31 e8 = StwoCudaQm31{ b551, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 54u, row_index, 0);
    unsigned b552 = stwo_m31_add(b42, b42);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    unsigned b553 = stwo_m31_add(b41, b41);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    unsigned b554 = stwo_m31_add(b40, b40);
    unsigned b555 = stwo_m31_add(b554, b547);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 438u, row_index, 0);
    unsigned b556 = stwo_m31_sub(b555, b77);
    unsigned b557 = base_params[612u];
    unsigned b558 = stwo_m31_mul(b556, b557);
    unsigned b559 = stwo_m31_add(b553, b558);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 439u, row_index, 0);
    unsigned b560 = stwo_m31_sub(b559, b78);
    unsigned b561 = base_params[613u];
    unsigned b562 = stwo_m31_mul(b560, b561);
    unsigned b563 = stwo_m31_add(b552, b562);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 440u, row_index, 0);
    unsigned b564 = stwo_m31_sub(b563, b79);
    unsigned b565 = base_params[614u];
    unsigned b566 = stwo_m31_mul(b564, b565);
    unsigned b567 = stwo_m31_mul(b566, b566);
    unsigned b568 = base_params[615u];
    unsigned b569 = stwo_m31_sub(b567, b568);
    unsigned b570 = stwo_m31_mul(b566, b569);
    StwoCudaQm31 e9 = StwoCudaQm31{ b570, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    unsigned b571 = stwo_m31_add(b45, b45);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    unsigned b572 = stwo_m31_add(b44, b44);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 55u, row_index, 0);
    unsigned b573 = stwo_m31_add(b43, b43);
    unsigned b574 = stwo_m31_add(b573, b566);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 441u, row_index, 0);
    unsigned b575 = stwo_m31_sub(b574, b80);
    unsigned b576 = base_params[616u];
    unsigned b577 = stwo_m31_mul(b575, b576);
    unsigned b578 = stwo_m31_add(b572, b577);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 442u, row_index, 0);
    unsigned b579 = stwo_m31_sub(b578, b81);
    unsigned b580 = base_params[617u];
    unsigned b581 = stwo_m31_mul(b579, b580);
    unsigned b582 = stwo_m31_add(b571, b581);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 443u, row_index, 0);
    unsigned b583 = stwo_m31_sub(b582, b82);
    unsigned b584 = base_params[618u];
    unsigned b585 = stwo_m31_mul(b583, b584);
    unsigned b586 = stwo_m31_mul(b585, b585);
    unsigned b587 = base_params[619u];
    unsigned b588 = stwo_m31_sub(b586, b587);
    unsigned b589 = stwo_m31_mul(b585, b588);
    StwoCudaQm31 e10 = StwoCudaQm31{ b589, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 60u, row_index, 0);
    unsigned b590 = stwo_m31_add(b48, b48);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    unsigned b591 = stwo_m31_add(b47, b47);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    unsigned b592 = stwo_m31_add(b46, b46);
    unsigned b593 = stwo_m31_add(b592, b585);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 444u, row_index, 0);
    unsigned b594 = stwo_m31_sub(b593, b83);
    unsigned b595 = base_params[620u];
    unsigned b596 = stwo_m31_mul(b594, b595);
    unsigned b597 = stwo_m31_add(b591, b596);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 445u, row_index, 0);
    unsigned b598 = stwo_m31_sub(b597, b84);
    unsigned b599 = base_params[621u];
    unsigned b600 = stwo_m31_mul(b598, b599);
    unsigned b601 = stwo_m31_add(b590, b600);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 446u, row_index, 0);
    unsigned b602 = stwo_m31_sub(b601, b85);
    unsigned b603 = base_params[622u];
    unsigned b604 = stwo_m31_mul(b602, b603);
    unsigned b605 = stwo_m31_mul(b604, b604);
    unsigned b606 = base_params[623u];
    unsigned b607 = stwo_m31_sub(b605, b606);
    unsigned b608 = stwo_m31_mul(b604, b607);
    StwoCudaQm31 e11 = StwoCudaQm31{ b608, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 63u, row_index, 0);
    unsigned b609 = stwo_m31_add(b51, b51);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 62u, row_index, 0);
    unsigned b610 = stwo_m31_add(b50, b50);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 61u, row_index, 0);
    unsigned b611 = stwo_m31_add(b49, b49);
    unsigned b612 = stwo_m31_add(b611, b604);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 447u, row_index, 0);
    unsigned b613 = stwo_m31_sub(b612, b86);
    unsigned b614 = base_params[624u];
    unsigned b615 = stwo_m31_mul(b614, b93);
    unsigned b616 = stwo_m31_sub(b613, b615);
    unsigned b617 = base_params[625u];
    unsigned b618 = stwo_m31_mul(b616, b617);
    unsigned b619 = stwo_m31_add(b610, b618);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 448u, row_index, 0);
    unsigned b620 = stwo_m31_sub(b619, b87);
    unsigned b621 = base_params[626u];
    unsigned b622 = stwo_m31_mul(b620, b621);
    unsigned b623 = stwo_m31_add(b609, b622);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 449u, row_index, 0);
    unsigned b624 = stwo_m31_sub(b623, b88);
    unsigned b625 = base_params[627u];
    unsigned b626 = stwo_m31_mul(b624, b625);
    unsigned b627 = stwo_m31_mul(b626, b626);
    unsigned b628 = base_params[628u];
    unsigned b629 = stwo_m31_sub(b627, b628);
    unsigned b630 = stwo_m31_mul(b626, b629);
    StwoCudaQm31 e12 = StwoCudaQm31{ b630, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 66u, row_index, 0);
    unsigned b631 = stwo_m31_add(b54, b54);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 65u, row_index, 0);
    unsigned b632 = stwo_m31_add(b53, b53);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 64u, row_index, 0);
    unsigned b633 = stwo_m31_add(b52, b52);
    unsigned b634 = stwo_m31_add(b633, b626);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 450u, row_index, 0);
    unsigned b635 = stwo_m31_sub(b634, b89);
    unsigned b636 = base_params[629u];
    unsigned b637 = stwo_m31_mul(b635, b636);
    unsigned b638 = stwo_m31_add(b632, b637);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 451u, row_index, 0);
    unsigned b639 = stwo_m31_sub(b638, b90);
    unsigned b640 = base_params[630u];
    unsigned b641 = stwo_m31_mul(b639, b640);
    unsigned b642 = stwo_m31_add(b631, b641);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 452u, row_index, 0);
    unsigned b643 = stwo_m31_sub(b642, b91);
    unsigned b644 = base_params[631u];
    unsigned b645 = stwo_m31_mul(b643, b644);
    unsigned b646 = stwo_m31_mul(b645, b645);
    unsigned b647 = base_params[632u];
    unsigned b648 = stwo_m31_sub(b646, b647);
    unsigned b649 = stwo_m31_mul(b645, b648);
    StwoCudaQm31 e13 = StwoCudaQm31{ b649, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 67u, row_index, 0);
    unsigned b650 = stwo_m31_add(b55, b55);
    unsigned b651 = stwo_m31_add(b650, b645);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 453u, row_index, 0);
    unsigned b652 = stwo_m31_sub(b651, b92);
    unsigned b653 = base_params[633u];
    unsigned b654 = stwo_m31_mul(b653, b93);
    unsigned b655 = stwo_m31_sub(b652, b654);
    StwoCudaQm31 e14 = StwoCudaQm31{ b655, b94, b94, b94 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
