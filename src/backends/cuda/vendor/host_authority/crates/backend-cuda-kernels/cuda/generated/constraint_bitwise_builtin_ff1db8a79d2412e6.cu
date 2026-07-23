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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_3580cfff4a530943(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 210u);
    unsigned b203 = base_params[35u];
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    unsigned b201 = base_params[34u];
    unsigned b202 = stwo_m31_mul(b0, b201);
    unsigned b204 = stwo_m31_add(b203, b202);
    unsigned b205 = base_params[36u];
    unsigned b206 = stwo_m31_add(b204, b205);
    unsigned b88 = base_params[2u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b206, b88, b88, b88 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 211u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 212u);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 86u, row_index, 0);
    e2 = StwoCudaQm31{ b85, b88, b88, b88 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 213u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 214u);
    e2 = StwoCudaQm31{ b85, b88, b88, b88 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 215u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 216u);
    unsigned b91 = base_params[6u];
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    unsigned b89 = stwo_m31_add(b1, b29);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    unsigned b90 = stwo_m31_sub(b89, b57);
    unsigned b92 = stwo_m31_mul(b91, b90);
    e1 = StwoCudaQm31{ b92, b88, b88, b88 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 217u);
    unsigned b95 = base_params[7u];
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    unsigned b93 = stwo_m31_add(b2, b30);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    unsigned b94 = stwo_m31_sub(b93, b58);
    unsigned b96 = stwo_m31_mul(b95, b94);
    e3 = StwoCudaQm31{ b96, b88, b88, b88 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 218u);
    unsigned b99 = base_params[8u];
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    unsigned b97 = stwo_m31_add(b3, b31);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 60u, row_index, 0);
    unsigned b98 = stwo_m31_sub(b97, b59);
    unsigned b100 = stwo_m31_mul(b99, b98);
    e1 = StwoCudaQm31{ b100, b88, b88, b88 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 219u);
    unsigned b103 = base_params[9u];
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    unsigned b101 = stwo_m31_add(b4, b32);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 61u, row_index, 0);
    unsigned b102 = stwo_m31_sub(b101, b60);
    unsigned b104 = stwo_m31_mul(b103, b102);
    e3 = StwoCudaQm31{ b104, b88, b88, b88 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 220u);
    unsigned b107 = base_params[10u];
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    unsigned b105 = stwo_m31_add(b5, b33);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 62u, row_index, 0);
    unsigned b106 = stwo_m31_sub(b105, b61);
    unsigned b108 = stwo_m31_mul(b107, b106);
    e1 = StwoCudaQm31{ b108, b88, b88, b88 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 221u);
    unsigned b111 = base_params[11u];
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    unsigned b109 = stwo_m31_add(b6, b34);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 63u, row_index, 0);
    unsigned b110 = stwo_m31_sub(b109, b62);
    unsigned b112 = stwo_m31_mul(b111, b110);
    e3 = StwoCudaQm31{ b112, b88, b88, b88 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 222u);
    unsigned b115 = base_params[12u];
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    unsigned b113 = stwo_m31_add(b7, b35);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 64u, row_index, 0);
    unsigned b114 = stwo_m31_sub(b113, b63);
    unsigned b116 = stwo_m31_mul(b115, b114);
    e1 = StwoCudaQm31{ b116, b88, b88, b88 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 223u);
    unsigned b119 = base_params[13u];
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    unsigned b117 = stwo_m31_add(b8, b36);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 65u, row_index, 0);
    unsigned b118 = stwo_m31_sub(b117, b64);
    unsigned b120 = stwo_m31_mul(b119, b118);
    e3 = StwoCudaQm31{ b120, b88, b88, b88 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 224u);
    unsigned b123 = base_params[14u];
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    unsigned b121 = stwo_m31_add(b9, b37);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 66u, row_index, 0);
    unsigned b122 = stwo_m31_sub(b121, b65);
    unsigned b124 = stwo_m31_mul(b123, b122);
    e1 = StwoCudaQm31{ b124, b88, b88, b88 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 225u);
    unsigned b127 = base_params[15u];
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    unsigned b125 = stwo_m31_add(b10, b38);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 67u, row_index, 0);
    unsigned b126 = stwo_m31_sub(b125, b66);
    unsigned b128 = stwo_m31_mul(b127, b126);
    e3 = StwoCudaQm31{ b128, b88, b88, b88 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 226u);
    unsigned b131 = base_params[16u];
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    unsigned b129 = stwo_m31_add(b11, b39);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 68u, row_index, 0);
    unsigned b130 = stwo_m31_sub(b129, b67);
    unsigned b132 = stwo_m31_mul(b131, b130);
    e1 = StwoCudaQm31{ b132, b88, b88, b88 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 227u);
    unsigned b135 = base_params[17u];
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    unsigned b133 = stwo_m31_add(b12, b40);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 69u, row_index, 0);
    unsigned b134 = stwo_m31_sub(b133, b68);
    unsigned b136 = stwo_m31_mul(b135, b134);
    e3 = StwoCudaQm31{ b136, b88, b88, b88 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 228u);
    unsigned b139 = base_params[18u];
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    unsigned b137 = stwo_m31_add(b13, b41);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 70u, row_index, 0);
    unsigned b138 = stwo_m31_sub(b137, b69);
    unsigned b140 = stwo_m31_mul(b139, b138);
    e1 = StwoCudaQm31{ b140, b88, b88, b88 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 229u);
    unsigned b143 = base_params[19u];
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    unsigned b141 = stwo_m31_add(b14, b42);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 71u, row_index, 0);
    unsigned b142 = stwo_m31_sub(b141, b70);
    unsigned b144 = stwo_m31_mul(b143, b142);
    e3 = StwoCudaQm31{ b144, b88, b88, b88 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 230u);
    unsigned b147 = base_params[20u];
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    unsigned b145 = stwo_m31_add(b15, b43);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 72u, row_index, 0);
    unsigned b146 = stwo_m31_sub(b145, b71);
    unsigned b148 = stwo_m31_mul(b147, b146);
    e1 = StwoCudaQm31{ b148, b88, b88, b88 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 231u);
    unsigned b151 = base_params[21u];
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    unsigned b149 = stwo_m31_add(b16, b44);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 73u, row_index, 0);
    unsigned b150 = stwo_m31_sub(b149, b72);
    unsigned b152 = stwo_m31_mul(b151, b150);
    e3 = StwoCudaQm31{ b152, b88, b88, b88 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 232u);
    unsigned b155 = base_params[22u];
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    unsigned b153 = stwo_m31_add(b17, b45);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 74u, row_index, 0);
    unsigned b154 = stwo_m31_sub(b153, b73);
    unsigned b156 = stwo_m31_mul(b155, b154);
    e1 = StwoCudaQm31{ b156, b88, b88, b88 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 233u);
    unsigned b159 = base_params[23u];
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    unsigned b157 = stwo_m31_add(b18, b46);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 75u, row_index, 0);
    unsigned b158 = stwo_m31_sub(b157, b74);
    unsigned b160 = stwo_m31_mul(b159, b158);
    e3 = StwoCudaQm31{ b160, b88, b88, b88 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 234u);
    unsigned b163 = base_params[24u];
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    unsigned b161 = stwo_m31_add(b19, b47);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 76u, row_index, 0);
    unsigned b162 = stwo_m31_sub(b161, b75);
    unsigned b164 = stwo_m31_mul(b163, b162);
    e1 = StwoCudaQm31{ b164, b88, b88, b88 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 235u);
    unsigned b167 = base_params[25u];
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    unsigned b165 = stwo_m31_add(b20, b48);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 77u, row_index, 0);
    unsigned b166 = stwo_m31_sub(b165, b76);
    unsigned b168 = stwo_m31_mul(b167, b166);
    e3 = StwoCudaQm31{ b168, b88, b88, b88 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 236u);
    unsigned b171 = base_params[26u];
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    unsigned b169 = stwo_m31_add(b21, b49);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 78u, row_index, 0);
    unsigned b170 = stwo_m31_sub(b169, b77);
    unsigned b172 = stwo_m31_mul(b171, b170);
    e1 = StwoCudaQm31{ b172, b88, b88, b88 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 237u);
    unsigned b175 = base_params[27u];
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    unsigned b173 = stwo_m31_add(b22, b50);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 79u, row_index, 0);
    unsigned b174 = stwo_m31_sub(b173, b78);
    unsigned b176 = stwo_m31_mul(b175, b174);
    e3 = StwoCudaQm31{ b176, b88, b88, b88 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 238u);
    unsigned b179 = base_params[28u];
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    unsigned b177 = stwo_m31_add(b23, b51);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 80u, row_index, 0);
    unsigned b178 = stwo_m31_sub(b177, b79);
    unsigned b180 = stwo_m31_mul(b179, b178);
    e1 = StwoCudaQm31{ b180, b88, b88, b88 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 239u);
    unsigned b183 = base_params[29u];
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    unsigned b181 = stwo_m31_add(b24, b52);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 81u, row_index, 0);
    unsigned b182 = stwo_m31_sub(b181, b80);
    unsigned b184 = stwo_m31_mul(b183, b182);
    e3 = StwoCudaQm31{ b184, b88, b88, b88 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 240u);
    unsigned b187 = base_params[30u];
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 54u, row_index, 0);
    unsigned b185 = stwo_m31_add(b25, b53);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 82u, row_index, 0);
    unsigned b186 = stwo_m31_sub(b185, b81);
    unsigned b188 = stwo_m31_mul(b187, b186);
    e1 = StwoCudaQm31{ b188, b88, b88, b88 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 241u);
    unsigned b191 = base_params[31u];
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 55u, row_index, 0);
    unsigned b189 = stwo_m31_add(b26, b54);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 83u, row_index, 0);
    unsigned b190 = stwo_m31_sub(b189, b82);
    unsigned b192 = stwo_m31_mul(b191, b190);
    e3 = StwoCudaQm31{ b192, b88, b88, b88 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 242u);
    unsigned b195 = base_params[32u];
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    unsigned b193 = stwo_m31_add(b27, b55);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 84u, row_index, 0);
    unsigned b194 = stwo_m31_sub(b193, b83);
    unsigned b196 = stwo_m31_mul(b195, b194);
    e1 = StwoCudaQm31{ b196, b88, b88, b88 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 243u);
    unsigned b199 = base_params[33u];
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    unsigned b197 = stwo_m31_add(b28, b56);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 85u, row_index, 0);
    unsigned b198 = stwo_m31_sub(b197, b84);
    unsigned b200 = stwo_m31_mul(b199, b198);
    e3 = StwoCudaQm31{ b200, b88, b88, b88 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 244u);
    e1 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(ext_params, 245u);
    unsigned b209 = base_params[38u];
    unsigned b207 = base_params[37u];
    unsigned b208 = stwo_m31_mul(b0, b207);
    unsigned b210 = stwo_m31_add(b209, b208);
    unsigned b211 = base_params[39u];
    unsigned b212 = stwo_m31_add(b210, b211);
    e3 = StwoCudaQm31{ b212, b88, b88, b88 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 246u);
    e2 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(ext_params, 247u);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 87u, row_index, 0);
    e4 = StwoCudaQm31{ b86, b88, b88, b88 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(ext_params, 248u);
    e2 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(ext_params, 249u);
    e4 = StwoCudaQm31{ b86, b88, b88, b88 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(ext_params, 250u);
    e5 = stwo_qm31_add(e4, e3);
    e4 = stwo_load_qm31(ext_params, 251u);
    e3 = StwoCudaQm31{ b57, b88, b88, b88 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 252u);
    e5 = StwoCudaQm31{ b58, b88, b88, b88 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 253u);
    e3 = StwoCudaQm31{ b59, b88, b88, b88 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 254u);
    e5 = StwoCudaQm31{ b60, b88, b88, b88 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 255u);
    e3 = StwoCudaQm31{ b61, b88, b88, b88 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 256u);
    e5 = StwoCudaQm31{ b62, b88, b88, b88 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 257u);
    e3 = StwoCudaQm31{ b63, b88, b88, b88 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 258u);
    e5 = StwoCudaQm31{ b64, b88, b88, b88 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 259u);
    e3 = StwoCudaQm31{ b65, b88, b88, b88 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 260u);
    e5 = StwoCudaQm31{ b66, b88, b88, b88 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 261u);
    e3 = StwoCudaQm31{ b67, b88, b88, b88 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 262u);
    e5 = StwoCudaQm31{ b68, b88, b88, b88 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 263u);
    e3 = StwoCudaQm31{ b69, b88, b88, b88 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 264u);
    e5 = StwoCudaQm31{ b70, b88, b88, b88 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 265u);
    e3 = StwoCudaQm31{ b71, b88, b88, b88 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 266u);
    e5 = StwoCudaQm31{ b72, b88, b88, b88 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 267u);
    e3 = StwoCudaQm31{ b73, b88, b88, b88 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 268u);
    e5 = StwoCudaQm31{ b74, b88, b88, b88 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 269u);
    e3 = StwoCudaQm31{ b75, b88, b88, b88 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 270u);
    e5 = StwoCudaQm31{ b76, b88, b88, b88 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 271u);
    e3 = StwoCudaQm31{ b77, b88, b88, b88 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 272u);
    e5 = StwoCudaQm31{ b78, b88, b88, b88 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 273u);
    e3 = StwoCudaQm31{ b79, b88, b88, b88 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 274u);
    e5 = StwoCudaQm31{ b80, b88, b88, b88 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 275u);
    e3 = StwoCudaQm31{ b81, b88, b88, b88 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 276u);
    e5 = StwoCudaQm31{ b82, b88, b88, b88 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 277u);
    e3 = StwoCudaQm31{ b83, b88, b88, b88 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 278u);
    e5 = StwoCudaQm31{ b84, b88, b88, b88 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 279u);
    e3 = stwo_qm31_sub(e5, e4);
    e4 = stwo_load_qm31(ext_params, 280u);
    unsigned b215 = base_params[41u];
    unsigned b213 = base_params[40u];
    unsigned b214 = stwo_m31_mul(b0, b213);
    unsigned b216 = stwo_m31_add(b215, b214);
    unsigned b217 = base_params[42u];
    unsigned b218 = stwo_m31_add(b216, b217);
    e5 = StwoCudaQm31{ b218, b88, b88, b88 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 281u);
    e4 = stwo_qm31_add(e5, e6);
    e5 = stwo_load_qm31(ext_params, 282u);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 88u, row_index, 0);
    e6 = StwoCudaQm31{ b87, b88, b88, b88 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 283u);
    e4 = stwo_qm31_sub(e6, e7);
    e7 = stwo_load_qm31(ext_params, 284u);
    e6 = StwoCudaQm31{ b87, b88, b88, b88 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_load_qm31(ext_params, 285u);
    e7 = stwo_qm31_add(e6, e5);
    e6 = stwo_load_qm31(ext_params, 286u);
    unsigned b219 = stwo_m31_add(b92, b57);
    e5 = StwoCudaQm31{ b219, b88, b88, b88 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 287u);
    unsigned b220 = stwo_m31_add(b96, b58);
    e7 = StwoCudaQm31{ b220, b88, b88, b88 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 288u);
    unsigned b221 = stwo_m31_add(b100, b59);
    e5 = StwoCudaQm31{ b221, b88, b88, b88 };
    e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 289u);
    unsigned b222 = stwo_m31_add(b104, b60);
    e7 = StwoCudaQm31{ b222, b88, b88, b88 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 290u);
    unsigned b223 = stwo_m31_add(b108, b61);
    e5 = StwoCudaQm31{ b223, b88, b88, b88 };
    e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 291u);
    unsigned b224 = stwo_m31_add(b112, b62);
    e7 = StwoCudaQm31{ b224, b88, b88, b88 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 292u);
    unsigned b225 = stwo_m31_add(b116, b63);
    e5 = StwoCudaQm31{ b225, b88, b88, b88 };
    e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 293u);
    unsigned b226 = stwo_m31_add(b120, b64);
    e7 = StwoCudaQm31{ b226, b88, b88, b88 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 294u);
    unsigned b227 = stwo_m31_add(b124, b65);
    e5 = StwoCudaQm31{ b227, b88, b88, b88 };
    e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 295u);
    unsigned b228 = stwo_m31_add(b128, b66);
    e7 = StwoCudaQm31{ b228, b88, b88, b88 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 296u);
    unsigned b229 = stwo_m31_add(b132, b67);
    e5 = StwoCudaQm31{ b229, b88, b88, b88 };
    e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 297u);
    unsigned b230 = stwo_m31_add(b136, b68);
    e7 = StwoCudaQm31{ b230, b88, b88, b88 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 298u);
    unsigned b231 = stwo_m31_add(b140, b69);
    e5 = StwoCudaQm31{ b231, b88, b88, b88 };
    e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 299u);
    unsigned b232 = stwo_m31_add(b144, b70);
    e7 = StwoCudaQm31{ b232, b88, b88, b88 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 300u);
    unsigned b233 = stwo_m31_add(b148, b71);
    e5 = StwoCudaQm31{ b233, b88, b88, b88 };
    e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 301u);
    unsigned b234 = stwo_m31_add(b152, b72);
    e7 = StwoCudaQm31{ b234, b88, b88, b88 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 302u);
    unsigned b235 = stwo_m31_add(b156, b73);
    e5 = StwoCudaQm31{ b235, b88, b88, b88 };
    e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 303u);
    unsigned b236 = stwo_m31_add(b160, b74);
    e7 = StwoCudaQm31{ b236, b88, b88, b88 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 304u);
    unsigned b237 = stwo_m31_add(b164, b75);
    e5 = StwoCudaQm31{ b237, b88, b88, b88 };
    e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 305u);
    unsigned b238 = stwo_m31_add(b168, b76);
    e7 = StwoCudaQm31{ b238, b88, b88, b88 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 306u);
    unsigned b239 = stwo_m31_add(b172, b77);
    e5 = StwoCudaQm31{ b239, b88, b88, b88 };
    e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 307u);
    unsigned b240 = stwo_m31_add(b176, b78);
    e7 = StwoCudaQm31{ b240, b88, b88, b88 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 308u);
    unsigned b241 = stwo_m31_add(b180, b79);
    e5 = StwoCudaQm31{ b241, b88, b88, b88 };
    e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 309u);
    unsigned b242 = stwo_m31_add(b184, b80);
    e7 = StwoCudaQm31{ b242, b88, b88, b88 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 310u);
    unsigned b243 = stwo_m31_add(b188, b81);
    e5 = StwoCudaQm31{ b243, b88, b88, b88 };
    e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 311u);
    unsigned b244 = stwo_m31_add(b192, b82);
    e7 = StwoCudaQm31{ b244, b88, b88, b88 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 312u);
    unsigned b245 = stwo_m31_add(b196, b83);
    e5 = StwoCudaQm31{ b245, b88, b88, b88 };
    e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 313u);
    unsigned b246 = stwo_m31_add(b200, b84);
    e7 = StwoCudaQm31{ b246, b88, b88, b88 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 314u);
    e5 = stwo_qm31_sub(e7, e6);
    e6 = stwo_load_qm31(ext_params, 347u);
    e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_load_qm31(ext_params, 348u);
    e8 = stwo_qm31_mul(e0, e6);
    e6 = stwo_qm31_add(e7, e8);
    e8 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 349u);
    e0 = stwo_qm31_mul(e3, e1);
    e1 = stwo_load_qm31(ext_params, 350u);
    e7 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e0, e7);
    e7 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 351u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 352u);
    e0 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e0);
    e0 = stwo_qm31_mul(e4, e5);
    unsigned b247 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 60u, row_index, 0);
    unsigned b248 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 61u, row_index, 0);
    unsigned b249 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 62u, row_index, 0);
    unsigned b250 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 63u, row_index, 0);
    e5 = StwoCudaQm31{ b247, b248, b249, b250 };
    unsigned b251 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 64u, row_index, 0);
    unsigned b252 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 65u, row_index, 0);
    unsigned b253 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 66u, row_index, 0);
    unsigned b254 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 67u, row_index, 0);
    e4 = StwoCudaQm31{ b251, b252, b253, b254 };
    e2 = stwo_qm31_sub(e4, e5);
    e5 = stwo_qm31_mul(e2, e8);
    e2 = stwo_qm31_sub(e5, e6);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b255 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 68u, row_index, 0);
    unsigned b256 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 69u, row_index, 0);
    unsigned b257 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 70u, row_index, 0);
    unsigned b258 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 71u, row_index, 0);
    e5 = StwoCudaQm31{ b255, b256, b257, b258 };
    e6 = stwo_qm31_sub(e5, e4);
    e4 = stwo_qm31_mul(e6, e7);
    e6 = stwo_qm31_sub(e4, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b259 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 72u, row_index, -1);
    unsigned b261 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 73u, row_index, -1);
    unsigned b263 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 74u, row_index, -1);
    unsigned b265 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 75u, row_index, -1);
    e4 = StwoCudaQm31{ b259, b261, b263, b265 };
    unsigned b260 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 72u, row_index, 0);
    unsigned b262 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 73u, row_index, 0);
    unsigned b264 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 74u, row_index, 0);
    unsigned b266 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 75u, row_index, 0);
    e1 = StwoCudaQm31{ b260, b262, b264, b266 };
    e7 = stwo_qm31_sub(e1, e4);
    e1 = stwo_qm31_sub(e7, e5);
    e7 = stwo_load_qm31(ext_params, 353u);
    e5 = stwo_qm31_add(e1, e7);
    e7 = stwo_qm31_mul(e5, e0);
    e5 = stwo_qm31_sub(e7, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
