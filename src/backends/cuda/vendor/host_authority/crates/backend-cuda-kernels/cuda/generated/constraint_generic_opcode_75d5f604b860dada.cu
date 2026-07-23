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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_b215c5a89b5de51b(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b108 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b0, b108, b108, b108 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 2u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e2 = StwoCudaQm31{ b3, b108, b108, b108 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 3u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e0 = StwoCudaQm31{ b4, b108, b108, b108 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 4u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e2 = StwoCudaQm31{ b5, b108, b108, b108 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 5u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b109 = base_params[16u];
    unsigned b110 = stwo_m31_mul(b6, b109);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b111 = base_params[17u];
    unsigned b112 = stwo_m31_mul(b7, b111);
    unsigned b113 = stwo_m31_add(b110, b112);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b114 = base_params[18u];
    unsigned b115 = stwo_m31_mul(b8, b114);
    unsigned b116 = stwo_m31_add(b113, b115);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b117 = base_params[19u];
    unsigned b118 = stwo_m31_mul(b9, b117);
    unsigned b119 = stwo_m31_add(b116, b118);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b120 = base_params[20u];
    unsigned b121 = stwo_m31_mul(b10, b120);
    unsigned b122 = stwo_m31_add(b119, b121);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b123 = base_params[21u];
    unsigned b124 = stwo_m31_mul(b11, b123);
    unsigned b125 = stwo_m31_add(b122, b124);
    e0 = StwoCudaQm31{ b125, b108, b108, b108 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 6u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    unsigned b126 = base_params[22u];
    unsigned b127 = stwo_m31_mul(b13, b126);
    unsigned b128 = stwo_m31_add(b12, b127);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    unsigned b129 = base_params[23u];
    unsigned b130 = stwo_m31_mul(b14, b129);
    unsigned b131 = stwo_m31_add(b128, b130);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b132 = base_params[24u];
    unsigned b133 = stwo_m31_mul(b15, b132);
    unsigned b134 = stwo_m31_add(b131, b133);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b135 = base_params[25u];
    unsigned b136 = stwo_m31_mul(b16, b135);
    unsigned b137 = stwo_m31_add(b134, b136);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    unsigned b138 = base_params[26u];
    unsigned b139 = stwo_m31_mul(b17, b138);
    unsigned b140 = stwo_m31_add(b137, b139);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    unsigned b141 = base_params[27u];
    unsigned b142 = stwo_m31_mul(b18, b141);
    unsigned b143 = stwo_m31_add(b140, b142);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    unsigned b144 = base_params[28u];
    unsigned b145 = stwo_m31_mul(b19, b144);
    unsigned b146 = stwo_m31_add(b143, b145);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    unsigned b147 = base_params[29u];
    unsigned b148 = stwo_m31_mul(b20, b147);
    unsigned b149 = stwo_m31_add(b146, b148);
    e2 = StwoCudaQm31{ b149, b108, b108, b108 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 7u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 8u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    unsigned b150 = base_params[30u];
    unsigned b151 = stwo_m31_sub(b3, b150);
    unsigned b165 = stwo_m31_add(b21, b151);
    e2 = StwoCudaQm31{ b165, b108, b108, b108 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 9u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 10u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    e1 = StwoCudaQm31{ b22, b108, b108, b108 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 11u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 12u);
    e1 = StwoCudaQm31{ b22, b108, b108, b108 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 13u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 14u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    e2 = StwoCudaQm31{ b23, b108, b108, b108 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 15u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    e4 = StwoCudaQm31{ b24, b108, b108, b108 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 16u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    e2 = StwoCudaQm31{ b25, b108, b108, b108 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 17u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    e4 = StwoCudaQm31{ b26, b108, b108, b108 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 18u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    e2 = StwoCudaQm31{ b27, b108, b108, b108 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 19u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    e4 = StwoCudaQm31{ b28, b108, b108, b108 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 20u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    e2 = StwoCudaQm31{ b29, b108, b108, b108 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 21u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    e4 = StwoCudaQm31{ b30, b108, b108, b108 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 22u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    e2 = StwoCudaQm31{ b31, b108, b108, b108 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 23u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    e4 = StwoCudaQm31{ b32, b108, b108, b108 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 24u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    e2 = StwoCudaQm31{ b33, b108, b108, b108 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 25u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    e4 = StwoCudaQm31{ b34, b108, b108, b108 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 26u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    e2 = StwoCudaQm31{ b35, b108, b108, b108 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 27u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    e4 = StwoCudaQm31{ b36, b108, b108, b108 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 28u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    e2 = StwoCudaQm31{ b37, b108, b108, b108 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 29u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    e4 = StwoCudaQm31{ b38, b108, b108, b108 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 30u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    e2 = StwoCudaQm31{ b39, b108, b108, b108 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 31u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    e4 = StwoCudaQm31{ b40, b108, b108, b108 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 32u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    e2 = StwoCudaQm31{ b41, b108, b108, b108 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 33u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    e4 = StwoCudaQm31{ b42, b108, b108, b108 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 34u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    e2 = StwoCudaQm31{ b43, b108, b108, b108 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 35u);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    e4 = StwoCudaQm31{ b44, b108, b108, b108 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 36u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    e2 = StwoCudaQm31{ b45, b108, b108, b108 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 37u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    e4 = StwoCudaQm31{ b46, b108, b108, b108 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 38u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    e2 = StwoCudaQm31{ b47, b108, b108, b108 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 39u);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    e4 = StwoCudaQm31{ b48, b108, b108, b108 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 40u);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    e2 = StwoCudaQm31{ b49, b108, b108, b108 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 41u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    e4 = StwoCudaQm31{ b50, b108, b108, b108 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 42u);
    e2 = stwo_qm31_sub(e4, e1);
    e1 = stwo_load_qm31(ext_params, 43u);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    unsigned b152 = base_params[31u];
    unsigned b153 = stwo_m31_sub(b4, b152);
    unsigned b166 = stwo_m31_add(b51, b153);
    e4 = StwoCudaQm31{ b166, b108, b108, b108 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_load_qm31(ext_params, 44u);
    e1 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(ext_params, 45u);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    e5 = StwoCudaQm31{ b52, b108, b108, b108 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e1, e6);
    e6 = stwo_load_qm31(ext_params, 46u);
    e1 = stwo_qm31_sub(e5, e6);
    e6 = stwo_load_qm31(ext_params, 47u);
    e5 = StwoCudaQm31{ b52, b108, b108, b108 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_load_qm31(ext_params, 48u);
    e6 = stwo_qm31_add(e5, e4);
    e5 = stwo_load_qm31(ext_params, 49u);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    e4 = StwoCudaQm31{ b53, b108, b108, b108 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 50u);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 54u, row_index, 0);
    e6 = StwoCudaQm31{ b54, b108, b108, b108 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 51u);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 55u, row_index, 0);
    e4 = StwoCudaQm31{ b55, b108, b108, b108 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 52u);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    e6 = StwoCudaQm31{ b56, b108, b108, b108 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 53u);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    e4 = StwoCudaQm31{ b57, b108, b108, b108 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 54u);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    e6 = StwoCudaQm31{ b58, b108, b108, b108 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 55u);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    e4 = StwoCudaQm31{ b59, b108, b108, b108 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 56u);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 60u, row_index, 0);
    e6 = StwoCudaQm31{ b60, b108, b108, b108 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 57u);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 61u, row_index, 0);
    e4 = StwoCudaQm31{ b61, b108, b108, b108 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 58u);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 62u, row_index, 0);
    e6 = StwoCudaQm31{ b62, b108, b108, b108 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 59u);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 63u, row_index, 0);
    e4 = StwoCudaQm31{ b63, b108, b108, b108 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 60u);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 64u, row_index, 0);
    e6 = StwoCudaQm31{ b64, b108, b108, b108 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 61u);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 65u, row_index, 0);
    e4 = StwoCudaQm31{ b65, b108, b108, b108 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 62u);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 66u, row_index, 0);
    e6 = StwoCudaQm31{ b66, b108, b108, b108 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 63u);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 67u, row_index, 0);
    e4 = StwoCudaQm31{ b67, b108, b108, b108 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 64u);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 68u, row_index, 0);
    e6 = StwoCudaQm31{ b68, b108, b108, b108 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 65u);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 69u, row_index, 0);
    e4 = StwoCudaQm31{ b69, b108, b108, b108 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 66u);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 70u, row_index, 0);
    e6 = StwoCudaQm31{ b70, b108, b108, b108 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 67u);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 71u, row_index, 0);
    e4 = StwoCudaQm31{ b71, b108, b108, b108 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 68u);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 72u, row_index, 0);
    e6 = StwoCudaQm31{ b72, b108, b108, b108 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 69u);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 73u, row_index, 0);
    e4 = StwoCudaQm31{ b73, b108, b108, b108 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 70u);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 74u, row_index, 0);
    e6 = StwoCudaQm31{ b74, b108, b108, b108 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 71u);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 75u, row_index, 0);
    e4 = StwoCudaQm31{ b75, b108, b108, b108 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 72u);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 76u, row_index, 0);
    e6 = StwoCudaQm31{ b76, b108, b108, b108 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 73u);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 77u, row_index, 0);
    e4 = StwoCudaQm31{ b77, b108, b108, b108 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 74u);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 78u, row_index, 0);
    e6 = StwoCudaQm31{ b78, b108, b108, b108 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 75u);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 79u, row_index, 0);
    e4 = StwoCudaQm31{ b79, b108, b108, b108 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 76u);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 80u, row_index, 0);
    e6 = StwoCudaQm31{ b80, b108, b108, b108 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 77u);
    e4 = stwo_qm31_sub(e6, e5);
    e5 = stwo_load_qm31(ext_params, 78u);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 82u, row_index, 0);
    unsigned b154 = base_params[32u];
    unsigned b155 = stwo_m31_sub(b5, b154);
    unsigned b167 = stwo_m31_add(b81, b155);
    e6 = StwoCudaQm31{ b167, b108, b108, b108 };
    e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_load_qm31(ext_params, 79u);
    e5 = stwo_qm31_add(e6, e7);
    e6 = stwo_load_qm31(ext_params, 80u);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 83u, row_index, 0);
    e7 = StwoCudaQm31{ b82, b108, b108, b108 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(ext_params, 81u);
    e5 = stwo_qm31_sub(e7, e8);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 233u, row_index, 0);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 106u, row_index, 0);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 107u, row_index, 0);
    unsigned b225 = stwo_m31_add(b87, b88);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 108u, row_index, 0);
    unsigned b226 = stwo_m31_add(b225, b89);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 109u, row_index, 0);
    unsigned b227 = stwo_m31_add(b226, b90);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 110u, row_index, 0);
    unsigned b228 = stwo_m31_add(b227, b91);
    unsigned b229 = stwo_m31_mul(b100, b228);
    e8 = StwoCudaQm31{ b229, b108, b108, b108 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 111u, row_index, 0);
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 234u, row_index, 0);
    unsigned b222 = base_params[284u];
    unsigned b223 = stwo_m31_mul(b101, b222);
    unsigned b230 = stwo_m31_sub(b92, b223);
    unsigned b231 = stwo_m31_mul(b100, b230);
    e7 = StwoCudaQm31{ b231, b108, b108, b108 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 237u, row_index, 0);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 84u, row_index, 0);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 85u, row_index, 0);
    unsigned b232 = base_params[289u];
    unsigned b233 = stwo_m31_mul(b84, b232);
    unsigned b234 = stwo_m31_add(b83, b233);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 86u, row_index, 0);
    unsigned b235 = base_params[290u];
    unsigned b236 = stwo_m31_mul(b85, b235);
    unsigned b237 = stwo_m31_add(b234, b236);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 87u, row_index, 0);
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 235u, row_index, 0);
    unsigned b220 = base_params[281u];
    unsigned b221 = stwo_m31_mul(b102, b220);
    unsigned b224 = stwo_m31_sub(b86, b221);
    unsigned b238 = base_params[291u];
    unsigned b239 = stwo_m31_mul(b224, b238);
    unsigned b240 = stwo_m31_add(b237, b239);
    unsigned b241 = stwo_m31_sub(b240, b101);
    unsigned b242 = base_params[292u];
    unsigned b243 = stwo_m31_mul(b242, b102);
    unsigned b244 = stwo_m31_sub(b241, b243);
    unsigned b245 = stwo_m31_add(b0, b244);
    unsigned b246 = stwo_m31_sub(b103, b245);
    unsigned b193 = stwo_m31_add(b23, b24);
    unsigned b194 = stwo_m31_add(b193, b25);
    unsigned b195 = stwo_m31_add(b194, b26);
    unsigned b196 = stwo_m31_add(b195, b27);
    unsigned b197 = stwo_m31_add(b196, b28);
    unsigned b198 = stwo_m31_add(b197, b29);
    unsigned b199 = stwo_m31_add(b198, b30);
    unsigned b200 = stwo_m31_add(b199, b31);
    unsigned b201 = stwo_m31_add(b200, b32);
    unsigned b202 = stwo_m31_add(b201, b33);
    unsigned b203 = stwo_m31_add(b202, b34);
    unsigned b204 = stwo_m31_add(b203, b35);
    unsigned b205 = stwo_m31_add(b204, b36);
    unsigned b206 = stwo_m31_add(b205, b37);
    unsigned b207 = stwo_m31_add(b206, b38);
    unsigned b208 = stwo_m31_add(b207, b39);
    unsigned b209 = stwo_m31_add(b208, b40);
    unsigned b210 = stwo_m31_add(b209, b41);
    unsigned b211 = stwo_m31_add(b210, b42);
    unsigned b212 = stwo_m31_add(b211, b43);
    unsigned b213 = stwo_m31_add(b212, b44);
    unsigned b214 = stwo_m31_add(b213, b45);
    unsigned b215 = stwo_m31_add(b214, b46);
    unsigned b216 = stwo_m31_add(b215, b47);
    unsigned b217 = stwo_m31_add(b216, b48);
    unsigned b218 = stwo_m31_add(b217, b49);
    unsigned b219 = stwo_m31_add(b218, b50);
    unsigned b247 = stwo_m31_mul(b246, b219);
    e6 = StwoCudaQm31{ b247, b108, b108, b108 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b163 = base_params[43u];
    unsigned b164 = stwo_m31_add(b163, b8);
    unsigned b248 = stwo_m31_add(b0, b164);
    unsigned b249 = stwo_m31_sub(b103, b248);
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 232u, row_index, 0);
    unsigned b250 = stwo_m31_mul(b219, b99);
    unsigned b251 = base_params[293u];
    unsigned b252 = stwo_m31_sub(b250, b251);
    unsigned b253 = stwo_m31_mul(b249, b252);
    StwoCudaQm31 e9 = StwoCudaQm31{ b253, b108, b108, b108 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 238u, row_index, 0);
    unsigned b156 = base_params[37u];
    unsigned b157 = stwo_m31_sub(b156, b13);
    unsigned b158 = stwo_m31_sub(b157, b14);
    unsigned b159 = stwo_m31_sub(b158, b15);
    unsigned b254 = stwo_m31_add(b0, b164);
    unsigned b255 = stwo_m31_mul(b159, b254);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 197u, row_index, 0);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 198u, row_index, 0);
    unsigned b180 = base_params[270u];
    unsigned b181 = stwo_m31_mul(b94, b180);
    unsigned b182 = stwo_m31_add(b93, b181);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 199u, row_index, 0);
    unsigned b183 = base_params[271u];
    unsigned b184 = stwo_m31_mul(b95, b183);
    unsigned b185 = stwo_m31_add(b182, b184);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 200u, row_index, 0);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 229u, row_index, 0);
    unsigned b177 = base_params[262u];
    unsigned b178 = stwo_m31_mul(b98, b177);
    unsigned b179 = stwo_m31_sub(b96, b178);
    unsigned b186 = base_params[272u];
    unsigned b187 = stwo_m31_mul(b179, b186);
    unsigned b188 = stwo_m31_add(b185, b187);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 228u, row_index, 0);
    unsigned b189 = stwo_m31_sub(b188, b97);
    unsigned b190 = base_params[273u];
    unsigned b191 = stwo_m31_mul(b190, b98);
    unsigned b192 = stwo_m31_sub(b189, b191);
    unsigned b256 = stwo_m31_mul(b13, b192);
    unsigned b257 = stwo_m31_add(b255, b256);
    unsigned b258 = stwo_m31_add(b0, b192);
    unsigned b259 = stwo_m31_mul(b14, b258);
    unsigned b260 = stwo_m31_add(b257, b259);
    unsigned b261 = stwo_m31_mul(b15, b103);
    unsigned b262 = stwo_m31_add(b260, b261);
    unsigned b263 = stwo_m31_sub(b104, b262);
    StwoCudaQm31 e10 = StwoCudaQm31{ b263, b108, b108, b108 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 239u, row_index, 0);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    unsigned b264 = stwo_m31_mul(b16, b192);
    unsigned b265 = stwo_m31_add(b1, b264);
    unsigned b266 = stwo_m31_add(b265, b17);
    unsigned b267 = base_params[294u];
    unsigned b268 = stwo_m31_mul(b18, b267);
    unsigned b269 = stwo_m31_add(b266, b268);
    unsigned b270 = stwo_m31_sub(b105, b269);
    StwoCudaQm31 e11 = StwoCudaQm31{ b270, b108, b108, b108 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b106 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 241u, row_index, 0);
    unsigned b160 = base_params[41u];
    unsigned b161 = stwo_m31_sub(b160, b18);
    unsigned b162 = stwo_m31_sub(b161, b19);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b271 = stwo_m31_mul(b162, b2);
    unsigned b168 = base_params[256u];
    unsigned b169 = stwo_m31_mul(b24, b168);
    unsigned b170 = stwo_m31_add(b23, b169);
    unsigned b171 = base_params[257u];
    unsigned b172 = stwo_m31_mul(b25, b171);
    unsigned b173 = stwo_m31_add(b170, b172);
    unsigned b174 = base_params[258u];
    unsigned b175 = stwo_m31_mul(b26, b174);
    unsigned b176 = stwo_m31_add(b173, b175);
    unsigned b272 = stwo_m31_mul(b19, b176);
    unsigned b273 = stwo_m31_add(b271, b272);
    unsigned b274 = base_params[296u];
    unsigned b275 = stwo_m31_add(b1, b274);
    unsigned b276 = stwo_m31_mul(b18, b275);
    unsigned b277 = stwo_m31_add(b273, b276);
    unsigned b278 = stwo_m31_sub(b106, b277);
    StwoCudaQm31 e12 = StwoCudaQm31{ b278, b108, b108, b108 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b107 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 242u, row_index, 0);
    unsigned b279 = stwo_m31_mul(b107, b107);
    unsigned b280 = stwo_m31_sub(b279, b107);
    StwoCudaQm31 e13 = StwoCudaQm31{ b280, b108, b108, b108 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    StwoCudaQm31 e14 = stwo_load_qm31(ext_params, 325u);
    StwoCudaQm31 e15 = stwo_qm31_mul(e3, e14);
    e14 = stwo_load_qm31(ext_params, 326u);
    StwoCudaQm31 e16 = stwo_qm31_mul(e0, e14);
    e14 = stwo_qm31_add(e15, e16);
    e16 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(ext_params, 327u);
    e0 = stwo_qm31_mul(e1, e3);
    e3 = stwo_load_qm31(ext_params, 328u);
    e15 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e15);
    e15 = stwo_qm31_mul(e2, e1);
    e1 = stwo_load_qm31(ext_params, 329u);
    e2 = stwo_qm31_mul(e5, e1);
    e1 = stwo_load_qm31(ext_params, 330u);
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e2, e0);
    e0 = stwo_qm31_mul(e4, e5);
    unsigned b281 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b282 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b283 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b284 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e5 = StwoCudaQm31{ b281, b282, b283, b284 };
    e4 = stwo_qm31_mul(e5, e16);
    e16 = stwo_qm31_sub(e4, e14);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b285 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b286 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b287 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b288 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e4 = StwoCudaQm31{ b285, b286, b287, b288 };
    e14 = stwo_qm31_sub(e4, e5);
    e5 = stwo_qm31_mul(e14, e15);
    e14 = stwo_qm31_sub(e5, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b289 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b290 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b291 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b292 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e5 = StwoCudaQm31{ b289, b290, b291, b292 };
    e3 = stwo_qm31_sub(e5, e4);
    e5 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e5, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
