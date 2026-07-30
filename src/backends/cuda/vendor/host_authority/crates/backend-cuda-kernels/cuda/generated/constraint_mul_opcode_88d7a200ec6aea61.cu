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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_971729336d2befa4(
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
    unsigned b103 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b0, b103, b103, b103 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 2u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e2 = StwoCudaQm31{ b1, b103, b103, b103 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 3u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e0 = StwoCudaQm31{ b2, b103, b103, b103 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 4u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e2 = StwoCudaQm31{ b3, b103, b103, b103 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 5u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b107 = base_params[8u];
    unsigned b108 = stwo_m31_mul(b4, b107);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b109 = base_params[9u];
    unsigned b110 = stwo_m31_mul(b5, b109);
    unsigned b111 = stwo_m31_add(b108, b110);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b112 = base_params[10u];
    unsigned b113 = stwo_m31_mul(b6, b112);
    unsigned b114 = stwo_m31_add(b111, b113);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b115 = base_params[11u];
    unsigned b116 = stwo_m31_mul(b7, b115);
    unsigned b117 = stwo_m31_add(b114, b116);
    unsigned b104 = base_params[5u];
    unsigned b105 = stwo_m31_sub(b104, b6);
    unsigned b106 = stwo_m31_sub(b105, b7);
    unsigned b118 = base_params[12u];
    unsigned b119 = stwo_m31_mul(b106, b118);
    unsigned b120 = stwo_m31_add(b117, b119);
    e0 = StwoCudaQm31{ b120, b103, b103, b103 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 6u);
    unsigned b123 = base_params[14u];
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b121 = base_params[13u];
    unsigned b122 = stwo_m31_mul(b8, b121);
    unsigned b124 = stwo_m31_add(b123, b122);
    unsigned b125 = base_params[15u];
    unsigned b126 = stwo_m31_add(b124, b125);
    e2 = StwoCudaQm31{ b126, b103, b103, b103 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 7u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 8u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b127 = base_params[16u];
    unsigned b128 = stwo_m31_sub(b1, b127);
    unsigned b133 = stwo_m31_add(b9, b128);
    e2 = StwoCudaQm31{ b133, b103, b103, b103 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 9u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 10u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    e1 = StwoCudaQm31{ b12, b103, b103, b103 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 11u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 12u);
    e1 = StwoCudaQm31{ b12, b103, b103, b103 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 13u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 14u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    e2 = StwoCudaQm31{ b13, b103, b103, b103 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 15u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    e4 = StwoCudaQm31{ b14, b103, b103, b103 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 16u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    e2 = StwoCudaQm31{ b15, b103, b103, b103 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 17u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    e4 = StwoCudaQm31{ b16, b103, b103, b103 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 18u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    e2 = StwoCudaQm31{ b17, b103, b103, b103 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 19u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    e4 = StwoCudaQm31{ b18, b103, b103, b103 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 20u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    e2 = StwoCudaQm31{ b19, b103, b103, b103 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 21u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    e4 = StwoCudaQm31{ b20, b103, b103, b103 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 22u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    e2 = StwoCudaQm31{ b21, b103, b103, b103 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 23u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    e4 = StwoCudaQm31{ b22, b103, b103, b103 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 24u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    e2 = StwoCudaQm31{ b23, b103, b103, b103 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 25u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    e4 = StwoCudaQm31{ b24, b103, b103, b103 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 26u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    e2 = StwoCudaQm31{ b25, b103, b103, b103 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 27u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    e4 = StwoCudaQm31{ b26, b103, b103, b103 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 28u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    e2 = StwoCudaQm31{ b27, b103, b103, b103 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 29u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    e4 = StwoCudaQm31{ b28, b103, b103, b103 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 30u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    e2 = StwoCudaQm31{ b29, b103, b103, b103 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 31u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    e4 = StwoCudaQm31{ b30, b103, b103, b103 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 32u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    e2 = StwoCudaQm31{ b31, b103, b103, b103 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 33u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    e4 = StwoCudaQm31{ b32, b103, b103, b103 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 34u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    e2 = StwoCudaQm31{ b33, b103, b103, b103 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 35u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    e4 = StwoCudaQm31{ b34, b103, b103, b103 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 36u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    e2 = StwoCudaQm31{ b35, b103, b103, b103 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 37u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    e4 = StwoCudaQm31{ b36, b103, b103, b103 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 38u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    e2 = StwoCudaQm31{ b37, b103, b103, b103 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 39u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    e4 = StwoCudaQm31{ b38, b103, b103, b103 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 40u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    e2 = StwoCudaQm31{ b39, b103, b103, b103 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 41u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    e4 = StwoCudaQm31{ b40, b103, b103, b103 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 42u);
    e2 = stwo_qm31_sub(e4, e1);
    e1 = stwo_load_qm31(ext_params, 43u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b129 = base_params[17u];
    unsigned b130 = stwo_m31_sub(b2, b129);
    unsigned b134 = stwo_m31_add(b10, b130);
    e4 = StwoCudaQm31{ b134, b103, b103, b103 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_load_qm31(ext_params, 44u);
    e1 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(ext_params, 45u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    e5 = StwoCudaQm31{ b41, b103, b103, b103 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e1, e6);
    e6 = stwo_load_qm31(ext_params, 46u);
    e1 = stwo_qm31_sub(e5, e6);
    e6 = stwo_load_qm31(ext_params, 47u);
    e5 = StwoCudaQm31{ b41, b103, b103, b103 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_load_qm31(ext_params, 48u);
    e6 = stwo_qm31_add(e5, e4);
    e5 = stwo_load_qm31(ext_params, 49u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    e4 = StwoCudaQm31{ b42, b103, b103, b103 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 50u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    e6 = StwoCudaQm31{ b43, b103, b103, b103 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 51u);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    e4 = StwoCudaQm31{ b44, b103, b103, b103 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 52u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    e6 = StwoCudaQm31{ b45, b103, b103, b103 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 53u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    e4 = StwoCudaQm31{ b46, b103, b103, b103 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 54u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    e6 = StwoCudaQm31{ b47, b103, b103, b103 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 55u);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    e4 = StwoCudaQm31{ b48, b103, b103, b103 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 56u);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    e6 = StwoCudaQm31{ b49, b103, b103, b103 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 57u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    e4 = StwoCudaQm31{ b50, b103, b103, b103 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 58u);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    e6 = StwoCudaQm31{ b51, b103, b103, b103 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 59u);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 54u, row_index, 0);
    e4 = StwoCudaQm31{ b52, b103, b103, b103 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 60u);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 55u, row_index, 0);
    e6 = StwoCudaQm31{ b53, b103, b103, b103 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 61u);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    e4 = StwoCudaQm31{ b54, b103, b103, b103 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 62u);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    e6 = StwoCudaQm31{ b55, b103, b103, b103 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 63u);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    e4 = StwoCudaQm31{ b56, b103, b103, b103 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 64u);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    e6 = StwoCudaQm31{ b57, b103, b103, b103 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 65u);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 60u, row_index, 0);
    e4 = StwoCudaQm31{ b58, b103, b103, b103 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 66u);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 61u, row_index, 0);
    e6 = StwoCudaQm31{ b59, b103, b103, b103 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 67u);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 62u, row_index, 0);
    e4 = StwoCudaQm31{ b60, b103, b103, b103 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 68u);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 63u, row_index, 0);
    e6 = StwoCudaQm31{ b61, b103, b103, b103 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 69u);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 64u, row_index, 0);
    e4 = StwoCudaQm31{ b62, b103, b103, b103 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 70u);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 65u, row_index, 0);
    e6 = StwoCudaQm31{ b63, b103, b103, b103 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 71u);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 66u, row_index, 0);
    e4 = StwoCudaQm31{ b64, b103, b103, b103 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 72u);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 67u, row_index, 0);
    e6 = StwoCudaQm31{ b65, b103, b103, b103 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 73u);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 68u, row_index, 0);
    e4 = StwoCudaQm31{ b66, b103, b103, b103 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 74u);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 69u, row_index, 0);
    e6 = StwoCudaQm31{ b67, b103, b103, b103 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 75u);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 70u, row_index, 0);
    e4 = StwoCudaQm31{ b68, b103, b103, b103 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 76u);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 71u, row_index, 0);
    e6 = StwoCudaQm31{ b69, b103, b103, b103 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 77u);
    e4 = stwo_qm31_sub(e6, e5);
    e5 = stwo_load_qm31(ext_params, 78u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    unsigned b131 = base_params[18u];
    unsigned b132 = stwo_m31_sub(b3, b131);
    unsigned b135 = stwo_m31_add(b11, b132);
    e6 = StwoCudaQm31{ b135, b103, b103, b103 };
    e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_load_qm31(ext_params, 79u);
    e5 = stwo_qm31_add(e6, e7);
    e6 = stwo_load_qm31(ext_params, 80u);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 72u, row_index, 0);
    e7 = StwoCudaQm31{ b70, b103, b103, b103 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(ext_params, 81u);
    e5 = stwo_qm31_sub(e7, e8);
    e8 = stwo_load_qm31(ext_params, 82u);
    e7 = StwoCudaQm31{ b70, b103, b103, b103 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_load_qm31(ext_params, 83u);
    e8 = stwo_qm31_add(e7, e6);
    e7 = stwo_load_qm31(ext_params, 84u);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 73u, row_index, 0);
    e6 = StwoCudaQm31{ b71, b103, b103, b103 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 85u);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 74u, row_index, 0);
    e8 = StwoCudaQm31{ b72, b103, b103, b103 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 86u);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 75u, row_index, 0);
    e6 = StwoCudaQm31{ b73, b103, b103, b103 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 87u);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 76u, row_index, 0);
    e8 = StwoCudaQm31{ b74, b103, b103, b103 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 88u);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 77u, row_index, 0);
    e6 = StwoCudaQm31{ b75, b103, b103, b103 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 89u);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 78u, row_index, 0);
    e8 = StwoCudaQm31{ b76, b103, b103, b103 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 90u);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 79u, row_index, 0);
    e6 = StwoCudaQm31{ b77, b103, b103, b103 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 91u);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 80u, row_index, 0);
    e8 = StwoCudaQm31{ b78, b103, b103, b103 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 92u);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 81u, row_index, 0);
    e6 = StwoCudaQm31{ b79, b103, b103, b103 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 93u);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 82u, row_index, 0);
    e8 = StwoCudaQm31{ b80, b103, b103, b103 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 94u);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 83u, row_index, 0);
    e6 = StwoCudaQm31{ b81, b103, b103, b103 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 95u);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 84u, row_index, 0);
    e8 = StwoCudaQm31{ b82, b103, b103, b103 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 96u);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 85u, row_index, 0);
    e6 = StwoCudaQm31{ b83, b103, b103, b103 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 97u);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 86u, row_index, 0);
    e8 = StwoCudaQm31{ b84, b103, b103, b103 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 98u);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 87u, row_index, 0);
    e6 = StwoCudaQm31{ b85, b103, b103, b103 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 99u);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 88u, row_index, 0);
    e8 = StwoCudaQm31{ b86, b103, b103, b103 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 100u);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 89u, row_index, 0);
    e6 = StwoCudaQm31{ b87, b103, b103, b103 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 101u);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 90u, row_index, 0);
    e8 = StwoCudaQm31{ b88, b103, b103, b103 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 102u);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 91u, row_index, 0);
    e6 = StwoCudaQm31{ b89, b103, b103, b103 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 103u);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 92u, row_index, 0);
    e8 = StwoCudaQm31{ b90, b103, b103, b103 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 104u);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 93u, row_index, 0);
    e6 = StwoCudaQm31{ b91, b103, b103, b103 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 105u);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 94u, row_index, 0);
    e8 = StwoCudaQm31{ b92, b103, b103, b103 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 106u);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 95u, row_index, 0);
    e6 = StwoCudaQm31{ b93, b103, b103, b103 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 107u);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 96u, row_index, 0);
    e8 = StwoCudaQm31{ b94, b103, b103, b103 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 108u);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 97u, row_index, 0);
    e6 = StwoCudaQm31{ b95, b103, b103, b103 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 109u);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 98u, row_index, 0);
    e8 = StwoCudaQm31{ b96, b103, b103, b103 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 110u);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 99u, row_index, 0);
    e6 = StwoCudaQm31{ b97, b103, b103, b103 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 111u);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 100u, row_index, 0);
    e8 = StwoCudaQm31{ b98, b103, b103, b103 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 112u);
    e6 = stwo_qm31_sub(e8, e7);
    e7 = stwo_load_qm31(ext_params, 113u);
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 101u, row_index, 0);
    unsigned b316 = base_params[110u];
    unsigned b317 = stwo_m31_add(b99, b316);
    e8 = StwoCudaQm31{ b317, b103, b103, b103 };
    e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_load_qm31(ext_params, 114u);
    e7 = stwo_qm31_add(e8, e9);
    e8 = stwo_load_qm31(ext_params, 115u);
    e9 = stwo_qm31_sub(e7, e8);
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 128u, row_index, 0);
    unsigned b318 = base_params[164u];
    unsigned b319 = stwo_m31_mul(b101, b318);
    unsigned b297 = base_params[103u];
    unsigned b161 = stwo_m31_mul(b49, b83);
    unsigned b162 = stwo_m31_mul(b50, b82);
    unsigned b163 = stwo_m31_add(b161, b162);
    unsigned b164 = stwo_m31_mul(b51, b81);
    unsigned b165 = stwo_m31_add(b163, b164);
    unsigned b166 = stwo_m31_mul(b52, b80);
    unsigned b167 = stwo_m31_add(b165, b166);
    unsigned b168 = stwo_m31_mul(b53, b79);
    unsigned b169 = stwo_m31_add(b167, b168);
    unsigned b170 = stwo_m31_mul(b54, b78);
    unsigned b171 = stwo_m31_add(b169, b170);
    unsigned b186 = stwo_m31_add(b48, b55);
    unsigned b187 = stwo_m31_add(b77, b84);
    unsigned b188 = stwo_m31_mul(b186, b187);
    unsigned b160 = stwo_m31_mul(b48, b77);
    unsigned b189 = stwo_m31_sub(b188, b160);
    unsigned b185 = stwo_m31_mul(b55, b84);
    unsigned b190 = stwo_m31_sub(b189, b185);
    unsigned b191 = stwo_m31_add(b171, b190);
    unsigned b251 = stwo_m31_add(b42, b56);
    unsigned b263 = stwo_m31_add(b76, b90);
    unsigned b265 = stwo_m31_mul(b251, b263);
    unsigned b252 = stwo_m31_add(b43, b57);
    unsigned b262 = stwo_m31_add(b75, b89);
    unsigned b266 = stwo_m31_mul(b252, b262);
    unsigned b267 = stwo_m31_add(b265, b266);
    unsigned b253 = stwo_m31_add(b44, b58);
    unsigned b261 = stwo_m31_add(b74, b88);
    unsigned b268 = stwo_m31_mul(b253, b261);
    unsigned b269 = stwo_m31_add(b267, b268);
    unsigned b254 = stwo_m31_add(b45, b59);
    unsigned b260 = stwo_m31_add(b73, b87);
    unsigned b270 = stwo_m31_mul(b254, b260);
    unsigned b271 = stwo_m31_add(b269, b270);
    unsigned b255 = stwo_m31_add(b46, b60);
    unsigned b259 = stwo_m31_add(b72, b86);
    unsigned b272 = stwo_m31_mul(b255, b259);
    unsigned b273 = stwo_m31_add(b271, b272);
    unsigned b256 = stwo_m31_add(b47, b61);
    unsigned b258 = stwo_m31_add(b71, b85);
    unsigned b274 = stwo_m31_mul(b256, b258);
    unsigned b275 = stwo_m31_add(b273, b274);
    unsigned b136 = stwo_m31_mul(b42, b76);
    unsigned b137 = stwo_m31_mul(b43, b75);
    unsigned b138 = stwo_m31_add(b136, b137);
    unsigned b139 = stwo_m31_mul(b44, b74);
    unsigned b140 = stwo_m31_add(b138, b139);
    unsigned b141 = stwo_m31_mul(b45, b73);
    unsigned b142 = stwo_m31_add(b140, b141);
    unsigned b143 = stwo_m31_mul(b46, b72);
    unsigned b144 = stwo_m31_add(b142, b143);
    unsigned b145 = stwo_m31_mul(b47, b71);
    unsigned b146 = stwo_m31_add(b144, b145);
    unsigned b289 = stwo_m31_sub(b275, b146);
    unsigned b192 = stwo_m31_mul(b56, b90);
    unsigned b193 = stwo_m31_mul(b57, b89);
    unsigned b194 = stwo_m31_add(b192, b193);
    unsigned b195 = stwo_m31_mul(b58, b88);
    unsigned b196 = stwo_m31_add(b194, b195);
    unsigned b197 = stwo_m31_mul(b59, b87);
    unsigned b198 = stwo_m31_add(b196, b197);
    unsigned b199 = stwo_m31_mul(b60, b86);
    unsigned b200 = stwo_m31_add(b198, b199);
    unsigned b201 = stwo_m31_mul(b61, b85);
    unsigned b202 = stwo_m31_add(b200, b201);
    unsigned b290 = stwo_m31_sub(b289, b202);
    unsigned b291 = stwo_m31_add(b191, b290);
    unsigned b295 = stwo_m31_sub(b291, b32);
    unsigned b298 = stwo_m31_mul(b297, b295);
    unsigned b299 = base_params[104u];
    unsigned b217 = stwo_m31_mul(b63, b97);
    unsigned b218 = stwo_m31_mul(b64, b96);
    unsigned b219 = stwo_m31_add(b217, b218);
    unsigned b220 = stwo_m31_mul(b65, b95);
    unsigned b221 = stwo_m31_add(b219, b220);
    unsigned b222 = stwo_m31_mul(b66, b94);
    unsigned b223 = stwo_m31_add(b221, b222);
    unsigned b224 = stwo_m31_mul(b67, b93);
    unsigned b225 = stwo_m31_add(b223, b224);
    unsigned b226 = stwo_m31_mul(b68, b92);
    unsigned b227 = stwo_m31_add(b225, b226);
    unsigned b245 = stwo_m31_add(b62, b69);
    unsigned b246 = stwo_m31_add(b91, b98);
    unsigned b247 = stwo_m31_mul(b245, b246);
    unsigned b216 = stwo_m31_mul(b62, b91);
    unsigned b248 = stwo_m31_sub(b247, b216);
    unsigned b244 = stwo_m31_mul(b69, b98);
    unsigned b249 = stwo_m31_sub(b248, b244);
    unsigned b250 = stwo_m31_add(b227, b249);
    unsigned b300 = stwo_m31_mul(b299, b250);
    unsigned b301 = stwo_m31_sub(b298, b300);
    unsigned b302 = base_params[105u];
    unsigned b241 = stwo_m31_mul(b68, b98);
    unsigned b242 = stwo_m31_mul(b69, b97);
    unsigned b243 = stwo_m31_add(b241, b242);
    unsigned b303 = stwo_m31_mul(b302, b243);
    unsigned b304 = stwo_m31_add(b301, b303);
    unsigned b305 = base_params[106u];
    unsigned b306 = stwo_m31_mul(b305, b244);
    unsigned b307 = stwo_m31_add(b304, b306);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 127u, row_index, 0);
    unsigned b320 = stwo_m31_add(b307, b100);
    unsigned b321 = stwo_m31_sub(b319, b320);
    e8 = StwoCudaQm31{ b321, b103, b103, b103 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b308 = base_params[107u];
    unsigned b172 = stwo_m31_mul(b49, b84);
    unsigned b173 = stwo_m31_mul(b50, b83);
    unsigned b174 = stwo_m31_add(b172, b173);
    unsigned b175 = stwo_m31_mul(b51, b82);
    unsigned b176 = stwo_m31_add(b174, b175);
    unsigned b177 = stwo_m31_mul(b52, b81);
    unsigned b178 = stwo_m31_add(b176, b177);
    unsigned b179 = stwo_m31_mul(b53, b80);
    unsigned b180 = stwo_m31_add(b178, b179);
    unsigned b181 = stwo_m31_mul(b54, b79);
    unsigned b182 = stwo_m31_add(b180, b181);
    unsigned b183 = stwo_m31_mul(b55, b78);
    unsigned b184 = stwo_m31_add(b182, b183);
    unsigned b264 = stwo_m31_add(b77, b91);
    unsigned b276 = stwo_m31_mul(b251, b264);
    unsigned b277 = stwo_m31_mul(b252, b263);
    unsigned b278 = stwo_m31_add(b276, b277);
    unsigned b279 = stwo_m31_mul(b253, b262);
    unsigned b280 = stwo_m31_add(b278, b279);
    unsigned b281 = stwo_m31_mul(b254, b261);
    unsigned b282 = stwo_m31_add(b280, b281);
    unsigned b283 = stwo_m31_mul(b255, b260);
    unsigned b284 = stwo_m31_add(b282, b283);
    unsigned b285 = stwo_m31_mul(b256, b259);
    unsigned b286 = stwo_m31_add(b284, b285);
    unsigned b257 = stwo_m31_add(b48, b62);
    unsigned b287 = stwo_m31_mul(b257, b258);
    unsigned b288 = stwo_m31_add(b286, b287);
    unsigned b147 = stwo_m31_mul(b42, b77);
    unsigned b148 = stwo_m31_mul(b43, b76);
    unsigned b149 = stwo_m31_add(b147, b148);
    unsigned b150 = stwo_m31_mul(b44, b75);
    unsigned b151 = stwo_m31_add(b149, b150);
    unsigned b152 = stwo_m31_mul(b45, b74);
    unsigned b153 = stwo_m31_add(b151, b152);
    unsigned b154 = stwo_m31_mul(b46, b73);
    unsigned b155 = stwo_m31_add(b153, b154);
    unsigned b156 = stwo_m31_mul(b47, b72);
    unsigned b157 = stwo_m31_add(b155, b156);
    unsigned b158 = stwo_m31_mul(b48, b71);
    unsigned b159 = stwo_m31_add(b157, b158);
    unsigned b292 = stwo_m31_sub(b288, b159);
    unsigned b203 = stwo_m31_mul(b56, b91);
    unsigned b204 = stwo_m31_mul(b57, b90);
    unsigned b205 = stwo_m31_add(b203, b204);
    unsigned b206 = stwo_m31_mul(b58, b89);
    unsigned b207 = stwo_m31_add(b205, b206);
    unsigned b208 = stwo_m31_mul(b59, b88);
    unsigned b209 = stwo_m31_add(b207, b208);
    unsigned b210 = stwo_m31_mul(b60, b87);
    unsigned b211 = stwo_m31_add(b209, b210);
    unsigned b212 = stwo_m31_mul(b61, b86);
    unsigned b213 = stwo_m31_add(b211, b212);
    unsigned b214 = stwo_m31_mul(b62, b85);
    unsigned b215 = stwo_m31_add(b213, b214);
    unsigned b293 = stwo_m31_sub(b292, b215);
    unsigned b294 = stwo_m31_add(b184, b293);
    unsigned b296 = stwo_m31_sub(b294, b33);
    unsigned b309 = stwo_m31_mul(b308, b296);
    unsigned b310 = base_params[108u];
    unsigned b228 = stwo_m31_mul(b63, b98);
    unsigned b229 = stwo_m31_mul(b64, b97);
    unsigned b230 = stwo_m31_add(b228, b229);
    unsigned b231 = stwo_m31_mul(b65, b96);
    unsigned b232 = stwo_m31_add(b230, b231);
    unsigned b233 = stwo_m31_mul(b66, b95);
    unsigned b234 = stwo_m31_add(b232, b233);
    unsigned b235 = stwo_m31_mul(b67, b94);
    unsigned b236 = stwo_m31_add(b234, b235);
    unsigned b237 = stwo_m31_mul(b68, b93);
    unsigned b238 = stwo_m31_add(b236, b237);
    unsigned b239 = stwo_m31_mul(b69, b92);
    unsigned b240 = stwo_m31_add(b238, b239);
    unsigned b311 = stwo_m31_mul(b310, b240);
    unsigned b312 = stwo_m31_sub(b309, b311);
    unsigned b313 = base_params[109u];
    unsigned b314 = stwo_m31_mul(b313, b244);
    unsigned b315 = stwo_m31_add(b312, b314);
    unsigned b322 = base_params[166u];
    unsigned b323 = stwo_m31_mul(b322, b99);
    unsigned b324 = stwo_m31_sub(b315, b323);
    unsigned b325 = stwo_m31_add(b324, b101);
    e7 = StwoCudaQm31{ b325, b103, b103, b103 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 129u, row_index, 0);
    unsigned b326 = stwo_m31_mul(b102, b102);
    unsigned b327 = stwo_m31_sub(b326, b102);
    StwoCudaQm31 e10 = StwoCudaQm31{ b327, b103, b103, b103 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    StwoCudaQm31 e11 = stwo_load_qm31(ext_params, 207u);
    StwoCudaQm31 e12 = stwo_qm31_mul(e3, e11);
    e11 = stwo_load_qm31(ext_params, 208u);
    StwoCudaQm31 e13 = stwo_qm31_mul(e0, e11);
    e11 = stwo_qm31_add(e12, e13);
    e13 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(ext_params, 209u);
    e0 = stwo_qm31_mul(e1, e3);
    e3 = stwo_load_qm31(ext_params, 210u);
    e12 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e12);
    e12 = stwo_qm31_mul(e2, e1);
    e1 = stwo_load_qm31(ext_params, 211u);
    e2 = stwo_qm31_mul(e5, e1);
    e1 = stwo_load_qm31(ext_params, 212u);
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e2, e0);
    e0 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 213u);
    e4 = stwo_qm31_mul(e9, e5);
    e5 = stwo_load_qm31(ext_params, 214u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e9);
    unsigned b328 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b329 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b330 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b331 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e9 = StwoCudaQm31{ b328, b329, b330, b331 };
    e6 = stwo_qm31_mul(e9, e13);
    e13 = stwo_qm31_sub(e6, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b332 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b333 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b334 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b335 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e6 = StwoCudaQm31{ b332, b333, b334, b335 };
    e11 = stwo_qm31_sub(e6, e9);
    e9 = stwo_qm31_mul(e11, e12);
    e11 = stwo_qm31_sub(e9, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b336 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b337 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b338 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b339 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e9 = StwoCudaQm31{ b336, b337, b338, b339 };
    e3 = stwo_qm31_sub(e9, e6);
    e6 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e6, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b340 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b341 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b342 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b343 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e6 = StwoCudaQm31{ b340, b341, b342, b343 };
    e1 = stwo_qm31_sub(e6, e9);
    e6 = stwo_qm31_mul(e1, e2);
    e1 = stwo_qm31_sub(e6, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
