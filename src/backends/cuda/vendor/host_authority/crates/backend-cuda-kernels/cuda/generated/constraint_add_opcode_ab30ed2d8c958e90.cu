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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_74ed8f99f35104c3(
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
    unsigned b102 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b0, b102, b102, b102 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 2u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e2 = StwoCudaQm31{ b3, b102, b102, b102 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 3u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e0 = StwoCudaQm31{ b4, b102, b102, b102 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 4u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e2 = StwoCudaQm31{ b5, b102, b102, b102 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 5u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b106 = base_params[8u];
    unsigned b107 = stwo_m31_mul(b6, b106);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b108 = base_params[9u];
    unsigned b109 = stwo_m31_mul(b7, b108);
    unsigned b110 = stwo_m31_add(b107, b109);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b111 = base_params[10u];
    unsigned b112 = stwo_m31_mul(b8, b111);
    unsigned b113 = stwo_m31_add(b110, b112);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b114 = base_params[11u];
    unsigned b115 = stwo_m31_mul(b9, b114);
    unsigned b116 = stwo_m31_add(b113, b115);
    unsigned b103 = base_params[5u];
    unsigned b104 = stwo_m31_sub(b103, b8);
    unsigned b105 = stwo_m31_sub(b104, b9);
    unsigned b117 = base_params[12u];
    unsigned b118 = stwo_m31_mul(b105, b117);
    unsigned b119 = stwo_m31_add(b116, b118);
    unsigned b120 = base_params[13u];
    unsigned b121 = stwo_m31_add(b119, b120);
    e0 = StwoCudaQm31{ b121, b102, b102, b102 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 6u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b122 = base_params[14u];
    unsigned b123 = stwo_m31_mul(b10, b122);
    unsigned b124 = base_params[15u];
    unsigned b125 = stwo_m31_add(b123, b124);
    e2 = StwoCudaQm31{ b125, b102, b102, b102 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 7u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 8u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b126 = base_params[16u];
    unsigned b127 = stwo_m31_sub(b3, b126);
    unsigned b132 = stwo_m31_add(b11, b127);
    e2 = StwoCudaQm31{ b132, b102, b102, b102 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 9u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 10u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    e1 = StwoCudaQm31{ b14, b102, b102, b102 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 11u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 12u);
    e1 = StwoCudaQm31{ b14, b102, b102, b102 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 13u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 14u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    e2 = StwoCudaQm31{ b15, b102, b102, b102 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 15u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    e4 = StwoCudaQm31{ b16, b102, b102, b102 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 16u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    e2 = StwoCudaQm31{ b17, b102, b102, b102 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 17u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    e4 = StwoCudaQm31{ b18, b102, b102, b102 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 18u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    e2 = StwoCudaQm31{ b19, b102, b102, b102 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 19u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    e4 = StwoCudaQm31{ b20, b102, b102, b102 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 20u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    e2 = StwoCudaQm31{ b21, b102, b102, b102 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 21u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    e4 = StwoCudaQm31{ b22, b102, b102, b102 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 22u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    e2 = StwoCudaQm31{ b23, b102, b102, b102 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 23u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    e4 = StwoCudaQm31{ b24, b102, b102, b102 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 24u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    e2 = StwoCudaQm31{ b25, b102, b102, b102 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 25u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    e4 = StwoCudaQm31{ b26, b102, b102, b102 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 26u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    e2 = StwoCudaQm31{ b27, b102, b102, b102 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 27u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    e4 = StwoCudaQm31{ b28, b102, b102, b102 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 28u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    e2 = StwoCudaQm31{ b29, b102, b102, b102 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 29u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    e4 = StwoCudaQm31{ b30, b102, b102, b102 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 30u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    e2 = StwoCudaQm31{ b31, b102, b102, b102 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 31u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    e4 = StwoCudaQm31{ b32, b102, b102, b102 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 32u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    e2 = StwoCudaQm31{ b33, b102, b102, b102 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 33u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    e4 = StwoCudaQm31{ b34, b102, b102, b102 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 34u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    e2 = StwoCudaQm31{ b35, b102, b102, b102 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 35u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    e4 = StwoCudaQm31{ b36, b102, b102, b102 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 36u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    e2 = StwoCudaQm31{ b37, b102, b102, b102 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 37u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    e4 = StwoCudaQm31{ b38, b102, b102, b102 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 38u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    e2 = StwoCudaQm31{ b39, b102, b102, b102 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 39u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    e4 = StwoCudaQm31{ b40, b102, b102, b102 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 40u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    e2 = StwoCudaQm31{ b41, b102, b102, b102 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 41u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    e4 = StwoCudaQm31{ b42, b102, b102, b102 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 42u);
    e2 = stwo_qm31_sub(e4, e1);
    e1 = stwo_load_qm31(ext_params, 43u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b128 = base_params[17u];
    unsigned b129 = stwo_m31_sub(b4, b128);
    unsigned b133 = stwo_m31_add(b12, b129);
    e4 = StwoCudaQm31{ b133, b102, b102, b102 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_load_qm31(ext_params, 44u);
    e1 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(ext_params, 45u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    e5 = StwoCudaQm31{ b43, b102, b102, b102 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e1, e6);
    e6 = stwo_load_qm31(ext_params, 46u);
    e1 = stwo_qm31_sub(e5, e6);
    e6 = stwo_load_qm31(ext_params, 47u);
    e5 = StwoCudaQm31{ b43, b102, b102, b102 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_load_qm31(ext_params, 48u);
    e6 = stwo_qm31_add(e5, e4);
    e5 = stwo_load_qm31(ext_params, 49u);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    e4 = StwoCudaQm31{ b44, b102, b102, b102 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 50u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    e6 = StwoCudaQm31{ b45, b102, b102, b102 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 51u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    e4 = StwoCudaQm31{ b46, b102, b102, b102 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 52u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    e6 = StwoCudaQm31{ b47, b102, b102, b102 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 53u);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    e4 = StwoCudaQm31{ b48, b102, b102, b102 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 54u);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    e6 = StwoCudaQm31{ b49, b102, b102, b102 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 55u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    e4 = StwoCudaQm31{ b50, b102, b102, b102 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 56u);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    e6 = StwoCudaQm31{ b51, b102, b102, b102 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 57u);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    e4 = StwoCudaQm31{ b52, b102, b102, b102 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 58u);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    e6 = StwoCudaQm31{ b53, b102, b102, b102 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 59u);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 54u, row_index, 0);
    e4 = StwoCudaQm31{ b54, b102, b102, b102 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 60u);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 55u, row_index, 0);
    e6 = StwoCudaQm31{ b55, b102, b102, b102 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 61u);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    e4 = StwoCudaQm31{ b56, b102, b102, b102 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 62u);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    e6 = StwoCudaQm31{ b57, b102, b102, b102 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 63u);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    e4 = StwoCudaQm31{ b58, b102, b102, b102 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 64u);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    e6 = StwoCudaQm31{ b59, b102, b102, b102 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 65u);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 60u, row_index, 0);
    e4 = StwoCudaQm31{ b60, b102, b102, b102 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 66u);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 61u, row_index, 0);
    e6 = StwoCudaQm31{ b61, b102, b102, b102 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 67u);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 62u, row_index, 0);
    e4 = StwoCudaQm31{ b62, b102, b102, b102 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 68u);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 63u, row_index, 0);
    e6 = StwoCudaQm31{ b63, b102, b102, b102 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 69u);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 64u, row_index, 0);
    e4 = StwoCudaQm31{ b64, b102, b102, b102 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 70u);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 65u, row_index, 0);
    e6 = StwoCudaQm31{ b65, b102, b102, b102 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 71u);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 66u, row_index, 0);
    e4 = StwoCudaQm31{ b66, b102, b102, b102 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 72u);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 67u, row_index, 0);
    e6 = StwoCudaQm31{ b67, b102, b102, b102 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 73u);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 68u, row_index, 0);
    e4 = StwoCudaQm31{ b68, b102, b102, b102 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 74u);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 69u, row_index, 0);
    e6 = StwoCudaQm31{ b69, b102, b102, b102 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 75u);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 70u, row_index, 0);
    e4 = StwoCudaQm31{ b70, b102, b102, b102 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 76u);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 71u, row_index, 0);
    e6 = StwoCudaQm31{ b71, b102, b102, b102 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 77u);
    e4 = stwo_qm31_sub(e6, e5);
    e5 = stwo_load_qm31(ext_params, 78u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    unsigned b130 = base_params[18u];
    unsigned b131 = stwo_m31_sub(b5, b130);
    unsigned b134 = stwo_m31_add(b13, b131);
    e6 = StwoCudaQm31{ b134, b102, b102, b102 };
    e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_load_qm31(ext_params, 79u);
    e5 = stwo_qm31_add(e6, e7);
    e6 = stwo_load_qm31(ext_params, 80u);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 72u, row_index, 0);
    e7 = StwoCudaQm31{ b72, b102, b102, b102 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(ext_params, 81u);
    e5 = stwo_qm31_sub(e7, e8);
    e8 = stwo_load_qm31(ext_params, 82u);
    e7 = StwoCudaQm31{ b72, b102, b102, b102 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_load_qm31(ext_params, 83u);
    e8 = stwo_qm31_add(e7, e6);
    e7 = stwo_load_qm31(ext_params, 84u);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 73u, row_index, 0);
    e6 = StwoCudaQm31{ b73, b102, b102, b102 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 85u);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 74u, row_index, 0);
    e8 = StwoCudaQm31{ b74, b102, b102, b102 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 86u);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 75u, row_index, 0);
    e6 = StwoCudaQm31{ b75, b102, b102, b102 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 87u);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 76u, row_index, 0);
    e8 = StwoCudaQm31{ b76, b102, b102, b102 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 88u);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 77u, row_index, 0);
    e6 = StwoCudaQm31{ b77, b102, b102, b102 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 89u);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 78u, row_index, 0);
    e8 = StwoCudaQm31{ b78, b102, b102, b102 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 90u);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 79u, row_index, 0);
    e6 = StwoCudaQm31{ b79, b102, b102, b102 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 91u);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 80u, row_index, 0);
    e8 = StwoCudaQm31{ b80, b102, b102, b102 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 92u);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 81u, row_index, 0);
    e6 = StwoCudaQm31{ b81, b102, b102, b102 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 93u);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 82u, row_index, 0);
    e8 = StwoCudaQm31{ b82, b102, b102, b102 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 94u);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 83u, row_index, 0);
    e6 = StwoCudaQm31{ b83, b102, b102, b102 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 95u);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 84u, row_index, 0);
    e8 = StwoCudaQm31{ b84, b102, b102, b102 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 96u);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 85u, row_index, 0);
    e6 = StwoCudaQm31{ b85, b102, b102, b102 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 97u);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 86u, row_index, 0);
    e8 = StwoCudaQm31{ b86, b102, b102, b102 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 98u);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 87u, row_index, 0);
    e6 = StwoCudaQm31{ b87, b102, b102, b102 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 99u);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 88u, row_index, 0);
    e8 = StwoCudaQm31{ b88, b102, b102, b102 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 100u);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 89u, row_index, 0);
    e6 = StwoCudaQm31{ b89, b102, b102, b102 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 101u);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 90u, row_index, 0);
    e8 = StwoCudaQm31{ b90, b102, b102, b102 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 102u);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 91u, row_index, 0);
    e6 = StwoCudaQm31{ b91, b102, b102, b102 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 103u);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 92u, row_index, 0);
    e8 = StwoCudaQm31{ b92, b102, b102, b102 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 104u);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 93u, row_index, 0);
    e6 = StwoCudaQm31{ b93, b102, b102, b102 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 105u);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 94u, row_index, 0);
    e8 = StwoCudaQm31{ b94, b102, b102, b102 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 106u);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 95u, row_index, 0);
    e6 = StwoCudaQm31{ b95, b102, b102, b102 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 107u);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 96u, row_index, 0);
    e8 = StwoCudaQm31{ b96, b102, b102, b102 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 108u);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 97u, row_index, 0);
    e6 = StwoCudaQm31{ b97, b102, b102, b102 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 109u);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 98u, row_index, 0);
    e8 = StwoCudaQm31{ b98, b102, b102, b102 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 110u);
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 99u, row_index, 0);
    e6 = StwoCudaQm31{ b99, b102, b102, b102 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 111u);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 100u, row_index, 0);
    e8 = StwoCudaQm31{ b100, b102, b102, b102 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 112u);
    e6 = stwo_qm31_sub(e8, e7);
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 102u, row_index, 0);
    unsigned b135 = stwo_m31_mul(b101, b101);
    unsigned b136 = stwo_m31_sub(b135, b101);
    e7 = StwoCudaQm31{ b136, b102, b102, b102 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    e8 = stwo_load_qm31(ext_params, 113u);
    e9 = StwoCudaQm31{ b0, b102, b102, b102 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 114u);
    e8 = stwo_qm31_add(e9, e10);
    e9 = stwo_load_qm31(ext_params, 115u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e10 = StwoCudaQm31{ b1, b102, b102, b102 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 116u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    e8 = StwoCudaQm31{ b2, b102, b102, b102 };
    e9 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 117u);
    e10 = stwo_qm31_sub(e8, e9);
    e9 = StwoCudaQm31{ b101, b102, b102, b102 };
    e8 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e9);
    e9 = stwo_load_qm31(ext_params, 118u);
    unsigned b137 = base_params[61u];
    unsigned b138 = stwo_m31_add(b0, b137);
    unsigned b139 = stwo_m31_add(b138, b8);
    e11 = StwoCudaQm31{ b139, b102, b102, b102 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e9, e11);
    e11 = stwo_load_qm31(ext_params, 119u);
    e9 = stwo_qm31_add(e11, e12);
    e11 = stwo_load_qm31(ext_params, 120u);
    unsigned b140 = stwo_m31_add(b1, b10);
    e12 = StwoCudaQm31{ b140, b102, b102, b102 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e11, e12);
    e12 = stwo_qm31_add(e9, e13);
    e13 = stwo_load_qm31(ext_params, 121u);
    e9 = StwoCudaQm31{ b2, b102, b102, b102 };
    e11 = stwo_qm31_mul(e13, e9);
    e9 = stwo_qm31_add(e12, e11);
    e11 = stwo_load_qm31(ext_params, 122u);
    e12 = stwo_qm31_sub(e9, e11);
    e11 = stwo_load_qm31(ext_params, 123u);
    e9 = stwo_qm31_mul(e3, e11);
    e11 = stwo_load_qm31(ext_params, 124u);
    e13 = stwo_qm31_mul(e0, e11);
    e11 = stwo_qm31_add(e9, e13);
    e13 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(ext_params, 125u);
    e0 = stwo_qm31_mul(e1, e3);
    e3 = stwo_load_qm31(ext_params, 126u);
    e9 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e9);
    e9 = stwo_qm31_mul(e2, e1);
    e1 = stwo_load_qm31(ext_params, 127u);
    e2 = stwo_qm31_mul(e5, e1);
    e1 = stwo_load_qm31(ext_params, 128u);
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e2, e0);
    e0 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 129u);
    e4 = stwo_qm31_mul(e10, e5);
    e5 = StwoCudaQm31{ b101, b102, b102, b102 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e10);
    unsigned b141 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b142 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b143 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b144 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e10 = StwoCudaQm31{ b141, b142, b143, b144 };
    e6 = stwo_qm31_mul(e10, e13);
    e13 = stwo_qm31_sub(e6, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b145 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b146 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b147 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b148 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e6 = StwoCudaQm31{ b145, b146, b147, b148 };
    e11 = stwo_qm31_sub(e6, e10);
    e10 = stwo_qm31_mul(e11, e9);
    e11 = stwo_qm31_sub(e10, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b149 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b150 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b151 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b152 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e10 = StwoCudaQm31{ b149, b150, b151, b152 };
    e3 = stwo_qm31_sub(e10, e6);
    e6 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e6, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b153 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b154 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b155 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b156 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e6 = StwoCudaQm31{ b153, b154, b155, b156 };
    e1 = stwo_qm31_sub(e6, e10);
    e10 = stwo_qm31_mul(e1, e2);
    e1 = stwo_qm31_sub(e10, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b157 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, -1);
    unsigned b159 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, -1);
    unsigned b161 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, -1);
    unsigned b163 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, -1);
    e10 = StwoCudaQm31{ b157, b159, b161, b163 };
    unsigned b158 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, 0);
    unsigned b160 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, 0);
    unsigned b162 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, 0);
    unsigned b164 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, 0);
    e5 = StwoCudaQm31{ b158, b160, b162, b164 };
    e2 = stwo_qm31_sub(e5, e10);
    e5 = stwo_qm31_sub(e2, e6);
    e2 = stwo_load_qm31(ext_params, 130u);
    e6 = stwo_qm31_add(e5, e2);
    e2 = stwo_qm31_mul(e6, e12);
    e6 = stwo_qm31_sub(e2, e8);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
