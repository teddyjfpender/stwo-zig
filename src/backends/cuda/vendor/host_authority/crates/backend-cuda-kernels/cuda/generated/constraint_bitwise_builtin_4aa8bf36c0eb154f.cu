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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_cdc95f4af6e6dcdc(
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
    unsigned b73 = base_params[1u];
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    unsigned b71 = base_params[0u];
    unsigned b72 = stwo_m31_mul(b0, b71);
    unsigned b74 = stwo_m31_add(b73, b72);
    unsigned b75 = base_params[2u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b74, b75, b75, b75 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 2u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    e2 = StwoCudaQm31{ b1, b75, b75, b75 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 3u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 4u);
    e2 = StwoCudaQm31{ b1, b75, b75, b75 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 5u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 6u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e1 = StwoCudaQm31{ b2, b75, b75, b75 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 7u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    e3 = StwoCudaQm31{ b3, b75, b75, b75 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 8u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e1 = StwoCudaQm31{ b4, b75, b75, b75 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 9u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e3 = StwoCudaQm31{ b5, b75, b75, b75 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 10u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e1 = StwoCudaQm31{ b6, b75, b75, b75 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 11u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    e3 = StwoCudaQm31{ b7, b75, b75, b75 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 12u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    e1 = StwoCudaQm31{ b8, b75, b75, b75 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 13u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    e3 = StwoCudaQm31{ b9, b75, b75, b75 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 14u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    e1 = StwoCudaQm31{ b10, b75, b75, b75 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 15u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    e3 = StwoCudaQm31{ b11, b75, b75, b75 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 16u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    e1 = StwoCudaQm31{ b12, b75, b75, b75 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 17u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    e3 = StwoCudaQm31{ b13, b75, b75, b75 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 18u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    e1 = StwoCudaQm31{ b14, b75, b75, b75 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 19u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    e3 = StwoCudaQm31{ b15, b75, b75, b75 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 20u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    e1 = StwoCudaQm31{ b16, b75, b75, b75 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 21u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    e3 = StwoCudaQm31{ b17, b75, b75, b75 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 22u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    e1 = StwoCudaQm31{ b18, b75, b75, b75 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 23u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    e3 = StwoCudaQm31{ b19, b75, b75, b75 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 24u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    e1 = StwoCudaQm31{ b20, b75, b75, b75 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 25u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    e3 = StwoCudaQm31{ b21, b75, b75, b75 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 26u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    e1 = StwoCudaQm31{ b22, b75, b75, b75 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 27u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    e3 = StwoCudaQm31{ b23, b75, b75, b75 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 28u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    e1 = StwoCudaQm31{ b24, b75, b75, b75 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 29u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    e3 = StwoCudaQm31{ b25, b75, b75, b75 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 30u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    e1 = StwoCudaQm31{ b26, b75, b75, b75 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 31u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    e3 = StwoCudaQm31{ b27, b75, b75, b75 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 32u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    e1 = StwoCudaQm31{ b28, b75, b75, b75 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 33u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    e3 = StwoCudaQm31{ b29, b75, b75, b75 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 34u);
    e1 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(ext_params, 35u);
    unsigned b78 = base_params[4u];
    unsigned b76 = base_params[3u];
    unsigned b77 = stwo_m31_mul(b0, b76);
    unsigned b79 = stwo_m31_add(b78, b77);
    unsigned b80 = base_params[5u];
    unsigned b81 = stwo_m31_add(b79, b80);
    e3 = StwoCudaQm31{ b81, b75, b75, b75 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 36u);
    e2 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(ext_params, 37u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    e4 = StwoCudaQm31{ b30, b75, b75, b75 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(ext_params, 38u);
    e2 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(ext_params, 39u);
    e4 = StwoCudaQm31{ b30, b75, b75, b75 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(ext_params, 40u);
    e5 = stwo_qm31_add(e4, e3);
    e4 = stwo_load_qm31(ext_params, 41u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    e3 = StwoCudaQm31{ b31, b75, b75, b75 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 42u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    e5 = StwoCudaQm31{ b32, b75, b75, b75 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 43u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    e3 = StwoCudaQm31{ b33, b75, b75, b75 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 44u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    e5 = StwoCudaQm31{ b34, b75, b75, b75 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 45u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    e3 = StwoCudaQm31{ b35, b75, b75, b75 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 46u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    e5 = StwoCudaQm31{ b36, b75, b75, b75 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 47u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    e3 = StwoCudaQm31{ b37, b75, b75, b75 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 48u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    e5 = StwoCudaQm31{ b38, b75, b75, b75 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 49u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    e3 = StwoCudaQm31{ b39, b75, b75, b75 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 50u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    e5 = StwoCudaQm31{ b40, b75, b75, b75 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 51u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    e3 = StwoCudaQm31{ b41, b75, b75, b75 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 52u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    e5 = StwoCudaQm31{ b42, b75, b75, b75 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 53u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    e3 = StwoCudaQm31{ b43, b75, b75, b75 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 54u);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    e5 = StwoCudaQm31{ b44, b75, b75, b75 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 55u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    e3 = StwoCudaQm31{ b45, b75, b75, b75 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 56u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    e5 = StwoCudaQm31{ b46, b75, b75, b75 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 57u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    e3 = StwoCudaQm31{ b47, b75, b75, b75 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 58u);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    e5 = StwoCudaQm31{ b48, b75, b75, b75 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 59u);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    e3 = StwoCudaQm31{ b49, b75, b75, b75 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 60u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    e5 = StwoCudaQm31{ b50, b75, b75, b75 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 61u);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    e3 = StwoCudaQm31{ b51, b75, b75, b75 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 62u);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    e5 = StwoCudaQm31{ b52, b75, b75, b75 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 63u);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    e3 = StwoCudaQm31{ b53, b75, b75, b75 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 64u);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    e5 = StwoCudaQm31{ b54, b75, b75, b75 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 65u);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 54u, row_index, 0);
    e3 = StwoCudaQm31{ b55, b75, b75, b75 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 66u);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 55u, row_index, 0);
    e5 = StwoCudaQm31{ b56, b75, b75, b75 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 67u);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    e3 = StwoCudaQm31{ b57, b75, b75, b75 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 68u);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    e5 = StwoCudaQm31{ b58, b75, b75, b75 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 69u);
    e3 = stwo_qm31_sub(e5, e4);
    e4 = stwo_load_qm31(ext_params, 70u);
    e5 = StwoCudaQm31{ b2, b75, b75, b75 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 71u);
    e4 = stwo_qm31_add(e5, e6);
    e5 = stwo_load_qm31(ext_params, 72u);
    e6 = StwoCudaQm31{ b31, b75, b75, b75 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 73u);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    e4 = StwoCudaQm31{ b59, b75, b75, b75 };
    e5 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(ext_params, 74u);
    e6 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(ext_params, 75u);
    e4 = StwoCudaQm31{ b3, b75, b75, b75 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(ext_params, 76u);
    e5 = stwo_qm31_add(e4, e7);
    e4 = stwo_load_qm31(ext_params, 77u);
    e7 = StwoCudaQm31{ b32, b75, b75, b75 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e4, e7);
    e7 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(ext_params, 78u);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    e5 = StwoCudaQm31{ b60, b75, b75, b75 };
    e4 = stwo_qm31_mul(e8, e5);
    e5 = stwo_qm31_add(e7, e4);
    e4 = stwo_load_qm31(ext_params, 79u);
    e7 = stwo_qm31_sub(e5, e4);
    e4 = stwo_load_qm31(ext_params, 80u);
    e5 = StwoCudaQm31{ b4, b75, b75, b75 };
    e8 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 81u);
    e4 = stwo_qm31_add(e5, e8);
    e5 = stwo_load_qm31(ext_params, 82u);
    e8 = StwoCudaQm31{ b33, b75, b75, b75 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e5, e8);
    e8 = stwo_qm31_add(e4, e9);
    e9 = stwo_load_qm31(ext_params, 83u);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 60u, row_index, 0);
    e4 = StwoCudaQm31{ b61, b75, b75, b75 };
    e5 = stwo_qm31_mul(e9, e4);
    e4 = stwo_qm31_add(e8, e5);
    e5 = stwo_load_qm31(ext_params, 84u);
    e8 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(ext_params, 85u);
    e4 = StwoCudaQm31{ b5, b75, b75, b75 };
    e9 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(ext_params, 86u);
    e5 = stwo_qm31_add(e4, e9);
    e4 = stwo_load_qm31(ext_params, 87u);
    e9 = StwoCudaQm31{ b34, b75, b75, b75 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e4, e9);
    e9 = stwo_qm31_add(e5, e10);
    e10 = stwo_load_qm31(ext_params, 88u);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 61u, row_index, 0);
    e5 = StwoCudaQm31{ b62, b75, b75, b75 };
    e4 = stwo_qm31_mul(e10, e5);
    e5 = stwo_qm31_add(e9, e4);
    e4 = stwo_load_qm31(ext_params, 89u);
    e9 = stwo_qm31_sub(e5, e4);
    e4 = stwo_load_qm31(ext_params, 90u);
    e5 = StwoCudaQm31{ b6, b75, b75, b75 };
    e10 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 91u);
    e4 = stwo_qm31_add(e5, e10);
    e5 = stwo_load_qm31(ext_params, 92u);
    e10 = StwoCudaQm31{ b35, b75, b75, b75 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e5, e10);
    e10 = stwo_qm31_add(e4, e11);
    e11 = stwo_load_qm31(ext_params, 93u);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 62u, row_index, 0);
    e4 = StwoCudaQm31{ b63, b75, b75, b75 };
    e5 = stwo_qm31_mul(e11, e4);
    e4 = stwo_qm31_add(e10, e5);
    e5 = stwo_load_qm31(ext_params, 94u);
    e10 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(ext_params, 95u);
    e4 = StwoCudaQm31{ b7, b75, b75, b75 };
    e11 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(ext_params, 96u);
    e5 = stwo_qm31_add(e4, e11);
    e4 = stwo_load_qm31(ext_params, 97u);
    e11 = StwoCudaQm31{ b36, b75, b75, b75 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e4, e11);
    e11 = stwo_qm31_add(e5, e12);
    e12 = stwo_load_qm31(ext_params, 98u);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 63u, row_index, 0);
    e5 = StwoCudaQm31{ b64, b75, b75, b75 };
    e4 = stwo_qm31_mul(e12, e5);
    e5 = stwo_qm31_add(e11, e4);
    e4 = stwo_load_qm31(ext_params, 99u);
    e11 = stwo_qm31_sub(e5, e4);
    e4 = stwo_load_qm31(ext_params, 100u);
    e5 = StwoCudaQm31{ b8, b75, b75, b75 };
    e12 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 101u);
    e4 = stwo_qm31_add(e5, e12);
    e5 = stwo_load_qm31(ext_params, 102u);
    e12 = StwoCudaQm31{ b37, b75, b75, b75 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e5, e12);
    e12 = stwo_qm31_add(e4, e13);
    e13 = stwo_load_qm31(ext_params, 103u);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 64u, row_index, 0);
    e4 = StwoCudaQm31{ b65, b75, b75, b75 };
    e5 = stwo_qm31_mul(e13, e4);
    e4 = stwo_qm31_add(e12, e5);
    e5 = stwo_load_qm31(ext_params, 104u);
    e12 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(ext_params, 105u);
    e4 = StwoCudaQm31{ b9, b75, b75, b75 };
    e13 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(ext_params, 106u);
    e5 = stwo_qm31_add(e4, e13);
    e4 = stwo_load_qm31(ext_params, 107u);
    e13 = StwoCudaQm31{ b38, b75, b75, b75 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e4, e13);
    e13 = stwo_qm31_add(e5, e14);
    e14 = stwo_load_qm31(ext_params, 108u);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 65u, row_index, 0);
    e5 = StwoCudaQm31{ b66, b75, b75, b75 };
    e4 = stwo_qm31_mul(e14, e5);
    e5 = stwo_qm31_add(e13, e4);
    e4 = stwo_load_qm31(ext_params, 109u);
    e13 = stwo_qm31_sub(e5, e4);
    e4 = stwo_load_qm31(ext_params, 110u);
    e5 = StwoCudaQm31{ b10, b75, b75, b75 };
    e14 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 111u);
    e4 = stwo_qm31_add(e5, e14);
    e5 = stwo_load_qm31(ext_params, 112u);
    e14 = StwoCudaQm31{ b39, b75, b75, b75 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e5, e14);
    e14 = stwo_qm31_add(e4, e15);
    e15 = stwo_load_qm31(ext_params, 113u);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 66u, row_index, 0);
    e4 = StwoCudaQm31{ b67, b75, b75, b75 };
    e5 = stwo_qm31_mul(e15, e4);
    e4 = stwo_qm31_add(e14, e5);
    e5 = stwo_load_qm31(ext_params, 114u);
    e14 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(ext_params, 115u);
    e4 = StwoCudaQm31{ b11, b75, b75, b75 };
    e15 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(ext_params, 116u);
    e5 = stwo_qm31_add(e4, e15);
    e4 = stwo_load_qm31(ext_params, 117u);
    e15 = StwoCudaQm31{ b40, b75, b75, b75 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e4, e15);
    e15 = stwo_qm31_add(e5, e16);
    e16 = stwo_load_qm31(ext_params, 118u);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 67u, row_index, 0);
    e5 = StwoCudaQm31{ b68, b75, b75, b75 };
    e4 = stwo_qm31_mul(e16, e5);
    e5 = stwo_qm31_add(e15, e4);
    e4 = stwo_load_qm31(ext_params, 119u);
    e15 = stwo_qm31_sub(e5, e4);
    e4 = stwo_load_qm31(ext_params, 120u);
    e5 = StwoCudaQm31{ b12, b75, b75, b75 };
    e16 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 121u);
    e4 = stwo_qm31_add(e5, e16);
    e5 = stwo_load_qm31(ext_params, 122u);
    e16 = StwoCudaQm31{ b41, b75, b75, b75 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e5, e16);
    e16 = stwo_qm31_add(e4, e17);
    e17 = stwo_load_qm31(ext_params, 123u);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 68u, row_index, 0);
    e4 = StwoCudaQm31{ b69, b75, b75, b75 };
    e5 = stwo_qm31_mul(e17, e4);
    e4 = stwo_qm31_add(e16, e5);
    e5 = stwo_load_qm31(ext_params, 124u);
    e16 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(ext_params, 125u);
    e4 = StwoCudaQm31{ b13, b75, b75, b75 };
    e17 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(ext_params, 126u);
    e5 = stwo_qm31_add(e4, e17);
    e4 = stwo_load_qm31(ext_params, 127u);
    e17 = StwoCudaQm31{ b42, b75, b75, b75 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e4, e17);
    e17 = stwo_qm31_add(e5, e18);
    e18 = stwo_load_qm31(ext_params, 128u);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 69u, row_index, 0);
    e5 = StwoCudaQm31{ b70, b75, b75, b75 };
    e4 = stwo_qm31_mul(e18, e5);
    e5 = stwo_qm31_add(e17, e4);
    e4 = stwo_load_qm31(ext_params, 129u);
    e17 = stwo_qm31_sub(e5, e4);
    e4 = stwo_load_qm31(ext_params, 315u);
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_load_qm31(ext_params, 316u);
    e18 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e18);
    e18 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 317u);
    e0 = stwo_qm31_mul(e3, e1);
    e1 = stwo_load_qm31(ext_params, 318u);
    e5 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e0, e5);
    e5 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 319u);
    e2 = stwo_qm31_mul(e7, e3);
    e3 = stwo_load_qm31(ext_params, 320u);
    e0 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e2, e0);
    e0 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 321u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(ext_params, 322u);
    e2 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e2);
    e2 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 323u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(ext_params, 324u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(ext_params, 325u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(ext_params, 326u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(ext_params, 327u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(ext_params, 328u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 329u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(ext_params, 330u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e17 = StwoCudaQm31{ b82, b83, b84, b85 };
    e16 = stwo_qm31_mul(e17, e18);
    e18 = stwo_qm31_sub(e16, e4);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e16 = StwoCudaQm31{ b86, b87, b88, b89 };
    e4 = stwo_qm31_sub(e16, e17);
    e17 = stwo_qm31_mul(e4, e5);
    e4 = stwo_qm31_sub(e17, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e17 = StwoCudaQm31{ b90, b91, b92, b93 };
    e1 = stwo_qm31_sub(e17, e16);
    e16 = stwo_qm31_mul(e1, e0);
    e1 = stwo_qm31_sub(e16, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e16 = StwoCudaQm31{ b94, b95, b96, b97 };
    e3 = stwo_qm31_sub(e16, e17);
    e17 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e17, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, 0);
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, 0);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, 0);
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, 0);
    e17 = StwoCudaQm31{ b98, b99, b100, b101 };
    e7 = stwo_qm31_sub(e17, e16);
    e16 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e16, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 20u, row_index, 0);
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 21u, row_index, 0);
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 22u, row_index, 0);
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 23u, row_index, 0);
    e16 = StwoCudaQm31{ b102, b103, b104, b105 };
    e9 = stwo_qm31_sub(e16, e17);
    e17 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e17, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b106 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 24u, row_index, 0);
    unsigned b107 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 25u, row_index, 0);
    unsigned b108 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 26u, row_index, 0);
    unsigned b109 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 27u, row_index, 0);
    e17 = StwoCudaQm31{ b106, b107, b108, b109 };
    e11 = stwo_qm31_sub(e17, e16);
    e16 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e16, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b110 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 28u, row_index, 0);
    unsigned b111 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 29u, row_index, 0);
    unsigned b112 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 30u, row_index, 0);
    unsigned b113 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 31u, row_index, 0);
    e16 = StwoCudaQm31{ b110, b111, b112, b113 };
    e13 = stwo_qm31_sub(e16, e17);
    e16 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e16, e15);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
