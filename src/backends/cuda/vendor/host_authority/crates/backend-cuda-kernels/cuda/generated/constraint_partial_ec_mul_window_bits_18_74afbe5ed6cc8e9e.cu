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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_f94151d7dfa16aac(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 476u);
    unsigned b128 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 295u, row_index, 0);
    unsigned b131 = base_params[435u];
    unsigned b132 = stwo_m31_add(b128, b131);
    unsigned b130 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b132, b130, b130, b130 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 477u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 478u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 479u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    e0 = StwoCudaQm31{ b0, b130, b130, b130 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 480u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 481u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e3 = StwoCudaQm31{ b1, b130, b130, b130 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 482u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    e1 = StwoCudaQm31{ b2, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 483u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e3 = StwoCudaQm31{ b3, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 484u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e1 = StwoCudaQm31{ b4, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 485u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e3 = StwoCudaQm31{ b5, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 486u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    e1 = StwoCudaQm31{ b6, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 487u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    e3 = StwoCudaQm31{ b7, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 488u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    e1 = StwoCudaQm31{ b8, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 489u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    e3 = StwoCudaQm31{ b9, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 490u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    e1 = StwoCudaQm31{ b10, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 491u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    e3 = StwoCudaQm31{ b11, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 492u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    e1 = StwoCudaQm31{ b12, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 493u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    e3 = StwoCudaQm31{ b13, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 494u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    e1 = StwoCudaQm31{ b14, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 495u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    e3 = StwoCudaQm31{ b15, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 496u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    e1 = StwoCudaQm31{ b16, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 497u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    e3 = StwoCudaQm31{ b17, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 498u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    e1 = StwoCudaQm31{ b18, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 499u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    e3 = StwoCudaQm31{ b19, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 500u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    e1 = StwoCudaQm31{ b20, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 501u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    e3 = StwoCudaQm31{ b21, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 502u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    e1 = StwoCudaQm31{ b22, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 503u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    e3 = StwoCudaQm31{ b23, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 504u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    e1 = StwoCudaQm31{ b24, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 505u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    e3 = StwoCudaQm31{ b25, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 506u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    e1 = StwoCudaQm31{ b26, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 507u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    e3 = StwoCudaQm31{ b27, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 508u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    e1 = StwoCudaQm31{ b28, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 509u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    e3 = StwoCudaQm31{ b29, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 510u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    e1 = StwoCudaQm31{ b30, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 511u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    e3 = StwoCudaQm31{ b31, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 512u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    e1 = StwoCudaQm31{ b32, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 513u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    e3 = StwoCudaQm31{ b33, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 514u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    e1 = StwoCudaQm31{ b34, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 515u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    e3 = StwoCudaQm31{ b35, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 516u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    e1 = StwoCudaQm31{ b36, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 517u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    e3 = StwoCudaQm31{ b37, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 518u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    e1 = StwoCudaQm31{ b38, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 519u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    e3 = StwoCudaQm31{ b39, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 520u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    e1 = StwoCudaQm31{ b40, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 521u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    e3 = StwoCudaQm31{ b41, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 522u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    e1 = StwoCudaQm31{ b42, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 523u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    e3 = StwoCudaQm31{ b43, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 524u);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    e1 = StwoCudaQm31{ b44, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 525u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    e3 = StwoCudaQm31{ b45, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 526u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    e1 = StwoCudaQm31{ b46, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 527u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    e3 = StwoCudaQm31{ b47, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 528u);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    e1 = StwoCudaQm31{ b48, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 529u);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    e3 = StwoCudaQm31{ b49, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 530u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    e1 = StwoCudaQm31{ b50, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 531u);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    e3 = StwoCudaQm31{ b51, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 532u);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    e1 = StwoCudaQm31{ b52, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 533u);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    e3 = StwoCudaQm31{ b53, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 534u);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 54u, row_index, 0);
    e1 = StwoCudaQm31{ b54, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 535u);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 55u, row_index, 0);
    e3 = StwoCudaQm31{ b55, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 536u);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    e1 = StwoCudaQm31{ b56, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 537u);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    e3 = StwoCudaQm31{ b57, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 538u);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    e1 = StwoCudaQm31{ b58, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 539u);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    e3 = StwoCudaQm31{ b59, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 540u);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 60u, row_index, 0);
    e1 = StwoCudaQm31{ b60, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 541u);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 61u, row_index, 0);
    e3 = StwoCudaQm31{ b61, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 542u);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 62u, row_index, 0);
    e1 = StwoCudaQm31{ b62, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 543u);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 63u, row_index, 0);
    e3 = StwoCudaQm31{ b63, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 544u);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 64u, row_index, 0);
    e1 = StwoCudaQm31{ b64, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 545u);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 65u, row_index, 0);
    e3 = StwoCudaQm31{ b65, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 546u);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 66u, row_index, 0);
    e1 = StwoCudaQm31{ b66, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 547u);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 67u, row_index, 0);
    e3 = StwoCudaQm31{ b67, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 548u);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 68u, row_index, 0);
    e1 = StwoCudaQm31{ b68, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 549u);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 69u, row_index, 0);
    e3 = StwoCudaQm31{ b69, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 550u);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 70u, row_index, 0);
    e1 = StwoCudaQm31{ b70, b130, b130, b130 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 551u);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 71u, row_index, 0);
    e3 = StwoCudaQm31{ b71, b130, b130, b130 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 552u);
    e1 = stwo_qm31_sub(e3, e4);
    unsigned b129 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 296u, row_index, 0);
    e4 = StwoCudaQm31{ b129, b130, b130, b130 };
    e3 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e4);
    e4 = stwo_load_qm31(ext_params, 553u);
    e0 = StwoCudaQm31{ b0, b130, b130, b130 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e4, e0);
    e0 = stwo_load_qm31(ext_params, 554u);
    e4 = stwo_qm31_add(e0, e5);
    e0 = stwo_load_qm31(ext_params, 555u);
    unsigned b133 = base_params[437u];
    unsigned b134 = stwo_m31_add(b1, b133);
    e5 = StwoCudaQm31{ b134, b130, b130, b130 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e0, e5);
    e5 = stwo_qm31_add(e4, e6);
    e6 = stwo_load_qm31(ext_params, 556u);
    e4 = StwoCudaQm31{ b3, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e4);
    e4 = stwo_qm31_add(e5, e0);
    e0 = stwo_load_qm31(ext_params, 557u);
    e5 = StwoCudaQm31{ b4, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e5);
    e5 = stwo_qm31_add(e4, e6);
    e6 = stwo_load_qm31(ext_params, 558u);
    e4 = StwoCudaQm31{ b5, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e4);
    e4 = stwo_qm31_add(e5, e0);
    e0 = stwo_load_qm31(ext_params, 559u);
    e5 = StwoCudaQm31{ b6, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e5);
    e5 = stwo_qm31_add(e4, e6);
    e6 = stwo_load_qm31(ext_params, 560u);
    e4 = StwoCudaQm31{ b7, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e4);
    e4 = stwo_qm31_add(e5, e0);
    e0 = stwo_load_qm31(ext_params, 561u);
    e5 = StwoCudaQm31{ b8, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e5);
    e5 = stwo_qm31_add(e4, e6);
    e6 = stwo_load_qm31(ext_params, 562u);
    e4 = StwoCudaQm31{ b9, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e4);
    e4 = stwo_qm31_add(e5, e0);
    e0 = stwo_load_qm31(ext_params, 563u);
    e5 = StwoCudaQm31{ b10, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e5);
    e5 = stwo_qm31_add(e4, e6);
    e6 = stwo_load_qm31(ext_params, 564u);
    e4 = StwoCudaQm31{ b11, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e4);
    e4 = stwo_qm31_add(e5, e0);
    e0 = stwo_load_qm31(ext_params, 565u);
    e5 = StwoCudaQm31{ b12, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e5);
    e5 = stwo_qm31_add(e4, e6);
    e6 = stwo_load_qm31(ext_params, 566u);
    e4 = StwoCudaQm31{ b13, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e4);
    e4 = stwo_qm31_add(e5, e0);
    e0 = stwo_load_qm31(ext_params, 567u);
    e5 = StwoCudaQm31{ b14, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e5);
    e5 = stwo_qm31_add(e4, e6);
    e6 = stwo_load_qm31(ext_params, 568u);
    e4 = StwoCudaQm31{ b15, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e4);
    e4 = stwo_qm31_add(e5, e0);
    e0 = stwo_load_qm31(ext_params, 569u);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 570u);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 184u, row_index, 0);
    e4 = StwoCudaQm31{ b72, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 571u);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 185u, row_index, 0);
    e5 = StwoCudaQm31{ b73, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 572u);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 186u, row_index, 0);
    e4 = StwoCudaQm31{ b74, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 573u);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 187u, row_index, 0);
    e5 = StwoCudaQm31{ b75, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 574u);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 188u, row_index, 0);
    e4 = StwoCudaQm31{ b76, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 575u);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 189u, row_index, 0);
    e5 = StwoCudaQm31{ b77, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 576u);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 190u, row_index, 0);
    e4 = StwoCudaQm31{ b78, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 577u);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 191u, row_index, 0);
    e5 = StwoCudaQm31{ b79, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 578u);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 192u, row_index, 0);
    e4 = StwoCudaQm31{ b80, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 579u);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 193u, row_index, 0);
    e5 = StwoCudaQm31{ b81, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 580u);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 194u, row_index, 0);
    e4 = StwoCudaQm31{ b82, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 581u);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 195u, row_index, 0);
    e5 = StwoCudaQm31{ b83, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 582u);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 196u, row_index, 0);
    e4 = StwoCudaQm31{ b84, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 583u);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 197u, row_index, 0);
    e5 = StwoCudaQm31{ b85, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 584u);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 198u, row_index, 0);
    e4 = StwoCudaQm31{ b86, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 585u);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 199u, row_index, 0);
    e5 = StwoCudaQm31{ b87, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 586u);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 200u, row_index, 0);
    e4 = StwoCudaQm31{ b88, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 587u);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 201u, row_index, 0);
    e5 = StwoCudaQm31{ b89, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 588u);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 202u, row_index, 0);
    e4 = StwoCudaQm31{ b90, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 589u);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 203u, row_index, 0);
    e5 = StwoCudaQm31{ b91, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 590u);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 204u, row_index, 0);
    e4 = StwoCudaQm31{ b92, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 591u);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 205u, row_index, 0);
    e5 = StwoCudaQm31{ b93, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 592u);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 206u, row_index, 0);
    e4 = StwoCudaQm31{ b94, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 593u);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 207u, row_index, 0);
    e5 = StwoCudaQm31{ b95, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 594u);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 208u, row_index, 0);
    e4 = StwoCudaQm31{ b96, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 595u);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 209u, row_index, 0);
    e5 = StwoCudaQm31{ b97, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 596u);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 210u, row_index, 0);
    e4 = StwoCudaQm31{ b98, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 597u);
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 211u, row_index, 0);
    e5 = StwoCudaQm31{ b99, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 598u);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 240u, row_index, 0);
    e4 = StwoCudaQm31{ b100, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 599u);
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 241u, row_index, 0);
    e5 = StwoCudaQm31{ b101, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 600u);
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 242u, row_index, 0);
    e4 = StwoCudaQm31{ b102, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 601u);
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 243u, row_index, 0);
    e5 = StwoCudaQm31{ b103, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 602u);
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 244u, row_index, 0);
    e4 = StwoCudaQm31{ b104, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 603u);
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 245u, row_index, 0);
    e5 = StwoCudaQm31{ b105, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 604u);
    unsigned b106 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 246u, row_index, 0);
    e4 = StwoCudaQm31{ b106, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 605u);
    unsigned b107 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 247u, row_index, 0);
    e5 = StwoCudaQm31{ b107, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 606u);
    unsigned b108 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 248u, row_index, 0);
    e4 = StwoCudaQm31{ b108, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 607u);
    unsigned b109 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 249u, row_index, 0);
    e5 = StwoCudaQm31{ b109, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 608u);
    unsigned b110 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 250u, row_index, 0);
    e4 = StwoCudaQm31{ b110, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 609u);
    unsigned b111 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 251u, row_index, 0);
    e5 = StwoCudaQm31{ b111, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 610u);
    unsigned b112 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 252u, row_index, 0);
    e4 = StwoCudaQm31{ b112, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 611u);
    unsigned b113 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 253u, row_index, 0);
    e5 = StwoCudaQm31{ b113, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 612u);
    unsigned b114 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 254u, row_index, 0);
    e4 = StwoCudaQm31{ b114, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 613u);
    unsigned b115 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 255u, row_index, 0);
    e5 = StwoCudaQm31{ b115, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 614u);
    unsigned b116 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 256u, row_index, 0);
    e4 = StwoCudaQm31{ b116, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 615u);
    unsigned b117 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 257u, row_index, 0);
    e5 = StwoCudaQm31{ b117, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 616u);
    unsigned b118 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 258u, row_index, 0);
    e4 = StwoCudaQm31{ b118, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 617u);
    unsigned b119 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 259u, row_index, 0);
    e5 = StwoCudaQm31{ b119, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 618u);
    unsigned b120 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 260u, row_index, 0);
    e4 = StwoCudaQm31{ b120, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 619u);
    unsigned b121 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 261u, row_index, 0);
    e5 = StwoCudaQm31{ b121, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 620u);
    unsigned b122 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 262u, row_index, 0);
    e4 = StwoCudaQm31{ b122, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 621u);
    unsigned b123 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 263u, row_index, 0);
    e5 = StwoCudaQm31{ b123, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 622u);
    unsigned b124 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 264u, row_index, 0);
    e4 = StwoCudaQm31{ b124, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 623u);
    unsigned b125 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 265u, row_index, 0);
    e5 = StwoCudaQm31{ b125, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 624u);
    unsigned b126 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 266u, row_index, 0);
    e4 = StwoCudaQm31{ b126, b130, b130, b130 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 625u);
    unsigned b127 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 267u, row_index, 0);
    e5 = StwoCudaQm31{ b127, b130, b130, b130 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_load_qm31(ext_params, 626u);
    e4 = stwo_qm31_sub(e5, e0);
    e0 = stwo_load_qm31(ext_params, 753u);
    e5 = stwo_qm31_mul(e1, e0);
    e0 = StwoCudaQm31{ b129, b130, b130, b130 };
    e6 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e5, e6);
    e6 = stwo_qm31_mul(e2, e1);
    unsigned b135 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 248u, row_index, 0);
    unsigned b136 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 249u, row_index, 0);
    unsigned b137 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 250u, row_index, 0);
    unsigned b138 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 251u, row_index, 0);
    e1 = StwoCudaQm31{ b135, b136, b137, b138 };
    unsigned b139 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 252u, row_index, 0);
    unsigned b140 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 253u, row_index, 0);
    unsigned b141 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 254u, row_index, 0);
    unsigned b142 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 255u, row_index, 0);
    e2 = StwoCudaQm31{ b139, b140, b141, b142 };
    e5 = stwo_qm31_sub(e2, e1);
    e1 = stwo_qm31_mul(e5, e6);
    e5 = stwo_qm31_sub(e1, e0);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b143 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 256u, row_index, -1);
    unsigned b145 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 257u, row_index, -1);
    unsigned b147 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 258u, row_index, -1);
    unsigned b149 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 259u, row_index, -1);
    e1 = StwoCudaQm31{ b143, b145, b147, b149 };
    unsigned b144 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 256u, row_index, 0);
    unsigned b146 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 257u, row_index, 0);
    unsigned b148 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 258u, row_index, 0);
    unsigned b150 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 259u, row_index, 0);
    e0 = StwoCudaQm31{ b144, b146, b148, b150 };
    e6 = stwo_qm31_sub(e0, e1);
    e0 = stwo_qm31_sub(e6, e2);
    e6 = stwo_load_qm31(ext_params, 754u);
    e2 = stwo_qm31_add(e0, e6);
    e6 = stwo_qm31_mul(e2, e4);
    e2 = stwo_qm31_sub(e6, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
