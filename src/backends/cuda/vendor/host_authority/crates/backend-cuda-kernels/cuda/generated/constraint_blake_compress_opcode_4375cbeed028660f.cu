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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_4ab02f544c34492d(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 536u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 100u, row_index, 0);
    unsigned b60 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b12, b60, b60, b60 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 537u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 538u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 101u, row_index, 0);
    e2 = StwoCudaQm31{ b13, b60, b60, b60 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 539u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 116u, row_index, 0);
    e0 = StwoCudaQm31{ b20, b60, b60, b60 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 540u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 117u, row_index, 0);
    e2 = StwoCudaQm31{ b21, b60, b60, b60 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 541u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 62u, row_index, 0);
    e0 = StwoCudaQm31{ b4, b60, b60, b60 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 542u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 63u, row_index, 0);
    e2 = StwoCudaQm31{ b5, b60, b60, b60 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 543u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 133u, row_index, 0);
    e0 = StwoCudaQm31{ b36, b60, b60, b60 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 544u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 134u, row_index, 0);
    e2 = StwoCudaQm31{ b37, b60, b60, b60 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 545u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 546u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 102u, row_index, 0);
    e2 = StwoCudaQm31{ b14, b60, b60, b60 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 547u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 548u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 103u, row_index, 0);
    e1 = StwoCudaQm31{ b15, b60, b60, b60 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 549u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 118u, row_index, 0);
    e3 = StwoCudaQm31{ b22, b60, b60, b60 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 550u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 119u, row_index, 0);
    e1 = StwoCudaQm31{ b23, b60, b60, b60 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 551u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 68u, row_index, 0);
    e3 = StwoCudaQm31{ b6, b60, b60, b60 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 552u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 69u, row_index, 0);
    e1 = StwoCudaQm31{ b7, b60, b60, b60 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 553u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 135u, row_index, 0);
    e3 = StwoCudaQm31{ b38, b60, b60, b60 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 554u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 136u, row_index, 0);
    e1 = StwoCudaQm31{ b39, b60, b60, b60 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 555u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 556u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 104u, row_index, 0);
    e1 = StwoCudaQm31{ b16, b60, b60, b60 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 557u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 558u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 105u, row_index, 0);
    e2 = StwoCudaQm31{ b17, b60, b60, b60 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 559u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 120u, row_index, 0);
    e4 = StwoCudaQm31{ b24, b60, b60, b60 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 560u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 121u, row_index, 0);
    e2 = StwoCudaQm31{ b25, b60, b60, b60 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 561u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 74u, row_index, 0);
    e4 = StwoCudaQm31{ b8, b60, b60, b60 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 562u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 75u, row_index, 0);
    e2 = StwoCudaQm31{ b9, b60, b60, b60 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 563u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 137u, row_index, 0);
    e4 = StwoCudaQm31{ b40, b60, b60, b60 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 564u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 138u, row_index, 0);
    e2 = StwoCudaQm31{ b41, b60, b60, b60 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 565u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(ext_params, 566u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 106u, row_index, 0);
    e2 = StwoCudaQm31{ b18, b60, b60, b60 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(ext_params, 567u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 568u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 107u, row_index, 0);
    e1 = StwoCudaQm31{ b19, b60, b60, b60 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 569u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 122u, row_index, 0);
    e5 = StwoCudaQm31{ b26, b60, b60, b60 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 570u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 123u, row_index, 0);
    e1 = StwoCudaQm31{ b27, b60, b60, b60 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 571u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 80u, row_index, 0);
    e5 = StwoCudaQm31{ b10, b60, b60, b60 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 572u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 81u, row_index, 0);
    e1 = StwoCudaQm31{ b11, b60, b60, b60 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 573u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 139u, row_index, 0);
    e5 = StwoCudaQm31{ b42, b60, b60, b60 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 574u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 140u, row_index, 0);
    e1 = StwoCudaQm31{ b43, b60, b60, b60 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 575u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(ext_params, 576u);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 141u, row_index, 0);
    e1 = StwoCudaQm31{ b44, b60, b60, b60 };
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(ext_params, 577u);
    e6 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 578u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 126u, row_index, 0);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 142u, row_index, 0);
    unsigned b70 = base_params[97u];
    unsigned b71 = stwo_m31_mul(b45, b70);
    unsigned b72 = stwo_m31_sub(b29, b71);
    e2 = StwoCudaQm31{ b72, b60, b60, b60 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 579u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 143u, row_index, 0);
    e6 = StwoCudaQm31{ b46, b60, b60, b60 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 580u);
    e2 = stwo_qm31_sub(e6, e1);
    e1 = stwo_load_qm31(ext_params, 581u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    unsigned b61 = base_params[44u];
    unsigned b62 = stwo_m31_mul(b1, b61);
    unsigned b63 = stwo_m31_add(b0, b62);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    unsigned b64 = base_params[45u];
    unsigned b65 = stwo_m31_mul(b2, b64);
    unsigned b66 = stwo_m31_add(b63, b65);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    unsigned b67 = base_params[46u];
    unsigned b68 = stwo_m31_mul(b3, b67);
    unsigned b69 = stwo_m31_add(b66, b68);
    e6 = StwoCudaQm31{ b69, b60, b60, b60 };
    e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_load_qm31(ext_params, 582u);
    e1 = stwo_qm31_add(e6, e7);
    e6 = stwo_load_qm31(ext_params, 583u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 144u, row_index, 0);
    e7 = StwoCudaQm31{ b47, b60, b60, b60 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e1, e8);
    e8 = stwo_load_qm31(ext_params, 584u);
    e1 = stwo_qm31_sub(e7, e8);
    e8 = stwo_load_qm31(ext_params, 585u);
    e7 = StwoCudaQm31{ b47, b60, b60, b60 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_load_qm31(ext_params, 586u);
    e8 = stwo_qm31_add(e7, e6);
    e7 = stwo_load_qm31(ext_params, 587u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 125u, row_index, 0);
    unsigned b73 = base_params[98u];
    unsigned b74 = stwo_m31_mul(b44, b73);
    unsigned b75 = stwo_m31_sub(b28, b74);
    e6 = StwoCudaQm31{ b75, b60, b60, b60 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 588u);
    unsigned b76 = base_params[99u];
    unsigned b77 = stwo_m31_mul(b72, b76);
    unsigned b78 = stwo_m31_add(b44, b77);
    e8 = StwoCudaQm31{ b78, b60, b60, b60 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 589u);
    unsigned b79 = base_params[100u];
    unsigned b80 = stwo_m31_mul(b46, b79);
    unsigned b81 = stwo_m31_sub(b45, b80);
    e6 = StwoCudaQm31{ b81, b60, b60, b60 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 590u);
    e8 = StwoCudaQm31{ b46, b60, b60, b60 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 591u);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 592u);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 593u);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 594u);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 595u);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 596u);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 597u);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 598u);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 599u);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 600u);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 601u);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 602u);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 603u);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 604u);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 605u);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 606u);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 607u);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 608u);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 609u);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 610u);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 611u);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 612u);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 613u);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 614u);
    e8 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 615u);
    e6 = stwo_qm31_sub(e8, e7);
    e7 = stwo_load_qm31(ext_params, 616u);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 145u, row_index, 0);
    e8 = StwoCudaQm31{ b48, b60, b60, b60 };
    e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_load_qm31(ext_params, 617u);
    e7 = stwo_qm31_add(e8, e9);
    e8 = stwo_load_qm31(ext_params, 618u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 128u, row_index, 0);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 146u, row_index, 0);
    unsigned b84 = base_params[102u];
    unsigned b85 = stwo_m31_mul(b49, b84);
    unsigned b86 = stwo_m31_sub(b31, b85);
    e9 = StwoCudaQm31{ b86, b60, b60, b60 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 619u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 147u, row_index, 0);
    e7 = StwoCudaQm31{ b50, b60, b60, b60 };
    e8 = stwo_qm31_mul(e10, e7);
    e7 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(ext_params, 620u);
    e9 = stwo_qm31_sub(e7, e8);
    e8 = stwo_load_qm31(ext_params, 621u);
    unsigned b82 = base_params[101u];
    unsigned b83 = stwo_m31_add(b69, b82);
    e7 = StwoCudaQm31{ b83, b60, b60, b60 };
    e10 = stwo_qm31_mul(e8, e7);
    e7 = stwo_load_qm31(ext_params, 622u);
    e8 = stwo_qm31_add(e7, e10);
    e7 = stwo_load_qm31(ext_params, 623u);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 148u, row_index, 0);
    e10 = StwoCudaQm31{ b51, b60, b60, b60 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e7, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 624u);
    e8 = stwo_qm31_sub(e10, e11);
    e11 = stwo_load_qm31(ext_params, 625u);
    e10 = StwoCudaQm31{ b51, b60, b60, b60 };
    e7 = stwo_qm31_mul(e11, e10);
    e10 = stwo_load_qm31(ext_params, 626u);
    e11 = stwo_qm31_add(e10, e7);
    e10 = stwo_load_qm31(ext_params, 627u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 127u, row_index, 0);
    unsigned b87 = base_params[103u];
    unsigned b88 = stwo_m31_mul(b48, b87);
    unsigned b89 = stwo_m31_sub(b30, b88);
    e7 = StwoCudaQm31{ b89, b60, b60, b60 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e10, e7);
    e7 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 628u);
    unsigned b90 = base_params[104u];
    unsigned b91 = stwo_m31_mul(b86, b90);
    unsigned b92 = stwo_m31_add(b48, b91);
    e11 = StwoCudaQm31{ b92, b60, b60, b60 };
    e10 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 629u);
    unsigned b93 = base_params[105u];
    unsigned b94 = stwo_m31_mul(b50, b93);
    unsigned b95 = stwo_m31_sub(b49, b94);
    e7 = StwoCudaQm31{ b95, b60, b60, b60 };
    e12 = stwo_qm31_mul(e10, e7);
    e7 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 630u);
    e11 = StwoCudaQm31{ b50, b60, b60, b60 };
    e10 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 631u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 632u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 633u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 634u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 635u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 636u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 637u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 638u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 639u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 640u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 641u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 642u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 643u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 644u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 645u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 646u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 647u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 648u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 649u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 650u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 651u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 652u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 653u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 654u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 655u);
    e7 = stwo_qm31_sub(e11, e10);
    e10 = stwo_load_qm31(ext_params, 656u);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 149u, row_index, 0);
    e11 = StwoCudaQm31{ b52, b60, b60, b60 };
    e12 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(ext_params, 657u);
    e10 = stwo_qm31_add(e11, e12);
    e11 = stwo_load_qm31(ext_params, 658u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 130u, row_index, 0);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 150u, row_index, 0);
    unsigned b98 = base_params[107u];
    unsigned b99 = stwo_m31_mul(b53, b98);
    unsigned b100 = stwo_m31_sub(b33, b99);
    e12 = StwoCudaQm31{ b100, b60, b60, b60 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e11, e12);
    e12 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 659u);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 151u, row_index, 0);
    e10 = StwoCudaQm31{ b54, b60, b60, b60 };
    e11 = stwo_qm31_mul(e13, e10);
    e10 = stwo_qm31_add(e12, e11);
    e11 = stwo_load_qm31(ext_params, 660u);
    e12 = stwo_qm31_sub(e10, e11);
    e11 = stwo_load_qm31(ext_params, 661u);
    unsigned b96 = base_params[106u];
    unsigned b97 = stwo_m31_add(b69, b96);
    e10 = StwoCudaQm31{ b97, b60, b60, b60 };
    e13 = stwo_qm31_mul(e11, e10);
    e10 = stwo_load_qm31(ext_params, 662u);
    e11 = stwo_qm31_add(e10, e13);
    e10 = stwo_load_qm31(ext_params, 663u);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 152u, row_index, 0);
    e13 = StwoCudaQm31{ b55, b60, b60, b60 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e10, e13);
    e13 = stwo_qm31_add(e11, e14);
    e14 = stwo_load_qm31(ext_params, 664u);
    e11 = stwo_qm31_sub(e13, e14);
    e14 = stwo_load_qm31(ext_params, 665u);
    e13 = StwoCudaQm31{ b55, b60, b60, b60 };
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_load_qm31(ext_params, 666u);
    e14 = stwo_qm31_add(e13, e10);
    e13 = stwo_load_qm31(ext_params, 667u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 129u, row_index, 0);
    unsigned b101 = base_params[108u];
    unsigned b102 = stwo_m31_mul(b52, b101);
    unsigned b103 = stwo_m31_sub(b32, b102);
    e10 = StwoCudaQm31{ b103, b60, b60, b60 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e13, e10);
    e10 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 668u);
    unsigned b104 = base_params[109u];
    unsigned b105 = stwo_m31_mul(b100, b104);
    unsigned b106 = stwo_m31_add(b52, b105);
    e14 = StwoCudaQm31{ b106, b60, b60, b60 };
    e13 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 669u);
    unsigned b107 = base_params[110u];
    unsigned b108 = stwo_m31_mul(b54, b107);
    unsigned b109 = stwo_m31_sub(b53, b108);
    e10 = StwoCudaQm31{ b109, b60, b60, b60 };
    e15 = stwo_qm31_mul(e13, e10);
    e10 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 670u);
    e14 = StwoCudaQm31{ b54, b60, b60, b60 };
    e13 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 671u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 672u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 673u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 674u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 675u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 676u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 677u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 678u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 679u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 680u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 681u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 682u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 683u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 684u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 685u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 686u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 687u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 688u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 689u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 690u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 691u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 692u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 693u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 694u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 695u);
    e10 = stwo_qm31_sub(e14, e13);
    e13 = stwo_load_qm31(ext_params, 696u);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 153u, row_index, 0);
    e14 = StwoCudaQm31{ b56, b60, b60, b60 };
    e15 = stwo_qm31_mul(e13, e14);
    e14 = stwo_load_qm31(ext_params, 697u);
    e13 = stwo_qm31_add(e14, e15);
    e14 = stwo_load_qm31(ext_params, 698u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 132u, row_index, 0);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 154u, row_index, 0);
    unsigned b112 = base_params[112u];
    unsigned b113 = stwo_m31_mul(b57, b112);
    unsigned b114 = stwo_m31_sub(b35, b113);
    e15 = StwoCudaQm31{ b114, b60, b60, b60 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 699u);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 155u, row_index, 0);
    e13 = StwoCudaQm31{ b58, b60, b60, b60 };
    e14 = stwo_qm31_mul(e16, e13);
    e13 = stwo_qm31_add(e15, e14);
    e14 = stwo_load_qm31(ext_params, 700u);
    e15 = stwo_qm31_sub(e13, e14);
    e14 = stwo_load_qm31(ext_params, 701u);
    unsigned b110 = base_params[111u];
    unsigned b111 = stwo_m31_add(b69, b110);
    e13 = StwoCudaQm31{ b111, b60, b60, b60 };
    e16 = stwo_qm31_mul(e14, e13);
    e13 = stwo_load_qm31(ext_params, 702u);
    e14 = stwo_qm31_add(e13, e16);
    e13 = stwo_load_qm31(ext_params, 703u);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 156u, row_index, 0);
    e16 = StwoCudaQm31{ b59, b60, b60, b60 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e13, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(ext_params, 704u);
    e14 = stwo_qm31_sub(e16, e17);
    e17 = stwo_load_qm31(ext_params, 705u);
    e16 = StwoCudaQm31{ b59, b60, b60, b60 };
    e13 = stwo_qm31_mul(e17, e16);
    e16 = stwo_load_qm31(ext_params, 706u);
    e17 = stwo_qm31_add(e16, e13);
    e16 = stwo_load_qm31(ext_params, 707u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 131u, row_index, 0);
    unsigned b115 = base_params[113u];
    unsigned b116 = stwo_m31_mul(b56, b115);
    unsigned b117 = stwo_m31_sub(b34, b116);
    e13 = StwoCudaQm31{ b117, b60, b60, b60 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e16, e13);
    e13 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(ext_params, 708u);
    unsigned b118 = base_params[114u];
    unsigned b119 = stwo_m31_mul(b114, b118);
    unsigned b120 = stwo_m31_add(b56, b119);
    e17 = StwoCudaQm31{ b120, b60, b60, b60 };
    e16 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 709u);
    unsigned b121 = base_params[115u];
    unsigned b122 = stwo_m31_mul(b58, b121);
    unsigned b123 = stwo_m31_sub(b57, b122);
    e13 = StwoCudaQm31{ b123, b60, b60, b60 };
    e18 = stwo_qm31_mul(e16, e13);
    e13 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(ext_params, 710u);
    e17 = StwoCudaQm31{ b58, b60, b60, b60 };
    e16 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 711u);
    e13 = stwo_qm31_add(e17, e16);
    e16 = stwo_load_qm31(ext_params, 712u);
    e17 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 713u);
    e13 = stwo_qm31_add(e17, e16);
    e16 = stwo_load_qm31(ext_params, 714u);
    e17 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 715u);
    e13 = stwo_qm31_add(e17, e16);
    e16 = stwo_load_qm31(ext_params, 716u);
    e17 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 717u);
    e13 = stwo_qm31_add(e17, e16);
    e16 = stwo_load_qm31(ext_params, 718u);
    e17 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 719u);
    e13 = stwo_qm31_add(e17, e16);
    e16 = stwo_load_qm31(ext_params, 720u);
    e17 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 721u);
    e13 = stwo_qm31_add(e17, e16);
    e16 = stwo_load_qm31(ext_params, 722u);
    e17 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 723u);
    e13 = stwo_qm31_add(e17, e16);
    e16 = stwo_load_qm31(ext_params, 724u);
    e17 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 725u);
    e13 = stwo_qm31_add(e17, e16);
    e16 = stwo_load_qm31(ext_params, 726u);
    e17 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 727u);
    e13 = stwo_qm31_add(e17, e16);
    e16 = stwo_load_qm31(ext_params, 728u);
    e17 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 729u);
    e13 = stwo_qm31_add(e17, e16);
    e16 = stwo_load_qm31(ext_params, 730u);
    e17 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 731u);
    e13 = stwo_qm31_add(e17, e16);
    e16 = stwo_load_qm31(ext_params, 732u);
    e17 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 733u);
    e13 = stwo_qm31_add(e17, e16);
    e16 = stwo_load_qm31(ext_params, 734u);
    e17 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 735u);
    e13 = stwo_qm31_sub(e17, e16);
    e16 = stwo_load_qm31(ext_params, 950u);
    e17 = stwo_qm31_mul(e3, e16);
    e16 = stwo_load_qm31(ext_params, 951u);
    e18 = stwo_qm31_mul(e0, e16);
    e16 = stwo_qm31_add(e17, e18);
    e18 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(ext_params, 952u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 953u);
    e17 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e17);
    e17 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 954u);
    e4 = stwo_qm31_mul(e1, e5);
    e5 = stwo_load_qm31(ext_params, 955u);
    e0 = stwo_qm31_mul(e2, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e2, e1);
    e1 = stwo_load_qm31(ext_params, 956u);
    e2 = stwo_qm31_mul(e9, e1);
    e1 = stwo_load_qm31(ext_params, 957u);
    e4 = stwo_qm31_mul(e6, e1);
    e1 = stwo_qm31_add(e2, e4);
    e4 = stwo_qm31_mul(e6, e9);
    e9 = stwo_load_qm31(ext_params, 958u);
    e6 = stwo_qm31_mul(e7, e9);
    e9 = stwo_load_qm31(ext_params, 959u);
    e2 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e6, e2);
    e2 = stwo_qm31_mul(e8, e7);
    e7 = stwo_load_qm31(ext_params, 960u);
    e8 = stwo_qm31_mul(e11, e7);
    e7 = stwo_load_qm31(ext_params, 961u);
    e6 = stwo_qm31_mul(e12, e7);
    e7 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e12, e11);
    e11 = stwo_load_qm31(ext_params, 962u);
    e12 = stwo_qm31_mul(e15, e11);
    e11 = stwo_load_qm31(ext_params, 963u);
    e8 = stwo_qm31_mul(e10, e11);
    e11 = stwo_qm31_add(e12, e8);
    e8 = stwo_qm31_mul(e10, e15);
    e15 = stwo_load_qm31(ext_params, 964u);
    e10 = stwo_qm31_mul(e13, e15);
    e15 = stwo_load_qm31(ext_params, 965u);
    e12 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e10, e12);
    e12 = stwo_qm31_mul(e14, e13);
    unsigned b124 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 84u, row_index, 0);
    unsigned b125 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 85u, row_index, 0);
    unsigned b126 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 86u, row_index, 0);
    unsigned b127 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 87u, row_index, 0);
    e13 = StwoCudaQm31{ b124, b125, b126, b127 };
    unsigned b128 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 88u, row_index, 0);
    unsigned b129 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 89u, row_index, 0);
    unsigned b130 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 90u, row_index, 0);
    unsigned b131 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 91u, row_index, 0);
    e14 = StwoCudaQm31{ b128, b129, b130, b131 };
    e10 = stwo_qm31_sub(e14, e13);
    e13 = stwo_qm31_mul(e10, e18);
    e10 = stwo_qm31_sub(e13, e16);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b132 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 92u, row_index, 0);
    unsigned b133 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 93u, row_index, 0);
    unsigned b134 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 94u, row_index, 0);
    unsigned b135 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 95u, row_index, 0);
    e13 = StwoCudaQm31{ b132, b133, b134, b135 };
    e16 = stwo_qm31_sub(e13, e14);
    e14 = stwo_qm31_mul(e16, e17);
    e16 = stwo_qm31_sub(e14, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b136 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 96u, row_index, 0);
    unsigned b137 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 97u, row_index, 0);
    unsigned b138 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 98u, row_index, 0);
    unsigned b139 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 99u, row_index, 0);
    e14 = StwoCudaQm31{ b136, b137, b138, b139 };
    e3 = stwo_qm31_sub(e14, e13);
    e13 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e13, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b140 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 100u, row_index, 0);
    unsigned b141 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 101u, row_index, 0);
    unsigned b142 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 102u, row_index, 0);
    unsigned b143 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 103u, row_index, 0);
    e13 = StwoCudaQm31{ b140, b141, b142, b143 };
    e5 = stwo_qm31_sub(e13, e14);
    e14 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e14, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b144 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 104u, row_index, 0);
    unsigned b145 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 105u, row_index, 0);
    unsigned b146 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 106u, row_index, 0);
    unsigned b147 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 107u, row_index, 0);
    e14 = StwoCudaQm31{ b144, b145, b146, b147 };
    e1 = stwo_qm31_sub(e14, e13);
    e13 = stwo_qm31_mul(e1, e2);
    e1 = stwo_qm31_sub(e13, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b148 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 108u, row_index, 0);
    unsigned b149 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 109u, row_index, 0);
    unsigned b150 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 110u, row_index, 0);
    unsigned b151 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 111u, row_index, 0);
    e13 = StwoCudaQm31{ b148, b149, b150, b151 };
    e9 = stwo_qm31_sub(e13, e14);
    e14 = stwo_qm31_mul(e9, e6);
    e9 = stwo_qm31_sub(e14, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b152 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 112u, row_index, 0);
    unsigned b153 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 113u, row_index, 0);
    unsigned b154 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 114u, row_index, 0);
    unsigned b155 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 115u, row_index, 0);
    e14 = StwoCudaQm31{ b152, b153, b154, b155 };
    e7 = stwo_qm31_sub(e14, e13);
    e13 = stwo_qm31_mul(e7, e8);
    e7 = stwo_qm31_sub(e13, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b156 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 116u, row_index, 0);
    unsigned b157 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 117u, row_index, 0);
    unsigned b158 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 118u, row_index, 0);
    unsigned b159 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 119u, row_index, 0);
    e13 = StwoCudaQm31{ b156, b157, b158, b159 };
    e11 = stwo_qm31_sub(e13, e14);
    e13 = stwo_qm31_mul(e11, e12);
    e11 = stwo_qm31_sub(e13, e15);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
