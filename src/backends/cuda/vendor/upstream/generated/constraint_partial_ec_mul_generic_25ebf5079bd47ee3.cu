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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_88971bd0790d570c(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 542u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 416u, row_index, 0);
    unsigned b35 = base_params[574u];
    unsigned b36 = stwo_m31_add(b0, b35);
    unsigned b34 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b36, b34, b34, b34 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 543u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 544u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 545u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 417u, row_index, 0);
    unsigned b37 = base_params[576u];
    unsigned b38 = stwo_m31_add(b1, b37);
    e0 = StwoCudaQm31{ b38, b34, b34, b34 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 546u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 547u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 548u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 418u, row_index, 0);
    unsigned b39 = base_params[578u];
    unsigned b40 = stwo_m31_add(b2, b39);
    e1 = StwoCudaQm31{ b40, b34, b34, b34 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 549u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(ext_params, 550u);
    e4 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 551u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 419u, row_index, 0);
    unsigned b41 = base_params[580u];
    unsigned b42 = stwo_m31_add(b3, b41);
    e0 = StwoCudaQm31{ b42, b34, b34, b34 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 552u);
    e1 = stwo_qm31_add(e0, e5);
    e0 = stwo_load_qm31(ext_params, 553u);
    e5 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 554u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 420u, row_index, 0);
    unsigned b43 = base_params[583u];
    unsigned b44 = stwo_m31_add(b4, b43);
    e1 = StwoCudaQm31{ b44, b34, b34, b34 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 555u);
    e0 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(ext_params, 556u);
    e6 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 557u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 421u, row_index, 0);
    unsigned b45 = base_params[585u];
    unsigned b46 = stwo_m31_add(b5, b45);
    e0 = StwoCudaQm31{ b46, b34, b34, b34 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 558u);
    e1 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(ext_params, 559u);
    e7 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 560u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 422u, row_index, 0);
    unsigned b47 = base_params[587u];
    unsigned b48 = stwo_m31_add(b6, b47);
    e1 = StwoCudaQm31{ b48, b34, b34, b34 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 561u);
    e0 = stwo_qm31_add(e1, e8);
    e1 = stwo_load_qm31(ext_params, 562u);
    e8 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 563u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 423u, row_index, 0);
    unsigned b49 = base_params[589u];
    unsigned b50 = stwo_m31_add(b7, b49);
    e0 = StwoCudaQm31{ b50, b34, b34, b34 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 564u);
    e1 = stwo_qm31_add(e0, e9);
    e0 = stwo_load_qm31(ext_params, 565u);
    e9 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 566u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 424u, row_index, 0);
    unsigned b51 = base_params[591u];
    unsigned b52 = stwo_m31_add(b8, b51);
    e1 = StwoCudaQm31{ b52, b34, b34, b34 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 567u);
    e0 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(ext_params, 568u);
    e10 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 569u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 425u, row_index, 0);
    unsigned b53 = base_params[593u];
    unsigned b54 = stwo_m31_add(b9, b53);
    e0 = StwoCudaQm31{ b54, b34, b34, b34 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 570u);
    e1 = stwo_qm31_add(e0, e11);
    e0 = stwo_load_qm31(ext_params, 571u);
    e11 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 572u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 426u, row_index, 0);
    e1 = StwoCudaQm31{ b10, b34, b34, b34 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 573u);
    e0 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(ext_params, 574u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 427u, row_index, 0);
    e12 = StwoCudaQm31{ b11, b34, b34, b34 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e0, e13);
    e13 = stwo_load_qm31(ext_params, 575u);
    e0 = stwo_qm31_sub(e12, e13);
    e13 = stwo_load_qm31(ext_params, 576u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 428u, row_index, 0);
    e12 = StwoCudaQm31{ b12, b34, b34, b34 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_load_qm31(ext_params, 577u);
    e13 = stwo_qm31_add(e12, e1);
    e12 = stwo_load_qm31(ext_params, 578u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 429u, row_index, 0);
    e1 = StwoCudaQm31{ b13, b34, b34, b34 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e12, e1);
    e1 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(ext_params, 579u);
    e13 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(ext_params, 580u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 430u, row_index, 0);
    e1 = StwoCudaQm31{ b14, b34, b34, b34 };
    e12 = stwo_qm31_mul(e14, e1);
    e1 = stwo_load_qm31(ext_params, 581u);
    e14 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(ext_params, 582u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 431u, row_index, 0);
    e12 = StwoCudaQm31{ b15, b34, b34, b34 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 583u);
    e14 = stwo_qm31_sub(e12, e15);
    e15 = stwo_load_qm31(ext_params, 584u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 432u, row_index, 0);
    e12 = StwoCudaQm31{ b16, b34, b34, b34 };
    e1 = stwo_qm31_mul(e15, e12);
    e12 = stwo_load_qm31(ext_params, 585u);
    e15 = stwo_qm31_add(e12, e1);
    e12 = stwo_load_qm31(ext_params, 586u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 433u, row_index, 0);
    e1 = StwoCudaQm31{ b17, b34, b34, b34 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e12, e1);
    e1 = stwo_qm31_add(e15, e16);
    e16 = stwo_load_qm31(ext_params, 587u);
    e15 = stwo_qm31_sub(e1, e16);
    e16 = stwo_load_qm31(ext_params, 588u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 434u, row_index, 0);
    e1 = StwoCudaQm31{ b18, b34, b34, b34 };
    e12 = stwo_qm31_mul(e16, e1);
    e1 = stwo_load_qm31(ext_params, 589u);
    e16 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(ext_params, 590u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 435u, row_index, 0);
    e12 = StwoCudaQm31{ b19, b34, b34, b34 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 591u);
    e16 = stwo_qm31_sub(e12, e17);
    e17 = stwo_load_qm31(ext_params, 592u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 436u, row_index, 0);
    e12 = StwoCudaQm31{ b20, b34, b34, b34 };
    e1 = stwo_qm31_mul(e17, e12);
    e12 = stwo_load_qm31(ext_params, 593u);
    e17 = stwo_qm31_add(e12, e1);
    e12 = stwo_load_qm31(ext_params, 594u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 437u, row_index, 0);
    e1 = StwoCudaQm31{ b21, b34, b34, b34 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e12, e1);
    e1 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(ext_params, 595u);
    e17 = stwo_qm31_sub(e1, e18);
    e18 = stwo_load_qm31(ext_params, 596u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 438u, row_index, 0);
    e1 = StwoCudaQm31{ b22, b34, b34, b34 };
    e12 = stwo_qm31_mul(e18, e1);
    e1 = stwo_load_qm31(ext_params, 597u);
    e18 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(ext_params, 598u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 439u, row_index, 0);
    e12 = StwoCudaQm31{ b23, b34, b34, b34 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(ext_params, 599u);
    e18 = stwo_qm31_sub(e12, e19);
    e19 = stwo_load_qm31(ext_params, 600u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 440u, row_index, 0);
    e12 = StwoCudaQm31{ b24, b34, b34, b34 };
    e1 = stwo_qm31_mul(e19, e12);
    e12 = stwo_load_qm31(ext_params, 601u);
    e19 = stwo_qm31_add(e12, e1);
    e12 = stwo_load_qm31(ext_params, 602u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 441u, row_index, 0);
    e1 = StwoCudaQm31{ b25, b34, b34, b34 };
    StwoCudaQm31 e20 = stwo_qm31_mul(e12, e1);
    e1 = stwo_qm31_add(e19, e20);
    e20 = stwo_load_qm31(ext_params, 603u);
    e19 = stwo_qm31_sub(e1, e20);
    e20 = stwo_load_qm31(ext_params, 604u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 442u, row_index, 0);
    e1 = StwoCudaQm31{ b26, b34, b34, b34 };
    e12 = stwo_qm31_mul(e20, e1);
    e1 = stwo_load_qm31(ext_params, 605u);
    e20 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(ext_params, 606u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 443u, row_index, 0);
    e12 = StwoCudaQm31{ b27, b34, b34, b34 };
    StwoCudaQm31 e21 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e20, e21);
    e21 = stwo_load_qm31(ext_params, 607u);
    e20 = stwo_qm31_sub(e12, e21);
    e21 = stwo_load_qm31(ext_params, 608u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 444u, row_index, 0);
    e12 = StwoCudaQm31{ b28, b34, b34, b34 };
    e1 = stwo_qm31_mul(e21, e12);
    e12 = stwo_load_qm31(ext_params, 609u);
    e21 = stwo_qm31_add(e12, e1);
    e12 = stwo_load_qm31(ext_params, 610u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 445u, row_index, 0);
    e1 = StwoCudaQm31{ b29, b34, b34, b34 };
    StwoCudaQm31 e22 = stwo_qm31_mul(e12, e1);
    e1 = stwo_qm31_add(e21, e22);
    e22 = stwo_load_qm31(ext_params, 611u);
    e21 = stwo_qm31_sub(e1, e22);
    e22 = stwo_load_qm31(ext_params, 612u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 446u, row_index, 0);
    e1 = StwoCudaQm31{ b30, b34, b34, b34 };
    e12 = stwo_qm31_mul(e22, e1);
    e1 = stwo_load_qm31(ext_params, 613u);
    e22 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(ext_params, 614u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 447u, row_index, 0);
    e12 = StwoCudaQm31{ b31, b34, b34, b34 };
    StwoCudaQm31 e23 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e22, e23);
    e23 = stwo_load_qm31(ext_params, 615u);
    e22 = stwo_qm31_sub(e12, e23);
    e23 = stwo_load_qm31(ext_params, 616u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 448u, row_index, 0);
    e12 = StwoCudaQm31{ b32, b34, b34, b34 };
    e1 = stwo_qm31_mul(e23, e12);
    e12 = stwo_load_qm31(ext_params, 617u);
    e23 = stwo_qm31_add(e12, e1);
    e12 = stwo_load_qm31(ext_params, 618u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 449u, row_index, 0);
    e1 = StwoCudaQm31{ b33, b34, b34, b34 };
    StwoCudaQm31 e24 = stwo_qm31_mul(e12, e1);
    e1 = stwo_qm31_add(e23, e24);
    e24 = stwo_load_qm31(ext_params, 619u);
    e23 = stwo_qm31_sub(e1, e24);
    e24 = stwo_load_qm31(ext_params, 1464u);
    e1 = stwo_qm31_mul(e3, e24);
    e24 = stwo_load_qm31(ext_params, 1465u);
    e12 = stwo_qm31_mul(e2, e24);
    e24 = stwo_qm31_add(e1, e12);
    e12 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 1466u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 1467u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 1468u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 1469u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 1470u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(ext_params, 1471u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 1472u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(ext_params, 1473u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(ext_params, 1474u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(ext_params, 1475u);
    e8 = stwo_qm31_mul(e0, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e0, e13);
    e13 = stwo_load_qm31(ext_params, 1476u);
    e0 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(ext_params, 1477u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e0, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 1478u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(ext_params, 1479u);
    e0 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e0);
    e0 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(ext_params, 1480u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(ext_params, 1481u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(ext_params, 1482u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(ext_params, 1483u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e20, e21);
    e21 = stwo_load_qm31(ext_params, 1484u);
    e20 = stwo_qm31_mul(e23, e21);
    e21 = stwo_load_qm31(ext_params, 1485u);
    e18 = stwo_qm31_mul(e22, e21);
    e21 = stwo_qm31_add(e20, e18);
    e18 = stwo_qm31_mul(e22, e23);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 320u, row_index, 0);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 321u, row_index, 0);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 322u, row_index, 0);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 323u, row_index, 0);
    e23 = StwoCudaQm31{ b55, b56, b57, b58 };
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 324u, row_index, 0);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 325u, row_index, 0);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 326u, row_index, 0);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 327u, row_index, 0);
    e22 = StwoCudaQm31{ b59, b60, b61, b62 };
    e20 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e20, e12);
    e20 = stwo_qm31_sub(e23, e24);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e20, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 328u, row_index, 0);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 329u, row_index, 0);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 330u, row_index, 0);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 331u, row_index, 0);
    e23 = StwoCudaQm31{ b63, b64, b65, b66 };
    e24 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e24, e1);
    e24 = stwo_qm31_sub(e22, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e24, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 332u, row_index, 0);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 333u, row_index, 0);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 334u, row_index, 0);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 335u, row_index, 0);
    e22 = StwoCudaQm31{ b67, b68, b69, b70 };
    e3 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e23, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 336u, row_index, 0);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 337u, row_index, 0);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 338u, row_index, 0);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 339u, row_index, 0);
    e23 = StwoCudaQm31{ b71, b72, b73, b74 };
    e5 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e22, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 340u, row_index, 0);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 341u, row_index, 0);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 342u, row_index, 0);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 343u, row_index, 0);
    e22 = StwoCudaQm31{ b75, b76, b77, b78 };
    e7 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e23, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 344u, row_index, 0);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 345u, row_index, 0);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 346u, row_index, 0);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 347u, row_index, 0);
    e23 = StwoCudaQm31{ b79, b80, b81, b82 };
    e9 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e22, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 348u, row_index, 0);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 349u, row_index, 0);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 350u, row_index, 0);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 351u, row_index, 0);
    e22 = StwoCudaQm31{ b83, b84, b85, b86 };
    e11 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e23, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 352u, row_index, 0);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 353u, row_index, 0);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 354u, row_index, 0);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 355u, row_index, 0);
    e23 = StwoCudaQm31{ b87, b88, b89, b90 };
    e13 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e13, e0);
    e13 = stwo_qm31_sub(e22, e15);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 356u, row_index, 0);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 357u, row_index, 0);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 358u, row_index, 0);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 359u, row_index, 0);
    e22 = StwoCudaQm31{ b91, b92, b93, b94 };
    e15 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e23, e17);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 360u, row_index, 0);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 361u, row_index, 0);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 362u, row_index, 0);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 363u, row_index, 0);
    e23 = StwoCudaQm31{ b95, b96, b97, b98 };
    e17 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e22, e19);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 364u, row_index, 0);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 365u, row_index, 0);
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 366u, row_index, 0);
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 367u, row_index, 0);
    e22 = StwoCudaQm31{ b99, b100, b101, b102 };
    e19 = stwo_qm31_sub(e22, e23);
    e22 = stwo_qm31_mul(e19, e18);
    e19 = stwo_qm31_sub(e22, e21);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e19, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
