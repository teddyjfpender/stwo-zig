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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_f485637a7c02b44c(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 549u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 279u, row_index, 0);
    unsigned b57 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b26, b57, b57, b57 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 550u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 551u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 552u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 280u, row_index, 0);
    e0 = StwoCudaQm31{ b27, b57, b57, b57 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 553u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 554u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 555u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 281u, row_index, 0);
    e1 = StwoCudaQm31{ b28, b57, b57, b57 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 556u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(ext_params, 557u);
    e4 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 558u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 282u, row_index, 0);
    e0 = StwoCudaQm31{ b29, b57, b57, b57 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 559u);
    e1 = stwo_qm31_add(e0, e5);
    e0 = stwo_load_qm31(ext_params, 560u);
    e5 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 561u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 283u, row_index, 0);
    e1 = StwoCudaQm31{ b30, b57, b57, b57 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 562u);
    e0 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(ext_params, 563u);
    e6 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 564u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 284u, row_index, 0);
    unsigned b58 = base_params[119u];
    unsigned b59 = stwo_m31_mul(b31, b58);
    unsigned b60 = stwo_m31_sub(b0, b59);
    e0 = StwoCudaQm31{ b60, b57, b57, b57 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 565u);
    e1 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(ext_params, 566u);
    e7 = StwoCudaQm31{ b31, b57, b57, b57 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e0, e7);
    e7 = stwo_qm31_add(e1, e8);
    e8 = stwo_load_qm31(ext_params, 567u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 285u, row_index, 0);
    unsigned b61 = base_params[120u];
    unsigned b62 = stwo_m31_mul(b32, b61);
    unsigned b63 = stwo_m31_sub(b1, b62);
    e1 = StwoCudaQm31{ b63, b57, b57, b57 };
    e0 = stwo_qm31_mul(e8, e1);
    e1 = stwo_qm31_add(e7, e0);
    e0 = stwo_load_qm31(ext_params, 568u);
    e7 = StwoCudaQm31{ b32, b57, b57, b57 };
    e8 = stwo_qm31_mul(e0, e7);
    e7 = stwo_qm31_add(e1, e8);
    e8 = stwo_load_qm31(ext_params, 569u);
    e1 = stwo_qm31_sub(e7, e8);
    e8 = stwo_load_qm31(ext_params, 570u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 286u, row_index, 0);
    unsigned b64 = base_params[121u];
    unsigned b65 = stwo_m31_mul(b33, b64);
    unsigned b66 = stwo_m31_sub(b2, b65);
    e7 = StwoCudaQm31{ b66, b57, b57, b57 };
    e0 = stwo_qm31_mul(e8, e7);
    e7 = stwo_load_qm31(ext_params, 571u);
    e8 = stwo_qm31_add(e7, e0);
    e7 = stwo_load_qm31(ext_params, 572u);
    e0 = StwoCudaQm31{ b33, b57, b57, b57 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e7, e0);
    e0 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 573u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 287u, row_index, 0);
    unsigned b67 = base_params[122u];
    unsigned b68 = stwo_m31_mul(b34, b67);
    unsigned b69 = stwo_m31_sub(b3, b68);
    e8 = StwoCudaQm31{ b69, b57, b57, b57 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e0, e7);
    e7 = stwo_load_qm31(ext_params, 574u);
    e0 = StwoCudaQm31{ b34, b57, b57, b57 };
    e9 = stwo_qm31_mul(e7, e0);
    e0 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 575u);
    e8 = stwo_qm31_sub(e0, e9);
    e9 = stwo_load_qm31(ext_params, 576u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 289u, row_index, 0);
    unsigned b73 = base_params[124u];
    unsigned b74 = stwo_m31_mul(b36, b73);
    unsigned b75 = stwo_m31_sub(b5, b74);
    e0 = StwoCudaQm31{ b75, b57, b57, b57 };
    e7 = stwo_qm31_mul(e9, e0);
    e0 = stwo_load_qm31(ext_params, 577u);
    e9 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(ext_params, 578u);
    e7 = StwoCudaQm31{ b36, b57, b57, b57 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e0, e7);
    e7 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 579u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 290u, row_index, 0);
    unsigned b76 = base_params[125u];
    unsigned b77 = stwo_m31_mul(b37, b76);
    unsigned b78 = stwo_m31_sub(b6, b77);
    e9 = StwoCudaQm31{ b78, b57, b57, b57 };
    e0 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e7, e0);
    e0 = stwo_load_qm31(ext_params, 580u);
    e7 = StwoCudaQm31{ b37, b57, b57, b57 };
    e10 = stwo_qm31_mul(e0, e7);
    e7 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 581u);
    e9 = stwo_qm31_sub(e7, e10);
    e10 = stwo_load_qm31(ext_params, 582u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 291u, row_index, 0);
    unsigned b79 = base_params[126u];
    unsigned b80 = stwo_m31_mul(b38, b79);
    unsigned b81 = stwo_m31_sub(b7, b80);
    e7 = StwoCudaQm31{ b81, b57, b57, b57 };
    e0 = stwo_qm31_mul(e10, e7);
    e7 = stwo_load_qm31(ext_params, 583u);
    e10 = stwo_qm31_add(e7, e0);
    e7 = stwo_load_qm31(ext_params, 584u);
    e0 = StwoCudaQm31{ b38, b57, b57, b57 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e7, e0);
    e0 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 585u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 292u, row_index, 0);
    unsigned b82 = base_params[127u];
    unsigned b83 = stwo_m31_mul(b39, b82);
    unsigned b84 = stwo_m31_sub(b8, b83);
    e10 = StwoCudaQm31{ b84, b57, b57, b57 };
    e7 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e0, e7);
    e7 = stwo_load_qm31(ext_params, 586u);
    e0 = StwoCudaQm31{ b39, b57, b57, b57 };
    e11 = stwo_qm31_mul(e7, e0);
    e0 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 587u);
    e10 = stwo_qm31_sub(e0, e11);
    e11 = stwo_load_qm31(ext_params, 588u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 288u, row_index, 0);
    unsigned b70 = base_params[123u];
    unsigned b71 = stwo_m31_mul(b35, b70);
    unsigned b72 = stwo_m31_sub(b4, b71);
    e0 = StwoCudaQm31{ b72, b57, b57, b57 };
    e7 = stwo_qm31_mul(e11, e0);
    e0 = stwo_load_qm31(ext_params, 589u);
    e11 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(ext_params, 590u);
    e7 = StwoCudaQm31{ b35, b57, b57, b57 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e0, e7);
    e7 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 591u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 293u, row_index, 0);
    e11 = StwoCudaQm31{ b40, b57, b57, b57 };
    e0 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e7, e0);
    e0 = stwo_load_qm31(ext_params, 592u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    unsigned b85 = base_params[128u];
    unsigned b86 = stwo_m31_mul(b40, b85);
    unsigned b87 = stwo_m31_sub(b9, b86);
    e7 = StwoCudaQm31{ b87, b57, b57, b57 };
    e12 = stwo_qm31_mul(e0, e7);
    e7 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 593u);
    e11 = stwo_qm31_sub(e7, e12);
    e12 = stwo_load_qm31(ext_params, 594u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 294u, row_index, 0);
    unsigned b88 = base_params[145u];
    unsigned b89 = stwo_m31_mul(b41, b88);
    unsigned b90 = stwo_m31_sub(b10, b89);
    e7 = StwoCudaQm31{ b90, b57, b57, b57 };
    e0 = stwo_qm31_mul(e12, e7);
    e7 = stwo_load_qm31(ext_params, 595u);
    e12 = stwo_qm31_add(e7, e0);
    e7 = stwo_load_qm31(ext_params, 596u);
    e0 = StwoCudaQm31{ b41, b57, b57, b57 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e7, e0);
    e0 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 597u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 295u, row_index, 0);
    unsigned b91 = base_params[146u];
    unsigned b92 = stwo_m31_mul(b42, b91);
    unsigned b93 = stwo_m31_sub(b11, b92);
    e12 = StwoCudaQm31{ b93, b57, b57, b57 };
    e7 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e0, e7);
    e7 = stwo_load_qm31(ext_params, 598u);
    e0 = StwoCudaQm31{ b42, b57, b57, b57 };
    e13 = stwo_qm31_mul(e7, e0);
    e0 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 599u);
    e12 = stwo_qm31_sub(e0, e13);
    e13 = stwo_load_qm31(ext_params, 600u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 296u, row_index, 0);
    unsigned b94 = base_params[147u];
    unsigned b95 = stwo_m31_mul(b43, b94);
    unsigned b96 = stwo_m31_sub(b12, b95);
    e0 = StwoCudaQm31{ b96, b57, b57, b57 };
    e7 = stwo_qm31_mul(e13, e0);
    e0 = stwo_load_qm31(ext_params, 601u);
    e13 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(ext_params, 602u);
    e7 = StwoCudaQm31{ b43, b57, b57, b57 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e0, e7);
    e7 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(ext_params, 603u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 297u, row_index, 0);
    unsigned b97 = base_params[148u];
    unsigned b98 = stwo_m31_mul(b44, b97);
    unsigned b99 = stwo_m31_sub(b13, b98);
    e13 = StwoCudaQm31{ b99, b57, b57, b57 };
    e0 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e7, e0);
    e0 = stwo_load_qm31(ext_params, 604u);
    e7 = StwoCudaQm31{ b44, b57, b57, b57 };
    e14 = stwo_qm31_mul(e0, e7);
    e7 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(ext_params, 605u);
    e13 = stwo_qm31_sub(e7, e14);
    e14 = stwo_load_qm31(ext_params, 606u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 299u, row_index, 0);
    unsigned b103 = base_params[150u];
    unsigned b104 = stwo_m31_mul(b46, b103);
    unsigned b105 = stwo_m31_sub(b15, b104);
    e7 = StwoCudaQm31{ b105, b57, b57, b57 };
    e0 = stwo_qm31_mul(e14, e7);
    e7 = stwo_load_qm31(ext_params, 607u);
    e14 = stwo_qm31_add(e7, e0);
    e7 = stwo_load_qm31(ext_params, 608u);
    e0 = StwoCudaQm31{ b46, b57, b57, b57 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e7, e0);
    e0 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 609u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 300u, row_index, 0);
    unsigned b106 = base_params[151u];
    unsigned b107 = stwo_m31_mul(b47, b106);
    unsigned b108 = stwo_m31_sub(b16, b107);
    e14 = StwoCudaQm31{ b108, b57, b57, b57 };
    e7 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e0, e7);
    e7 = stwo_load_qm31(ext_params, 610u);
    e0 = StwoCudaQm31{ b47, b57, b57, b57 };
    e15 = stwo_qm31_mul(e7, e0);
    e0 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 611u);
    e14 = stwo_qm31_sub(e0, e15);
    e15 = stwo_load_qm31(ext_params, 612u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 301u, row_index, 0);
    unsigned b109 = base_params[152u];
    unsigned b110 = stwo_m31_mul(b48, b109);
    unsigned b111 = stwo_m31_sub(b17, b110);
    e0 = StwoCudaQm31{ b111, b57, b57, b57 };
    e7 = stwo_qm31_mul(e15, e0);
    e0 = stwo_load_qm31(ext_params, 613u);
    e15 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(ext_params, 614u);
    e7 = StwoCudaQm31{ b48, b57, b57, b57 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e0, e7);
    e7 = stwo_qm31_add(e15, e16);
    e16 = stwo_load_qm31(ext_params, 615u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 302u, row_index, 0);
    unsigned b112 = base_params[153u];
    unsigned b113 = stwo_m31_mul(b49, b112);
    unsigned b114 = stwo_m31_sub(b18, b113);
    e15 = StwoCudaQm31{ b114, b57, b57, b57 };
    e0 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e7, e0);
    e0 = stwo_load_qm31(ext_params, 616u);
    e7 = StwoCudaQm31{ b49, b57, b57, b57 };
    e16 = stwo_qm31_mul(e0, e7);
    e7 = stwo_qm31_add(e15, e16);
    e16 = stwo_load_qm31(ext_params, 617u);
    e15 = stwo_qm31_sub(e7, e16);
    e16 = stwo_load_qm31(ext_params, 618u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 298u, row_index, 0);
    unsigned b100 = base_params[149u];
    unsigned b101 = stwo_m31_mul(b45, b100);
    unsigned b102 = stwo_m31_sub(b14, b101);
    e7 = StwoCudaQm31{ b102, b57, b57, b57 };
    e0 = stwo_qm31_mul(e16, e7);
    e7 = stwo_load_qm31(ext_params, 619u);
    e16 = stwo_qm31_add(e7, e0);
    e7 = stwo_load_qm31(ext_params, 620u);
    e0 = StwoCudaQm31{ b45, b57, b57, b57 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e7, e0);
    e0 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 621u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 303u, row_index, 0);
    e16 = StwoCudaQm31{ b50, b57, b57, b57 };
    e7 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e0, e7);
    e7 = stwo_load_qm31(ext_params, 622u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    unsigned b115 = base_params[154u];
    unsigned b116 = stwo_m31_mul(b50, b115);
    unsigned b117 = stwo_m31_sub(b19, b116);
    e0 = StwoCudaQm31{ b117, b57, b57, b57 };
    e17 = stwo_qm31_mul(e7, e0);
    e0 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 623u);
    e16 = stwo_qm31_sub(e0, e17);
    e17 = stwo_load_qm31(ext_params, 624u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 110u, row_index, 0);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 304u, row_index, 0);
    unsigned b118 = base_params[171u];
    unsigned b119 = stwo_m31_mul(b51, b118);
    unsigned b120 = stwo_m31_sub(b20, b119);
    e0 = StwoCudaQm31{ b120, b57, b57, b57 };
    e7 = stwo_qm31_mul(e17, e0);
    e0 = stwo_load_qm31(ext_params, 625u);
    e17 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(ext_params, 626u);
    e7 = StwoCudaQm31{ b51, b57, b57, b57 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e0, e7);
    e7 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(ext_params, 627u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 111u, row_index, 0);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 305u, row_index, 0);
    unsigned b121 = base_params[172u];
    unsigned b122 = stwo_m31_mul(b52, b121);
    unsigned b123 = stwo_m31_sub(b21, b122);
    e17 = StwoCudaQm31{ b123, b57, b57, b57 };
    e0 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e7, e0);
    e0 = stwo_load_qm31(ext_params, 628u);
    e7 = StwoCudaQm31{ b52, b57, b57, b57 };
    e18 = stwo_qm31_mul(e0, e7);
    e7 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(ext_params, 629u);
    e17 = stwo_qm31_sub(e7, e18);
    e18 = stwo_load_qm31(ext_params, 630u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 114u, row_index, 0);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 306u, row_index, 0);
    unsigned b124 = base_params[173u];
    unsigned b125 = stwo_m31_mul(b53, b124);
    unsigned b126 = stwo_m31_sub(b22, b125);
    e7 = StwoCudaQm31{ b126, b57, b57, b57 };
    e0 = stwo_qm31_mul(e18, e7);
    e7 = stwo_load_qm31(ext_params, 631u);
    e18 = stwo_qm31_add(e7, e0);
    e7 = stwo_load_qm31(ext_params, 632u);
    e0 = StwoCudaQm31{ b53, b57, b57, b57 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e7, e0);
    e0 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(ext_params, 633u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 115u, row_index, 0);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 307u, row_index, 0);
    unsigned b127 = base_params[174u];
    unsigned b128 = stwo_m31_mul(b54, b127);
    unsigned b129 = stwo_m31_sub(b23, b128);
    e18 = StwoCudaQm31{ b129, b57, b57, b57 };
    e7 = stwo_qm31_mul(e19, e18);
    e18 = stwo_qm31_add(e0, e7);
    e7 = stwo_load_qm31(ext_params, 634u);
    e0 = StwoCudaQm31{ b54, b57, b57, b57 };
    e19 = stwo_qm31_mul(e7, e0);
    e0 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(ext_params, 635u);
    e18 = stwo_qm31_sub(e0, e19);
    e19 = stwo_load_qm31(ext_params, 636u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 122u, row_index, 0);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 309u, row_index, 0);
    unsigned b130 = base_params[176u];
    unsigned b131 = stwo_m31_mul(b55, b130);
    unsigned b132 = stwo_m31_sub(b24, b131);
    e0 = StwoCudaQm31{ b132, b57, b57, b57 };
    e7 = stwo_qm31_mul(e19, e0);
    e0 = stwo_load_qm31(ext_params, 637u);
    e19 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(ext_params, 638u);
    e7 = StwoCudaQm31{ b55, b57, b57, b57 };
    StwoCudaQm31 e20 = stwo_qm31_mul(e0, e7);
    e7 = stwo_qm31_add(e19, e20);
    e20 = stwo_load_qm31(ext_params, 639u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 123u, row_index, 0);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 310u, row_index, 0);
    unsigned b133 = base_params[177u];
    unsigned b134 = stwo_m31_mul(b56, b133);
    unsigned b135 = stwo_m31_sub(b25, b134);
    e19 = StwoCudaQm31{ b135, b57, b57, b57 };
    e0 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e7, e0);
    e0 = stwo_load_qm31(ext_params, 640u);
    e7 = StwoCudaQm31{ b56, b57, b57, b57 };
    e20 = stwo_qm31_mul(e0, e7);
    e7 = stwo_qm31_add(e19, e20);
    e20 = stwo_load_qm31(ext_params, 641u);
    e19 = stwo_qm31_sub(e7, e20);
    e20 = stwo_load_qm31(ext_params, 1070u);
    e7 = stwo_qm31_mul(e3, e20);
    e20 = stwo_load_qm31(ext_params, 1071u);
    e0 = stwo_qm31_mul(e2, e20);
    e20 = stwo_qm31_add(e7, e0);
    e0 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 1072u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 1073u);
    e7 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e7);
    e7 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 1074u);
    e4 = stwo_qm31_mul(e1, e5);
    e5 = stwo_load_qm31(ext_params, 1075u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(ext_params, 1076u);
    e6 = stwo_qm31_mul(e9, e1);
    e1 = stwo_load_qm31(ext_params, 1077u);
    e4 = stwo_qm31_mul(e8, e1);
    e1 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 1078u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(ext_params, 1079u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(ext_params, 1080u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(ext_params, 1081u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(ext_params, 1082u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(ext_params, 1083u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 1084u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(ext_params, 1085u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(ext_params, 1086u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(ext_params, 1087u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    unsigned b136 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 156u, row_index, 0);
    unsigned b137 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 157u, row_index, 0);
    unsigned b138 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 158u, row_index, 0);
    unsigned b139 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 159u, row_index, 0);
    e19 = StwoCudaQm31{ b136, b137, b138, b139 };
    unsigned b140 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 160u, row_index, 0);
    unsigned b141 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 161u, row_index, 0);
    unsigned b142 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 162u, row_index, 0);
    unsigned b143 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 163u, row_index, 0);
    e18 = StwoCudaQm31{ b140, b141, b142, b143 };
    e16 = stwo_qm31_sub(e18, e19);
    e19 = stwo_qm31_mul(e16, e0);
    e16 = stwo_qm31_sub(e19, e20);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b144 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 164u, row_index, 0);
    unsigned b145 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 165u, row_index, 0);
    unsigned b146 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 166u, row_index, 0);
    unsigned b147 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 167u, row_index, 0);
    e19 = StwoCudaQm31{ b144, b145, b146, b147 };
    e20 = stwo_qm31_sub(e19, e18);
    e18 = stwo_qm31_mul(e20, e7);
    e20 = stwo_qm31_sub(e18, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e20, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b148 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 168u, row_index, 0);
    unsigned b149 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 169u, row_index, 0);
    unsigned b150 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 170u, row_index, 0);
    unsigned b151 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 171u, row_index, 0);
    e18 = StwoCudaQm31{ b148, b149, b150, b151 };
    e3 = stwo_qm31_sub(e18, e19);
    e19 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e19, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b152 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 172u, row_index, 0);
    unsigned b153 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 173u, row_index, 0);
    unsigned b154 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 174u, row_index, 0);
    unsigned b155 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 175u, row_index, 0);
    e19 = StwoCudaQm31{ b152, b153, b154, b155 };
    e5 = stwo_qm31_sub(e19, e18);
    e18 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e18, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b156 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 176u, row_index, 0);
    unsigned b157 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 177u, row_index, 0);
    unsigned b158 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 178u, row_index, 0);
    unsigned b159 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 179u, row_index, 0);
    e18 = StwoCudaQm31{ b156, b157, b158, b159 };
    e1 = stwo_qm31_sub(e18, e19);
    e19 = stwo_qm31_mul(e1, e6);
    e1 = stwo_qm31_sub(e19, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b160 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 180u, row_index, 0);
    unsigned b161 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 181u, row_index, 0);
    unsigned b162 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 182u, row_index, 0);
    unsigned b163 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 183u, row_index, 0);
    e19 = StwoCudaQm31{ b160, b161, b162, b163 };
    e9 = stwo_qm31_sub(e19, e18);
    e18 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e18, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b164 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 184u, row_index, 0);
    unsigned b165 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 185u, row_index, 0);
    unsigned b166 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 186u, row_index, 0);
    unsigned b167 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 187u, row_index, 0);
    e18 = StwoCudaQm31{ b164, b165, b166, b167 };
    e11 = stwo_qm31_sub(e18, e19);
    e19 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e19, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b168 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 188u, row_index, 0);
    unsigned b169 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 189u, row_index, 0);
    unsigned b170 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 190u, row_index, 0);
    unsigned b171 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 191u, row_index, 0);
    e19 = StwoCudaQm31{ b168, b169, b170, b171 };
    e13 = stwo_qm31_sub(e19, e18);
    e18 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e18, e15);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b172 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 192u, row_index, 0);
    unsigned b173 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 193u, row_index, 0);
    unsigned b174 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 194u, row_index, 0);
    unsigned b175 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 195u, row_index, 0);
    e18 = StwoCudaQm31{ b172, b173, b174, b175 };
    e15 = stwo_qm31_sub(e18, e19);
    e18 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e18, e17);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
