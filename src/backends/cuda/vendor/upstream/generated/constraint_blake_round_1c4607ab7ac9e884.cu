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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_e984ae70d9a33a41(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 468u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 122u, row_index, 0);
    unsigned b55 = base_params[0u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b22, b55, b55, b55 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 469u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 470u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 117u, row_index, 0);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 119u, row_index, 0);
    unsigned b59 = base_params[46u];
    unsigned b60 = stwo_m31_mul(b19, b59);
    unsigned b61 = stwo_m31_sub(b17, b60);
    e2 = StwoCudaQm31{ b61, b55, b55, b55 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 471u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 118u, row_index, 0);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 120u, row_index, 0);
    unsigned b56 = base_params[45u];
    unsigned b57 = stwo_m31_mul(b20, b56);
    unsigned b58 = stwo_m31_sub(b18, b57);
    unsigned b62 = base_params[47u];
    unsigned b63 = stwo_m31_mul(b58, b62);
    unsigned b64 = stwo_m31_add(b19, b63);
    e0 = StwoCudaQm31{ b64, b55, b55, b55 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 472u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 121u, row_index, 0);
    unsigned b65 = base_params[48u];
    unsigned b66 = stwo_m31_mul(b21, b65);
    unsigned b67 = stwo_m31_sub(b20, b66);
    e2 = StwoCudaQm31{ b67, b55, b55, b55 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 473u);
    e0 = StwoCudaQm31{ b21, b55, b55, b55 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 474u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 475u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 476u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 477u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 478u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 479u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 480u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 481u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 482u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 483u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 484u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 485u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 486u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 487u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 488u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 489u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 490u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 491u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 492u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 493u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 494u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 495u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 496u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 497u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 498u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 499u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 125u, row_index, 0);
    e0 = StwoCudaQm31{ b25, b55, b55, b55 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 500u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 501u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 124u, row_index, 0);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 126u, row_index, 0);
    unsigned b69 = base_params[49u];
    unsigned b70 = stwo_m31_mul(b26, b69);
    unsigned b71 = stwo_m31_sub(b24, b70);
    e3 = StwoCudaQm31{ b71, b55, b55, b55 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 502u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 127u, row_index, 0);
    e1 = StwoCudaQm31{ b27, b55, b55, b55 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 503u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 504u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    unsigned b68 = stwo_m31_add(b8, b9);
    e1 = StwoCudaQm31{ b68, b55, b55, b55 };
    e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 505u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(ext_params, 506u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 128u, row_index, 0);
    e4 = StwoCudaQm31{ b28, b55, b55, b55 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 507u);
    e0 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(ext_params, 508u);
    e4 = StwoCudaQm31{ b28, b55, b55, b55 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(ext_params, 509u);
    e5 = stwo_qm31_add(e4, e1);
    e4 = stwo_load_qm31(ext_params, 510u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 123u, row_index, 0);
    unsigned b72 = base_params[50u];
    unsigned b73 = stwo_m31_mul(b25, b72);
    unsigned b74 = stwo_m31_sub(b23, b73);
    e1 = StwoCudaQm31{ b74, b55, b55, b55 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 511u);
    unsigned b75 = base_params[51u];
    unsigned b76 = stwo_m31_mul(b71, b75);
    unsigned b77 = stwo_m31_add(b25, b76);
    e5 = StwoCudaQm31{ b77, b55, b55, b55 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 512u);
    unsigned b78 = base_params[52u];
    unsigned b79 = stwo_m31_mul(b27, b78);
    unsigned b80 = stwo_m31_sub(b26, b79);
    e1 = StwoCudaQm31{ b80, b55, b55, b55 };
    e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 513u);
    e5 = StwoCudaQm31{ b27, b55, b55, b55 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 514u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 515u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 516u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 517u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 518u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 519u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 520u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 521u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 522u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 523u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 524u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 525u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 526u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 527u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 528u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 529u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 530u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 531u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 532u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 533u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 534u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 535u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 536u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 537u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 538u);
    e1 = stwo_qm31_sub(e5, e4);
    e4 = stwo_load_qm31(ext_params, 539u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 131u, row_index, 0);
    e5 = StwoCudaQm31{ b31, b55, b55, b55 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 540u);
    e4 = stwo_qm31_add(e5, e6);
    e5 = stwo_load_qm31(ext_params, 541u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 130u, row_index, 0);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 132u, row_index, 0);
    unsigned b82 = base_params[53u];
    unsigned b83 = stwo_m31_mul(b32, b82);
    unsigned b84 = stwo_m31_sub(b30, b83);
    e6 = StwoCudaQm31{ b84, b55, b55, b55 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 542u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 133u, row_index, 0);
    e4 = StwoCudaQm31{ b33, b55, b55, b55 };
    e5 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(ext_params, 543u);
    e6 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(ext_params, 544u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    unsigned b81 = stwo_m31_add(b8, b10);
    e4 = StwoCudaQm31{ b81, b55, b55, b55 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(ext_params, 545u);
    e5 = stwo_qm31_add(e4, e7);
    e4 = stwo_load_qm31(ext_params, 546u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 134u, row_index, 0);
    e7 = StwoCudaQm31{ b34, b55, b55, b55 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e4, e7);
    e7 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(ext_params, 547u);
    e5 = stwo_qm31_sub(e7, e8);
    e8 = stwo_load_qm31(ext_params, 548u);
    e7 = StwoCudaQm31{ b34, b55, b55, b55 };
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_load_qm31(ext_params, 549u);
    e8 = stwo_qm31_add(e7, e4);
    e7 = stwo_load_qm31(ext_params, 550u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 129u, row_index, 0);
    unsigned b85 = base_params[54u];
    unsigned b86 = stwo_m31_mul(b31, b85);
    unsigned b87 = stwo_m31_sub(b29, b86);
    e4 = StwoCudaQm31{ b87, b55, b55, b55 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 551u);
    unsigned b88 = base_params[55u];
    unsigned b89 = stwo_m31_mul(b84, b88);
    unsigned b90 = stwo_m31_add(b31, b89);
    e8 = StwoCudaQm31{ b90, b55, b55, b55 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 552u);
    unsigned b91 = base_params[56u];
    unsigned b92 = stwo_m31_mul(b33, b91);
    unsigned b93 = stwo_m31_sub(b32, b92);
    e4 = StwoCudaQm31{ b93, b55, b55, b55 };
    e9 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 553u);
    e8 = StwoCudaQm31{ b33, b55, b55, b55 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 554u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 555u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 556u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 557u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 558u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 559u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 560u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 561u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 562u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 563u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 564u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 565u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 566u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 567u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 568u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 569u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 570u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 571u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 572u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 573u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 574u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 575u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 576u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 577u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 578u);
    e4 = stwo_qm31_sub(e8, e7);
    e7 = stwo_load_qm31(ext_params, 579u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 137u, row_index, 0);
    e8 = StwoCudaQm31{ b37, b55, b55, b55 };
    e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_load_qm31(ext_params, 580u);
    e7 = stwo_qm31_add(e8, e9);
    e8 = stwo_load_qm31(ext_params, 581u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 136u, row_index, 0);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 138u, row_index, 0);
    unsigned b95 = base_params[57u];
    unsigned b96 = stwo_m31_mul(b38, b95);
    unsigned b97 = stwo_m31_sub(b36, b96);
    e9 = StwoCudaQm31{ b97, b55, b55, b55 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 582u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 139u, row_index, 0);
    e7 = StwoCudaQm31{ b39, b55, b55, b55 };
    e8 = stwo_qm31_mul(e10, e7);
    e7 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(ext_params, 583u);
    e9 = stwo_qm31_sub(e7, e8);
    e8 = stwo_load_qm31(ext_params, 584u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    unsigned b94 = stwo_m31_add(b8, b11);
    e7 = StwoCudaQm31{ b94, b55, b55, b55 };
    e10 = stwo_qm31_mul(e8, e7);
    e7 = stwo_load_qm31(ext_params, 585u);
    e8 = stwo_qm31_add(e7, e10);
    e7 = stwo_load_qm31(ext_params, 586u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 140u, row_index, 0);
    e10 = StwoCudaQm31{ b40, b55, b55, b55 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e7, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 587u);
    e8 = stwo_qm31_sub(e10, e11);
    e11 = stwo_load_qm31(ext_params, 588u);
    e10 = StwoCudaQm31{ b40, b55, b55, b55 };
    e7 = stwo_qm31_mul(e11, e10);
    e10 = stwo_load_qm31(ext_params, 589u);
    e11 = stwo_qm31_add(e10, e7);
    e10 = stwo_load_qm31(ext_params, 590u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 135u, row_index, 0);
    unsigned b98 = base_params[58u];
    unsigned b99 = stwo_m31_mul(b37, b98);
    unsigned b100 = stwo_m31_sub(b35, b99);
    e7 = StwoCudaQm31{ b100, b55, b55, b55 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e10, e7);
    e7 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 591u);
    unsigned b101 = base_params[59u];
    unsigned b102 = stwo_m31_mul(b97, b101);
    unsigned b103 = stwo_m31_add(b37, b102);
    e11 = StwoCudaQm31{ b103, b55, b55, b55 };
    e10 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 592u);
    unsigned b104 = base_params[60u];
    unsigned b105 = stwo_m31_mul(b39, b104);
    unsigned b106 = stwo_m31_sub(b38, b105);
    e7 = StwoCudaQm31{ b106, b55, b55, b55 };
    e12 = stwo_qm31_mul(e10, e7);
    e7 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 593u);
    e11 = StwoCudaQm31{ b39, b55, b55, b55 };
    e10 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 594u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 595u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 596u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 597u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 598u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 599u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 600u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 601u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 602u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 603u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 604u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 605u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 606u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 607u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 608u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 609u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 610u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 611u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 612u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 613u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 614u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 615u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 616u);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 617u);
    e11 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 618u);
    e7 = stwo_qm31_sub(e11, e10);
    e10 = stwo_load_qm31(ext_params, 619u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 143u, row_index, 0);
    e11 = StwoCudaQm31{ b43, b55, b55, b55 };
    e12 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(ext_params, 620u);
    e10 = stwo_qm31_add(e11, e12);
    e11 = stwo_load_qm31(ext_params, 621u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 142u, row_index, 0);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 144u, row_index, 0);
    unsigned b108 = base_params[61u];
    unsigned b109 = stwo_m31_mul(b44, b108);
    unsigned b110 = stwo_m31_sub(b42, b109);
    e12 = StwoCudaQm31{ b110, b55, b55, b55 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e11, e12);
    e12 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 622u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 145u, row_index, 0);
    e10 = StwoCudaQm31{ b45, b55, b55, b55 };
    e11 = stwo_qm31_mul(e13, e10);
    e10 = stwo_qm31_add(e12, e11);
    e11 = stwo_load_qm31(ext_params, 623u);
    e12 = stwo_qm31_sub(e10, e11);
    e11 = stwo_load_qm31(ext_params, 624u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    unsigned b107 = stwo_m31_add(b8, b12);
    e10 = StwoCudaQm31{ b107, b55, b55, b55 };
    e13 = stwo_qm31_mul(e11, e10);
    e10 = stwo_load_qm31(ext_params, 625u);
    e11 = stwo_qm31_add(e10, e13);
    e10 = stwo_load_qm31(ext_params, 626u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 146u, row_index, 0);
    e13 = StwoCudaQm31{ b46, b55, b55, b55 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e10, e13);
    e13 = stwo_qm31_add(e11, e14);
    e14 = stwo_load_qm31(ext_params, 627u);
    e11 = stwo_qm31_sub(e13, e14);
    e14 = stwo_load_qm31(ext_params, 628u);
    e13 = StwoCudaQm31{ b46, b55, b55, b55 };
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_load_qm31(ext_params, 629u);
    e14 = stwo_qm31_add(e13, e10);
    e13 = stwo_load_qm31(ext_params, 630u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 141u, row_index, 0);
    unsigned b111 = base_params[62u];
    unsigned b112 = stwo_m31_mul(b43, b111);
    unsigned b113 = stwo_m31_sub(b41, b112);
    e10 = StwoCudaQm31{ b113, b55, b55, b55 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e13, e10);
    e10 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 631u);
    unsigned b114 = base_params[63u];
    unsigned b115 = stwo_m31_mul(b110, b114);
    unsigned b116 = stwo_m31_add(b43, b115);
    e14 = StwoCudaQm31{ b116, b55, b55, b55 };
    e13 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 632u);
    unsigned b117 = base_params[64u];
    unsigned b118 = stwo_m31_mul(b45, b117);
    unsigned b119 = stwo_m31_sub(b44, b118);
    e10 = StwoCudaQm31{ b119, b55, b55, b55 };
    e15 = stwo_qm31_mul(e13, e10);
    e10 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 633u);
    e14 = StwoCudaQm31{ b45, b55, b55, b55 };
    e13 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 634u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 635u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 636u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 637u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 638u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 639u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 640u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 641u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 642u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 643u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 644u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 645u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 646u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 647u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 648u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 649u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 650u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 651u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 652u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 653u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 654u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 655u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 656u);
    e10 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 657u);
    e14 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 658u);
    e10 = stwo_qm31_sub(e14, e13);
    e13 = stwo_load_qm31(ext_params, 659u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    e14 = StwoCudaQm31{ b0, b55, b55, b55 };
    e15 = stwo_qm31_mul(e13, e14);
    e14 = stwo_load_qm31(ext_params, 660u);
    e13 = stwo_qm31_add(e14, e15);
    e14 = stwo_load_qm31(ext_params, 661u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e15 = StwoCudaQm31{ b1, b55, b55, b55 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 662u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    e13 = StwoCudaQm31{ b2, b55, b55, b55 };
    e14 = stwo_qm31_mul(e16, e13);
    e13 = stwo_qm31_add(e15, e14);
    e14 = stwo_load_qm31(ext_params, 663u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    e15 = StwoCudaQm31{ b3, b55, b55, b55 };
    e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 664u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    e13 = StwoCudaQm31{ b4, b55, b55, b55 };
    e14 = stwo_qm31_mul(e16, e13);
    e13 = stwo_qm31_add(e15, e14);
    e14 = stwo_load_qm31(ext_params, 665u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    e15 = StwoCudaQm31{ b5, b55, b55, b55 };
    e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 666u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    e13 = StwoCudaQm31{ b6, b55, b55, b55 };
    e14 = stwo_qm31_mul(e16, e13);
    e13 = stwo_qm31_add(e15, e14);
    e14 = stwo_load_qm31(ext_params, 667u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    e15 = StwoCudaQm31{ b7, b55, b55, b55 };
    e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 668u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    e13 = StwoCudaQm31{ b13, b55, b55, b55 };
    e14 = stwo_qm31_mul(e16, e13);
    e13 = stwo_qm31_add(e15, e14);
    e14 = stwo_load_qm31(ext_params, 669u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    e15 = StwoCudaQm31{ b14, b55, b55, b55 };
    e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 670u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    e13 = StwoCudaQm31{ b15, b55, b55, b55 };
    e14 = stwo_qm31_mul(e16, e13);
    e13 = stwo_qm31_add(e15, e14);
    e14 = stwo_load_qm31(ext_params, 671u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    e15 = StwoCudaQm31{ b16, b55, b55, b55 };
    e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 672u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 147u, row_index, 0);
    e13 = StwoCudaQm31{ b47, b55, b55, b55 };
    e14 = stwo_qm31_mul(e16, e13);
    e13 = stwo_qm31_add(e15, e14);
    e14 = stwo_load_qm31(ext_params, 673u);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 148u, row_index, 0);
    e15 = StwoCudaQm31{ b48, b55, b55, b55 };
    e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 674u);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 149u, row_index, 0);
    e13 = StwoCudaQm31{ b49, b55, b55, b55 };
    e14 = stwo_qm31_mul(e16, e13);
    e13 = stwo_qm31_add(e15, e14);
    e14 = stwo_load_qm31(ext_params, 675u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 150u, row_index, 0);
    e15 = StwoCudaQm31{ b50, b55, b55, b55 };
    e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 676u);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 151u, row_index, 0);
    e13 = StwoCudaQm31{ b51, b55, b55, b55 };
    e14 = stwo_qm31_mul(e16, e13);
    e13 = stwo_qm31_add(e15, e14);
    e14 = stwo_load_qm31(ext_params, 677u);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 152u, row_index, 0);
    e15 = StwoCudaQm31{ b52, b55, b55, b55 };
    e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 678u);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 153u, row_index, 0);
    e13 = StwoCudaQm31{ b53, b55, b55, b55 };
    e14 = stwo_qm31_mul(e16, e13);
    e13 = stwo_qm31_add(e15, e14);
    e14 = stwo_load_qm31(ext_params, 679u);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 154u, row_index, 0);
    e15 = StwoCudaQm31{ b54, b55, b55, b55 };
    e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 680u);
    e13 = stwo_qm31_sub(e15, e16);
    e16 = stwo_load_qm31(ext_params, 945u);
    e15 = stwo_qm31_mul(e3, e16);
    e16 = stwo_load_qm31(ext_params, 946u);
    e14 = stwo_qm31_mul(e2, e16);
    e16 = stwo_qm31_add(e15, e14);
    e14 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 947u);
    e2 = stwo_qm31_mul(e1, e3);
    e3 = stwo_load_qm31(ext_params, 948u);
    e15 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e2, e15);
    e15 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 949u);
    e0 = stwo_qm31_mul(e5, e1);
    e1 = stwo_load_qm31(ext_params, 950u);
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_qm31_add(e0, e2);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_load_qm31(ext_params, 951u);
    e6 = stwo_qm31_mul(e9, e5);
    e5 = stwo_load_qm31(ext_params, 952u);
    e0 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e6, e0);
    e0 = stwo_qm31_mul(e4, e9);
    e9 = stwo_load_qm31(ext_params, 953u);
    e4 = stwo_qm31_mul(e7, e9);
    e9 = stwo_load_qm31(ext_params, 954u);
    e6 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e4, e6);
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_load_qm31(ext_params, 955u);
    e8 = stwo_qm31_mul(e11, e7);
    e7 = stwo_load_qm31(ext_params, 956u);
    e4 = stwo_qm31_mul(e12, e7);
    e7 = stwo_qm31_add(e8, e4);
    e4 = stwo_qm31_mul(e12, e11);
    e11 = stwo_load_qm31(ext_params, 957u);
    e12 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(ext_params, 958u);
    e8 = stwo_qm31_mul(e10, e11);
    e11 = stwo_qm31_add(e12, e8);
    e8 = stwo_qm31_mul(e10, e13);
    unsigned b120 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 68u, row_index, 0);
    unsigned b121 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 69u, row_index, 0);
    unsigned b122 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 70u, row_index, 0);
    unsigned b123 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 71u, row_index, 0);
    e13 = StwoCudaQm31{ b120, b121, b122, b123 };
    unsigned b124 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 72u, row_index, 0);
    unsigned b125 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 73u, row_index, 0);
    unsigned b126 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 74u, row_index, 0);
    unsigned b127 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 75u, row_index, 0);
    e10 = StwoCudaQm31{ b124, b125, b126, b127 };
    e12 = stwo_qm31_sub(e10, e13);
    e13 = stwo_qm31_mul(e12, e14);
    e12 = stwo_qm31_sub(e13, e16);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b128 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 76u, row_index, 0);
    unsigned b129 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 77u, row_index, 0);
    unsigned b130 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 78u, row_index, 0);
    unsigned b131 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 79u, row_index, 0);
    e13 = StwoCudaQm31{ b128, b129, b130, b131 };
    e16 = stwo_qm31_sub(e13, e10);
    e10 = stwo_qm31_mul(e16, e15);
    e16 = stwo_qm31_sub(e10, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b132 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 80u, row_index, 0);
    unsigned b133 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 81u, row_index, 0);
    unsigned b134 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 82u, row_index, 0);
    unsigned b135 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 83u, row_index, 0);
    e10 = StwoCudaQm31{ b132, b133, b134, b135 };
    e3 = stwo_qm31_sub(e10, e13);
    e13 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e13, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b136 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 84u, row_index, 0);
    unsigned b137 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 85u, row_index, 0);
    unsigned b138 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 86u, row_index, 0);
    unsigned b139 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 87u, row_index, 0);
    e13 = StwoCudaQm31{ b136, b137, b138, b139 };
    e1 = stwo_qm31_sub(e13, e10);
    e10 = stwo_qm31_mul(e1, e0);
    e1 = stwo_qm31_sub(e10, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b140 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 88u, row_index, 0);
    unsigned b141 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 89u, row_index, 0);
    unsigned b142 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 90u, row_index, 0);
    unsigned b143 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 91u, row_index, 0);
    e10 = StwoCudaQm31{ b140, b141, b142, b143 };
    e5 = stwo_qm31_sub(e10, e13);
    e13 = stwo_qm31_mul(e5, e6);
    e5 = stwo_qm31_sub(e13, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b144 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 92u, row_index, 0);
    unsigned b145 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 93u, row_index, 0);
    unsigned b146 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 94u, row_index, 0);
    unsigned b147 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 95u, row_index, 0);
    e13 = StwoCudaQm31{ b144, b145, b146, b147 };
    e9 = stwo_qm31_sub(e13, e10);
    e10 = stwo_qm31_mul(e9, e4);
    e9 = stwo_qm31_sub(e10, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b148 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 96u, row_index, 0);
    unsigned b149 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 97u, row_index, 0);
    unsigned b150 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 98u, row_index, 0);
    unsigned b151 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 99u, row_index, 0);
    e10 = StwoCudaQm31{ b148, b149, b150, b151 };
    e7 = stwo_qm31_sub(e10, e13);
    e10 = stwo_qm31_mul(e7, e8);
    e7 = stwo_qm31_sub(e10, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
