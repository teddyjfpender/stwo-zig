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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_5245c8f6a4c00b3c(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 620u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 450u, row_index, 0);
    unsigned b38 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b0, b38, b38, b38 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 621u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 622u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 451u, row_index, 0);
    e2 = StwoCudaQm31{ b1, b38, b38, b38 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 623u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 624u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 452u, row_index, 0);
    e2 = StwoCudaQm31{ b2, b38, b38, b38 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 625u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 626u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 453u, row_index, 0);
    e1 = StwoCudaQm31{ b3, b38, b38, b38 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 627u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 628u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 455u, row_index, 0);
    e1 = StwoCudaQm31{ b4, b38, b38, b38 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 629u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 630u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 456u, row_index, 0);
    e2 = StwoCudaQm31{ b5, b38, b38, b38 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 631u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(ext_params, 632u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 457u, row_index, 0);
    e2 = StwoCudaQm31{ b6, b38, b38, b38 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(ext_params, 633u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 634u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 458u, row_index, 0);
    e1 = StwoCudaQm31{ b7, b38, b38, b38 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 635u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(ext_params, 636u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 459u, row_index, 0);
    e1 = StwoCudaQm31{ b8, b38, b38, b38 };
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(ext_params, 637u);
    e6 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 638u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 460u, row_index, 0);
    e2 = StwoCudaQm31{ b9, b38, b38, b38 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 639u);
    e6 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(ext_params, 640u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 461u, row_index, 0);
    e2 = StwoCudaQm31{ b10, b38, b38, b38 };
    e1 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(ext_params, 641u);
    e7 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 642u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 462u, row_index, 0);
    e1 = StwoCudaQm31{ b11, b38, b38, b38 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 643u);
    e7 = stwo_qm31_sub(e1, e8);
    e8 = stwo_load_qm31(ext_params, 644u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 463u, row_index, 0);
    e1 = StwoCudaQm31{ b12, b38, b38, b38 };
    e2 = stwo_qm31_mul(e8, e1);
    e1 = stwo_load_qm31(ext_params, 645u);
    e8 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 646u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 464u, row_index, 0);
    e2 = StwoCudaQm31{ b13, b38, b38, b38 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 647u);
    e8 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(ext_params, 648u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 465u, row_index, 0);
    e2 = StwoCudaQm31{ b14, b38, b38, b38 };
    e1 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(ext_params, 649u);
    e9 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 650u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 466u, row_index, 0);
    e1 = StwoCudaQm31{ b15, b38, b38, b38 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 651u);
    e9 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(ext_params, 652u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 467u, row_index, 0);
    e1 = StwoCudaQm31{ b16, b38, b38, b38 };
    e2 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(ext_params, 653u);
    e10 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 654u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 468u, row_index, 0);
    e2 = StwoCudaQm31{ b17, b38, b38, b38 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 655u);
    e10 = stwo_qm31_sub(e2, e11);
    e11 = stwo_load_qm31(ext_params, 656u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 469u, row_index, 0);
    e2 = StwoCudaQm31{ b18, b38, b38, b38 };
    e1 = stwo_qm31_mul(e11, e2);
    e2 = stwo_load_qm31(ext_params, 657u);
    e11 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 658u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 470u, row_index, 0);
    e1 = StwoCudaQm31{ b19, b38, b38, b38 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 659u);
    e11 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(ext_params, 660u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 471u, row_index, 0);
    e1 = StwoCudaQm31{ b20, b38, b38, b38 };
    e2 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(ext_params, 661u);
    e12 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 662u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 472u, row_index, 0);
    e2 = StwoCudaQm31{ b21, b38, b38, b38 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 663u);
    e12 = stwo_qm31_sub(e2, e13);
    e13 = stwo_load_qm31(ext_params, 664u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 473u, row_index, 0);
    e2 = StwoCudaQm31{ b22, b38, b38, b38 };
    e1 = stwo_qm31_mul(e13, e2);
    e2 = stwo_load_qm31(ext_params, 665u);
    e13 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 666u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 474u, row_index, 0);
    e1 = StwoCudaQm31{ b23, b38, b38, b38 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(ext_params, 667u);
    e13 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(ext_params, 668u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 475u, row_index, 0);
    e1 = StwoCudaQm31{ b24, b38, b38, b38 };
    e2 = stwo_qm31_mul(e14, e1);
    e1 = stwo_load_qm31(ext_params, 669u);
    e14 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 670u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 476u, row_index, 0);
    e2 = StwoCudaQm31{ b25, b38, b38, b38 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 671u);
    e14 = stwo_qm31_sub(e2, e15);
    e15 = stwo_load_qm31(ext_params, 672u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 477u, row_index, 0);
    e2 = StwoCudaQm31{ b26, b38, b38, b38 };
    e1 = stwo_qm31_mul(e15, e2);
    e2 = stwo_load_qm31(ext_params, 673u);
    e15 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 674u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 478u, row_index, 0);
    e1 = StwoCudaQm31{ b27, b38, b38, b38 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e15, e16);
    e16 = stwo_load_qm31(ext_params, 675u);
    e15 = stwo_qm31_sub(e1, e16);
    e16 = stwo_load_qm31(ext_params, 676u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 479u, row_index, 0);
    e1 = StwoCudaQm31{ b28, b38, b38, b38 };
    e2 = stwo_qm31_mul(e16, e1);
    e1 = stwo_load_qm31(ext_params, 677u);
    e16 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 678u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 480u, row_index, 0);
    e2 = StwoCudaQm31{ b29, b38, b38, b38 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 679u);
    e16 = stwo_qm31_sub(e2, e17);
    e17 = stwo_load_qm31(ext_params, 680u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 481u, row_index, 0);
    e2 = StwoCudaQm31{ b30, b38, b38, b38 };
    e1 = stwo_qm31_mul(e17, e2);
    e2 = stwo_load_qm31(ext_params, 681u);
    e17 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 682u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 482u, row_index, 0);
    e1 = StwoCudaQm31{ b31, b38, b38, b38 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(ext_params, 683u);
    e17 = stwo_qm31_sub(e1, e18);
    e18 = stwo_load_qm31(ext_params, 684u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 483u, row_index, 0);
    unsigned b39 = base_params[751u];
    unsigned b40 = stwo_m31_add(b32, b39);
    e1 = StwoCudaQm31{ b40, b38, b38, b38 };
    e2 = stwo_qm31_mul(e18, e1);
    e1 = stwo_load_qm31(ext_params, 685u);
    e18 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 686u);
    e2 = stwo_qm31_sub(e18, e1);
    e1 = stwo_load_qm31(ext_params, 687u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 484u, row_index, 0);
    unsigned b41 = base_params[753u];
    unsigned b42 = stwo_m31_add(b33, b41);
    e18 = StwoCudaQm31{ b42, b38, b38, b38 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e1, e18);
    e18 = stwo_load_qm31(ext_params, 688u);
    e1 = stwo_qm31_add(e18, e19);
    e18 = stwo_load_qm31(ext_params, 689u);
    e19 = stwo_qm31_sub(e1, e18);
    e18 = stwo_load_qm31(ext_params, 690u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 485u, row_index, 0);
    unsigned b43 = base_params[755u];
    unsigned b44 = stwo_m31_add(b34, b43);
    e1 = StwoCudaQm31{ b44, b38, b38, b38 };
    StwoCudaQm31 e20 = stwo_qm31_mul(e18, e1);
    e1 = stwo_load_qm31(ext_params, 691u);
    e18 = stwo_qm31_add(e1, e20);
    e1 = stwo_load_qm31(ext_params, 692u);
    e20 = stwo_qm31_sub(e18, e1);
    e1 = stwo_load_qm31(ext_params, 693u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 486u, row_index, 0);
    unsigned b45 = base_params[757u];
    unsigned b46 = stwo_m31_add(b35, b45);
    e18 = StwoCudaQm31{ b46, b38, b38, b38 };
    StwoCudaQm31 e21 = stwo_qm31_mul(e1, e18);
    e18 = stwo_load_qm31(ext_params, 694u);
    e1 = stwo_qm31_add(e18, e21);
    e18 = stwo_load_qm31(ext_params, 695u);
    e21 = stwo_qm31_sub(e1, e18);
    e18 = stwo_load_qm31(ext_params, 696u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 487u, row_index, 0);
    unsigned b47 = base_params[759u];
    unsigned b48 = stwo_m31_add(b36, b47);
    e1 = StwoCudaQm31{ b48, b38, b38, b38 };
    StwoCudaQm31 e22 = stwo_qm31_mul(e18, e1);
    e1 = stwo_load_qm31(ext_params, 697u);
    e18 = stwo_qm31_add(e1, e22);
    e1 = stwo_load_qm31(ext_params, 698u);
    e22 = stwo_qm31_sub(e18, e1);
    e1 = stwo_load_qm31(ext_params, 699u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 488u, row_index, 0);
    unsigned b49 = base_params[761u];
    unsigned b50 = stwo_m31_add(b37, b49);
    e18 = StwoCudaQm31{ b50, b38, b38, b38 };
    StwoCudaQm31 e23 = stwo_qm31_mul(e1, e18);
    e18 = stwo_load_qm31(ext_params, 700u);
    e1 = stwo_qm31_add(e18, e23);
    e18 = stwo_load_qm31(ext_params, 701u);
    e23 = stwo_qm31_sub(e1, e18);
    e18 = stwo_load_qm31(ext_params, 1486u);
    e1 = stwo_qm31_mul(e3, e18);
    e18 = stwo_load_qm31(ext_params, 1487u);
    StwoCudaQm31 e24 = stwo_qm31_mul(e0, e18);
    e18 = stwo_qm31_add(e1, e24);
    e24 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(ext_params, 1488u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 1489u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 1490u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 1491u);
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 1492u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(ext_params, 1493u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 1494u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(ext_params, 1495u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(ext_params, 1496u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(ext_params, 1497u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(ext_params, 1498u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(ext_params, 1499u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 1500u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(ext_params, 1501u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(ext_params, 1502u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(ext_params, 1503u);
    e14 = stwo_qm31_mul(e2, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e2, e19);
    e19 = stwo_load_qm31(ext_params, 1504u);
    e2 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(ext_params, 1505u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e2, e16);
    e16 = stwo_qm31_mul(e20, e21);
    e21 = stwo_load_qm31(ext_params, 1506u);
    e20 = stwo_qm31_mul(e23, e21);
    e21 = stwo_load_qm31(ext_params, 1507u);
    e2 = stwo_qm31_mul(e22, e21);
    e21 = stwo_qm31_add(e20, e2);
    e2 = stwo_qm31_mul(e22, e23);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 364u, row_index, 0);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 365u, row_index, 0);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 366u, row_index, 0);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 367u, row_index, 0);
    e23 = StwoCudaQm31{ b51, b52, b53, b54 };
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 368u, row_index, 0);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 369u, row_index, 0);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 370u, row_index, 0);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 371u, row_index, 0);
    e22 = StwoCudaQm31{ b55, b56, b57, b58 };
    e20 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e20, e24);
    e20 = stwo_qm31_sub(e23, e18);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e20, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 372u, row_index, 0);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 373u, row_index, 0);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 374u, row_index, 0);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 375u, row_index, 0);
    e23 = StwoCudaQm31{ b59, b60, b61, b62 };
    e18 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e18, e1);
    e18 = stwo_qm31_sub(e22, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 376u, row_index, 0);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 377u, row_index, 0);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 378u, row_index, 0);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 379u, row_index, 0);
    e22 = StwoCudaQm31{ b63, b64, b65, b66 };
    e3 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e23, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 380u, row_index, 0);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 381u, row_index, 0);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 382u, row_index, 0);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 383u, row_index, 0);
    e23 = StwoCudaQm31{ b67, b68, b69, b70 };
    e5 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e22, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 384u, row_index, 0);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 385u, row_index, 0);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 386u, row_index, 0);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 387u, row_index, 0);
    e22 = StwoCudaQm31{ b71, b72, b73, b74 };
    e7 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e23, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 388u, row_index, 0);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 389u, row_index, 0);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 390u, row_index, 0);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 391u, row_index, 0);
    e23 = StwoCudaQm31{ b75, b76, b77, b78 };
    e9 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e22, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 392u, row_index, 0);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 393u, row_index, 0);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 394u, row_index, 0);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 395u, row_index, 0);
    e22 = StwoCudaQm31{ b79, b80, b81, b82 };
    e11 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e23, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 396u, row_index, 0);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 397u, row_index, 0);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 398u, row_index, 0);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 399u, row_index, 0);
    e23 = StwoCudaQm31{ b83, b84, b85, b86 };
    e13 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e22, e15);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 400u, row_index, 0);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 401u, row_index, 0);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 402u, row_index, 0);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 403u, row_index, 0);
    e22 = StwoCudaQm31{ b87, b88, b89, b90 };
    e15 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e23, e17);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 404u, row_index, 0);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 405u, row_index, 0);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 406u, row_index, 0);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 407u, row_index, 0);
    e23 = StwoCudaQm31{ b91, b92, b93, b94 };
    e17 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e22, e19);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 408u, row_index, 0);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 409u, row_index, 0);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 410u, row_index, 0);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 411u, row_index, 0);
    e22 = StwoCudaQm31{ b95, b96, b97, b98 };
    e19 = stwo_qm31_sub(e22, e23);
    e22 = stwo_qm31_mul(e19, e2);
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
