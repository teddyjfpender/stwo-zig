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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_5cf9018a763488c8(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 642u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 126u, row_index, 0);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 311u, row_index, 0);
    unsigned b68 = base_params[178u];
    unsigned b69 = stwo_m31_mul(b33, b68);
    unsigned b70 = stwo_m31_sub(b1, b69);
    unsigned b64 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b70, b64, b64, b64 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 643u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 644u);
    e2 = StwoCudaQm31{ b33, b64, b64, b64 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 645u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 127u, row_index, 0);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 312u, row_index, 0);
    unsigned b71 = base_params[179u];
    unsigned b72 = stwo_m31_mul(b34, b71);
    unsigned b73 = stwo_m31_sub(b2, b72);
    e0 = StwoCudaQm31{ b73, b64, b64, b64 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 646u);
    e2 = StwoCudaQm31{ b34, b64, b64, b64 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 647u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 648u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 118u, row_index, 0);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 308u, row_index, 0);
    unsigned b65 = base_params[175u];
    unsigned b66 = stwo_m31_mul(b32, b65);
    unsigned b67 = stwo_m31_sub(b0, b66);
    e2 = StwoCudaQm31{ b67, b64, b64, b64 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 649u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 650u);
    e1 = StwoCudaQm31{ b32, b64, b64, b64 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 651u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 313u, row_index, 0);
    e3 = StwoCudaQm31{ b35, b64, b64, b64 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 652u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 130u, row_index, 0);
    unsigned b74 = base_params[180u];
    unsigned b75 = stwo_m31_mul(b35, b74);
    unsigned b76 = stwo_m31_sub(b3, b75);
    e1 = StwoCudaQm31{ b76, b64, b64, b64 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 653u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 654u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 134u, row_index, 0);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 314u, row_index, 0);
    unsigned b77 = base_params[197u];
    unsigned b78 = stwo_m31_mul(b36, b77);
    unsigned b79 = stwo_m31_sub(b4, b78);
    e1 = StwoCudaQm31{ b79, b64, b64, b64 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 655u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 656u);
    e2 = StwoCudaQm31{ b36, b64, b64, b64 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 657u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 135u, row_index, 0);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 315u, row_index, 0);
    unsigned b80 = base_params[198u];
    unsigned b81 = stwo_m31_mul(b37, b80);
    unsigned b82 = stwo_m31_sub(b5, b81);
    e4 = StwoCudaQm31{ b82, b64, b64, b64 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 658u);
    e2 = StwoCudaQm31{ b37, b64, b64, b64 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 659u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(ext_params, 660u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 138u, row_index, 0);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 316u, row_index, 0);
    unsigned b83 = base_params[199u];
    unsigned b84 = stwo_m31_mul(b38, b83);
    unsigned b85 = stwo_m31_sub(b6, b84);
    e2 = StwoCudaQm31{ b85, b64, b64, b64 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(ext_params, 661u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 662u);
    e1 = StwoCudaQm31{ b38, b64, b64, b64 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 663u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 139u, row_index, 0);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 317u, row_index, 0);
    unsigned b86 = base_params[200u];
    unsigned b87 = stwo_m31_mul(b39, b86);
    unsigned b88 = stwo_m31_sub(b7, b87);
    e5 = StwoCudaQm31{ b88, b64, b64, b64 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 664u);
    e1 = StwoCudaQm31{ b39, b64, b64, b64 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 665u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(ext_params, 666u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 146u, row_index, 0);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 319u, row_index, 0);
    unsigned b92 = base_params[202u];
    unsigned b93 = stwo_m31_mul(b41, b92);
    unsigned b94 = stwo_m31_sub(b9, b93);
    e1 = StwoCudaQm31{ b94, b64, b64, b64 };
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(ext_params, 667u);
    e6 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 668u);
    e2 = StwoCudaQm31{ b41, b64, b64, b64 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 669u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 147u, row_index, 0);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 320u, row_index, 0);
    unsigned b95 = base_params[203u];
    unsigned b96 = stwo_m31_mul(b42, b95);
    unsigned b97 = stwo_m31_sub(b10, b96);
    e6 = StwoCudaQm31{ b97, b64, b64, b64 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 670u);
    e2 = StwoCudaQm31{ b42, b64, b64, b64 };
    e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 671u);
    e6 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(ext_params, 672u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 150u, row_index, 0);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 321u, row_index, 0);
    unsigned b98 = base_params[204u];
    unsigned b99 = stwo_m31_mul(b43, b98);
    unsigned b100 = stwo_m31_sub(b11, b99);
    e2 = StwoCudaQm31{ b100, b64, b64, b64 };
    e1 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(ext_params, 673u);
    e7 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 674u);
    e1 = StwoCudaQm31{ b43, b64, b64, b64 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 675u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 151u, row_index, 0);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 322u, row_index, 0);
    unsigned b101 = base_params[205u];
    unsigned b102 = stwo_m31_mul(b44, b101);
    unsigned b103 = stwo_m31_sub(b12, b102);
    e7 = StwoCudaQm31{ b103, b64, b64, b64 };
    e2 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 676u);
    e1 = StwoCudaQm31{ b44, b64, b64, b64 };
    e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 677u);
    e7 = stwo_qm31_sub(e1, e8);
    e8 = stwo_load_qm31(ext_params, 678u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 142u, row_index, 0);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 318u, row_index, 0);
    unsigned b89 = base_params[201u];
    unsigned b90 = stwo_m31_mul(b40, b89);
    unsigned b91 = stwo_m31_sub(b8, b90);
    e1 = StwoCudaQm31{ b91, b64, b64, b64 };
    e2 = stwo_qm31_mul(e8, e1);
    e1 = stwo_load_qm31(ext_params, 679u);
    e8 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 680u);
    e2 = StwoCudaQm31{ b40, b64, b64, b64 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 681u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 323u, row_index, 0);
    e8 = StwoCudaQm31{ b45, b64, b64, b64 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 682u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 154u, row_index, 0);
    unsigned b104 = base_params[206u];
    unsigned b105 = stwo_m31_mul(b45, b104);
    unsigned b106 = stwo_m31_sub(b13, b105);
    e2 = StwoCudaQm31{ b106, b64, b64, b64 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 683u);
    e8 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(ext_params, 684u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 158u, row_index, 0);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 324u, row_index, 0);
    unsigned b107 = base_params[223u];
    unsigned b108 = stwo_m31_mul(b46, b107);
    unsigned b109 = stwo_m31_sub(b14, b108);
    e2 = StwoCudaQm31{ b109, b64, b64, b64 };
    e1 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(ext_params, 685u);
    e9 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 686u);
    e1 = StwoCudaQm31{ b46, b64, b64, b64 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 687u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 159u, row_index, 0);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 325u, row_index, 0);
    unsigned b110 = base_params[224u];
    unsigned b111 = stwo_m31_mul(b47, b110);
    unsigned b112 = stwo_m31_sub(b15, b111);
    e9 = StwoCudaQm31{ b112, b64, b64, b64 };
    e2 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 688u);
    e1 = StwoCudaQm31{ b47, b64, b64, b64 };
    e10 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 689u);
    e9 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(ext_params, 690u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 162u, row_index, 0);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 326u, row_index, 0);
    unsigned b113 = base_params[225u];
    unsigned b114 = stwo_m31_mul(b48, b113);
    unsigned b115 = stwo_m31_sub(b16, b114);
    e1 = StwoCudaQm31{ b115, b64, b64, b64 };
    e2 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(ext_params, 691u);
    e10 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 692u);
    e2 = StwoCudaQm31{ b48, b64, b64, b64 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 693u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 163u, row_index, 0);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 327u, row_index, 0);
    unsigned b116 = base_params[226u];
    unsigned b117 = stwo_m31_mul(b49, b116);
    unsigned b118 = stwo_m31_sub(b17, b117);
    e10 = StwoCudaQm31{ b118, b64, b64, b64 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 694u);
    e2 = StwoCudaQm31{ b49, b64, b64, b64 };
    e11 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 695u);
    e10 = stwo_qm31_sub(e2, e11);
    e11 = stwo_load_qm31(ext_params, 696u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 170u, row_index, 0);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 329u, row_index, 0);
    unsigned b122 = base_params[228u];
    unsigned b123 = stwo_m31_mul(b51, b122);
    unsigned b124 = stwo_m31_sub(b19, b123);
    e2 = StwoCudaQm31{ b124, b64, b64, b64 };
    e1 = stwo_qm31_mul(e11, e2);
    e2 = stwo_load_qm31(ext_params, 697u);
    e11 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 698u);
    e1 = StwoCudaQm31{ b51, b64, b64, b64 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 699u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 171u, row_index, 0);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 330u, row_index, 0);
    unsigned b125 = base_params[229u];
    unsigned b126 = stwo_m31_mul(b52, b125);
    unsigned b127 = stwo_m31_sub(b20, b126);
    e11 = StwoCudaQm31{ b127, b64, b64, b64 };
    e2 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 700u);
    e1 = StwoCudaQm31{ b52, b64, b64, b64 };
    e12 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 701u);
    e11 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(ext_params, 702u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 174u, row_index, 0);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 331u, row_index, 0);
    unsigned b128 = base_params[230u];
    unsigned b129 = stwo_m31_mul(b53, b128);
    unsigned b130 = stwo_m31_sub(b21, b129);
    e1 = StwoCudaQm31{ b130, b64, b64, b64 };
    e2 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(ext_params, 703u);
    e12 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 704u);
    e2 = StwoCudaQm31{ b53, b64, b64, b64 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 705u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 175u, row_index, 0);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 332u, row_index, 0);
    unsigned b131 = base_params[231u];
    unsigned b132 = stwo_m31_mul(b54, b131);
    unsigned b133 = stwo_m31_sub(b22, b132);
    e12 = StwoCudaQm31{ b133, b64, b64, b64 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 706u);
    e2 = StwoCudaQm31{ b54, b64, b64, b64 };
    e13 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 707u);
    e12 = stwo_qm31_sub(e2, e13);
    e13 = stwo_load_qm31(ext_params, 708u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 166u, row_index, 0);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 328u, row_index, 0);
    unsigned b119 = base_params[227u];
    unsigned b120 = stwo_m31_mul(b50, b119);
    unsigned b121 = stwo_m31_sub(b18, b120);
    e2 = StwoCudaQm31{ b121, b64, b64, b64 };
    e1 = stwo_qm31_mul(e13, e2);
    e2 = stwo_load_qm31(ext_params, 709u);
    e13 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 710u);
    e1 = StwoCudaQm31{ b50, b64, b64, b64 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(ext_params, 711u);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 333u, row_index, 0);
    e13 = StwoCudaQm31{ b55, b64, b64, b64 };
    e2 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 712u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 178u, row_index, 0);
    unsigned b134 = base_params[232u];
    unsigned b135 = stwo_m31_mul(b55, b134);
    unsigned b136 = stwo_m31_sub(b23, b135);
    e1 = StwoCudaQm31{ b136, b64, b64, b64 };
    e14 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(ext_params, 713u);
    e13 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(ext_params, 714u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 182u, row_index, 0);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 334u, row_index, 0);
    unsigned b137 = base_params[249u];
    unsigned b138 = stwo_m31_mul(b56, b137);
    unsigned b139 = stwo_m31_sub(b24, b138);
    e1 = StwoCudaQm31{ b139, b64, b64, b64 };
    e2 = stwo_qm31_mul(e14, e1);
    e1 = stwo_load_qm31(ext_params, 715u);
    e14 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 716u);
    e2 = StwoCudaQm31{ b56, b64, b64, b64 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 717u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 183u, row_index, 0);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 335u, row_index, 0);
    unsigned b140 = base_params[250u];
    unsigned b141 = stwo_m31_mul(b57, b140);
    unsigned b142 = stwo_m31_sub(b25, b141);
    e14 = StwoCudaQm31{ b142, b64, b64, b64 };
    e1 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 718u);
    e2 = StwoCudaQm31{ b57, b64, b64, b64 };
    e15 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 719u);
    e14 = stwo_qm31_sub(e2, e15);
    e15 = stwo_load_qm31(ext_params, 720u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 186u, row_index, 0);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 336u, row_index, 0);
    unsigned b143 = base_params[251u];
    unsigned b144 = stwo_m31_mul(b58, b143);
    unsigned b145 = stwo_m31_sub(b26, b144);
    e2 = StwoCudaQm31{ b145, b64, b64, b64 };
    e1 = stwo_qm31_mul(e15, e2);
    e2 = stwo_load_qm31(ext_params, 721u);
    e15 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 722u);
    e1 = StwoCudaQm31{ b58, b64, b64, b64 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e15, e16);
    e16 = stwo_load_qm31(ext_params, 723u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 187u, row_index, 0);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 337u, row_index, 0);
    unsigned b146 = base_params[252u];
    unsigned b147 = stwo_m31_mul(b59, b146);
    unsigned b148 = stwo_m31_sub(b27, b147);
    e15 = StwoCudaQm31{ b148, b64, b64, b64 };
    e2 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 724u);
    e1 = StwoCudaQm31{ b59, b64, b64, b64 };
    e16 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e15, e16);
    e16 = stwo_load_qm31(ext_params, 725u);
    e15 = stwo_qm31_sub(e1, e16);
    e16 = stwo_load_qm31(ext_params, 726u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 194u, row_index, 0);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 339u, row_index, 0);
    unsigned b149 = base_params[254u];
    unsigned b150 = stwo_m31_mul(b60, b149);
    unsigned b151 = stwo_m31_sub(b28, b150);
    e1 = StwoCudaQm31{ b151, b64, b64, b64 };
    e2 = stwo_qm31_mul(e16, e1);
    e1 = stwo_load_qm31(ext_params, 727u);
    e16 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 728u);
    e2 = StwoCudaQm31{ b60, b64, b64, b64 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 729u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 195u, row_index, 0);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 340u, row_index, 0);
    unsigned b152 = base_params[255u];
    unsigned b153 = stwo_m31_mul(b61, b152);
    unsigned b154 = stwo_m31_sub(b29, b153);
    e16 = StwoCudaQm31{ b154, b64, b64, b64 };
    e1 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 730u);
    e2 = StwoCudaQm31{ b61, b64, b64, b64 };
    e17 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 731u);
    e16 = stwo_qm31_sub(e2, e17);
    e17 = stwo_load_qm31(ext_params, 732u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 198u, row_index, 0);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 341u, row_index, 0);
    unsigned b155 = base_params[256u];
    unsigned b156 = stwo_m31_mul(b62, b155);
    unsigned b157 = stwo_m31_sub(b30, b156);
    e2 = StwoCudaQm31{ b157, b64, b64, b64 };
    e1 = stwo_qm31_mul(e17, e2);
    e2 = stwo_load_qm31(ext_params, 733u);
    e17 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 734u);
    e1 = StwoCudaQm31{ b62, b64, b64, b64 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(ext_params, 735u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 199u, row_index, 0);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 342u, row_index, 0);
    unsigned b158 = base_params[257u];
    unsigned b159 = stwo_m31_mul(b63, b158);
    unsigned b160 = stwo_m31_sub(b31, b159);
    e17 = StwoCudaQm31{ b160, b64, b64, b64 };
    e2 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 736u);
    e1 = StwoCudaQm31{ b63, b64, b64, b64 };
    e18 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(ext_params, 737u);
    e17 = stwo_qm31_sub(e1, e18);
    e18 = stwo_load_qm31(ext_params, 1088u);
    e1 = stwo_qm31_mul(e3, e18);
    e18 = stwo_load_qm31(ext_params, 1089u);
    e2 = stwo_qm31_mul(e0, e18);
    e18 = stwo_qm31_add(e1, e2);
    e2 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(ext_params, 1090u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 1091u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 1092u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 1093u);
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 1094u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(ext_params, 1095u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 1096u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(ext_params, 1097u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(ext_params, 1098u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(ext_params, 1099u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(ext_params, 1100u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(ext_params, 1101u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 1102u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(ext_params, 1103u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    unsigned b161 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 192u, row_index, 0);
    unsigned b162 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 193u, row_index, 0);
    unsigned b163 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 194u, row_index, 0);
    unsigned b164 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 195u, row_index, 0);
    e17 = StwoCudaQm31{ b161, b162, b163, b164 };
    unsigned b165 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 196u, row_index, 0);
    unsigned b166 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 197u, row_index, 0);
    unsigned b167 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 198u, row_index, 0);
    unsigned b168 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 199u, row_index, 0);
    e16 = StwoCudaQm31{ b165, b166, b167, b168 };
    e14 = stwo_qm31_sub(e16, e17);
    e17 = stwo_qm31_mul(e14, e2);
    e14 = stwo_qm31_sub(e17, e18);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b169 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 200u, row_index, 0);
    unsigned b170 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 201u, row_index, 0);
    unsigned b171 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 202u, row_index, 0);
    unsigned b172 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 203u, row_index, 0);
    e17 = StwoCudaQm31{ b169, b170, b171, b172 };
    e18 = stwo_qm31_sub(e17, e16);
    e16 = stwo_qm31_mul(e18, e1);
    e18 = stwo_qm31_sub(e16, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b173 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 204u, row_index, 0);
    unsigned b174 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 205u, row_index, 0);
    unsigned b175 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 206u, row_index, 0);
    unsigned b176 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 207u, row_index, 0);
    e16 = StwoCudaQm31{ b173, b174, b175, b176 };
    e3 = stwo_qm31_sub(e16, e17);
    e17 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e17, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b177 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 208u, row_index, 0);
    unsigned b178 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 209u, row_index, 0);
    unsigned b179 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 210u, row_index, 0);
    unsigned b180 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 211u, row_index, 0);
    e17 = StwoCudaQm31{ b177, b178, b179, b180 };
    e5 = stwo_qm31_sub(e17, e16);
    e16 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e16, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b181 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 212u, row_index, 0);
    unsigned b182 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 213u, row_index, 0);
    unsigned b183 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 214u, row_index, 0);
    unsigned b184 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 215u, row_index, 0);
    e16 = StwoCudaQm31{ b181, b182, b183, b184 };
    e7 = stwo_qm31_sub(e16, e17);
    e17 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e17, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b185 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 216u, row_index, 0);
    unsigned b186 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 217u, row_index, 0);
    unsigned b187 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 218u, row_index, 0);
    unsigned b188 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 219u, row_index, 0);
    e17 = StwoCudaQm31{ b185, b186, b187, b188 };
    e9 = stwo_qm31_sub(e17, e16);
    e16 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e16, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b189 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 220u, row_index, 0);
    unsigned b190 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 221u, row_index, 0);
    unsigned b191 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 222u, row_index, 0);
    unsigned b192 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 223u, row_index, 0);
    e16 = StwoCudaQm31{ b189, b190, b191, b192 };
    e11 = stwo_qm31_sub(e16, e17);
    e17 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e17, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b193 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 224u, row_index, 0);
    unsigned b194 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 225u, row_index, 0);
    unsigned b195 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 226u, row_index, 0);
    unsigned b196 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 227u, row_index, 0);
    e17 = StwoCudaQm31{ b193, b194, b195, b196 };
    e13 = stwo_qm31_sub(e17, e16);
    e17 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e17, e15);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
