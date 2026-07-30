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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_e3f4092008e7152d(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 318u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 134u, row_index, 0);
    unsigned b46 = base_params[297u];
    unsigned b47 = stwo_m31_add(b38, b46);
    unsigned b45 = base_params[18u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b47, b45, b45, b45 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 319u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 320u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 321u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 135u, row_index, 0);
    unsigned b48 = base_params[299u];
    unsigned b49 = stwo_m31_add(b39, b48);
    e0 = StwoCudaQm31{ b49, b45, b45, b45 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 322u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 323u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 324u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 136u, row_index, 0);
    unsigned b50 = base_params[301u];
    unsigned b51 = stwo_m31_add(b40, b50);
    e1 = StwoCudaQm31{ b51, b45, b45, b45 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 325u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(ext_params, 326u);
    e4 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 327u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 137u, row_index, 0);
    unsigned b52 = base_params[303u];
    unsigned b53 = stwo_m31_add(b41, b52);
    e0 = StwoCudaQm31{ b53, b45, b45, b45 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 328u);
    e1 = stwo_qm31_add(e0, e5);
    e0 = stwo_load_qm31(ext_params, 329u);
    e5 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 330u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 138u, row_index, 0);
    unsigned b54 = base_params[305u];
    unsigned b55 = stwo_m31_add(b42, b54);
    e1 = StwoCudaQm31{ b55, b45, b45, b45 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 331u);
    e0 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(ext_params, 332u);
    e6 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 333u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 139u, row_index, 0);
    unsigned b56 = base_params[307u];
    unsigned b57 = stwo_m31_add(b43, b56);
    e0 = StwoCudaQm31{ b57, b45, b45, b45 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 334u);
    e1 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(ext_params, 335u);
    e7 = stwo_qm31_sub(e1, e0);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 140u, row_index, 0);
    e0 = StwoCudaQm31{ b44, b45, b45, b45 };
    e1 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e0);
    e0 = stwo_load_qm31(ext_params, 336u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    StwoCudaQm31 e8 = StwoCudaQm31{ b0, b45, b45, b45 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e0, e8);
    e8 = stwo_load_qm31(ext_params, 337u);
    e0 = stwo_qm31_add(e8, e9);
    e8 = stwo_load_qm31(ext_params, 338u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e9 = StwoCudaQm31{ b1, b45, b45, b45 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e0, e10);
    e10 = stwo_load_qm31(ext_params, 339u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    e0 = StwoCudaQm31{ b2, b45, b45, b45 };
    e8 = stwo_qm31_mul(e10, e0);
    e0 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(ext_params, 340u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e9 = StwoCudaQm31{ b3, b45, b45, b45 };
    e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e0, e10);
    e10 = stwo_load_qm31(ext_params, 341u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e0 = StwoCudaQm31{ b4, b45, b45, b45 };
    e8 = stwo_qm31_mul(e10, e0);
    e0 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(ext_params, 342u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e9 = StwoCudaQm31{ b5, b45, b45, b45 };
    e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e0, e10);
    e10 = stwo_load_qm31(ext_params, 343u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    e0 = StwoCudaQm31{ b6, b45, b45, b45 };
    e8 = stwo_qm31_mul(e10, e0);
    e0 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(ext_params, 344u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    e9 = StwoCudaQm31{ b7, b45, b45, b45 };
    e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e0, e10);
    e10 = stwo_load_qm31(ext_params, 345u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    e0 = StwoCudaQm31{ b8, b45, b45, b45 };
    e8 = stwo_qm31_mul(e10, e0);
    e0 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(ext_params, 346u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    e9 = StwoCudaQm31{ b9, b45, b45, b45 };
    e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e0, e10);
    e10 = stwo_load_qm31(ext_params, 347u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 84u, row_index, 0);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 85u, row_index, 0);
    unsigned b58 = base_params[309u];
    unsigned b59 = stwo_m31_mul(b11, b58);
    unsigned b60 = stwo_m31_add(b10, b59);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 86u, row_index, 0);
    unsigned b61 = base_params[310u];
    unsigned b62 = stwo_m31_mul(b12, b61);
    unsigned b63 = stwo_m31_add(b60, b62);
    e0 = StwoCudaQm31{ b63, b45, b45, b45 };
    e8 = stwo_qm31_mul(e10, e0);
    e0 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(ext_params, 348u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 87u, row_index, 0);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 88u, row_index, 0);
    unsigned b64 = base_params[311u];
    unsigned b65 = stwo_m31_mul(b14, b64);
    unsigned b66 = stwo_m31_add(b13, b65);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 89u, row_index, 0);
    unsigned b67 = base_params[312u];
    unsigned b68 = stwo_m31_mul(b15, b67);
    unsigned b69 = stwo_m31_add(b66, b68);
    e9 = StwoCudaQm31{ b69, b45, b45, b45 };
    e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e0, e10);
    e10 = stwo_load_qm31(ext_params, 349u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 90u, row_index, 0);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 91u, row_index, 0);
    unsigned b70 = base_params[313u];
    unsigned b71 = stwo_m31_mul(b17, b70);
    unsigned b72 = stwo_m31_add(b16, b71);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 92u, row_index, 0);
    unsigned b73 = base_params[314u];
    unsigned b74 = stwo_m31_mul(b18, b73);
    unsigned b75 = stwo_m31_add(b72, b74);
    e0 = StwoCudaQm31{ b75, b45, b45, b45 };
    e8 = stwo_qm31_mul(e10, e0);
    e0 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(ext_params, 350u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 93u, row_index, 0);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 94u, row_index, 0);
    unsigned b76 = base_params[315u];
    unsigned b77 = stwo_m31_mul(b20, b76);
    unsigned b78 = stwo_m31_add(b19, b77);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 95u, row_index, 0);
    unsigned b79 = base_params[316u];
    unsigned b80 = stwo_m31_mul(b21, b79);
    unsigned b81 = stwo_m31_add(b78, b80);
    e9 = StwoCudaQm31{ b81, b45, b45, b45 };
    e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e0, e10);
    e10 = stwo_load_qm31(ext_params, 351u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 96u, row_index, 0);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 97u, row_index, 0);
    unsigned b82 = base_params[317u];
    unsigned b83 = stwo_m31_mul(b23, b82);
    unsigned b84 = stwo_m31_add(b22, b83);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 98u, row_index, 0);
    unsigned b85 = base_params[318u];
    unsigned b86 = stwo_m31_mul(b24, b85);
    unsigned b87 = stwo_m31_add(b84, b86);
    e0 = StwoCudaQm31{ b87, b45, b45, b45 };
    e8 = stwo_qm31_mul(e10, e0);
    e0 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(ext_params, 352u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 99u, row_index, 0);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 100u, row_index, 0);
    unsigned b88 = base_params[319u];
    unsigned b89 = stwo_m31_mul(b26, b88);
    unsigned b90 = stwo_m31_add(b25, b89);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 101u, row_index, 0);
    unsigned b91 = base_params[320u];
    unsigned b92 = stwo_m31_mul(b27, b91);
    unsigned b93 = stwo_m31_add(b90, b92);
    e9 = StwoCudaQm31{ b93, b45, b45, b45 };
    e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e0, e10);
    e10 = stwo_load_qm31(ext_params, 353u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 102u, row_index, 0);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 103u, row_index, 0);
    unsigned b94 = base_params[321u];
    unsigned b95 = stwo_m31_mul(b29, b94);
    unsigned b96 = stwo_m31_add(b28, b95);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 104u, row_index, 0);
    unsigned b97 = base_params[322u];
    unsigned b98 = stwo_m31_mul(b30, b97);
    unsigned b99 = stwo_m31_add(b96, b98);
    e0 = StwoCudaQm31{ b99, b45, b45, b45 };
    e8 = stwo_qm31_mul(e10, e0);
    e0 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(ext_params, 354u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 105u, row_index, 0);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 106u, row_index, 0);
    unsigned b100 = base_params[323u];
    unsigned b101 = stwo_m31_mul(b32, b100);
    unsigned b102 = stwo_m31_add(b31, b101);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 107u, row_index, 0);
    unsigned b103 = base_params[324u];
    unsigned b104 = stwo_m31_mul(b33, b103);
    unsigned b105 = stwo_m31_add(b102, b104);
    e9 = StwoCudaQm31{ b105, b45, b45, b45 };
    e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e0, e10);
    e10 = stwo_load_qm31(ext_params, 355u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 108u, row_index, 0);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 109u, row_index, 0);
    unsigned b106 = base_params[325u];
    unsigned b107 = stwo_m31_mul(b35, b106);
    unsigned b108 = stwo_m31_add(b34, b107);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 110u, row_index, 0);
    unsigned b109 = base_params[326u];
    unsigned b110 = stwo_m31_mul(b36, b109);
    unsigned b111 = stwo_m31_add(b108, b110);
    e0 = StwoCudaQm31{ b111, b45, b45, b45 };
    e8 = stwo_qm31_mul(e10, e0);
    e0 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(ext_params, 356u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 111u, row_index, 0);
    e9 = StwoCudaQm31{ b37, b45, b45, b45 };
    e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e0, e10);
    e10 = stwo_load_qm31(ext_params, 357u);
    e0 = stwo_qm31_sub(e9, e10);
    e10 = stwo_load_qm31(ext_params, 450u);
    e9 = stwo_qm31_mul(e3, e10);
    e10 = stwo_load_qm31(ext_params, 451u);
    e8 = stwo_qm31_mul(e2, e10);
    e10 = stwo_qm31_add(e9, e8);
    e8 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 452u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 453u);
    e9 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e9);
    e9 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 454u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 455u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e7);
    unsigned b112 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 180u, row_index, 0);
    unsigned b113 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 181u, row_index, 0);
    unsigned b114 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 182u, row_index, 0);
    unsigned b115 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 183u, row_index, 0);
    e7 = StwoCudaQm31{ b112, b113, b114, b115 };
    unsigned b116 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 184u, row_index, 0);
    unsigned b117 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 185u, row_index, 0);
    unsigned b118 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 186u, row_index, 0);
    unsigned b119 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 187u, row_index, 0);
    e6 = StwoCudaQm31{ b116, b117, b118, b119 };
    e4 = stwo_qm31_sub(e6, e7);
    e7 = stwo_qm31_mul(e4, e8);
    e4 = stwo_qm31_sub(e7, e10);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b120 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 188u, row_index, 0);
    unsigned b121 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 189u, row_index, 0);
    unsigned b122 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 190u, row_index, 0);
    unsigned b123 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 191u, row_index, 0);
    e7 = StwoCudaQm31{ b120, b121, b122, b123 };
    e10 = stwo_qm31_sub(e7, e6);
    e6 = stwo_qm31_mul(e10, e9);
    e10 = stwo_qm31_sub(e6, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b124 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 192u, row_index, 0);
    unsigned b125 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 193u, row_index, 0);
    unsigned b126 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 194u, row_index, 0);
    unsigned b127 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 195u, row_index, 0);
    e6 = StwoCudaQm31{ b124, b125, b126, b127 };
    e3 = stwo_qm31_sub(e6, e7);
    e7 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e7, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b128 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 196u, row_index, -1);
    unsigned b130 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 197u, row_index, -1);
    unsigned b132 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 198u, row_index, -1);
    unsigned b134 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 199u, row_index, -1);
    e7 = StwoCudaQm31{ b128, b130, b132, b134 };
    unsigned b129 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 196u, row_index, 0);
    unsigned b131 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 197u, row_index, 0);
    unsigned b133 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 198u, row_index, 0);
    unsigned b135 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 199u, row_index, 0);
    e5 = StwoCudaQm31{ b129, b131, b133, b135 };
    e2 = stwo_qm31_sub(e5, e7);
    e5 = stwo_qm31_sub(e2, e6);
    e2 = stwo_load_qm31(ext_params, 456u);
    e6 = stwo_qm31_add(e5, e2);
    e2 = stwo_qm31_mul(e6, e0);
    e6 = stwo_qm31_sub(e2, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
