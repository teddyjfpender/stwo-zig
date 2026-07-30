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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_8f4a5524f04b1174(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 738u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 190u, row_index, 0);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 338u, row_index, 0);
    unsigned b54 = base_params[253u];
    unsigned b55 = stwo_m31_mul(b22, b54);
    unsigned b56 = stwo_m31_sub(b0, b55);
    unsigned b53 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b56, b53, b53, b53 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 739u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 740u);
    e2 = StwoCudaQm31{ b22, b53, b53, b53 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 741u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 343u, row_index, 0);
    e0 = StwoCudaQm31{ b23, b53, b53, b53 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 742u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 202u, row_index, 0);
    unsigned b57 = base_params[258u];
    unsigned b58 = stwo_m31_mul(b23, b57);
    unsigned b59 = stwo_m31_sub(b1, b58);
    e2 = StwoCudaQm31{ b59, b53, b53, b53 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 743u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 744u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 206u, row_index, 0);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 344u, row_index, 0);
    unsigned b60 = base_params[275u];
    unsigned b61 = stwo_m31_mul(b24, b60);
    unsigned b62 = stwo_m31_sub(b2, b61);
    e2 = StwoCudaQm31{ b62, b53, b53, b53 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 745u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 746u);
    e1 = StwoCudaQm31{ b24, b53, b53, b53 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 747u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 207u, row_index, 0);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 345u, row_index, 0);
    unsigned b63 = base_params[276u];
    unsigned b64 = stwo_m31_mul(b25, b63);
    unsigned b65 = stwo_m31_sub(b3, b64);
    e3 = StwoCudaQm31{ b65, b53, b53, b53 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 748u);
    e1 = StwoCudaQm31{ b25, b53, b53, b53 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 749u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 750u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 210u, row_index, 0);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 346u, row_index, 0);
    unsigned b66 = base_params[277u];
    unsigned b67 = stwo_m31_mul(b26, b66);
    unsigned b68 = stwo_m31_sub(b4, b67);
    e1 = StwoCudaQm31{ b68, b53, b53, b53 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 751u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 752u);
    e2 = StwoCudaQm31{ b26, b53, b53, b53 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 753u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 211u, row_index, 0);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 347u, row_index, 0);
    unsigned b69 = base_params[278u];
    unsigned b70 = stwo_m31_mul(b27, b69);
    unsigned b71 = stwo_m31_sub(b5, b70);
    e4 = StwoCudaQm31{ b71, b53, b53, b53 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 754u);
    e2 = StwoCudaQm31{ b27, b53, b53, b53 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 755u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(ext_params, 756u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 218u, row_index, 0);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 349u, row_index, 0);
    unsigned b75 = base_params[280u];
    unsigned b76 = stwo_m31_mul(b29, b75);
    unsigned b77 = stwo_m31_sub(b7, b76);
    e2 = StwoCudaQm31{ b77, b53, b53, b53 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(ext_params, 757u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 758u);
    e1 = StwoCudaQm31{ b29, b53, b53, b53 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 759u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 219u, row_index, 0);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 350u, row_index, 0);
    unsigned b78 = base_params[281u];
    unsigned b79 = stwo_m31_mul(b30, b78);
    unsigned b80 = stwo_m31_sub(b8, b79);
    e5 = StwoCudaQm31{ b80, b53, b53, b53 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 760u);
    e1 = StwoCudaQm31{ b30, b53, b53, b53 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 761u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(ext_params, 762u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 222u, row_index, 0);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 351u, row_index, 0);
    unsigned b81 = base_params[282u];
    unsigned b82 = stwo_m31_mul(b31, b81);
    unsigned b83 = stwo_m31_sub(b9, b82);
    e1 = StwoCudaQm31{ b83, b53, b53, b53 };
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(ext_params, 763u);
    e6 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 764u);
    e2 = StwoCudaQm31{ b31, b53, b53, b53 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 765u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 223u, row_index, 0);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 352u, row_index, 0);
    unsigned b84 = base_params[283u];
    unsigned b85 = stwo_m31_mul(b32, b84);
    unsigned b86 = stwo_m31_sub(b10, b85);
    e6 = StwoCudaQm31{ b86, b53, b53, b53 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 766u);
    e2 = StwoCudaQm31{ b32, b53, b53, b53 };
    e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 767u);
    e6 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(ext_params, 768u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 214u, row_index, 0);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 348u, row_index, 0);
    unsigned b72 = base_params[279u];
    unsigned b73 = stwo_m31_mul(b28, b72);
    unsigned b74 = stwo_m31_sub(b6, b73);
    e2 = StwoCudaQm31{ b74, b53, b53, b53 };
    e1 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(ext_params, 769u);
    e7 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 770u);
    e1 = StwoCudaQm31{ b28, b53, b53, b53 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 771u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 353u, row_index, 0);
    e7 = StwoCudaQm31{ b33, b53, b53, b53 };
    e2 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 772u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 226u, row_index, 0);
    unsigned b87 = base_params[284u];
    unsigned b88 = stwo_m31_mul(b33, b87);
    unsigned b89 = stwo_m31_sub(b11, b88);
    e1 = StwoCudaQm31{ b89, b53, b53, b53 };
    e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 773u);
    e7 = stwo_qm31_sub(e1, e8);
    e8 = stwo_load_qm31(ext_params, 774u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 230u, row_index, 0);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 354u, row_index, 0);
    unsigned b90 = base_params[301u];
    unsigned b91 = stwo_m31_mul(b34, b90);
    unsigned b92 = stwo_m31_sub(b12, b91);
    e1 = StwoCudaQm31{ b92, b53, b53, b53 };
    e2 = stwo_qm31_mul(e8, e1);
    e1 = stwo_load_qm31(ext_params, 775u);
    e8 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 776u);
    e2 = StwoCudaQm31{ b34, b53, b53, b53 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 777u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 231u, row_index, 0);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 355u, row_index, 0);
    unsigned b93 = base_params[302u];
    unsigned b94 = stwo_m31_mul(b35, b93);
    unsigned b95 = stwo_m31_sub(b13, b94);
    e8 = StwoCudaQm31{ b95, b53, b53, b53 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 778u);
    e2 = StwoCudaQm31{ b35, b53, b53, b53 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 779u);
    e8 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(ext_params, 780u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 234u, row_index, 0);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 356u, row_index, 0);
    unsigned b96 = base_params[303u];
    unsigned b97 = stwo_m31_mul(b36, b96);
    unsigned b98 = stwo_m31_sub(b14, b97);
    e2 = StwoCudaQm31{ b98, b53, b53, b53 };
    e1 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(ext_params, 781u);
    e9 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 782u);
    e1 = StwoCudaQm31{ b36, b53, b53, b53 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 783u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 235u, row_index, 0);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 357u, row_index, 0);
    unsigned b99 = base_params[304u];
    unsigned b100 = stwo_m31_mul(b37, b99);
    unsigned b101 = stwo_m31_sub(b15, b100);
    e9 = StwoCudaQm31{ b101, b53, b53, b53 };
    e2 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 784u);
    e1 = StwoCudaQm31{ b37, b53, b53, b53 };
    e10 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 785u);
    e9 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(ext_params, 786u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 242u, row_index, 0);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 359u, row_index, 0);
    unsigned b105 = base_params[306u];
    unsigned b106 = stwo_m31_mul(b39, b105);
    unsigned b107 = stwo_m31_sub(b17, b106);
    e1 = StwoCudaQm31{ b107, b53, b53, b53 };
    e2 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(ext_params, 787u);
    e10 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 788u);
    e2 = StwoCudaQm31{ b39, b53, b53, b53 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 789u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 243u, row_index, 0);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 360u, row_index, 0);
    unsigned b108 = base_params[307u];
    unsigned b109 = stwo_m31_mul(b40, b108);
    unsigned b110 = stwo_m31_sub(b18, b109);
    e10 = StwoCudaQm31{ b110, b53, b53, b53 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 790u);
    e2 = StwoCudaQm31{ b40, b53, b53, b53 };
    e11 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 791u);
    e10 = stwo_qm31_sub(e2, e11);
    e11 = stwo_load_qm31(ext_params, 792u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 246u, row_index, 0);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 361u, row_index, 0);
    unsigned b111 = base_params[308u];
    unsigned b112 = stwo_m31_mul(b41, b111);
    unsigned b113 = stwo_m31_sub(b19, b112);
    e2 = StwoCudaQm31{ b113, b53, b53, b53 };
    e1 = stwo_qm31_mul(e11, e2);
    e2 = stwo_load_qm31(ext_params, 793u);
    e11 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 794u);
    e1 = StwoCudaQm31{ b41, b53, b53, b53 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 795u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 247u, row_index, 0);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 362u, row_index, 0);
    unsigned b114 = base_params[309u];
    unsigned b115 = stwo_m31_mul(b42, b114);
    unsigned b116 = stwo_m31_sub(b20, b115);
    e11 = StwoCudaQm31{ b116, b53, b53, b53 };
    e2 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 796u);
    e1 = StwoCudaQm31{ b42, b53, b53, b53 };
    e12 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 797u);
    e11 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(ext_params, 798u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 238u, row_index, 0);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 358u, row_index, 0);
    unsigned b102 = base_params[305u];
    unsigned b103 = stwo_m31_mul(b38, b102);
    unsigned b104 = stwo_m31_sub(b16, b103);
    e1 = StwoCudaQm31{ b104, b53, b53, b53 };
    e2 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(ext_params, 799u);
    e12 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 800u);
    e2 = StwoCudaQm31{ b38, b53, b53, b53 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 801u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 363u, row_index, 0);
    e12 = StwoCudaQm31{ b43, b53, b53, b53 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 802u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 250u, row_index, 0);
    unsigned b117 = base_params[310u];
    unsigned b118 = stwo_m31_mul(b43, b117);
    unsigned b119 = stwo_m31_sub(b21, b118);
    e2 = StwoCudaQm31{ b119, b53, b53, b53 };
    e13 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 803u);
    e12 = stwo_qm31_sub(e2, e13);
    e13 = stwo_load_qm31(ext_params, 804u);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 364u, row_index, 0);
    unsigned b120 = base_params[329u];
    unsigned b121 = stwo_m31_add(b44, b120);
    e2 = StwoCudaQm31{ b121, b53, b53, b53 };
    e1 = stwo_qm31_mul(e13, e2);
    e2 = stwo_load_qm31(ext_params, 805u);
    e13 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 806u);
    e1 = stwo_qm31_sub(e13, e2);
    e2 = stwo_load_qm31(ext_params, 807u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 365u, row_index, 0);
    unsigned b122 = base_params[331u];
    unsigned b123 = stwo_m31_add(b45, b122);
    e13 = StwoCudaQm31{ b123, b53, b53, b53 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e2, e13);
    e13 = stwo_load_qm31(ext_params, 808u);
    e2 = stwo_qm31_add(e13, e14);
    e13 = stwo_load_qm31(ext_params, 809u);
    e14 = stwo_qm31_sub(e2, e13);
    e13 = stwo_load_qm31(ext_params, 810u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 366u, row_index, 0);
    unsigned b124 = base_params[333u];
    unsigned b125 = stwo_m31_add(b46, b124);
    e2 = StwoCudaQm31{ b125, b53, b53, b53 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e13, e2);
    e2 = stwo_load_qm31(ext_params, 811u);
    e13 = stwo_qm31_add(e2, e15);
    e2 = stwo_load_qm31(ext_params, 812u);
    e15 = stwo_qm31_sub(e13, e2);
    e2 = stwo_load_qm31(ext_params, 813u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 367u, row_index, 0);
    unsigned b126 = base_params[335u];
    unsigned b127 = stwo_m31_add(b47, b126);
    e13 = StwoCudaQm31{ b127, b53, b53, b53 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e2, e13);
    e13 = stwo_load_qm31(ext_params, 814u);
    e2 = stwo_qm31_add(e13, e16);
    e13 = stwo_load_qm31(ext_params, 815u);
    e16 = stwo_qm31_sub(e2, e13);
    e13 = stwo_load_qm31(ext_params, 816u);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 368u, row_index, 0);
    unsigned b128 = base_params[337u];
    unsigned b129 = stwo_m31_add(b48, b128);
    e2 = StwoCudaQm31{ b129, b53, b53, b53 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e13, e2);
    e2 = stwo_load_qm31(ext_params, 817u);
    e13 = stwo_qm31_add(e2, e17);
    e2 = stwo_load_qm31(ext_params, 818u);
    e17 = stwo_qm31_sub(e13, e2);
    e2 = stwo_load_qm31(ext_params, 819u);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 369u, row_index, 0);
    unsigned b130 = base_params[339u];
    unsigned b131 = stwo_m31_add(b49, b130);
    e13 = StwoCudaQm31{ b131, b53, b53, b53 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e2, e13);
    e13 = stwo_load_qm31(ext_params, 820u);
    e2 = stwo_qm31_add(e13, e18);
    e13 = stwo_load_qm31(ext_params, 821u);
    e18 = stwo_qm31_sub(e2, e13);
    e13 = stwo_load_qm31(ext_params, 822u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 370u, row_index, 0);
    unsigned b132 = base_params[341u];
    unsigned b133 = stwo_m31_add(b50, b132);
    e2 = StwoCudaQm31{ b133, b53, b53, b53 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e13, e2);
    e2 = stwo_load_qm31(ext_params, 823u);
    e13 = stwo_qm31_add(e2, e19);
    e2 = stwo_load_qm31(ext_params, 824u);
    e19 = stwo_qm31_sub(e13, e2);
    e2 = stwo_load_qm31(ext_params, 825u);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 371u, row_index, 0);
    unsigned b134 = base_params[343u];
    unsigned b135 = stwo_m31_add(b51, b134);
    e13 = StwoCudaQm31{ b135, b53, b53, b53 };
    StwoCudaQm31 e20 = stwo_qm31_mul(e2, e13);
    e13 = stwo_load_qm31(ext_params, 826u);
    e2 = stwo_qm31_add(e13, e20);
    e13 = stwo_load_qm31(ext_params, 827u);
    e20 = stwo_qm31_sub(e2, e13);
    e13 = stwo_load_qm31(ext_params, 828u);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 372u, row_index, 0);
    unsigned b136 = base_params[345u];
    unsigned b137 = stwo_m31_add(b52, b136);
    e2 = StwoCudaQm31{ b137, b53, b53, b53 };
    StwoCudaQm31 e21 = stwo_qm31_mul(e13, e2);
    e2 = stwo_load_qm31(ext_params, 829u);
    e13 = stwo_qm31_add(e2, e21);
    e2 = stwo_load_qm31(ext_params, 830u);
    e21 = stwo_qm31_sub(e13, e2);
    e2 = stwo_load_qm31(ext_params, 1104u);
    e13 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 1105u);
    StwoCudaQm31 e22 = stwo_qm31_mul(e0, e2);
    e2 = stwo_qm31_add(e13, e22);
    e22 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(ext_params, 1106u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 1107u);
    e13 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e13);
    e13 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 1108u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 1109u);
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 1110u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(ext_params, 1111u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 1112u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(ext_params, 1113u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(ext_params, 1114u);
    e10 = stwo_qm31_mul(e1, e11);
    e11 = stwo_load_qm31(ext_params, 1115u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(ext_params, 1116u);
    e12 = stwo_qm31_mul(e15, e1);
    e1 = stwo_load_qm31(ext_params, 1117u);
    e10 = stwo_qm31_mul(e14, e1);
    e1 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 1118u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(ext_params, 1119u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(ext_params, 1120u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(ext_params, 1121u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(ext_params, 1122u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(ext_params, 1123u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e20, e21);
    unsigned b138 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 224u, row_index, 0);
    unsigned b139 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 225u, row_index, 0);
    unsigned b140 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 226u, row_index, 0);
    unsigned b141 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 227u, row_index, 0);
    e21 = StwoCudaQm31{ b138, b139, b140, b141 };
    unsigned b142 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 228u, row_index, 0);
    unsigned b143 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 229u, row_index, 0);
    unsigned b144 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 230u, row_index, 0);
    unsigned b145 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 231u, row_index, 0);
    e20 = StwoCudaQm31{ b142, b143, b144, b145 };
    e18 = stwo_qm31_sub(e20, e21);
    e21 = stwo_qm31_mul(e18, e22);
    e18 = stwo_qm31_sub(e21, e2);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b146 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 232u, row_index, 0);
    unsigned b147 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 233u, row_index, 0);
    unsigned b148 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 234u, row_index, 0);
    unsigned b149 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 235u, row_index, 0);
    e21 = StwoCudaQm31{ b146, b147, b148, b149 };
    e2 = stwo_qm31_sub(e21, e20);
    e20 = stwo_qm31_mul(e2, e13);
    e2 = stwo_qm31_sub(e20, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b150 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 236u, row_index, 0);
    unsigned b151 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 237u, row_index, 0);
    unsigned b152 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 238u, row_index, 0);
    unsigned b153 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 239u, row_index, 0);
    e20 = StwoCudaQm31{ b150, b151, b152, b153 };
    e3 = stwo_qm31_sub(e20, e21);
    e21 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e21, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b154 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 240u, row_index, 0);
    unsigned b155 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 241u, row_index, 0);
    unsigned b156 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 242u, row_index, 0);
    unsigned b157 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 243u, row_index, 0);
    e21 = StwoCudaQm31{ b154, b155, b156, b157 };
    e5 = stwo_qm31_sub(e21, e20);
    e20 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e20, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b158 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 244u, row_index, 0);
    unsigned b159 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 245u, row_index, 0);
    unsigned b160 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 246u, row_index, 0);
    unsigned b161 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 247u, row_index, 0);
    e20 = StwoCudaQm31{ b158, b159, b160, b161 };
    e7 = stwo_qm31_sub(e20, e21);
    e21 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e21, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b162 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 248u, row_index, 0);
    unsigned b163 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 249u, row_index, 0);
    unsigned b164 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 250u, row_index, 0);
    unsigned b165 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 251u, row_index, 0);
    e21 = StwoCudaQm31{ b162, b163, b164, b165 };
    e9 = stwo_qm31_sub(e21, e20);
    e20 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e20, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b166 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 252u, row_index, 0);
    unsigned b167 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 253u, row_index, 0);
    unsigned b168 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 254u, row_index, 0);
    unsigned b169 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 255u, row_index, 0);
    e20 = StwoCudaQm31{ b166, b167, b168, b169 };
    e11 = stwo_qm31_sub(e20, e21);
    e21 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e21, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b170 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 256u, row_index, 0);
    unsigned b171 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 257u, row_index, 0);
    unsigned b172 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 258u, row_index, 0);
    unsigned b173 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 259u, row_index, 0);
    e21 = StwoCudaQm31{ b170, b171, b172, b173 };
    e1 = stwo_qm31_sub(e21, e20);
    e20 = stwo_qm31_mul(e1, e12);
    e1 = stwo_qm31_sub(e20, e15);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b174 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 260u, row_index, 0);
    unsigned b175 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 261u, row_index, 0);
    unsigned b176 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 262u, row_index, 0);
    unsigned b177 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 263u, row_index, 0);
    e20 = StwoCudaQm31{ b174, b175, b176, b177 };
    e15 = stwo_qm31_sub(e20, e21);
    e21 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e21, e17);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b178 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 264u, row_index, 0);
    unsigned b179 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 265u, row_index, 0);
    unsigned b180 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 266u, row_index, 0);
    unsigned b181 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 267u, row_index, 0);
    e21 = StwoCudaQm31{ b178, b179, b180, b181 };
    e17 = stwo_qm31_sub(e21, e20);
    e21 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e21, e19);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
