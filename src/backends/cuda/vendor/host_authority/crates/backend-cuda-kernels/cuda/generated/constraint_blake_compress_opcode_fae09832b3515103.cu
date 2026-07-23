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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_067df88a864246ee(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 736u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 157u, row_index, 0);
    unsigned b33 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b16, b33, b33, b33 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 737u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 738u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 134u, row_index, 0);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 158u, row_index, 0);
    unsigned b45 = base_params[117u];
    unsigned b46 = stwo_m31_mul(b17, b45);
    unsigned b47 = stwo_m31_sub(b9, b46);
    e2 = StwoCudaQm31{ b47, b33, b33, b33 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 739u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 159u, row_index, 0);
    e0 = StwoCudaQm31{ b18, b33, b33, b33 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 740u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 741u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    unsigned b34 = base_params[44u];
    unsigned b35 = stwo_m31_mul(b5, b34);
    unsigned b36 = stwo_m31_add(b4, b35);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    unsigned b37 = base_params[45u];
    unsigned b38 = stwo_m31_mul(b6, b37);
    unsigned b39 = stwo_m31_add(b36, b38);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    unsigned b40 = base_params[46u];
    unsigned b41 = stwo_m31_mul(b7, b40);
    unsigned b42 = stwo_m31_add(b39, b41);
    unsigned b43 = base_params[116u];
    unsigned b44 = stwo_m31_add(b42, b43);
    e0 = StwoCudaQm31{ b44, b33, b33, b33 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 742u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 743u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 160u, row_index, 0);
    e3 = StwoCudaQm31{ b19, b33, b33, b33 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 744u);
    e1 = stwo_qm31_sub(e3, e4);
    e4 = stwo_load_qm31(ext_params, 745u);
    e3 = StwoCudaQm31{ b19, b33, b33, b33 };
    e0 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(ext_params, 746u);
    e4 = stwo_qm31_add(e3, e0);
    e3 = stwo_load_qm31(ext_params, 747u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 133u, row_index, 0);
    unsigned b48 = base_params[118u];
    unsigned b49 = stwo_m31_mul(b16, b48);
    unsigned b50 = stwo_m31_sub(b8, b49);
    e0 = StwoCudaQm31{ b50, b33, b33, b33 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 748u);
    unsigned b51 = base_params[119u];
    unsigned b52 = stwo_m31_mul(b47, b51);
    unsigned b53 = stwo_m31_add(b16, b52);
    e4 = StwoCudaQm31{ b53, b33, b33, b33 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 749u);
    unsigned b54 = base_params[120u];
    unsigned b55 = stwo_m31_mul(b18, b54);
    unsigned b56 = stwo_m31_sub(b17, b55);
    e0 = StwoCudaQm31{ b56, b33, b33, b33 };
    e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 750u);
    e4 = StwoCudaQm31{ b18, b33, b33, b33 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 751u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(ext_params, 752u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 753u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(ext_params, 754u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 755u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(ext_params, 756u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 757u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(ext_params, 758u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 759u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(ext_params, 760u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 761u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(ext_params, 762u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 763u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(ext_params, 764u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 765u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(ext_params, 766u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 767u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(ext_params, 768u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 769u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(ext_params, 770u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 771u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(ext_params, 772u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 773u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(ext_params, 774u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 775u);
    e0 = stwo_qm31_sub(e4, e3);
    e3 = stwo_load_qm31(ext_params, 776u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 161u, row_index, 0);
    e4 = StwoCudaQm31{ b20, b33, b33, b33 };
    e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_load_qm31(ext_params, 777u);
    e3 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(ext_params, 778u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 136u, row_index, 0);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 162u, row_index, 0);
    unsigned b59 = base_params[122u];
    unsigned b60 = stwo_m31_mul(b21, b59);
    unsigned b61 = stwo_m31_sub(b11, b60);
    e5 = StwoCudaQm31{ b61, b33, b33, b33 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 779u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 163u, row_index, 0);
    e3 = StwoCudaQm31{ b22, b33, b33, b33 };
    e4 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 780u);
    e5 = stwo_qm31_sub(e3, e4);
    e4 = stwo_load_qm31(ext_params, 781u);
    unsigned b57 = base_params[121u];
    unsigned b58 = stwo_m31_add(b42, b57);
    e3 = StwoCudaQm31{ b58, b33, b33, b33 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(ext_params, 782u);
    e4 = stwo_qm31_add(e3, e6);
    e3 = stwo_load_qm31(ext_params, 783u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 164u, row_index, 0);
    e6 = StwoCudaQm31{ b23, b33, b33, b33 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e3, e6);
    e6 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 784u);
    e4 = stwo_qm31_sub(e6, e7);
    e7 = stwo_load_qm31(ext_params, 785u);
    e6 = StwoCudaQm31{ b23, b33, b33, b33 };
    e3 = stwo_qm31_mul(e7, e6);
    e6 = stwo_load_qm31(ext_params, 786u);
    e7 = stwo_qm31_add(e6, e3);
    e6 = stwo_load_qm31(ext_params, 787u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 135u, row_index, 0);
    unsigned b62 = base_params[123u];
    unsigned b63 = stwo_m31_mul(b20, b62);
    unsigned b64 = stwo_m31_sub(b10, b63);
    e3 = StwoCudaQm31{ b64, b33, b33, b33 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 788u);
    unsigned b65 = base_params[124u];
    unsigned b66 = stwo_m31_mul(b61, b65);
    unsigned b67 = stwo_m31_add(b20, b66);
    e7 = StwoCudaQm31{ b67, b33, b33, b33 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 789u);
    unsigned b68 = base_params[125u];
    unsigned b69 = stwo_m31_mul(b22, b68);
    unsigned b70 = stwo_m31_sub(b21, b69);
    e3 = StwoCudaQm31{ b70, b33, b33, b33 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 790u);
    e7 = StwoCudaQm31{ b22, b33, b33, b33 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 791u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(ext_params, 792u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 793u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(ext_params, 794u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 795u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(ext_params, 796u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 797u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(ext_params, 798u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 799u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(ext_params, 800u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 801u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(ext_params, 802u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 803u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(ext_params, 804u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 805u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(ext_params, 806u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 807u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(ext_params, 808u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 809u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(ext_params, 810u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 811u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(ext_params, 812u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 813u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(ext_params, 814u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 815u);
    e3 = stwo_qm31_sub(e7, e6);
    e6 = stwo_load_qm31(ext_params, 816u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 165u, row_index, 0);
    e7 = StwoCudaQm31{ b24, b33, b33, b33 };
    e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 817u);
    e6 = stwo_qm31_add(e7, e8);
    e7 = stwo_load_qm31(ext_params, 818u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 138u, row_index, 0);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 166u, row_index, 0);
    unsigned b73 = base_params[127u];
    unsigned b74 = stwo_m31_mul(b25, b73);
    unsigned b75 = stwo_m31_sub(b13, b74);
    e8 = StwoCudaQm31{ b75, b33, b33, b33 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 819u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 167u, row_index, 0);
    e6 = StwoCudaQm31{ b26, b33, b33, b33 };
    e7 = stwo_qm31_mul(e9, e6);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(ext_params, 820u);
    e8 = stwo_qm31_sub(e6, e7);
    e7 = stwo_load_qm31(ext_params, 821u);
    unsigned b71 = base_params[126u];
    unsigned b72 = stwo_m31_add(b42, b71);
    e6 = StwoCudaQm31{ b72, b33, b33, b33 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_load_qm31(ext_params, 822u);
    e7 = stwo_qm31_add(e6, e9);
    e6 = stwo_load_qm31(ext_params, 823u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 168u, row_index, 0);
    e9 = StwoCudaQm31{ b27, b33, b33, b33 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e6, e9);
    e9 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(ext_params, 824u);
    e7 = stwo_qm31_sub(e9, e10);
    e10 = stwo_load_qm31(ext_params, 825u);
    e9 = StwoCudaQm31{ b27, b33, b33, b33 };
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_load_qm31(ext_params, 826u);
    e10 = stwo_qm31_add(e9, e6);
    e9 = stwo_load_qm31(ext_params, 827u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 137u, row_index, 0);
    unsigned b76 = base_params[128u];
    unsigned b77 = stwo_m31_mul(b24, b76);
    unsigned b78 = stwo_m31_sub(b12, b77);
    e6 = StwoCudaQm31{ b78, b33, b33, b33 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e9, e6);
    e6 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 828u);
    unsigned b79 = base_params[129u];
    unsigned b80 = stwo_m31_mul(b75, b79);
    unsigned b81 = stwo_m31_add(b24, b80);
    e10 = StwoCudaQm31{ b81, b33, b33, b33 };
    e9 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 829u);
    unsigned b82 = base_params[130u];
    unsigned b83 = stwo_m31_mul(b26, b82);
    unsigned b84 = stwo_m31_sub(b25, b83);
    e6 = StwoCudaQm31{ b84, b33, b33, b33 };
    e11 = stwo_qm31_mul(e9, e6);
    e6 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 830u);
    e10 = StwoCudaQm31{ b26, b33, b33, b33 };
    e9 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 831u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 832u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 833u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 834u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 835u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 836u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 837u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 838u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 839u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 840u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 841u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 842u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 843u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 844u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 845u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 846u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 847u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 848u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 849u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 850u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 851u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 852u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 853u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 854u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 855u);
    e6 = stwo_qm31_sub(e10, e9);
    e9 = stwo_load_qm31(ext_params, 856u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 169u, row_index, 0);
    e10 = StwoCudaQm31{ b28, b33, b33, b33 };
    e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_load_qm31(ext_params, 857u);
    e9 = stwo_qm31_add(e10, e11);
    e10 = stwo_load_qm31(ext_params, 858u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 140u, row_index, 0);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 170u, row_index, 0);
    unsigned b87 = base_params[132u];
    unsigned b88 = stwo_m31_mul(b29, b87);
    unsigned b89 = stwo_m31_sub(b15, b88);
    e11 = StwoCudaQm31{ b89, b33, b33, b33 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e10, e11);
    e11 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(ext_params, 859u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 171u, row_index, 0);
    e9 = StwoCudaQm31{ b30, b33, b33, b33 };
    e10 = stwo_qm31_mul(e12, e9);
    e9 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 860u);
    e11 = stwo_qm31_sub(e9, e10);
    e10 = stwo_load_qm31(ext_params, 861u);
    unsigned b85 = base_params[131u];
    unsigned b86 = stwo_m31_add(b42, b85);
    e9 = StwoCudaQm31{ b86, b33, b33, b33 };
    e12 = stwo_qm31_mul(e10, e9);
    e9 = stwo_load_qm31(ext_params, 862u);
    e10 = stwo_qm31_add(e9, e12);
    e9 = stwo_load_qm31(ext_params, 863u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 172u, row_index, 0);
    e12 = StwoCudaQm31{ b31, b33, b33, b33 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e9, e12);
    e12 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 864u);
    e10 = stwo_qm31_sub(e12, e13);
    e13 = stwo_load_qm31(ext_params, 865u);
    e12 = StwoCudaQm31{ b31, b33, b33, b33 };
    e9 = stwo_qm31_mul(e13, e12);
    e12 = stwo_load_qm31(ext_params, 866u);
    e13 = stwo_qm31_add(e12, e9);
    e12 = stwo_load_qm31(ext_params, 867u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 139u, row_index, 0);
    unsigned b90 = base_params[133u];
    unsigned b91 = stwo_m31_mul(b28, b90);
    unsigned b92 = stwo_m31_sub(b14, b91);
    e9 = StwoCudaQm31{ b92, b33, b33, b33 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e12, e9);
    e9 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(ext_params, 868u);
    unsigned b93 = base_params[134u];
    unsigned b94 = stwo_m31_mul(b89, b93);
    unsigned b95 = stwo_m31_add(b28, b94);
    e13 = StwoCudaQm31{ b95, b33, b33, b33 };
    e12 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(ext_params, 869u);
    unsigned b96 = base_params[135u];
    unsigned b97 = stwo_m31_mul(b30, b96);
    unsigned b98 = stwo_m31_sub(b29, b97);
    e9 = StwoCudaQm31{ b98, b33, b33, b33 };
    e14 = stwo_qm31_mul(e12, e9);
    e9 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(ext_params, 870u);
    e13 = StwoCudaQm31{ b30, b33, b33, b33 };
    e12 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(ext_params, 871u);
    e9 = stwo_qm31_add(e13, e12);
    e12 = stwo_load_qm31(ext_params, 872u);
    e13 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(ext_params, 873u);
    e9 = stwo_qm31_add(e13, e12);
    e12 = stwo_load_qm31(ext_params, 874u);
    e13 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(ext_params, 875u);
    e9 = stwo_qm31_add(e13, e12);
    e12 = stwo_load_qm31(ext_params, 876u);
    e13 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(ext_params, 877u);
    e9 = stwo_qm31_add(e13, e12);
    e12 = stwo_load_qm31(ext_params, 878u);
    e13 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(ext_params, 879u);
    e9 = stwo_qm31_add(e13, e12);
    e12 = stwo_load_qm31(ext_params, 880u);
    e13 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(ext_params, 881u);
    e9 = stwo_qm31_add(e13, e12);
    e12 = stwo_load_qm31(ext_params, 882u);
    e13 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(ext_params, 883u);
    e9 = stwo_qm31_add(e13, e12);
    e12 = stwo_load_qm31(ext_params, 884u);
    e13 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(ext_params, 885u);
    e9 = stwo_qm31_add(e13, e12);
    e12 = stwo_load_qm31(ext_params, 886u);
    e13 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(ext_params, 887u);
    e9 = stwo_qm31_add(e13, e12);
    e12 = stwo_load_qm31(ext_params, 888u);
    e13 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(ext_params, 889u);
    e9 = stwo_qm31_add(e13, e12);
    e12 = stwo_load_qm31(ext_params, 890u);
    e13 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(ext_params, 891u);
    e9 = stwo_qm31_add(e13, e12);
    e12 = stwo_load_qm31(ext_params, 892u);
    e13 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(ext_params, 893u);
    e9 = stwo_qm31_add(e13, e12);
    e12 = stwo_load_qm31(ext_params, 894u);
    e13 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(ext_params, 895u);
    e9 = stwo_qm31_sub(e13, e12);
    e12 = stwo_load_qm31(ext_params, 896u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    e13 = StwoCudaQm31{ b0, b33, b33, b33 };
    e14 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(ext_params, 897u);
    e12 = stwo_qm31_add(e13, e14);
    e13 = stwo_load_qm31(ext_params, 898u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e14 = StwoCudaQm31{ b1, b33, b33, b33 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e13, e14);
    e14 = stwo_qm31_add(e12, e15);
    e15 = stwo_load_qm31(ext_params, 899u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    e12 = StwoCudaQm31{ b2, b33, b33, b33 };
    e13 = stwo_qm31_mul(e15, e12);
    e12 = stwo_qm31_add(e14, e13);
    e13 = stwo_load_qm31(ext_params, 900u);
    e14 = stwo_qm31_sub(e12, e13);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 173u, row_index, 0);
    e13 = StwoCudaQm31{ b32, b33, b33, b33 };
    e12 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e13);
    e13 = stwo_load_qm31(ext_params, 901u);
    unsigned b99 = base_params[136u];
    unsigned b100 = stwo_m31_add(b0, b99);
    e15 = StwoCudaQm31{ b100, b33, b33, b33 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e13, e15);
    e15 = stwo_load_qm31(ext_params, 902u);
    e13 = stwo_qm31_add(e15, e16);
    e15 = stwo_load_qm31(ext_params, 903u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b101 = stwo_m31_add(b1, b3);
    e16 = StwoCudaQm31{ b101, b33, b33, b33 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e13, e17);
    e17 = stwo_load_qm31(ext_params, 904u);
    e13 = StwoCudaQm31{ b2, b33, b33, b33 };
    e15 = stwo_qm31_mul(e17, e13);
    e13 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(ext_params, 905u);
    e16 = stwo_qm31_sub(e13, e15);
    e15 = stwo_load_qm31(ext_params, 966u);
    e13 = stwo_qm31_mul(e1, e15);
    e15 = stwo_load_qm31(ext_params, 967u);
    e17 = stwo_qm31_mul(e2, e15);
    e15 = stwo_qm31_add(e13, e17);
    e17 = stwo_qm31_mul(e2, e1);
    e1 = stwo_load_qm31(ext_params, 968u);
    e2 = stwo_qm31_mul(e5, e1);
    e1 = stwo_load_qm31(ext_params, 969u);
    e13 = stwo_qm31_mul(e0, e1);
    e1 = stwo_qm31_add(e2, e13);
    e13 = stwo_qm31_mul(e0, e5);
    e5 = stwo_load_qm31(ext_params, 970u);
    e0 = stwo_qm31_mul(e3, e5);
    e5 = stwo_load_qm31(ext_params, 971u);
    e2 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e0, e2);
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(ext_params, 972u);
    e4 = stwo_qm31_mul(e7, e3);
    e3 = stwo_load_qm31(ext_params, 973u);
    e0 = stwo_qm31_mul(e8, e3);
    e3 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e8, e7);
    e7 = stwo_load_qm31(ext_params, 974u);
    e8 = stwo_qm31_mul(e11, e7);
    e7 = stwo_load_qm31(ext_params, 975u);
    e4 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e8, e4);
    e4 = stwo_qm31_mul(e6, e11);
    e11 = stwo_load_qm31(ext_params, 976u);
    e6 = stwo_qm31_mul(e9, e11);
    e11 = stwo_load_qm31(ext_params, 977u);
    e8 = stwo_qm31_mul(e10, e11);
    e11 = stwo_qm31_add(e6, e8);
    e8 = stwo_qm31_mul(e10, e9);
    e9 = StwoCudaQm31{ b32, b33, b33, b33 };
    e10 = stwo_qm31_mul(e16, e9);
    e9 = stwo_qm31_mul(e14, e12);
    e12 = stwo_qm31_add(e10, e9);
    e9 = stwo_qm31_mul(e14, e16);
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 116u, row_index, 0);
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 117u, row_index, 0);
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 118u, row_index, 0);
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 119u, row_index, 0);
    e16 = StwoCudaQm31{ b102, b103, b104, b105 };
    unsigned b106 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 120u, row_index, 0);
    unsigned b107 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 121u, row_index, 0);
    unsigned b108 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 122u, row_index, 0);
    unsigned b109 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 123u, row_index, 0);
    e14 = StwoCudaQm31{ b106, b107, b108, b109 };
    e10 = stwo_qm31_sub(e14, e16);
    e16 = stwo_qm31_mul(e10, e17);
    e10 = stwo_qm31_sub(e16, e15);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b110 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 124u, row_index, 0);
    unsigned b111 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 125u, row_index, 0);
    unsigned b112 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 126u, row_index, 0);
    unsigned b113 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 127u, row_index, 0);
    e16 = StwoCudaQm31{ b110, b111, b112, b113 };
    e15 = stwo_qm31_sub(e16, e14);
    e14 = stwo_qm31_mul(e15, e13);
    e15 = stwo_qm31_sub(e14, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b114 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 128u, row_index, 0);
    unsigned b115 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 129u, row_index, 0);
    unsigned b116 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 130u, row_index, 0);
    unsigned b117 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 131u, row_index, 0);
    e14 = StwoCudaQm31{ b114, b115, b116, b117 };
    e1 = stwo_qm31_sub(e14, e16);
    e16 = stwo_qm31_mul(e1, e2);
    e1 = stwo_qm31_sub(e16, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b118 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 132u, row_index, 0);
    unsigned b119 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 133u, row_index, 0);
    unsigned b120 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 134u, row_index, 0);
    unsigned b121 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 135u, row_index, 0);
    e16 = StwoCudaQm31{ b118, b119, b120, b121 };
    e5 = stwo_qm31_sub(e16, e14);
    e14 = stwo_qm31_mul(e5, e0);
    e5 = stwo_qm31_sub(e14, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b122 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 136u, row_index, 0);
    unsigned b123 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 137u, row_index, 0);
    unsigned b124 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 138u, row_index, 0);
    unsigned b125 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 139u, row_index, 0);
    e14 = StwoCudaQm31{ b122, b123, b124, b125 };
    e3 = stwo_qm31_sub(e14, e16);
    e16 = stwo_qm31_mul(e3, e4);
    e3 = stwo_qm31_sub(e16, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b126 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 140u, row_index, 0);
    unsigned b127 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 141u, row_index, 0);
    unsigned b128 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 142u, row_index, 0);
    unsigned b129 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 143u, row_index, 0);
    e16 = StwoCudaQm31{ b126, b127, b128, b129 };
    e7 = stwo_qm31_sub(e16, e14);
    e14 = stwo_qm31_mul(e7, e8);
    e7 = stwo_qm31_sub(e14, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b130 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 144u, row_index, -1);
    unsigned b132 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 145u, row_index, -1);
    unsigned b134 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 146u, row_index, -1);
    unsigned b136 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 147u, row_index, -1);
    e14 = StwoCudaQm31{ b130, b132, b134, b136 };
    unsigned b131 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 144u, row_index, 0);
    unsigned b133 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 145u, row_index, 0);
    unsigned b135 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 146u, row_index, 0);
    unsigned b137 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 147u, row_index, 0);
    e11 = StwoCudaQm31{ b131, b133, b135, b137 };
    e8 = stwo_qm31_sub(e11, e14);
    e11 = stwo_qm31_sub(e8, e16);
    e8 = stwo_load_qm31(ext_params, 978u);
    e16 = stwo_qm31_add(e11, e8);
    e8 = stwo_qm31_mul(e16, e9);
    e16 = stwo_qm31_sub(e8, e12);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
