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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_6b6a94cf7cd9bef9(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 813u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 171u, row_index, 0);
    unsigned b80 = base_params[0u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b45, b80, b80, b80 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 814u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 815u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 172u, row_index, 0);
    e2 = StwoCudaQm31{ b46, b80, b80, b80 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 816u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 149u, row_index, 0);
    e0 = StwoCudaQm31{ b39, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 817u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 150u, row_index, 0);
    e2 = StwoCudaQm31{ b40, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 818u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 159u, row_index, 0);
    e0 = StwoCudaQm31{ b41, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 819u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 160u, row_index, 0);
    e2 = StwoCudaQm31{ b42, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 820u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 169u, row_index, 0);
    e0 = StwoCudaQm31{ b43, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 821u);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 170u, row_index, 0);
    e2 = StwoCudaQm31{ b44, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 822u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 135u, row_index, 0);
    e0 = StwoCudaQm31{ b35, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 823u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 136u, row_index, 0);
    e2 = StwoCudaQm31{ b36, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 824u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 141u, row_index, 0);
    e0 = StwoCudaQm31{ b37, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 825u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 142u, row_index, 0);
    e2 = StwoCudaQm31{ b38, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 826u);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 203u, row_index, 0);
    e0 = StwoCudaQm31{ b71, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 827u);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 204u, row_index, 0);
    e2 = StwoCudaQm31{ b72, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 828u);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 205u, row_index, 0);
    e0 = StwoCudaQm31{ b73, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 829u);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 206u, row_index, 0);
    e2 = StwoCudaQm31{ b74, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 830u);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 207u, row_index, 0);
    e0 = StwoCudaQm31{ b75, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 831u);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 208u, row_index, 0);
    e2 = StwoCudaQm31{ b76, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 832u);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 209u, row_index, 0);
    e0 = StwoCudaQm31{ b77, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 833u);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 210u, row_index, 0);
    e2 = StwoCudaQm31{ b78, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 834u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 835u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    e2 = StwoCudaQm31{ b0, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 836u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 837u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e1 = StwoCudaQm31{ b1, b80, b80, b80 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 838u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    e3 = StwoCudaQm31{ b2, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 839u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e1 = StwoCudaQm31{ b3, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 840u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e3 = StwoCudaQm31{ b4, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 841u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e1 = StwoCudaQm31{ b5, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 842u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    e3 = StwoCudaQm31{ b6, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 843u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    e1 = StwoCudaQm31{ b7, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 844u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    e3 = StwoCudaQm31{ b8, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 845u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    e1 = StwoCudaQm31{ b9, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 846u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    e3 = StwoCudaQm31{ b10, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 847u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    e1 = StwoCudaQm31{ b11, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 848u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    e3 = StwoCudaQm31{ b12, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 849u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    e1 = StwoCudaQm31{ b13, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 850u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    e3 = StwoCudaQm31{ b14, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 851u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    e1 = StwoCudaQm31{ b15, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 852u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    e3 = StwoCudaQm31{ b16, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 853u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    e1 = StwoCudaQm31{ b17, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 854u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    e3 = StwoCudaQm31{ b18, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 855u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    e1 = StwoCudaQm31{ b19, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 856u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    e3 = StwoCudaQm31{ b20, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 857u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    e1 = StwoCudaQm31{ b21, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 858u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    e3 = StwoCudaQm31{ b22, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 859u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    e1 = StwoCudaQm31{ b23, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 860u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    e3 = StwoCudaQm31{ b24, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 861u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    e1 = StwoCudaQm31{ b25, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 862u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    e3 = StwoCudaQm31{ b26, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 863u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    e1 = StwoCudaQm31{ b27, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 864u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    e3 = StwoCudaQm31{ b28, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 865u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    e1 = StwoCudaQm31{ b29, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 866u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    e3 = StwoCudaQm31{ b30, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 867u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    e1 = StwoCudaQm31{ b31, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 868u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    e3 = StwoCudaQm31{ b32, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 869u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    e1 = StwoCudaQm31{ b33, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 870u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    e3 = StwoCudaQm31{ b34, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 871u);
    e1 = stwo_qm31_sub(e3, e2);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 211u, row_index, 0);
    e2 = StwoCudaQm31{ b79, b80, b80, b80 };
    e3 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e2);
    e2 = stwo_load_qm31(ext_params, 872u);
    e4 = StwoCudaQm31{ b0, b80, b80, b80 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e2, e4);
    e4 = stwo_load_qm31(ext_params, 873u);
    e2 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(ext_params, 874u);
    unsigned b81 = base_params[65u];
    unsigned b82 = stwo_m31_add(b1, b81);
    e5 = StwoCudaQm31{ b82, b80, b80, b80 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 875u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 179u, row_index, 0);
    e2 = StwoCudaQm31{ b47, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 876u);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 180u, row_index, 0);
    e5 = StwoCudaQm31{ b48, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 877u);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 187u, row_index, 0);
    e2 = StwoCudaQm31{ b55, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 878u);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 188u, row_index, 0);
    e5 = StwoCudaQm31{ b56, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 879u);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 195u, row_index, 0);
    e2 = StwoCudaQm31{ b63, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 880u);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 196u, row_index, 0);
    e5 = StwoCudaQm31{ b64, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 881u);
    e2 = StwoCudaQm31{ b71, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 882u);
    e5 = StwoCudaQm31{ b72, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 883u);
    e2 = StwoCudaQm31{ b73, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 884u);
    e5 = StwoCudaQm31{ b74, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 885u);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 181u, row_index, 0);
    e2 = StwoCudaQm31{ b49, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 886u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 182u, row_index, 0);
    e5 = StwoCudaQm31{ b50, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 887u);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 189u, row_index, 0);
    e2 = StwoCudaQm31{ b57, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 888u);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 190u, row_index, 0);
    e5 = StwoCudaQm31{ b58, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 889u);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 197u, row_index, 0);
    e2 = StwoCudaQm31{ b65, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 890u);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 198u, row_index, 0);
    e5 = StwoCudaQm31{ b66, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 891u);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 199u, row_index, 0);
    e2 = StwoCudaQm31{ b67, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 892u);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 200u, row_index, 0);
    e5 = StwoCudaQm31{ b68, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 893u);
    e2 = StwoCudaQm31{ b75, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 894u);
    e5 = StwoCudaQm31{ b76, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 895u);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 183u, row_index, 0);
    e2 = StwoCudaQm31{ b51, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 896u);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 184u, row_index, 0);
    e5 = StwoCudaQm31{ b52, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 897u);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 191u, row_index, 0);
    e2 = StwoCudaQm31{ b59, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 898u);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 192u, row_index, 0);
    e5 = StwoCudaQm31{ b60, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 899u);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 193u, row_index, 0);
    e2 = StwoCudaQm31{ b61, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 900u);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 194u, row_index, 0);
    e5 = StwoCudaQm31{ b62, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 901u);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 201u, row_index, 0);
    e2 = StwoCudaQm31{ b69, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 902u);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 202u, row_index, 0);
    e5 = StwoCudaQm31{ b70, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 903u);
    e2 = StwoCudaQm31{ b77, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 904u);
    e5 = StwoCudaQm31{ b78, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 905u);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 185u, row_index, 0);
    e2 = StwoCudaQm31{ b53, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 906u);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 186u, row_index, 0);
    e5 = StwoCudaQm31{ b54, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 907u);
    e2 = StwoCudaQm31{ b34, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 908u);
    e5 = stwo_qm31_sub(e2, e4);
    e4 = stwo_load_qm31(ext_params, 965u);
    e2 = stwo_qm31_mul(e1, e4);
    e4 = StwoCudaQm31{ b79, b80, b80, b80 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e2, e6);
    e6 = stwo_qm31_mul(e0, e1);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 108u, row_index, 0);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 109u, row_index, 0);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 110u, row_index, 0);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 111u, row_index, 0);
    e1 = StwoCudaQm31{ b83, b84, b85, b86 };
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 112u, row_index, 0);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 113u, row_index, 0);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 114u, row_index, 0);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 115u, row_index, 0);
    e0 = StwoCudaQm31{ b87, b88, b89, b90 };
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_qm31_mul(e2, e6);
    e2 = stwo_qm31_sub(e1, e4);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 116u, row_index, -1);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 117u, row_index, -1);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 118u, row_index, -1);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 119u, row_index, -1);
    e1 = StwoCudaQm31{ b91, b93, b95, b97 };
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 116u, row_index, 0);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 117u, row_index, 0);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 118u, row_index, 0);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 119u, row_index, 0);
    e4 = StwoCudaQm31{ b92, b94, b96, b98 };
    e6 = stwo_qm31_sub(e4, e1);
    e4 = stwo_qm31_sub(e6, e0);
    e6 = stwo_load_qm31(ext_params, 966u);
    e0 = stwo_qm31_add(e4, e6);
    e6 = stwo_qm31_mul(e0, e5);
    e0 = stwo_qm31_sub(e6, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
