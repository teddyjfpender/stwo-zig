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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_738234e3d5ad085d(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 127u);
    unsigned b66 = base_params[4u];
    unsigned b64 = base_params[3u];
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    unsigned b65 = stwo_m31_mul(b64, b0);
    unsigned b67 = stwo_m31_add(b66, b65);
    unsigned b68 = base_params[5u];
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b62 = base_params[2u];
    unsigned b63 = stwo_m31_sub(b1, b62);
    unsigned b69 = stwo_m31_mul(b68, b63);
    unsigned b70 = stwo_m31_add(b67, b69);
    unsigned b80 = base_params[53u];
    unsigned b81 = stwo_m31_add(b70, b80);
    unsigned b61 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b81, b61, b61, b61 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 128u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 129u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 79u, row_index, 0);
    e2 = StwoCudaQm31{ b10, b61, b61, b61 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 130u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 131u);
    e2 = StwoCudaQm31{ b70, b61, b61, b61 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 132u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 133u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 80u, row_index, 0);
    e1 = StwoCudaQm31{ b11, b61, b61, b61 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 134u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 135u);
    unsigned b82 = base_params[54u];
    unsigned b83 = stwo_m31_add(b70, b82);
    e1 = StwoCudaQm31{ b83, b61, b61, b61 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 136u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 137u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 81u, row_index, 0);
    e2 = StwoCudaQm31{ b12, b61, b61, b61 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 138u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(ext_params, 139u);
    unsigned b84 = base_params[55u];
    unsigned b85 = stwo_m31_add(b70, b84);
    e2 = StwoCudaQm31{ b85, b61, b61, b61 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(ext_params, 140u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 141u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 82u, row_index, 0);
    e1 = StwoCudaQm31{ b13, b61, b61, b61 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 142u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(ext_params, 143u);
    unsigned b86 = base_params[56u];
    unsigned b87 = stwo_m31_add(b70, b86);
    e1 = StwoCudaQm31{ b87, b61, b61, b61 };
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(ext_params, 144u);
    e6 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 145u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 83u, row_index, 0);
    e2 = StwoCudaQm31{ b14, b61, b61, b61 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 146u);
    e6 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(ext_params, 147u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    unsigned b71 = base_params[43u];
    unsigned b72 = stwo_m31_mul(b7, b71);
    unsigned b73 = stwo_m31_add(b6, b72);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    unsigned b74 = base_params[44u];
    unsigned b75 = stwo_m31_mul(b8, b74);
    unsigned b76 = stwo_m31_add(b73, b75);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    unsigned b77 = base_params[45u];
    unsigned b78 = stwo_m31_mul(b9, b77);
    unsigned b79 = stwo_m31_add(b76, b78);
    e2 = StwoCudaQm31{ b79, b61, b61, b61 };
    e1 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(ext_params, 148u);
    e7 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 149u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 84u, row_index, 0);
    e1 = StwoCudaQm31{ b15, b61, b61, b61 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 150u);
    e7 = stwo_qm31_sub(e1, e8);
    e8 = stwo_load_qm31(ext_params, 151u);
    e1 = StwoCudaQm31{ b15, b61, b61, b61 };
    e2 = stwo_qm31_mul(e8, e1);
    e1 = stwo_load_qm31(ext_params, 152u);
    e8 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 153u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 87u, row_index, 0);
    e2 = StwoCudaQm31{ b18, b61, b61, b61 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 154u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 88u, row_index, 0);
    e8 = StwoCudaQm31{ b19, b61, b61, b61 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 155u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 89u, row_index, 0);
    e2 = StwoCudaQm31{ b20, b61, b61, b61 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 156u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 90u, row_index, 0);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 86u, row_index, 0);
    unsigned b88 = base_params[60u];
    unsigned b89 = stwo_m31_mul(b17, b88);
    unsigned b97 = stwo_m31_add(b21, b89);
    e8 = StwoCudaQm31{ b97, b61, b61, b61 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 157u);
    unsigned b90 = base_params[61u];
    unsigned b91 = stwo_m31_mul(b17, b90);
    e2 = StwoCudaQm31{ b91, b61, b61, b61 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 158u);
    e8 = StwoCudaQm31{ b91, b61, b61, b61 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 159u);
    e2 = StwoCudaQm31{ b91, b61, b61, b61 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 160u);
    e8 = StwoCudaQm31{ b91, b61, b61, b61 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 161u);
    e2 = StwoCudaQm31{ b91, b61, b61, b61 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 162u);
    e8 = StwoCudaQm31{ b91, b61, b61, b61 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 163u);
    e2 = StwoCudaQm31{ b91, b61, b61, b61 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 164u);
    e8 = StwoCudaQm31{ b91, b61, b61, b61 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 165u);
    e2 = StwoCudaQm31{ b91, b61, b61, b61 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 166u);
    e8 = StwoCudaQm31{ b91, b61, b61, b61 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 167u);
    e2 = StwoCudaQm31{ b91, b61, b61, b61 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 168u);
    e8 = StwoCudaQm31{ b91, b61, b61, b61 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 169u);
    e2 = StwoCudaQm31{ b91, b61, b61, b61 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 170u);
    e8 = StwoCudaQm31{ b91, b61, b61, b61 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 171u);
    e2 = StwoCudaQm31{ b91, b61, b61, b61 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 172u);
    e8 = StwoCudaQm31{ b91, b61, b61, b61 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 173u);
    e2 = StwoCudaQm31{ b91, b61, b61, b61 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 174u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 85u, row_index, 0);
    unsigned b92 = base_params[62u];
    unsigned b93 = stwo_m31_mul(b16, b92);
    unsigned b94 = stwo_m31_sub(b93, b17);
    e8 = StwoCudaQm31{ b94, b61, b61, b61 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 175u);
    e2 = stwo_qm31_add(e8, e1);
    e1 = stwo_load_qm31(ext_params, 176u);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 177u);
    e2 = stwo_qm31_add(e8, e1);
    e1 = stwo_load_qm31(ext_params, 178u);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 179u);
    e2 = stwo_qm31_add(e8, e1);
    e1 = stwo_load_qm31(ext_params, 180u);
    unsigned b95 = base_params[63u];
    unsigned b96 = stwo_m31_mul(b16, b95);
    e8 = StwoCudaQm31{ b96, b61, b61, b61 };
    e9 = stwo_qm31_mul(e1, e8);
    e8 = stwo_qm31_add(e2, e9);
    e9 = stwo_load_qm31(ext_params, 181u);
    e2 = stwo_qm31_sub(e8, e9);
    e9 = stwo_load_qm31(ext_params, 182u);
    unsigned b111 = base_params[73u];
    unsigned b112 = stwo_m31_add(b79, b111);
    e8 = StwoCudaQm31{ b112, b61, b61, b61 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_load_qm31(ext_params, 183u);
    e9 = stwo_qm31_add(e8, e1);
    e8 = stwo_load_qm31(ext_params, 184u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 92u, row_index, 0);
    e1 = StwoCudaQm31{ b22, b61, b61, b61 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e8, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 185u);
    e9 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(ext_params, 186u);
    e1 = StwoCudaQm31{ b22, b61, b61, b61 };
    e8 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(ext_params, 187u);
    e10 = stwo_qm31_add(e1, e8);
    e1 = stwo_load_qm31(ext_params, 188u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 95u, row_index, 0);
    e8 = StwoCudaQm31{ b25, b61, b61, b61 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e1, e8);
    e8 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 189u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 96u, row_index, 0);
    e10 = StwoCudaQm31{ b26, b61, b61, b61 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e8, e1);
    e1 = stwo_load_qm31(ext_params, 190u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 97u, row_index, 0);
    e8 = StwoCudaQm31{ b27, b61, b61, b61 };
    e11 = stwo_qm31_mul(e1, e8);
    e8 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 191u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 98u, row_index, 0);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 94u, row_index, 0);
    unsigned b113 = base_params[77u];
    unsigned b114 = stwo_m31_mul(b24, b113);
    unsigned b122 = stwo_m31_add(b28, b114);
    e10 = StwoCudaQm31{ b122, b61, b61, b61 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e8, e1);
    e1 = stwo_load_qm31(ext_params, 192u);
    unsigned b115 = base_params[78u];
    unsigned b116 = stwo_m31_mul(b24, b115);
    e8 = StwoCudaQm31{ b116, b61, b61, b61 };
    e11 = stwo_qm31_mul(e1, e8);
    e8 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 193u);
    e10 = StwoCudaQm31{ b116, b61, b61, b61 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e8, e1);
    e1 = stwo_load_qm31(ext_params, 194u);
    e8 = StwoCudaQm31{ b116, b61, b61, b61 };
    e11 = stwo_qm31_mul(e1, e8);
    e8 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 195u);
    e10 = StwoCudaQm31{ b116, b61, b61, b61 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e8, e1);
    e1 = stwo_load_qm31(ext_params, 196u);
    e8 = StwoCudaQm31{ b116, b61, b61, b61 };
    e11 = stwo_qm31_mul(e1, e8);
    e8 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 197u);
    e10 = StwoCudaQm31{ b116, b61, b61, b61 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e8, e1);
    e1 = stwo_load_qm31(ext_params, 198u);
    e8 = StwoCudaQm31{ b116, b61, b61, b61 };
    e11 = stwo_qm31_mul(e1, e8);
    e8 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 199u);
    e10 = StwoCudaQm31{ b116, b61, b61, b61 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e8, e1);
    e1 = stwo_load_qm31(ext_params, 200u);
    e8 = StwoCudaQm31{ b116, b61, b61, b61 };
    e11 = stwo_qm31_mul(e1, e8);
    e8 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 201u);
    e10 = StwoCudaQm31{ b116, b61, b61, b61 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e8, e1);
    e1 = stwo_load_qm31(ext_params, 202u);
    e8 = StwoCudaQm31{ b116, b61, b61, b61 };
    e11 = stwo_qm31_mul(e1, e8);
    e8 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 203u);
    e10 = StwoCudaQm31{ b116, b61, b61, b61 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e8, e1);
    e1 = stwo_load_qm31(ext_params, 204u);
    e8 = StwoCudaQm31{ b116, b61, b61, b61 };
    e11 = stwo_qm31_mul(e1, e8);
    e8 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 205u);
    e10 = StwoCudaQm31{ b116, b61, b61, b61 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e8, e1);
    e1 = stwo_load_qm31(ext_params, 206u);
    e8 = StwoCudaQm31{ b116, b61, b61, b61 };
    e11 = stwo_qm31_mul(e1, e8);
    e8 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 207u);
    e10 = StwoCudaQm31{ b116, b61, b61, b61 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e8, e1);
    e1 = stwo_load_qm31(ext_params, 208u);
    e8 = StwoCudaQm31{ b116, b61, b61, b61 };
    e11 = stwo_qm31_mul(e1, e8);
    e8 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 209u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 93u, row_index, 0);
    unsigned b117 = base_params[79u];
    unsigned b118 = stwo_m31_mul(b23, b117);
    unsigned b119 = stwo_m31_sub(b118, b24);
    e10 = StwoCudaQm31{ b119, b61, b61, b61 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e8, e1);
    e1 = stwo_load_qm31(ext_params, 210u);
    e8 = stwo_qm31_add(e10, e1);
    e1 = stwo_load_qm31(ext_params, 211u);
    e10 = stwo_qm31_add(e8, e1);
    e1 = stwo_load_qm31(ext_params, 212u);
    e8 = stwo_qm31_add(e10, e1);
    e1 = stwo_load_qm31(ext_params, 213u);
    e10 = stwo_qm31_add(e8, e1);
    e1 = stwo_load_qm31(ext_params, 214u);
    e8 = stwo_qm31_add(e10, e1);
    e1 = stwo_load_qm31(ext_params, 215u);
    unsigned b120 = base_params[80u];
    unsigned b121 = stwo_m31_mul(b23, b120);
    e10 = StwoCudaQm31{ b121, b61, b61, b61 };
    e11 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 216u);
    e8 = stwo_qm31_sub(e10, e11);
    e11 = stwo_load_qm31(ext_params, 217u);
    unsigned b123 = base_params[90u];
    unsigned b124 = stwo_m31_add(b79, b123);
    e10 = StwoCudaQm31{ b124, b61, b61, b61 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_load_qm31(ext_params, 218u);
    e11 = stwo_qm31_add(e10, e1);
    e10 = stwo_load_qm31(ext_params, 219u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 100u, row_index, 0);
    e1 = StwoCudaQm31{ b29, b61, b61, b61 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 220u);
    e11 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(ext_params, 221u);
    e1 = StwoCudaQm31{ b29, b61, b61, b61 };
    e10 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(ext_params, 222u);
    e12 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(ext_params, 223u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 103u, row_index, 0);
    e10 = StwoCudaQm31{ b32, b61, b61, b61 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 224u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 104u, row_index, 0);
    e12 = StwoCudaQm31{ b33, b61, b61, b61 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e10, e1);
    e1 = stwo_load_qm31(ext_params, 225u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 105u, row_index, 0);
    e10 = StwoCudaQm31{ b34, b61, b61, b61 };
    e13 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 226u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 106u, row_index, 0);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 102u, row_index, 0);
    unsigned b125 = base_params[94u];
    unsigned b126 = stwo_m31_mul(b31, b125);
    unsigned b134 = stwo_m31_add(b35, b126);
    e12 = StwoCudaQm31{ b134, b61, b61, b61 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e10, e1);
    e1 = stwo_load_qm31(ext_params, 227u);
    unsigned b127 = base_params[95u];
    unsigned b128 = stwo_m31_mul(b31, b127);
    e10 = StwoCudaQm31{ b128, b61, b61, b61 };
    e13 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 228u);
    e12 = StwoCudaQm31{ b128, b61, b61, b61 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e10, e1);
    e1 = stwo_load_qm31(ext_params, 229u);
    e10 = StwoCudaQm31{ b128, b61, b61, b61 };
    e13 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 230u);
    e12 = StwoCudaQm31{ b128, b61, b61, b61 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e10, e1);
    e1 = stwo_load_qm31(ext_params, 231u);
    e10 = StwoCudaQm31{ b128, b61, b61, b61 };
    e13 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 232u);
    e12 = StwoCudaQm31{ b128, b61, b61, b61 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e10, e1);
    e1 = stwo_load_qm31(ext_params, 233u);
    e10 = StwoCudaQm31{ b128, b61, b61, b61 };
    e13 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 234u);
    e12 = StwoCudaQm31{ b128, b61, b61, b61 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e10, e1);
    e1 = stwo_load_qm31(ext_params, 235u);
    e10 = StwoCudaQm31{ b128, b61, b61, b61 };
    e13 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 236u);
    e12 = StwoCudaQm31{ b128, b61, b61, b61 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e10, e1);
    e1 = stwo_load_qm31(ext_params, 237u);
    e10 = StwoCudaQm31{ b128, b61, b61, b61 };
    e13 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 238u);
    e12 = StwoCudaQm31{ b128, b61, b61, b61 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e10, e1);
    e1 = stwo_load_qm31(ext_params, 239u);
    e10 = StwoCudaQm31{ b128, b61, b61, b61 };
    e13 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 240u);
    e12 = StwoCudaQm31{ b128, b61, b61, b61 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e10, e1);
    e1 = stwo_load_qm31(ext_params, 241u);
    e10 = StwoCudaQm31{ b128, b61, b61, b61 };
    e13 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 242u);
    e12 = StwoCudaQm31{ b128, b61, b61, b61 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e10, e1);
    e1 = stwo_load_qm31(ext_params, 243u);
    e10 = StwoCudaQm31{ b128, b61, b61, b61 };
    e13 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 244u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 101u, row_index, 0);
    unsigned b129 = base_params[96u];
    unsigned b130 = stwo_m31_mul(b30, b129);
    unsigned b131 = stwo_m31_sub(b130, b31);
    e12 = StwoCudaQm31{ b131, b61, b61, b61 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e10, e1);
    e1 = stwo_load_qm31(ext_params, 245u);
    e10 = stwo_qm31_add(e12, e1);
    e1 = stwo_load_qm31(ext_params, 246u);
    e12 = stwo_qm31_add(e10, e1);
    e1 = stwo_load_qm31(ext_params, 247u);
    e10 = stwo_qm31_add(e12, e1);
    e1 = stwo_load_qm31(ext_params, 248u);
    e12 = stwo_qm31_add(e10, e1);
    e1 = stwo_load_qm31(ext_params, 249u);
    e10 = stwo_qm31_add(e12, e1);
    e1 = stwo_load_qm31(ext_params, 250u);
    unsigned b132 = base_params[97u];
    unsigned b133 = stwo_m31_mul(b30, b132);
    e12 = StwoCudaQm31{ b133, b61, b61, b61 };
    e13 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 251u);
    e10 = stwo_qm31_sub(e12, e13);
    e13 = stwo_load_qm31(ext_params, 252u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    unsigned b135 = base_params[107u];
    unsigned b136 = stwo_m31_mul(b3, b135);
    unsigned b137 = stwo_m31_add(b2, b136);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    unsigned b138 = base_params[108u];
    unsigned b139 = stwo_m31_mul(b4, b138);
    unsigned b140 = stwo_m31_add(b137, b139);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    unsigned b141 = base_params[109u];
    unsigned b142 = stwo_m31_mul(b5, b141);
    unsigned b143 = stwo_m31_add(b140, b142);
    unsigned b98 = base_params[69u];
    unsigned b99 = stwo_m31_mul(b19, b98);
    unsigned b100 = stwo_m31_add(b18, b99);
    unsigned b101 = base_params[70u];
    unsigned b102 = stwo_m31_mul(b20, b101);
    unsigned b103 = stwo_m31_add(b100, b102);
    unsigned b104 = base_params[71u];
    unsigned b105 = stwo_m31_mul(b21, b104);
    unsigned b106 = stwo_m31_add(b103, b105);
    unsigned b107 = stwo_m31_sub(b106, b16);
    unsigned b108 = base_params[72u];
    unsigned b109 = stwo_m31_mul(b108, b17);
    unsigned b110 = stwo_m31_sub(b107, b109);
    unsigned b144 = stwo_m31_add(b143, b110);
    e12 = StwoCudaQm31{ b144, b61, b61, b61 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_load_qm31(ext_params, 253u);
    e13 = stwo_qm31_add(e12, e1);
    e12 = stwo_load_qm31(ext_params, 254u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 108u, row_index, 0);
    e1 = StwoCudaQm31{ b36, b61, b61, b61 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e12, e1);
    e1 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(ext_params, 255u);
    e13 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(ext_params, 256u);
    e1 = StwoCudaQm31{ b36, b61, b61, b61 };
    e12 = stwo_qm31_mul(e14, e1);
    e1 = stwo_load_qm31(ext_params, 257u);
    e14 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(ext_params, 258u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 109u, row_index, 0);
    e12 = StwoCudaQm31{ b37, b61, b61, b61 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 259u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 110u, row_index, 0);
    e14 = StwoCudaQm31{ b38, b61, b61, b61 };
    e1 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e12, e1);
    e1 = stwo_load_qm31(ext_params, 260u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 111u, row_index, 0);
    e12 = StwoCudaQm31{ b39, b61, b61, b61 };
    e15 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 261u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 112u, row_index, 0);
    e14 = StwoCudaQm31{ b40, b61, b61, b61 };
    e1 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e12, e1);
    e1 = stwo_load_qm31(ext_params, 262u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 113u, row_index, 0);
    e12 = StwoCudaQm31{ b41, b61, b61, b61 };
    e15 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 263u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 114u, row_index, 0);
    e14 = StwoCudaQm31{ b42, b61, b61, b61 };
    e1 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e12, e1);
    e1 = stwo_load_qm31(ext_params, 264u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 115u, row_index, 0);
    e12 = StwoCudaQm31{ b43, b61, b61, b61 };
    e15 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 265u);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 116u, row_index, 0);
    e14 = StwoCudaQm31{ b44, b61, b61, b61 };
    e1 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e12, e1);
    e1 = stwo_load_qm31(ext_params, 266u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 117u, row_index, 0);
    e12 = StwoCudaQm31{ b45, b61, b61, b61 };
    e15 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 267u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 118u, row_index, 0);
    e14 = StwoCudaQm31{ b46, b61, b61, b61 };
    e1 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e12, e1);
    e1 = stwo_load_qm31(ext_params, 268u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 119u, row_index, 0);
    e12 = StwoCudaQm31{ b47, b61, b61, b61 };
    e15 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 269u);
    e14 = stwo_qm31_sub(e12, e15);
    e15 = stwo_load_qm31(ext_params, 270u);
    unsigned b145 = stwo_m31_add(b143, b110);
    unsigned b146 = base_params[110u];
    unsigned b147 = stwo_m31_add(b145, b146);
    e12 = StwoCudaQm31{ b147, b61, b61, b61 };
    e1 = stwo_qm31_mul(e15, e12);
    e12 = stwo_load_qm31(ext_params, 271u);
    e15 = stwo_qm31_add(e12, e1);
    e12 = stwo_load_qm31(ext_params, 272u);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 120u, row_index, 0);
    e1 = StwoCudaQm31{ b48, b61, b61, b61 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e12, e1);
    e1 = stwo_qm31_add(e15, e16);
    e16 = stwo_load_qm31(ext_params, 273u);
    e15 = stwo_qm31_sub(e1, e16);
    e16 = stwo_load_qm31(ext_params, 274u);
    e1 = StwoCudaQm31{ b48, b61, b61, b61 };
    e12 = stwo_qm31_mul(e16, e1);
    e1 = stwo_load_qm31(ext_params, 275u);
    e16 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(ext_params, 276u);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 121u, row_index, 0);
    e12 = StwoCudaQm31{ b49, b61, b61, b61 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 277u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 122u, row_index, 0);
    e16 = StwoCudaQm31{ b50, b61, b61, b61 };
    e1 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e12, e1);
    e1 = stwo_load_qm31(ext_params, 278u);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 123u, row_index, 0);
    e12 = StwoCudaQm31{ b51, b61, b61, b61 };
    e17 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 279u);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 124u, row_index, 0);
    e16 = StwoCudaQm31{ b52, b61, b61, b61 };
    e1 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e12, e1);
    e1 = stwo_load_qm31(ext_params, 280u);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 125u, row_index, 0);
    e12 = StwoCudaQm31{ b53, b61, b61, b61 };
    e17 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 281u);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 126u, row_index, 0);
    e16 = StwoCudaQm31{ b54, b61, b61, b61 };
    e1 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e12, e1);
    e1 = stwo_load_qm31(ext_params, 282u);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 127u, row_index, 0);
    e12 = StwoCudaQm31{ b55, b61, b61, b61 };
    e17 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 283u);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 128u, row_index, 0);
    e16 = StwoCudaQm31{ b56, b61, b61, b61 };
    e1 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e12, e1);
    e1 = stwo_load_qm31(ext_params, 284u);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 129u, row_index, 0);
    e12 = StwoCudaQm31{ b57, b61, b61, b61 };
    e17 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 285u);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 130u, row_index, 0);
    e16 = StwoCudaQm31{ b58, b61, b61, b61 };
    e1 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e12, e1);
    e1 = stwo_load_qm31(ext_params, 286u);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 131u, row_index, 0);
    e12 = StwoCudaQm31{ b59, b61, b61, b61 };
    e17 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 287u);
    e16 = stwo_qm31_sub(e12, e17);
    e17 = stwo_load_qm31(ext_params, 288u);
    unsigned b148 = stwo_m31_add(b143, b110);
    unsigned b149 = base_params[111u];
    unsigned b150 = stwo_m31_add(b148, b149);
    e12 = StwoCudaQm31{ b150, b61, b61, b61 };
    e1 = stwo_qm31_mul(e17, e12);
    e12 = stwo_load_qm31(ext_params, 289u);
    e17 = stwo_qm31_add(e12, e1);
    e12 = stwo_load_qm31(ext_params, 290u);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 132u, row_index, 0);
    e1 = StwoCudaQm31{ b60, b61, b61, b61 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e12, e1);
    e1 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(ext_params, 291u);
    e17 = stwo_qm31_sub(e1, e18);
    e18 = stwo_load_qm31(ext_params, 486u);
    e1 = stwo_qm31_mul(e3, e18);
    e18 = stwo_load_qm31(ext_params, 487u);
    e12 = stwo_qm31_mul(e0, e18);
    e18 = stwo_qm31_add(e1, e12);
    e12 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(ext_params, 488u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 489u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 490u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 491u);
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 492u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(ext_params, 493u);
    e4 = stwo_qm31_mul(e2, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e2, e9);
    e9 = stwo_load_qm31(ext_params, 494u);
    e2 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(ext_params, 495u);
    e6 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e2, e6);
    e6 = stwo_qm31_mul(e8, e11);
    e11 = stwo_load_qm31(ext_params, 496u);
    e8 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(ext_params, 497u);
    e2 = stwo_qm31_mul(e10, e11);
    e11 = stwo_qm31_add(e8, e2);
    e2 = stwo_qm31_mul(e10, e13);
    e13 = stwo_load_qm31(ext_params, 498u);
    e10 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(ext_params, 499u);
    e8 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 500u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(ext_params, 501u);
    e10 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e10);
    e10 = stwo_qm31_mul(e16, e17);
    unsigned b151 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 32u, row_index, 0);
    unsigned b152 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 33u, row_index, 0);
    unsigned b153 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 34u, row_index, 0);
    unsigned b154 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 35u, row_index, 0);
    e17 = StwoCudaQm31{ b151, b152, b153, b154 };
    unsigned b155 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 36u, row_index, 0);
    unsigned b156 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 37u, row_index, 0);
    unsigned b157 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 38u, row_index, 0);
    unsigned b158 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 39u, row_index, 0);
    e16 = StwoCudaQm31{ b155, b156, b157, b158 };
    e14 = stwo_qm31_sub(e16, e17);
    e17 = stwo_qm31_mul(e14, e12);
    e14 = stwo_qm31_sub(e17, e18);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b159 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 40u, row_index, 0);
    unsigned b160 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 41u, row_index, 0);
    unsigned b161 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 42u, row_index, 0);
    unsigned b162 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 43u, row_index, 0);
    e17 = StwoCudaQm31{ b159, b160, b161, b162 };
    e18 = stwo_qm31_sub(e17, e16);
    e16 = stwo_qm31_mul(e18, e1);
    e18 = stwo_qm31_sub(e16, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b163 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 44u, row_index, 0);
    unsigned b164 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 45u, row_index, 0);
    unsigned b165 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 46u, row_index, 0);
    unsigned b166 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 47u, row_index, 0);
    e16 = StwoCudaQm31{ b163, b164, b165, b166 };
    e3 = stwo_qm31_sub(e16, e17);
    e17 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e17, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b167 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 48u, row_index, 0);
    unsigned b168 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 49u, row_index, 0);
    unsigned b169 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 50u, row_index, 0);
    unsigned b170 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 51u, row_index, 0);
    e17 = StwoCudaQm31{ b167, b168, b169, b170 };
    e5 = stwo_qm31_sub(e17, e16);
    e16 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e16, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b171 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 52u, row_index, 0);
    unsigned b172 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 53u, row_index, 0);
    unsigned b173 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 54u, row_index, 0);
    unsigned b174 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 55u, row_index, 0);
    e16 = StwoCudaQm31{ b171, b172, b173, b174 };
    e7 = stwo_qm31_sub(e16, e17);
    e17 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e17, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b175 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 56u, row_index, 0);
    unsigned b176 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 57u, row_index, 0);
    unsigned b177 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 58u, row_index, 0);
    unsigned b178 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 59u, row_index, 0);
    e17 = StwoCudaQm31{ b175, b176, b177, b178 };
    e9 = stwo_qm31_sub(e17, e16);
    e16 = stwo_qm31_mul(e9, e2);
    e9 = stwo_qm31_sub(e16, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b179 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 60u, row_index, 0);
    unsigned b180 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 61u, row_index, 0);
    unsigned b181 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 62u, row_index, 0);
    unsigned b182 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 63u, row_index, 0);
    e16 = StwoCudaQm31{ b179, b180, b181, b182 };
    e11 = stwo_qm31_sub(e16, e17);
    e17 = stwo_qm31_mul(e11, e8);
    e11 = stwo_qm31_sub(e17, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b183 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 64u, row_index, 0);
    unsigned b184 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 65u, row_index, 0);
    unsigned b185 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 66u, row_index, 0);
    unsigned b186 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 67u, row_index, 0);
    e17 = StwoCudaQm31{ b183, b184, b185, b186 };
    e13 = stwo_qm31_sub(e17, e16);
    e17 = stwo_qm31_mul(e13, e10);
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
