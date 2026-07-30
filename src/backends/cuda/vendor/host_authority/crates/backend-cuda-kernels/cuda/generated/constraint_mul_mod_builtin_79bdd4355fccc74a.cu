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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_115954e91d70d46c(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 83u);
    unsigned b47 = base_params[4u];
    unsigned b45 = base_params[3u];
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    unsigned b46 = stwo_m31_mul(b45, b0);
    unsigned b48 = stwo_m31_add(b47, b46);
    unsigned b52 = base_params[15u];
    unsigned b53 = stwo_m31_add(b48, b52);
    unsigned b42 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b53, b42, b42, b42 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 84u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 85u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 55u, row_index, 0);
    e2 = StwoCudaQm31{ b2, b42, b42, b42 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 86u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 87u);
    e2 = StwoCudaQm31{ b2, b42, b42, b42 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 88u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 89u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    e1 = StwoCudaQm31{ b3, b42, b42, b42 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 90u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    e3 = StwoCudaQm31{ b4, b42, b42, b42 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 91u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    e1 = StwoCudaQm31{ b5, b42, b42, b42 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 92u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    e3 = StwoCudaQm31{ b6, b42, b42, b42 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 93u);
    e1 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(ext_params, 94u);
    unsigned b49 = base_params[5u];
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b43 = base_params[2u];
    unsigned b44 = stwo_m31_sub(b1, b43);
    unsigned b50 = stwo_m31_mul(b49, b44);
    unsigned b51 = stwo_m31_add(b48, b50);
    unsigned b54 = base_params[21u];
    unsigned b55 = stwo_m31_add(b51, b54);
    e3 = StwoCudaQm31{ b55, b42, b42, b42 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 95u);
    e2 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(ext_params, 96u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 61u, row_index, 0);
    e4 = StwoCudaQm31{ b7, b42, b42, b42 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(ext_params, 97u);
    e2 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(ext_params, 98u);
    e4 = StwoCudaQm31{ b7, b42, b42, b42 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(ext_params, 99u);
    e5 = stwo_qm31_add(e4, e3);
    e4 = stwo_load_qm31(ext_params, 100u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 62u, row_index, 0);
    e3 = StwoCudaQm31{ b8, b42, b42, b42 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 101u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 63u, row_index, 0);
    e5 = StwoCudaQm31{ b9, b42, b42, b42 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 102u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 64u, row_index, 0);
    e3 = StwoCudaQm31{ b10, b42, b42, b42 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 103u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 65u, row_index, 0);
    e5 = StwoCudaQm31{ b11, b42, b42, b42 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 104u);
    e3 = stwo_qm31_sub(e5, e4);
    e4 = stwo_load_qm31(ext_params, 105u);
    unsigned b56 = base_params[27u];
    unsigned b57 = stwo_m31_add(b48, b56);
    e5 = StwoCudaQm31{ b57, b42, b42, b42 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 106u);
    e4 = stwo_qm31_add(e5, e6);
    e5 = stwo_load_qm31(ext_params, 107u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 67u, row_index, 0);
    e6 = StwoCudaQm31{ b12, b42, b42, b42 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 108u);
    e4 = stwo_qm31_sub(e6, e7);
    e7 = stwo_load_qm31(ext_params, 109u);
    e6 = StwoCudaQm31{ b12, b42, b42, b42 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_load_qm31(ext_params, 110u);
    e7 = stwo_qm31_add(e6, e5);
    e6 = stwo_load_qm31(ext_params, 111u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 68u, row_index, 0);
    e5 = StwoCudaQm31{ b13, b42, b42, b42 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 112u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 69u, row_index, 0);
    e7 = StwoCudaQm31{ b14, b42, b42, b42 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 113u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 70u, row_index, 0);
    e5 = StwoCudaQm31{ b15, b42, b42, b42 };
    e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 114u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 71u, row_index, 0);
    e7 = StwoCudaQm31{ b16, b42, b42, b42 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 115u);
    e5 = stwo_qm31_sub(e7, e6);
    e6 = stwo_load_qm31(ext_params, 116u);
    unsigned b58 = base_params[33u];
    unsigned b59 = stwo_m31_add(b51, b58);
    e7 = StwoCudaQm31{ b59, b42, b42, b42 };
    e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 117u);
    e6 = stwo_qm31_add(e7, e8);
    e7 = stwo_load_qm31(ext_params, 118u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 73u, row_index, 0);
    e8 = StwoCudaQm31{ b17, b42, b42, b42 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(ext_params, 119u);
    e6 = stwo_qm31_sub(e8, e9);
    e9 = stwo_load_qm31(ext_params, 120u);
    e8 = StwoCudaQm31{ b17, b42, b42, b42 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_load_qm31(ext_params, 121u);
    e9 = stwo_qm31_add(e8, e7);
    e8 = stwo_load_qm31(ext_params, 122u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 74u, row_index, 0);
    e7 = StwoCudaQm31{ b18, b42, b42, b42 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 123u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 75u, row_index, 0);
    e9 = StwoCudaQm31{ b19, b42, b42, b42 };
    e8 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 124u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 76u, row_index, 0);
    e7 = StwoCudaQm31{ b20, b42, b42, b42 };
    e10 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 125u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 77u, row_index, 0);
    e9 = StwoCudaQm31{ b21, b42, b42, b42 };
    e8 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 126u);
    e7 = stwo_qm31_sub(e9, e8);
    e8 = stwo_load_qm31(ext_params, 127u);
    unsigned b69 = base_params[53u];
    unsigned b70 = stwo_m31_add(b51, b69);
    e9 = StwoCudaQm31{ b70, b42, b42, b42 };
    e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 128u);
    e8 = stwo_qm31_add(e9, e10);
    e9 = stwo_load_qm31(ext_params, 129u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 79u, row_index, 0);
    e10 = StwoCudaQm31{ b22, b42, b42, b42 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 130u);
    e8 = stwo_qm31_sub(e10, e11);
    e11 = stwo_load_qm31(ext_params, 131u);
    e10 = StwoCudaQm31{ b51, b42, b42, b42 };
    e9 = stwo_qm31_mul(e11, e10);
    e10 = stwo_load_qm31(ext_params, 132u);
    e11 = stwo_qm31_add(e10, e9);
    e10 = stwo_load_qm31(ext_params, 133u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 80u, row_index, 0);
    e9 = StwoCudaQm31{ b23, b42, b42, b42 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 134u);
    e11 = stwo_qm31_sub(e9, e12);
    e12 = stwo_load_qm31(ext_params, 135u);
    unsigned b71 = base_params[54u];
    unsigned b72 = stwo_m31_add(b51, b71);
    e9 = StwoCudaQm31{ b72, b42, b42, b42 };
    e10 = stwo_qm31_mul(e12, e9);
    e9 = stwo_load_qm31(ext_params, 136u);
    e12 = stwo_qm31_add(e9, e10);
    e9 = stwo_load_qm31(ext_params, 137u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 81u, row_index, 0);
    e10 = StwoCudaQm31{ b24, b42, b42, b42 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 138u);
    e12 = stwo_qm31_sub(e10, e13);
    e13 = stwo_load_qm31(ext_params, 139u);
    unsigned b73 = base_params[55u];
    unsigned b74 = stwo_m31_add(b51, b73);
    e10 = StwoCudaQm31{ b74, b42, b42, b42 };
    e9 = stwo_qm31_mul(e13, e10);
    e10 = stwo_load_qm31(ext_params, 140u);
    e13 = stwo_qm31_add(e10, e9);
    e10 = stwo_load_qm31(ext_params, 141u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 82u, row_index, 0);
    e9 = StwoCudaQm31{ b25, b42, b42, b42 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(ext_params, 142u);
    e13 = stwo_qm31_sub(e9, e14);
    e14 = stwo_load_qm31(ext_params, 143u);
    unsigned b75 = base_params[56u];
    unsigned b76 = stwo_m31_add(b51, b75);
    e9 = StwoCudaQm31{ b76, b42, b42, b42 };
    e10 = stwo_qm31_mul(e14, e9);
    e9 = stwo_load_qm31(ext_params, 144u);
    e14 = stwo_qm31_add(e9, e10);
    e9 = stwo_load_qm31(ext_params, 145u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 83u, row_index, 0);
    e10 = StwoCudaQm31{ b26, b42, b42, b42 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 146u);
    e14 = stwo_qm31_sub(e10, e15);
    e15 = stwo_load_qm31(ext_params, 147u);
    unsigned b60 = base_params[43u];
    unsigned b61 = stwo_m31_mul(b4, b60);
    unsigned b62 = stwo_m31_add(b3, b61);
    unsigned b63 = base_params[44u];
    unsigned b64 = stwo_m31_mul(b5, b63);
    unsigned b65 = stwo_m31_add(b62, b64);
    unsigned b66 = base_params[45u];
    unsigned b67 = stwo_m31_mul(b6, b66);
    unsigned b68 = stwo_m31_add(b65, b67);
    e10 = StwoCudaQm31{ b68, b42, b42, b42 };
    e9 = stwo_qm31_mul(e15, e10);
    e10 = stwo_load_qm31(ext_params, 148u);
    e15 = stwo_qm31_add(e10, e9);
    e10 = stwo_load_qm31(ext_params, 149u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 84u, row_index, 0);
    e9 = StwoCudaQm31{ b27, b42, b42, b42 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e15, e16);
    e16 = stwo_load_qm31(ext_params, 150u);
    e15 = stwo_qm31_sub(e9, e16);
    e16 = stwo_load_qm31(ext_params, 151u);
    e9 = StwoCudaQm31{ b27, b42, b42, b42 };
    e10 = stwo_qm31_mul(e16, e9);
    e9 = stwo_load_qm31(ext_params, 152u);
    e16 = stwo_qm31_add(e9, e10);
    e9 = stwo_load_qm31(ext_params, 153u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 87u, row_index, 0);
    e10 = StwoCudaQm31{ b30, b42, b42, b42 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 154u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 88u, row_index, 0);
    e16 = StwoCudaQm31{ b31, b42, b42, b42 };
    e9 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 155u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 89u, row_index, 0);
    e10 = StwoCudaQm31{ b32, b42, b42, b42 };
    e17 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 156u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 90u, row_index, 0);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 86u, row_index, 0);
    unsigned b77 = base_params[60u];
    unsigned b78 = stwo_m31_mul(b29, b77);
    unsigned b86 = stwo_m31_add(b33, b78);
    e16 = StwoCudaQm31{ b86, b42, b42, b42 };
    e9 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 157u);
    unsigned b79 = base_params[61u];
    unsigned b80 = stwo_m31_mul(b29, b79);
    e10 = StwoCudaQm31{ b80, b42, b42, b42 };
    e17 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 158u);
    e16 = StwoCudaQm31{ b80, b42, b42, b42 };
    e9 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 159u);
    e10 = StwoCudaQm31{ b80, b42, b42, b42 };
    e17 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 160u);
    e16 = StwoCudaQm31{ b80, b42, b42, b42 };
    e9 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 161u);
    e10 = StwoCudaQm31{ b80, b42, b42, b42 };
    e17 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 162u);
    e16 = StwoCudaQm31{ b80, b42, b42, b42 };
    e9 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 163u);
    e10 = StwoCudaQm31{ b80, b42, b42, b42 };
    e17 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 164u);
    e16 = StwoCudaQm31{ b80, b42, b42, b42 };
    e9 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 165u);
    e10 = StwoCudaQm31{ b80, b42, b42, b42 };
    e17 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 166u);
    e16 = StwoCudaQm31{ b80, b42, b42, b42 };
    e9 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 167u);
    e10 = StwoCudaQm31{ b80, b42, b42, b42 };
    e17 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 168u);
    e16 = StwoCudaQm31{ b80, b42, b42, b42 };
    e9 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 169u);
    e10 = StwoCudaQm31{ b80, b42, b42, b42 };
    e17 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 170u);
    e16 = StwoCudaQm31{ b80, b42, b42, b42 };
    e9 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 171u);
    e10 = StwoCudaQm31{ b80, b42, b42, b42 };
    e17 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 172u);
    e16 = StwoCudaQm31{ b80, b42, b42, b42 };
    e9 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 173u);
    e10 = StwoCudaQm31{ b80, b42, b42, b42 };
    e17 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 174u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 85u, row_index, 0);
    unsigned b81 = base_params[62u];
    unsigned b82 = stwo_m31_mul(b28, b81);
    unsigned b83 = stwo_m31_sub(b82, b29);
    e16 = StwoCudaQm31{ b83, b42, b42, b42 };
    e9 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 175u);
    e10 = stwo_qm31_add(e16, e9);
    e9 = stwo_load_qm31(ext_params, 176u);
    e16 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 177u);
    e10 = stwo_qm31_add(e16, e9);
    e9 = stwo_load_qm31(ext_params, 178u);
    e16 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 179u);
    e10 = stwo_qm31_add(e16, e9);
    e9 = stwo_load_qm31(ext_params, 180u);
    unsigned b84 = base_params[63u];
    unsigned b85 = stwo_m31_mul(b28, b84);
    e16 = StwoCudaQm31{ b85, b42, b42, b42 };
    e17 = stwo_qm31_mul(e9, e16);
    e16 = stwo_qm31_add(e10, e17);
    e17 = stwo_load_qm31(ext_params, 181u);
    e10 = stwo_qm31_sub(e16, e17);
    e17 = stwo_load_qm31(ext_params, 182u);
    unsigned b87 = base_params[73u];
    unsigned b88 = stwo_m31_add(b68, b87);
    e16 = StwoCudaQm31{ b88, b42, b42, b42 };
    e9 = stwo_qm31_mul(e17, e16);
    e16 = stwo_load_qm31(ext_params, 183u);
    e17 = stwo_qm31_add(e16, e9);
    e16 = stwo_load_qm31(ext_params, 184u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 92u, row_index, 0);
    e9 = StwoCudaQm31{ b34, b42, b42, b42 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e16, e9);
    e9 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(ext_params, 185u);
    e17 = stwo_qm31_sub(e9, e18);
    e18 = stwo_load_qm31(ext_params, 186u);
    e9 = StwoCudaQm31{ b34, b42, b42, b42 };
    e16 = stwo_qm31_mul(e18, e9);
    e9 = stwo_load_qm31(ext_params, 187u);
    e18 = stwo_qm31_add(e9, e16);
    e9 = stwo_load_qm31(ext_params, 188u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 95u, row_index, 0);
    e16 = StwoCudaQm31{ b37, b42, b42, b42 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e9, e16);
    e16 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(ext_params, 189u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 96u, row_index, 0);
    e18 = StwoCudaQm31{ b38, b42, b42, b42 };
    e9 = stwo_qm31_mul(e19, e18);
    e18 = stwo_qm31_add(e16, e9);
    e9 = stwo_load_qm31(ext_params, 190u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 97u, row_index, 0);
    e16 = StwoCudaQm31{ b39, b42, b42, b42 };
    e19 = stwo_qm31_mul(e9, e16);
    e16 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(ext_params, 191u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 98u, row_index, 0);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 94u, row_index, 0);
    unsigned b89 = base_params[77u];
    unsigned b90 = stwo_m31_mul(b36, b89);
    unsigned b98 = stwo_m31_add(b40, b90);
    e18 = StwoCudaQm31{ b98, b42, b42, b42 };
    e9 = stwo_qm31_mul(e19, e18);
    e18 = stwo_qm31_add(e16, e9);
    e9 = stwo_load_qm31(ext_params, 192u);
    unsigned b91 = base_params[78u];
    unsigned b92 = stwo_m31_mul(b36, b91);
    e16 = StwoCudaQm31{ b92, b42, b42, b42 };
    e19 = stwo_qm31_mul(e9, e16);
    e16 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(ext_params, 193u);
    e18 = StwoCudaQm31{ b92, b42, b42, b42 };
    e9 = stwo_qm31_mul(e19, e18);
    e18 = stwo_qm31_add(e16, e9);
    e9 = stwo_load_qm31(ext_params, 194u);
    e16 = StwoCudaQm31{ b92, b42, b42, b42 };
    e19 = stwo_qm31_mul(e9, e16);
    e16 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(ext_params, 195u);
    e18 = StwoCudaQm31{ b92, b42, b42, b42 };
    e9 = stwo_qm31_mul(e19, e18);
    e18 = stwo_qm31_add(e16, e9);
    e9 = stwo_load_qm31(ext_params, 196u);
    e16 = StwoCudaQm31{ b92, b42, b42, b42 };
    e19 = stwo_qm31_mul(e9, e16);
    e16 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(ext_params, 197u);
    e18 = StwoCudaQm31{ b92, b42, b42, b42 };
    e9 = stwo_qm31_mul(e19, e18);
    e18 = stwo_qm31_add(e16, e9);
    e9 = stwo_load_qm31(ext_params, 198u);
    e16 = StwoCudaQm31{ b92, b42, b42, b42 };
    e19 = stwo_qm31_mul(e9, e16);
    e16 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(ext_params, 199u);
    e18 = StwoCudaQm31{ b92, b42, b42, b42 };
    e9 = stwo_qm31_mul(e19, e18);
    e18 = stwo_qm31_add(e16, e9);
    e9 = stwo_load_qm31(ext_params, 200u);
    e16 = StwoCudaQm31{ b92, b42, b42, b42 };
    e19 = stwo_qm31_mul(e9, e16);
    e16 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(ext_params, 201u);
    e18 = StwoCudaQm31{ b92, b42, b42, b42 };
    e9 = stwo_qm31_mul(e19, e18);
    e18 = stwo_qm31_add(e16, e9);
    e9 = stwo_load_qm31(ext_params, 202u);
    e16 = StwoCudaQm31{ b92, b42, b42, b42 };
    e19 = stwo_qm31_mul(e9, e16);
    e16 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(ext_params, 203u);
    e18 = StwoCudaQm31{ b92, b42, b42, b42 };
    e9 = stwo_qm31_mul(e19, e18);
    e18 = stwo_qm31_add(e16, e9);
    e9 = stwo_load_qm31(ext_params, 204u);
    e16 = StwoCudaQm31{ b92, b42, b42, b42 };
    e19 = stwo_qm31_mul(e9, e16);
    e16 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(ext_params, 205u);
    e18 = StwoCudaQm31{ b92, b42, b42, b42 };
    e9 = stwo_qm31_mul(e19, e18);
    e18 = stwo_qm31_add(e16, e9);
    e9 = stwo_load_qm31(ext_params, 206u);
    e16 = StwoCudaQm31{ b92, b42, b42, b42 };
    e19 = stwo_qm31_mul(e9, e16);
    e16 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(ext_params, 207u);
    e18 = StwoCudaQm31{ b92, b42, b42, b42 };
    e9 = stwo_qm31_mul(e19, e18);
    e18 = stwo_qm31_add(e16, e9);
    e9 = stwo_load_qm31(ext_params, 208u);
    e16 = StwoCudaQm31{ b92, b42, b42, b42 };
    e19 = stwo_qm31_mul(e9, e16);
    e16 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(ext_params, 209u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 93u, row_index, 0);
    unsigned b93 = base_params[79u];
    unsigned b94 = stwo_m31_mul(b35, b93);
    unsigned b95 = stwo_m31_sub(b94, b36);
    e18 = StwoCudaQm31{ b95, b42, b42, b42 };
    e9 = stwo_qm31_mul(e19, e18);
    e18 = stwo_qm31_add(e16, e9);
    e9 = stwo_load_qm31(ext_params, 210u);
    e16 = stwo_qm31_add(e18, e9);
    e9 = stwo_load_qm31(ext_params, 211u);
    e18 = stwo_qm31_add(e16, e9);
    e9 = stwo_load_qm31(ext_params, 212u);
    e16 = stwo_qm31_add(e18, e9);
    e9 = stwo_load_qm31(ext_params, 213u);
    e18 = stwo_qm31_add(e16, e9);
    e9 = stwo_load_qm31(ext_params, 214u);
    e16 = stwo_qm31_add(e18, e9);
    e9 = stwo_load_qm31(ext_params, 215u);
    unsigned b96 = base_params[80u];
    unsigned b97 = stwo_m31_mul(b35, b96);
    e18 = StwoCudaQm31{ b97, b42, b42, b42 };
    e19 = stwo_qm31_mul(e9, e18);
    e18 = stwo_qm31_add(e16, e19);
    e19 = stwo_load_qm31(ext_params, 216u);
    e16 = stwo_qm31_sub(e18, e19);
    e19 = stwo_load_qm31(ext_params, 217u);
    unsigned b99 = base_params[90u];
    unsigned b100 = stwo_m31_add(b68, b99);
    e18 = StwoCudaQm31{ b100, b42, b42, b42 };
    e9 = stwo_qm31_mul(e19, e18);
    e18 = stwo_load_qm31(ext_params, 218u);
    e19 = stwo_qm31_add(e18, e9);
    e18 = stwo_load_qm31(ext_params, 219u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 100u, row_index, 0);
    e9 = StwoCudaQm31{ b41, b42, b42, b42 };
    StwoCudaQm31 e20 = stwo_qm31_mul(e18, e9);
    e9 = stwo_qm31_add(e19, e20);
    e20 = stwo_load_qm31(ext_params, 220u);
    e19 = stwo_qm31_sub(e9, e20);
    e20 = stwo_load_qm31(ext_params, 1000u);
    e9 = stwo_qm31_mul(e1, e20);
    e20 = stwo_load_qm31(ext_params, 1001u);
    e18 = stwo_qm31_mul(e0, e20);
    e20 = stwo_qm31_add(e9, e18);
    e18 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 1002u);
    e0 = stwo_qm31_mul(e3, e1);
    e1 = stwo_load_qm31(ext_params, 1003u);
    e9 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e0, e9);
    e9 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 1004u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 1005u);
    e0 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e0);
    e0 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 1006u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 1007u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 1008u);
    e6 = stwo_qm31_mul(e11, e7);
    e7 = stwo_load_qm31(ext_params, 1009u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e11);
    e11 = stwo_load_qm31(ext_params, 1010u);
    e8 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(ext_params, 1011u);
    e6 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(ext_params, 1012u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(ext_params, 1013u);
    e8 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e8);
    e8 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 1014u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(ext_params, 1015u);
    e12 = stwo_qm31_mul(e10, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e10, e17);
    e17 = stwo_load_qm31(ext_params, 1016u);
    e10 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(ext_params, 1017u);
    e14 = stwo_qm31_mul(e16, e17);
    e17 = stwo_qm31_add(e10, e14);
    e14 = stwo_qm31_mul(e16, e19);
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, 0);
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, 0);
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, 0);
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, 0);
    e19 = StwoCudaQm31{ b101, b102, b103, b104 };
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 20u, row_index, 0);
    unsigned b106 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 21u, row_index, 0);
    unsigned b107 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 22u, row_index, 0);
    unsigned b108 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 23u, row_index, 0);
    e16 = StwoCudaQm31{ b105, b106, b107, b108 };
    e10 = stwo_qm31_sub(e16, e19);
    e19 = stwo_qm31_mul(e10, e18);
    e10 = stwo_qm31_sub(e19, e20);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b109 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 24u, row_index, 0);
    unsigned b110 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 25u, row_index, 0);
    unsigned b111 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 26u, row_index, 0);
    unsigned b112 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 27u, row_index, 0);
    e19 = StwoCudaQm31{ b109, b110, b111, b112 };
    e20 = stwo_qm31_sub(e19, e16);
    e16 = stwo_qm31_mul(e20, e9);
    e20 = stwo_qm31_sub(e16, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e20, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b113 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 28u, row_index, 0);
    unsigned b114 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 29u, row_index, 0);
    unsigned b115 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 30u, row_index, 0);
    unsigned b116 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 31u, row_index, 0);
    e16 = StwoCudaQm31{ b113, b114, b115, b116 };
    e1 = stwo_qm31_sub(e16, e19);
    e19 = stwo_qm31_mul(e1, e0);
    e1 = stwo_qm31_sub(e19, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b117 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 32u, row_index, 0);
    unsigned b118 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 33u, row_index, 0);
    unsigned b119 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 34u, row_index, 0);
    unsigned b120 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 35u, row_index, 0);
    e19 = StwoCudaQm31{ b117, b118, b119, b120 };
    e3 = stwo_qm31_sub(e19, e16);
    e16 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e16, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b121 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 36u, row_index, 0);
    unsigned b122 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 37u, row_index, 0);
    unsigned b123 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 38u, row_index, 0);
    unsigned b124 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 39u, row_index, 0);
    e16 = StwoCudaQm31{ b121, b122, b123, b124 };
    e5 = stwo_qm31_sub(e16, e19);
    e19 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e19, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b125 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 40u, row_index, 0);
    unsigned b126 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 41u, row_index, 0);
    unsigned b127 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 42u, row_index, 0);
    unsigned b128 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 43u, row_index, 0);
    e19 = StwoCudaQm31{ b125, b126, b127, b128 };
    e7 = stwo_qm31_sub(e19, e16);
    e16 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e16, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b129 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 44u, row_index, 0);
    unsigned b130 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 45u, row_index, 0);
    unsigned b131 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 46u, row_index, 0);
    unsigned b132 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 47u, row_index, 0);
    e16 = StwoCudaQm31{ b129, b130, b131, b132 };
    e11 = stwo_qm31_sub(e16, e19);
    e19 = stwo_qm31_mul(e11, e8);
    e11 = stwo_qm31_sub(e19, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b133 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 48u, row_index, 0);
    unsigned b134 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 49u, row_index, 0);
    unsigned b135 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 50u, row_index, 0);
    unsigned b136 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 51u, row_index, 0);
    e19 = StwoCudaQm31{ b133, b134, b135, b136 };
    e13 = stwo_qm31_sub(e19, e16);
    e16 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e16, e15);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b137 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 52u, row_index, 0);
    unsigned b138 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 53u, row_index, 0);
    unsigned b139 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 54u, row_index, 0);
    unsigned b140 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 55u, row_index, 0);
    e16 = StwoCudaQm31{ b137, b138, b139, b140 };
    e15 = stwo_qm31_sub(e16, e19);
    e16 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e16, e17);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
