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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_253be2dca1403a6c(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 105u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    unsigned b61 = base_params[0u];
    unsigned b62 = stwo_m31_mul(b0, b61);
    unsigned b63 = base_params[1u];
    unsigned b64 = stwo_m31_add(b62, b63);
    unsigned b66 = base_params[5u];
    unsigned b67 = stwo_m31_add(b64, b66);
    unsigned b65 = base_params[2u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b67, b65, b65, b65 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 106u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 107u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 87u, row_index, 0);
    e2 = StwoCudaQm31{ b1, b65, b65, b65 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 108u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 109u);
    e2 = StwoCudaQm31{ b1, b65, b65, b65 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 110u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 111u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 88u, row_index, 0);
    e1 = StwoCudaQm31{ b2, b65, b65, b65 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 112u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 89u, row_index, 0);
    e3 = StwoCudaQm31{ b3, b65, b65, b65 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 113u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 90u, row_index, 0);
    e1 = StwoCudaQm31{ b4, b65, b65, b65 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 114u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 91u, row_index, 0);
    e3 = StwoCudaQm31{ b5, b65, b65, b65 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 115u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 92u, row_index, 0);
    e1 = StwoCudaQm31{ b6, b65, b65, b65 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 116u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 93u, row_index, 0);
    e3 = StwoCudaQm31{ b7, b65, b65, b65 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 117u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 94u, row_index, 0);
    e1 = StwoCudaQm31{ b8, b65, b65, b65 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 118u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 95u, row_index, 0);
    e3 = StwoCudaQm31{ b9, b65, b65, b65 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 119u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 96u, row_index, 0);
    e1 = StwoCudaQm31{ b10, b65, b65, b65 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 120u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 97u, row_index, 0);
    e3 = StwoCudaQm31{ b11, b65, b65, b65 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 121u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 98u, row_index, 0);
    e1 = StwoCudaQm31{ b12, b65, b65, b65 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 122u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 99u, row_index, 0);
    e3 = StwoCudaQm31{ b13, b65, b65, b65 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 123u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 100u, row_index, 0);
    e1 = StwoCudaQm31{ b14, b65, b65, b65 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 124u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 101u, row_index, 0);
    e3 = StwoCudaQm31{ b15, b65, b65, b65 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 125u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 102u, row_index, 0);
    e1 = StwoCudaQm31{ b16, b65, b65, b65 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 126u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 103u, row_index, 0);
    e3 = StwoCudaQm31{ b17, b65, b65, b65 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 127u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 104u, row_index, 0);
    e1 = StwoCudaQm31{ b18, b65, b65, b65 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 128u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 105u, row_index, 0);
    e3 = StwoCudaQm31{ b19, b65, b65, b65 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 129u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 106u, row_index, 0);
    e1 = StwoCudaQm31{ b20, b65, b65, b65 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 130u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 107u, row_index, 0);
    e3 = StwoCudaQm31{ b21, b65, b65, b65 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 131u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 108u, row_index, 0);
    e1 = StwoCudaQm31{ b22, b65, b65, b65 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 132u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 109u, row_index, 0);
    e3 = StwoCudaQm31{ b23, b65, b65, b65 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 133u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 110u, row_index, 0);
    e1 = StwoCudaQm31{ b24, b65, b65, b65 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 134u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 111u, row_index, 0);
    e3 = StwoCudaQm31{ b25, b65, b65, b65 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 135u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 112u, row_index, 0);
    e1 = StwoCudaQm31{ b26, b65, b65, b65 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 136u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 113u, row_index, 0);
    e3 = StwoCudaQm31{ b27, b65, b65, b65 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 137u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 114u, row_index, 0);
    e1 = StwoCudaQm31{ b28, b65, b65, b65 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 138u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 115u, row_index, 0);
    e3 = StwoCudaQm31{ b29, b65, b65, b65 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 139u);
    e1 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(ext_params, 140u);
    unsigned b68 = base_params[6u];
    unsigned b69 = stwo_m31_add(b64, b68);
    e3 = StwoCudaQm31{ b69, b65, b65, b65 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 141u);
    e2 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(ext_params, 142u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 116u, row_index, 0);
    e4 = StwoCudaQm31{ b30, b65, b65, b65 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(ext_params, 143u);
    e2 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(ext_params, 144u);
    e4 = StwoCudaQm31{ b30, b65, b65, b65 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(ext_params, 145u);
    e5 = stwo_qm31_add(e4, e3);
    e4 = stwo_load_qm31(ext_params, 146u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 117u, row_index, 0);
    e3 = StwoCudaQm31{ b31, b65, b65, b65 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 147u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 118u, row_index, 0);
    e5 = StwoCudaQm31{ b32, b65, b65, b65 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 148u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 119u, row_index, 0);
    e3 = StwoCudaQm31{ b33, b65, b65, b65 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 149u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 120u, row_index, 0);
    e5 = StwoCudaQm31{ b34, b65, b65, b65 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 150u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 121u, row_index, 0);
    e3 = StwoCudaQm31{ b35, b65, b65, b65 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 151u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 122u, row_index, 0);
    e5 = StwoCudaQm31{ b36, b65, b65, b65 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 152u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 123u, row_index, 0);
    e3 = StwoCudaQm31{ b37, b65, b65, b65 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 153u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 124u, row_index, 0);
    e5 = StwoCudaQm31{ b38, b65, b65, b65 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 154u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 125u, row_index, 0);
    e3 = StwoCudaQm31{ b39, b65, b65, b65 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 155u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 126u, row_index, 0);
    e5 = StwoCudaQm31{ b40, b65, b65, b65 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 156u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 127u, row_index, 0);
    e3 = StwoCudaQm31{ b41, b65, b65, b65 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 157u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 128u, row_index, 0);
    e5 = StwoCudaQm31{ b42, b65, b65, b65 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 158u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 129u, row_index, 0);
    e3 = StwoCudaQm31{ b43, b65, b65, b65 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 159u);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 130u, row_index, 0);
    e5 = StwoCudaQm31{ b44, b65, b65, b65 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 160u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 131u, row_index, 0);
    e3 = StwoCudaQm31{ b45, b65, b65, b65 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 161u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 132u, row_index, 0);
    e5 = StwoCudaQm31{ b46, b65, b65, b65 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 162u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 133u, row_index, 0);
    e3 = StwoCudaQm31{ b47, b65, b65, b65 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 163u);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 134u, row_index, 0);
    e5 = StwoCudaQm31{ b48, b65, b65, b65 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 164u);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 135u, row_index, 0);
    e3 = StwoCudaQm31{ b49, b65, b65, b65 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 165u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 136u, row_index, 0);
    e5 = StwoCudaQm31{ b50, b65, b65, b65 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 166u);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 137u, row_index, 0);
    e3 = StwoCudaQm31{ b51, b65, b65, b65 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 167u);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 138u, row_index, 0);
    e5 = StwoCudaQm31{ b52, b65, b65, b65 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 168u);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 139u, row_index, 0);
    e3 = StwoCudaQm31{ b53, b65, b65, b65 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 169u);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 140u, row_index, 0);
    e5 = StwoCudaQm31{ b54, b65, b65, b65 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 170u);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 141u, row_index, 0);
    e3 = StwoCudaQm31{ b55, b65, b65, b65 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 171u);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 142u, row_index, 0);
    e5 = StwoCudaQm31{ b56, b65, b65, b65 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 172u);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 143u, row_index, 0);
    e3 = StwoCudaQm31{ b57, b65, b65, b65 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 173u);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 144u, row_index, 0);
    e5 = StwoCudaQm31{ b58, b65, b65, b65 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 174u);
    e3 = stwo_qm31_sub(e5, e4);
    e4 = stwo_load_qm31(ext_params, 175u);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 145u, row_index, 0);
    unsigned b70 = stwo_m31_sub(b58, b59);
    e5 = StwoCudaQm31{ b70, b65, b65, b65 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 176u);
    e4 = stwo_qm31_add(e5, e6);
    e5 = stwo_load_qm31(ext_params, 177u);
    e6 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(ext_params, 178u);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 147u, row_index, 0);
    e4 = StwoCudaQm31{ b60, b65, b65, b65 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(ext_params, 179u);
    e5 = stwo_qm31_add(e4, e7);
    e4 = stwo_load_qm31(ext_params, 180u);
    e7 = stwo_qm31_sub(e5, e4);
    e4 = stwo_load_qm31(ext_params, 511u);
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_load_qm31(ext_params, 512u);
    StwoCudaQm31 e8 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e5, e8);
    e8 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 513u);
    e0 = stwo_qm31_mul(e3, e1);
    e1 = stwo_load_qm31(ext_params, 514u);
    e5 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e0, e5);
    e5 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 515u);
    e2 = stwo_qm31_mul(e7, e3);
    e3 = stwo_load_qm31(ext_params, 516u);
    e0 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e2, e0);
    e0 = stwo_qm31_mul(e6, e7);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e7 = StwoCudaQm31{ b71, b72, b73, b74 };
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e6 = StwoCudaQm31{ b75, b76, b77, b78 };
    e2 = stwo_qm31_sub(e6, e7);
    e7 = stwo_qm31_mul(e2, e8);
    e2 = stwo_qm31_sub(e7, e4);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, 0);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, 0);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, 0);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, 0);
    e7 = StwoCudaQm31{ b79, b80, b81, b82 };
    e4 = stwo_qm31_sub(e7, e6);
    e6 = stwo_qm31_mul(e4, e5);
    e4 = stwo_qm31_sub(e6, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 20u, row_index, 0);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 21u, row_index, 0);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 22u, row_index, 0);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 23u, row_index, 0);
    e6 = StwoCudaQm31{ b83, b84, b85, b86 };
    e1 = stwo_qm31_sub(e6, e7);
    e6 = stwo_qm31_mul(e1, e0);
    e1 = stwo_qm31_sub(e6, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
