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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_af1735c3d12045b1(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 221u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 100u, row_index, 0);
    unsigned b96 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b16, b96, b96, b96 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 222u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 223u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 103u, row_index, 0);
    e2 = StwoCudaQm31{ b19, b96, b96, b96 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 224u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 104u, row_index, 0);
    e0 = StwoCudaQm31{ b20, b96, b96, b96 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 225u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 105u, row_index, 0);
    e2 = StwoCudaQm31{ b21, b96, b96, b96 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 226u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 106u, row_index, 0);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 102u, row_index, 0);
    unsigned b123 = base_params[94u];
    unsigned b124 = stwo_m31_mul(b18, b123);
    unsigned b132 = stwo_m31_add(b22, b124);
    e0 = StwoCudaQm31{ b132, b96, b96, b96 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 227u);
    unsigned b125 = base_params[95u];
    unsigned b126 = stwo_m31_mul(b18, b125);
    e2 = StwoCudaQm31{ b126, b96, b96, b96 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 228u);
    e0 = StwoCudaQm31{ b126, b96, b96, b96 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 229u);
    e2 = StwoCudaQm31{ b126, b96, b96, b96 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 230u);
    e0 = StwoCudaQm31{ b126, b96, b96, b96 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 231u);
    e2 = StwoCudaQm31{ b126, b96, b96, b96 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 232u);
    e0 = StwoCudaQm31{ b126, b96, b96, b96 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 233u);
    e2 = StwoCudaQm31{ b126, b96, b96, b96 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 234u);
    e0 = StwoCudaQm31{ b126, b96, b96, b96 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 235u);
    e2 = StwoCudaQm31{ b126, b96, b96, b96 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 236u);
    e0 = StwoCudaQm31{ b126, b96, b96, b96 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 237u);
    e2 = StwoCudaQm31{ b126, b96, b96, b96 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 238u);
    e0 = StwoCudaQm31{ b126, b96, b96, b96 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 239u);
    e2 = StwoCudaQm31{ b126, b96, b96, b96 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 240u);
    e0 = StwoCudaQm31{ b126, b96, b96, b96 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 241u);
    e2 = StwoCudaQm31{ b126, b96, b96, b96 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 242u);
    e0 = StwoCudaQm31{ b126, b96, b96, b96 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 243u);
    e2 = StwoCudaQm31{ b126, b96, b96, b96 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 244u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 101u, row_index, 0);
    unsigned b127 = base_params[96u];
    unsigned b128 = stwo_m31_mul(b17, b127);
    unsigned b129 = stwo_m31_sub(b128, b18);
    e0 = StwoCudaQm31{ b129, b96, b96, b96 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 245u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 246u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 247u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 248u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 249u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 250u);
    unsigned b130 = base_params[97u];
    unsigned b131 = stwo_m31_mul(b17, b130);
    e0 = StwoCudaQm31{ b131, b96, b96, b96 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(ext_params, 251u);
    e2 = stwo_qm31_sub(e0, e3);
    e3 = stwo_load_qm31(ext_params, 252u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    unsigned b133 = base_params[107u];
    unsigned b134 = stwo_m31_mul(b1, b133);
    unsigned b135 = stwo_m31_add(b0, b134);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    unsigned b136 = base_params[108u];
    unsigned b137 = stwo_m31_mul(b2, b136);
    unsigned b138 = stwo_m31_add(b135, b137);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    unsigned b139 = base_params[109u];
    unsigned b140 = stwo_m31_mul(b3, b139);
    unsigned b141 = stwo_m31_add(b138, b140);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 87u, row_index, 0);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 88u, row_index, 0);
    unsigned b97 = base_params[69u];
    unsigned b98 = stwo_m31_mul(b7, b97);
    unsigned b99 = stwo_m31_add(b6, b98);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 89u, row_index, 0);
    unsigned b100 = base_params[70u];
    unsigned b101 = stwo_m31_mul(b8, b100);
    unsigned b102 = stwo_m31_add(b99, b101);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 90u, row_index, 0);
    unsigned b103 = base_params[71u];
    unsigned b104 = stwo_m31_mul(b9, b103);
    unsigned b105 = stwo_m31_add(b102, b104);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 85u, row_index, 0);
    unsigned b106 = stwo_m31_sub(b105, b4);
    unsigned b107 = base_params[72u];
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 86u, row_index, 0);
    unsigned b108 = stwo_m31_mul(b107, b5);
    unsigned b109 = stwo_m31_sub(b106, b108);
    unsigned b142 = stwo_m31_add(b141, b109);
    e0 = StwoCudaQm31{ b142, b96, b96, b96 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_load_qm31(ext_params, 253u);
    e3 = stwo_qm31_add(e0, e1);
    e0 = stwo_load_qm31(ext_params, 254u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 108u, row_index, 0);
    e1 = StwoCudaQm31{ b23, b96, b96, b96 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 255u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 256u);
    e1 = StwoCudaQm31{ b23, b96, b96, b96 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 257u);
    e4 = stwo_qm31_add(e1, e0);
    e1 = stwo_load_qm31(ext_params, 258u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 109u, row_index, 0);
    e0 = StwoCudaQm31{ b24, b96, b96, b96 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 259u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 110u, row_index, 0);
    e4 = StwoCudaQm31{ b25, b96, b96, b96 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 260u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 111u, row_index, 0);
    e0 = StwoCudaQm31{ b26, b96, b96, b96 };
    e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 261u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 112u, row_index, 0);
    e4 = StwoCudaQm31{ b27, b96, b96, b96 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 262u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 113u, row_index, 0);
    e0 = StwoCudaQm31{ b28, b96, b96, b96 };
    e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 263u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 114u, row_index, 0);
    e4 = StwoCudaQm31{ b29, b96, b96, b96 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 264u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 115u, row_index, 0);
    e0 = StwoCudaQm31{ b30, b96, b96, b96 };
    e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 265u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 116u, row_index, 0);
    e4 = StwoCudaQm31{ b31, b96, b96, b96 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 266u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 117u, row_index, 0);
    e0 = StwoCudaQm31{ b32, b96, b96, b96 };
    e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 267u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 118u, row_index, 0);
    e4 = StwoCudaQm31{ b33, b96, b96, b96 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 268u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 119u, row_index, 0);
    e0 = StwoCudaQm31{ b34, b96, b96, b96 };
    e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 269u);
    e4 = stwo_qm31_sub(e0, e5);
    e5 = stwo_load_qm31(ext_params, 270u);
    unsigned b143 = stwo_m31_add(b141, b109);
    unsigned b144 = base_params[110u];
    unsigned b145 = stwo_m31_add(b143, b144);
    e0 = StwoCudaQm31{ b145, b96, b96, b96 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_load_qm31(ext_params, 271u);
    e5 = stwo_qm31_add(e0, e1);
    e0 = stwo_load_qm31(ext_params, 272u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 120u, row_index, 0);
    e1 = StwoCudaQm31{ b35, b96, b96, b96 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e0, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 273u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(ext_params, 274u);
    e1 = StwoCudaQm31{ b35, b96, b96, b96 };
    e0 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(ext_params, 275u);
    e6 = stwo_qm31_add(e1, e0);
    e1 = stwo_load_qm31(ext_params, 276u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 121u, row_index, 0);
    e0 = StwoCudaQm31{ b36, b96, b96, b96 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 277u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 122u, row_index, 0);
    e6 = StwoCudaQm31{ b37, b96, b96, b96 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 278u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 123u, row_index, 0);
    e0 = StwoCudaQm31{ b38, b96, b96, b96 };
    e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 279u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 124u, row_index, 0);
    e6 = StwoCudaQm31{ b39, b96, b96, b96 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 280u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 125u, row_index, 0);
    e0 = StwoCudaQm31{ b40, b96, b96, b96 };
    e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 281u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 126u, row_index, 0);
    e6 = StwoCudaQm31{ b41, b96, b96, b96 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 282u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 127u, row_index, 0);
    e0 = StwoCudaQm31{ b42, b96, b96, b96 };
    e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 283u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 128u, row_index, 0);
    e6 = StwoCudaQm31{ b43, b96, b96, b96 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 284u);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 129u, row_index, 0);
    e0 = StwoCudaQm31{ b44, b96, b96, b96 };
    e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 285u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 130u, row_index, 0);
    e6 = StwoCudaQm31{ b45, b96, b96, b96 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 286u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 131u, row_index, 0);
    e0 = StwoCudaQm31{ b46, b96, b96, b96 };
    e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 287u);
    e6 = stwo_qm31_sub(e0, e7);
    e7 = stwo_load_qm31(ext_params, 288u);
    unsigned b146 = stwo_m31_add(b141, b109);
    unsigned b147 = base_params[111u];
    unsigned b148 = stwo_m31_add(b146, b147);
    e0 = StwoCudaQm31{ b148, b96, b96, b96 };
    e1 = stwo_qm31_mul(e7, e0);
    e0 = stwo_load_qm31(ext_params, 289u);
    e7 = stwo_qm31_add(e0, e1);
    e0 = stwo_load_qm31(ext_params, 290u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 132u, row_index, 0);
    e1 = StwoCudaQm31{ b47, b96, b96, b96 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e0, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 291u);
    e7 = stwo_qm31_sub(e1, e8);
    e8 = stwo_load_qm31(ext_params, 292u);
    e1 = StwoCudaQm31{ b47, b96, b96, b96 };
    e0 = stwo_qm31_mul(e8, e1);
    e1 = stwo_load_qm31(ext_params, 293u);
    e8 = stwo_qm31_add(e1, e0);
    e1 = stwo_load_qm31(ext_params, 294u);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 133u, row_index, 0);
    e0 = StwoCudaQm31{ b48, b96, b96, b96 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 295u);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 134u, row_index, 0);
    e8 = StwoCudaQm31{ b49, b96, b96, b96 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 296u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 135u, row_index, 0);
    e0 = StwoCudaQm31{ b50, b96, b96, b96 };
    e9 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 297u);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 136u, row_index, 0);
    e8 = StwoCudaQm31{ b51, b96, b96, b96 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 298u);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 137u, row_index, 0);
    e0 = StwoCudaQm31{ b52, b96, b96, b96 };
    e9 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 299u);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 138u, row_index, 0);
    e8 = StwoCudaQm31{ b53, b96, b96, b96 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 300u);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 139u, row_index, 0);
    e0 = StwoCudaQm31{ b54, b96, b96, b96 };
    e9 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 301u);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 140u, row_index, 0);
    e8 = StwoCudaQm31{ b55, b96, b96, b96 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 302u);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 141u, row_index, 0);
    e0 = StwoCudaQm31{ b56, b96, b96, b96 };
    e9 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 303u);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 142u, row_index, 0);
    e8 = StwoCudaQm31{ b57, b96, b96, b96 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 304u);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 143u, row_index, 0);
    e0 = StwoCudaQm31{ b58, b96, b96, b96 };
    e9 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 305u);
    e8 = stwo_qm31_sub(e0, e9);
    e9 = stwo_load_qm31(ext_params, 306u);
    unsigned b149 = stwo_m31_add(b141, b109);
    unsigned b150 = base_params[112u];
    unsigned b151 = stwo_m31_add(b149, b150);
    e0 = StwoCudaQm31{ b151, b96, b96, b96 };
    e1 = stwo_qm31_mul(e9, e0);
    e0 = stwo_load_qm31(ext_params, 307u);
    e9 = stwo_qm31_add(e0, e1);
    e0 = stwo_load_qm31(ext_params, 308u);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 144u, row_index, 0);
    e1 = StwoCudaQm31{ b59, b96, b96, b96 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e0, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 309u);
    e9 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(ext_params, 310u);
    e1 = StwoCudaQm31{ b59, b96, b96, b96 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(ext_params, 311u);
    e10 = stwo_qm31_add(e1, e0);
    e1 = stwo_load_qm31(ext_params, 312u);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 145u, row_index, 0);
    e0 = StwoCudaQm31{ b60, b96, b96, b96 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 313u);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 146u, row_index, 0);
    e10 = StwoCudaQm31{ b61, b96, b96, b96 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 314u);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 147u, row_index, 0);
    e0 = StwoCudaQm31{ b62, b96, b96, b96 };
    e11 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 315u);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 148u, row_index, 0);
    e10 = StwoCudaQm31{ b63, b96, b96, b96 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 316u);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 149u, row_index, 0);
    e0 = StwoCudaQm31{ b64, b96, b96, b96 };
    e11 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 317u);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 150u, row_index, 0);
    e10 = StwoCudaQm31{ b65, b96, b96, b96 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 318u);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 151u, row_index, 0);
    e0 = StwoCudaQm31{ b66, b96, b96, b96 };
    e11 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 319u);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 152u, row_index, 0);
    e10 = StwoCudaQm31{ b67, b96, b96, b96 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 320u);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 153u, row_index, 0);
    e0 = StwoCudaQm31{ b68, b96, b96, b96 };
    e11 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 321u);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 154u, row_index, 0);
    e10 = StwoCudaQm31{ b69, b96, b96, b96 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 322u);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 155u, row_index, 0);
    e0 = StwoCudaQm31{ b70, b96, b96, b96 };
    e11 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 323u);
    e10 = stwo_qm31_sub(e0, e11);
    e11 = stwo_load_qm31(ext_params, 324u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 95u, row_index, 0);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 96u, row_index, 0);
    unsigned b110 = base_params[86u];
    unsigned b111 = stwo_m31_mul(b13, b110);
    unsigned b112 = stwo_m31_add(b12, b111);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 97u, row_index, 0);
    unsigned b113 = base_params[87u];
    unsigned b114 = stwo_m31_mul(b14, b113);
    unsigned b115 = stwo_m31_add(b112, b114);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 98u, row_index, 0);
    unsigned b116 = base_params[88u];
    unsigned b117 = stwo_m31_mul(b15, b116);
    unsigned b118 = stwo_m31_add(b115, b117);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 93u, row_index, 0);
    unsigned b119 = stwo_m31_sub(b118, b10);
    unsigned b120 = base_params[89u];
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 94u, row_index, 0);
    unsigned b121 = stwo_m31_mul(b120, b11);
    unsigned b122 = stwo_m31_sub(b119, b121);
    unsigned b152 = stwo_m31_add(b141, b122);
    e0 = StwoCudaQm31{ b152, b96, b96, b96 };
    e1 = stwo_qm31_mul(e11, e0);
    e0 = stwo_load_qm31(ext_params, 325u);
    e11 = stwo_qm31_add(e0, e1);
    e0 = stwo_load_qm31(ext_params, 326u);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 156u, row_index, 0);
    e1 = StwoCudaQm31{ b71, b96, b96, b96 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e0, e1);
    e1 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 327u);
    e11 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(ext_params, 328u);
    e1 = StwoCudaQm31{ b71, b96, b96, b96 };
    e0 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(ext_params, 329u);
    e12 = stwo_qm31_add(e1, e0);
    e1 = stwo_load_qm31(ext_params, 330u);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 157u, row_index, 0);
    e0 = StwoCudaQm31{ b72, b96, b96, b96 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 331u);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 158u, row_index, 0);
    e12 = StwoCudaQm31{ b73, b96, b96, b96 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 332u);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 159u, row_index, 0);
    e0 = StwoCudaQm31{ b74, b96, b96, b96 };
    e13 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 333u);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 160u, row_index, 0);
    e12 = StwoCudaQm31{ b75, b96, b96, b96 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 334u);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 161u, row_index, 0);
    e0 = StwoCudaQm31{ b76, b96, b96, b96 };
    e13 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 335u);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 162u, row_index, 0);
    e12 = StwoCudaQm31{ b77, b96, b96, b96 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 336u);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 163u, row_index, 0);
    e0 = StwoCudaQm31{ b78, b96, b96, b96 };
    e13 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 337u);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 164u, row_index, 0);
    e12 = StwoCudaQm31{ b79, b96, b96, b96 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 338u);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 165u, row_index, 0);
    e0 = StwoCudaQm31{ b80, b96, b96, b96 };
    e13 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 339u);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 166u, row_index, 0);
    e12 = StwoCudaQm31{ b81, b96, b96, b96 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 340u);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 167u, row_index, 0);
    e0 = StwoCudaQm31{ b82, b96, b96, b96 };
    e13 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 341u);
    e12 = stwo_qm31_sub(e0, e13);
    e13 = stwo_load_qm31(ext_params, 342u);
    unsigned b153 = stwo_m31_add(b141, b122);
    unsigned b154 = base_params[113u];
    unsigned b155 = stwo_m31_add(b153, b154);
    e0 = StwoCudaQm31{ b155, b96, b96, b96 };
    e1 = stwo_qm31_mul(e13, e0);
    e0 = stwo_load_qm31(ext_params, 343u);
    e13 = stwo_qm31_add(e0, e1);
    e0 = stwo_load_qm31(ext_params, 344u);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 168u, row_index, 0);
    e1 = StwoCudaQm31{ b83, b96, b96, b96 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e0, e1);
    e1 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(ext_params, 345u);
    e13 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(ext_params, 346u);
    e1 = StwoCudaQm31{ b83, b96, b96, b96 };
    e0 = stwo_qm31_mul(e14, e1);
    e1 = stwo_load_qm31(ext_params, 347u);
    e14 = stwo_qm31_add(e1, e0);
    e1 = stwo_load_qm31(ext_params, 348u);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 169u, row_index, 0);
    e0 = StwoCudaQm31{ b84, b96, b96, b96 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 349u);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 170u, row_index, 0);
    e14 = StwoCudaQm31{ b85, b96, b96, b96 };
    e1 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 350u);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 171u, row_index, 0);
    e0 = StwoCudaQm31{ b86, b96, b96, b96 };
    e15 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 351u);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 172u, row_index, 0);
    e14 = StwoCudaQm31{ b87, b96, b96, b96 };
    e1 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 352u);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 173u, row_index, 0);
    e0 = StwoCudaQm31{ b88, b96, b96, b96 };
    e15 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 353u);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 174u, row_index, 0);
    e14 = StwoCudaQm31{ b89, b96, b96, b96 };
    e1 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 354u);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 175u, row_index, 0);
    e0 = StwoCudaQm31{ b90, b96, b96, b96 };
    e15 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 355u);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 176u, row_index, 0);
    e14 = StwoCudaQm31{ b91, b96, b96, b96 };
    e1 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 356u);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 177u, row_index, 0);
    e0 = StwoCudaQm31{ b92, b96, b96, b96 };
    e15 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 357u);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 178u, row_index, 0);
    e14 = StwoCudaQm31{ b93, b96, b96, b96 };
    e1 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(ext_params, 358u);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 179u, row_index, 0);
    e0 = StwoCudaQm31{ b94, b96, b96, b96 };
    e15 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 359u);
    e14 = stwo_qm31_sub(e0, e15);
    e15 = stwo_load_qm31(ext_params, 360u);
    unsigned b156 = stwo_m31_add(b141, b122);
    unsigned b157 = base_params[114u];
    unsigned b158 = stwo_m31_add(b156, b157);
    e0 = StwoCudaQm31{ b158, b96, b96, b96 };
    e1 = stwo_qm31_mul(e15, e0);
    e0 = stwo_load_qm31(ext_params, 361u);
    e15 = stwo_qm31_add(e0, e1);
    e0 = stwo_load_qm31(ext_params, 362u);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 180u, row_index, 0);
    e1 = StwoCudaQm31{ b95, b96, b96, b96 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e0, e1);
    e1 = stwo_qm31_add(e15, e16);
    e16 = stwo_load_qm31(ext_params, 363u);
    e15 = stwo_qm31_sub(e1, e16);
    e16 = stwo_load_qm31(ext_params, 1018u);
    e1 = stwo_qm31_mul(e3, e16);
    e16 = stwo_load_qm31(ext_params, 1019u);
    e0 = stwo_qm31_mul(e2, e16);
    e16 = stwo_qm31_add(e1, e0);
    e0 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 1020u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 1021u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 1022u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 1023u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 1024u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(ext_params, 1025u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 1026u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(ext_params, 1027u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(ext_params, 1028u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(ext_params, 1029u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(ext_params, 1030u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(ext_params, 1031u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    unsigned b159 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 52u, row_index, 0);
    unsigned b160 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 53u, row_index, 0);
    unsigned b161 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 54u, row_index, 0);
    unsigned b162 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 55u, row_index, 0);
    e15 = StwoCudaQm31{ b159, b160, b161, b162 };
    unsigned b163 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 56u, row_index, 0);
    unsigned b164 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 57u, row_index, 0);
    unsigned b165 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 58u, row_index, 0);
    unsigned b166 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 59u, row_index, 0);
    e14 = StwoCudaQm31{ b163, b164, b165, b166 };
    e12 = stwo_qm31_sub(e14, e15);
    e15 = stwo_qm31_mul(e12, e0);
    e12 = stwo_qm31_sub(e15, e16);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b167 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 60u, row_index, 0);
    unsigned b168 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 61u, row_index, 0);
    unsigned b169 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 62u, row_index, 0);
    unsigned b170 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 63u, row_index, 0);
    e15 = StwoCudaQm31{ b167, b168, b169, b170 };
    e16 = stwo_qm31_sub(e15, e14);
    e14 = stwo_qm31_mul(e16, e1);
    e16 = stwo_qm31_sub(e14, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b171 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 64u, row_index, 0);
    unsigned b172 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 65u, row_index, 0);
    unsigned b173 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 66u, row_index, 0);
    unsigned b174 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 67u, row_index, 0);
    e14 = StwoCudaQm31{ b171, b172, b173, b174 };
    e3 = stwo_qm31_sub(e14, e15);
    e15 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e15, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b175 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 68u, row_index, 0);
    unsigned b176 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 69u, row_index, 0);
    unsigned b177 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 70u, row_index, 0);
    unsigned b178 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 71u, row_index, 0);
    e15 = StwoCudaQm31{ b175, b176, b177, b178 };
    e5 = stwo_qm31_sub(e15, e14);
    e14 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e14, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b179 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 72u, row_index, 0);
    unsigned b180 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 73u, row_index, 0);
    unsigned b181 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 74u, row_index, 0);
    unsigned b182 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 75u, row_index, 0);
    e14 = StwoCudaQm31{ b179, b180, b181, b182 };
    e7 = stwo_qm31_sub(e14, e15);
    e15 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e15, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b183 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 76u, row_index, 0);
    unsigned b184 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 77u, row_index, 0);
    unsigned b185 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 78u, row_index, 0);
    unsigned b186 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 79u, row_index, 0);
    e15 = StwoCudaQm31{ b183, b184, b185, b186 };
    e9 = stwo_qm31_sub(e15, e14);
    e14 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e14, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b187 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 80u, row_index, 0);
    unsigned b188 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 81u, row_index, 0);
    unsigned b189 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 82u, row_index, 0);
    unsigned b190 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 83u, row_index, 0);
    e14 = StwoCudaQm31{ b187, b188, b189, b190 };
    e11 = stwo_qm31_sub(e14, e15);
    e14 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e14, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
