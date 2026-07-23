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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_3f8cec5def75d2ac(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 364u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 180u, row_index, 0);
    unsigned b91 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b16, b91, b91, b91 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 365u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 366u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 181u, row_index, 0);
    e2 = StwoCudaQm31{ b17, b91, b91, b91 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 367u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 182u, row_index, 0);
    e0 = StwoCudaQm31{ b18, b91, b91, b91 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 368u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 183u, row_index, 0);
    e2 = StwoCudaQm31{ b19, b91, b91, b91 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 369u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 184u, row_index, 0);
    e0 = StwoCudaQm31{ b20, b91, b91, b91 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 370u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 185u, row_index, 0);
    e2 = StwoCudaQm31{ b21, b91, b91, b91 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 371u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 186u, row_index, 0);
    e0 = StwoCudaQm31{ b22, b91, b91, b91 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 372u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 187u, row_index, 0);
    e2 = StwoCudaQm31{ b23, b91, b91, b91 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 373u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 188u, row_index, 0);
    e0 = StwoCudaQm31{ b24, b91, b91, b91 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 374u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 189u, row_index, 0);
    e2 = StwoCudaQm31{ b25, b91, b91, b91 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 375u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 190u, row_index, 0);
    e0 = StwoCudaQm31{ b26, b91, b91, b91 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 376u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 191u, row_index, 0);
    e2 = StwoCudaQm31{ b27, b91, b91, b91 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 377u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 378u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    unsigned b118 = base_params[107u];
    unsigned b119 = stwo_m31_mul(b1, b118);
    unsigned b120 = stwo_m31_add(b0, b119);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    unsigned b121 = base_params[108u];
    unsigned b122 = stwo_m31_mul(b2, b121);
    unsigned b123 = stwo_m31_add(b120, b122);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    unsigned b124 = base_params[109u];
    unsigned b125 = stwo_m31_mul(b3, b124);
    unsigned b126 = stwo_m31_add(b123, b125);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 95u, row_index, 0);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 96u, row_index, 0);
    unsigned b92 = base_params[86u];
    unsigned b93 = stwo_m31_mul(b7, b92);
    unsigned b94 = stwo_m31_add(b6, b93);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 97u, row_index, 0);
    unsigned b95 = base_params[87u];
    unsigned b96 = stwo_m31_mul(b8, b95);
    unsigned b97 = stwo_m31_add(b94, b96);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 98u, row_index, 0);
    unsigned b98 = base_params[88u];
    unsigned b99 = stwo_m31_mul(b9, b98);
    unsigned b100 = stwo_m31_add(b97, b99);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 93u, row_index, 0);
    unsigned b101 = stwo_m31_sub(b100, b4);
    unsigned b102 = base_params[89u];
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 94u, row_index, 0);
    unsigned b103 = stwo_m31_mul(b102, b5);
    unsigned b104 = stwo_m31_sub(b101, b103);
    unsigned b127 = stwo_m31_add(b126, b104);
    unsigned b128 = base_params[115u];
    unsigned b129 = stwo_m31_add(b127, b128);
    e2 = StwoCudaQm31{ b129, b91, b91, b91 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 379u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 380u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 192u, row_index, 0);
    e1 = StwoCudaQm31{ b28, b91, b91, b91 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 381u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 382u);
    e1 = StwoCudaQm31{ b28, b91, b91, b91 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 383u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 384u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 193u, row_index, 0);
    e2 = StwoCudaQm31{ b29, b91, b91, b91 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 385u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 194u, row_index, 0);
    e4 = StwoCudaQm31{ b30, b91, b91, b91 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 386u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 195u, row_index, 0);
    e2 = StwoCudaQm31{ b31, b91, b91, b91 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 387u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 196u, row_index, 0);
    e4 = StwoCudaQm31{ b32, b91, b91, b91 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 388u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 197u, row_index, 0);
    e2 = StwoCudaQm31{ b33, b91, b91, b91 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 389u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 198u, row_index, 0);
    e4 = StwoCudaQm31{ b34, b91, b91, b91 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 390u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 199u, row_index, 0);
    e2 = StwoCudaQm31{ b35, b91, b91, b91 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 391u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 200u, row_index, 0);
    e4 = StwoCudaQm31{ b36, b91, b91, b91 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 392u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 201u, row_index, 0);
    e2 = StwoCudaQm31{ b37, b91, b91, b91 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 393u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 202u, row_index, 0);
    e4 = StwoCudaQm31{ b38, b91, b91, b91 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 394u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 203u, row_index, 0);
    e2 = StwoCudaQm31{ b39, b91, b91, b91 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 395u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(ext_params, 396u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 103u, row_index, 0);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 104u, row_index, 0);
    unsigned b105 = base_params[103u];
    unsigned b106 = stwo_m31_mul(b13, b105);
    unsigned b107 = stwo_m31_add(b12, b106);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 105u, row_index, 0);
    unsigned b108 = base_params[104u];
    unsigned b109 = stwo_m31_mul(b14, b108);
    unsigned b110 = stwo_m31_add(b107, b109);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 106u, row_index, 0);
    unsigned b111 = base_params[105u];
    unsigned b112 = stwo_m31_mul(b15, b111);
    unsigned b113 = stwo_m31_add(b110, b112);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 101u, row_index, 0);
    unsigned b114 = stwo_m31_sub(b113, b10);
    unsigned b115 = base_params[106u];
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 102u, row_index, 0);
    unsigned b116 = stwo_m31_mul(b115, b11);
    unsigned b117 = stwo_m31_sub(b114, b116);
    unsigned b130 = stwo_m31_add(b126, b117);
    e2 = StwoCudaQm31{ b130, b91, b91, b91 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(ext_params, 397u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 398u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 204u, row_index, 0);
    e1 = StwoCudaQm31{ b40, b91, b91, b91 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 399u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(ext_params, 400u);
    e1 = StwoCudaQm31{ b40, b91, b91, b91 };
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(ext_params, 401u);
    e6 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 402u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 205u, row_index, 0);
    e2 = StwoCudaQm31{ b41, b91, b91, b91 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 403u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 206u, row_index, 0);
    e6 = StwoCudaQm31{ b42, b91, b91, b91 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 404u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 207u, row_index, 0);
    e2 = StwoCudaQm31{ b43, b91, b91, b91 };
    e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 405u);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 208u, row_index, 0);
    e6 = StwoCudaQm31{ b44, b91, b91, b91 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 406u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 209u, row_index, 0);
    e2 = StwoCudaQm31{ b45, b91, b91, b91 };
    e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 407u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 210u, row_index, 0);
    e6 = StwoCudaQm31{ b46, b91, b91, b91 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 408u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 211u, row_index, 0);
    e2 = StwoCudaQm31{ b47, b91, b91, b91 };
    e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 409u);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 212u, row_index, 0);
    e6 = StwoCudaQm31{ b48, b91, b91, b91 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 410u);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 213u, row_index, 0);
    e2 = StwoCudaQm31{ b49, b91, b91, b91 };
    e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 411u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 214u, row_index, 0);
    e6 = StwoCudaQm31{ b50, b91, b91, b91 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 412u);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 215u, row_index, 0);
    e2 = StwoCudaQm31{ b51, b91, b91, b91 };
    e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 413u);
    e6 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(ext_params, 414u);
    unsigned b131 = stwo_m31_add(b126, b117);
    unsigned b132 = base_params[116u];
    unsigned b133 = stwo_m31_add(b131, b132);
    e2 = StwoCudaQm31{ b133, b91, b91, b91 };
    e1 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(ext_params, 415u);
    e7 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 416u);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 216u, row_index, 0);
    e1 = StwoCudaQm31{ b52, b91, b91, b91 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 417u);
    e7 = stwo_qm31_sub(e1, e8);
    e8 = stwo_load_qm31(ext_params, 418u);
    e1 = StwoCudaQm31{ b52, b91, b91, b91 };
    e2 = stwo_qm31_mul(e8, e1);
    e1 = stwo_load_qm31(ext_params, 419u);
    e8 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 420u);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 217u, row_index, 0);
    e2 = StwoCudaQm31{ b53, b91, b91, b91 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 421u);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 218u, row_index, 0);
    e8 = StwoCudaQm31{ b54, b91, b91, b91 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 422u);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 219u, row_index, 0);
    e2 = StwoCudaQm31{ b55, b91, b91, b91 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 423u);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 220u, row_index, 0);
    e8 = StwoCudaQm31{ b56, b91, b91, b91 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 424u);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 221u, row_index, 0);
    e2 = StwoCudaQm31{ b57, b91, b91, b91 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 425u);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 222u, row_index, 0);
    e8 = StwoCudaQm31{ b58, b91, b91, b91 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 426u);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 223u, row_index, 0);
    e2 = StwoCudaQm31{ b59, b91, b91, b91 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 427u);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 224u, row_index, 0);
    e8 = StwoCudaQm31{ b60, b91, b91, b91 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 428u);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 225u, row_index, 0);
    e2 = StwoCudaQm31{ b61, b91, b91, b91 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 429u);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 226u, row_index, 0);
    e8 = StwoCudaQm31{ b62, b91, b91, b91 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 430u);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 227u, row_index, 0);
    e2 = StwoCudaQm31{ b63, b91, b91, b91 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 431u);
    e8 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(ext_params, 432u);
    unsigned b134 = stwo_m31_add(b126, b117);
    unsigned b135 = base_params[117u];
    unsigned b136 = stwo_m31_add(b134, b135);
    e2 = StwoCudaQm31{ b136, b91, b91, b91 };
    e1 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(ext_params, 433u);
    e9 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 434u);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 228u, row_index, 0);
    e1 = StwoCudaQm31{ b64, b91, b91, b91 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 435u);
    e9 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(ext_params, 436u);
    e1 = StwoCudaQm31{ b64, b91, b91, b91 };
    e2 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(ext_params, 437u);
    e10 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 438u);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 229u, row_index, 0);
    e2 = StwoCudaQm31{ b65, b91, b91, b91 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 439u);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 230u, row_index, 0);
    e10 = StwoCudaQm31{ b66, b91, b91, b91 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 440u);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 231u, row_index, 0);
    e2 = StwoCudaQm31{ b67, b91, b91, b91 };
    e11 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 441u);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 232u, row_index, 0);
    e10 = StwoCudaQm31{ b68, b91, b91, b91 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 442u);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 233u, row_index, 0);
    e2 = StwoCudaQm31{ b69, b91, b91, b91 };
    e11 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 443u);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 234u, row_index, 0);
    e10 = StwoCudaQm31{ b70, b91, b91, b91 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 444u);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 235u, row_index, 0);
    e2 = StwoCudaQm31{ b71, b91, b91, b91 };
    e11 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 445u);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 236u, row_index, 0);
    e10 = StwoCudaQm31{ b72, b91, b91, b91 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 446u);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 237u, row_index, 0);
    e2 = StwoCudaQm31{ b73, b91, b91, b91 };
    e11 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 447u);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 238u, row_index, 0);
    e10 = StwoCudaQm31{ b74, b91, b91, b91 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 448u);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 239u, row_index, 0);
    e2 = StwoCudaQm31{ b75, b91, b91, b91 };
    e11 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 449u);
    e10 = stwo_qm31_sub(e2, e11);
    e11 = stwo_load_qm31(ext_params, 450u);
    unsigned b137 = stwo_m31_add(b126, b117);
    unsigned b138 = base_params[118u];
    unsigned b139 = stwo_m31_add(b137, b138);
    e2 = StwoCudaQm31{ b139, b91, b91, b91 };
    e1 = stwo_qm31_mul(e11, e2);
    e2 = stwo_load_qm31(ext_params, 451u);
    e11 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 452u);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 240u, row_index, 0);
    e1 = StwoCudaQm31{ b76, b91, b91, b91 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 453u);
    e11 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(ext_params, 454u);
    e1 = StwoCudaQm31{ b76, b91, b91, b91 };
    e2 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(ext_params, 455u);
    e12 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 456u);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 241u, row_index, 0);
    e2 = StwoCudaQm31{ b77, b91, b91, b91 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 457u);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 242u, row_index, 0);
    e12 = StwoCudaQm31{ b78, b91, b91, b91 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 458u);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 243u, row_index, 0);
    e2 = StwoCudaQm31{ b79, b91, b91, b91 };
    e13 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 459u);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 244u, row_index, 0);
    e12 = StwoCudaQm31{ b80, b91, b91, b91 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 460u);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 245u, row_index, 0);
    e2 = StwoCudaQm31{ b81, b91, b91, b91 };
    e13 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 461u);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 246u, row_index, 0);
    e12 = StwoCudaQm31{ b82, b91, b91, b91 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 462u);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 247u, row_index, 0);
    e2 = StwoCudaQm31{ b83, b91, b91, b91 };
    e13 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 463u);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 248u, row_index, 0);
    e12 = StwoCudaQm31{ b84, b91, b91, b91 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 464u);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 249u, row_index, 0);
    e2 = StwoCudaQm31{ b85, b91, b91, b91 };
    e13 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 465u);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 250u, row_index, 0);
    e12 = StwoCudaQm31{ b86, b91, b91, b91 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 466u);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 251u, row_index, 0);
    e2 = StwoCudaQm31{ b87, b91, b91, b91 };
    e13 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 467u);
    e12 = stwo_qm31_sub(e2, e13);
    e13 = stwo_load_qm31(ext_params, 468u);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 252u, row_index, 0);
    e2 = StwoCudaQm31{ b88, b91, b91, b91 };
    e1 = stwo_qm31_mul(e13, e2);
    e2 = stwo_load_qm31(ext_params, 469u);
    e13 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 470u);
    e1 = stwo_qm31_sub(e13, e2);
    e2 = stwo_load_qm31(ext_params, 471u);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 253u, row_index, 0);
    e13 = StwoCudaQm31{ b89, b91, b91, b91 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e2, e13);
    e13 = stwo_load_qm31(ext_params, 472u);
    e2 = stwo_qm31_add(e13, e14);
    e13 = stwo_load_qm31(ext_params, 473u);
    e14 = stwo_qm31_sub(e2, e13);
    e13 = stwo_load_qm31(ext_params, 474u);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 254u, row_index, 0);
    e2 = StwoCudaQm31{ b90, b91, b91, b91 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e13, e2);
    e2 = stwo_load_qm31(ext_params, 475u);
    e13 = stwo_qm31_add(e2, e15);
    e2 = stwo_load_qm31(ext_params, 476u);
    e15 = stwo_qm31_sub(e13, e2);
    e2 = stwo_load_qm31(ext_params, 1032u);
    e13 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 1033u);
    StwoCudaQm31 e16 = stwo_qm31_mul(e0, e2);
    e2 = stwo_qm31_add(e13, e16);
    e16 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(ext_params, 1034u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 1035u);
    e13 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e13);
    e13 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 1036u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 1037u);
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 1038u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(ext_params, 1039u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 1040u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(ext_params, 1041u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(ext_params, 1042u);
    e10 = stwo_qm31_mul(e1, e11);
    e11 = stwo_load_qm31(ext_params, 1043u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(ext_params, 1044u);
    e12 = stwo_qm31_mul(e15, e1);
    e1 = stwo_load_qm31(ext_params, 1045u);
    e10 = stwo_qm31_mul(e14, e1);
    e1 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    unsigned b140 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 80u, row_index, 0);
    unsigned b141 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 81u, row_index, 0);
    unsigned b142 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 82u, row_index, 0);
    unsigned b143 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 83u, row_index, 0);
    e15 = StwoCudaQm31{ b140, b141, b142, b143 };
    unsigned b144 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 84u, row_index, 0);
    unsigned b145 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 85u, row_index, 0);
    unsigned b146 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 86u, row_index, 0);
    unsigned b147 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 87u, row_index, 0);
    e14 = StwoCudaQm31{ b144, b145, b146, b147 };
    e12 = stwo_qm31_sub(e14, e15);
    e15 = stwo_qm31_mul(e12, e16);
    e12 = stwo_qm31_sub(e15, e2);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b148 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 88u, row_index, 0);
    unsigned b149 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 89u, row_index, 0);
    unsigned b150 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 90u, row_index, 0);
    unsigned b151 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 91u, row_index, 0);
    e15 = StwoCudaQm31{ b148, b149, b150, b151 };
    e2 = stwo_qm31_sub(e15, e14);
    e14 = stwo_qm31_mul(e2, e13);
    e2 = stwo_qm31_sub(e14, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b152 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 92u, row_index, 0);
    unsigned b153 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 93u, row_index, 0);
    unsigned b154 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 94u, row_index, 0);
    unsigned b155 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 95u, row_index, 0);
    e14 = StwoCudaQm31{ b152, b153, b154, b155 };
    e3 = stwo_qm31_sub(e14, e15);
    e15 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e15, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b156 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 96u, row_index, 0);
    unsigned b157 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 97u, row_index, 0);
    unsigned b158 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 98u, row_index, 0);
    unsigned b159 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 99u, row_index, 0);
    e15 = StwoCudaQm31{ b156, b157, b158, b159 };
    e5 = stwo_qm31_sub(e15, e14);
    e14 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e14, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b160 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 100u, row_index, 0);
    unsigned b161 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 101u, row_index, 0);
    unsigned b162 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 102u, row_index, 0);
    unsigned b163 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 103u, row_index, 0);
    e14 = StwoCudaQm31{ b160, b161, b162, b163 };
    e7 = stwo_qm31_sub(e14, e15);
    e15 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e15, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b164 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 104u, row_index, 0);
    unsigned b165 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 105u, row_index, 0);
    unsigned b166 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 106u, row_index, 0);
    unsigned b167 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 107u, row_index, 0);
    e15 = StwoCudaQm31{ b164, b165, b166, b167 };
    e9 = stwo_qm31_sub(e15, e14);
    e14 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e14, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b168 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 108u, row_index, 0);
    unsigned b169 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 109u, row_index, 0);
    unsigned b170 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 110u, row_index, 0);
    unsigned b171 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 111u, row_index, 0);
    e14 = StwoCudaQm31{ b168, b169, b170, b171 };
    e11 = stwo_qm31_sub(e14, e15);
    e14 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e14, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
