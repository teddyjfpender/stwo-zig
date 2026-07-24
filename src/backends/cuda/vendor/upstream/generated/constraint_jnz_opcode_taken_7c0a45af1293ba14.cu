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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_010434f9c83db704(
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
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    unsigned b47 = base_params[0u];
    unsigned b48 = stwo_m31_sub(b47, b4);
    unsigned b49 = stwo_m31_mul(b4, b48);
    unsigned b50 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b49, b50, b50, b50 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    unsigned b51 = base_params[2u];
    unsigned b52 = stwo_m31_sub(b51, b5);
    unsigned b53 = stwo_m31_mul(b5, b52);
    StwoCudaQm31 e1 = StwoCudaQm31{ b53, b50, b50, b50 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    StwoCudaQm31 e2 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    StwoCudaQm31 e3 = StwoCudaQm31{ b0, b50, b50, b50 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 1u);
    e2 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(ext_params, 2u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e4 = StwoCudaQm31{ b3, b50, b50, b50 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(ext_params, 3u);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 4u);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(ext_params, 5u);
    unsigned b54 = base_params[3u];
    unsigned b55 = stwo_m31_mul(b4, b54);
    unsigned b56 = base_params[4u];
    unsigned b57 = stwo_m31_add(b55, b56);
    unsigned b58 = base_params[5u];
    unsigned b59 = stwo_m31_add(b57, b58);
    e2 = StwoCudaQm31{ b59, b50, b50, b50 };
    e3 = stwo_qm31_mul(e5, e2);
    e2 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(ext_params, 6u);
    unsigned b62 = base_params[7u];
    unsigned b60 = base_params[6u];
    unsigned b61 = stwo_m31_mul(b5, b60);
    unsigned b63 = stwo_m31_add(b62, b61);
    e4 = StwoCudaQm31{ b63, b50, b50, b50 };
    e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(ext_params, 7u);
    e2 = stwo_qm31_sub(e4, e5);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b66 = stwo_m31_mul(b4, b2);
    unsigned b67 = base_params[9u];
    unsigned b68 = stwo_m31_sub(b67, b4);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    unsigned b69 = stwo_m31_mul(b68, b1);
    unsigned b70 = stwo_m31_add(b66, b69);
    unsigned b71 = stwo_m31_sub(b6, b70);
    e5 = StwoCudaQm31{ b71, b50, b50, b50 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    e4 = stwo_load_qm31(ext_params, 8u);
    unsigned b64 = base_params[8u];
    unsigned b65 = stwo_m31_sub(b3, b64);
    unsigned b72 = stwo_m31_add(b6, b65);
    e3 = StwoCudaQm31{ b72, b50, b50, b50 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(ext_params, 9u);
    e4 = stwo_qm31_add(e3, e6);
    e3 = stwo_load_qm31(ext_params, 10u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    e6 = StwoCudaQm31{ b7, b50, b50, b50 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e3, e6);
    e6 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 11u);
    e4 = stwo_qm31_sub(e6, e7);
    e7 = stwo_load_qm31(ext_params, 12u);
    e6 = StwoCudaQm31{ b7, b50, b50, b50 };
    e3 = stwo_qm31_mul(e7, e6);
    e6 = stwo_load_qm31(ext_params, 13u);
    e7 = stwo_qm31_add(e6, e3);
    e6 = stwo_load_qm31(ext_params, 14u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    e3 = StwoCudaQm31{ b8, b50, b50, b50 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 15u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    e7 = StwoCudaQm31{ b9, b50, b50, b50 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 16u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    e3 = StwoCudaQm31{ b10, b50, b50, b50 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 17u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    e7 = StwoCudaQm31{ b11, b50, b50, b50 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 18u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    e3 = StwoCudaQm31{ b12, b50, b50, b50 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 19u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    e7 = StwoCudaQm31{ b13, b50, b50, b50 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 20u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    e3 = StwoCudaQm31{ b14, b50, b50, b50 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 21u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    e7 = StwoCudaQm31{ b15, b50, b50, b50 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 22u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    e3 = StwoCudaQm31{ b16, b50, b50, b50 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 23u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    e7 = StwoCudaQm31{ b17, b50, b50, b50 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 24u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    e3 = StwoCudaQm31{ b18, b50, b50, b50 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 25u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    e7 = StwoCudaQm31{ b19, b50, b50, b50 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 26u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    e3 = StwoCudaQm31{ b20, b50, b50, b50 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 27u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    e7 = StwoCudaQm31{ b21, b50, b50, b50 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 28u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    e3 = StwoCudaQm31{ b22, b50, b50, b50 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 29u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    e7 = StwoCudaQm31{ b23, b50, b50, b50 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 30u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    e3 = StwoCudaQm31{ b24, b50, b50, b50 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 31u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    e7 = StwoCudaQm31{ b25, b50, b50, b50 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 32u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    e3 = StwoCudaQm31{ b26, b50, b50, b50 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 33u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    e7 = StwoCudaQm31{ b27, b50, b50, b50 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 34u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    e3 = StwoCudaQm31{ b28, b50, b50, b50 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 35u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    e7 = StwoCudaQm31{ b29, b50, b50, b50 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 36u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    e3 = StwoCudaQm31{ b30, b50, b50, b50 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 37u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    e7 = StwoCudaQm31{ b31, b50, b50, b50 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 38u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    e3 = StwoCudaQm31{ b32, b50, b50, b50 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 39u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    e7 = StwoCudaQm31{ b33, b50, b50, b50 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 40u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    e3 = StwoCudaQm31{ b34, b50, b50, b50 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 41u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    e7 = StwoCudaQm31{ b35, b50, b50, b50 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 42u);
    e3 = stwo_qm31_sub(e7, e6);
    unsigned b73 = stwo_m31_add(b9, b10);
    unsigned b74 = stwo_m31_add(b73, b11);
    unsigned b75 = stwo_m31_add(b74, b12);
    unsigned b76 = stwo_m31_add(b75, b13);
    unsigned b77 = stwo_m31_add(b76, b14);
    unsigned b78 = stwo_m31_add(b77, b15);
    unsigned b79 = stwo_m31_add(b78, b16);
    unsigned b80 = stwo_m31_add(b79, b17);
    unsigned b81 = stwo_m31_add(b80, b18);
    unsigned b82 = stwo_m31_add(b81, b19);
    unsigned b83 = stwo_m31_add(b82, b20);
    unsigned b84 = stwo_m31_add(b83, b21);
    unsigned b85 = stwo_m31_add(b84, b22);
    unsigned b86 = stwo_m31_add(b85, b23);
    unsigned b87 = stwo_m31_add(b86, b24);
    unsigned b88 = stwo_m31_add(b87, b25);
    unsigned b89 = stwo_m31_add(b88, b26);
    unsigned b90 = stwo_m31_add(b89, b27);
    unsigned b91 = stwo_m31_add(b90, b28);
    unsigned b92 = stwo_m31_add(b91, b30);
    unsigned b93 = stwo_m31_add(b92, b31);
    unsigned b94 = stwo_m31_add(b93, b32);
    unsigned b95 = stwo_m31_add(b94, b33);
    unsigned b96 = stwo_m31_add(b95, b34);
    unsigned b97 = stwo_m31_add(b8, b29);
    unsigned b98 = stwo_m31_add(b97, b35);
    unsigned b99 = stwo_m31_add(b96, b98);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    unsigned b100 = stwo_m31_mul(b99, b36);
    unsigned b101 = base_params[10u];
    unsigned b102 = stwo_m31_sub(b100, b101);
    e6 = StwoCudaQm31{ b102, b50, b50, b50 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b103 = base_params[11u];
    unsigned b104 = stwo_m31_sub(b8, b103);
    unsigned b109 = stwo_m31_mul(b104, b104);
    unsigned b105 = base_params[12u];
    unsigned b106 = stwo_m31_sub(b29, b105);
    unsigned b110 = stwo_m31_mul(b106, b106);
    unsigned b111 = stwo_m31_add(b109, b110);
    unsigned b107 = base_params[13u];
    unsigned b108 = stwo_m31_sub(b35, b107);
    unsigned b112 = stwo_m31_mul(b108, b108);
    unsigned b113 = stwo_m31_add(b111, b112);
    unsigned b114 = stwo_m31_add(b96, b113);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    unsigned b115 = stwo_m31_mul(b114, b37);
    unsigned b116 = base_params[14u];
    unsigned b117 = stwo_m31_sub(b115, b116);
    e7 = StwoCudaQm31{ b117, b50, b50, b50 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    e8 = stwo_load_qm31(ext_params, 43u);
    unsigned b118 = base_params[15u];
    unsigned b119 = stwo_m31_add(b0, b118);
    StwoCudaQm31 e9 = StwoCudaQm31{ b119, b50, b50, b50 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 44u);
    e8 = stwo_qm31_add(e9, e10);
    e9 = stwo_load_qm31(ext_params, 45u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    e10 = StwoCudaQm31{ b38, b50, b50, b50 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 46u);
    e8 = stwo_qm31_sub(e10, e11);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    unsigned b120 = base_params[16u];
    unsigned b121 = stwo_m31_sub(b39, b120);
    unsigned b122 = stwo_m31_mul(b39, b121);
    e11 = StwoCudaQm31{ b122, b50, b50, b50 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    unsigned b123 = base_params[17u];
    unsigned b124 = stwo_m31_sub(b40, b123);
    unsigned b125 = stwo_m31_mul(b40, b124);
    e10 = StwoCudaQm31{ b125, b50, b50, b50 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b126 = base_params[18u];
    unsigned b127 = stwo_m31_sub(b39, b126);
    unsigned b128 = stwo_m31_mul(b40, b127);
    e9 = StwoCudaQm31{ b128, b50, b50, b50 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    unsigned b138 = base_params[23u];
    unsigned b139 = stwo_m31_sub(b138, b45);
    unsigned b140 = stwo_m31_mul(b45, b139);
    unsigned b141 = base_params[24u];
    unsigned b142 = stwo_m31_mul(b140, b141);
    StwoCudaQm31 e12 = StwoCudaQm31{ b142, b50, b50, b50 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    unsigned b143 = base_params[25u];
    unsigned b144 = stwo_m31_mul(b45, b143);
    unsigned b145 = stwo_m31_sub(b44, b144);
    unsigned b146 = base_params[26u];
    unsigned b147 = stwo_m31_sub(b146, b145);
    unsigned b148 = stwo_m31_mul(b145, b147);
    unsigned b149 = base_params[27u];
    unsigned b150 = stwo_m31_mul(b148, b149);
    StwoCudaQm31 e13 = StwoCudaQm31{ b150, b50, b50, b50 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    StwoCudaQm31 e14 = stwo_load_qm31(ext_params, 47u);
    StwoCudaQm31 e15 = StwoCudaQm31{ b38, b50, b50, b50 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 48u);
    e14 = stwo_qm31_add(e15, e16);
    e15 = stwo_load_qm31(ext_params, 49u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    e16 = StwoCudaQm31{ b41, b50, b50, b50 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(ext_params, 50u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    e14 = StwoCudaQm31{ b42, b50, b50, b50 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(ext_params, 51u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    e16 = StwoCudaQm31{ b43, b50, b50, b50 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(ext_params, 52u);
    unsigned b129 = base_params[19u];
    unsigned b130 = stwo_m31_mul(b40, b129);
    unsigned b151 = stwo_m31_add(b44, b130);
    e14 = StwoCudaQm31{ b151, b50, b50, b50 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(ext_params, 53u);
    unsigned b131 = base_params[20u];
    unsigned b132 = stwo_m31_mul(b40, b131);
    e16 = StwoCudaQm31{ b132, b50, b50, b50 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(ext_params, 54u);
    e14 = StwoCudaQm31{ b132, b50, b50, b50 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(ext_params, 55u);
    e16 = StwoCudaQm31{ b132, b50, b50, b50 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(ext_params, 56u);
    e14 = StwoCudaQm31{ b132, b50, b50, b50 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(ext_params, 57u);
    e16 = StwoCudaQm31{ b132, b50, b50, b50 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(ext_params, 58u);
    e14 = StwoCudaQm31{ b132, b50, b50, b50 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(ext_params, 59u);
    e16 = StwoCudaQm31{ b132, b50, b50, b50 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(ext_params, 60u);
    e14 = StwoCudaQm31{ b132, b50, b50, b50 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(ext_params, 61u);
    e16 = StwoCudaQm31{ b132, b50, b50, b50 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(ext_params, 62u);
    e14 = StwoCudaQm31{ b132, b50, b50, b50 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(ext_params, 63u);
    e16 = StwoCudaQm31{ b132, b50, b50, b50 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(ext_params, 64u);
    e14 = StwoCudaQm31{ b132, b50, b50, b50 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(ext_params, 65u);
    e16 = StwoCudaQm31{ b132, b50, b50, b50 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(ext_params, 66u);
    e14 = StwoCudaQm31{ b132, b50, b50, b50 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(ext_params, 67u);
    e16 = StwoCudaQm31{ b132, b50, b50, b50 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(ext_params, 68u);
    e14 = StwoCudaQm31{ b132, b50, b50, b50 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(ext_params, 69u);
    e16 = StwoCudaQm31{ b132, b50, b50, b50 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(ext_params, 70u);
    unsigned b133 = base_params[21u];
    unsigned b134 = stwo_m31_mul(b39, b133);
    unsigned b135 = stwo_m31_sub(b134, b40);
    e14 = StwoCudaQm31{ b135, b50, b50, b50 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(ext_params, 71u);
    e16 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 72u);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(ext_params, 73u);
    e16 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 74u);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(ext_params, 75u);
    e16 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 76u);
    unsigned b136 = base_params[22u];
    unsigned b137 = stwo_m31_mul(b39, b136);
    e14 = StwoCudaQm31{ b137, b50, b50, b50 };
    e17 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 77u);
    e16 = stwo_qm31_sub(e14, e17);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    unsigned b165 = stwo_m31_mul(b46, b46);
    unsigned b166 = stwo_m31_sub(b165, b46);
    e17 = StwoCudaQm31{ b166, b50, b50, b50 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    e14 = stwo_load_qm31(ext_params, 78u);
    e15 = StwoCudaQm31{ b0, b50, b50, b50 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 79u);
    e14 = stwo_qm31_add(e15, e18);
    e15 = stwo_load_qm31(ext_params, 80u);
    e18 = StwoCudaQm31{ b1, b50, b50, b50 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e15, e18);
    e18 = stwo_qm31_add(e14, e19);
    e19 = stwo_load_qm31(ext_params, 81u);
    e14 = StwoCudaQm31{ b2, b50, b50, b50 };
    e15 = stwo_qm31_mul(e19, e14);
    e14 = stwo_qm31_add(e18, e15);
    e15 = stwo_load_qm31(ext_params, 82u);
    e18 = stwo_qm31_sub(e14, e15);
    e15 = StwoCudaQm31{ b46, b50, b50, b50 };
    e14 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e15);
    e15 = stwo_load_qm31(ext_params, 83u);
    unsigned b152 = base_params[28u];
    unsigned b153 = stwo_m31_mul(b42, b152);
    unsigned b154 = stwo_m31_add(b41, b153);
    unsigned b155 = base_params[29u];
    unsigned b156 = stwo_m31_mul(b43, b155);
    unsigned b157 = stwo_m31_add(b154, b156);
    unsigned b158 = base_params[30u];
    unsigned b159 = stwo_m31_mul(b44, b158);
    unsigned b160 = stwo_m31_add(b157, b159);
    unsigned b161 = stwo_m31_sub(b160, b39);
    unsigned b162 = base_params[31u];
    unsigned b163 = stwo_m31_mul(b162, b40);
    unsigned b164 = stwo_m31_sub(b161, b163);
    unsigned b167 = stwo_m31_add(b0, b164);
    e19 = StwoCudaQm31{ b167, b50, b50, b50 };
    StwoCudaQm31 e20 = stwo_qm31_mul(e15, e19);
    e19 = stwo_load_qm31(ext_params, 84u);
    e15 = stwo_qm31_add(e19, e20);
    e19 = stwo_load_qm31(ext_params, 85u);
    unsigned b168 = stwo_m31_add(b1, b5);
    e20 = StwoCudaQm31{ b168, b50, b50, b50 };
    StwoCudaQm31 e21 = stwo_qm31_mul(e19, e20);
    e20 = stwo_qm31_add(e15, e21);
    e21 = stwo_load_qm31(ext_params, 86u);
    e15 = StwoCudaQm31{ b2, b50, b50, b50 };
    e19 = stwo_qm31_mul(e21, e15);
    e15 = stwo_qm31_add(e20, e19);
    e19 = stwo_load_qm31(ext_params, 87u);
    e20 = stwo_qm31_sub(e15, e19);
    e19 = stwo_load_qm31(ext_params, 88u);
    e15 = stwo_qm31_mul(e4, e19);
    e19 = stwo_load_qm31(ext_params, 89u);
    e21 = stwo_qm31_mul(e2, e19);
    e19 = stwo_qm31_add(e15, e21);
    e21 = stwo_qm31_mul(e2, e4);
    e4 = stwo_load_qm31(ext_params, 90u);
    e2 = stwo_qm31_mul(e8, e4);
    e4 = stwo_load_qm31(ext_params, 91u);
    e15 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e15);
    e15 = stwo_qm31_mul(e3, e8);
    e8 = stwo_load_qm31(ext_params, 92u);
    e3 = stwo_qm31_mul(e18, e8);
    e8 = StwoCudaQm31{ b46, b50, b50, b50 };
    e2 = stwo_qm31_mul(e16, e8);
    e8 = stwo_qm31_add(e3, e2);
    e2 = stwo_qm31_mul(e16, e18);
    unsigned b169 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b170 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b171 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b172 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e18 = StwoCudaQm31{ b169, b170, b171, b172 };
    e16 = stwo_qm31_mul(e18, e21);
    e21 = stwo_qm31_sub(e16, e19);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e21, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b173 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b174 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b175 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b176 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e16 = StwoCudaQm31{ b173, b174, b175, b176 };
    e19 = stwo_qm31_sub(e16, e18);
    e18 = stwo_qm31_mul(e19, e15);
    e19 = stwo_qm31_sub(e18, e4);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e19, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b177 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b178 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b179 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b180 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e18 = StwoCudaQm31{ b177, b178, b179, b180 };
    e4 = stwo_qm31_sub(e18, e16);
    e16 = stwo_qm31_mul(e4, e2);
    e4 = stwo_qm31_sub(e16, e8);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b181 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, -1);
    unsigned b183 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, -1);
    unsigned b185 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, -1);
    unsigned b187 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, -1);
    e16 = StwoCudaQm31{ b181, b183, b185, b187 };
    unsigned b182 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b184 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b186 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b188 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e8 = StwoCudaQm31{ b182, b184, b186, b188 };
    e2 = stwo_qm31_sub(e8, e16);
    e8 = stwo_qm31_sub(e2, e18);
    e2 = stwo_load_qm31(ext_params, 93u);
    e18 = stwo_qm31_add(e8, e2);
    e2 = stwo_qm31_mul(e18, e20);
    e18 = stwo_qm31_sub(e2, e14);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
