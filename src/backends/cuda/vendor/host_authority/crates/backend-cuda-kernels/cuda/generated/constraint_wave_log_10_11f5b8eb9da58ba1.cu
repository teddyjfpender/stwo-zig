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

struct StwoCudaCompositionWavePart {
    const unsigned *const *trace_cols;
    const unsigned *interaction_offsets;
    const unsigned *base_params;
    const unsigned *ext_params;
    const unsigned *denom_inv;
    unsigned log_n_rows;
    unsigned rc_base;
};
static_assert(sizeof(StwoCudaCompositionWavePart) == 48, "wave part ABI");

__device__ __noinline__ StwoCudaQm31 stwo_composition_wave_part_0(
    const StwoCudaCompositionWavePart &part,
    const unsigned *random_coeff_powers,
    unsigned full_domain_rows,
    unsigned row_index
) {
    unsigned row_count = full_domain_rows;
    const unsigned *const *trace_cols = part.trace_cols;
    const unsigned *interaction_offsets = part.interaction_offsets;
    const unsigned *base_params = part.base_params;
    const unsigned *ext_params = part.ext_params;
    unsigned log_n_rows = part.log_n_rows;
    unsigned rc_base = part.rc_base;
    // Canonical ext stream with demand-driven, versioned base cones.
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    unsigned b9 = base_params[0u];
    unsigned b10 = stwo_m31_sub(b9, b4);
    unsigned b11 = stwo_m31_mul(b4, b10);
    unsigned b12 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b11, b12, b12, b12 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    unsigned b13 = base_params[2u];
    unsigned b14 = stwo_m31_sub(b13, b5);
    unsigned b15 = stwo_m31_mul(b5, b14);
    StwoCudaQm31 e1 = StwoCudaQm31{ b15, b12, b12, b12 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    StwoCudaQm31 e2 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    StwoCudaQm31 e3 = StwoCudaQm31{ b0, b12, b12, b12 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 1u);
    e2 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(ext_params, 2u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e4 = StwoCudaQm31{ b3, b12, b12, b12 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(ext_params, 3u);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 4u);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(ext_params, 5u);
    unsigned b16 = base_params[3u];
    unsigned b17 = stwo_m31_mul(b4, b16);
    unsigned b18 = base_params[4u];
    unsigned b19 = stwo_m31_add(b17, b18);
    unsigned b20 = base_params[5u];
    unsigned b21 = stwo_m31_add(b19, b20);
    e2 = StwoCudaQm31{ b21, b12, b12, b12 };
    e3 = stwo_qm31_mul(e5, e2);
    e2 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(ext_params, 6u);
    unsigned b22 = base_params[6u];
    unsigned b23 = stwo_m31_mul(b5, b22);
    unsigned b24 = base_params[7u];
    unsigned b25 = stwo_m31_add(b23, b24);
    e4 = StwoCudaQm31{ b25, b12, b12, b12 };
    e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(ext_params, 7u);
    e2 = stwo_qm31_sub(e4, e5);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b28 = stwo_m31_mul(b4, b2);
    unsigned b29 = base_params[9u];
    unsigned b30 = stwo_m31_sub(b29, b4);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    unsigned b31 = stwo_m31_mul(b30, b1);
    unsigned b32 = stwo_m31_add(b28, b31);
    unsigned b33 = stwo_m31_sub(b6, b32);
    e5 = StwoCudaQm31{ b33, b12, b12, b12 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    e4 = stwo_load_qm31(ext_params, 8u);
    unsigned b26 = base_params[8u];
    unsigned b27 = stwo_m31_sub(b3, b26);
    unsigned b34 = stwo_m31_add(b6, b27);
    e3 = StwoCudaQm31{ b34, b12, b12, b12 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(ext_params, 9u);
    e4 = stwo_qm31_add(e3, e6);
    e3 = stwo_load_qm31(ext_params, 10u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    e6 = StwoCudaQm31{ b7, b12, b12, b12 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e3, e6);
    e6 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 11u);
    e4 = stwo_qm31_sub(e6, e7);
    e7 = stwo_load_qm31(ext_params, 12u);
    unsigned b35 = base_params[10u];
    unsigned b36 = stwo_m31_add(b0, b35);
    e6 = StwoCudaQm31{ b36, b12, b12, b12 };
    e3 = stwo_qm31_mul(e7, e6);
    e6 = stwo_load_qm31(ext_params, 13u);
    e7 = stwo_qm31_add(e6, e3);
    e6 = stwo_load_qm31(ext_params, 14u);
    e3 = StwoCudaQm31{ b7, b12, b12, b12 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 15u);
    e7 = stwo_qm31_sub(e3, e8);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b37 = stwo_m31_mul(b8, b8);
    unsigned b38 = stwo_m31_sub(b37, b8);
    e8 = StwoCudaQm31{ b38, b12, b12, b12 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    e3 = stwo_load_qm31(ext_params, 16u);
    e6 = StwoCudaQm31{ b0, b12, b12, b12 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e3, e6);
    e6 = stwo_load_qm31(ext_params, 17u);
    e3 = stwo_qm31_add(e6, e9);
    e6 = stwo_load_qm31(ext_params, 18u);
    e9 = StwoCudaQm31{ b1, b12, b12, b12 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e6, e9);
    e9 = stwo_qm31_add(e3, e10);
    e10 = stwo_load_qm31(ext_params, 19u);
    e3 = StwoCudaQm31{ b2, b12, b12, b12 };
    e6 = stwo_qm31_mul(e10, e3);
    e3 = stwo_qm31_add(e9, e6);
    e6 = stwo_load_qm31(ext_params, 20u);
    e9 = stwo_qm31_sub(e3, e6);
    e6 = StwoCudaQm31{ b8, b12, b12, b12 };
    e3 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e6);
    e6 = stwo_load_qm31(ext_params, 21u);
    unsigned b39 = base_params[11u];
    unsigned b40 = stwo_m31_add(b0, b39);
    e10 = StwoCudaQm31{ b40, b12, b12, b12 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e6, e10);
    e10 = stwo_load_qm31(ext_params, 22u);
    e6 = stwo_qm31_add(e10, e11);
    e10 = stwo_load_qm31(ext_params, 23u);
    unsigned b41 = stwo_m31_add(b1, b5);
    e11 = StwoCudaQm31{ b41, b12, b12, b12 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e10, e11);
    e11 = stwo_qm31_add(e6, e12);
    e12 = stwo_load_qm31(ext_params, 24u);
    e6 = StwoCudaQm31{ b2, b12, b12, b12 };
    e10 = stwo_qm31_mul(e12, e6);
    e6 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 25u);
    e11 = stwo_qm31_sub(e6, e10);
    e10 = stwo_load_qm31(ext_params, 26u);
    e6 = stwo_qm31_mul(e4, e10);
    e10 = stwo_load_qm31(ext_params, 27u);
    e12 = stwo_qm31_mul(e2, e10);
    e10 = stwo_qm31_add(e6, e12);
    e12 = stwo_qm31_mul(e2, e4);
    e4 = stwo_load_qm31(ext_params, 28u);
    e2 = stwo_qm31_mul(e9, e4);
    e4 = StwoCudaQm31{ b8, b12, b12, b12 };
    e6 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e2, e6);
    e6 = stwo_qm31_mul(e7, e9);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e9 = StwoCudaQm31{ b42, b43, b44, b45 };
    e7 = stwo_qm31_mul(e9, e12);
    e12 = stwo_qm31_sub(e7, e10);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e7 = StwoCudaQm31{ b46, b47, b48, b49 };
    e10 = stwo_qm31_sub(e7, e9);
    e9 = stwo_qm31_mul(e10, e6);
    e10 = stwo_qm31_sub(e9, e4);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, -1);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, -1);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, -1);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, -1);
    e9 = StwoCudaQm31{ b50, b52, b54, b56 };
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e4 = StwoCudaQm31{ b51, b53, b55, b57 };
    e6 = stwo_qm31_sub(e4, e9);
    e4 = stwo_qm31_sub(e6, e7);
    e6 = stwo_load_qm31(ext_params, 29u);
    e7 = stwo_qm31_add(e4, e6);
    e6 = stwo_qm31_mul(e7, e11);
    e7 = stwo_qm31_sub(e6, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));

    unsigned denom_idx = row_index >> log_n_rows;
    return stwo_qm31_mul_base(acc, part.denom_inv[denom_idx]);
}

__device__ __noinline__ StwoCudaQm31 stwo_composition_wave_part_1(
    const StwoCudaCompositionWavePart &part,
    const unsigned *random_coeff_powers,
    unsigned full_domain_rows,
    unsigned row_index
) {
    unsigned row_count = full_domain_rows;
    const unsigned *const *trace_cols = part.trace_cols;
    const unsigned *interaction_offsets = part.interaction_offsets;
    const unsigned *base_params = part.base_params;
    const unsigned *ext_params = part.ext_params;
    unsigned log_n_rows = part.log_n_rows;
    unsigned rc_base = part.rc_base;
    // Canonical ext stream with demand-driven, versioned base cones.
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b19 = base_params[0u];
    unsigned b20 = stwo_m31_sub(b19, b6);
    unsigned b21 = stwo_m31_mul(b6, b20);
    unsigned b22 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b21, b22, b22, b22 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b23 = base_params[2u];
    unsigned b24 = stwo_m31_sub(b23, b7);
    unsigned b25 = stwo_m31_mul(b7, b24);
    StwoCudaQm31 e1 = StwoCudaQm31{ b25, b22, b22, b22 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b26 = base_params[3u];
    unsigned b27 = stwo_m31_sub(b26, b8);
    unsigned b28 = stwo_m31_mul(b8, b27);
    StwoCudaQm31 e2 = StwoCudaQm31{ b28, b22, b22, b22 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    StwoCudaQm31 e3 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    StwoCudaQm31 e4 = StwoCudaQm31{ b0, b22, b22, b22 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_load_qm31(ext_params, 1u);
    e3 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(ext_params, 2u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e5 = StwoCudaQm31{ b3, b22, b22, b22 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 3u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e3 = StwoCudaQm31{ b4, b22, b22, b22 };
    e4 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 4u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e5 = StwoCudaQm31{ b5, b22, b22, b22 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 5u);
    unsigned b29 = base_params[4u];
    unsigned b30 = stwo_m31_mul(b6, b29);
    unsigned b31 = base_params[5u];
    unsigned b32 = stwo_m31_mul(b7, b31);
    unsigned b33 = stwo_m31_add(b30, b32);
    e3 = StwoCudaQm31{ b33, b22, b22, b22 };
    e4 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 6u);
    unsigned b34 = base_params[6u];
    unsigned b35 = stwo_m31_mul(b8, b34);
    unsigned b36 = base_params[7u];
    unsigned b37 = stwo_m31_add(b35, b36);
    e5 = StwoCudaQm31{ b37, b22, b22, b22 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 7u);
    e3 = stwo_qm31_sub(e5, e6);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b44 = stwo_m31_mul(b6, b2);
    unsigned b45 = base_params[11u];
    unsigned b46 = stwo_m31_sub(b45, b6);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    unsigned b47 = stwo_m31_mul(b46, b1);
    unsigned b48 = stwo_m31_add(b44, b47);
    unsigned b49 = stwo_m31_sub(b9, b48);
    e6 = StwoCudaQm31{ b49, b22, b22, b22 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b50 = stwo_m31_mul(b7, b2);
    unsigned b51 = base_params[12u];
    unsigned b52 = stwo_m31_sub(b51, b7);
    unsigned b53 = stwo_m31_mul(b52, b1);
    unsigned b54 = stwo_m31_add(b50, b53);
    unsigned b55 = stwo_m31_sub(b10, b54);
    e5 = StwoCudaQm31{ b55, b22, b22, b22 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    e4 = stwo_load_qm31(ext_params, 8u);
    unsigned b40 = base_params[9u];
    unsigned b41 = stwo_m31_sub(b4, b40);
    unsigned b56 = stwo_m31_add(b10, b41);
    StwoCudaQm31 e7 = StwoCudaQm31{ b56, b22, b22, b22 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e4, e7);
    e7 = stwo_load_qm31(ext_params, 9u);
    e4 = stwo_qm31_add(e7, e8);
    e7 = stwo_load_qm31(ext_params, 10u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    e8 = StwoCudaQm31{ b11, b22, b22, b22 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e4, e9);
    e9 = stwo_load_qm31(ext_params, 11u);
    e4 = stwo_qm31_sub(e8, e9);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b57 = base_params[13u];
    unsigned b58 = stwo_m31_sub(b57, b16);
    unsigned b59 = stwo_m31_mul(b16, b58);
    unsigned b60 = base_params[14u];
    unsigned b61 = stwo_m31_mul(b59, b60);
    e9 = StwoCudaQm31{ b61, b22, b22, b22 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b62 = base_params[15u];
    unsigned b63 = stwo_m31_mul(b16, b62);
    unsigned b64 = stwo_m31_sub(b15, b63);
    unsigned b65 = base_params[16u];
    unsigned b66 = stwo_m31_sub(b65, b64);
    unsigned b67 = stwo_m31_mul(b64, b66);
    unsigned b68 = base_params[17u];
    unsigned b69 = stwo_m31_mul(b67, b68);
    e8 = StwoCudaQm31{ b69, b22, b22, b22 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    e7 = stwo_load_qm31(ext_params, 12u);
    StwoCudaQm31 e10 = StwoCudaQm31{ b11, b22, b22, b22 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e7, e10);
    e10 = stwo_load_qm31(ext_params, 13u);
    e7 = stwo_qm31_add(e10, e11);
    e10 = stwo_load_qm31(ext_params, 14u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    e11 = StwoCudaQm31{ b12, b22, b22, b22 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e10, e11);
    e11 = stwo_qm31_add(e7, e12);
    e12 = stwo_load_qm31(ext_params, 15u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    e7 = StwoCudaQm31{ b13, b22, b22, b22 };
    e10 = stwo_qm31_mul(e12, e7);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 16u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    e11 = StwoCudaQm31{ b14, b22, b22, b22 };
    e12 = stwo_qm31_mul(e10, e11);
    e11 = stwo_qm31_add(e7, e12);
    e12 = stwo_load_qm31(ext_params, 17u);
    e7 = StwoCudaQm31{ b15, b22, b22, b22 };
    e10 = stwo_qm31_mul(e12, e7);
    e7 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 18u);
    e11 = stwo_qm31_sub(e7, e10);
    e10 = stwo_load_qm31(ext_params, 19u);
    unsigned b38 = base_params[8u];
    unsigned b39 = stwo_m31_sub(b3, b38);
    unsigned b70 = stwo_m31_add(b9, b39);
    e7 = StwoCudaQm31{ b70, b22, b22, b22 };
    e12 = stwo_qm31_mul(e10, e7);
    e7 = stwo_load_qm31(ext_params, 20u);
    e10 = stwo_qm31_add(e7, e12);
    e7 = stwo_load_qm31(ext_params, 21u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    e12 = StwoCudaQm31{ b17, b22, b22, b22 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e7, e12);
    e12 = stwo_qm31_add(e10, e13);
    e13 = stwo_load_qm31(ext_params, 22u);
    e10 = stwo_qm31_sub(e12, e13);
    e13 = stwo_load_qm31(ext_params, 23u);
    unsigned b71 = base_params[18u];
    unsigned b72 = stwo_m31_mul(b13, b71);
    unsigned b73 = stwo_m31_add(b12, b72);
    unsigned b74 = base_params[19u];
    unsigned b75 = stwo_m31_mul(b14, b74);
    unsigned b76 = stwo_m31_add(b73, b75);
    unsigned b77 = base_params[20u];
    unsigned b78 = stwo_m31_mul(b15, b77);
    unsigned b79 = stwo_m31_add(b76, b78);
    unsigned b42 = base_params[10u];
    unsigned b43 = stwo_m31_sub(b5, b42);
    unsigned b80 = stwo_m31_add(b79, b43);
    e12 = StwoCudaQm31{ b80, b22, b22, b22 };
    e7 = stwo_qm31_mul(e13, e12);
    e12 = stwo_load_qm31(ext_params, 24u);
    e13 = stwo_qm31_add(e12, e7);
    e12 = stwo_load_qm31(ext_params, 25u);
    e7 = StwoCudaQm31{ b17, b22, b22, b22 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e12, e7);
    e7 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(ext_params, 26u);
    e13 = stwo_qm31_sub(e7, e14);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    unsigned b81 = stwo_m31_mul(b18, b18);
    unsigned b82 = stwo_m31_sub(b81, b18);
    e14 = StwoCudaQm31{ b82, b22, b22, b22 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    e7 = stwo_load_qm31(ext_params, 27u);
    e12 = StwoCudaQm31{ b0, b22, b22, b22 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e7, e12);
    e12 = stwo_load_qm31(ext_params, 28u);
    e7 = stwo_qm31_add(e12, e15);
    e12 = stwo_load_qm31(ext_params, 29u);
    e15 = StwoCudaQm31{ b1, b22, b22, b22 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e12, e15);
    e15 = stwo_qm31_add(e7, e16);
    e16 = stwo_load_qm31(ext_params, 30u);
    e7 = StwoCudaQm31{ b2, b22, b22, b22 };
    e12 = stwo_qm31_mul(e16, e7);
    e7 = stwo_qm31_add(e15, e12);
    e12 = stwo_load_qm31(ext_params, 31u);
    e15 = stwo_qm31_sub(e7, e12);
    e12 = StwoCudaQm31{ b18, b22, b22, b22 };
    e7 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e12);
    e12 = stwo_load_qm31(ext_params, 32u);
    unsigned b83 = base_params[21u];
    unsigned b84 = stwo_m31_add(b0, b83);
    e16 = StwoCudaQm31{ b84, b22, b22, b22 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e12, e16);
    e16 = stwo_load_qm31(ext_params, 33u);
    e12 = stwo_qm31_add(e16, e17);
    e16 = stwo_load_qm31(ext_params, 34u);
    unsigned b85 = stwo_m31_add(b1, b8);
    e17 = StwoCudaQm31{ b85, b22, b22, b22 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e16, e17);
    e17 = stwo_qm31_add(e12, e18);
    e18 = stwo_load_qm31(ext_params, 35u);
    e12 = StwoCudaQm31{ b2, b22, b22, b22 };
    e16 = stwo_qm31_mul(e18, e12);
    e12 = stwo_qm31_add(e17, e16);
    e16 = stwo_load_qm31(ext_params, 36u);
    e17 = stwo_qm31_sub(e12, e16);
    e16 = stwo_load_qm31(ext_params, 37u);
    e12 = stwo_qm31_mul(e4, e16);
    e16 = stwo_load_qm31(ext_params, 38u);
    e18 = stwo_qm31_mul(e3, e16);
    e16 = stwo_qm31_add(e12, e18);
    e18 = stwo_qm31_mul(e3, e4);
    e4 = stwo_load_qm31(ext_params, 39u);
    e3 = stwo_qm31_mul(e10, e4);
    e4 = stwo_load_qm31(ext_params, 40u);
    e12 = stwo_qm31_mul(e11, e4);
    e4 = stwo_qm31_add(e3, e12);
    e12 = stwo_qm31_mul(e11, e10);
    e10 = stwo_load_qm31(ext_params, 41u);
    e11 = stwo_qm31_mul(e15, e10);
    e10 = StwoCudaQm31{ b18, b22, b22, b22 };
    e3 = stwo_qm31_mul(e13, e10);
    e10 = stwo_qm31_add(e11, e3);
    e3 = stwo_qm31_mul(e13, e15);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e15 = StwoCudaQm31{ b86, b87, b88, b89 };
    e13 = stwo_qm31_mul(e15, e18);
    e18 = stwo_qm31_sub(e13, e16);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e13 = StwoCudaQm31{ b90, b91, b92, b93 };
    e16 = stwo_qm31_sub(e13, e15);
    e15 = stwo_qm31_mul(e16, e12);
    e16 = stwo_qm31_sub(e15, e4);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e15 = StwoCudaQm31{ b94, b95, b96, b97 };
    e4 = stwo_qm31_sub(e15, e13);
    e13 = stwo_qm31_mul(e4, e3);
    e4 = stwo_qm31_sub(e13, e10);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, -1);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, -1);
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, -1);
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, -1);
    e13 = StwoCudaQm31{ b98, b100, b102, b104 };
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e10 = StwoCudaQm31{ b99, b101, b103, b105 };
    e3 = stwo_qm31_sub(e10, e13);
    e10 = stwo_qm31_sub(e3, e15);
    e3 = stwo_load_qm31(ext_params, 42u);
    e15 = stwo_qm31_add(e10, e3);
    e3 = stwo_qm31_mul(e15, e17);
    e15 = stwo_qm31_sub(e3, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));

    unsigned denom_idx = row_index >> log_n_rows;
    return stwo_qm31_mul_base(acc, part.denom_inv[denom_idx]);
}

__device__ __noinline__ StwoCudaQm31 stwo_composition_wave_part_2(
    const StwoCudaCompositionWavePart &part,
    const unsigned *random_coeff_powers,
    unsigned full_domain_rows,
    unsigned row_index
) {
    unsigned row_count = full_domain_rows;
    const unsigned *const *trace_cols = part.trace_cols;
    const unsigned *interaction_offsets = part.interaction_offsets;
    const unsigned *base_params = part.base_params;
    const unsigned *ext_params = part.ext_params;
    unsigned log_n_rows = part.log_n_rows;
    unsigned rc_base = part.rc_base;
    // Canonical ext stream with demand-driven, versioned base cones.
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 0u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b10 = base_params[0u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b1, b10, b10, b10 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 2u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e2 = StwoCudaQm31{ b2, b10, b10, b10 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 3u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 4u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    e2 = StwoCudaQm31{ b3, b10, b10, b10 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 5u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 6u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e1 = StwoCudaQm31{ b4, b10, b10, b10 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 7u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 8u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e1 = StwoCudaQm31{ b5, b10, b10, b10 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 9u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 10u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e2 = StwoCudaQm31{ b6, b10, b10, b10 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 11u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(ext_params, 12u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    e2 = StwoCudaQm31{ b7, b10, b10, b10 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(ext_params, 13u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 14u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    e1 = StwoCudaQm31{ b8, b10, b10, b10 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 15u);
    e5 = stwo_qm31_sub(e1, e6);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    e6 = StwoCudaQm31{ b9, b10, b10, b10 };
    e1 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e6);
    e6 = stwo_load_qm31(ext_params, 16u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    e2 = StwoCudaQm31{ b0, b10, b10, b10 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e6, e2);
    e2 = stwo_load_qm31(ext_params, 17u);
    e6 = stwo_qm31_add(e2, e7);
    e2 = stwo_load_qm31(ext_params, 18u);
    e7 = StwoCudaQm31{ b1, b10, b10, b10 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e2, e7);
    e7 = stwo_qm31_add(e6, e8);
    e8 = stwo_load_qm31(ext_params, 19u);
    e6 = StwoCudaQm31{ b2, b10, b10, b10 };
    e2 = stwo_qm31_mul(e8, e6);
    e6 = stwo_qm31_add(e7, e2);
    e2 = stwo_load_qm31(ext_params, 20u);
    e7 = StwoCudaQm31{ b3, b10, b10, b10 };
    e8 = stwo_qm31_mul(e2, e7);
    e7 = stwo_qm31_add(e6, e8);
    e8 = stwo_load_qm31(ext_params, 21u);
    e6 = StwoCudaQm31{ b4, b10, b10, b10 };
    e2 = stwo_qm31_mul(e8, e6);
    e6 = stwo_qm31_add(e7, e2);
    e2 = stwo_load_qm31(ext_params, 22u);
    e7 = StwoCudaQm31{ b5, b10, b10, b10 };
    e8 = stwo_qm31_mul(e2, e7);
    e7 = stwo_qm31_add(e6, e8);
    e8 = stwo_load_qm31(ext_params, 23u);
    e6 = StwoCudaQm31{ b6, b10, b10, b10 };
    e2 = stwo_qm31_mul(e8, e6);
    e6 = stwo_qm31_add(e7, e2);
    e2 = stwo_load_qm31(ext_params, 24u);
    e7 = StwoCudaQm31{ b7, b10, b10, b10 };
    e8 = stwo_qm31_mul(e2, e7);
    e7 = stwo_qm31_add(e6, e8);
    e8 = stwo_load_qm31(ext_params, 25u);
    e6 = StwoCudaQm31{ b8, b10, b10, b10 };
    e2 = stwo_qm31_mul(e8, e6);
    e6 = stwo_qm31_add(e7, e2);
    e2 = stwo_load_qm31(ext_params, 26u);
    e7 = stwo_qm31_sub(e6, e2);
    e2 = stwo_load_qm31(ext_params, 27u);
    e6 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 28u);
    e8 = stwo_qm31_mul(e0, e2);
    e2 = stwo_qm31_add(e6, e8);
    e8 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(ext_params, 29u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 30u);
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e6);
    e6 = stwo_qm31_mul(e4, e5);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e5 = StwoCudaQm31{ b11, b12, b13, b14 };
    e4 = stwo_qm31_mul(e5, e8);
    e8 = stwo_qm31_sub(e4, e2);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e4 = StwoCudaQm31{ b15, b16, b17, b18 };
    e2 = stwo_qm31_sub(e4, e5);
    e5 = stwo_qm31_mul(e2, e6);
    e2 = stwo_qm31_sub(e5, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, -1);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, -1);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, -1);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, -1);
    e5 = StwoCudaQm31{ b19, b21, b23, b25 };
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e3 = StwoCudaQm31{ b20, b22, b24, b26 };
    e6 = stwo_qm31_sub(e3, e5);
    e3 = stwo_qm31_sub(e6, e4);
    e6 = stwo_load_qm31(ext_params, 31u);
    e4 = stwo_qm31_add(e3, e6);
    e6 = stwo_qm31_mul(e4, e7);
    e4 = stwo_qm31_sub(e6, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));

    unsigned denom_idx = row_index >> log_n_rows;
    return stwo_qm31_mul_base(acc, part.denom_inv[denom_idx]);
}

extern "C" __global__ void __launch_bounds__(128) stwo_composition_wave_0724f4176010f520(
    const StwoCudaCompositionWavePart *parts,
    const unsigned *random_coeff_powers,
    unsigned *coord_0,
    unsigned *coord_1,
    unsigned *coord_2,
    unsigned *coord_3,
    unsigned full_domain_rows,
    unsigned shard_start,
    unsigned shard_rows
) {
    unsigned local_row = blockIdx.x * blockDim.x + threadIdx.x;
    if (shard_rows == 0u || shard_start >= full_domain_rows ||
        shard_rows > full_domain_rows - shard_start || local_row >= shard_rows) { return; }
    unsigned row_index = shard_start + local_row;
    StwoCudaQm31 wave_acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    wave_acc = stwo_qm31_add(wave_acc, stwo_composition_wave_part_0(
        parts[0u], random_coeff_powers, full_domain_rows, row_index));
    wave_acc = stwo_qm31_add(wave_acc, stwo_composition_wave_part_1(
        parts[1u], random_coeff_powers, full_domain_rows, row_index));
    wave_acc = stwo_qm31_add(wave_acc, stwo_composition_wave_part_2(
        parts[2u], random_coeff_powers, full_domain_rows, row_index));
    coord_0[local_row] = wave_acc.a;
    coord_1[local_row] = wave_acc.b;
    coord_2[local_row] = wave_acc.c;
    coord_3[local_row] = wave_acc.d;
}
