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
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b3 = base_params[0u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b1, b3, b3, b3 };
    StwoCudaQm31 e1 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e0);
    e0 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    StwoCudaQm31 e2 = StwoCudaQm31{ b0, b3, b3, b3 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e0, e2);
    e2 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(ext_params, 2u);
    e3 = stwo_qm31_sub(e0, e2);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e2 = StwoCudaQm31{ b2, b3, b3, b3 };
    e0 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e2);
    e2 = stwo_load_qm31(ext_params, 3u);
    StwoCudaQm31 e4 = StwoCudaQm31{ b0, b3, b3, b3 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e2, e4);
    e4 = stwo_load_qm31(ext_params, 4u);
    e2 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(ext_params, 5u);
    e5 = stwo_qm31_sub(e2, e4);
    e4 = stwo_qm31_mul(e5, e1);
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_qm31_mul(e3, e5);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, -1);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, -1);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, -1);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, -1);
    e5 = StwoCudaQm31{ b4, b6, b8, b10 };
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e3 = StwoCudaQm31{ b5, b7, b9, b11 };
    e4 = stwo_qm31_sub(e3, e5);
    e3 = stwo_load_qm31(ext_params, 6u);
    e5 = stwo_qm31_add(e4, e3);
    e3 = stwo_qm31_mul(e5, e1);
    e5 = stwo_qm31_sub(e3, e0);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));

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
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b10 = base_params[0u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b2, b10, b10, b10 };
    StwoCudaQm31 e1 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e0);
    e0 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    StwoCudaQm31 e2 = StwoCudaQm31{ b0, b10, b10, b10 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e0, e2);
    e2 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(ext_params, 2u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 1u, row_index, 0);
    e3 = StwoCudaQm31{ b1, b10, b10, b10 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 3u);
    e0 = stwo_qm31_sub(e3, e4);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e4 = StwoCudaQm31{ b3, b10, b10, b10 };
    e3 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e4);
    e4 = stwo_load_qm31(ext_params, 4u);
    e2 = StwoCudaQm31{ b0, b10, b10, b10 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e4, e2);
    e2 = stwo_load_qm31(ext_params, 5u);
    e4 = stwo_qm31_add(e2, e5);
    e2 = stwo_load_qm31(ext_params, 6u);
    e5 = StwoCudaQm31{ b1, b10, b10, b10 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e2, e5);
    e5 = stwo_qm31_add(e4, e6);
    e6 = stwo_load_qm31(ext_params, 7u);
    e4 = stwo_qm31_sub(e5, e6);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    e6 = StwoCudaQm31{ b4, b10, b10, b10 };
    e5 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e6);
    e6 = stwo_load_qm31(ext_params, 8u);
    e2 = StwoCudaQm31{ b0, b10, b10, b10 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e6, e2);
    e2 = stwo_load_qm31(ext_params, 9u);
    e6 = stwo_qm31_add(e2, e7);
    e2 = stwo_load_qm31(ext_params, 10u);
    e7 = StwoCudaQm31{ b1, b10, b10, b10 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e2, e7);
    e7 = stwo_qm31_add(e6, e8);
    e8 = stwo_load_qm31(ext_params, 11u);
    e6 = stwo_qm31_sub(e7, e8);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e8 = StwoCudaQm31{ b5, b10, b10, b10 };
    e7 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e8);
    e8 = stwo_load_qm31(ext_params, 12u);
    e2 = StwoCudaQm31{ b0, b10, b10, b10 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e8, e2);
    e2 = stwo_load_qm31(ext_params, 13u);
    e8 = stwo_qm31_add(e2, e9);
    e2 = stwo_load_qm31(ext_params, 14u);
    e9 = StwoCudaQm31{ b1, b10, b10, b10 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e2, e9);
    e9 = stwo_qm31_add(e8, e10);
    e10 = stwo_load_qm31(ext_params, 15u);
    e8 = stwo_qm31_sub(e9, e10);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e10 = StwoCudaQm31{ b6, b10, b10, b10 };
    e9 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e10);
    e10 = stwo_load_qm31(ext_params, 16u);
    e2 = StwoCudaQm31{ b0, b10, b10, b10 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e10, e2);
    e2 = stwo_load_qm31(ext_params, 17u);
    e10 = stwo_qm31_add(e2, e11);
    e2 = stwo_load_qm31(ext_params, 18u);
    e11 = StwoCudaQm31{ b1, b10, b10, b10 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e2, e11);
    e11 = stwo_qm31_add(e10, e12);
    e12 = stwo_load_qm31(ext_params, 19u);
    e10 = stwo_qm31_sub(e11, e12);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e12 = StwoCudaQm31{ b7, b10, b10, b10 };
    e11 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e12);
    e12 = stwo_load_qm31(ext_params, 20u);
    e2 = StwoCudaQm31{ b0, b10, b10, b10 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e12, e2);
    e2 = stwo_load_qm31(ext_params, 21u);
    e12 = stwo_qm31_add(e2, e13);
    e2 = stwo_load_qm31(ext_params, 22u);
    e13 = StwoCudaQm31{ b1, b10, b10, b10 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e2, e13);
    e13 = stwo_qm31_add(e12, e14);
    e14 = stwo_load_qm31(ext_params, 23u);
    e12 = stwo_qm31_sub(e13, e14);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    e14 = StwoCudaQm31{ b8, b10, b10, b10 };
    e13 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e14);
    e14 = stwo_load_qm31(ext_params, 24u);
    e2 = StwoCudaQm31{ b0, b10, b10, b10 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e14, e2);
    e2 = stwo_load_qm31(ext_params, 25u);
    e14 = stwo_qm31_add(e2, e15);
    e2 = stwo_load_qm31(ext_params, 26u);
    e15 = StwoCudaQm31{ b1, b10, b10, b10 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e2, e15);
    e15 = stwo_qm31_add(e14, e16);
    e16 = stwo_load_qm31(ext_params, 27u);
    e14 = stwo_qm31_sub(e15, e16);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    e16 = StwoCudaQm31{ b9, b10, b10, b10 };
    e15 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e16);
    e16 = stwo_load_qm31(ext_params, 28u);
    e2 = StwoCudaQm31{ b0, b10, b10, b10 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e16, e2);
    e2 = stwo_load_qm31(ext_params, 29u);
    e16 = stwo_qm31_add(e2, e17);
    e2 = stwo_load_qm31(ext_params, 30u);
    e17 = StwoCudaQm31{ b1, b10, b10, b10 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e2, e17);
    e17 = stwo_qm31_add(e16, e18);
    e18 = stwo_load_qm31(ext_params, 31u);
    e16 = stwo_qm31_sub(e17, e18);
    e18 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e18, e1);
    e1 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_mul(e8, e5);
    e5 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e4, e5);
    e5 = stwo_qm31_mul(e6, e8);
    e8 = stwo_qm31_mul(e12, e9);
    e9 = stwo_qm31_mul(e10, e11);
    e11 = stwo_qm31_add(e8, e9);
    e9 = stwo_qm31_mul(e10, e12);
    e12 = stwo_qm31_mul(e16, e13);
    e13 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e12, e13);
    e13 = stwo_qm31_mul(e14, e16);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e16 = StwoCudaQm31{ b11, b12, b13, b14 };
    e14 = stwo_qm31_mul(e16, e1);
    e1 = stwo_qm31_sub(e14, e3);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e14 = StwoCudaQm31{ b15, b16, b17, b18 };
    e3 = stwo_qm31_sub(e14, e16);
    e16 = stwo_qm31_mul(e3, e5);
    e3 = stwo_qm31_sub(e16, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e16 = StwoCudaQm31{ b19, b20, b21, b22 };
    e7 = stwo_qm31_sub(e16, e14);
    e14 = stwo_qm31_mul(e7, e9);
    e7 = stwo_qm31_sub(e14, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, -1);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, -1);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, -1);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, -1);
    e14 = StwoCudaQm31{ b23, b25, b27, b29 };
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e11 = StwoCudaQm31{ b24, b26, b28, b30 };
    e9 = stwo_qm31_sub(e11, e14);
    e11 = stwo_qm31_sub(e9, e16);
    e9 = stwo_load_qm31(ext_params, 32u);
    e16 = stwo_qm31_add(e11, e9);
    e9 = stwo_qm31_mul(e16, e13);
    e16 = stwo_qm31_sub(e9, e15);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));

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
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b5 = base_params[0u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b4, b5, b5, b5 };
    StwoCudaQm31 e1 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e0);
    e0 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    StwoCudaQm31 e2 = StwoCudaQm31{ b0, b5, b5, b5 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e0, e2);
    e2 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(ext_params, 2u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 1u, row_index, 0);
    e3 = StwoCudaQm31{ b1, b5, b5, b5 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 3u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 2u, row_index, 0);
    e0 = StwoCudaQm31{ b2, b5, b5, b5 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 4u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 3u, row_index, 0);
    e3 = StwoCudaQm31{ b3, b5, b5, b5 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 5u);
    e0 = stwo_qm31_sub(e3, e4);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, -1);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, -1);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, -1);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, -1);
    e4 = StwoCudaQm31{ b6, b8, b10, b12 };
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e3 = StwoCudaQm31{ b7, b9, b11, b13 };
    e2 = stwo_qm31_sub(e3, e4);
    e3 = stwo_load_qm31(ext_params, 6u);
    e4 = stwo_qm31_add(e2, e3);
    e3 = stwo_qm31_mul(e4, e0);
    e4 = stwo_qm31_sub(e3, e1);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));

    unsigned denom_idx = row_index >> log_n_rows;
    return stwo_qm31_mul_base(acc, part.denom_inv[denom_idx]);
}

__device__ __noinline__ StwoCudaQm31 stwo_composition_wave_part_3(
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
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b4 = base_params[0u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b3, b4, b4, b4 };
    StwoCudaQm31 e1 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e0);
    e0 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    StwoCudaQm31 e2 = StwoCudaQm31{ b0, b4, b4, b4 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e0, e2);
    e2 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(ext_params, 2u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 1u, row_index, 0);
    e3 = StwoCudaQm31{ b1, b4, b4, b4 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 3u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 2u, row_index, 0);
    e0 = StwoCudaQm31{ b2, b4, b4, b4 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 4u);
    e3 = stwo_qm31_sub(e0, e2);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, -1);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, -1);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, -1);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, -1);
    e2 = StwoCudaQm31{ b5, b7, b9, b11 };
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e0 = StwoCudaQm31{ b6, b8, b10, b12 };
    e4 = stwo_qm31_sub(e0, e2);
    e0 = stwo_load_qm31(ext_params, 5u);
    e2 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e2, e3);
    e2 = stwo_qm31_sub(e0, e1);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));

    unsigned denom_idx = row_index >> log_n_rows;
    return stwo_qm31_mul_base(acc, part.denom_inv[denom_idx]);
}

extern "C" __global__ void __launch_bounds__(128) stwo_composition_wave_60d2b7627154ca26(
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
    wave_acc = stwo_qm31_add(wave_acc, stwo_composition_wave_part_3(
        parts[3u], random_coeff_powers, full_domain_rows, row_index));
    coord_0[local_row] = wave_acc.a;
    coord_1[local_row] = wave_acc.b;
    coord_2[local_row] = wave_acc.c;
    coord_3[local_row] = wave_acc.d;
}
