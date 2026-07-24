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
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b17 = base_params[0u];
    unsigned b18 = stwo_m31_mul(b8, b17);
    unsigned b19 = stwo_m31_add(b7, b18);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    unsigned b20 = stwo_m31_sub(b19, b1);
    unsigned b21 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b20, b21, b21, b21 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b22 = base_params[2u];
    unsigned b23 = stwo_m31_mul(b10, b22);
    unsigned b24 = stwo_m31_add(b9, b23);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b25 = base_params[3u];
    unsigned b26 = stwo_m31_mul(b11, b25);
    unsigned b27 = stwo_m31_add(b24, b26);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b28 = stwo_m31_sub(b27, b2);
    StwoCudaQm31 e1 = StwoCudaQm31{ b28, b21, b21, b21 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    unsigned b29 = base_params[4u];
    unsigned b30 = stwo_m31_mul(b13, b29);
    unsigned b31 = stwo_m31_add(b12, b30);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    unsigned b32 = base_params[5u];
    unsigned b33 = stwo_m31_mul(b14, b32);
    unsigned b34 = stwo_m31_add(b31, b33);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    unsigned b35 = stwo_m31_sub(b34, b3);
    StwoCudaQm31 e2 = StwoCudaQm31{ b35, b21, b21, b21 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    StwoCudaQm31 e3 = stwo_load_qm31(ext_params, 0u);
    StwoCudaQm31 e4 = StwoCudaQm31{ b8, b21, b21, b21 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_load_qm31(ext_params, 1u);
    e3 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(ext_params, 2u);
    e5 = StwoCudaQm31{ b9, b21, b21, b21 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 3u);
    e3 = StwoCudaQm31{ b11, b21, b21, b21 };
    e4 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 4u);
    e5 = stwo_qm31_sub(e3, e4);
    e4 = stwo_load_qm31(ext_params, 5u);
    e3 = StwoCudaQm31{ b12, b21, b21, b21 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(ext_params, 6u);
    e4 = stwo_qm31_add(e3, e6);
    e3 = stwo_load_qm31(ext_params, 7u);
    e6 = StwoCudaQm31{ b14, b21, b21, b21 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e3, e6);
    e6 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 8u);
    e4 = stwo_qm31_sub(e6, e7);
    e7 = stwo_load_qm31(ext_params, 9u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    e6 = StwoCudaQm31{ b0, b21, b21, b21 };
    e3 = stwo_qm31_mul(e7, e6);
    e6 = stwo_load_qm31(ext_params, 10u);
    e7 = stwo_qm31_add(e6, e3);
    e6 = stwo_load_qm31(ext_params, 11u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    e3 = StwoCudaQm31{ b15, b21, b21, b21 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 12u);
    e7 = stwo_qm31_sub(e3, e8);
    e8 = stwo_load_qm31(ext_params, 13u);
    e3 = StwoCudaQm31{ b15, b21, b21, b21 };
    e6 = stwo_qm31_mul(e8, e3);
    e3 = stwo_load_qm31(ext_params, 14u);
    e8 = stwo_qm31_add(e3, e6);
    e3 = stwo_load_qm31(ext_params, 15u);
    e6 = StwoCudaQm31{ b7, b21, b21, b21 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e3, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 16u);
    unsigned b36 = base_params[6u];
    unsigned b37 = stwo_m31_mul(b9, b36);
    unsigned b38 = stwo_m31_add(b8, b37);
    e8 = StwoCudaQm31{ b38, b21, b21, b21 };
    e3 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(ext_params, 17u);
    e6 = StwoCudaQm31{ b10, b21, b21, b21 };
    e9 = stwo_qm31_mul(e3, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 18u);
    unsigned b39 = base_params[7u];
    unsigned b40 = stwo_m31_mul(b12, b39);
    unsigned b41 = stwo_m31_add(b11, b40);
    e8 = StwoCudaQm31{ b41, b21, b21, b21 };
    e3 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(ext_params, 19u);
    e6 = StwoCudaQm31{ b13, b21, b21, b21 };
    e9 = stwo_qm31_mul(e3, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 20u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    unsigned b42 = stwo_m31_add(b14, b4);
    e8 = StwoCudaQm31{ b42, b21, b21, b21 };
    e3 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(ext_params, 21u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e6 = StwoCudaQm31{ b5, b21, b21, b21 };
    e9 = stwo_qm31_mul(e3, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 22u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    e8 = StwoCudaQm31{ b6, b21, b21, b21 };
    e3 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(ext_params, 23u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(ext_params, 24u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(ext_params, 25u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(ext_params, 26u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(ext_params, 27u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(ext_params, 28u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(ext_params, 29u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(ext_params, 30u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(ext_params, 31u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(ext_params, 32u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(ext_params, 33u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(ext_params, 34u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(ext_params, 35u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(ext_params, 36u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(ext_params, 37u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(ext_params, 38u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(ext_params, 39u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(ext_params, 40u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(ext_params, 41u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(ext_params, 42u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(ext_params, 43u);
    e6 = stwo_qm31_sub(e8, e3);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    e3 = StwoCudaQm31{ b16, b21, b21, b21 };
    e8 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e3);
    e3 = stwo_load_qm31(ext_params, 44u);
    e9 = StwoCudaQm31{ b0, b21, b21, b21 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e3, e9);
    e9 = stwo_load_qm31(ext_params, 45u);
    e3 = stwo_qm31_add(e9, e10);
    e9 = stwo_load_qm31(ext_params, 46u);
    e10 = StwoCudaQm31{ b1, b21, b21, b21 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e3, e11);
    e11 = stwo_load_qm31(ext_params, 47u);
    e3 = StwoCudaQm31{ b2, b21, b21, b21 };
    e9 = stwo_qm31_mul(e11, e3);
    e3 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 48u);
    e10 = StwoCudaQm31{ b3, b21, b21, b21 };
    e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e3, e11);
    e11 = stwo_load_qm31(ext_params, 49u);
    e3 = StwoCudaQm31{ b4, b21, b21, b21 };
    e9 = stwo_qm31_mul(e11, e3);
    e3 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 50u);
    e10 = StwoCudaQm31{ b5, b21, b21, b21 };
    e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e3, e11);
    e11 = stwo_load_qm31(ext_params, 51u);
    e3 = StwoCudaQm31{ b6, b21, b21, b21 };
    e9 = stwo_qm31_mul(e11, e3);
    e3 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 52u);
    e10 = stwo_qm31_sub(e3, e9);
    e9 = stwo_load_qm31(ext_params, 53u);
    e3 = stwo_qm31_mul(e4, e9);
    e9 = stwo_load_qm31(ext_params, 54u);
    e11 = stwo_qm31_mul(e5, e9);
    e9 = stwo_qm31_add(e3, e11);
    e11 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(ext_params, 55u);
    e5 = stwo_qm31_mul(e6, e4);
    e4 = stwo_load_qm31(ext_params, 56u);
    e3 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e5, e3);
    e3 = stwo_qm31_mul(e7, e6);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e6 = StwoCudaQm31{ b43, b44, b45, b46 };
    e7 = stwo_qm31_mul(e6, e11);
    e11 = stwo_qm31_sub(e7, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e7 = StwoCudaQm31{ b47, b48, b49, b50 };
    e9 = stwo_qm31_sub(e7, e6);
    e6 = stwo_qm31_mul(e9, e3);
    e9 = stwo_qm31_sub(e6, e4);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, -1);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, -1);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, -1);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, -1);
    e6 = StwoCudaQm31{ b51, b53, b55, b57 };
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e4 = StwoCudaQm31{ b52, b54, b56, b58 };
    e3 = stwo_qm31_sub(e4, e6);
    e4 = stwo_qm31_sub(e3, e7);
    e3 = stwo_load_qm31(ext_params, 57u);
    e7 = stwo_qm31_add(e4, e3);
    e3 = stwo_qm31_mul(e7, e10);
    e7 = stwo_qm31_sub(e3, e8);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));

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
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b2 = base_params[0u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b1, b2, b2, b2 };
    StwoCudaQm31 e1 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e0);
    e0 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    StwoCudaQm31 e2 = StwoCudaQm31{ b0, b2, b2, b2 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e0, e2);
    e2 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(ext_params, 2u);
    e3 = stwo_qm31_sub(e0, e2);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, -1);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, -1);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, -1);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, -1);
    e2 = StwoCudaQm31{ b3, b5, b7, b9 };
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e0 = StwoCudaQm31{ b4, b6, b8, b10 };
    StwoCudaQm31 e4 = stwo_qm31_sub(e0, e2);
    e0 = stwo_load_qm31(ext_params, 3u);
    e2 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e2, e3);
    e2 = stwo_qm31_sub(e0, e1);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));

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
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b3 = base_params[0u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b2, b3, b3, b3 };
    StwoCudaQm31 e1 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e0);
    e0 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    StwoCudaQm31 e2 = StwoCudaQm31{ b0, b3, b3, b3 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e0, e2);
    e2 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(ext_params, 2u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 1u, row_index, 0);
    e3 = StwoCudaQm31{ b1, b3, b3, b3 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 3u);
    e0 = stwo_qm31_sub(e3, e4);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, -1);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, -1);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, -1);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, -1);
    e4 = StwoCudaQm31{ b4, b6, b8, b10 };
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e3 = StwoCudaQm31{ b5, b7, b9, b11 };
    e2 = stwo_qm31_sub(e3, e4);
    e3 = stwo_load_qm31(ext_params, 4u);
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

extern "C" __global__ void __launch_bounds__(128) stwo_composition_wave_43e68bcebe6187ea(
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
