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
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b10 = base_params[3u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b3, b10, b10, b10 };
    StwoCudaQm31 e1 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e0);
    e0 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    unsigned b4 = base_params[0u];
    unsigned b5 = stwo_m31_add(b0, b4);
    StwoCudaQm31 e2 = StwoCudaQm31{ b5, b10, b10, b10 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e0, e2);
    e2 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(ext_params, 2u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 1u, row_index, 0);
    unsigned b6 = base_params[1u];
    unsigned b7 = stwo_m31_add(b1, b6);
    e3 = StwoCudaQm31{ b7, b10, b10, b10 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 3u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 2u, row_index, 0);
    unsigned b8 = base_params[2u];
    unsigned b9 = stwo_m31_add(b2, b8);
    e0 = StwoCudaQm31{ b9, b10, b10, b10 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 4u);
    e3 = stwo_qm31_sub(e0, e2);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e2 = StwoCudaQm31{ b11, b10, b10, b10 };
    e0 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e2);
    e2 = stwo_load_qm31(ext_params, 5u);
    unsigned b12 = base_params[4u];
    unsigned b13 = stwo_m31_add(b0, b12);
    e4 = StwoCudaQm31{ b13, b10, b10, b10 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e2, e4);
    e4 = stwo_load_qm31(ext_params, 6u);
    e2 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(ext_params, 7u);
    unsigned b14 = base_params[5u];
    unsigned b15 = stwo_m31_add(b1, b14);
    e5 = StwoCudaQm31{ b15, b10, b10, b10 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 8u);
    unsigned b16 = base_params[6u];
    unsigned b17 = stwo_m31_add(b2, b16);
    e2 = StwoCudaQm31{ b17, b10, b10, b10 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 9u);
    e5 = stwo_qm31_sub(e2, e4);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    e4 = StwoCudaQm31{ b18, b10, b10, b10 };
    e2 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e4);
    e4 = stwo_load_qm31(ext_params, 10u);
    unsigned b19 = base_params[7u];
    unsigned b20 = stwo_m31_add(b0, b19);
    e6 = StwoCudaQm31{ b20, b10, b10, b10 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e4, e6);
    e6 = stwo_load_qm31(ext_params, 11u);
    e4 = stwo_qm31_add(e6, e7);
    e6 = stwo_load_qm31(ext_params, 12u);
    unsigned b21 = base_params[8u];
    unsigned b22 = stwo_m31_add(b1, b21);
    e7 = StwoCudaQm31{ b22, b10, b10, b10 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e4, e8);
    e8 = stwo_load_qm31(ext_params, 13u);
    unsigned b23 = base_params[9u];
    unsigned b24 = stwo_m31_add(b2, b23);
    e4 = StwoCudaQm31{ b24, b10, b10, b10 };
    e6 = stwo_qm31_mul(e8, e4);
    e4 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(ext_params, 14u);
    e7 = stwo_qm31_sub(e4, e6);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e6 = StwoCudaQm31{ b25, b10, b10, b10 };
    e4 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e6);
    e6 = stwo_load_qm31(ext_params, 15u);
    unsigned b26 = base_params[10u];
    unsigned b27 = stwo_m31_add(b0, b26);
    e8 = StwoCudaQm31{ b27, b10, b10, b10 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e6, e8);
    e8 = stwo_load_qm31(ext_params, 16u);
    e6 = stwo_qm31_add(e8, e9);
    e8 = stwo_load_qm31(ext_params, 17u);
    unsigned b28 = base_params[11u];
    unsigned b29 = stwo_m31_add(b1, b28);
    e9 = StwoCudaQm31{ b29, b10, b10, b10 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e6, e10);
    e10 = stwo_load_qm31(ext_params, 18u);
    unsigned b30 = base_params[12u];
    unsigned b31 = stwo_m31_add(b2, b30);
    e6 = StwoCudaQm31{ b31, b10, b10, b10 };
    e8 = stwo_qm31_mul(e10, e6);
    e6 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(ext_params, 19u);
    e9 = stwo_qm31_sub(e6, e8);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e8 = StwoCudaQm31{ b32, b10, b10, b10 };
    e6 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e8);
    e8 = stwo_load_qm31(ext_params, 20u);
    unsigned b33 = base_params[13u];
    unsigned b34 = stwo_m31_add(b0, b33);
    e10 = StwoCudaQm31{ b34, b10, b10, b10 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e8, e10);
    e10 = stwo_load_qm31(ext_params, 21u);
    e8 = stwo_qm31_add(e10, e11);
    e10 = stwo_load_qm31(ext_params, 22u);
    unsigned b35 = base_params[14u];
    unsigned b36 = stwo_m31_add(b1, b35);
    e11 = StwoCudaQm31{ b36, b10, b10, b10 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e10, e11);
    e11 = stwo_qm31_add(e8, e12);
    e12 = stwo_load_qm31(ext_params, 23u);
    unsigned b37 = base_params[15u];
    unsigned b38 = stwo_m31_add(b2, b37);
    e8 = StwoCudaQm31{ b38, b10, b10, b10 };
    e10 = stwo_qm31_mul(e12, e8);
    e8 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(ext_params, 24u);
    e11 = stwo_qm31_sub(e8, e10);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e10 = StwoCudaQm31{ b39, b10, b10, b10 };
    e8 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e10);
    e10 = stwo_load_qm31(ext_params, 25u);
    unsigned b40 = base_params[16u];
    unsigned b41 = stwo_m31_add(b0, b40);
    e12 = StwoCudaQm31{ b41, b10, b10, b10 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e10, e12);
    e12 = stwo_load_qm31(ext_params, 26u);
    e10 = stwo_qm31_add(e12, e13);
    e12 = stwo_load_qm31(ext_params, 27u);
    unsigned b42 = base_params[17u];
    unsigned b43 = stwo_m31_add(b1, b42);
    e13 = StwoCudaQm31{ b43, b10, b10, b10 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e12, e13);
    e13 = stwo_qm31_add(e10, e14);
    e14 = stwo_load_qm31(ext_params, 28u);
    unsigned b44 = base_params[18u];
    unsigned b45 = stwo_m31_add(b2, b44);
    e10 = StwoCudaQm31{ b45, b10, b10, b10 };
    e12 = stwo_qm31_mul(e14, e10);
    e10 = stwo_qm31_add(e13, e12);
    e12 = stwo_load_qm31(ext_params, 29u);
    e13 = stwo_qm31_sub(e10, e12);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    e12 = StwoCudaQm31{ b46, b10, b10, b10 };
    e10 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e12);
    e12 = stwo_load_qm31(ext_params, 30u);
    unsigned b47 = base_params[19u];
    unsigned b48 = stwo_m31_add(b0, b47);
    e14 = StwoCudaQm31{ b48, b10, b10, b10 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e12, e14);
    e14 = stwo_load_qm31(ext_params, 31u);
    e12 = stwo_qm31_add(e14, e15);
    e14 = stwo_load_qm31(ext_params, 32u);
    unsigned b49 = base_params[20u];
    unsigned b50 = stwo_m31_add(b1, b49);
    e15 = StwoCudaQm31{ b50, b10, b10, b10 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e12, e16);
    e16 = stwo_load_qm31(ext_params, 33u);
    unsigned b51 = base_params[21u];
    unsigned b52 = stwo_m31_add(b2, b51);
    e12 = StwoCudaQm31{ b52, b10, b10, b10 };
    e14 = stwo_qm31_mul(e16, e12);
    e12 = stwo_qm31_add(e15, e14);
    e14 = stwo_load_qm31(ext_params, 34u);
    e15 = stwo_qm31_sub(e12, e14);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    e14 = StwoCudaQm31{ b53, b10, b10, b10 };
    e12 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e14);
    e14 = stwo_load_qm31(ext_params, 35u);
    unsigned b54 = base_params[22u];
    unsigned b55 = stwo_m31_add(b0, b54);
    e16 = StwoCudaQm31{ b55, b10, b10, b10 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e14, e16);
    e16 = stwo_load_qm31(ext_params, 36u);
    e14 = stwo_qm31_add(e16, e17);
    e16 = stwo_load_qm31(ext_params, 37u);
    unsigned b56 = base_params[23u];
    unsigned b57 = stwo_m31_add(b1, b56);
    e17 = StwoCudaQm31{ b57, b10, b10, b10 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e16, e17);
    e17 = stwo_qm31_add(e14, e18);
    e18 = stwo_load_qm31(ext_params, 38u);
    unsigned b58 = base_params[24u];
    unsigned b59 = stwo_m31_add(b2, b58);
    e14 = StwoCudaQm31{ b59, b10, b10, b10 };
    e16 = stwo_qm31_mul(e18, e14);
    e14 = stwo_qm31_add(e17, e16);
    e16 = stwo_load_qm31(ext_params, 39u);
    e17 = stwo_qm31_sub(e14, e16);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    e16 = StwoCudaQm31{ b60, b10, b10, b10 };
    e14 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e16);
    e16 = stwo_load_qm31(ext_params, 40u);
    unsigned b61 = base_params[25u];
    unsigned b62 = stwo_m31_add(b0, b61);
    e18 = StwoCudaQm31{ b62, b10, b10, b10 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e16, e18);
    e18 = stwo_load_qm31(ext_params, 41u);
    e16 = stwo_qm31_add(e18, e19);
    e18 = stwo_load_qm31(ext_params, 42u);
    unsigned b63 = base_params[26u];
    unsigned b64 = stwo_m31_add(b1, b63);
    e19 = StwoCudaQm31{ b64, b10, b10, b10 };
    StwoCudaQm31 e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e16, e20);
    e20 = stwo_load_qm31(ext_params, 43u);
    unsigned b65 = base_params[27u];
    unsigned b66 = stwo_m31_add(b2, b65);
    e16 = StwoCudaQm31{ b66, b10, b10, b10 };
    e18 = stwo_qm31_mul(e20, e16);
    e16 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(ext_params, 44u);
    e19 = stwo_qm31_sub(e16, e18);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    e18 = StwoCudaQm31{ b67, b10, b10, b10 };
    e16 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e18);
    e18 = stwo_load_qm31(ext_params, 45u);
    unsigned b68 = base_params[28u];
    unsigned b69 = stwo_m31_add(b0, b68);
    e20 = StwoCudaQm31{ b69, b10, b10, b10 };
    StwoCudaQm31 e21 = stwo_qm31_mul(e18, e20);
    e20 = stwo_load_qm31(ext_params, 46u);
    e18 = stwo_qm31_add(e20, e21);
    e20 = stwo_load_qm31(ext_params, 47u);
    unsigned b70 = base_params[29u];
    unsigned b71 = stwo_m31_add(b1, b70);
    e21 = StwoCudaQm31{ b71, b10, b10, b10 };
    StwoCudaQm31 e22 = stwo_qm31_mul(e20, e21);
    e21 = stwo_qm31_add(e18, e22);
    e22 = stwo_load_qm31(ext_params, 48u);
    unsigned b72 = base_params[30u];
    unsigned b73 = stwo_m31_add(b2, b72);
    e18 = StwoCudaQm31{ b73, b10, b10, b10 };
    e20 = stwo_qm31_mul(e22, e18);
    e18 = stwo_qm31_add(e21, e20);
    e20 = stwo_load_qm31(ext_params, 49u);
    e21 = stwo_qm31_sub(e18, e20);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    e20 = StwoCudaQm31{ b74, b10, b10, b10 };
    e18 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e20);
    e20 = stwo_load_qm31(ext_params, 50u);
    unsigned b75 = base_params[31u];
    unsigned b76 = stwo_m31_add(b0, b75);
    e22 = StwoCudaQm31{ b76, b10, b10, b10 };
    StwoCudaQm31 e23 = stwo_qm31_mul(e20, e22);
    e22 = stwo_load_qm31(ext_params, 51u);
    e20 = stwo_qm31_add(e22, e23);
    e22 = stwo_load_qm31(ext_params, 52u);
    unsigned b77 = base_params[32u];
    unsigned b78 = stwo_m31_add(b1, b77);
    e23 = StwoCudaQm31{ b78, b10, b10, b10 };
    StwoCudaQm31 e24 = stwo_qm31_mul(e22, e23);
    e23 = stwo_qm31_add(e20, e24);
    e24 = stwo_load_qm31(ext_params, 53u);
    unsigned b79 = base_params[33u];
    unsigned b80 = stwo_m31_add(b2, b79);
    e20 = StwoCudaQm31{ b80, b10, b10, b10 };
    e22 = stwo_qm31_mul(e24, e20);
    e20 = stwo_qm31_add(e23, e22);
    e22 = stwo_load_qm31(ext_params, 54u);
    e23 = stwo_qm31_sub(e20, e22);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    e22 = StwoCudaQm31{ b81, b10, b10, b10 };
    e20 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e22);
    e22 = stwo_load_qm31(ext_params, 55u);
    unsigned b82 = base_params[34u];
    unsigned b83 = stwo_m31_add(b0, b82);
    e24 = StwoCudaQm31{ b83, b10, b10, b10 };
    StwoCudaQm31 e25 = stwo_qm31_mul(e22, e24);
    e24 = stwo_load_qm31(ext_params, 56u);
    e22 = stwo_qm31_add(e24, e25);
    e24 = stwo_load_qm31(ext_params, 57u);
    unsigned b84 = base_params[35u];
    unsigned b85 = stwo_m31_add(b1, b84);
    e25 = StwoCudaQm31{ b85, b10, b10, b10 };
    StwoCudaQm31 e26 = stwo_qm31_mul(e24, e25);
    e25 = stwo_qm31_add(e22, e26);
    e26 = stwo_load_qm31(ext_params, 58u);
    unsigned b86 = base_params[36u];
    unsigned b87 = stwo_m31_add(b2, b86);
    e22 = StwoCudaQm31{ b87, b10, b10, b10 };
    e24 = stwo_qm31_mul(e26, e22);
    e22 = stwo_qm31_add(e25, e24);
    e24 = stwo_load_qm31(ext_params, 59u);
    e25 = stwo_qm31_sub(e22, e24);
    e24 = stwo_qm31_mul(e5, e1);
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e24, e1);
    e1 = stwo_qm31_mul(e3, e5);
    e5 = stwo_qm31_mul(e9, e2);
    e2 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e5, e2);
    e2 = stwo_qm31_mul(e7, e9);
    e9 = stwo_qm31_mul(e13, e6);
    e6 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e9, e6);
    e6 = stwo_qm31_mul(e11, e13);
    e13 = stwo_qm31_mul(e17, e10);
    e10 = stwo_qm31_mul(e15, e12);
    e12 = stwo_qm31_add(e13, e10);
    e10 = stwo_qm31_mul(e15, e17);
    e17 = stwo_qm31_mul(e21, e14);
    e14 = stwo_qm31_mul(e19, e16);
    e16 = stwo_qm31_add(e17, e14);
    e14 = stwo_qm31_mul(e19, e21);
    e21 = stwo_qm31_mul(e25, e18);
    e18 = stwo_qm31_mul(e23, e20);
    e20 = stwo_qm31_add(e21, e18);
    e18 = stwo_qm31_mul(e23, e25);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e25 = StwoCudaQm31{ b88, b89, b90, b91 };
    e23 = stwo_qm31_mul(e25, e1);
    e1 = stwo_qm31_sub(e23, e0);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e23 = StwoCudaQm31{ b92, b93, b94, b95 };
    e0 = stwo_qm31_sub(e23, e25);
    e25 = stwo_qm31_mul(e0, e2);
    e0 = stwo_qm31_sub(e25, e4);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e25 = StwoCudaQm31{ b96, b97, b98, b99 };
    e4 = stwo_qm31_sub(e25, e23);
    e23 = stwo_qm31_mul(e4, e6);
    e4 = stwo_qm31_sub(e23, e8);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e23 = StwoCudaQm31{ b100, b101, b102, b103 };
    e8 = stwo_qm31_sub(e23, e25);
    e25 = stwo_qm31_mul(e8, e10);
    e8 = stwo_qm31_sub(e25, e12);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, 0);
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, 0);
    unsigned b106 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, 0);
    unsigned b107 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, 0);
    e25 = StwoCudaQm31{ b104, b105, b106, b107 };
    e12 = stwo_qm31_sub(e25, e23);
    e23 = stwo_qm31_mul(e12, e14);
    e12 = stwo_qm31_sub(e23, e16);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b108 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 20u, row_index, 0);
    unsigned b109 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 21u, row_index, 0);
    unsigned b110 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 22u, row_index, 0);
    unsigned b111 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 23u, row_index, 0);
    e23 = StwoCudaQm31{ b108, b109, b110, b111 };
    e16 = stwo_qm31_sub(e23, e25);
    e23 = stwo_qm31_mul(e16, e18);
    e16 = stwo_qm31_sub(e23, e20);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));

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
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b3 = base_params[3u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b4, b3, b3, b3 };
    StwoCudaQm31 e1 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e0);
    e0 = stwo_load_qm31(ext_params, 60u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    unsigned b5 = base_params[37u];
    unsigned b6 = stwo_m31_add(b0, b5);
    StwoCudaQm31 e2 = StwoCudaQm31{ b6, b3, b3, b3 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e0, e2);
    e2 = stwo_load_qm31(ext_params, 61u);
    e0 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(ext_params, 62u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 1u, row_index, 0);
    unsigned b7 = base_params[38u];
    unsigned b8 = stwo_m31_add(b1, b7);
    e3 = StwoCudaQm31{ b8, b3, b3, b3 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 63u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 2u, row_index, 0);
    unsigned b9 = base_params[39u];
    unsigned b10 = stwo_m31_add(b2, b9);
    e0 = StwoCudaQm31{ b10, b3, b3, b3 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 64u);
    e3 = stwo_qm31_sub(e0, e2);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    e2 = StwoCudaQm31{ b11, b3, b3, b3 };
    e0 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e2);
    e2 = stwo_load_qm31(ext_params, 65u);
    unsigned b12 = base_params[40u];
    unsigned b13 = stwo_m31_add(b0, b12);
    e4 = StwoCudaQm31{ b13, b3, b3, b3 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e2, e4);
    e4 = stwo_load_qm31(ext_params, 66u);
    e2 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(ext_params, 67u);
    unsigned b14 = base_params[41u];
    unsigned b15 = stwo_m31_add(b1, b14);
    e5 = StwoCudaQm31{ b15, b3, b3, b3 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(ext_params, 68u);
    unsigned b16 = base_params[42u];
    unsigned b17 = stwo_m31_add(b2, b16);
    e2 = StwoCudaQm31{ b17, b3, b3, b3 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 69u);
    e5 = stwo_qm31_sub(e2, e4);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    e4 = StwoCudaQm31{ b18, b3, b3, b3 };
    e2 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e4);
    e4 = stwo_load_qm31(ext_params, 70u);
    unsigned b19 = base_params[43u];
    unsigned b20 = stwo_m31_add(b0, b19);
    e6 = StwoCudaQm31{ b20, b3, b3, b3 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e4, e6);
    e6 = stwo_load_qm31(ext_params, 71u);
    e4 = stwo_qm31_add(e6, e7);
    e6 = stwo_load_qm31(ext_params, 72u);
    unsigned b21 = base_params[44u];
    unsigned b22 = stwo_m31_add(b1, b21);
    e7 = StwoCudaQm31{ b22, b3, b3, b3 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e4, e8);
    e8 = stwo_load_qm31(ext_params, 73u);
    unsigned b23 = base_params[45u];
    unsigned b24 = stwo_m31_add(b2, b23);
    e4 = StwoCudaQm31{ b24, b3, b3, b3 };
    e6 = stwo_qm31_mul(e8, e4);
    e4 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(ext_params, 74u);
    e7 = stwo_qm31_sub(e4, e6);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    e6 = StwoCudaQm31{ b25, b3, b3, b3 };
    e4 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e6);
    e6 = stwo_load_qm31(ext_params, 75u);
    unsigned b26 = base_params[46u];
    unsigned b27 = stwo_m31_add(b0, b26);
    e8 = StwoCudaQm31{ b27, b3, b3, b3 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e6, e8);
    e8 = stwo_load_qm31(ext_params, 76u);
    e6 = stwo_qm31_add(e8, e9);
    e8 = stwo_load_qm31(ext_params, 77u);
    unsigned b28 = base_params[47u];
    unsigned b29 = stwo_m31_add(b1, b28);
    e9 = StwoCudaQm31{ b29, b3, b3, b3 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e6, e10);
    e10 = stwo_load_qm31(ext_params, 78u);
    unsigned b30 = base_params[48u];
    unsigned b31 = stwo_m31_add(b2, b30);
    e6 = StwoCudaQm31{ b31, b3, b3, b3 };
    e8 = stwo_qm31_mul(e10, e6);
    e6 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(ext_params, 79u);
    e9 = stwo_qm31_sub(e6, e8);
    e8 = stwo_qm31_mul(e5, e1);
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e8, e1);
    e1 = stwo_qm31_mul(e3, e5);
    e5 = stwo_qm31_mul(e9, e2);
    e2 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e5, e2);
    e2 = stwo_qm31_mul(e7, e9);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 20u, row_index, 0);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 21u, row_index, 0);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 22u, row_index, 0);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 23u, row_index, 0);
    e9 = StwoCudaQm31{ b32, b33, b34, b35 };
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 24u, row_index, 0);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 25u, row_index, 0);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 26u, row_index, 0);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 27u, row_index, 0);
    e7 = StwoCudaQm31{ b36, b37, b38, b39 };
    e5 = stwo_qm31_sub(e7, e9);
    e9 = stwo_qm31_mul(e5, e1);
    e5 = stwo_qm31_sub(e9, e0);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 28u, row_index, -1);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 29u, row_index, -1);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 30u, row_index, -1);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 31u, row_index, -1);
    e9 = StwoCudaQm31{ b40, b42, b44, b46 };
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 28u, row_index, 0);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 29u, row_index, 0);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 30u, row_index, 0);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 31u, row_index, 0);
    e0 = StwoCudaQm31{ b41, b43, b45, b47 };
    e1 = stwo_qm31_sub(e0, e9);
    e0 = stwo_qm31_sub(e1, e7);
    e1 = stwo_load_qm31(ext_params, 80u);
    e7 = stwo_qm31_add(e0, e1);
    e1 = stwo_qm31_mul(e7, e2);
    e7 = stwo_qm31_sub(e1, e4);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));

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
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b9 = base_params[0u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b1, b9, b9, b9 };
    StwoCudaQm31 e1 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e0);
    e0 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    StwoCudaQm31 e2 = StwoCudaQm31{ b0, b9, b9, b9 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e0, e2);
    e2 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(ext_params, 2u);
    e3 = stwo_qm31_sub(e0, e2);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e2 = StwoCudaQm31{ b2, b9, b9, b9 };
    e0 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e2);
    e2 = stwo_load_qm31(ext_params, 3u);
    StwoCudaQm31 e4 = StwoCudaQm31{ b0, b9, b9, b9 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e2, e4);
    e4 = stwo_load_qm31(ext_params, 4u);
    e2 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(ext_params, 5u);
    e5 = stwo_qm31_sub(e2, e4);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    e4 = StwoCudaQm31{ b3, b9, b9, b9 };
    e2 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e4);
    e4 = stwo_load_qm31(ext_params, 6u);
    StwoCudaQm31 e6 = StwoCudaQm31{ b0, b9, b9, b9 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e4, e6);
    e6 = stwo_load_qm31(ext_params, 7u);
    e4 = stwo_qm31_add(e6, e7);
    e6 = stwo_load_qm31(ext_params, 8u);
    e7 = stwo_qm31_sub(e4, e6);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e6 = StwoCudaQm31{ b4, b9, b9, b9 };
    e4 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e6);
    e6 = stwo_load_qm31(ext_params, 9u);
    StwoCudaQm31 e8 = StwoCudaQm31{ b0, b9, b9, b9 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e6, e8);
    e8 = stwo_load_qm31(ext_params, 10u);
    e6 = stwo_qm31_add(e8, e9);
    e8 = stwo_load_qm31(ext_params, 11u);
    e9 = stwo_qm31_sub(e6, e8);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e8 = StwoCudaQm31{ b5, b9, b9, b9 };
    e6 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e8);
    e8 = stwo_load_qm31(ext_params, 12u);
    StwoCudaQm31 e10 = StwoCudaQm31{ b0, b9, b9, b9 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e8, e10);
    e10 = stwo_load_qm31(ext_params, 13u);
    e8 = stwo_qm31_add(e10, e11);
    e10 = stwo_load_qm31(ext_params, 14u);
    e11 = stwo_qm31_sub(e8, e10);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e10 = StwoCudaQm31{ b6, b9, b9, b9 };
    e8 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e10);
    e10 = stwo_load_qm31(ext_params, 15u);
    StwoCudaQm31 e12 = StwoCudaQm31{ b0, b9, b9, b9 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e10, e12);
    e12 = stwo_load_qm31(ext_params, 16u);
    e10 = stwo_qm31_add(e12, e13);
    e12 = stwo_load_qm31(ext_params, 17u);
    e13 = stwo_qm31_sub(e10, e12);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    e12 = StwoCudaQm31{ b7, b9, b9, b9 };
    e10 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e12);
    e12 = stwo_load_qm31(ext_params, 18u);
    StwoCudaQm31 e14 = StwoCudaQm31{ b0, b9, b9, b9 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e12, e14);
    e14 = stwo_load_qm31(ext_params, 19u);
    e12 = stwo_qm31_add(e14, e15);
    e14 = stwo_load_qm31(ext_params, 20u);
    e15 = stwo_qm31_sub(e12, e14);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    e14 = StwoCudaQm31{ b8, b9, b9, b9 };
    e12 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e14);
    e14 = stwo_load_qm31(ext_params, 21u);
    StwoCudaQm31 e16 = StwoCudaQm31{ b0, b9, b9, b9 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e14, e16);
    e16 = stwo_load_qm31(ext_params, 22u);
    e14 = stwo_qm31_add(e16, e17);
    e16 = stwo_load_qm31(ext_params, 23u);
    e17 = stwo_qm31_sub(e14, e16);
    e16 = stwo_qm31_mul(e5, e1);
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e16, e1);
    e1 = stwo_qm31_mul(e3, e5);
    e5 = stwo_qm31_mul(e9, e2);
    e2 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e5, e2);
    e2 = stwo_qm31_mul(e7, e9);
    e9 = stwo_qm31_mul(e13, e6);
    e6 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e9, e6);
    e6 = stwo_qm31_mul(e11, e13);
    e13 = stwo_qm31_mul(e17, e10);
    e10 = stwo_qm31_mul(e15, e12);
    e12 = stwo_qm31_add(e13, e10);
    e10 = stwo_qm31_mul(e15, e17);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e17 = StwoCudaQm31{ b10, b11, b12, b13 };
    e15 = stwo_qm31_mul(e17, e1);
    e1 = stwo_qm31_sub(e15, e0);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e15 = StwoCudaQm31{ b14, b15, b16, b17 };
    e0 = stwo_qm31_sub(e15, e17);
    e17 = stwo_qm31_mul(e0, e2);
    e0 = stwo_qm31_sub(e17, e4);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e17 = StwoCudaQm31{ b18, b19, b20, b21 };
    e4 = stwo_qm31_sub(e17, e15);
    e15 = stwo_qm31_mul(e4, e6);
    e4 = stwo_qm31_sub(e15, e8);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, -1);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, -1);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, -1);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, -1);
    e15 = StwoCudaQm31{ b22, b24, b26, b28 };
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e8 = StwoCudaQm31{ b23, b25, b27, b29 };
    e6 = stwo_qm31_sub(e8, e15);
    e8 = stwo_qm31_sub(e6, e17);
    e6 = stwo_load_qm31(ext_params, 24u);
    e17 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e17, e10);
    e17 = stwo_qm31_sub(e6, e12);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));

    unsigned denom_idx = row_index >> log_n_rows;
    return stwo_qm31_mul_base(acc, part.denom_inv[denom_idx]);
}

extern "C" __global__ void __launch_bounds__(128) stwo_composition_wave_0802298dbb462516(
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
