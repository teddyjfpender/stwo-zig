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
    unsigned b25 = base_params[0u];
    unsigned b26 = stwo_m31_sub(b25, b4);
    unsigned b27 = stwo_m31_mul(b4, b26);
    unsigned b28 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b27, b28, b28, b28 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    StwoCudaQm31 e1 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    StwoCudaQm31 e2 = StwoCudaQm31{ b0, b28, b28, b28 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_load_qm31(ext_params, 1u);
    e1 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(ext_params, 2u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 3u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 4u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e3 = StwoCudaQm31{ b3, b28, b28, b28 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 5u);
    unsigned b29 = base_params[2u];
    unsigned b30 = stwo_m31_mul(b4, b29);
    unsigned b31 = base_params[3u];
    unsigned b32 = stwo_m31_sub(b31, b4);
    unsigned b33 = base_params[4u];
    unsigned b34 = stwo_m31_mul(b32, b33);
    unsigned b35 = stwo_m31_add(b30, b34);
    e1 = StwoCudaQm31{ b35, b28, b28, b28 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 6u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 7u);
    e1 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(ext_params, 8u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e3 = StwoCudaQm31{ b1, b28, b28, b28 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 9u);
    e2 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(ext_params, 10u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e4 = StwoCudaQm31{ b5, b28, b28, b28 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(ext_params, 11u);
    e2 = stwo_qm31_sub(e4, e5);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b40 = base_params[7u];
    unsigned b41 = stwo_m31_sub(b40, b10);
    unsigned b42 = stwo_m31_mul(b10, b41);
    unsigned b43 = base_params[8u];
    unsigned b44 = stwo_m31_mul(b42, b43);
    e5 = StwoCudaQm31{ b44, b28, b28, b28 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b45 = base_params[9u];
    unsigned b46 = stwo_m31_mul(b10, b45);
    unsigned b47 = stwo_m31_sub(b9, b46);
    unsigned b48 = base_params[10u];
    unsigned b49 = stwo_m31_sub(b48, b47);
    unsigned b50 = stwo_m31_mul(b47, b49);
    unsigned b51 = base_params[11u];
    unsigned b52 = stwo_m31_mul(b50, b51);
    e4 = StwoCudaQm31{ b52, b28, b28, b28 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    e3 = stwo_load_qm31(ext_params, 12u);
    StwoCudaQm31 e6 = StwoCudaQm31{ b5, b28, b28, b28 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e3, e6);
    e6 = stwo_load_qm31(ext_params, 13u);
    e3 = stwo_qm31_add(e6, e7);
    e6 = stwo_load_qm31(ext_params, 14u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    e7 = StwoCudaQm31{ b6, b28, b28, b28 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e3, e8);
    e8 = stwo_load_qm31(ext_params, 15u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    e3 = StwoCudaQm31{ b7, b28, b28, b28 };
    e6 = stwo_qm31_mul(e8, e3);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(ext_params, 16u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    e7 = StwoCudaQm31{ b8, b28, b28, b28 };
    e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e3, e8);
    e8 = stwo_load_qm31(ext_params, 17u);
    e3 = StwoCudaQm31{ b9, b28, b28, b28 };
    e6 = stwo_qm31_mul(e8, e3);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(ext_params, 18u);
    e7 = stwo_qm31_sub(e3, e6);
    unsigned b53 = base_params[12u];
    unsigned b54 = stwo_m31_mul(b7, b53);
    unsigned b55 = stwo_m31_add(b6, b54);
    unsigned b56 = base_params[13u];
    unsigned b57 = stwo_m31_mul(b8, b56);
    unsigned b58 = stwo_m31_add(b55, b57);
    unsigned b59 = base_params[14u];
    unsigned b60 = stwo_m31_mul(b9, b59);
    unsigned b61 = stwo_m31_add(b58, b60);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b62 = stwo_m31_sub(b61, b2);
    e6 = StwoCudaQm31{ b62, b28, b28, b28 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    e3 = stwo_load_qm31(ext_params, 19u);
    unsigned b63 = base_params[15u];
    unsigned b64 = stwo_m31_add(b1, b63);
    e8 = StwoCudaQm31{ b64, b28, b28, b28 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e3, e8);
    e8 = stwo_load_qm31(ext_params, 20u);
    e3 = stwo_qm31_add(e8, e9);
    e8 = stwo_load_qm31(ext_params, 21u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    e9 = StwoCudaQm31{ b11, b28, b28, b28 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e3, e10);
    e10 = stwo_load_qm31(ext_params, 22u);
    e3 = stwo_qm31_sub(e9, e10);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b65 = base_params[16u];
    unsigned b66 = stwo_m31_sub(b65, b16);
    unsigned b67 = stwo_m31_mul(b16, b66);
    unsigned b68 = base_params[17u];
    unsigned b69 = stwo_m31_mul(b67, b68);
    e10 = StwoCudaQm31{ b69, b28, b28, b28 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b70 = base_params[18u];
    unsigned b71 = stwo_m31_mul(b16, b70);
    unsigned b72 = stwo_m31_sub(b15, b71);
    unsigned b73 = base_params[19u];
    unsigned b74 = stwo_m31_sub(b73, b72);
    unsigned b75 = stwo_m31_mul(b72, b74);
    unsigned b76 = base_params[20u];
    unsigned b77 = stwo_m31_mul(b75, b76);
    e9 = StwoCudaQm31{ b77, b28, b28, b28 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    e8 = stwo_load_qm31(ext_params, 23u);
    StwoCudaQm31 e11 = StwoCudaQm31{ b11, b28, b28, b28 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e8, e11);
    e11 = stwo_load_qm31(ext_params, 24u);
    e8 = stwo_qm31_add(e11, e12);
    e11 = stwo_load_qm31(ext_params, 25u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    e12 = StwoCudaQm31{ b12, b28, b28, b28 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e11, e12);
    e12 = stwo_qm31_add(e8, e13);
    e13 = stwo_load_qm31(ext_params, 26u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    e8 = StwoCudaQm31{ b13, b28, b28, b28 };
    e11 = stwo_qm31_mul(e13, e8);
    e8 = stwo_qm31_add(e12, e11);
    e11 = stwo_load_qm31(ext_params, 27u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    e12 = StwoCudaQm31{ b14, b28, b28, b28 };
    e13 = stwo_qm31_mul(e11, e12);
    e12 = stwo_qm31_add(e8, e13);
    e13 = stwo_load_qm31(ext_params, 28u);
    e8 = StwoCudaQm31{ b15, b28, b28, b28 };
    e11 = stwo_qm31_mul(e13, e8);
    e8 = stwo_qm31_add(e12, e11);
    e11 = stwo_load_qm31(ext_params, 29u);
    e12 = stwo_qm31_sub(e8, e11);
    unsigned b78 = base_params[21u];
    unsigned b79 = stwo_m31_mul(b13, b78);
    unsigned b80 = stwo_m31_add(b12, b79);
    unsigned b81 = base_params[22u];
    unsigned b82 = stwo_m31_mul(b14, b81);
    unsigned b83 = stwo_m31_add(b80, b82);
    unsigned b84 = base_params[23u];
    unsigned b85 = stwo_m31_mul(b15, b84);
    unsigned b86 = stwo_m31_add(b83, b85);
    unsigned b87 = base_params[24u];
    unsigned b88 = stwo_m31_add(b0, b87);
    unsigned b89 = stwo_m31_sub(b86, b88);
    e11 = StwoCudaQm31{ b89, b28, b28, b28 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    unsigned b90 = stwo_m31_mul(b4, b2);
    unsigned b38 = base_params[6u];
    unsigned b39 = stwo_m31_sub(b38, b4);
    unsigned b91 = stwo_m31_mul(b39, b1);
    unsigned b92 = stwo_m31_add(b90, b91);
    unsigned b93 = stwo_m31_sub(b17, b92);
    e8 = StwoCudaQm31{ b93, b28, b28, b28 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    e13 = stwo_load_qm31(ext_params, 30u);
    unsigned b36 = base_params[5u];
    unsigned b37 = stwo_m31_sub(b3, b36);
    unsigned b94 = stwo_m31_add(b17, b37);
    StwoCudaQm31 e14 = StwoCudaQm31{ b94, b28, b28, b28 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e13, e14);
    e14 = stwo_load_qm31(ext_params, 31u);
    e13 = stwo_qm31_add(e14, e15);
    e14 = stwo_load_qm31(ext_params, 32u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    e15 = StwoCudaQm31{ b18, b28, b28, b28 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(ext_params, 33u);
    e13 = stwo_qm31_sub(e15, e16);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    unsigned b95 = base_params[25u];
    unsigned b96 = stwo_m31_sub(b95, b23);
    unsigned b97 = stwo_m31_mul(b23, b96);
    unsigned b98 = base_params[26u];
    unsigned b99 = stwo_m31_mul(b97, b98);
    e16 = StwoCudaQm31{ b99, b28, b28, b28 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    unsigned b100 = base_params[27u];
    unsigned b101 = stwo_m31_mul(b23, b100);
    unsigned b102 = stwo_m31_sub(b22, b101);
    unsigned b103 = base_params[28u];
    unsigned b104 = stwo_m31_sub(b103, b102);
    unsigned b105 = stwo_m31_mul(b102, b104);
    unsigned b106 = base_params[29u];
    unsigned b107 = stwo_m31_mul(b105, b106);
    e15 = StwoCudaQm31{ b107, b28, b28, b28 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    e14 = stwo_load_qm31(ext_params, 34u);
    StwoCudaQm31 e17 = StwoCudaQm31{ b18, b28, b28, b28 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e14, e17);
    e17 = stwo_load_qm31(ext_params, 35u);
    e14 = stwo_qm31_add(e17, e18);
    e17 = stwo_load_qm31(ext_params, 36u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    e18 = StwoCudaQm31{ b19, b28, b28, b28 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e17, e18);
    e18 = stwo_qm31_add(e14, e19);
    e19 = stwo_load_qm31(ext_params, 37u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    e14 = StwoCudaQm31{ b20, b28, b28, b28 };
    e17 = stwo_qm31_mul(e19, e14);
    e14 = stwo_qm31_add(e18, e17);
    e17 = stwo_load_qm31(ext_params, 38u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    e18 = StwoCudaQm31{ b21, b28, b28, b28 };
    e19 = stwo_qm31_mul(e17, e18);
    e18 = stwo_qm31_add(e14, e19);
    e19 = stwo_load_qm31(ext_params, 39u);
    e14 = StwoCudaQm31{ b22, b28, b28, b28 };
    e17 = stwo_qm31_mul(e19, e14);
    e14 = stwo_qm31_add(e18, e17);
    e17 = stwo_load_qm31(ext_params, 40u);
    e18 = stwo_qm31_sub(e14, e17);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    unsigned b108 = stwo_m31_mul(b24, b24);
    unsigned b109 = stwo_m31_sub(b108, b24);
    e17 = StwoCudaQm31{ b109, b28, b28, b28 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    e14 = stwo_load_qm31(ext_params, 41u);
    e19 = StwoCudaQm31{ b0, b28, b28, b28 };
    StwoCudaQm31 e20 = stwo_qm31_mul(e14, e19);
    e19 = stwo_load_qm31(ext_params, 42u);
    e14 = stwo_qm31_add(e19, e20);
    e19 = stwo_load_qm31(ext_params, 43u);
    e20 = StwoCudaQm31{ b1, b28, b28, b28 };
    StwoCudaQm31 e21 = stwo_qm31_mul(e19, e20);
    e20 = stwo_qm31_add(e14, e21);
    e21 = stwo_load_qm31(ext_params, 44u);
    e14 = StwoCudaQm31{ b2, b28, b28, b28 };
    e19 = stwo_qm31_mul(e21, e14);
    e14 = stwo_qm31_add(e20, e19);
    e19 = stwo_load_qm31(ext_params, 45u);
    e20 = stwo_qm31_sub(e14, e19);
    e19 = StwoCudaQm31{ b24, b28, b28, b28 };
    e14 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e19);
    e19 = stwo_load_qm31(ext_params, 46u);
    unsigned b110 = base_params[30u];
    unsigned b111 = stwo_m31_mul(b20, b110);
    unsigned b112 = stwo_m31_add(b19, b111);
    unsigned b113 = base_params[31u];
    unsigned b114 = stwo_m31_mul(b21, b113);
    unsigned b115 = stwo_m31_add(b112, b114);
    unsigned b116 = base_params[32u];
    unsigned b117 = stwo_m31_mul(b22, b116);
    unsigned b118 = stwo_m31_add(b115, b117);
    e21 = StwoCudaQm31{ b118, b28, b28, b28 };
    StwoCudaQm31 e22 = stwo_qm31_mul(e19, e21);
    e21 = stwo_load_qm31(ext_params, 47u);
    e19 = stwo_qm31_add(e21, e22);
    e21 = stwo_load_qm31(ext_params, 48u);
    unsigned b119 = base_params[33u];
    unsigned b120 = stwo_m31_add(b1, b119);
    e22 = StwoCudaQm31{ b120, b28, b28, b28 };
    StwoCudaQm31 e23 = stwo_qm31_mul(e21, e22);
    e22 = stwo_qm31_add(e19, e23);
    e23 = stwo_load_qm31(ext_params, 49u);
    unsigned b121 = base_params[34u];
    unsigned b122 = stwo_m31_add(b1, b121);
    e19 = StwoCudaQm31{ b122, b28, b28, b28 };
    e21 = stwo_qm31_mul(e23, e19);
    e19 = stwo_qm31_add(e22, e21);
    e21 = stwo_load_qm31(ext_params, 50u);
    e22 = stwo_qm31_sub(e19, e21);
    e21 = stwo_load_qm31(ext_params, 51u);
    e19 = stwo_qm31_mul(e2, e21);
    e21 = stwo_load_qm31(ext_params, 52u);
    e23 = stwo_qm31_mul(e1, e21);
    e21 = stwo_qm31_add(e19, e23);
    e23 = stwo_qm31_mul(e1, e2);
    e2 = stwo_load_qm31(ext_params, 53u);
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 54u);
    e19 = stwo_qm31_mul(e7, e2);
    e2 = stwo_qm31_add(e1, e19);
    e19 = stwo_qm31_mul(e7, e3);
    e3 = stwo_load_qm31(ext_params, 55u);
    e7 = stwo_qm31_mul(e13, e3);
    e3 = stwo_load_qm31(ext_params, 56u);
    e1 = stwo_qm31_mul(e12, e3);
    e3 = stwo_qm31_add(e7, e1);
    e1 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(ext_params, 57u);
    e12 = stwo_qm31_mul(e20, e13);
    e13 = StwoCudaQm31{ b24, b28, b28, b28 };
    e7 = stwo_qm31_mul(e18, e13);
    e13 = stwo_qm31_add(e12, e7);
    e7 = stwo_qm31_mul(e18, e20);
    unsigned b123 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b124 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b125 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b126 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e20 = StwoCudaQm31{ b123, b124, b125, b126 };
    e18 = stwo_qm31_mul(e20, e23);
    e23 = stwo_qm31_sub(e18, e21);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e23, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b127 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b128 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b129 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b130 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e18 = StwoCudaQm31{ b127, b128, b129, b130 };
    e21 = stwo_qm31_sub(e18, e20);
    e20 = stwo_qm31_mul(e21, e19);
    e21 = stwo_qm31_sub(e20, e2);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e21, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b131 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b132 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b133 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b134 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e20 = StwoCudaQm31{ b131, b132, b133, b134 };
    e2 = stwo_qm31_sub(e20, e18);
    e18 = stwo_qm31_mul(e2, e1);
    e2 = stwo_qm31_sub(e18, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b135 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b136 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b137 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b138 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e18 = StwoCudaQm31{ b135, b136, b137, b138 };
    e3 = stwo_qm31_sub(e18, e20);
    e20 = stwo_qm31_mul(e3, e7);
    e3 = stwo_qm31_sub(e20, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));
    unsigned b139 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, -1);
    unsigned b141 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, -1);
    unsigned b143 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, -1);
    unsigned b145 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, -1);
    e20 = StwoCudaQm31{ b139, b141, b143, b145 };
    unsigned b140 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, 0);
    unsigned b142 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, 0);
    unsigned b144 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, 0);
    unsigned b146 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, 0);
    e13 = StwoCudaQm31{ b140, b142, b144, b146 };
    e7 = stwo_qm31_sub(e13, e20);
    e13 = stwo_qm31_sub(e7, e18);
    e7 = stwo_load_qm31(ext_params, 58u);
    e18 = stwo_qm31_add(e13, e7);
    e7 = stwo_qm31_mul(e18, e22);
    e18 = stwo_qm31_sub(e7, e14);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 15u)));

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
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    unsigned b21 = base_params[0u];
    unsigned b22 = stwo_m31_sub(b21, b5);
    unsigned b23 = stwo_m31_mul(b5, b22);
    unsigned b24 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b23, b24, b24, b24 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b25 = base_params[2u];
    unsigned b26 = stwo_m31_sub(b25, b6);
    unsigned b27 = stwo_m31_mul(b6, b26);
    StwoCudaQm31 e1 = StwoCudaQm31{ b27, b24, b24, b24 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    StwoCudaQm31 e2 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    StwoCudaQm31 e3 = StwoCudaQm31{ b0, b24, b24, b24 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 1u);
    e2 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(ext_params, 2u);
    e4 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(ext_params, 3u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e2 = StwoCudaQm31{ b3, b24, b24, b24 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 4u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e4 = StwoCudaQm31{ b4, b24, b24, b24 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(ext_params, 5u);
    unsigned b30 = base_params[4u];
    unsigned b28 = base_params[3u];
    unsigned b29 = stwo_m31_mul(b5, b28);
    unsigned b31 = stwo_m31_add(b30, b29);
    e2 = StwoCudaQm31{ b31, b24, b24, b24 };
    e5 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 6u);
    unsigned b34 = base_params[6u];
    unsigned b32 = base_params[5u];
    unsigned b33 = stwo_m31_mul(b6, b32);
    unsigned b35 = stwo_m31_add(b34, b33);
    e4 = StwoCudaQm31{ b35, b24, b24, b24 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(ext_params, 7u);
    e2 = stwo_qm31_sub(e4, e3);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b40 = stwo_m31_mul(b5, b2);
    unsigned b41 = base_params[9u];
    unsigned b42 = stwo_m31_sub(b41, b5);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    unsigned b43 = stwo_m31_mul(b42, b1);
    unsigned b44 = stwo_m31_add(b40, b43);
    unsigned b45 = stwo_m31_sub(b7, b44);
    e3 = StwoCudaQm31{ b45, b24, b24, b24 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    e4 = stwo_load_qm31(ext_params, 8u);
    unsigned b36 = base_params[7u];
    unsigned b37 = stwo_m31_sub(b3, b36);
    unsigned b46 = stwo_m31_add(b7, b37);
    e5 = StwoCudaQm31{ b46, b24, b24, b24 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 9u);
    e4 = stwo_qm31_add(e5, e6);
    e5 = stwo_load_qm31(ext_params, 10u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    e6 = StwoCudaQm31{ b8, b24, b24, b24 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(ext_params, 11u);
    e4 = stwo_qm31_sub(e6, e7);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    unsigned b47 = base_params[10u];
    unsigned b48 = stwo_m31_sub(b47, b13);
    unsigned b49 = stwo_m31_mul(b13, b48);
    unsigned b50 = base_params[11u];
    unsigned b51 = stwo_m31_mul(b49, b50);
    e7 = StwoCudaQm31{ b51, b24, b24, b24 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b52 = base_params[12u];
    unsigned b53 = stwo_m31_mul(b13, b52);
    unsigned b54 = stwo_m31_sub(b12, b53);
    unsigned b55 = base_params[13u];
    unsigned b56 = stwo_m31_sub(b55, b54);
    unsigned b57 = stwo_m31_mul(b54, b56);
    unsigned b58 = base_params[14u];
    unsigned b59 = stwo_m31_mul(b57, b58);
    e6 = StwoCudaQm31{ b59, b24, b24, b24 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    e5 = stwo_load_qm31(ext_params, 12u);
    StwoCudaQm31 e8 = StwoCudaQm31{ b8, b24, b24, b24 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e5, e8);
    e8 = stwo_load_qm31(ext_params, 13u);
    e5 = stwo_qm31_add(e8, e9);
    e8 = stwo_load_qm31(ext_params, 14u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    e9 = StwoCudaQm31{ b9, b24, b24, b24 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e5, e10);
    e10 = stwo_load_qm31(ext_params, 15u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    e5 = StwoCudaQm31{ b10, b24, b24, b24 };
    e8 = stwo_qm31_mul(e10, e5);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(ext_params, 16u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    e9 = StwoCudaQm31{ b11, b24, b24, b24 };
    e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e5, e10);
    e10 = stwo_load_qm31(ext_params, 17u);
    e5 = StwoCudaQm31{ b12, b24, b24, b24 };
    e8 = stwo_qm31_mul(e10, e5);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(ext_params, 18u);
    e9 = stwo_qm31_sub(e5, e8);
    e8 = stwo_load_qm31(ext_params, 19u);
    unsigned b60 = base_params[15u];
    unsigned b61 = stwo_m31_mul(b10, b60);
    unsigned b62 = stwo_m31_add(b9, b61);
    unsigned b63 = base_params[16u];
    unsigned b64 = stwo_m31_mul(b11, b63);
    unsigned b65 = stwo_m31_add(b62, b64);
    unsigned b66 = base_params[17u];
    unsigned b67 = stwo_m31_mul(b12, b66);
    unsigned b68 = stwo_m31_add(b65, b67);
    unsigned b38 = base_params[8u];
    unsigned b39 = stwo_m31_sub(b4, b38);
    unsigned b69 = stwo_m31_add(b68, b39);
    e5 = StwoCudaQm31{ b69, b24, b24, b24 };
    e10 = stwo_qm31_mul(e8, e5);
    e5 = stwo_load_qm31(ext_params, 20u);
    e8 = stwo_qm31_add(e5, e10);
    e5 = stwo_load_qm31(ext_params, 21u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    e10 = StwoCudaQm31{ b14, b24, b24, b24 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e5, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 22u);
    e8 = stwo_qm31_sub(e10, e11);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    unsigned b70 = base_params[18u];
    unsigned b71 = stwo_m31_sub(b70, b19);
    unsigned b72 = stwo_m31_mul(b19, b71);
    unsigned b73 = base_params[19u];
    unsigned b74 = stwo_m31_mul(b72, b73);
    e11 = StwoCudaQm31{ b74, b24, b24, b24 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    unsigned b75 = base_params[20u];
    unsigned b76 = stwo_m31_mul(b19, b75);
    unsigned b77 = stwo_m31_sub(b18, b76);
    unsigned b78 = base_params[21u];
    unsigned b79 = stwo_m31_sub(b78, b77);
    unsigned b80 = stwo_m31_mul(b77, b79);
    unsigned b81 = base_params[22u];
    unsigned b82 = stwo_m31_mul(b80, b81);
    e10 = StwoCudaQm31{ b82, b24, b24, b24 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    e5 = stwo_load_qm31(ext_params, 23u);
    StwoCudaQm31 e12 = StwoCudaQm31{ b14, b24, b24, b24 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e5, e12);
    e12 = stwo_load_qm31(ext_params, 24u);
    e5 = stwo_qm31_add(e12, e13);
    e12 = stwo_load_qm31(ext_params, 25u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    e13 = StwoCudaQm31{ b15, b24, b24, b24 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e12, e13);
    e13 = stwo_qm31_add(e5, e14);
    e14 = stwo_load_qm31(ext_params, 26u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    e5 = StwoCudaQm31{ b16, b24, b24, b24 };
    e12 = stwo_qm31_mul(e14, e5);
    e5 = stwo_qm31_add(e13, e12);
    e12 = stwo_load_qm31(ext_params, 27u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    e13 = StwoCudaQm31{ b17, b24, b24, b24 };
    e14 = stwo_qm31_mul(e12, e13);
    e13 = stwo_qm31_add(e5, e14);
    e14 = stwo_load_qm31(ext_params, 28u);
    e5 = StwoCudaQm31{ b18, b24, b24, b24 };
    e12 = stwo_qm31_mul(e14, e5);
    e5 = stwo_qm31_add(e13, e12);
    e12 = stwo_load_qm31(ext_params, 29u);
    e13 = stwo_qm31_sub(e5, e12);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    unsigned b83 = stwo_m31_mul(b20, b20);
    unsigned b84 = stwo_m31_sub(b83, b20);
    e12 = StwoCudaQm31{ b84, b24, b24, b24 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    e5 = stwo_load_qm31(ext_params, 30u);
    e14 = StwoCudaQm31{ b0, b24, b24, b24 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e5, e14);
    e14 = stwo_load_qm31(ext_params, 31u);
    e5 = stwo_qm31_add(e14, e15);
    e14 = stwo_load_qm31(ext_params, 32u);
    e15 = StwoCudaQm31{ b1, b24, b24, b24 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e5, e16);
    e16 = stwo_load_qm31(ext_params, 33u);
    e5 = StwoCudaQm31{ b2, b24, b24, b24 };
    e14 = stwo_qm31_mul(e16, e5);
    e5 = stwo_qm31_add(e15, e14);
    e14 = stwo_load_qm31(ext_params, 34u);
    e15 = stwo_qm31_sub(e5, e14);
    e14 = StwoCudaQm31{ b20, b24, b24, b24 };
    e5 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e14);
    e14 = stwo_load_qm31(ext_params, 35u);
    unsigned b85 = base_params[23u];
    unsigned b86 = stwo_m31_mul(b16, b85);
    unsigned b87 = stwo_m31_add(b15, b86);
    unsigned b88 = base_params[24u];
    unsigned b89 = stwo_m31_mul(b17, b88);
    unsigned b90 = stwo_m31_add(b87, b89);
    unsigned b91 = base_params[25u];
    unsigned b92 = stwo_m31_mul(b18, b91);
    unsigned b93 = stwo_m31_add(b90, b92);
    e16 = StwoCudaQm31{ b93, b24, b24, b24 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e14, e16);
    e16 = stwo_load_qm31(ext_params, 36u);
    e14 = stwo_qm31_add(e16, e17);
    e16 = stwo_load_qm31(ext_params, 37u);
    unsigned b94 = stwo_m31_add(b1, b6);
    e17 = StwoCudaQm31{ b94, b24, b24, b24 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e16, e17);
    e17 = stwo_qm31_add(e14, e18);
    e18 = stwo_load_qm31(ext_params, 38u);
    e14 = StwoCudaQm31{ b2, b24, b24, b24 };
    e16 = stwo_qm31_mul(e18, e14);
    e14 = stwo_qm31_add(e17, e16);
    e16 = stwo_load_qm31(ext_params, 39u);
    e17 = stwo_qm31_sub(e14, e16);
    e16 = stwo_load_qm31(ext_params, 40u);
    e14 = stwo_qm31_mul(e4, e16);
    e16 = stwo_load_qm31(ext_params, 41u);
    e18 = stwo_qm31_mul(e2, e16);
    e16 = stwo_qm31_add(e14, e18);
    e18 = stwo_qm31_mul(e2, e4);
    e4 = stwo_load_qm31(ext_params, 42u);
    e2 = stwo_qm31_mul(e8, e4);
    e4 = stwo_load_qm31(ext_params, 43u);
    e14 = stwo_qm31_mul(e9, e4);
    e4 = stwo_qm31_add(e2, e14);
    e14 = stwo_qm31_mul(e9, e8);
    e8 = stwo_load_qm31(ext_params, 44u);
    e9 = stwo_qm31_mul(e15, e8);
    e8 = StwoCudaQm31{ b20, b24, b24, b24 };
    e2 = stwo_qm31_mul(e13, e8);
    e8 = stwo_qm31_add(e9, e2);
    e2 = stwo_qm31_mul(e13, e15);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e15 = StwoCudaQm31{ b95, b96, b97, b98 };
    e13 = stwo_qm31_mul(e15, e18);
    e18 = stwo_qm31_sub(e13, e16);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e13 = StwoCudaQm31{ b99, b100, b101, b102 };
    e16 = stwo_qm31_sub(e13, e15);
    e15 = stwo_qm31_mul(e16, e14);
    e16 = stwo_qm31_sub(e15, e4);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b106 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e15 = StwoCudaQm31{ b103, b104, b105, b106 };
    e4 = stwo_qm31_sub(e15, e13);
    e13 = stwo_qm31_mul(e4, e2);
    e4 = stwo_qm31_sub(e13, e8);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b107 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, -1);
    unsigned b109 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, -1);
    unsigned b111 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, -1);
    unsigned b113 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, -1);
    e13 = StwoCudaQm31{ b107, b109, b111, b113 };
    unsigned b108 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b110 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b112 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b114 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e8 = StwoCudaQm31{ b108, b110, b112, b114 };
    e2 = stwo_qm31_sub(e8, e13);
    e8 = stwo_qm31_sub(e2, e15);
    e2 = stwo_load_qm31(ext_params, 45u);
    e15 = stwo_qm31_add(e8, e2);
    e2 = stwo_qm31_mul(e15, e17);
    e15 = stwo_qm31_sub(e2, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));

    unsigned denom_idx = row_index >> log_n_rows;
    return stwo_qm31_mul_base(acc, part.denom_inv[denom_idx]);
}

extern "C" __global__ void __launch_bounds__(128) stwo_composition_wave_b4661bf86bdca12c(
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
    coord_0[local_row] = wave_acc.a;
    coord_1[local_row] = wave_acc.b;
    coord_2[local_row] = wave_acc.c;
    coord_3[local_row] = wave_acc.d;
}
