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
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b49 = stwo_m31_add(b0, b2);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b50 = stwo_m31_add(b49, b8);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b51 = stwo_m31_sub(b50, b12);
    unsigned b52 = base_params[0u];
    unsigned b53 = stwo_m31_mul(b51, b52);
    unsigned b54 = base_params[1u];
    unsigned b55 = stwo_m31_sub(b53, b54);
    unsigned b56 = stwo_m31_mul(b53, b55);
    unsigned b57 = base_params[2u];
    unsigned b58 = stwo_m31_sub(b53, b57);
    unsigned b59 = stwo_m31_mul(b56, b58);
    unsigned b60 = base_params[3u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b59, b60, b60, b60 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    unsigned b61 = stwo_m31_add(b1, b3);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b62 = stwo_m31_add(b61, b9);
    unsigned b63 = stwo_m31_add(b62, b53);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    unsigned b64 = stwo_m31_sub(b63, b13);
    unsigned b65 = base_params[4u];
    unsigned b66 = stwo_m31_mul(b64, b65);
    unsigned b67 = base_params[5u];
    unsigned b68 = stwo_m31_sub(b66, b67);
    unsigned b69 = stwo_m31_mul(b66, b68);
    unsigned b70 = base_params[6u];
    unsigned b71 = stwo_m31_sub(b66, b70);
    unsigned b72 = stwo_m31_mul(b69, b71);
    StwoCudaQm31 e1 = StwoCudaQm31{ b72, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    StwoCudaQm31 e2 = stwo_load_qm31(ext_params, 0u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    unsigned b73 = base_params[7u];
    unsigned b74 = stwo_m31_mul(b14, b73);
    unsigned b75 = stwo_m31_sub(b12, b74);
    StwoCudaQm31 e3 = StwoCudaQm31{ b75, b60, b60, b60 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 1u);
    e2 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(ext_params, 2u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b79 = base_params[9u];
    unsigned b80 = stwo_m31_mul(b16, b79);
    unsigned b81 = stwo_m31_sub(b6, b80);
    e4 = StwoCudaQm31{ b81, b60, b60, b60 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(ext_params, 3u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    e2 = StwoCudaQm31{ b18, b60, b60, b60 };
    e3 = stwo_qm31_mul(e5, e2);
    e2 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(ext_params, 4u);
    e4 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 5u);
    e2 = StwoCudaQm31{ b14, b60, b60, b60 };
    e5 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 6u);
    e3 = stwo_qm31_add(e2, e5);
    e2 = stwo_load_qm31(ext_params, 7u);
    e5 = StwoCudaQm31{ b16, b60, b60, b60 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e2, e5);
    e5 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(ext_params, 8u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    e3 = StwoCudaQm31{ b19, b60, b60, b60 };
    e2 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e5, e2);
    e2 = stwo_load_qm31(ext_params, 9u);
    e5 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(ext_params, 10u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b76 = base_params[8u];
    unsigned b77 = stwo_m31_mul(b15, b76);
    unsigned b78 = stwo_m31_sub(b13, b77);
    e3 = StwoCudaQm31{ b78, b60, b60, b60 };
    e6 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 11u);
    e2 = stwo_qm31_add(e3, e6);
    e3 = stwo_load_qm31(ext_params, 12u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    unsigned b82 = base_params[10u];
    unsigned b83 = stwo_m31_mul(b17, b82);
    unsigned b84 = stwo_m31_sub(b7, b83);
    e6 = StwoCudaQm31{ b84, b60, b60, b60 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e3, e6);
    e6 = stwo_qm31_add(e2, e7);
    e7 = stwo_load_qm31(ext_params, 13u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    e2 = StwoCudaQm31{ b20, b60, b60, b60 };
    e3 = stwo_qm31_mul(e7, e2);
    e2 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(ext_params, 14u);
    e6 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 15u);
    e2 = StwoCudaQm31{ b15, b60, b60, b60 };
    e7 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 16u);
    e3 = stwo_qm31_add(e2, e7);
    e2 = stwo_load_qm31(ext_params, 17u);
    e7 = StwoCudaQm31{ b17, b60, b60, b60 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e2, e7);
    e7 = stwo_qm31_add(e3, e8);
    e8 = stwo_load_qm31(ext_params, 18u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    e3 = StwoCudaQm31{ b21, b60, b60, b60 };
    e2 = stwo_qm31_mul(e8, e3);
    e3 = stwo_qm31_add(e7, e2);
    e2 = stwo_load_qm31(ext_params, 19u);
    e7 = stwo_qm31_sub(e3, e2);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    unsigned b85 = base_params[11u];
    unsigned b86 = stwo_m31_mul(b21, b85);
    unsigned b87 = stwo_m31_add(b20, b86);
    unsigned b91 = stwo_m31_add(b4, b87);
    unsigned b92 = base_params[13u];
    unsigned b93 = stwo_m31_add(b91, b92);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    unsigned b94 = stwo_m31_sub(b93, b22);
    unsigned b95 = base_params[14u];
    unsigned b96 = stwo_m31_mul(b94, b95);
    unsigned b97 = base_params[15u];
    unsigned b98 = stwo_m31_sub(b96, b97);
    unsigned b99 = stwo_m31_mul(b96, b98);
    unsigned b100 = base_params[16u];
    unsigned b101 = stwo_m31_sub(b96, b100);
    unsigned b102 = stwo_m31_mul(b99, b101);
    e2 = StwoCudaQm31{ b102, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    unsigned b88 = base_params[12u];
    unsigned b89 = stwo_m31_mul(b19, b88);
    unsigned b90 = stwo_m31_add(b18, b89);
    unsigned b103 = stwo_m31_add(b5, b90);
    unsigned b104 = base_params[17u];
    unsigned b105 = stwo_m31_add(b103, b104);
    unsigned b106 = stwo_m31_add(b105, b96);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    unsigned b107 = stwo_m31_sub(b106, b23);
    unsigned b108 = base_params[18u];
    unsigned b109 = stwo_m31_mul(b107, b108);
    unsigned b110 = base_params[19u];
    unsigned b111 = stwo_m31_sub(b109, b110);
    unsigned b112 = stwo_m31_mul(b109, b111);
    unsigned b113 = base_params[20u];
    unsigned b114 = stwo_m31_sub(b109, b113);
    unsigned b115 = stwo_m31_mul(b112, b114);
    e3 = StwoCudaQm31{ b115, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    e8 = stwo_load_qm31(ext_params, 20u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    unsigned b116 = base_params[21u];
    unsigned b117 = stwo_m31_mul(b24, b116);
    unsigned b118 = stwo_m31_sub(b2, b117);
    StwoCudaQm31 e9 = StwoCudaQm31{ b118, b60, b60, b60 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 21u);
    e8 = stwo_qm31_add(e9, e10);
    e9 = stwo_load_qm31(ext_params, 22u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    unsigned b122 = base_params[23u];
    unsigned b123 = stwo_m31_mul(b26, b122);
    unsigned b124 = stwo_m31_sub(b22, b123);
    e10 = StwoCudaQm31{ b124, b60, b60, b60 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(ext_params, 23u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    e8 = StwoCudaQm31{ b28, b60, b60, b60 };
    e9 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(ext_params, 24u);
    e10 = stwo_qm31_sub(e8, e9);
    e9 = stwo_load_qm31(ext_params, 25u);
    e8 = StwoCudaQm31{ b24, b60, b60, b60 };
    e11 = stwo_qm31_mul(e9, e8);
    e8 = stwo_load_qm31(ext_params, 26u);
    e9 = stwo_qm31_add(e8, e11);
    e8 = stwo_load_qm31(ext_params, 27u);
    e11 = StwoCudaQm31{ b26, b60, b60, b60 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e8, e11);
    e11 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(ext_params, 28u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    e9 = StwoCudaQm31{ b29, b60, b60, b60 };
    e8 = stwo_qm31_mul(e12, e9);
    e9 = stwo_qm31_add(e11, e8);
    e8 = stwo_load_qm31(ext_params, 29u);
    e11 = stwo_qm31_sub(e9, e8);
    e8 = stwo_load_qm31(ext_params, 30u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    unsigned b119 = base_params[22u];
    unsigned b120 = stwo_m31_mul(b25, b119);
    unsigned b121 = stwo_m31_sub(b3, b120);
    e9 = StwoCudaQm31{ b121, b60, b60, b60 };
    e12 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 31u);
    e8 = stwo_qm31_add(e9, e12);
    e9 = stwo_load_qm31(ext_params, 32u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    unsigned b125 = base_params[24u];
    unsigned b126 = stwo_m31_mul(b27, b125);
    unsigned b127 = stwo_m31_sub(b23, b126);
    e12 = StwoCudaQm31{ b127, b60, b60, b60 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e9, e12);
    e12 = stwo_qm31_add(e8, e13);
    e13 = stwo_load_qm31(ext_params, 33u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    e8 = StwoCudaQm31{ b30, b60, b60, b60 };
    e9 = stwo_qm31_mul(e13, e8);
    e8 = stwo_qm31_add(e12, e9);
    e9 = stwo_load_qm31(ext_params, 34u);
    e12 = stwo_qm31_sub(e8, e9);
    e9 = stwo_load_qm31(ext_params, 35u);
    e8 = StwoCudaQm31{ b25, b60, b60, b60 };
    e13 = stwo_qm31_mul(e9, e8);
    e8 = stwo_load_qm31(ext_params, 36u);
    e9 = stwo_qm31_add(e8, e13);
    e8 = stwo_load_qm31(ext_params, 37u);
    e13 = StwoCudaQm31{ b27, b60, b60, b60 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e8, e13);
    e13 = stwo_qm31_add(e9, e14);
    e14 = stwo_load_qm31(ext_params, 38u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    e9 = StwoCudaQm31{ b31, b60, b60, b60 };
    e8 = stwo_qm31_mul(e14, e9);
    e9 = stwo_qm31_add(e13, e8);
    e8 = stwo_load_qm31(ext_params, 39u);
    e13 = stwo_qm31_sub(e9, e8);
    unsigned b128 = base_params[25u];
    unsigned b129 = stwo_m31_mul(b30, b128);
    unsigned b130 = stwo_m31_add(b29, b129);
    unsigned b134 = stwo_m31_add(b12, b130);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b135 = stwo_m31_add(b134, b10);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    unsigned b136 = stwo_m31_sub(b135, b32);
    unsigned b137 = base_params[27u];
    unsigned b138 = stwo_m31_mul(b136, b137);
    unsigned b139 = base_params[28u];
    unsigned b140 = stwo_m31_sub(b138, b139);
    unsigned b141 = stwo_m31_mul(b138, b140);
    unsigned b142 = base_params[29u];
    unsigned b143 = stwo_m31_sub(b138, b142);
    unsigned b144 = stwo_m31_mul(b141, b143);
    e8 = StwoCudaQm31{ b144, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b131 = base_params[26u];
    unsigned b132 = stwo_m31_mul(b28, b131);
    unsigned b133 = stwo_m31_add(b31, b132);
    unsigned b145 = stwo_m31_add(b13, b133);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b146 = stwo_m31_add(b145, b11);
    unsigned b147 = stwo_m31_add(b146, b138);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    unsigned b148 = stwo_m31_sub(b147, b33);
    unsigned b149 = base_params[30u];
    unsigned b150 = stwo_m31_mul(b148, b149);
    unsigned b151 = base_params[31u];
    unsigned b152 = stwo_m31_sub(b150, b151);
    unsigned b153 = stwo_m31_mul(b150, b152);
    unsigned b154 = base_params[32u];
    unsigned b155 = stwo_m31_sub(b150, b154);
    unsigned b156 = stwo_m31_mul(b153, b155);
    e9 = StwoCudaQm31{ b156, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    e14 = stwo_load_qm31(ext_params, 40u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    unsigned b157 = base_params[33u];
    unsigned b158 = stwo_m31_mul(b34, b157);
    unsigned b159 = stwo_m31_sub(b32, b158);
    StwoCudaQm31 e15 = StwoCudaQm31{ b159, b60, b60, b60 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 41u);
    e14 = stwo_qm31_add(e15, e16);
    e15 = stwo_load_qm31(ext_params, 42u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    unsigned b163 = base_params[35u];
    unsigned b164 = stwo_m31_mul(b36, b163);
    unsigned b165 = stwo_m31_sub(b87, b164);
    e16 = StwoCudaQm31{ b165, b60, b60, b60 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(ext_params, 43u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    e14 = StwoCudaQm31{ b38, b60, b60, b60 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(ext_params, 44u);
    e16 = stwo_qm31_sub(e14, e15);
    e15 = stwo_load_qm31(ext_params, 45u);
    e14 = StwoCudaQm31{ b34, b60, b60, b60 };
    e17 = stwo_qm31_mul(e15, e14);
    e14 = stwo_load_qm31(ext_params, 46u);
    e15 = stwo_qm31_add(e14, e17);
    e14 = stwo_load_qm31(ext_params, 47u);
    e17 = StwoCudaQm31{ b36, b60, b60, b60 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e14, e17);
    e17 = stwo_qm31_add(e15, e18);
    e18 = stwo_load_qm31(ext_params, 48u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    e15 = StwoCudaQm31{ b39, b60, b60, b60 };
    e14 = stwo_qm31_mul(e18, e15);
    e15 = stwo_qm31_add(e17, e14);
    e14 = stwo_load_qm31(ext_params, 49u);
    e17 = stwo_qm31_sub(e15, e14);
    e14 = stwo_load_qm31(ext_params, 50u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    unsigned b160 = base_params[34u];
    unsigned b161 = stwo_m31_mul(b35, b160);
    unsigned b162 = stwo_m31_sub(b33, b161);
    e15 = StwoCudaQm31{ b162, b60, b60, b60 };
    e18 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 51u);
    e14 = stwo_qm31_add(e15, e18);
    e15 = stwo_load_qm31(ext_params, 52u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    unsigned b166 = base_params[36u];
    unsigned b167 = stwo_m31_mul(b37, b166);
    unsigned b168 = stwo_m31_sub(b90, b167);
    e18 = StwoCudaQm31{ b168, b60, b60, b60 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e15, e18);
    e18 = stwo_qm31_add(e14, e19);
    e19 = stwo_load_qm31(ext_params, 53u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    e14 = StwoCudaQm31{ b40, b60, b60, b60 };
    e15 = stwo_qm31_mul(e19, e14);
    e14 = stwo_qm31_add(e18, e15);
    e15 = stwo_load_qm31(ext_params, 54u);
    e18 = stwo_qm31_sub(e14, e15);
    e15 = stwo_load_qm31(ext_params, 55u);
    e14 = StwoCudaQm31{ b35, b60, b60, b60 };
    e19 = stwo_qm31_mul(e15, e14);
    e14 = stwo_load_qm31(ext_params, 56u);
    e15 = stwo_qm31_add(e14, e19);
    e14 = stwo_load_qm31(ext_params, 57u);
    e19 = StwoCudaQm31{ b37, b60, b60, b60 };
    StwoCudaQm31 e20 = stwo_qm31_mul(e14, e19);
    e19 = stwo_qm31_add(e15, e20);
    e20 = stwo_load_qm31(ext_params, 58u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    e15 = StwoCudaQm31{ b41, b60, b60, b60 };
    e14 = stwo_qm31_mul(e20, e15);
    e15 = stwo_qm31_add(e19, e14);
    e14 = stwo_load_qm31(ext_params, 59u);
    e19 = stwo_qm31_sub(e15, e14);
    unsigned b169 = base_params[37u];
    unsigned b170 = stwo_m31_mul(b40, b169);
    unsigned b171 = stwo_m31_add(b39, b170);
    unsigned b175 = stwo_m31_add(b22, b171);
    unsigned b176 = base_params[39u];
    unsigned b177 = stwo_m31_add(b175, b176);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    unsigned b178 = stwo_m31_sub(b177, b42);
    unsigned b179 = base_params[40u];
    unsigned b180 = stwo_m31_mul(b178, b179);
    unsigned b181 = base_params[41u];
    unsigned b182 = stwo_m31_sub(b180, b181);
    unsigned b183 = stwo_m31_mul(b180, b182);
    unsigned b184 = base_params[42u];
    unsigned b185 = stwo_m31_sub(b180, b184);
    unsigned b186 = stwo_m31_mul(b183, b185);
    e14 = StwoCudaQm31{ b186, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b172 = base_params[38u];
    unsigned b173 = stwo_m31_mul(b38, b172);
    unsigned b174 = stwo_m31_add(b41, b173);
    unsigned b187 = stwo_m31_add(b23, b174);
    unsigned b188 = base_params[43u];
    unsigned b189 = stwo_m31_add(b187, b188);
    unsigned b190 = stwo_m31_add(b189, b180);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    unsigned b191 = stwo_m31_sub(b190, b43);
    unsigned b192 = base_params[44u];
    unsigned b193 = stwo_m31_mul(b191, b192);
    unsigned b194 = base_params[45u];
    unsigned b195 = stwo_m31_sub(b193, b194);
    unsigned b196 = stwo_m31_mul(b193, b195);
    unsigned b197 = base_params[46u];
    unsigned b198 = stwo_m31_sub(b193, b197);
    unsigned b199 = stwo_m31_mul(b196, b198);
    e15 = StwoCudaQm31{ b199, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    e20 = stwo_load_qm31(ext_params, 60u);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    unsigned b200 = base_params[47u];
    unsigned b201 = stwo_m31_mul(b44, b200);
    unsigned b202 = stwo_m31_sub(b130, b201);
    StwoCudaQm31 e21 = StwoCudaQm31{ b202, b60, b60, b60 };
    StwoCudaQm31 e22 = stwo_qm31_mul(e20, e21);
    e21 = stwo_load_qm31(ext_params, 61u);
    e20 = stwo_qm31_add(e21, e22);
    e21 = stwo_load_qm31(ext_params, 62u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    unsigned b203 = base_params[49u];
    unsigned b204 = stwo_m31_mul(b45, b203);
    unsigned b205 = stwo_m31_sub(b42, b204);
    e22 = StwoCudaQm31{ b205, b60, b60, b60 };
    StwoCudaQm31 e23 = stwo_qm31_mul(e21, e22);
    e22 = stwo_qm31_add(e20, e23);
    e23 = stwo_load_qm31(ext_params, 63u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    e20 = StwoCudaQm31{ b46, b60, b60, b60 };
    e21 = stwo_qm31_mul(e23, e20);
    e20 = stwo_qm31_add(e22, e21);
    e21 = stwo_load_qm31(ext_params, 64u);
    e22 = stwo_qm31_sub(e20, e21);
    e21 = stwo_load_qm31(ext_params, 65u);
    e20 = StwoCudaQm31{ b44, b60, b60, b60 };
    e23 = stwo_qm31_mul(e21, e20);
    e20 = stwo_load_qm31(ext_params, 66u);
    e21 = stwo_qm31_add(e20, e23);
    e20 = stwo_load_qm31(ext_params, 67u);
    e23 = StwoCudaQm31{ b45, b60, b60, b60 };
    StwoCudaQm31 e24 = stwo_qm31_mul(e20, e23);
    e23 = stwo_qm31_add(e21, e24);
    e24 = stwo_load_qm31(ext_params, 68u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    e21 = StwoCudaQm31{ b47, b60, b60, b60 };
    e20 = stwo_qm31_mul(e24, e21);
    e21 = stwo_qm31_add(e23, e20);
    e20 = stwo_load_qm31(ext_params, 69u);
    e23 = stwo_qm31_sub(e21, e20);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    unsigned b206 = stwo_m31_mul(b48, b48);
    unsigned b207 = stwo_m31_sub(b206, b48);
    e20 = StwoCudaQm31{ b207, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e20, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    e21 = stwo_load_qm31(ext_params, 102u);
    e24 = stwo_qm31_mul(e5, e21);
    e21 = stwo_load_qm31(ext_params, 103u);
    StwoCudaQm31 e25 = stwo_qm31_mul(e4, e21);
    e21 = stwo_qm31_add(e24, e25);
    e25 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 104u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 105u);
    e24 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e24);
    e24 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 106u);
    e6 = stwo_qm31_mul(e11, e7);
    e7 = stwo_load_qm31(ext_params, 107u);
    e4 = stwo_qm31_mul(e10, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(ext_params, 108u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(ext_params, 109u);
    e6 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e6);
    e6 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(ext_params, 110u);
    e12 = stwo_qm31_mul(e17, e13);
    e13 = stwo_load_qm31(ext_params, 111u);
    e10 = stwo_qm31_mul(e16, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(ext_params, 112u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(ext_params, 113u);
    e12 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e12);
    e12 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(ext_params, 114u);
    e18 = stwo_qm31_mul(e23, e19);
    e19 = stwo_load_qm31(ext_params, 115u);
    e16 = stwo_qm31_mul(e22, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e22, e23);
    unsigned b208 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b209 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b210 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b211 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e23 = StwoCudaQm31{ b208, b209, b210, b211 };
    e22 = stwo_qm31_mul(e23, e25);
    e25 = stwo_qm31_sub(e22, e21);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e25, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b212 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b213 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b214 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b215 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e22 = StwoCudaQm31{ b212, b213, b214, b215 };
    e21 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e21, e24);
    e21 = stwo_qm31_sub(e23, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e21, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b216 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b217 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b218 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b219 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e23 = StwoCudaQm31{ b216, b217, b218, b219 };
    e5 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e22, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b220 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b221 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b222 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b223 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e22 = StwoCudaQm31{ b220, b221, b222, b223 };
    e7 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e23, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b224 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, 0);
    unsigned b225 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, 0);
    unsigned b226 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, 0);
    unsigned b227 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, 0);
    e23 = StwoCudaQm31{ b224, b225, b226, b227 };
    e11 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e22, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b228 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 20u, row_index, 0);
    unsigned b229 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 21u, row_index, 0);
    unsigned b230 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 22u, row_index, 0);
    unsigned b231 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 23u, row_index, 0);
    e22 = StwoCudaQm31{ b228, b229, b230, b231 };
    e13 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e23, e17);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));
    unsigned b232 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 24u, row_index, 0);
    unsigned b233 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 25u, row_index, 0);
    unsigned b234 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 26u, row_index, 0);
    unsigned b235 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 27u, row_index, 0);
    e23 = StwoCudaQm31{ b232, b233, b234, b235 };
    e17 = stwo_qm31_sub(e23, e22);
    e23 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e23, e19);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 15u)));

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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 70u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    unsigned b30 = base_params[26u];
    unsigned b31 = stwo_m31_mul(b12, b30);
    unsigned b32 = stwo_m31_add(b13, b31);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    unsigned b39 = base_params[48u];
    unsigned b40 = stwo_m31_mul(b22, b39);
    unsigned b41 = stwo_m31_sub(b32, b40);
    unsigned b29 = base_params[3u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b41, b29, b29, b29 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 71u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 72u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    unsigned b42 = base_params[50u];
    unsigned b43 = stwo_m31_mul(b23, b42);
    unsigned b44 = stwo_m31_sub(b21, b43);
    e2 = StwoCudaQm31{ b44, b29, b29, b29 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 73u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    e0 = StwoCudaQm31{ b26, b29, b29, b29 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 74u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 75u);
    e0 = StwoCudaQm31{ b22, b29, b29, b29 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 76u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 77u);
    e3 = StwoCudaQm31{ b23, b29, b29, b29 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 78u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    e1 = StwoCudaQm31{ b27, b29, b29, b29 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 79u);
    e3 = stwo_qm31_sub(e1, e0);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    e0 = StwoCudaQm31{ b28, b29, b29, b29 };
    e1 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e0);
    e0 = stwo_load_qm31(ext_params, 80u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    e4 = StwoCudaQm31{ b0, b29, b29, b29 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e0, e4);
    e4 = stwo_load_qm31(ext_params, 81u);
    e0 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(ext_params, 82u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e5 = StwoCudaQm31{ b1, b29, b29, b29 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e0, e6);
    e6 = stwo_load_qm31(ext_params, 83u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    e0 = StwoCudaQm31{ b2, b29, b29, b29 };
    e4 = stwo_qm31_mul(e6, e0);
    e0 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 84u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e5 = StwoCudaQm31{ b3, b29, b29, b29 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e0, e6);
    e6 = stwo_load_qm31(ext_params, 85u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e0 = StwoCudaQm31{ b4, b29, b29, b29 };
    e4 = stwo_qm31_mul(e6, e0);
    e0 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 86u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e5 = StwoCudaQm31{ b5, b29, b29, b29 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e0, e6);
    e6 = stwo_load_qm31(ext_params, 87u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    e0 = StwoCudaQm31{ b6, b29, b29, b29 };
    e4 = stwo_qm31_mul(e6, e0);
    e0 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 88u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    e5 = StwoCudaQm31{ b7, b29, b29, b29 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e0, e6);
    e6 = stwo_load_qm31(ext_params, 89u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    e0 = StwoCudaQm31{ b8, b29, b29, b29 };
    e4 = stwo_qm31_mul(e6, e0);
    e0 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 90u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    e5 = StwoCudaQm31{ b9, b29, b29, b29 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e0, e6);
    e6 = stwo_load_qm31(ext_params, 91u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    e0 = StwoCudaQm31{ b10, b29, b29, b29 };
    e4 = stwo_qm31_mul(e6, e0);
    e0 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 92u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    e5 = StwoCudaQm31{ b11, b29, b29, b29 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e0, e6);
    e6 = stwo_load_qm31(ext_params, 93u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    e0 = StwoCudaQm31{ b14, b29, b29, b29 };
    e4 = stwo_qm31_mul(e6, e0);
    e0 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 94u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    e5 = StwoCudaQm31{ b15, b29, b29, b29 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e0, e6);
    e6 = stwo_load_qm31(ext_params, 95u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    unsigned b45 = base_params[51u];
    unsigned b46 = stwo_m31_mul(b26, b45);
    unsigned b47 = stwo_m31_add(b25, b46);
    e0 = StwoCudaQm31{ b47, b29, b29, b29 };
    e4 = stwo_qm31_mul(e6, e0);
    e0 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 96u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    unsigned b48 = base_params[52u];
    unsigned b49 = stwo_m31_mul(b24, b48);
    unsigned b50 = stwo_m31_add(b27, b49);
    e5 = StwoCudaQm31{ b50, b29, b29, b29 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e0, e6);
    e6 = stwo_load_qm31(ext_params, 97u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    e0 = StwoCudaQm31{ b20, b29, b29, b29 };
    e4 = stwo_qm31_mul(e6, e0);
    e0 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 98u);
    e5 = StwoCudaQm31{ b21, b29, b29, b29 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e0, e6);
    e6 = stwo_load_qm31(ext_params, 99u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    unsigned b33 = base_params[37u];
    unsigned b34 = stwo_m31_mul(b18, b33);
    unsigned b35 = stwo_m31_add(b17, b34);
    e0 = StwoCudaQm31{ b35, b29, b29, b29 };
    e4 = stwo_qm31_mul(e6, e0);
    e0 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(ext_params, 100u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    unsigned b36 = base_params[38u];
    unsigned b37 = stwo_m31_mul(b16, b36);
    unsigned b38 = stwo_m31_add(b19, b37);
    e5 = StwoCudaQm31{ b38, b29, b29, b29 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e0, e6);
    e6 = stwo_load_qm31(ext_params, 101u);
    e0 = stwo_qm31_sub(e5, e6);
    e6 = stwo_load_qm31(ext_params, 116u);
    e5 = stwo_qm31_mul(e3, e6);
    e6 = stwo_load_qm31(ext_params, 117u);
    e4 = stwo_qm31_mul(e2, e6);
    e6 = stwo_qm31_add(e5, e4);
    e4 = stwo_qm31_mul(e2, e3);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 24u, row_index, 0);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 25u, row_index, 0);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 26u, row_index, 0);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 27u, row_index, 0);
    e3 = StwoCudaQm31{ b51, b52, b53, b54 };
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 28u, row_index, 0);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 29u, row_index, 0);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 30u, row_index, 0);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 31u, row_index, 0);
    e2 = StwoCudaQm31{ b55, b56, b57, b58 };
    e5 = stwo_qm31_sub(e2, e3);
    e3 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e3, e6);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 32u, row_index, -1);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 33u, row_index, -1);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 34u, row_index, -1);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 35u, row_index, -1);
    e3 = StwoCudaQm31{ b59, b61, b63, b65 };
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 32u, row_index, 0);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 33u, row_index, 0);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 34u, row_index, 0);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 35u, row_index, 0);
    e6 = StwoCudaQm31{ b60, b62, b64, b66 };
    e4 = stwo_qm31_sub(e6, e3);
    e6 = stwo_qm31_sub(e4, e2);
    e4 = stwo_load_qm31(ext_params, 118u);
    e2 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e2, e0);
    e2 = stwo_qm31_sub(e4, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));

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
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b58 = base_params[0u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b57, b58, b58, b58 };
    StwoCudaQm31 e1 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e0);
    e0 = stwo_load_qm31(ext_params, 0u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    StwoCudaQm31 e2 = StwoCudaQm31{ b0, b58, b58, b58 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e0, e2);
    e2 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(ext_params, 2u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 1u, row_index, 0);
    e3 = StwoCudaQm31{ b1, b58, b58, b58 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 3u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 2u, row_index, 0);
    e0 = StwoCudaQm31{ b2, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 4u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 3u, row_index, 0);
    e3 = StwoCudaQm31{ b3, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 5u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 4u, row_index, 0);
    e0 = StwoCudaQm31{ b4, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 6u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 5u, row_index, 0);
    e3 = StwoCudaQm31{ b5, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 7u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 6u, row_index, 0);
    e0 = StwoCudaQm31{ b6, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 8u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 7u, row_index, 0);
    e3 = StwoCudaQm31{ b7, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 9u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 8u, row_index, 0);
    e0 = StwoCudaQm31{ b8, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 10u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 9u, row_index, 0);
    e3 = StwoCudaQm31{ b9, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 11u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 10u, row_index, 0);
    e0 = StwoCudaQm31{ b10, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 12u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 11u, row_index, 0);
    e3 = StwoCudaQm31{ b11, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 13u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 12u, row_index, 0);
    e0 = StwoCudaQm31{ b12, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 14u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 13u, row_index, 0);
    e3 = StwoCudaQm31{ b13, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 15u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 14u, row_index, 0);
    e0 = StwoCudaQm31{ b14, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 16u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 15u, row_index, 0);
    e3 = StwoCudaQm31{ b15, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 17u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 16u, row_index, 0);
    e0 = StwoCudaQm31{ b16, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 18u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 17u, row_index, 0);
    e3 = StwoCudaQm31{ b17, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 19u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 18u, row_index, 0);
    e0 = StwoCudaQm31{ b18, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 20u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 19u, row_index, 0);
    e3 = StwoCudaQm31{ b19, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 21u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 20u, row_index, 0);
    e0 = StwoCudaQm31{ b20, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 22u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 21u, row_index, 0);
    e3 = StwoCudaQm31{ b21, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 23u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 22u, row_index, 0);
    e0 = StwoCudaQm31{ b22, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 24u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 23u, row_index, 0);
    e3 = StwoCudaQm31{ b23, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 25u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 24u, row_index, 0);
    e0 = StwoCudaQm31{ b24, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 26u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 25u, row_index, 0);
    e3 = StwoCudaQm31{ b25, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 27u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 26u, row_index, 0);
    e0 = StwoCudaQm31{ b26, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 28u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 27u, row_index, 0);
    e3 = StwoCudaQm31{ b27, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 29u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 28u, row_index, 0);
    e0 = StwoCudaQm31{ b28, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 30u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 29u, row_index, 0);
    e3 = StwoCudaQm31{ b29, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 31u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 30u, row_index, 0);
    e0 = StwoCudaQm31{ b30, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 32u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 31u, row_index, 0);
    e3 = StwoCudaQm31{ b31, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 33u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 32u, row_index, 0);
    e0 = StwoCudaQm31{ b32, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 34u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 33u, row_index, 0);
    e3 = StwoCudaQm31{ b33, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 35u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 34u, row_index, 0);
    e0 = StwoCudaQm31{ b34, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 36u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 35u, row_index, 0);
    e3 = StwoCudaQm31{ b35, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 37u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 36u, row_index, 0);
    e0 = StwoCudaQm31{ b36, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 38u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 37u, row_index, 0);
    e3 = StwoCudaQm31{ b37, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 39u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 38u, row_index, 0);
    e0 = StwoCudaQm31{ b38, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 40u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 39u, row_index, 0);
    e3 = StwoCudaQm31{ b39, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 41u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 40u, row_index, 0);
    e0 = StwoCudaQm31{ b40, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 42u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 41u, row_index, 0);
    e3 = StwoCudaQm31{ b41, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 43u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 42u, row_index, 0);
    e0 = StwoCudaQm31{ b42, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 44u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 43u, row_index, 0);
    e3 = StwoCudaQm31{ b43, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 45u);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 44u, row_index, 0);
    e0 = StwoCudaQm31{ b44, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 46u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 45u, row_index, 0);
    e3 = StwoCudaQm31{ b45, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 47u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 46u, row_index, 0);
    e0 = StwoCudaQm31{ b46, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 48u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 47u, row_index, 0);
    e3 = StwoCudaQm31{ b47, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 49u);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 48u, row_index, 0);
    e0 = StwoCudaQm31{ b48, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 50u);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 49u, row_index, 0);
    e3 = StwoCudaQm31{ b49, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 51u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 50u, row_index, 0);
    e0 = StwoCudaQm31{ b50, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 52u);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 51u, row_index, 0);
    e3 = StwoCudaQm31{ b51, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 53u);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 52u, row_index, 0);
    e0 = StwoCudaQm31{ b52, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 54u);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 53u, row_index, 0);
    e3 = StwoCudaQm31{ b53, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 55u);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 54u, row_index, 0);
    e0 = StwoCudaQm31{ b54, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 56u);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 55u, row_index, 0);
    e3 = StwoCudaQm31{ b55, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(ext_params, 57u);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 56u, row_index, 0);
    e0 = StwoCudaQm31{ b56, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(ext_params, 58u);
    e3 = stwo_qm31_sub(e0, e2);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, -1);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, -1);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, -1);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, -1);
    e2 = StwoCudaQm31{ b59, b61, b63, b65 };
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e0 = StwoCudaQm31{ b60, b62, b64, b66 };
    e4 = stwo_qm31_sub(e0, e2);
    e0 = stwo_load_qm31(ext_params, 59u);
    e2 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e2, e3);
    e2 = stwo_qm31_sub(e0, e1);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));

    unsigned denom_idx = row_index >> log_n_rows;
    return stwo_qm31_mul_base(acc, part.denom_inv[denom_idx]);
}

extern "C" __global__ void __launch_bounds__(128) stwo_composition_wave_d4383fbf67de74a8(
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
