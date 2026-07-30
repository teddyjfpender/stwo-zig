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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_a55cb55ac86909c2(
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
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b68 = base_params[0u];
    unsigned b69 = stwo_m31_sub(b68, b4);
    unsigned b70 = stwo_m31_mul(b4, b69);
    unsigned b71 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b70, b71, b71, b71 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b72 = base_params[2u];
    unsigned b73 = stwo_m31_sub(b72, b5);
    unsigned b74 = stwo_m31_mul(b5, b73);
    StwoCudaQm31 e1 = StwoCudaQm31{ b74, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b75 = base_params[3u];
    unsigned b76 = stwo_m31_sub(b75, b6);
    unsigned b77 = stwo_m31_mul(b6, b76);
    StwoCudaQm31 e2 = StwoCudaQm31{ b77, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b78 = base_params[4u];
    unsigned b79 = stwo_m31_sub(b78, b7);
    unsigned b80 = stwo_m31_mul(b7, b79);
    StwoCudaQm31 e3 = StwoCudaQm31{ b80, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b81 = base_params[5u];
    unsigned b82 = stwo_m31_sub(b81, b6);
    unsigned b83 = stwo_m31_sub(b82, b7);
    unsigned b84 = base_params[6u];
    unsigned b85 = stwo_m31_sub(b84, b83);
    unsigned b86 = stwo_m31_mul(b83, b85);
    StwoCudaQm31 e4 = StwoCudaQm31{ b86, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b87 = base_params[7u];
    unsigned b88 = stwo_m31_sub(b87, b8);
    unsigned b89 = stwo_m31_mul(b8, b88);
    StwoCudaQm31 e5 = StwoCudaQm31{ b89, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b90 = base_params[8u];
    unsigned b91 = stwo_m31_sub(b90, b9);
    unsigned b92 = stwo_m31_mul(b9, b91);
    StwoCudaQm31 e6 = StwoCudaQm31{ b92, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    unsigned b93 = base_params[20u];
    unsigned b94 = stwo_m31_sub(b3, b93);
    unsigned b97 = base_params[22u];
    unsigned b98 = stwo_m31_sub(b94, b97);
    unsigned b99 = stwo_m31_mul(b6, b98);
    StwoCudaQm31 e7 = StwoCudaQm31{ b99, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b100 = stwo_m31_mul(b4, b2);
    unsigned b101 = base_params[23u];
    unsigned b102 = stwo_m31_sub(b101, b4);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    unsigned b103 = stwo_m31_mul(b102, b1);
    unsigned b104 = stwo_m31_add(b100, b103);
    unsigned b105 = stwo_m31_sub(b10, b104);
    StwoCudaQm31 e8 = StwoCudaQm31{ b105, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    unsigned b106 = stwo_m31_mul(b5, b2);
    unsigned b107 = base_params[24u];
    unsigned b108 = stwo_m31_sub(b107, b5);
    unsigned b109 = stwo_m31_mul(b108, b1);
    unsigned b110 = stwo_m31_add(b106, b109);
    unsigned b111 = stwo_m31_sub(b11, b110);
    StwoCudaQm31 e9 = StwoCudaQm31{ b111, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    unsigned b112 = stwo_m31_mul(b7, b2);
    unsigned b113 = stwo_m31_mul(b83, b1);
    unsigned b114 = stwo_m31_add(b112, b113);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b115 = stwo_m31_mul(b6, b0);
    unsigned b116 = stwo_m31_add(b114, b115);
    unsigned b117 = stwo_m31_sub(b12, b116);
    StwoCudaQm31 e10 = StwoCudaQm31{ b117, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    unsigned b118 = stwo_m31_add(b13, b14);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    unsigned b119 = stwo_m31_add(b118, b15);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    unsigned b120 = stwo_m31_add(b119, b16);
    unsigned b121 = base_params[25u];
    unsigned b122 = stwo_m31_sub(b120, b121);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    unsigned b123 = stwo_m31_add(b17, b18);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    unsigned b124 = stwo_m31_add(b123, b19);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    unsigned b125 = stwo_m31_add(b124, b20);
    unsigned b126 = base_params[26u];
    unsigned b127 = stwo_m31_sub(b125, b126);
    unsigned b128 = stwo_m31_mul(b122, b127);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    unsigned b129 = stwo_m31_mul(b128, b29);
    unsigned b130 = base_params[27u];
    unsigned b131 = stwo_m31_sub(b129, b130);
    StwoCudaQm31 e11 = StwoCudaQm31{ b131, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    unsigned b132 = stwo_m31_add(b21, b22);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    unsigned b133 = stwo_m31_add(b132, b23);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    unsigned b134 = stwo_m31_add(b133, b24);
    unsigned b135 = base_params[28u];
    unsigned b136 = stwo_m31_sub(b134, b135);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    unsigned b137 = stwo_m31_add(b25, b26);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    unsigned b138 = stwo_m31_add(b137, b27);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    unsigned b139 = stwo_m31_add(b138, b28);
    unsigned b140 = base_params[29u];
    unsigned b141 = stwo_m31_sub(b139, b140);
    unsigned b142 = stwo_m31_mul(b136, b141);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    unsigned b143 = stwo_m31_mul(b142, b30);
    unsigned b144 = base_params[30u];
    unsigned b145 = stwo_m31_sub(b143, b144);
    StwoCudaQm31 e12 = StwoCudaQm31{ b145, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    unsigned b182 = stwo_m31_add(b31, b32);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    unsigned b183 = stwo_m31_add(b182, b33);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    unsigned b184 = stwo_m31_add(b183, b34);
    unsigned b185 = base_params[43u];
    unsigned b186 = stwo_m31_sub(b184, b185);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    unsigned b187 = stwo_m31_add(b35, b36);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    unsigned b188 = stwo_m31_add(b187, b37);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    unsigned b189 = stwo_m31_add(b188, b38);
    unsigned b190 = base_params[44u];
    unsigned b191 = stwo_m31_sub(b189, b190);
    unsigned b192 = stwo_m31_mul(b186, b191);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    unsigned b193 = stwo_m31_mul(b192, b47);
    unsigned b194 = base_params[45u];
    unsigned b195 = stwo_m31_sub(b193, b194);
    StwoCudaQm31 e13 = StwoCudaQm31{ b195, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    unsigned b196 = stwo_m31_add(b39, b40);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    unsigned b197 = stwo_m31_add(b196, b41);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    unsigned b198 = stwo_m31_add(b197, b42);
    unsigned b199 = base_params[46u];
    unsigned b200 = stwo_m31_sub(b198, b199);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    unsigned b201 = stwo_m31_add(b43, b44);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    unsigned b202 = stwo_m31_add(b201, b45);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    unsigned b203 = stwo_m31_add(b202, b46);
    unsigned b204 = base_params[47u];
    unsigned b205 = stwo_m31_sub(b203, b204);
    unsigned b206 = stwo_m31_mul(b200, b205);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    unsigned b207 = stwo_m31_mul(b206, b48);
    unsigned b208 = base_params[48u];
    unsigned b209 = stwo_m31_sub(b207, b208);
    StwoCudaQm31 e14 = StwoCudaQm31{ b209, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 54u, row_index, 0);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 55u, row_index, 0);
    unsigned b246 = stwo_m31_add(b49, b50);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    unsigned b247 = stwo_m31_add(b246, b51);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    unsigned b248 = stwo_m31_add(b247, b52);
    unsigned b249 = base_params[61u];
    unsigned b250 = stwo_m31_sub(b248, b249);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    unsigned b251 = stwo_m31_add(b53, b54);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 60u, row_index, 0);
    unsigned b252 = stwo_m31_add(b251, b55);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 61u, row_index, 0);
    unsigned b253 = stwo_m31_add(b252, b56);
    unsigned b254 = base_params[62u];
    unsigned b255 = stwo_m31_sub(b253, b254);
    unsigned b256 = stwo_m31_mul(b250, b255);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 70u, row_index, 0);
    unsigned b257 = stwo_m31_mul(b256, b65);
    unsigned b258 = base_params[63u];
    unsigned b259 = stwo_m31_sub(b257, b258);
    StwoCudaQm31 e15 = StwoCudaQm31{ b259, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 15u)));
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 62u, row_index, 0);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 63u, row_index, 0);
    unsigned b260 = stwo_m31_add(b57, b58);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 64u, row_index, 0);
    unsigned b261 = stwo_m31_add(b260, b59);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 65u, row_index, 0);
    unsigned b262 = stwo_m31_add(b261, b60);
    unsigned b263 = base_params[64u];
    unsigned b264 = stwo_m31_sub(b262, b263);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 66u, row_index, 0);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 67u, row_index, 0);
    unsigned b265 = stwo_m31_add(b61, b62);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 68u, row_index, 0);
    unsigned b266 = stwo_m31_add(b265, b63);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 69u, row_index, 0);
    unsigned b267 = stwo_m31_add(b266, b64);
    unsigned b268 = base_params[65u];
    unsigned b269 = stwo_m31_sub(b267, b268);
    unsigned b270 = stwo_m31_mul(b264, b269);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 71u, row_index, 0);
    unsigned b271 = stwo_m31_mul(b270, b66);
    unsigned b272 = base_params[66u];
    unsigned b273 = stwo_m31_sub(b271, b272);
    StwoCudaQm31 e16 = StwoCudaQm31{ b273, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 16u)));
    unsigned b146 = base_params[31u];
    unsigned b147 = stwo_m31_mul(b14, b146);
    unsigned b148 = stwo_m31_add(b13, b147);
    unsigned b149 = base_params[32u];
    unsigned b150 = stwo_m31_mul(b15, b149);
    unsigned b151 = stwo_m31_add(b148, b150);
    unsigned b152 = base_params[33u];
    unsigned b153 = stwo_m31_mul(b16, b152);
    unsigned b154 = stwo_m31_add(b151, b153);
    unsigned b210 = base_params[49u];
    unsigned b211 = stwo_m31_mul(b32, b210);
    unsigned b212 = stwo_m31_add(b31, b211);
    unsigned b213 = base_params[50u];
    unsigned b214 = stwo_m31_mul(b33, b213);
    unsigned b215 = stwo_m31_add(b212, b214);
    unsigned b216 = base_params[51u];
    unsigned b217 = stwo_m31_mul(b34, b216);
    unsigned b218 = stwo_m31_add(b215, b217);
    unsigned b274 = base_params[67u];
    unsigned b275 = stwo_m31_mul(b50, b274);
    unsigned b276 = stwo_m31_add(b49, b275);
    unsigned b277 = base_params[68u];
    unsigned b278 = stwo_m31_mul(b51, b277);
    unsigned b279 = stwo_m31_add(b276, b278);
    unsigned b280 = base_params[69u];
    unsigned b281 = stwo_m31_mul(b52, b280);
    unsigned b282 = stwo_m31_add(b279, b281);
    unsigned b310 = stwo_m31_mul(b218, b282);
    unsigned b219 = base_params[52u];
    unsigned b220 = stwo_m31_mul(b36, b219);
    unsigned b221 = stwo_m31_add(b35, b220);
    unsigned b222 = base_params[53u];
    unsigned b223 = stwo_m31_mul(b37, b222);
    unsigned b224 = stwo_m31_add(b221, b223);
    unsigned b225 = base_params[54u];
    unsigned b226 = stwo_m31_mul(b38, b225);
    unsigned b227 = stwo_m31_add(b224, b226);
    unsigned b283 = base_params[70u];
    unsigned b284 = stwo_m31_mul(b54, b283);
    unsigned b285 = stwo_m31_add(b53, b284);
    unsigned b286 = base_params[71u];
    unsigned b287 = stwo_m31_mul(b55, b286);
    unsigned b288 = stwo_m31_add(b285, b287);
    unsigned b289 = base_params[72u];
    unsigned b290 = stwo_m31_mul(b56, b289);
    unsigned b291 = stwo_m31_add(b288, b290);
    unsigned b311 = stwo_m31_mul(b227, b291);
    unsigned b312 = stwo_m31_sub(b310, b311);
    unsigned b316 = base_params[79u];
    unsigned b228 = base_params[55u];
    unsigned b229 = stwo_m31_mul(b40, b228);
    unsigned b230 = stwo_m31_add(b39, b229);
    unsigned b231 = base_params[56u];
    unsigned b232 = stwo_m31_mul(b41, b231);
    unsigned b233 = stwo_m31_add(b230, b232);
    unsigned b234 = base_params[57u];
    unsigned b235 = stwo_m31_mul(b42, b234);
    unsigned b236 = stwo_m31_add(b233, b235);
    unsigned b292 = base_params[73u];
    unsigned b293 = stwo_m31_mul(b58, b292);
    unsigned b294 = stwo_m31_add(b57, b293);
    unsigned b295 = base_params[74u];
    unsigned b296 = stwo_m31_mul(b59, b295);
    unsigned b297 = stwo_m31_add(b294, b296);
    unsigned b298 = base_params[75u];
    unsigned b299 = stwo_m31_mul(b60, b298);
    unsigned b300 = stwo_m31_add(b297, b299);
    unsigned b313 = stwo_m31_mul(b236, b300);
    unsigned b237 = base_params[58u];
    unsigned b238 = stwo_m31_mul(b44, b237);
    unsigned b239 = stwo_m31_add(b43, b238);
    unsigned b240 = base_params[59u];
    unsigned b241 = stwo_m31_mul(b45, b240);
    unsigned b242 = stwo_m31_add(b239, b241);
    unsigned b243 = base_params[60u];
    unsigned b244 = stwo_m31_mul(b46, b243);
    unsigned b245 = stwo_m31_add(b242, b244);
    unsigned b301 = base_params[76u];
    unsigned b302 = stwo_m31_mul(b62, b301);
    unsigned b303 = stwo_m31_add(b61, b302);
    unsigned b304 = base_params[77u];
    unsigned b305 = stwo_m31_mul(b63, b304);
    unsigned b306 = stwo_m31_add(b303, b305);
    unsigned b307 = base_params[78u];
    unsigned b308 = stwo_m31_mul(b64, b307);
    unsigned b309 = stwo_m31_add(b306, b308);
    unsigned b314 = stwo_m31_mul(b245, b309);
    unsigned b315 = stwo_m31_sub(b313, b314);
    unsigned b317 = stwo_m31_mul(b316, b315);
    unsigned b318 = stwo_m31_add(b312, b317);
    unsigned b319 = stwo_m31_mul(b236, b309);
    unsigned b320 = stwo_m31_sub(b318, b319);
    unsigned b321 = stwo_m31_mul(b245, b300);
    unsigned b322 = stwo_m31_sub(b320, b321);
    unsigned b95 = base_params[21u];
    unsigned b96 = stwo_m31_sub(b95, b8);
    unsigned b323 = stwo_m31_mul(b322, b96);
    unsigned b324 = stwo_m31_sub(b154, b323);
    unsigned b325 = stwo_m31_add(b218, b282);
    unsigned b326 = stwo_m31_mul(b325, b8);
    unsigned b327 = stwo_m31_sub(b324, b326);
    StwoCudaQm31 e17 = StwoCudaQm31{ b327, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 17u)));
    unsigned b155 = base_params[34u];
    unsigned b156 = stwo_m31_mul(b18, b155);
    unsigned b157 = stwo_m31_add(b17, b156);
    unsigned b158 = base_params[35u];
    unsigned b159 = stwo_m31_mul(b19, b158);
    unsigned b160 = stwo_m31_add(b157, b159);
    unsigned b161 = base_params[36u];
    unsigned b162 = stwo_m31_mul(b20, b161);
    unsigned b163 = stwo_m31_add(b160, b162);
    unsigned b328 = stwo_m31_mul(b218, b291);
    unsigned b329 = stwo_m31_mul(b227, b282);
    unsigned b330 = stwo_m31_add(b328, b329);
    unsigned b334 = base_params[80u];
    unsigned b331 = stwo_m31_mul(b236, b309);
    unsigned b332 = stwo_m31_mul(b245, b300);
    unsigned b333 = stwo_m31_add(b331, b332);
    unsigned b335 = stwo_m31_mul(b334, b333);
    unsigned b336 = stwo_m31_add(b330, b335);
    unsigned b337 = stwo_m31_mul(b236, b300);
    unsigned b338 = stwo_m31_add(b336, b337);
    unsigned b339 = stwo_m31_mul(b245, b309);
    unsigned b340 = stwo_m31_sub(b338, b339);
    unsigned b341 = stwo_m31_mul(b340, b96);
    unsigned b342 = stwo_m31_sub(b163, b341);
    unsigned b343 = stwo_m31_add(b227, b291);
    unsigned b344 = stwo_m31_mul(b343, b8);
    unsigned b345 = stwo_m31_sub(b342, b344);
    StwoCudaQm31 e18 = StwoCudaQm31{ b345, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 18u)));
    unsigned b164 = base_params[37u];
    unsigned b165 = stwo_m31_mul(b22, b164);
    unsigned b166 = stwo_m31_add(b21, b165);
    unsigned b167 = base_params[38u];
    unsigned b168 = stwo_m31_mul(b23, b167);
    unsigned b169 = stwo_m31_add(b166, b168);
    unsigned b170 = base_params[39u];
    unsigned b171 = stwo_m31_mul(b24, b170);
    unsigned b172 = stwo_m31_add(b169, b171);
    unsigned b346 = stwo_m31_mul(b218, b300);
    unsigned b347 = stwo_m31_mul(b227, b309);
    unsigned b348 = stwo_m31_sub(b346, b347);
    unsigned b349 = stwo_m31_mul(b236, b282);
    unsigned b350 = stwo_m31_add(b348, b349);
    unsigned b351 = stwo_m31_mul(b245, b291);
    unsigned b352 = stwo_m31_sub(b350, b351);
    unsigned b353 = stwo_m31_mul(b352, b96);
    unsigned b354 = stwo_m31_sub(b172, b353);
    unsigned b355 = stwo_m31_add(b236, b300);
    unsigned b356 = stwo_m31_mul(b355, b8);
    unsigned b357 = stwo_m31_sub(b354, b356);
    StwoCudaQm31 e19 = StwoCudaQm31{ b357, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e19, stwo_load_qm31(random_coeff_powers, rc_base + 19u)));
    unsigned b173 = base_params[40u];
    unsigned b174 = stwo_m31_mul(b26, b173);
    unsigned b175 = stwo_m31_add(b25, b174);
    unsigned b176 = base_params[41u];
    unsigned b177 = stwo_m31_mul(b27, b176);
    unsigned b178 = stwo_m31_add(b175, b177);
    unsigned b179 = base_params[42u];
    unsigned b180 = stwo_m31_mul(b28, b179);
    unsigned b181 = stwo_m31_add(b178, b180);
    unsigned b358 = stwo_m31_mul(b218, b309);
    unsigned b359 = stwo_m31_mul(b227, b300);
    unsigned b360 = stwo_m31_add(b358, b359);
    unsigned b361 = stwo_m31_mul(b236, b291);
    unsigned b362 = stwo_m31_add(b360, b361);
    unsigned b363 = stwo_m31_mul(b245, b282);
    unsigned b364 = stwo_m31_add(b362, b363);
    unsigned b365 = stwo_m31_mul(b364, b96);
    unsigned b366 = stwo_m31_sub(b181, b365);
    unsigned b367 = stwo_m31_add(b245, b309);
    unsigned b368 = stwo_m31_mul(b367, b8);
    unsigned b369 = stwo_m31_sub(b366, b368);
    StwoCudaQm31 e20 = StwoCudaQm31{ b369, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e20, stwo_load_qm31(random_coeff_powers, rc_base + 20u)));
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 72u, row_index, 0);
    unsigned b370 = stwo_m31_mul(b67, b67);
    unsigned b371 = stwo_m31_sub(b370, b67);
    StwoCudaQm31 e21 = StwoCudaQm31{ b371, b71, b71, b71 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e21, stwo_load_qm31(random_coeff_powers, rc_base + 21u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
