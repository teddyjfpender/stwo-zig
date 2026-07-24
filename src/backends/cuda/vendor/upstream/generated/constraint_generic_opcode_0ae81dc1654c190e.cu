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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_7434959f0ed18ec5(
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
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 226u, row_index, 0);
    unsigned b96 = base_params[248u];
    unsigned b97 = stwo_m31_mul(b83, b96);
    unsigned b98 = stwo_m31_sub(b38, b97);
    unsigned b99 = base_params[249u];
    unsigned b100 = stwo_m31_sub(b99, b98);
    unsigned b101 = stwo_m31_mul(b98, b100);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    unsigned b102 = stwo_m31_mul(b101, b5);
    unsigned b93 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b102, b93, b93, b93 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 54u, row_index, 0);
    unsigned b103 = base_params[250u];
    unsigned b104 = stwo_m31_mul(b36, b103);
    unsigned b105 = stwo_m31_add(b35, b104);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 55u, row_index, 0);
    unsigned b106 = base_params[251u];
    unsigned b107 = stwo_m31_mul(b37, b106);
    unsigned b108 = stwo_m31_add(b105, b107);
    unsigned b109 = base_params[252u];
    unsigned b110 = stwo_m31_mul(b38, b109);
    unsigned b111 = stwo_m31_add(b108, b110);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b94 = base_params[43u];
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b95 = stwo_m31_add(b94, b1);
    unsigned b112 = stwo_m31_add(b0, b95);
    unsigned b113 = stwo_m31_sub(b111, b112);
    unsigned b114 = stwo_m31_mul(b5, b113);
    StwoCudaQm31 e1 = StwoCudaQm31{ b114, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    unsigned b115 = stwo_m31_add(b11, b12);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    unsigned b116 = stwo_m31_add(b115, b13);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    unsigned b117 = stwo_m31_add(b116, b14);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    unsigned b118 = stwo_m31_add(b117, b15);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    unsigned b119 = stwo_m31_add(b118, b16);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    unsigned b120 = stwo_m31_add(b119, b17);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    unsigned b121 = stwo_m31_add(b120, b18);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    unsigned b122 = stwo_m31_add(b121, b19);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    unsigned b123 = stwo_m31_add(b122, b20);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    unsigned b124 = stwo_m31_add(b123, b21);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    unsigned b125 = stwo_m31_add(b124, b22);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    unsigned b126 = stwo_m31_add(b125, b23);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    unsigned b127 = stwo_m31_add(b126, b24);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    unsigned b128 = stwo_m31_add(b127, b25);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    unsigned b129 = stwo_m31_add(b128, b26);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    unsigned b130 = stwo_m31_add(b129, b27);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    unsigned b131 = stwo_m31_add(b130, b28);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    unsigned b132 = stwo_m31_add(b131, b29);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    unsigned b133 = stwo_m31_add(b132, b30);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    unsigned b134 = stwo_m31_add(b133, b31);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    unsigned b135 = stwo_m31_add(b134, b32);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    unsigned b136 = stwo_m31_add(b135, b33);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    unsigned b137 = stwo_m31_add(b136, b34);
    unsigned b138 = stwo_m31_mul(b6, b137);
    StwoCudaQm31 e2 = StwoCudaQm31{ b138, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 227u, row_index, 0);
    unsigned b139 = base_params[253u];
    unsigned b140 = stwo_m31_sub(b139, b84);
    unsigned b141 = stwo_m31_mul(b84, b140);
    unsigned b142 = stwo_m31_mul(b141, b6);
    StwoCudaQm31 e3 = StwoCudaQm31{ b142, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    unsigned b143 = base_params[254u];
    unsigned b144 = stwo_m31_mul(b84, b143);
    unsigned b145 = stwo_m31_sub(b10, b144);
    unsigned b146 = base_params[255u];
    unsigned b147 = stwo_m31_sub(b146, b145);
    unsigned b148 = stwo_m31_mul(b145, b147);
    unsigned b149 = stwo_m31_mul(b148, b6);
    StwoCudaQm31 e4 = StwoCudaQm31{ b149, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 228u, row_index, 0);
    unsigned b151 = base_params[259u];
    unsigned b152 = stwo_m31_sub(b85, b151);
    unsigned b153 = stwo_m31_mul(b85, b152);
    StwoCudaQm31 e5 = StwoCudaQm31{ b153, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 229u, row_index, 0);
    unsigned b154 = base_params[260u];
    unsigned b155 = stwo_m31_sub(b86, b154);
    unsigned b156 = stwo_m31_mul(b86, b155);
    StwoCudaQm31 e6 = StwoCudaQm31{ b156, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b157 = base_params[261u];
    unsigned b158 = stwo_m31_sub(b85, b157);
    unsigned b159 = stwo_m31_mul(b86, b158);
    StwoCudaQm31 e7 = StwoCudaQm31{ b159, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 230u, row_index, 0);
    unsigned b170 = base_params[266u];
    unsigned b171 = stwo_m31_sub(b170, b87);
    unsigned b172 = stwo_m31_mul(b87, b171);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b150 = stwo_m31_add(b2, b4);
    unsigned b173 = stwo_m31_mul(b172, b150);
    StwoCudaQm31 e8 = StwoCudaQm31{ b173, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 200u, row_index, 0);
    unsigned b160 = base_params[262u];
    unsigned b161 = stwo_m31_mul(b86, b160);
    unsigned b169 = stwo_m31_sub(b58, b161);
    unsigned b174 = base_params[267u];
    unsigned b175 = stwo_m31_mul(b87, b174);
    unsigned b176 = stwo_m31_sub(b169, b175);
    unsigned b177 = base_params[268u];
    unsigned b178 = stwo_m31_sub(b177, b176);
    unsigned b179 = stwo_m31_mul(b176, b178);
    unsigned b180 = stwo_m31_mul(b179, b150);
    StwoCudaQm31 e9 = StwoCudaQm31{ b180, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 201u, row_index, 0);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 202u, row_index, 0);
    unsigned b181 = stwo_m31_add(b59, b60);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 203u, row_index, 0);
    unsigned b182 = stwo_m31_add(b181, b61);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 204u, row_index, 0);
    unsigned b183 = stwo_m31_add(b182, b62);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 205u, row_index, 0);
    unsigned b184 = stwo_m31_add(b183, b63);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 206u, row_index, 0);
    unsigned b185 = stwo_m31_add(b184, b64);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 207u, row_index, 0);
    unsigned b186 = stwo_m31_add(b185, b65);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 208u, row_index, 0);
    unsigned b187 = stwo_m31_add(b186, b66);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 209u, row_index, 0);
    unsigned b188 = stwo_m31_add(b187, b67);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 210u, row_index, 0);
    unsigned b189 = stwo_m31_add(b188, b68);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 211u, row_index, 0);
    unsigned b190 = stwo_m31_add(b189, b69);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 212u, row_index, 0);
    unsigned b191 = stwo_m31_add(b190, b70);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 213u, row_index, 0);
    unsigned b192 = stwo_m31_add(b191, b71);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 214u, row_index, 0);
    unsigned b193 = stwo_m31_add(b192, b72);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 215u, row_index, 0);
    unsigned b194 = stwo_m31_add(b193, b73);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 216u, row_index, 0);
    unsigned b195 = stwo_m31_add(b194, b74);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 217u, row_index, 0);
    unsigned b196 = stwo_m31_add(b195, b75);
    unsigned b162 = base_params[263u];
    unsigned b163 = stwo_m31_mul(b86, b162);
    unsigned b197 = base_params[269u];
    unsigned b198 = stwo_m31_mul(b163, b197);
    unsigned b199 = stwo_m31_sub(b196, b198);
    unsigned b200 = stwo_m31_mul(b150, b199);
    StwoCudaQm31 e10 = StwoCudaQm31{ b200, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 218u, row_index, 0);
    unsigned b164 = base_params[264u];
    unsigned b165 = stwo_m31_mul(b85, b164);
    unsigned b166 = stwo_m31_sub(b165, b86);
    unsigned b201 = stwo_m31_sub(b76, b166);
    unsigned b202 = stwo_m31_mul(b150, b201);
    StwoCudaQm31 e11 = StwoCudaQm31{ b202, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 219u, row_index, 0);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 220u, row_index, 0);
    unsigned b203 = stwo_m31_add(b77, b78);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 221u, row_index, 0);
    unsigned b204 = stwo_m31_add(b203, b79);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 222u, row_index, 0);
    unsigned b205 = stwo_m31_add(b204, b80);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 223u, row_index, 0);
    unsigned b206 = stwo_m31_add(b205, b81);
    unsigned b207 = stwo_m31_mul(b150, b206);
    StwoCudaQm31 e12 = StwoCudaQm31{ b207, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 224u, row_index, 0);
    unsigned b167 = base_params[265u];
    unsigned b168 = stwo_m31_mul(b85, b167);
    unsigned b208 = stwo_m31_sub(b82, b168);
    unsigned b209 = stwo_m31_mul(b150, b208);
    StwoCudaQm31 e13 = StwoCudaQm31{ b209, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    unsigned b210 = base_params[274u];
    unsigned b211 = stwo_m31_sub(b7, b210);
    unsigned b216 = stwo_m31_mul(b211, b211);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    unsigned b217 = stwo_m31_add(b216, b8);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    unsigned b218 = stwo_m31_add(b217, b9);
    unsigned b219 = stwo_m31_add(b218, b10);
    unsigned b220 = stwo_m31_add(b219, b11);
    unsigned b221 = stwo_m31_add(b220, b12);
    unsigned b222 = stwo_m31_add(b221, b13);
    unsigned b223 = stwo_m31_add(b222, b14);
    unsigned b224 = stwo_m31_add(b223, b15);
    unsigned b225 = stwo_m31_add(b224, b16);
    unsigned b226 = stwo_m31_add(b225, b17);
    unsigned b227 = stwo_m31_add(b226, b18);
    unsigned b228 = stwo_m31_add(b227, b19);
    unsigned b229 = stwo_m31_add(b228, b20);
    unsigned b230 = stwo_m31_add(b229, b21);
    unsigned b231 = stwo_m31_add(b230, b22);
    unsigned b232 = stwo_m31_add(b231, b23);
    unsigned b233 = stwo_m31_add(b232, b24);
    unsigned b234 = stwo_m31_add(b233, b25);
    unsigned b235 = stwo_m31_add(b234, b26);
    unsigned b236 = stwo_m31_add(b235, b27);
    unsigned b212 = base_params[275u];
    unsigned b213 = stwo_m31_sub(b28, b212);
    unsigned b237 = stwo_m31_mul(b213, b213);
    unsigned b238 = stwo_m31_add(b236, b237);
    unsigned b239 = stwo_m31_add(b238, b29);
    unsigned b240 = stwo_m31_add(b239, b30);
    unsigned b241 = stwo_m31_add(b240, b31);
    unsigned b242 = stwo_m31_add(b241, b32);
    unsigned b243 = stwo_m31_add(b242, b33);
    unsigned b214 = base_params[276u];
    unsigned b215 = stwo_m31_sub(b34, b214);
    unsigned b244 = stwo_m31_mul(b215, b215);
    unsigned b245 = stwo_m31_add(b243, b244);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 231u, row_index, 0);
    unsigned b246 = stwo_m31_mul(b245, b88);
    unsigned b247 = base_params[277u];
    unsigned b248 = stwo_m31_sub(b246, b247);
    StwoCudaQm31 e14 = StwoCudaQm31{ b248, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 233u, row_index, 0);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b249 = stwo_m31_add(b7, b8);
    unsigned b250 = stwo_m31_add(b249, b9);
    unsigned b251 = stwo_m31_add(b250, b10);
    unsigned b252 = stwo_m31_add(b251, b11);
    unsigned b253 = stwo_m31_add(b252, b12);
    unsigned b254 = stwo_m31_add(b253, b13);
    unsigned b255 = stwo_m31_add(b254, b14);
    unsigned b256 = stwo_m31_add(b255, b15);
    unsigned b257 = stwo_m31_add(b256, b16);
    unsigned b258 = stwo_m31_add(b257, b17);
    unsigned b259 = stwo_m31_add(b258, b18);
    unsigned b260 = stwo_m31_add(b259, b19);
    unsigned b261 = stwo_m31_add(b260, b20);
    unsigned b262 = stwo_m31_add(b261, b21);
    unsigned b263 = stwo_m31_add(b262, b22);
    unsigned b264 = stwo_m31_add(b263, b23);
    unsigned b265 = stwo_m31_add(b264, b24);
    unsigned b266 = stwo_m31_add(b265, b25);
    unsigned b267 = stwo_m31_add(b266, b26);
    unsigned b268 = stwo_m31_add(b267, b27);
    unsigned b269 = stwo_m31_add(b268, b28);
    unsigned b270 = stwo_m31_add(b269, b29);
    unsigned b271 = stwo_m31_add(b270, b30);
    unsigned b272 = stwo_m31_add(b271, b31);
    unsigned b273 = stwo_m31_add(b272, b32);
    unsigned b274 = stwo_m31_add(b273, b33);
    unsigned b275 = stwo_m31_add(b274, b34);
    unsigned b276 = stwo_m31_mul(b3, b275);
    unsigned b277 = stwo_m31_sub(b89, b276);
    StwoCudaQm31 e15 = StwoCudaQm31{ b277, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 15u)));
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 234u, row_index, 0);
    unsigned b278 = base_params[278u];
    unsigned b279 = stwo_m31_sub(b90, b278);
    unsigned b280 = stwo_m31_mul(b90, b279);
    StwoCudaQm31 e16 = StwoCudaQm31{ b280, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 16u)));
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 235u, row_index, 0);
    unsigned b281 = base_params[279u];
    unsigned b282 = stwo_m31_sub(b91, b281);
    unsigned b283 = stwo_m31_mul(b91, b282);
    StwoCudaQm31 e17 = StwoCudaQm31{ b283, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 17u)));
    unsigned b284 = base_params[280u];
    unsigned b285 = stwo_m31_sub(b90, b284);
    unsigned b286 = stwo_m31_mul(b91, b285);
    StwoCudaQm31 e18 = StwoCudaQm31{ b286, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 18u)));
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 236u, row_index, 0);
    unsigned b295 = base_params[285u];
    unsigned b296 = stwo_m31_sub(b295, b92);
    unsigned b297 = stwo_m31_mul(b92, b296);
    unsigned b298 = stwo_m31_mul(b297, b89);
    StwoCudaQm31 e19 = StwoCudaQm31{ b298, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e19, stwo_load_qm31(random_coeff_powers, rc_base + 19u)));
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 87u, row_index, 0);
    unsigned b287 = base_params[281u];
    unsigned b288 = stwo_m31_mul(b91, b287);
    unsigned b294 = stwo_m31_sub(b39, b288);
    unsigned b299 = base_params[286u];
    unsigned b300 = stwo_m31_mul(b92, b299);
    unsigned b301 = stwo_m31_sub(b294, b300);
    unsigned b302 = base_params[287u];
    unsigned b303 = stwo_m31_sub(b302, b301);
    unsigned b304 = stwo_m31_mul(b301, b303);
    unsigned b305 = stwo_m31_mul(b304, b89);
    StwoCudaQm31 e20 = StwoCudaQm31{ b305, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e20, stwo_load_qm31(random_coeff_powers, rc_base + 20u)));
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 88u, row_index, 0);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 89u, row_index, 0);
    unsigned b306 = stwo_m31_add(b40, b41);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 90u, row_index, 0);
    unsigned b307 = stwo_m31_add(b306, b42);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 91u, row_index, 0);
    unsigned b308 = stwo_m31_add(b307, b43);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 92u, row_index, 0);
    unsigned b309 = stwo_m31_add(b308, b44);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 93u, row_index, 0);
    unsigned b310 = stwo_m31_add(b309, b45);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 94u, row_index, 0);
    unsigned b311 = stwo_m31_add(b310, b46);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 95u, row_index, 0);
    unsigned b312 = stwo_m31_add(b311, b47);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 96u, row_index, 0);
    unsigned b313 = stwo_m31_add(b312, b48);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 97u, row_index, 0);
    unsigned b314 = stwo_m31_add(b313, b49);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 98u, row_index, 0);
    unsigned b315 = stwo_m31_add(b314, b50);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 99u, row_index, 0);
    unsigned b316 = stwo_m31_add(b315, b51);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 100u, row_index, 0);
    unsigned b317 = stwo_m31_add(b316, b52);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 101u, row_index, 0);
    unsigned b318 = stwo_m31_add(b317, b53);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 102u, row_index, 0);
    unsigned b319 = stwo_m31_add(b318, b54);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 103u, row_index, 0);
    unsigned b320 = stwo_m31_add(b319, b55);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 104u, row_index, 0);
    unsigned b321 = stwo_m31_add(b320, b56);
    unsigned b289 = base_params[282u];
    unsigned b290 = stwo_m31_mul(b91, b289);
    unsigned b322 = base_params[288u];
    unsigned b323 = stwo_m31_mul(b290, b322);
    unsigned b324 = stwo_m31_sub(b321, b323);
    unsigned b325 = stwo_m31_mul(b89, b324);
    StwoCudaQm31 e21 = StwoCudaQm31{ b325, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e21, stwo_load_qm31(random_coeff_powers, rc_base + 21u)));
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 105u, row_index, 0);
    unsigned b291 = base_params[283u];
    unsigned b292 = stwo_m31_mul(b90, b291);
    unsigned b293 = stwo_m31_sub(b292, b91);
    unsigned b326 = stwo_m31_sub(b57, b293);
    unsigned b327 = stwo_m31_mul(b89, b326);
    StwoCudaQm31 e22 = StwoCudaQm31{ b327, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e22, stwo_load_qm31(random_coeff_powers, rc_base + 22u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
