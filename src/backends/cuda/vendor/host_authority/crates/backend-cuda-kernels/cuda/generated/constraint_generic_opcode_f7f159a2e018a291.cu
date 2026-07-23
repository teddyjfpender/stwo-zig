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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_a7bd63296fc89989(
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
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    unsigned b57 = base_params[0u];
    unsigned b58 = stwo_m31_sub(b57, b3);
    unsigned b59 = stwo_m31_mul(b3, b58);
    unsigned b60 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b59, b60, b60, b60 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b61 = base_params[2u];
    unsigned b62 = stwo_m31_sub(b61, b4);
    unsigned b63 = stwo_m31_mul(b4, b62);
    StwoCudaQm31 e1 = StwoCudaQm31{ b63, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b64 = base_params[3u];
    unsigned b65 = stwo_m31_sub(b64, b5);
    unsigned b66 = stwo_m31_mul(b5, b65);
    StwoCudaQm31 e2 = StwoCudaQm31{ b66, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b67 = base_params[4u];
    unsigned b68 = stwo_m31_sub(b67, b6);
    unsigned b69 = stwo_m31_mul(b6, b68);
    StwoCudaQm31 e3 = StwoCudaQm31{ b69, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b70 = base_params[5u];
    unsigned b71 = stwo_m31_sub(b70, b7);
    unsigned b72 = stwo_m31_mul(b7, b71);
    StwoCudaQm31 e4 = StwoCudaQm31{ b72, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b73 = base_params[6u];
    unsigned b74 = stwo_m31_sub(b73, b8);
    unsigned b75 = stwo_m31_mul(b8, b74);
    StwoCudaQm31 e5 = StwoCudaQm31{ b75, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b76 = base_params[7u];
    unsigned b77 = stwo_m31_sub(b76, b9);
    unsigned b78 = stwo_m31_mul(b9, b77);
    StwoCudaQm31 e6 = StwoCudaQm31{ b78, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    unsigned b79 = base_params[8u];
    unsigned b80 = stwo_m31_sub(b79, b10);
    unsigned b81 = stwo_m31_mul(b10, b80);
    StwoCudaQm31 e7 = StwoCudaQm31{ b81, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    unsigned b82 = base_params[9u];
    unsigned b83 = stwo_m31_sub(b82, b11);
    unsigned b84 = stwo_m31_mul(b11, b83);
    StwoCudaQm31 e8 = StwoCudaQm31{ b84, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b85 = base_params[10u];
    unsigned b86 = stwo_m31_sub(b85, b12);
    unsigned b87 = stwo_m31_mul(b12, b86);
    StwoCudaQm31 e9 = StwoCudaQm31{ b87, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b88 = base_params[11u];
    unsigned b89 = stwo_m31_sub(b88, b13);
    unsigned b90 = stwo_m31_mul(b13, b89);
    StwoCudaQm31 e10 = StwoCudaQm31{ b90, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    unsigned b91 = base_params[12u];
    unsigned b92 = stwo_m31_sub(b91, b14);
    unsigned b93 = stwo_m31_mul(b14, b92);
    StwoCudaQm31 e11 = StwoCudaQm31{ b93, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    unsigned b94 = base_params[13u];
    unsigned b95 = stwo_m31_sub(b94, b15);
    unsigned b96 = stwo_m31_mul(b15, b95);
    StwoCudaQm31 e12 = StwoCudaQm31{ b96, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    unsigned b97 = base_params[14u];
    unsigned b98 = stwo_m31_sub(b97, b16);
    unsigned b99 = stwo_m31_mul(b16, b98);
    StwoCudaQm31 e13 = StwoCudaQm31{ b99, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    unsigned b100 = base_params[15u];
    unsigned b101 = stwo_m31_sub(b100, b17);
    unsigned b102 = stwo_m31_mul(b17, b101);
    StwoCudaQm31 e14 = StwoCudaQm31{ b102, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));
    unsigned b103 = base_params[33u];
    unsigned b104 = stwo_m31_sub(b103, b5);
    unsigned b105 = stwo_m31_sub(b104, b6);
    unsigned b106 = stwo_m31_sub(b105, b7);
    unsigned b107 = base_params[34u];
    unsigned b108 = stwo_m31_sub(b107, b106);
    unsigned b109 = stwo_m31_mul(b106, b108);
    StwoCudaQm31 e15 = StwoCudaQm31{ b109, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 15u)));
    unsigned b110 = base_params[35u];
    unsigned b111 = stwo_m31_sub(b110, b8);
    unsigned b112 = stwo_m31_sub(b111, b9);
    unsigned b113 = stwo_m31_sub(b112, b12);
    unsigned b114 = base_params[36u];
    unsigned b115 = stwo_m31_sub(b114, b113);
    unsigned b116 = stwo_m31_mul(b113, b115);
    StwoCudaQm31 e16 = StwoCudaQm31{ b116, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 16u)));
    unsigned b117 = base_params[37u];
    unsigned b118 = stwo_m31_sub(b117, b10);
    unsigned b119 = stwo_m31_sub(b118, b11);
    unsigned b120 = stwo_m31_sub(b119, b12);
    unsigned b121 = base_params[38u];
    unsigned b122 = stwo_m31_sub(b121, b120);
    unsigned b123 = stwo_m31_mul(b120, b122);
    StwoCudaQm31 e17 = StwoCudaQm31{ b123, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 17u)));
    unsigned b124 = base_params[39u];
    unsigned b125 = stwo_m31_sub(b124, b13);
    unsigned b126 = stwo_m31_sub(b125, b14);
    unsigned b127 = stwo_m31_sub(b126, b15);
    unsigned b128 = base_params[40u];
    unsigned b129 = stwo_m31_sub(b128, b127);
    unsigned b130 = stwo_m31_mul(b127, b129);
    StwoCudaQm31 e18 = StwoCudaQm31{ b130, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 18u)));
    unsigned b131 = base_params[41u];
    unsigned b132 = stwo_m31_sub(b131, b15);
    unsigned b133 = stwo_m31_sub(b132, b16);
    unsigned b134 = base_params[42u];
    unsigned b135 = stwo_m31_sub(b134, b133);
    unsigned b136 = stwo_m31_mul(b133, b135);
    StwoCudaQm31 e19 = StwoCudaQm31{ b136, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e19, stwo_load_qm31(random_coeff_powers, rc_base + 19u)));
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b137 = stwo_m31_mul(b3, b2);
    unsigned b138 = base_params[44u];
    unsigned b139 = stwo_m31_sub(b138, b3);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    unsigned b140 = stwo_m31_mul(b139, b1);
    unsigned b141 = stwo_m31_add(b137, b140);
    unsigned b142 = stwo_m31_sub(b18, b141);
    StwoCudaQm31 e20 = StwoCudaQm31{ b142, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e20, stwo_load_qm31(random_coeff_powers, rc_base + 20u)));
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    unsigned b143 = stwo_m31_mul(b4, b2);
    unsigned b144 = base_params[45u];
    unsigned b145 = stwo_m31_sub(b144, b4);
    unsigned b146 = stwo_m31_mul(b145, b1);
    unsigned b147 = stwo_m31_add(b143, b146);
    unsigned b148 = stwo_m31_sub(b19, b147);
    StwoCudaQm31 e21 = StwoCudaQm31{ b148, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e21, stwo_load_qm31(random_coeff_powers, rc_base + 21u)));
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    unsigned b149 = stwo_m31_add(b24, b25);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    unsigned b150 = stwo_m31_add(b149, b26);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 60u, row_index, 0);
    unsigned b151 = stwo_m31_add(b150, b27);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 61u, row_index, 0);
    unsigned b152 = stwo_m31_add(b151, b28);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 62u, row_index, 0);
    unsigned b153 = stwo_m31_add(b152, b29);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 63u, row_index, 0);
    unsigned b154 = stwo_m31_add(b153, b30);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 64u, row_index, 0);
    unsigned b155 = stwo_m31_add(b154, b31);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 65u, row_index, 0);
    unsigned b156 = stwo_m31_add(b155, b32);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 66u, row_index, 0);
    unsigned b157 = stwo_m31_add(b156, b33);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 67u, row_index, 0);
    unsigned b158 = stwo_m31_add(b157, b34);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 68u, row_index, 0);
    unsigned b159 = stwo_m31_add(b158, b35);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 69u, row_index, 0);
    unsigned b160 = stwo_m31_add(b159, b36);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 70u, row_index, 0);
    unsigned b161 = stwo_m31_add(b160, b37);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 71u, row_index, 0);
    unsigned b162 = stwo_m31_add(b161, b38);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 72u, row_index, 0);
    unsigned b163 = stwo_m31_add(b162, b39);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 73u, row_index, 0);
    unsigned b164 = stwo_m31_add(b163, b40);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 74u, row_index, 0);
    unsigned b165 = stwo_m31_add(b164, b41);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 75u, row_index, 0);
    unsigned b166 = stwo_m31_add(b165, b42);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 76u, row_index, 0);
    unsigned b167 = stwo_m31_add(b166, b43);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 77u, row_index, 0);
    unsigned b168 = stwo_m31_add(b167, b44);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 78u, row_index, 0);
    unsigned b169 = stwo_m31_add(b168, b45);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 79u, row_index, 0);
    unsigned b170 = stwo_m31_add(b169, b46);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 80u, row_index, 0);
    unsigned b171 = stwo_m31_add(b170, b47);
    unsigned b172 = stwo_m31_mul(b106, b171);
    StwoCudaQm31 e22 = StwoCudaQm31{ b172, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e22, stwo_load_qm31(random_coeff_powers, rc_base + 22u)));
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 81u, row_index, 0);
    unsigned b173 = base_params[46u];
    unsigned b174 = stwo_m31_sub(b173, b48);
    unsigned b175 = stwo_m31_mul(b48, b174);
    unsigned b176 = stwo_m31_mul(b175, b106);
    StwoCudaQm31 e23 = StwoCudaQm31{ b176, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e23, stwo_load_qm31(random_coeff_powers, rc_base + 23u)));
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    unsigned b177 = base_params[47u];
    unsigned b178 = stwo_m31_mul(b48, b177);
    unsigned b179 = stwo_m31_sub(b23, b178);
    unsigned b180 = base_params[48u];
    unsigned b181 = stwo_m31_sub(b180, b179);
    unsigned b182 = stwo_m31_mul(b179, b181);
    unsigned b183 = stwo_m31_mul(b182, b106);
    StwoCudaQm31 e24 = StwoCudaQm31{ b183, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e24, stwo_load_qm31(random_coeff_powers, rc_base + 24u)));
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 82u, row_index, 0);
    unsigned b193 = stwo_m31_mul(b6, b2);
    unsigned b194 = stwo_m31_mul(b7, b1);
    unsigned b195 = stwo_m31_add(b193, b194);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b196 = stwo_m31_mul(b5, b0);
    unsigned b197 = stwo_m31_add(b195, b196);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 54u, row_index, 0);
    unsigned b184 = base_params[49u];
    unsigned b185 = stwo_m31_mul(b21, b184);
    unsigned b186 = stwo_m31_add(b20, b185);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 55u, row_index, 0);
    unsigned b187 = base_params[50u];
    unsigned b188 = stwo_m31_mul(b22, b187);
    unsigned b189 = stwo_m31_add(b186, b188);
    unsigned b190 = base_params[51u];
    unsigned b191 = stwo_m31_mul(b23, b190);
    unsigned b192 = stwo_m31_add(b189, b191);
    unsigned b198 = stwo_m31_mul(b106, b192);
    unsigned b199 = stwo_m31_add(b197, b198);
    unsigned b200 = stwo_m31_sub(b49, b199);
    StwoCudaQm31 e25 = StwoCudaQm31{ b200, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e25, stwo_load_qm31(random_coeff_powers, rc_base + 25u)));
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 140u, row_index, 0);
    unsigned b201 = base_params[52u];
    unsigned b202 = stwo_m31_sub(b56, b201);
    unsigned b203 = stwo_m31_mul(b56, b202);
    StwoCudaQm31 e26 = StwoCudaQm31{ b203, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e26, stwo_load_qm31(random_coeff_powers, rc_base + 26u)));
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 86u, row_index, 0);
    unsigned b204 = stwo_m31_add(b22, b52);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 85u, row_index, 0);
    unsigned b205 = stwo_m31_add(b21, b51);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 84u, row_index, 0);
    unsigned b206 = stwo_m31_add(b20, b50);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 112u, row_index, 0);
    unsigned b207 = stwo_m31_sub(b206, b53);
    unsigned b208 = stwo_m31_sub(b207, b56);
    unsigned b209 = base_params[53u];
    unsigned b210 = stwo_m31_mul(b208, b209);
    unsigned b211 = stwo_m31_add(b205, b210);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 113u, row_index, 0);
    unsigned b212 = stwo_m31_sub(b211, b54);
    unsigned b213 = base_params[54u];
    unsigned b214 = stwo_m31_mul(b212, b213);
    unsigned b215 = stwo_m31_add(b204, b214);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 114u, row_index, 0);
    unsigned b216 = stwo_m31_sub(b215, b55);
    unsigned b217 = base_params[55u];
    unsigned b218 = stwo_m31_mul(b216, b217);
    unsigned b219 = stwo_m31_mul(b218, b218);
    unsigned b220 = base_params[56u];
    unsigned b221 = stwo_m31_sub(b219, b220);
    unsigned b222 = stwo_m31_mul(b218, b221);
    StwoCudaQm31 e27 = StwoCudaQm31{ b222, b60, b60, b60 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e27, stwo_load_qm31(random_coeff_powers, rc_base + 27u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
