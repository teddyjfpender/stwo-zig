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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_bee9b54ceab9ed05(
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
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 128u, row_index, 0);
    unsigned b87 = stwo_m31_mul(b0, b30);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 157u, row_index, 0);
    unsigned b88 = stwo_m31_mul(b1, b42);
    unsigned b89 = stwo_m31_add(b87, b88);
    unsigned b81 = base_params[35u];
    unsigned b82 = stwo_m31_sub(b81, b0);
    unsigned b83 = stwo_m31_sub(b82, b1);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b84 = stwo_m31_sub(b83, b2);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 100u, row_index, 0);
    unsigned b90 = stwo_m31_mul(b84, b18);
    unsigned b91 = stwo_m31_add(b89, b90);
    unsigned b85 = base_params[236u];
    unsigned b86 = stwo_m31_sub(b85, b2);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 213u, row_index, 0);
    unsigned b92 = stwo_m31_mul(b86, b68);
    unsigned b93 = stwo_m31_sub(b91, b92);
    unsigned b80 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b93, b80, b80, b80 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 129u, row_index, 0);
    unsigned b94 = stwo_m31_mul(b0, b31);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 158u, row_index, 0);
    unsigned b95 = stwo_m31_mul(b1, b43);
    unsigned b96 = stwo_m31_add(b94, b95);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 101u, row_index, 0);
    unsigned b97 = stwo_m31_mul(b84, b19);
    unsigned b98 = stwo_m31_add(b96, b97);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 214u, row_index, 0);
    unsigned b99 = stwo_m31_mul(b86, b69);
    unsigned b100 = stwo_m31_sub(b98, b99);
    StwoCudaQm31 e1 = StwoCudaQm31{ b100, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 130u, row_index, 0);
    unsigned b101 = stwo_m31_mul(b0, b32);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 159u, row_index, 0);
    unsigned b102 = stwo_m31_mul(b1, b44);
    unsigned b103 = stwo_m31_add(b101, b102);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 102u, row_index, 0);
    unsigned b104 = stwo_m31_mul(b84, b20);
    unsigned b105 = stwo_m31_add(b103, b104);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 215u, row_index, 0);
    unsigned b106 = stwo_m31_mul(b86, b70);
    unsigned b107 = stwo_m31_sub(b105, b106);
    StwoCudaQm31 e2 = StwoCudaQm31{ b107, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 131u, row_index, 0);
    unsigned b108 = stwo_m31_mul(b0, b33);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 160u, row_index, 0);
    unsigned b109 = stwo_m31_mul(b1, b45);
    unsigned b110 = stwo_m31_add(b108, b109);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 103u, row_index, 0);
    unsigned b111 = stwo_m31_mul(b84, b21);
    unsigned b112 = stwo_m31_add(b110, b111);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 216u, row_index, 0);
    unsigned b113 = stwo_m31_mul(b86, b71);
    unsigned b114 = stwo_m31_sub(b112, b113);
    StwoCudaQm31 e3 = StwoCudaQm31{ b114, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 132u, row_index, 0);
    unsigned b115 = stwo_m31_mul(b0, b34);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 161u, row_index, 0);
    unsigned b116 = stwo_m31_mul(b1, b46);
    unsigned b117 = stwo_m31_add(b115, b116);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 104u, row_index, 0);
    unsigned b118 = stwo_m31_mul(b84, b22);
    unsigned b119 = stwo_m31_add(b117, b118);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 217u, row_index, 0);
    unsigned b120 = stwo_m31_mul(b86, b72);
    unsigned b121 = stwo_m31_sub(b119, b120);
    StwoCudaQm31 e4 = StwoCudaQm31{ b121, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 133u, row_index, 0);
    unsigned b122 = stwo_m31_mul(b0, b35);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 162u, row_index, 0);
    unsigned b123 = stwo_m31_mul(b1, b47);
    unsigned b124 = stwo_m31_add(b122, b123);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 105u, row_index, 0);
    unsigned b125 = stwo_m31_mul(b84, b23);
    unsigned b126 = stwo_m31_add(b124, b125);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 218u, row_index, 0);
    unsigned b127 = stwo_m31_mul(b86, b73);
    unsigned b128 = stwo_m31_sub(b126, b127);
    StwoCudaQm31 e5 = StwoCudaQm31{ b128, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 134u, row_index, 0);
    unsigned b129 = stwo_m31_mul(b0, b36);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 163u, row_index, 0);
    unsigned b130 = stwo_m31_mul(b1, b48);
    unsigned b131 = stwo_m31_add(b129, b130);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 106u, row_index, 0);
    unsigned b132 = stwo_m31_mul(b84, b24);
    unsigned b133 = stwo_m31_add(b131, b132);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 219u, row_index, 0);
    unsigned b134 = stwo_m31_mul(b86, b74);
    unsigned b135 = stwo_m31_sub(b133, b134);
    StwoCudaQm31 e6 = StwoCudaQm31{ b135, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 135u, row_index, 0);
    unsigned b136 = stwo_m31_mul(b0, b37);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 164u, row_index, 0);
    unsigned b137 = stwo_m31_mul(b1, b49);
    unsigned b138 = stwo_m31_add(b136, b137);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 107u, row_index, 0);
    unsigned b139 = stwo_m31_mul(b84, b25);
    unsigned b140 = stwo_m31_add(b138, b139);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 220u, row_index, 0);
    unsigned b141 = stwo_m31_mul(b86, b75);
    unsigned b142 = stwo_m31_sub(b140, b141);
    StwoCudaQm31 e7 = StwoCudaQm31{ b142, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 136u, row_index, 0);
    unsigned b143 = stwo_m31_mul(b0, b38);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 165u, row_index, 0);
    unsigned b144 = stwo_m31_mul(b1, b50);
    unsigned b145 = stwo_m31_add(b143, b144);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 108u, row_index, 0);
    unsigned b146 = stwo_m31_mul(b84, b26);
    unsigned b147 = stwo_m31_add(b145, b146);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 221u, row_index, 0);
    unsigned b148 = stwo_m31_mul(b86, b76);
    unsigned b149 = stwo_m31_sub(b147, b148);
    StwoCudaQm31 e8 = StwoCudaQm31{ b149, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 137u, row_index, 0);
    unsigned b150 = stwo_m31_mul(b0, b39);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 166u, row_index, 0);
    unsigned b151 = stwo_m31_mul(b1, b51);
    unsigned b152 = stwo_m31_add(b150, b151);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 109u, row_index, 0);
    unsigned b153 = stwo_m31_mul(b84, b27);
    unsigned b154 = stwo_m31_add(b152, b153);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 222u, row_index, 0);
    unsigned b155 = stwo_m31_mul(b86, b77);
    unsigned b156 = stwo_m31_sub(b154, b155);
    StwoCudaQm31 e9 = StwoCudaQm31{ b156, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 138u, row_index, 0);
    unsigned b157 = stwo_m31_mul(b0, b40);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 167u, row_index, 0);
    unsigned b158 = stwo_m31_mul(b1, b52);
    unsigned b159 = stwo_m31_add(b157, b158);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 110u, row_index, 0);
    unsigned b160 = stwo_m31_mul(b84, b28);
    unsigned b161 = stwo_m31_add(b159, b160);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 223u, row_index, 0);
    unsigned b162 = stwo_m31_mul(b86, b78);
    unsigned b163 = stwo_m31_sub(b161, b162);
    StwoCudaQm31 e10 = StwoCudaQm31{ b163, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 139u, row_index, 0);
    unsigned b164 = stwo_m31_mul(b0, b41);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 168u, row_index, 0);
    unsigned b165 = stwo_m31_mul(b1, b53);
    unsigned b166 = stwo_m31_add(b164, b165);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 111u, row_index, 0);
    unsigned b167 = stwo_m31_mul(b84, b29);
    unsigned b168 = stwo_m31_add(b166, b167);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 224u, row_index, 0);
    unsigned b169 = stwo_m31_mul(b86, b79);
    unsigned b170 = stwo_m31_sub(b168, b169);
    StwoCudaQm31 e11 = StwoCudaQm31{ b170, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 197u, row_index, 0);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    unsigned b171 = stwo_m31_sub(b54, b4);
    unsigned b172 = stwo_m31_mul(b3, b171);
    StwoCudaQm31 e12 = StwoCudaQm31{ b172, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 198u, row_index, 0);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    unsigned b173 = stwo_m31_sub(b55, b5);
    unsigned b174 = stwo_m31_mul(b3, b173);
    StwoCudaQm31 e13 = StwoCudaQm31{ b174, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 199u, row_index, 0);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    unsigned b175 = stwo_m31_sub(b56, b6);
    unsigned b176 = stwo_m31_mul(b3, b175);
    StwoCudaQm31 e14 = StwoCudaQm31{ b176, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 200u, row_index, 0);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    unsigned b177 = stwo_m31_sub(b57, b7);
    unsigned b178 = stwo_m31_mul(b3, b177);
    StwoCudaQm31 e15 = StwoCudaQm31{ b178, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 15u)));
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 201u, row_index, 0);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    unsigned b179 = stwo_m31_sub(b58, b8);
    unsigned b180 = stwo_m31_mul(b3, b179);
    StwoCudaQm31 e16 = StwoCudaQm31{ b180, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 16u)));
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 202u, row_index, 0);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    unsigned b181 = stwo_m31_sub(b59, b9);
    unsigned b182 = stwo_m31_mul(b3, b181);
    StwoCudaQm31 e17 = StwoCudaQm31{ b182, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 17u)));
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 203u, row_index, 0);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    unsigned b183 = stwo_m31_sub(b60, b10);
    unsigned b184 = stwo_m31_mul(b3, b183);
    StwoCudaQm31 e18 = StwoCudaQm31{ b184, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 18u)));
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 204u, row_index, 0);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    unsigned b185 = stwo_m31_sub(b61, b11);
    unsigned b186 = stwo_m31_mul(b3, b185);
    StwoCudaQm31 e19 = StwoCudaQm31{ b186, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e19, stwo_load_qm31(random_coeff_powers, rc_base + 19u)));
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 205u, row_index, 0);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    unsigned b187 = stwo_m31_sub(b62, b12);
    unsigned b188 = stwo_m31_mul(b3, b187);
    StwoCudaQm31 e20 = StwoCudaQm31{ b188, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e20, stwo_load_qm31(random_coeff_powers, rc_base + 20u)));
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 206u, row_index, 0);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    unsigned b189 = stwo_m31_sub(b63, b13);
    unsigned b190 = stwo_m31_mul(b3, b189);
    StwoCudaQm31 e21 = StwoCudaQm31{ b190, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e21, stwo_load_qm31(random_coeff_powers, rc_base + 21u)));
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 207u, row_index, 0);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    unsigned b191 = stwo_m31_sub(b64, b14);
    unsigned b192 = stwo_m31_mul(b3, b191);
    StwoCudaQm31 e22 = StwoCudaQm31{ b192, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e22, stwo_load_qm31(random_coeff_powers, rc_base + 22u)));
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 208u, row_index, 0);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    unsigned b193 = stwo_m31_sub(b65, b15);
    unsigned b194 = stwo_m31_mul(b3, b193);
    StwoCudaQm31 e23 = StwoCudaQm31{ b194, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e23, stwo_load_qm31(random_coeff_powers, rc_base + 23u)));
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 209u, row_index, 0);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    unsigned b195 = stwo_m31_sub(b66, b16);
    unsigned b196 = stwo_m31_mul(b3, b195);
    StwoCudaQm31 e24 = StwoCudaQm31{ b196, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e24, stwo_load_qm31(random_coeff_powers, rc_base + 24u)));
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 210u, row_index, 0);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    unsigned b197 = stwo_m31_sub(b67, b17);
    unsigned b198 = stwo_m31_mul(b3, b197);
    StwoCudaQm31 e25 = StwoCudaQm31{ b198, b80, b80, b80 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e25, stwo_load_qm31(random_coeff_powers, rc_base + 25u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
