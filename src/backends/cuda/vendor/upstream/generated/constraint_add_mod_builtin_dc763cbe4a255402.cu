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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_e7b092da31b76065(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 0u);
    unsigned b104 = base_params[4u];
    unsigned b102 = base_params[3u];
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 0u, 0u, row_index, 0);
    unsigned b103 = stwo_m31_mul(b102, b0);
    unsigned b105 = stwo_m31_add(b104, b103);
    unsigned b101 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b105, b101, b101, b101 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 1u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 2u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e2 = StwoCudaQm31{ b1, b101, b101, b101 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 3u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 4u);
    e2 = StwoCudaQm31{ b1, b101, b101, b101 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 5u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 6u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    e1 = StwoCudaQm31{ b2, b101, b101, b101 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 7u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e3 = StwoCudaQm31{ b3, b101, b101, b101 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 8u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e1 = StwoCudaQm31{ b4, b101, b101, b101 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 9u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e3 = StwoCudaQm31{ b5, b101, b101, b101 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 10u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    e1 = StwoCudaQm31{ b6, b101, b101, b101 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 11u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    e3 = StwoCudaQm31{ b7, b101, b101, b101 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 12u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    e1 = StwoCudaQm31{ b8, b101, b101, b101 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 13u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    e3 = StwoCudaQm31{ b9, b101, b101, b101 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 14u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    e1 = StwoCudaQm31{ b10, b101, b101, b101 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 15u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    e3 = StwoCudaQm31{ b11, b101, b101, b101 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(ext_params, 16u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    e1 = StwoCudaQm31{ b12, b101, b101, b101 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 17u);
    e3 = stwo_qm31_sub(e1, e4);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 261u, row_index, 0);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 260u, row_index, 0);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 135u, row_index, 0);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 183u, row_index, 0);
    unsigned b106 = stwo_m31_add(b33, b53);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 231u, row_index, 0);
    unsigned b107 = stwo_m31_sub(b106, b73);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 252u, row_index, 0);
    unsigned b108 = stwo_m31_mul(b13, b93);
    unsigned b109 = stwo_m31_sub(b107, b108);
    unsigned b110 = stwo_m31_add(b94, b109);
    unsigned b115 = base_params[152u];
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 136u, row_index, 0);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 184u, row_index, 0);
    unsigned b111 = stwo_m31_add(b34, b54);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 232u, row_index, 0);
    unsigned b112 = stwo_m31_sub(b111, b74);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    unsigned b113 = stwo_m31_mul(b14, b93);
    unsigned b114 = stwo_m31_sub(b112, b113);
    unsigned b116 = stwo_m31_mul(b115, b114);
    unsigned b117 = stwo_m31_add(b110, b116);
    unsigned b122 = base_params[153u];
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 137u, row_index, 0);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 185u, row_index, 0);
    unsigned b118 = stwo_m31_add(b35, b55);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 233u, row_index, 0);
    unsigned b119 = stwo_m31_sub(b118, b75);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    unsigned b120 = stwo_m31_mul(b15, b93);
    unsigned b121 = stwo_m31_sub(b119, b120);
    unsigned b123 = stwo_m31_mul(b122, b121);
    unsigned b124 = stwo_m31_add(b117, b123);
    unsigned b125 = base_params[154u];
    unsigned b126 = stwo_m31_mul(b124, b125);
    unsigned b127 = stwo_m31_sub(b95, b126);
    e4 = StwoCudaQm31{ b127, b101, b101, b101 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b128 = stwo_m31_mul(b95, b95);
    unsigned b129 = base_params[155u];
    unsigned b130 = stwo_m31_sub(b128, b129);
    unsigned b131 = stwo_m31_mul(b95, b130);
    e1 = StwoCudaQm31{ b131, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 262u, row_index, 0);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 138u, row_index, 0);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 186u, row_index, 0);
    unsigned b132 = stwo_m31_add(b36, b56);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 234u, row_index, 0);
    unsigned b133 = stwo_m31_sub(b132, b76);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    unsigned b134 = stwo_m31_mul(b16, b93);
    unsigned b135 = stwo_m31_sub(b133, b134);
    unsigned b136 = stwo_m31_add(b95, b135);
    unsigned b141 = base_params[156u];
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 139u, row_index, 0);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 187u, row_index, 0);
    unsigned b137 = stwo_m31_add(b37, b57);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 235u, row_index, 0);
    unsigned b138 = stwo_m31_sub(b137, b77);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    unsigned b139 = stwo_m31_mul(b17, b93);
    unsigned b140 = stwo_m31_sub(b138, b139);
    unsigned b142 = stwo_m31_mul(b141, b140);
    unsigned b143 = stwo_m31_add(b136, b142);
    unsigned b148 = base_params[157u];
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 140u, row_index, 0);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 188u, row_index, 0);
    unsigned b144 = stwo_m31_add(b38, b58);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 236u, row_index, 0);
    unsigned b145 = stwo_m31_sub(b144, b78);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    unsigned b146 = stwo_m31_mul(b18, b93);
    unsigned b147 = stwo_m31_sub(b145, b146);
    unsigned b149 = stwo_m31_mul(b148, b147);
    unsigned b150 = stwo_m31_add(b143, b149);
    unsigned b151 = base_params[158u];
    unsigned b152 = stwo_m31_mul(b150, b151);
    unsigned b153 = stwo_m31_sub(b96, b152);
    e2 = StwoCudaQm31{ b153, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b154 = stwo_m31_mul(b96, b96);
    unsigned b155 = base_params[159u];
    unsigned b156 = stwo_m31_sub(b154, b155);
    unsigned b157 = stwo_m31_mul(b96, b156);
    StwoCudaQm31 e5 = StwoCudaQm31{ b157, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 263u, row_index, 0);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 141u, row_index, 0);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 189u, row_index, 0);
    unsigned b158 = stwo_m31_add(b39, b59);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 237u, row_index, 0);
    unsigned b159 = stwo_m31_sub(b158, b79);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    unsigned b160 = stwo_m31_mul(b19, b93);
    unsigned b161 = stwo_m31_sub(b159, b160);
    unsigned b162 = stwo_m31_add(b96, b161);
    unsigned b167 = base_params[160u];
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 142u, row_index, 0);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 190u, row_index, 0);
    unsigned b163 = stwo_m31_add(b40, b60);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 238u, row_index, 0);
    unsigned b164 = stwo_m31_sub(b163, b80);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    unsigned b165 = stwo_m31_mul(b20, b93);
    unsigned b166 = stwo_m31_sub(b164, b165);
    unsigned b168 = stwo_m31_mul(b167, b166);
    unsigned b169 = stwo_m31_add(b162, b168);
    unsigned b174 = base_params[161u];
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 143u, row_index, 0);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 191u, row_index, 0);
    unsigned b170 = stwo_m31_add(b41, b61);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 239u, row_index, 0);
    unsigned b171 = stwo_m31_sub(b170, b81);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    unsigned b172 = stwo_m31_mul(b21, b93);
    unsigned b173 = stwo_m31_sub(b171, b172);
    unsigned b175 = stwo_m31_mul(b174, b173);
    unsigned b176 = stwo_m31_add(b169, b175);
    unsigned b177 = base_params[162u];
    unsigned b178 = stwo_m31_mul(b176, b177);
    unsigned b179 = stwo_m31_sub(b97, b178);
    StwoCudaQm31 e6 = StwoCudaQm31{ b179, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b180 = stwo_m31_mul(b97, b97);
    unsigned b181 = base_params[163u];
    unsigned b182 = stwo_m31_sub(b180, b181);
    unsigned b183 = stwo_m31_mul(b97, b182);
    StwoCudaQm31 e7 = StwoCudaQm31{ b183, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 264u, row_index, 0);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 145u, row_index, 0);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 193u, row_index, 0);
    unsigned b184 = stwo_m31_add(b42, b62);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 241u, row_index, 0);
    unsigned b185 = stwo_m31_sub(b184, b82);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    unsigned b186 = stwo_m31_mul(b22, b93);
    unsigned b187 = stwo_m31_sub(b185, b186);
    unsigned b188 = stwo_m31_add(b97, b187);
    unsigned b193 = base_params[164u];
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 146u, row_index, 0);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 194u, row_index, 0);
    unsigned b189 = stwo_m31_add(b43, b63);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 242u, row_index, 0);
    unsigned b190 = stwo_m31_sub(b189, b83);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    unsigned b191 = stwo_m31_mul(b23, b93);
    unsigned b192 = stwo_m31_sub(b190, b191);
    unsigned b194 = stwo_m31_mul(b193, b192);
    unsigned b195 = stwo_m31_add(b188, b194);
    unsigned b200 = base_params[165u];
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 147u, row_index, 0);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 195u, row_index, 0);
    unsigned b196 = stwo_m31_add(b44, b64);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 243u, row_index, 0);
    unsigned b197 = stwo_m31_sub(b196, b84);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    unsigned b198 = stwo_m31_mul(b24, b93);
    unsigned b199 = stwo_m31_sub(b197, b198);
    unsigned b201 = stwo_m31_mul(b200, b199);
    unsigned b202 = stwo_m31_add(b195, b201);
    unsigned b203 = base_params[166u];
    unsigned b204 = stwo_m31_mul(b202, b203);
    unsigned b205 = stwo_m31_sub(b98, b204);
    StwoCudaQm31 e8 = StwoCudaQm31{ b205, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b206 = stwo_m31_mul(b98, b98);
    unsigned b207 = base_params[167u];
    unsigned b208 = stwo_m31_sub(b206, b207);
    unsigned b209 = stwo_m31_mul(b98, b208);
    StwoCudaQm31 e9 = StwoCudaQm31{ b209, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 265u, row_index, 0);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 148u, row_index, 0);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 196u, row_index, 0);
    unsigned b210 = stwo_m31_add(b45, b65);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 244u, row_index, 0);
    unsigned b211 = stwo_m31_sub(b210, b85);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 41u, row_index, 0);
    unsigned b212 = stwo_m31_mul(b25, b93);
    unsigned b213 = stwo_m31_sub(b211, b212);
    unsigned b214 = stwo_m31_add(b98, b213);
    unsigned b219 = base_params[168u];
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 149u, row_index, 0);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 197u, row_index, 0);
    unsigned b215 = stwo_m31_add(b46, b66);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 245u, row_index, 0);
    unsigned b216 = stwo_m31_sub(b215, b86);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    unsigned b217 = stwo_m31_mul(b26, b93);
    unsigned b218 = stwo_m31_sub(b216, b217);
    unsigned b220 = stwo_m31_mul(b219, b218);
    unsigned b221 = stwo_m31_add(b214, b220);
    unsigned b226 = base_params[169u];
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 150u, row_index, 0);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 198u, row_index, 0);
    unsigned b222 = stwo_m31_add(b47, b67);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 246u, row_index, 0);
    unsigned b223 = stwo_m31_sub(b222, b87);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    unsigned b224 = stwo_m31_mul(b27, b93);
    unsigned b225 = stwo_m31_sub(b223, b224);
    unsigned b227 = stwo_m31_mul(b226, b225);
    unsigned b228 = stwo_m31_add(b221, b227);
    unsigned b229 = base_params[170u];
    unsigned b230 = stwo_m31_mul(b228, b229);
    unsigned b231 = stwo_m31_sub(b99, b230);
    StwoCudaQm31 e10 = StwoCudaQm31{ b231, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b232 = stwo_m31_mul(b99, b99);
    unsigned b233 = base_params[171u];
    unsigned b234 = stwo_m31_sub(b232, b233);
    unsigned b235 = stwo_m31_mul(b99, b234);
    StwoCudaQm31 e11 = StwoCudaQm31{ b235, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 266u, row_index, 0);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 151u, row_index, 0);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 199u, row_index, 0);
    unsigned b236 = stwo_m31_add(b48, b68);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 247u, row_index, 0);
    unsigned b237 = stwo_m31_sub(b236, b88);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    unsigned b238 = stwo_m31_mul(b28, b93);
    unsigned b239 = stwo_m31_sub(b237, b238);
    unsigned b240 = stwo_m31_add(b99, b239);
    unsigned b245 = base_params[172u];
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 152u, row_index, 0);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 200u, row_index, 0);
    unsigned b241 = stwo_m31_add(b49, b69);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 248u, row_index, 0);
    unsigned b242 = stwo_m31_sub(b241, b89);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    unsigned b243 = stwo_m31_mul(b29, b93);
    unsigned b244 = stwo_m31_sub(b242, b243);
    unsigned b246 = stwo_m31_mul(b245, b244);
    unsigned b247 = stwo_m31_add(b240, b246);
    unsigned b252 = base_params[173u];
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 153u, row_index, 0);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 201u, row_index, 0);
    unsigned b248 = stwo_m31_add(b50, b70);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 249u, row_index, 0);
    unsigned b249 = stwo_m31_sub(b248, b90);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    unsigned b250 = stwo_m31_mul(b30, b93);
    unsigned b251 = stwo_m31_sub(b249, b250);
    unsigned b253 = stwo_m31_mul(b252, b251);
    unsigned b254 = stwo_m31_add(b247, b253);
    unsigned b255 = base_params[174u];
    unsigned b256 = stwo_m31_mul(b254, b255);
    unsigned b257 = stwo_m31_sub(b100, b256);
    StwoCudaQm31 e12 = StwoCudaQm31{ b257, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b258 = stwo_m31_mul(b100, b100);
    unsigned b259 = base_params[175u];
    unsigned b260 = stwo_m31_sub(b258, b259);
    unsigned b261 = stwo_m31_mul(b100, b260);
    StwoCudaQm31 e13 = StwoCudaQm31{ b261, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 154u, row_index, 0);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 202u, row_index, 0);
    unsigned b262 = stwo_m31_add(b51, b71);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 250u, row_index, 0);
    unsigned b263 = stwo_m31_sub(b262, b91);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    unsigned b264 = stwo_m31_mul(b31, b93);
    unsigned b265 = stwo_m31_sub(b263, b264);
    unsigned b266 = stwo_m31_add(b100, b265);
    unsigned b271 = base_params[176u];
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 155u, row_index, 0);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 203u, row_index, 0);
    unsigned b267 = stwo_m31_add(b52, b72);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 251u, row_index, 0);
    unsigned b268 = stwo_m31_sub(b267, b92);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    unsigned b269 = stwo_m31_mul(b32, b93);
    unsigned b270 = stwo_m31_sub(b268, b269);
    unsigned b272 = stwo_m31_mul(b271, b270);
    unsigned b273 = stwo_m31_add(b266, b272);
    StwoCudaQm31 e14 = StwoCudaQm31{ b273, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    StwoCudaQm31 e15 = stwo_load_qm31(ext_params, 468u);
    StwoCudaQm31 e16 = stwo_qm31_mul(e3, e15);
    e15 = stwo_load_qm31(ext_params, 469u);
    StwoCudaQm31 e17 = stwo_qm31_mul(e0, e15);
    e15 = stwo_qm31_add(e16, e17);
    e17 = stwo_qm31_mul(e0, e3);
    unsigned b274 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b275 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b276 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b277 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e3 = StwoCudaQm31{ b274, b275, b276, b277 };
    e0 = stwo_qm31_mul(e3, e17);
    e3 = stwo_qm31_sub(e0, e15);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
