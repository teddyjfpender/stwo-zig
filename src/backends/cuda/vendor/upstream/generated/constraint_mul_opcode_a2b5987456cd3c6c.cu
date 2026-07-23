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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_b8a38f5bde084db6(
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
    unsigned b84 = base_params[0u];
    unsigned b85 = stwo_m31_sub(b84, b4);
    unsigned b86 = stwo_m31_mul(b4, b85);
    unsigned b87 = base_params[1u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b86, b87, b87, b87 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    unsigned b88 = base_params[2u];
    unsigned b89 = stwo_m31_sub(b88, b5);
    unsigned b90 = stwo_m31_mul(b5, b89);
    StwoCudaQm31 e1 = StwoCudaQm31{ b90, b87, b87, b87 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    unsigned b91 = base_params[3u];
    unsigned b92 = stwo_m31_sub(b91, b6);
    unsigned b93 = stwo_m31_mul(b6, b92);
    StwoCudaQm31 e2 = StwoCudaQm31{ b93, b87, b87, b87 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    unsigned b94 = base_params[4u];
    unsigned b95 = stwo_m31_sub(b94, b7);
    unsigned b96 = stwo_m31_mul(b7, b95);
    StwoCudaQm31 e3 = StwoCudaQm31{ b96, b87, b87, b87 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b97 = base_params[5u];
    unsigned b98 = stwo_m31_sub(b97, b6);
    unsigned b99 = stwo_m31_sub(b98, b7);
    unsigned b100 = base_params[6u];
    unsigned b101 = stwo_m31_sub(b100, b99);
    unsigned b102 = stwo_m31_mul(b99, b101);
    StwoCudaQm31 e4 = StwoCudaQm31{ b102, b87, b87, b87 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    unsigned b103 = base_params[7u];
    unsigned b104 = stwo_m31_sub(b103, b8);
    unsigned b105 = stwo_m31_mul(b8, b104);
    StwoCudaQm31 e5 = StwoCudaQm31{ b105, b87, b87, b87 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b108 = base_params[19u];
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    unsigned b106 = base_params[18u];
    unsigned b107 = stwo_m31_sub(b3, b106);
    unsigned b109 = stwo_m31_sub(b108, b107);
    unsigned b110 = stwo_m31_mul(b6, b109);
    StwoCudaQm31 e6 = StwoCudaQm31{ b110, b87, b87, b87 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    unsigned b111 = stwo_m31_mul(b4, b2);
    unsigned b112 = base_params[20u];
    unsigned b113 = stwo_m31_sub(b112, b4);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    unsigned b114 = stwo_m31_mul(b113, b1);
    unsigned b115 = stwo_m31_add(b111, b114);
    unsigned b116 = stwo_m31_sub(b9, b115);
    StwoCudaQm31 e7 = StwoCudaQm31{ b116, b87, b87, b87 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    unsigned b117 = stwo_m31_mul(b5, b2);
    unsigned b118 = base_params[21u];
    unsigned b119 = stwo_m31_sub(b118, b5);
    unsigned b120 = stwo_m31_mul(b119, b1);
    unsigned b121 = stwo_m31_add(b117, b120);
    unsigned b122 = stwo_m31_sub(b10, b121);
    StwoCudaQm31 e8 = StwoCudaQm31{ b122, b87, b87, b87 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    unsigned b123 = stwo_m31_mul(b6, b0);
    unsigned b124 = stwo_m31_mul(b7, b2);
    unsigned b125 = stwo_m31_add(b123, b124);
    unsigned b126 = stwo_m31_mul(b99, b1);
    unsigned b127 = stwo_m31_add(b125, b126);
    unsigned b128 = stwo_m31_sub(b11, b127);
    StwoCudaQm31 e9 = StwoCudaQm31{ b128, b87, b87, b87 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 102u, row_index, 0);
    unsigned b697 = base_params[111u];
    unsigned b698 = stwo_m31_mul(b79, b697);
    unsigned b653 = base_params[22u];
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 73u, row_index, 0);
    unsigned b129 = stwo_m31_mul(b22, b50);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    unsigned b643 = stwo_m31_sub(b129, b12);
    unsigned b654 = stwo_m31_mul(b653, b643);
    unsigned b655 = base_params[23u];
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 86u, row_index, 0);
    unsigned b214 = stwo_m31_mul(b30, b63);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 85u, row_index, 0);
    unsigned b215 = stwo_m31_mul(b31, b62);
    unsigned b216 = stwo_m31_add(b214, b215);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 54u, row_index, 0);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 84u, row_index, 0);
    unsigned b217 = stwo_m31_mul(b32, b61);
    unsigned b218 = stwo_m31_add(b216, b217);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 55u, row_index, 0);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 83u, row_index, 0);
    unsigned b219 = stwo_m31_mul(b33, b60);
    unsigned b220 = stwo_m31_add(b218, b219);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 82u, row_index, 0);
    unsigned b221 = stwo_m31_mul(b34, b59);
    unsigned b222 = stwo_m31_add(b220, b221);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 81u, row_index, 0);
    unsigned b223 = stwo_m31_mul(b35, b58);
    unsigned b224 = stwo_m31_add(b222, b223);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    unsigned b470 = stwo_m31_add(b23, b37);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 79u, row_index, 0);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 93u, row_index, 0);
    unsigned b487 = stwo_m31_add(b56, b70);
    unsigned b518 = stwo_m31_mul(b470, b487);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 60u, row_index, 0);
    unsigned b471 = stwo_m31_add(b24, b38);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 78u, row_index, 0);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 92u, row_index, 0);
    unsigned b486 = stwo_m31_add(b55, b69);
    unsigned b519 = stwo_m31_mul(b471, b486);
    unsigned b520 = stwo_m31_add(b518, b519);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 61u, row_index, 0);
    unsigned b472 = stwo_m31_add(b25, b39);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 77u, row_index, 0);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 91u, row_index, 0);
    unsigned b485 = stwo_m31_add(b54, b68);
    unsigned b521 = stwo_m31_mul(b472, b485);
    unsigned b522 = stwo_m31_add(b520, b521);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 62u, row_index, 0);
    unsigned b473 = stwo_m31_add(b26, b40);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 76u, row_index, 0);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 90u, row_index, 0);
    unsigned b484 = stwo_m31_add(b53, b67);
    unsigned b523 = stwo_m31_mul(b473, b484);
    unsigned b524 = stwo_m31_add(b522, b523);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 63u, row_index, 0);
    unsigned b474 = stwo_m31_add(b27, b41);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 75u, row_index, 0);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 89u, row_index, 0);
    unsigned b483 = stwo_m31_add(b52, b66);
    unsigned b525 = stwo_m31_mul(b474, b483);
    unsigned b526 = stwo_m31_add(b524, b525);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 64u, row_index, 0);
    unsigned b475 = stwo_m31_add(b28, b42);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 74u, row_index, 0);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 88u, row_index, 0);
    unsigned b482 = stwo_m31_add(b51, b65);
    unsigned b527 = stwo_m31_mul(b475, b482);
    unsigned b528 = stwo_m31_add(b526, b527);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    unsigned b469 = stwo_m31_add(b22, b36);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 65u, row_index, 0);
    unsigned b476 = stwo_m31_add(b29, b43);
    unsigned b578 = stwo_m31_add(b469, b476);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 87u, row_index, 0);
    unsigned b481 = stwo_m31_add(b50, b64);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 80u, row_index, 0);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 94u, row_index, 0);
    unsigned b488 = stwo_m31_add(b57, b71);
    unsigned b583 = stwo_m31_add(b481, b488);
    unsigned b588 = stwo_m31_mul(b578, b583);
    unsigned b493 = stwo_m31_mul(b469, b481);
    unsigned b589 = stwo_m31_sub(b588, b493);
    unsigned b553 = stwo_m31_mul(b476, b488);
    unsigned b590 = stwo_m31_sub(b589, b553);
    unsigned b591 = stwo_m31_add(b528, b590);
    unsigned b154 = stwo_m31_mul(b23, b56);
    unsigned b155 = stwo_m31_mul(b24, b55);
    unsigned b156 = stwo_m31_add(b154, b155);
    unsigned b157 = stwo_m31_mul(b25, b54);
    unsigned b158 = stwo_m31_add(b156, b157);
    unsigned b159 = stwo_m31_mul(b26, b53);
    unsigned b160 = stwo_m31_add(b158, b159);
    unsigned b161 = stwo_m31_mul(b27, b52);
    unsigned b162 = stwo_m31_add(b160, b161);
    unsigned b163 = stwo_m31_mul(b28, b51);
    unsigned b164 = stwo_m31_add(b162, b163);
    unsigned b249 = stwo_m31_add(b22, b29);
    unsigned b254 = stwo_m31_add(b50, b57);
    unsigned b259 = stwo_m31_mul(b249, b254);
    unsigned b260 = stwo_m31_sub(b259, b129);
    unsigned b189 = stwo_m31_mul(b29, b57);
    unsigned b261 = stwo_m31_sub(b260, b189);
    unsigned b262 = stwo_m31_add(b164, b261);
    unsigned b628 = stwo_m31_sub(b591, b262);
    unsigned b324 = stwo_m31_mul(b37, b70);
    unsigned b325 = stwo_m31_mul(b38, b69);
    unsigned b326 = stwo_m31_add(b324, b325);
    unsigned b327 = stwo_m31_mul(b39, b68);
    unsigned b328 = stwo_m31_add(b326, b327);
    unsigned b329 = stwo_m31_mul(b40, b67);
    unsigned b330 = stwo_m31_add(b328, b329);
    unsigned b331 = stwo_m31_mul(b41, b66);
    unsigned b332 = stwo_m31_add(b330, b331);
    unsigned b333 = stwo_m31_mul(b42, b65);
    unsigned b334 = stwo_m31_add(b332, b333);
    unsigned b419 = stwo_m31_add(b36, b43);
    unsigned b424 = stwo_m31_add(b64, b71);
    unsigned b429 = stwo_m31_mul(b419, b424);
    unsigned b299 = stwo_m31_mul(b36, b64);
    unsigned b430 = stwo_m31_sub(b429, b299);
    unsigned b359 = stwo_m31_mul(b43, b71);
    unsigned b431 = stwo_m31_sub(b430, b359);
    unsigned b432 = stwo_m31_add(b334, b431);
    unsigned b629 = stwo_m31_sub(b628, b432);
    unsigned b630 = stwo_m31_add(b224, b629);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    unsigned b648 = stwo_m31_sub(b630, b17);
    unsigned b656 = stwo_m31_mul(b655, b648);
    unsigned b657 = stwo_m31_sub(b654, b656);
    unsigned b658 = base_params[24u];
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 66u, row_index, 0);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 100u, row_index, 0);
    unsigned b384 = stwo_m31_mul(b44, b77);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 67u, row_index, 0);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 99u, row_index, 0);
    unsigned b385 = stwo_m31_mul(b45, b76);
    unsigned b386 = stwo_m31_add(b384, b385);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 68u, row_index, 0);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 98u, row_index, 0);
    unsigned b387 = stwo_m31_mul(b46, b75);
    unsigned b388 = stwo_m31_add(b386, b387);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 69u, row_index, 0);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 97u, row_index, 0);
    unsigned b389 = stwo_m31_mul(b47, b74);
    unsigned b390 = stwo_m31_add(b388, b389);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 70u, row_index, 0);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 96u, row_index, 0);
    unsigned b391 = stwo_m31_mul(b48, b73);
    unsigned b392 = stwo_m31_add(b390, b391);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 71u, row_index, 0);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 95u, row_index, 0);
    unsigned b393 = stwo_m31_mul(b49, b72);
    unsigned b394 = stwo_m31_add(b392, b393);
    unsigned b659 = stwo_m31_mul(b658, b394);
    unsigned b660 = stwo_m31_add(b657, b659);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 101u, row_index, 0);
    unsigned b699 = stwo_m31_sub(b660, b78);
    unsigned b700 = stwo_m31_sub(b698, b699);
    StwoCudaQm31 e10 = StwoCudaQm31{ b700, b87, b87, b87 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 103u, row_index, 0);
    unsigned b701 = base_params[113u];
    unsigned b702 = stwo_m31_mul(b80, b701);
    unsigned b661 = base_params[25u];
    unsigned b130 = stwo_m31_mul(b22, b51);
    unsigned b131 = stwo_m31_mul(b23, b50);
    unsigned b132 = stwo_m31_add(b130, b131);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    unsigned b644 = stwo_m31_sub(b132, b13);
    unsigned b662 = stwo_m31_mul(b661, b644);
    unsigned b663 = stwo_m31_add(b643, b662);
    unsigned b664 = base_params[26u];
    unsigned b225 = stwo_m31_mul(b31, b63);
    unsigned b226 = stwo_m31_mul(b32, b62);
    unsigned b227 = stwo_m31_add(b225, b226);
    unsigned b228 = stwo_m31_mul(b33, b61);
    unsigned b229 = stwo_m31_add(b227, b228);
    unsigned b230 = stwo_m31_mul(b34, b60);
    unsigned b231 = stwo_m31_add(b229, b230);
    unsigned b232 = stwo_m31_mul(b35, b59);
    unsigned b233 = stwo_m31_add(b231, b232);
    unsigned b529 = stwo_m31_mul(b471, b487);
    unsigned b530 = stwo_m31_mul(b472, b486);
    unsigned b531 = stwo_m31_add(b529, b530);
    unsigned b532 = stwo_m31_mul(b473, b485);
    unsigned b533 = stwo_m31_add(b531, b532);
    unsigned b534 = stwo_m31_mul(b474, b484);
    unsigned b535 = stwo_m31_add(b533, b534);
    unsigned b536 = stwo_m31_mul(b475, b483);
    unsigned b537 = stwo_m31_add(b535, b536);
    unsigned b489 = stwo_m31_add(b58, b72);
    unsigned b584 = stwo_m31_add(b482, b489);
    unsigned b592 = stwo_m31_mul(b578, b584);
    unsigned b477 = stwo_m31_add(b30, b44);
    unsigned b579 = stwo_m31_add(b470, b477);
    unsigned b593 = stwo_m31_mul(b579, b583);
    unsigned b594 = stwo_m31_add(b592, b593);
    unsigned b494 = stwo_m31_mul(b469, b482);
    unsigned b495 = stwo_m31_mul(b470, b481);
    unsigned b496 = stwo_m31_add(b494, b495);
    unsigned b595 = stwo_m31_sub(b594, b496);
    unsigned b554 = stwo_m31_mul(b476, b489);
    unsigned b555 = stwo_m31_mul(b477, b488);
    unsigned b556 = stwo_m31_add(b554, b555);
    unsigned b596 = stwo_m31_sub(b595, b556);
    unsigned b597 = stwo_m31_add(b537, b596);
    unsigned b165 = stwo_m31_mul(b24, b56);
    unsigned b166 = stwo_m31_mul(b25, b55);
    unsigned b167 = stwo_m31_add(b165, b166);
    unsigned b168 = stwo_m31_mul(b26, b54);
    unsigned b169 = stwo_m31_add(b167, b168);
    unsigned b170 = stwo_m31_mul(b27, b53);
    unsigned b171 = stwo_m31_add(b169, b170);
    unsigned b172 = stwo_m31_mul(b28, b52);
    unsigned b173 = stwo_m31_add(b171, b172);
    unsigned b255 = stwo_m31_add(b51, b58);
    unsigned b263 = stwo_m31_mul(b249, b255);
    unsigned b250 = stwo_m31_add(b23, b30);
    unsigned b264 = stwo_m31_mul(b250, b254);
    unsigned b265 = stwo_m31_add(b263, b264);
    unsigned b266 = stwo_m31_sub(b265, b132);
    unsigned b190 = stwo_m31_mul(b29, b58);
    unsigned b191 = stwo_m31_mul(b30, b57);
    unsigned b192 = stwo_m31_add(b190, b191);
    unsigned b267 = stwo_m31_sub(b266, b192);
    unsigned b268 = stwo_m31_add(b173, b267);
    unsigned b631 = stwo_m31_sub(b597, b268);
    unsigned b335 = stwo_m31_mul(b38, b70);
    unsigned b336 = stwo_m31_mul(b39, b69);
    unsigned b337 = stwo_m31_add(b335, b336);
    unsigned b338 = stwo_m31_mul(b40, b68);
    unsigned b339 = stwo_m31_add(b337, b338);
    unsigned b340 = stwo_m31_mul(b41, b67);
    unsigned b341 = stwo_m31_add(b339, b340);
    unsigned b342 = stwo_m31_mul(b42, b66);
    unsigned b343 = stwo_m31_add(b341, b342);
    unsigned b425 = stwo_m31_add(b65, b72);
    unsigned b433 = stwo_m31_mul(b419, b425);
    unsigned b420 = stwo_m31_add(b37, b44);
    unsigned b434 = stwo_m31_mul(b420, b424);
    unsigned b435 = stwo_m31_add(b433, b434);
    unsigned b300 = stwo_m31_mul(b36, b65);
    unsigned b301 = stwo_m31_mul(b37, b64);
    unsigned b302 = stwo_m31_add(b300, b301);
    unsigned b436 = stwo_m31_sub(b435, b302);
    unsigned b360 = stwo_m31_mul(b43, b72);
    unsigned b361 = stwo_m31_mul(b44, b71);
    unsigned b362 = stwo_m31_add(b360, b361);
    unsigned b437 = stwo_m31_sub(b436, b362);
    unsigned b438 = stwo_m31_add(b343, b437);
    unsigned b632 = stwo_m31_sub(b631, b438);
    unsigned b633 = stwo_m31_add(b233, b632);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    unsigned b649 = stwo_m31_sub(b633, b18);
    unsigned b665 = stwo_m31_mul(b664, b649);
    unsigned b666 = stwo_m31_sub(b663, b665);
    unsigned b667 = base_params[27u];
    unsigned b395 = stwo_m31_mul(b45, b77);
    unsigned b396 = stwo_m31_mul(b46, b76);
    unsigned b397 = stwo_m31_add(b395, b396);
    unsigned b398 = stwo_m31_mul(b47, b75);
    unsigned b399 = stwo_m31_add(b397, b398);
    unsigned b400 = stwo_m31_mul(b48, b74);
    unsigned b401 = stwo_m31_add(b399, b400);
    unsigned b402 = stwo_m31_mul(b49, b73);
    unsigned b403 = stwo_m31_add(b401, b402);
    unsigned b668 = stwo_m31_mul(b667, b403);
    unsigned b669 = stwo_m31_add(b666, b668);
    unsigned b703 = stwo_m31_add(b669, b79);
    unsigned b704 = stwo_m31_sub(b702, b703);
    StwoCudaQm31 e11 = StwoCudaQm31{ b704, b87, b87, b87 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 104u, row_index, 0);
    unsigned b705 = base_params[115u];
    unsigned b706 = stwo_m31_mul(b81, b705);
    unsigned b670 = base_params[28u];
    unsigned b133 = stwo_m31_mul(b22, b52);
    unsigned b134 = stwo_m31_mul(b23, b51);
    unsigned b135 = stwo_m31_add(b133, b134);
    unsigned b136 = stwo_m31_mul(b24, b50);
    unsigned b137 = stwo_m31_add(b135, b136);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    unsigned b645 = stwo_m31_sub(b137, b14);
    unsigned b671 = stwo_m31_mul(b670, b645);
    unsigned b672 = stwo_m31_add(b644, b671);
    unsigned b673 = base_params[29u];
    unsigned b234 = stwo_m31_mul(b32, b63);
    unsigned b235 = stwo_m31_mul(b33, b62);
    unsigned b236 = stwo_m31_add(b234, b235);
    unsigned b237 = stwo_m31_mul(b34, b61);
    unsigned b238 = stwo_m31_add(b236, b237);
    unsigned b239 = stwo_m31_mul(b35, b60);
    unsigned b240 = stwo_m31_add(b238, b239);
    unsigned b538 = stwo_m31_mul(b472, b487);
    unsigned b539 = stwo_m31_mul(b473, b486);
    unsigned b540 = stwo_m31_add(b538, b539);
    unsigned b541 = stwo_m31_mul(b474, b485);
    unsigned b542 = stwo_m31_add(b540, b541);
    unsigned b543 = stwo_m31_mul(b475, b484);
    unsigned b544 = stwo_m31_add(b542, b543);
    unsigned b490 = stwo_m31_add(b59, b73);
    unsigned b585 = stwo_m31_add(b483, b490);
    unsigned b598 = stwo_m31_mul(b578, b585);
    unsigned b599 = stwo_m31_mul(b579, b584);
    unsigned b600 = stwo_m31_add(b598, b599);
    unsigned b478 = stwo_m31_add(b31, b45);
    unsigned b580 = stwo_m31_add(b471, b478);
    unsigned b601 = stwo_m31_mul(b580, b583);
    unsigned b602 = stwo_m31_add(b600, b601);
    unsigned b497 = stwo_m31_mul(b469, b483);
    unsigned b498 = stwo_m31_mul(b470, b482);
    unsigned b499 = stwo_m31_add(b497, b498);
    unsigned b500 = stwo_m31_mul(b471, b481);
    unsigned b501 = stwo_m31_add(b499, b500);
    unsigned b603 = stwo_m31_sub(b602, b501);
    unsigned b557 = stwo_m31_mul(b476, b490);
    unsigned b558 = stwo_m31_mul(b477, b489);
    unsigned b559 = stwo_m31_add(b557, b558);
    unsigned b560 = stwo_m31_mul(b478, b488);
    unsigned b561 = stwo_m31_add(b559, b560);
    unsigned b604 = stwo_m31_sub(b603, b561);
    unsigned b605 = stwo_m31_add(b544, b604);
    unsigned b174 = stwo_m31_mul(b25, b56);
    unsigned b175 = stwo_m31_mul(b26, b55);
    unsigned b176 = stwo_m31_add(b174, b175);
    unsigned b177 = stwo_m31_mul(b27, b54);
    unsigned b178 = stwo_m31_add(b176, b177);
    unsigned b179 = stwo_m31_mul(b28, b53);
    unsigned b180 = stwo_m31_add(b178, b179);
    unsigned b256 = stwo_m31_add(b52, b59);
    unsigned b269 = stwo_m31_mul(b249, b256);
    unsigned b270 = stwo_m31_mul(b250, b255);
    unsigned b271 = stwo_m31_add(b269, b270);
    unsigned b251 = stwo_m31_add(b24, b31);
    unsigned b272 = stwo_m31_mul(b251, b254);
    unsigned b273 = stwo_m31_add(b271, b272);
    unsigned b274 = stwo_m31_sub(b273, b137);
    unsigned b193 = stwo_m31_mul(b29, b59);
    unsigned b194 = stwo_m31_mul(b30, b58);
    unsigned b195 = stwo_m31_add(b193, b194);
    unsigned b196 = stwo_m31_mul(b31, b57);
    unsigned b197 = stwo_m31_add(b195, b196);
    unsigned b275 = stwo_m31_sub(b274, b197);
    unsigned b276 = stwo_m31_add(b180, b275);
    unsigned b634 = stwo_m31_sub(b605, b276);
    unsigned b344 = stwo_m31_mul(b39, b70);
    unsigned b345 = stwo_m31_mul(b40, b69);
    unsigned b346 = stwo_m31_add(b344, b345);
    unsigned b347 = stwo_m31_mul(b41, b68);
    unsigned b348 = stwo_m31_add(b346, b347);
    unsigned b349 = stwo_m31_mul(b42, b67);
    unsigned b350 = stwo_m31_add(b348, b349);
    unsigned b426 = stwo_m31_add(b66, b73);
    unsigned b439 = stwo_m31_mul(b419, b426);
    unsigned b440 = stwo_m31_mul(b420, b425);
    unsigned b441 = stwo_m31_add(b439, b440);
    unsigned b421 = stwo_m31_add(b38, b45);
    unsigned b442 = stwo_m31_mul(b421, b424);
    unsigned b443 = stwo_m31_add(b441, b442);
    unsigned b303 = stwo_m31_mul(b36, b66);
    unsigned b304 = stwo_m31_mul(b37, b65);
    unsigned b305 = stwo_m31_add(b303, b304);
    unsigned b306 = stwo_m31_mul(b38, b64);
    unsigned b307 = stwo_m31_add(b305, b306);
    unsigned b444 = stwo_m31_sub(b443, b307);
    unsigned b363 = stwo_m31_mul(b43, b73);
    unsigned b364 = stwo_m31_mul(b44, b72);
    unsigned b365 = stwo_m31_add(b363, b364);
    unsigned b366 = stwo_m31_mul(b45, b71);
    unsigned b367 = stwo_m31_add(b365, b366);
    unsigned b445 = stwo_m31_sub(b444, b367);
    unsigned b446 = stwo_m31_add(b350, b445);
    unsigned b635 = stwo_m31_sub(b634, b446);
    unsigned b636 = stwo_m31_add(b240, b635);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    unsigned b650 = stwo_m31_sub(b636, b19);
    unsigned b674 = stwo_m31_mul(b673, b650);
    unsigned b675 = stwo_m31_sub(b672, b674);
    unsigned b676 = base_params[30u];
    unsigned b404 = stwo_m31_mul(b46, b77);
    unsigned b405 = stwo_m31_mul(b47, b76);
    unsigned b406 = stwo_m31_add(b404, b405);
    unsigned b407 = stwo_m31_mul(b48, b75);
    unsigned b408 = stwo_m31_add(b406, b407);
    unsigned b409 = stwo_m31_mul(b49, b74);
    unsigned b410 = stwo_m31_add(b408, b409);
    unsigned b677 = stwo_m31_mul(b676, b410);
    unsigned b678 = stwo_m31_add(b675, b677);
    unsigned b707 = stwo_m31_add(b678, b80);
    unsigned b708 = stwo_m31_sub(b706, b707);
    StwoCudaQm31 e12 = StwoCudaQm31{ b708, b87, b87, b87 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 105u, row_index, 0);
    unsigned b709 = base_params[117u];
    unsigned b710 = stwo_m31_mul(b82, b709);
    unsigned b679 = base_params[31u];
    unsigned b138 = stwo_m31_mul(b22, b53);
    unsigned b139 = stwo_m31_mul(b23, b52);
    unsigned b140 = stwo_m31_add(b138, b139);
    unsigned b141 = stwo_m31_mul(b24, b51);
    unsigned b142 = stwo_m31_add(b140, b141);
    unsigned b143 = stwo_m31_mul(b25, b50);
    unsigned b144 = stwo_m31_add(b142, b143);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    unsigned b646 = stwo_m31_sub(b144, b15);
    unsigned b680 = stwo_m31_mul(b679, b646);
    unsigned b681 = stwo_m31_add(b645, b680);
    unsigned b682 = base_params[32u];
    unsigned b241 = stwo_m31_mul(b33, b63);
    unsigned b242 = stwo_m31_mul(b34, b62);
    unsigned b243 = stwo_m31_add(b241, b242);
    unsigned b244 = stwo_m31_mul(b35, b61);
    unsigned b245 = stwo_m31_add(b243, b244);
    unsigned b545 = stwo_m31_mul(b473, b487);
    unsigned b546 = stwo_m31_mul(b474, b486);
    unsigned b547 = stwo_m31_add(b545, b546);
    unsigned b548 = stwo_m31_mul(b475, b485);
    unsigned b549 = stwo_m31_add(b547, b548);
    unsigned b491 = stwo_m31_add(b60, b74);
    unsigned b586 = stwo_m31_add(b484, b491);
    unsigned b606 = stwo_m31_mul(b578, b586);
    unsigned b607 = stwo_m31_mul(b579, b585);
    unsigned b608 = stwo_m31_add(b606, b607);
    unsigned b609 = stwo_m31_mul(b580, b584);
    unsigned b610 = stwo_m31_add(b608, b609);
    unsigned b479 = stwo_m31_add(b32, b46);
    unsigned b581 = stwo_m31_add(b472, b479);
    unsigned b611 = stwo_m31_mul(b581, b583);
    unsigned b612 = stwo_m31_add(b610, b611);
    unsigned b502 = stwo_m31_mul(b469, b484);
    unsigned b503 = stwo_m31_mul(b470, b483);
    unsigned b504 = stwo_m31_add(b502, b503);
    unsigned b505 = stwo_m31_mul(b471, b482);
    unsigned b506 = stwo_m31_add(b504, b505);
    unsigned b507 = stwo_m31_mul(b472, b481);
    unsigned b508 = stwo_m31_add(b506, b507);
    unsigned b613 = stwo_m31_sub(b612, b508);
    unsigned b562 = stwo_m31_mul(b476, b491);
    unsigned b563 = stwo_m31_mul(b477, b490);
    unsigned b564 = stwo_m31_add(b562, b563);
    unsigned b565 = stwo_m31_mul(b478, b489);
    unsigned b566 = stwo_m31_add(b564, b565);
    unsigned b567 = stwo_m31_mul(b479, b488);
    unsigned b568 = stwo_m31_add(b566, b567);
    unsigned b614 = stwo_m31_sub(b613, b568);
    unsigned b615 = stwo_m31_add(b549, b614);
    unsigned b181 = stwo_m31_mul(b26, b56);
    unsigned b182 = stwo_m31_mul(b27, b55);
    unsigned b183 = stwo_m31_add(b181, b182);
    unsigned b184 = stwo_m31_mul(b28, b54);
    unsigned b185 = stwo_m31_add(b183, b184);
    unsigned b257 = stwo_m31_add(b53, b60);
    unsigned b277 = stwo_m31_mul(b249, b257);
    unsigned b278 = stwo_m31_mul(b250, b256);
    unsigned b279 = stwo_m31_add(b277, b278);
    unsigned b280 = stwo_m31_mul(b251, b255);
    unsigned b281 = stwo_m31_add(b279, b280);
    unsigned b252 = stwo_m31_add(b25, b32);
    unsigned b282 = stwo_m31_mul(b252, b254);
    unsigned b283 = stwo_m31_add(b281, b282);
    unsigned b284 = stwo_m31_sub(b283, b144);
    unsigned b198 = stwo_m31_mul(b29, b60);
    unsigned b199 = stwo_m31_mul(b30, b59);
    unsigned b200 = stwo_m31_add(b198, b199);
    unsigned b201 = stwo_m31_mul(b31, b58);
    unsigned b202 = stwo_m31_add(b200, b201);
    unsigned b203 = stwo_m31_mul(b32, b57);
    unsigned b204 = stwo_m31_add(b202, b203);
    unsigned b285 = stwo_m31_sub(b284, b204);
    unsigned b286 = stwo_m31_add(b185, b285);
    unsigned b637 = stwo_m31_sub(b615, b286);
    unsigned b351 = stwo_m31_mul(b40, b70);
    unsigned b352 = stwo_m31_mul(b41, b69);
    unsigned b353 = stwo_m31_add(b351, b352);
    unsigned b354 = stwo_m31_mul(b42, b68);
    unsigned b355 = stwo_m31_add(b353, b354);
    unsigned b427 = stwo_m31_add(b67, b74);
    unsigned b447 = stwo_m31_mul(b419, b427);
    unsigned b448 = stwo_m31_mul(b420, b426);
    unsigned b449 = stwo_m31_add(b447, b448);
    unsigned b450 = stwo_m31_mul(b421, b425);
    unsigned b451 = stwo_m31_add(b449, b450);
    unsigned b422 = stwo_m31_add(b39, b46);
    unsigned b452 = stwo_m31_mul(b422, b424);
    unsigned b453 = stwo_m31_add(b451, b452);
    unsigned b308 = stwo_m31_mul(b36, b67);
    unsigned b309 = stwo_m31_mul(b37, b66);
    unsigned b310 = stwo_m31_add(b308, b309);
    unsigned b311 = stwo_m31_mul(b38, b65);
    unsigned b312 = stwo_m31_add(b310, b311);
    unsigned b313 = stwo_m31_mul(b39, b64);
    unsigned b314 = stwo_m31_add(b312, b313);
    unsigned b454 = stwo_m31_sub(b453, b314);
    unsigned b368 = stwo_m31_mul(b43, b74);
    unsigned b369 = stwo_m31_mul(b44, b73);
    unsigned b370 = stwo_m31_add(b368, b369);
    unsigned b371 = stwo_m31_mul(b45, b72);
    unsigned b372 = stwo_m31_add(b370, b371);
    unsigned b373 = stwo_m31_mul(b46, b71);
    unsigned b374 = stwo_m31_add(b372, b373);
    unsigned b455 = stwo_m31_sub(b454, b374);
    unsigned b456 = stwo_m31_add(b355, b455);
    unsigned b638 = stwo_m31_sub(b637, b456);
    unsigned b639 = stwo_m31_add(b245, b638);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    unsigned b651 = stwo_m31_sub(b639, b20);
    unsigned b683 = stwo_m31_mul(b682, b651);
    unsigned b684 = stwo_m31_sub(b681, b683);
    unsigned b685 = base_params[33u];
    unsigned b411 = stwo_m31_mul(b47, b77);
    unsigned b412 = stwo_m31_mul(b48, b76);
    unsigned b413 = stwo_m31_add(b411, b412);
    unsigned b414 = stwo_m31_mul(b49, b75);
    unsigned b415 = stwo_m31_add(b413, b414);
    unsigned b686 = stwo_m31_mul(b685, b415);
    unsigned b687 = stwo_m31_add(b684, b686);
    unsigned b711 = stwo_m31_add(b687, b81);
    unsigned b712 = stwo_m31_sub(b710, b711);
    StwoCudaQm31 e13 = StwoCudaQm31{ b712, b87, b87, b87 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 106u, row_index, 0);
    unsigned b713 = base_params[119u];
    unsigned b714 = stwo_m31_mul(b83, b713);
    unsigned b688 = base_params[34u];
    unsigned b145 = stwo_m31_mul(b22, b54);
    unsigned b146 = stwo_m31_mul(b23, b53);
    unsigned b147 = stwo_m31_add(b145, b146);
    unsigned b148 = stwo_m31_mul(b24, b52);
    unsigned b149 = stwo_m31_add(b147, b148);
    unsigned b150 = stwo_m31_mul(b25, b51);
    unsigned b151 = stwo_m31_add(b149, b150);
    unsigned b152 = stwo_m31_mul(b26, b50);
    unsigned b153 = stwo_m31_add(b151, b152);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    unsigned b647 = stwo_m31_sub(b153, b16);
    unsigned b689 = stwo_m31_mul(b688, b647);
    unsigned b690 = stwo_m31_add(b646, b689);
    unsigned b691 = base_params[35u];
    unsigned b246 = stwo_m31_mul(b34, b63);
    unsigned b247 = stwo_m31_mul(b35, b62);
    unsigned b248 = stwo_m31_add(b246, b247);
    unsigned b550 = stwo_m31_mul(b474, b487);
    unsigned b551 = stwo_m31_mul(b475, b486);
    unsigned b552 = stwo_m31_add(b550, b551);
    unsigned b492 = stwo_m31_add(b61, b75);
    unsigned b587 = stwo_m31_add(b485, b492);
    unsigned b616 = stwo_m31_mul(b578, b587);
    unsigned b617 = stwo_m31_mul(b579, b586);
    unsigned b618 = stwo_m31_add(b616, b617);
    unsigned b619 = stwo_m31_mul(b580, b585);
    unsigned b620 = stwo_m31_add(b618, b619);
    unsigned b621 = stwo_m31_mul(b581, b584);
    unsigned b622 = stwo_m31_add(b620, b621);
    unsigned b480 = stwo_m31_add(b33, b47);
    unsigned b582 = stwo_m31_add(b473, b480);
    unsigned b623 = stwo_m31_mul(b582, b583);
    unsigned b624 = stwo_m31_add(b622, b623);
    unsigned b509 = stwo_m31_mul(b469, b485);
    unsigned b510 = stwo_m31_mul(b470, b484);
    unsigned b511 = stwo_m31_add(b509, b510);
    unsigned b512 = stwo_m31_mul(b471, b483);
    unsigned b513 = stwo_m31_add(b511, b512);
    unsigned b514 = stwo_m31_mul(b472, b482);
    unsigned b515 = stwo_m31_add(b513, b514);
    unsigned b516 = stwo_m31_mul(b473, b481);
    unsigned b517 = stwo_m31_add(b515, b516);
    unsigned b625 = stwo_m31_sub(b624, b517);
    unsigned b569 = stwo_m31_mul(b476, b492);
    unsigned b570 = stwo_m31_mul(b477, b491);
    unsigned b571 = stwo_m31_add(b569, b570);
    unsigned b572 = stwo_m31_mul(b478, b490);
    unsigned b573 = stwo_m31_add(b571, b572);
    unsigned b574 = stwo_m31_mul(b479, b489);
    unsigned b575 = stwo_m31_add(b573, b574);
    unsigned b576 = stwo_m31_mul(b480, b488);
    unsigned b577 = stwo_m31_add(b575, b576);
    unsigned b626 = stwo_m31_sub(b625, b577);
    unsigned b627 = stwo_m31_add(b552, b626);
    unsigned b186 = stwo_m31_mul(b27, b56);
    unsigned b187 = stwo_m31_mul(b28, b55);
    unsigned b188 = stwo_m31_add(b186, b187);
    unsigned b258 = stwo_m31_add(b54, b61);
    unsigned b287 = stwo_m31_mul(b249, b258);
    unsigned b288 = stwo_m31_mul(b250, b257);
    unsigned b289 = stwo_m31_add(b287, b288);
    unsigned b290 = stwo_m31_mul(b251, b256);
    unsigned b291 = stwo_m31_add(b289, b290);
    unsigned b292 = stwo_m31_mul(b252, b255);
    unsigned b293 = stwo_m31_add(b291, b292);
    unsigned b253 = stwo_m31_add(b26, b33);
    unsigned b294 = stwo_m31_mul(b253, b254);
    unsigned b295 = stwo_m31_add(b293, b294);
    unsigned b296 = stwo_m31_sub(b295, b153);
    unsigned b205 = stwo_m31_mul(b29, b61);
    unsigned b206 = stwo_m31_mul(b30, b60);
    unsigned b207 = stwo_m31_add(b205, b206);
    unsigned b208 = stwo_m31_mul(b31, b59);
    unsigned b209 = stwo_m31_add(b207, b208);
    unsigned b210 = stwo_m31_mul(b32, b58);
    unsigned b211 = stwo_m31_add(b209, b210);
    unsigned b212 = stwo_m31_mul(b33, b57);
    unsigned b213 = stwo_m31_add(b211, b212);
    unsigned b297 = stwo_m31_sub(b296, b213);
    unsigned b298 = stwo_m31_add(b188, b297);
    unsigned b640 = stwo_m31_sub(b627, b298);
    unsigned b356 = stwo_m31_mul(b41, b70);
    unsigned b357 = stwo_m31_mul(b42, b69);
    unsigned b358 = stwo_m31_add(b356, b357);
    unsigned b428 = stwo_m31_add(b68, b75);
    unsigned b457 = stwo_m31_mul(b419, b428);
    unsigned b458 = stwo_m31_mul(b420, b427);
    unsigned b459 = stwo_m31_add(b457, b458);
    unsigned b460 = stwo_m31_mul(b421, b426);
    unsigned b461 = stwo_m31_add(b459, b460);
    unsigned b462 = stwo_m31_mul(b422, b425);
    unsigned b463 = stwo_m31_add(b461, b462);
    unsigned b423 = stwo_m31_add(b40, b47);
    unsigned b464 = stwo_m31_mul(b423, b424);
    unsigned b465 = stwo_m31_add(b463, b464);
    unsigned b315 = stwo_m31_mul(b36, b68);
    unsigned b316 = stwo_m31_mul(b37, b67);
    unsigned b317 = stwo_m31_add(b315, b316);
    unsigned b318 = stwo_m31_mul(b38, b66);
    unsigned b319 = stwo_m31_add(b317, b318);
    unsigned b320 = stwo_m31_mul(b39, b65);
    unsigned b321 = stwo_m31_add(b319, b320);
    unsigned b322 = stwo_m31_mul(b40, b64);
    unsigned b323 = stwo_m31_add(b321, b322);
    unsigned b466 = stwo_m31_sub(b465, b323);
    unsigned b375 = stwo_m31_mul(b43, b75);
    unsigned b376 = stwo_m31_mul(b44, b74);
    unsigned b377 = stwo_m31_add(b375, b376);
    unsigned b378 = stwo_m31_mul(b45, b73);
    unsigned b379 = stwo_m31_add(b377, b378);
    unsigned b380 = stwo_m31_mul(b46, b72);
    unsigned b381 = stwo_m31_add(b379, b380);
    unsigned b382 = stwo_m31_mul(b47, b71);
    unsigned b383 = stwo_m31_add(b381, b382);
    unsigned b467 = stwo_m31_sub(b466, b383);
    unsigned b468 = stwo_m31_add(b358, b467);
    unsigned b641 = stwo_m31_sub(b640, b468);
    unsigned b642 = stwo_m31_add(b248, b641);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    unsigned b652 = stwo_m31_sub(b642, b21);
    unsigned b692 = stwo_m31_mul(b691, b652);
    unsigned b693 = stwo_m31_sub(b690, b692);
    unsigned b694 = base_params[36u];
    unsigned b416 = stwo_m31_mul(b48, b77);
    unsigned b417 = stwo_m31_mul(b49, b76);
    unsigned b418 = stwo_m31_add(b416, b417);
    unsigned b695 = stwo_m31_mul(b694, b418);
    unsigned b696 = stwo_m31_add(b693, b695);
    unsigned b715 = stwo_m31_add(b696, b82);
    unsigned b716 = stwo_m31_sub(b714, b715);
    StwoCudaQm31 e14 = StwoCudaQm31{ b716, b87, b87, b87 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
