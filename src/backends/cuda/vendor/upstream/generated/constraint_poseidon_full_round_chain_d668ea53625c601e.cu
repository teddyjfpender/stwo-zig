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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_8543bd8e3f45997a(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 127u);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 124u, row_index, 0);
    unsigned b185 = base_params[74u];
    unsigned b186 = stwo_m31_add(b98, b185);
    unsigned b100 = base_params[0u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b186, b100, b100, b100 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 128u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 129u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 32u, row_index, 0);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 42u, row_index, 0);
    unsigned b101 = stwo_m31_add(b32, b41);
    unsigned b102 = base_params[53u];
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    unsigned b103 = stwo_m31_mul(b102, b50);
    unsigned b104 = stwo_m31_sub(b101, b103);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 82u, row_index, 0);
    unsigned b105 = stwo_m31_add(b104, b59);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 114u, row_index, 0);
    unsigned b106 = stwo_m31_sub(b105, b88);
    unsigned b107 = stwo_m31_sub(b106, b98);
    unsigned b108 = base_params[54u];
    unsigned b109 = stwo_m31_mul(b107, b108);
    unsigned b187 = base_params[75u];
    unsigned b188 = stwo_m31_add(b109, b187);
    e2 = StwoCudaQm31{ b188, b100, b100, b100 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 130u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 33u, row_index, 0);
    unsigned b110 = stwo_m31_add(b109, b33);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 43u, row_index, 0);
    unsigned b111 = stwo_m31_add(b110, b42);
    unsigned b112 = base_params[55u];
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    unsigned b113 = stwo_m31_mul(b112, b51);
    unsigned b114 = stwo_m31_sub(b111, b113);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 83u, row_index, 0);
    unsigned b115 = stwo_m31_add(b114, b60);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 115u, row_index, 0);
    unsigned b116 = stwo_m31_sub(b115, b89);
    unsigned b117 = base_params[56u];
    unsigned b118 = stwo_m31_mul(b116, b117);
    unsigned b189 = base_params[76u];
    unsigned b190 = stwo_m31_add(b118, b189);
    e0 = StwoCudaQm31{ b190, b100, b100, b100 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 131u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 34u, row_index, 0);
    unsigned b119 = stwo_m31_add(b118, b34);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 44u, row_index, 0);
    unsigned b120 = stwo_m31_add(b119, b43);
    unsigned b121 = base_params[57u];
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 54u, row_index, 0);
    unsigned b122 = stwo_m31_mul(b121, b52);
    unsigned b123 = stwo_m31_sub(b120, b122);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 84u, row_index, 0);
    unsigned b124 = stwo_m31_add(b123, b61);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 116u, row_index, 0);
    unsigned b125 = stwo_m31_sub(b124, b90);
    unsigned b126 = base_params[58u];
    unsigned b127 = stwo_m31_mul(b125, b126);
    unsigned b191 = base_params[77u];
    unsigned b192 = stwo_m31_add(b127, b191);
    e2 = StwoCudaQm31{ b192, b100, b100, b100 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 132u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 35u, row_index, 0);
    unsigned b128 = stwo_m31_add(b127, b35);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 45u, row_index, 0);
    unsigned b129 = stwo_m31_add(b128, b44);
    unsigned b130 = base_params[59u];
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 55u, row_index, 0);
    unsigned b131 = stwo_m31_mul(b130, b53);
    unsigned b132 = stwo_m31_sub(b129, b131);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 85u, row_index, 0);
    unsigned b133 = stwo_m31_add(b132, b62);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 117u, row_index, 0);
    unsigned b134 = stwo_m31_sub(b133, b91);
    unsigned b135 = base_params[60u];
    unsigned b136 = stwo_m31_mul(b134, b135);
    unsigned b193 = base_params[78u];
    unsigned b194 = stwo_m31_add(b136, b193);
    e0 = StwoCudaQm31{ b194, b100, b100, b100 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 133u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 134u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 36u, row_index, 0);
    unsigned b137 = stwo_m31_add(b136, b36);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 46u, row_index, 0);
    unsigned b138 = stwo_m31_add(b137, b45);
    unsigned b139 = base_params[61u];
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 56u, row_index, 0);
    unsigned b140 = stwo_m31_mul(b139, b54);
    unsigned b141 = stwo_m31_sub(b138, b140);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 86u, row_index, 0);
    unsigned b142 = stwo_m31_add(b141, b63);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 118u, row_index, 0);
    unsigned b143 = stwo_m31_sub(b142, b92);
    unsigned b144 = base_params[62u];
    unsigned b145 = stwo_m31_mul(b143, b144);
    unsigned b195 = base_params[79u];
    unsigned b196 = stwo_m31_add(b145, b195);
    e0 = StwoCudaQm31{ b196, b100, b100, b100 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 135u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 136u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 37u, row_index, 0);
    unsigned b146 = stwo_m31_add(b145, b37);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 47u, row_index, 0);
    unsigned b147 = stwo_m31_add(b146, b46);
    unsigned b148 = base_params[63u];
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 57u, row_index, 0);
    unsigned b149 = stwo_m31_mul(b148, b55);
    unsigned b150 = stwo_m31_sub(b147, b149);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 87u, row_index, 0);
    unsigned b151 = stwo_m31_add(b150, b64);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 119u, row_index, 0);
    unsigned b152 = stwo_m31_sub(b151, b93);
    unsigned b153 = base_params[64u];
    unsigned b154 = stwo_m31_mul(b152, b153);
    unsigned b197 = base_params[80u];
    unsigned b198 = stwo_m31_add(b154, b197);
    e3 = StwoCudaQm31{ b198, b100, b100, b100 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 137u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 38u, row_index, 0);
    unsigned b155 = stwo_m31_add(b154, b38);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 48u, row_index, 0);
    unsigned b156 = stwo_m31_add(b155, b47);
    unsigned b157 = base_params[65u];
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 58u, row_index, 0);
    unsigned b158 = stwo_m31_mul(b157, b56);
    unsigned b159 = stwo_m31_sub(b156, b158);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 88u, row_index, 0);
    unsigned b160 = stwo_m31_add(b159, b65);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 120u, row_index, 0);
    unsigned b161 = stwo_m31_sub(b160, b94);
    unsigned b162 = base_params[66u];
    unsigned b163 = stwo_m31_mul(b161, b162);
    unsigned b199 = base_params[81u];
    unsigned b200 = stwo_m31_add(b163, b199);
    e1 = StwoCudaQm31{ b200, b100, b100, b100 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 138u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    unsigned b164 = stwo_m31_add(b163, b39);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 49u, row_index, 0);
    unsigned b165 = stwo_m31_add(b164, b48);
    unsigned b166 = base_params[67u];
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 59u, row_index, 0);
    unsigned b167 = stwo_m31_mul(b166, b57);
    unsigned b168 = stwo_m31_sub(b165, b167);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 89u, row_index, 0);
    unsigned b169 = stwo_m31_add(b168, b66);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 121u, row_index, 0);
    unsigned b170 = stwo_m31_sub(b169, b95);
    unsigned b171 = base_params[68u];
    unsigned b172 = stwo_m31_mul(b98, b171);
    unsigned b173 = stwo_m31_sub(b170, b172);
    unsigned b174 = base_params[69u];
    unsigned b175 = stwo_m31_mul(b173, b174);
    unsigned b201 = base_params[82u];
    unsigned b202 = stwo_m31_add(b175, b201);
    e3 = StwoCudaQm31{ b202, b100, b100, b100 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 139u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 40u, row_index, 0);
    unsigned b176 = stwo_m31_add(b175, b40);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    unsigned b177 = stwo_m31_add(b176, b49);
    unsigned b178 = base_params[70u];
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 60u, row_index, 0);
    unsigned b179 = stwo_m31_mul(b178, b58);
    unsigned b180 = stwo_m31_sub(b177, b179);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 90u, row_index, 0);
    unsigned b181 = stwo_m31_add(b180, b67);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 122u, row_index, 0);
    unsigned b182 = stwo_m31_sub(b181, b96);
    unsigned b183 = base_params[71u];
    unsigned b184 = stwo_m31_mul(b182, b183);
    unsigned b203 = base_params[83u];
    unsigned b204 = stwo_m31_add(b184, b203);
    e1 = StwoCudaQm31{ b204, b100, b100, b100 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(ext_params, 140u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 141u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 0u, row_index, 0);
    e1 = StwoCudaQm31{ b0, b100, b100, b100 };
    e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 142u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(ext_params, 143u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 1u, row_index, 0);
    e4 = StwoCudaQm31{ b1, b100, b100, b100 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 144u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 2u, row_index, 0);
    e0 = StwoCudaQm31{ b2, b100, b100, b100 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(ext_params, 145u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 3u, row_index, 0);
    e4 = StwoCudaQm31{ b3, b100, b100, b100 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 146u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 4u, row_index, 0);
    e0 = StwoCudaQm31{ b4, b100, b100, b100 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(ext_params, 147u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 5u, row_index, 0);
    e4 = StwoCudaQm31{ b5, b100, b100, b100 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 148u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 6u, row_index, 0);
    e0 = StwoCudaQm31{ b6, b100, b100, b100 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(ext_params, 149u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 7u, row_index, 0);
    e4 = StwoCudaQm31{ b7, b100, b100, b100 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 150u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 8u, row_index, 0);
    e0 = StwoCudaQm31{ b8, b100, b100, b100 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(ext_params, 151u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 9u, row_index, 0);
    e4 = StwoCudaQm31{ b9, b100, b100, b100 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 152u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 10u, row_index, 0);
    e0 = StwoCudaQm31{ b10, b100, b100, b100 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(ext_params, 153u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 11u, row_index, 0);
    e4 = StwoCudaQm31{ b11, b100, b100, b100 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 154u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 12u, row_index, 0);
    e0 = StwoCudaQm31{ b12, b100, b100, b100 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(ext_params, 155u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 13u, row_index, 0);
    e4 = StwoCudaQm31{ b13, b100, b100, b100 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 156u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 14u, row_index, 0);
    e0 = StwoCudaQm31{ b14, b100, b100, b100 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(ext_params, 157u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 15u, row_index, 0);
    e4 = StwoCudaQm31{ b15, b100, b100, b100 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 158u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 16u, row_index, 0);
    e0 = StwoCudaQm31{ b16, b100, b100, b100 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(ext_params, 159u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 17u, row_index, 0);
    e4 = StwoCudaQm31{ b17, b100, b100, b100 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 160u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 18u, row_index, 0);
    e0 = StwoCudaQm31{ b18, b100, b100, b100 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(ext_params, 161u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 19u, row_index, 0);
    e4 = StwoCudaQm31{ b19, b100, b100, b100 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 162u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 20u, row_index, 0);
    e0 = StwoCudaQm31{ b20, b100, b100, b100 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(ext_params, 163u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 21u, row_index, 0);
    e4 = StwoCudaQm31{ b21, b100, b100, b100 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 164u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 22u, row_index, 0);
    e0 = StwoCudaQm31{ b22, b100, b100, b100 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(ext_params, 165u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 23u, row_index, 0);
    e4 = StwoCudaQm31{ b23, b100, b100, b100 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 166u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 24u, row_index, 0);
    e0 = StwoCudaQm31{ b24, b100, b100, b100 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(ext_params, 167u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 25u, row_index, 0);
    e4 = StwoCudaQm31{ b25, b100, b100, b100 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 168u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 26u, row_index, 0);
    e0 = StwoCudaQm31{ b26, b100, b100, b100 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(ext_params, 169u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 27u, row_index, 0);
    e4 = StwoCudaQm31{ b27, b100, b100, b100 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 170u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 28u, row_index, 0);
    e0 = StwoCudaQm31{ b28, b100, b100, b100 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(ext_params, 171u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 29u, row_index, 0);
    e4 = StwoCudaQm31{ b29, b100, b100, b100 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 172u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 30u, row_index, 0);
    e0 = StwoCudaQm31{ b30, b100, b100, b100 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(ext_params, 173u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 31u, row_index, 0);
    e4 = StwoCudaQm31{ b31, b100, b100, b100 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 174u);
    e0 = stwo_qm31_sub(e4, e5);
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 125u, row_index, 0);
    e5 = StwoCudaQm31{ b99, b100, b100, b100 };
    e4 = stwo_qm31_sub(StwoCudaQm31{0u,0u,0u,0u}, e5);
    e5 = stwo_load_qm31(ext_params, 175u);
    e1 = StwoCudaQm31{ b0, b100, b100, b100 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e5, e1);
    e1 = stwo_load_qm31(ext_params, 176u);
    e5 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(ext_params, 177u);
    unsigned b205 = base_params[84u];
    unsigned b206 = stwo_m31_add(b1, b205);
    e6 = StwoCudaQm31{ b206, b100, b100, b100 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e5, e7);
    e7 = stwo_load_qm31(ext_params, 178u);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 92u, row_index, 0);
    e5 = StwoCudaQm31{ b68, b100, b100, b100 };
    e1 = stwo_qm31_mul(e7, e5);
    e5 = stwo_qm31_add(e6, e1);
    e1 = stwo_load_qm31(ext_params, 179u);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 93u, row_index, 0);
    e6 = StwoCudaQm31{ b69, b100, b100, b100 };
    e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e5, e7);
    e7 = stwo_load_qm31(ext_params, 180u);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 94u, row_index, 0);
    e5 = StwoCudaQm31{ b70, b100, b100, b100 };
    e1 = stwo_qm31_mul(e7, e5);
    e5 = stwo_qm31_add(e6, e1);
    e1 = stwo_load_qm31(ext_params, 181u);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 95u, row_index, 0);
    e6 = StwoCudaQm31{ b71, b100, b100, b100 };
    e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e5, e7);
    e7 = stwo_load_qm31(ext_params, 182u);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 96u, row_index, 0);
    e5 = StwoCudaQm31{ b72, b100, b100, b100 };
    e1 = stwo_qm31_mul(e7, e5);
    e5 = stwo_qm31_add(e6, e1);
    e1 = stwo_load_qm31(ext_params, 183u);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 97u, row_index, 0);
    e6 = StwoCudaQm31{ b73, b100, b100, b100 };
    e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e5, e7);
    e7 = stwo_load_qm31(ext_params, 184u);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 98u, row_index, 0);
    e5 = StwoCudaQm31{ b74, b100, b100, b100 };
    e1 = stwo_qm31_mul(e7, e5);
    e5 = stwo_qm31_add(e6, e1);
    e1 = stwo_load_qm31(ext_params, 185u);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 99u, row_index, 0);
    e6 = StwoCudaQm31{ b75, b100, b100, b100 };
    e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e5, e7);
    e7 = stwo_load_qm31(ext_params, 186u);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 100u, row_index, 0);
    e5 = StwoCudaQm31{ b76, b100, b100, b100 };
    e1 = stwo_qm31_mul(e7, e5);
    e5 = stwo_qm31_add(e6, e1);
    e1 = stwo_load_qm31(ext_params, 187u);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 101u, row_index, 0);
    e6 = StwoCudaQm31{ b77, b100, b100, b100 };
    e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e5, e7);
    e7 = stwo_load_qm31(ext_params, 188u);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 103u, row_index, 0);
    e5 = StwoCudaQm31{ b78, b100, b100, b100 };
    e1 = stwo_qm31_mul(e7, e5);
    e5 = stwo_qm31_add(e6, e1);
    e1 = stwo_load_qm31(ext_params, 189u);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 104u, row_index, 0);
    e6 = StwoCudaQm31{ b79, b100, b100, b100 };
    e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e5, e7);
    e7 = stwo_load_qm31(ext_params, 190u);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 105u, row_index, 0);
    e5 = StwoCudaQm31{ b80, b100, b100, b100 };
    e1 = stwo_qm31_mul(e7, e5);
    e5 = stwo_qm31_add(e6, e1);
    e1 = stwo_load_qm31(ext_params, 191u);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 106u, row_index, 0);
    e6 = StwoCudaQm31{ b81, b100, b100, b100 };
    e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e5, e7);
    e7 = stwo_load_qm31(ext_params, 192u);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 107u, row_index, 0);
    e5 = StwoCudaQm31{ b82, b100, b100, b100 };
    e1 = stwo_qm31_mul(e7, e5);
    e5 = stwo_qm31_add(e6, e1);
    e1 = stwo_load_qm31(ext_params, 193u);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 108u, row_index, 0);
    e6 = StwoCudaQm31{ b83, b100, b100, b100 };
    e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e5, e7);
    e7 = stwo_load_qm31(ext_params, 194u);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 109u, row_index, 0);
    e5 = StwoCudaQm31{ b84, b100, b100, b100 };
    e1 = stwo_qm31_mul(e7, e5);
    e5 = stwo_qm31_add(e6, e1);
    e1 = stwo_load_qm31(ext_params, 195u);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 110u, row_index, 0);
    e6 = StwoCudaQm31{ b85, b100, b100, b100 };
    e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e5, e7);
    e7 = stwo_load_qm31(ext_params, 196u);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 111u, row_index, 0);
    e5 = StwoCudaQm31{ b86, b100, b100, b100 };
    e1 = stwo_qm31_mul(e7, e5);
    e5 = stwo_qm31_add(e6, e1);
    e1 = stwo_load_qm31(ext_params, 197u);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 112u, row_index, 0);
    e6 = StwoCudaQm31{ b87, b100, b100, b100 };
    e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e5, e7);
    e7 = stwo_load_qm31(ext_params, 198u);
    e5 = StwoCudaQm31{ b88, b100, b100, b100 };
    e1 = stwo_qm31_mul(e7, e5);
    e5 = stwo_qm31_add(e6, e1);
    e1 = stwo_load_qm31(ext_params, 199u);
    e6 = StwoCudaQm31{ b89, b100, b100, b100 };
    e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e5, e7);
    e7 = stwo_load_qm31(ext_params, 200u);
    e5 = StwoCudaQm31{ b90, b100, b100, b100 };
    e1 = stwo_qm31_mul(e7, e5);
    e5 = stwo_qm31_add(e6, e1);
    e1 = stwo_load_qm31(ext_params, 201u);
    e6 = StwoCudaQm31{ b91, b100, b100, b100 };
    e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e5, e7);
    e7 = stwo_load_qm31(ext_params, 202u);
    e5 = StwoCudaQm31{ b92, b100, b100, b100 };
    e1 = stwo_qm31_mul(e7, e5);
    e5 = stwo_qm31_add(e6, e1);
    e1 = stwo_load_qm31(ext_params, 203u);
    e6 = StwoCudaQm31{ b93, b100, b100, b100 };
    e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e5, e7);
    e7 = stwo_load_qm31(ext_params, 204u);
    e5 = StwoCudaQm31{ b94, b100, b100, b100 };
    e1 = stwo_qm31_mul(e7, e5);
    e5 = stwo_qm31_add(e6, e1);
    e1 = stwo_load_qm31(ext_params, 205u);
    e6 = StwoCudaQm31{ b95, b100, b100, b100 };
    e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e5, e7);
    e7 = stwo_load_qm31(ext_params, 206u);
    e5 = StwoCudaQm31{ b96, b100, b100, b100 };
    e1 = stwo_qm31_mul(e7, e5);
    e5 = stwo_qm31_add(e6, e1);
    e1 = stwo_load_qm31(ext_params, 207u);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 123u, row_index, 0);
    e6 = StwoCudaQm31{ b97, b100, b100, b100 };
    e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e5, e7);
    e7 = stwo_load_qm31(ext_params, 208u);
    e5 = stwo_qm31_sub(e6, e7);
    e7 = stwo_load_qm31(ext_params, 217u);
    e6 = stwo_qm31_mul(e3, e7);
    e7 = stwo_load_qm31(ext_params, 218u);
    e1 = stwo_qm31_mul(e2, e7);
    e7 = stwo_qm31_add(e6, e1);
    e1 = stwo_qm31_mul(e2, e3);
    e3 = StwoCudaQm31{ b99, b100, b100, b100 };
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e2, e3);
    e3 = stwo_qm31_mul(e0, e5);
    unsigned b207 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b208 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b209 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b210 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e5 = StwoCudaQm31{ b207, b208, b209, b210 };
    unsigned b211 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, 0);
    unsigned b212 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, 0);
    unsigned b213 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, 0);
    unsigned b214 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, 0);
    e0 = StwoCudaQm31{ b211, b212, b213, b214 };
    e2 = stwo_qm31_sub(e0, e5);
    e5 = stwo_qm31_mul(e2, e1);
    e2 = stwo_qm31_sub(e5, e7);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b215 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 20u, row_index, -1);
    unsigned b217 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 21u, row_index, -1);
    unsigned b219 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 22u, row_index, -1);
    unsigned b221 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 23u, row_index, -1);
    e5 = StwoCudaQm31{ b215, b217, b219, b221 };
    unsigned b216 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 20u, row_index, 0);
    unsigned b218 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 21u, row_index, 0);
    unsigned b220 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 22u, row_index, 0);
    unsigned b222 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 23u, row_index, 0);
    e7 = StwoCudaQm31{ b216, b218, b220, b222 };
    e1 = stwo_qm31_sub(e7, e5);
    e7 = stwo_qm31_sub(e1, e0);
    e1 = stwo_load_qm31(ext_params, 219u);
    e0 = stwo_qm31_add(e7, e1);
    e1 = stwo_qm31_mul(e0, e3);
    e0 = stwo_qm31_sub(e1, e4);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
