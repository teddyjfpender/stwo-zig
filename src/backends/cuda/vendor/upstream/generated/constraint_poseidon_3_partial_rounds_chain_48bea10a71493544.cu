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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_817d546dce18c44f(
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
    unsigned b94 = base_params[124u];
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 114u, row_index, 0);
    unsigned b95 = stwo_m31_mul(b94, b40);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 125u, row_index, 0);
    unsigned b96 = stwo_m31_sub(b95, b49);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 135u, row_index, 0);
    unsigned b97 = stwo_m31_sub(b96, b59);
    unsigned b98 = base_params[125u];
    unsigned b99 = stwo_m31_mul(b97, b98);
    unsigned b100 = base_params[126u];
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 115u, row_index, 0);
    unsigned b101 = stwo_m31_mul(b100, b41);
    unsigned b102 = stwo_m31_add(b99, b101);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 126u, row_index, 0);
    unsigned b103 = stwo_m31_sub(b102, b50);
    unsigned b104 = base_params[127u];
    unsigned b105 = stwo_m31_mul(b103, b104);
    unsigned b151 = stwo_m31_mul(b105, b105);
    unsigned b152 = stwo_m31_mul(b151, b105);
    unsigned b153 = stwo_m31_sub(b152, b105);
    unsigned b93 = base_params[0u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b153, b93, b93, b93 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b106 = base_params[128u];
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 116u, row_index, 0);
    unsigned b107 = stwo_m31_mul(b106, b42);
    unsigned b108 = stwo_m31_add(b105, b107);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 127u, row_index, 0);
    unsigned b109 = stwo_m31_sub(b108, b51);
    unsigned b110 = base_params[129u];
    unsigned b111 = stwo_m31_mul(b109, b110);
    unsigned b154 = stwo_m31_mul(b111, b111);
    unsigned b155 = stwo_m31_mul(b154, b111);
    unsigned b156 = stwo_m31_sub(b155, b111);
    StwoCudaQm31 e1 = StwoCudaQm31{ b156, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b112 = base_params[130u];
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 117u, row_index, 0);
    unsigned b113 = stwo_m31_mul(b112, b43);
    unsigned b114 = stwo_m31_add(b111, b113);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 128u, row_index, 0);
    unsigned b115 = stwo_m31_sub(b114, b52);
    unsigned b116 = base_params[131u];
    unsigned b117 = stwo_m31_mul(b115, b116);
    unsigned b157 = stwo_m31_mul(b117, b117);
    unsigned b158 = stwo_m31_mul(b157, b117);
    unsigned b159 = stwo_m31_sub(b158, b117);
    StwoCudaQm31 e2 = StwoCudaQm31{ b159, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b118 = base_params[132u];
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 118u, row_index, 0);
    unsigned b119 = stwo_m31_mul(b118, b44);
    unsigned b120 = stwo_m31_add(b117, b119);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 129u, row_index, 0);
    unsigned b121 = stwo_m31_sub(b120, b53);
    unsigned b122 = base_params[133u];
    unsigned b123 = stwo_m31_mul(b121, b122);
    unsigned b160 = stwo_m31_mul(b123, b123);
    unsigned b161 = stwo_m31_mul(b160, b123);
    unsigned b162 = stwo_m31_sub(b161, b123);
    StwoCudaQm31 e3 = StwoCudaQm31{ b162, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b124 = base_params[134u];
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 119u, row_index, 0);
    unsigned b125 = stwo_m31_mul(b124, b45);
    unsigned b126 = stwo_m31_add(b123, b125);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 130u, row_index, 0);
    unsigned b127 = stwo_m31_sub(b126, b54);
    unsigned b128 = base_params[135u];
    unsigned b129 = stwo_m31_mul(b127, b128);
    unsigned b163 = stwo_m31_mul(b129, b129);
    unsigned b164 = stwo_m31_mul(b163, b129);
    unsigned b165 = stwo_m31_sub(b164, b129);
    StwoCudaQm31 e4 = StwoCudaQm31{ b165, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b130 = base_params[136u];
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 120u, row_index, 0);
    unsigned b131 = stwo_m31_mul(b130, b46);
    unsigned b132 = stwo_m31_add(b129, b131);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 131u, row_index, 0);
    unsigned b133 = stwo_m31_sub(b132, b55);
    unsigned b134 = base_params[137u];
    unsigned b135 = stwo_m31_mul(b133, b134);
    unsigned b166 = stwo_m31_mul(b135, b135);
    unsigned b167 = stwo_m31_mul(b166, b135);
    unsigned b168 = stwo_m31_sub(b167, b135);
    StwoCudaQm31 e5 = StwoCudaQm31{ b168, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b136 = base_params[138u];
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 121u, row_index, 0);
    unsigned b137 = stwo_m31_mul(b136, b47);
    unsigned b138 = stwo_m31_add(b135, b137);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 132u, row_index, 0);
    unsigned b139 = stwo_m31_sub(b138, b56);
    unsigned b140 = base_params[139u];
    unsigned b141 = stwo_m31_mul(b59, b140);
    unsigned b142 = stwo_m31_sub(b139, b141);
    unsigned b143 = base_params[140u];
    unsigned b144 = stwo_m31_mul(b142, b143);
    unsigned b169 = stwo_m31_mul(b144, b144);
    unsigned b170 = stwo_m31_mul(b169, b144);
    unsigned b171 = stwo_m31_sub(b170, b144);
    StwoCudaQm31 e6 = StwoCudaQm31{ b171, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b145 = base_params[141u];
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 122u, row_index, 0);
    unsigned b146 = stwo_m31_mul(b145, b48);
    unsigned b147 = stwo_m31_add(b144, b146);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 133u, row_index, 0);
    unsigned b148 = stwo_m31_sub(b147, b57);
    unsigned b149 = base_params[142u];
    unsigned b150 = stwo_m31_mul(b148, b149);
    unsigned b172 = stwo_m31_mul(b150, b150);
    unsigned b173 = stwo_m31_mul(b172, b150);
    unsigned b174 = stwo_m31_sub(b173, b150);
    StwoCudaQm31 e7 = StwoCudaQm31{ b174, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b175 = base_params[145u];
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 72u, row_index, 0);
    unsigned b176 = stwo_m31_mul(b175, b10);
    unsigned b177 = base_params[146u];
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 93u, row_index, 0);
    unsigned b178 = stwo_m31_mul(b177, b20);
    unsigned b179 = stwo_m31_add(b176, b178);
    unsigned b180 = base_params[147u];
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 104u, row_index, 0);
    unsigned b181 = stwo_m31_mul(b180, b30);
    unsigned b182 = stwo_m31_add(b179, b181);
    unsigned b183 = stwo_m31_add(b182, b49);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 136u, row_index, 0);
    unsigned b184 = stwo_m31_sub(b183, b60);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 62u, row_index, 0);
    unsigned b185 = stwo_m31_add(b184, b0);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 146u, row_index, 0);
    unsigned b186 = stwo_m31_sub(b185, b70);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 156u, row_index, 0);
    unsigned b187 = stwo_m31_sub(b186, b80);
    unsigned b188 = base_params[148u];
    unsigned b189 = stwo_m31_mul(b187, b188);
    unsigned b190 = base_params[149u];
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 73u, row_index, 0);
    unsigned b191 = stwo_m31_mul(b190, b11);
    unsigned b192 = stwo_m31_add(b189, b191);
    unsigned b193 = base_params[150u];
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 94u, row_index, 0);
    unsigned b194 = stwo_m31_mul(b193, b21);
    unsigned b195 = stwo_m31_add(b192, b194);
    unsigned b196 = base_params[151u];
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 105u, row_index, 0);
    unsigned b197 = stwo_m31_mul(b196, b31);
    unsigned b198 = stwo_m31_add(b195, b197);
    unsigned b199 = stwo_m31_add(b198, b50);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 137u, row_index, 0);
    unsigned b200 = stwo_m31_sub(b199, b61);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 63u, row_index, 0);
    unsigned b201 = stwo_m31_add(b200, b1);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 147u, row_index, 0);
    unsigned b202 = stwo_m31_sub(b201, b71);
    unsigned b203 = base_params[152u];
    unsigned b204 = stwo_m31_mul(b202, b203);
    unsigned b205 = base_params[153u];
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 74u, row_index, 0);
    unsigned b206 = stwo_m31_mul(b205, b12);
    unsigned b207 = stwo_m31_add(b204, b206);
    unsigned b208 = base_params[154u];
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 95u, row_index, 0);
    unsigned b209 = stwo_m31_mul(b208, b22);
    unsigned b210 = stwo_m31_add(b207, b209);
    unsigned b211 = base_params[155u];
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 106u, row_index, 0);
    unsigned b212 = stwo_m31_mul(b211, b32);
    unsigned b213 = stwo_m31_add(b210, b212);
    unsigned b214 = stwo_m31_add(b213, b51);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 138u, row_index, 0);
    unsigned b215 = stwo_m31_sub(b214, b62);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 64u, row_index, 0);
    unsigned b216 = stwo_m31_add(b215, b2);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 148u, row_index, 0);
    unsigned b217 = stwo_m31_sub(b216, b72);
    unsigned b218 = base_params[156u];
    unsigned b219 = stwo_m31_mul(b217, b218);
    unsigned b220 = base_params[157u];
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 75u, row_index, 0);
    unsigned b221 = stwo_m31_mul(b220, b13);
    unsigned b222 = stwo_m31_add(b219, b221);
    unsigned b223 = base_params[158u];
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 96u, row_index, 0);
    unsigned b224 = stwo_m31_mul(b223, b23);
    unsigned b225 = stwo_m31_add(b222, b224);
    unsigned b226 = base_params[159u];
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 107u, row_index, 0);
    unsigned b227 = stwo_m31_mul(b226, b33);
    unsigned b228 = stwo_m31_add(b225, b227);
    unsigned b229 = stwo_m31_add(b228, b52);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 139u, row_index, 0);
    unsigned b230 = stwo_m31_sub(b229, b63);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 65u, row_index, 0);
    unsigned b231 = stwo_m31_add(b230, b3);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 149u, row_index, 0);
    unsigned b232 = stwo_m31_sub(b231, b73);
    unsigned b233 = base_params[160u];
    unsigned b234 = stwo_m31_mul(b232, b233);
    unsigned b235 = base_params[161u];
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 76u, row_index, 0);
    unsigned b236 = stwo_m31_mul(b235, b14);
    unsigned b237 = stwo_m31_add(b234, b236);
    unsigned b238 = base_params[162u];
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 97u, row_index, 0);
    unsigned b239 = stwo_m31_mul(b238, b24);
    unsigned b240 = stwo_m31_add(b237, b239);
    unsigned b241 = base_params[163u];
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 108u, row_index, 0);
    unsigned b242 = stwo_m31_mul(b241, b34);
    unsigned b243 = stwo_m31_add(b240, b242);
    unsigned b244 = stwo_m31_add(b243, b53);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 140u, row_index, 0);
    unsigned b245 = stwo_m31_sub(b244, b64);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 66u, row_index, 0);
    unsigned b246 = stwo_m31_add(b245, b4);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 150u, row_index, 0);
    unsigned b247 = stwo_m31_sub(b246, b74);
    unsigned b248 = base_params[164u];
    unsigned b249 = stwo_m31_mul(b247, b248);
    unsigned b250 = base_params[165u];
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 77u, row_index, 0);
    unsigned b251 = stwo_m31_mul(b250, b15);
    unsigned b252 = stwo_m31_add(b249, b251);
    unsigned b253 = base_params[166u];
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 98u, row_index, 0);
    unsigned b254 = stwo_m31_mul(b253, b25);
    unsigned b255 = stwo_m31_add(b252, b254);
    unsigned b256 = base_params[167u];
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 109u, row_index, 0);
    unsigned b257 = stwo_m31_mul(b256, b35);
    unsigned b258 = stwo_m31_add(b255, b257);
    unsigned b259 = stwo_m31_add(b258, b54);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 141u, row_index, 0);
    unsigned b260 = stwo_m31_sub(b259, b65);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 67u, row_index, 0);
    unsigned b261 = stwo_m31_add(b260, b5);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 151u, row_index, 0);
    unsigned b262 = stwo_m31_sub(b261, b75);
    unsigned b263 = base_params[168u];
    unsigned b264 = stwo_m31_mul(b262, b263);
    unsigned b265 = base_params[169u];
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 78u, row_index, 0);
    unsigned b266 = stwo_m31_mul(b265, b16);
    unsigned b267 = stwo_m31_add(b264, b266);
    unsigned b268 = base_params[170u];
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 99u, row_index, 0);
    unsigned b269 = stwo_m31_mul(b268, b26);
    unsigned b270 = stwo_m31_add(b267, b269);
    unsigned b271 = base_params[171u];
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 110u, row_index, 0);
    unsigned b272 = stwo_m31_mul(b271, b36);
    unsigned b273 = stwo_m31_add(b270, b272);
    unsigned b274 = stwo_m31_add(b273, b55);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 142u, row_index, 0);
    unsigned b275 = stwo_m31_sub(b274, b66);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 68u, row_index, 0);
    unsigned b276 = stwo_m31_add(b275, b6);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 152u, row_index, 0);
    unsigned b277 = stwo_m31_sub(b276, b76);
    unsigned b278 = base_params[172u];
    unsigned b279 = stwo_m31_mul(b277, b278);
    unsigned b280 = base_params[173u];
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 79u, row_index, 0);
    unsigned b281 = stwo_m31_mul(b280, b17);
    unsigned b282 = stwo_m31_add(b279, b281);
    unsigned b283 = base_params[174u];
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 100u, row_index, 0);
    unsigned b284 = stwo_m31_mul(b283, b27);
    unsigned b285 = stwo_m31_add(b282, b284);
    unsigned b286 = base_params[175u];
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 111u, row_index, 0);
    unsigned b287 = stwo_m31_mul(b286, b37);
    unsigned b288 = stwo_m31_add(b285, b287);
    unsigned b289 = stwo_m31_add(b288, b56);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 143u, row_index, 0);
    unsigned b290 = stwo_m31_sub(b289, b67);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 69u, row_index, 0);
    unsigned b291 = stwo_m31_add(b290, b7);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 153u, row_index, 0);
    unsigned b292 = stwo_m31_sub(b291, b77);
    unsigned b293 = base_params[176u];
    unsigned b294 = stwo_m31_mul(b80, b293);
    unsigned b295 = stwo_m31_sub(b292, b294);
    unsigned b296 = base_params[177u];
    unsigned b297 = stwo_m31_mul(b295, b296);
    unsigned b298 = base_params[178u];
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 80u, row_index, 0);
    unsigned b299 = stwo_m31_mul(b298, b18);
    unsigned b300 = stwo_m31_add(b297, b299);
    unsigned b301 = base_params[179u];
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 101u, row_index, 0);
    unsigned b302 = stwo_m31_mul(b301, b28);
    unsigned b303 = stwo_m31_add(b300, b302);
    unsigned b304 = base_params[180u];
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 112u, row_index, 0);
    unsigned b305 = stwo_m31_mul(b304, b38);
    unsigned b306 = stwo_m31_add(b303, b305);
    unsigned b307 = stwo_m31_add(b306, b57);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 144u, row_index, 0);
    unsigned b308 = stwo_m31_sub(b307, b68);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 70u, row_index, 0);
    unsigned b309 = stwo_m31_add(b308, b8);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 154u, row_index, 0);
    unsigned b310 = stwo_m31_sub(b309, b78);
    unsigned b311 = base_params[181u];
    unsigned b312 = stwo_m31_mul(b310, b311);
    unsigned b313 = base_params[182u];
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 81u, row_index, 0);
    unsigned b314 = stwo_m31_mul(b313, b19);
    unsigned b315 = stwo_m31_add(b312, b314);
    unsigned b316 = base_params[183u];
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 102u, row_index, 0);
    unsigned b317 = stwo_m31_mul(b316, b29);
    unsigned b318 = stwo_m31_add(b315, b317);
    unsigned b319 = base_params[184u];
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 113u, row_index, 0);
    unsigned b320 = stwo_m31_mul(b319, b39);
    unsigned b321 = stwo_m31_add(b318, b320);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 134u, row_index, 0);
    unsigned b322 = stwo_m31_add(b321, b58);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 145u, row_index, 0);
    unsigned b323 = stwo_m31_sub(b322, b69);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 71u, row_index, 0);
    unsigned b324 = stwo_m31_add(b323, b9);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 155u, row_index, 0);
    unsigned b325 = stwo_m31_sub(b324, b79);
    unsigned b326 = base_params[185u];
    unsigned b327 = stwo_m31_mul(b80, b326);
    unsigned b328 = stwo_m31_sub(b325, b327);
    StwoCudaQm31 e8 = StwoCudaQm31{ b328, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b329 = base_params[196u];
    unsigned b330 = stwo_m31_mul(b329, b70);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 157u, row_index, 0);
    unsigned b331 = stwo_m31_sub(b330, b81);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 167u, row_index, 0);
    unsigned b332 = stwo_m31_sub(b331, b91);
    unsigned b333 = base_params[197u];
    unsigned b334 = stwo_m31_mul(b332, b333);
    unsigned b335 = base_params[198u];
    unsigned b336 = stwo_m31_mul(b335, b71);
    unsigned b337 = stwo_m31_add(b334, b336);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 158u, row_index, 0);
    unsigned b338 = stwo_m31_sub(b337, b82);
    unsigned b339 = base_params[199u];
    unsigned b340 = stwo_m31_mul(b338, b339);
    unsigned b341 = base_params[200u];
    unsigned b342 = stwo_m31_mul(b341, b72);
    unsigned b343 = stwo_m31_add(b340, b342);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 159u, row_index, 0);
    unsigned b344 = stwo_m31_sub(b343, b83);
    unsigned b345 = base_params[201u];
    unsigned b346 = stwo_m31_mul(b344, b345);
    unsigned b347 = base_params[202u];
    unsigned b348 = stwo_m31_mul(b347, b73);
    unsigned b349 = stwo_m31_add(b346, b348);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 160u, row_index, 0);
    unsigned b350 = stwo_m31_sub(b349, b84);
    unsigned b351 = base_params[203u];
    unsigned b352 = stwo_m31_mul(b350, b351);
    unsigned b353 = base_params[204u];
    unsigned b354 = stwo_m31_mul(b353, b74);
    unsigned b355 = stwo_m31_add(b352, b354);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 161u, row_index, 0);
    unsigned b356 = stwo_m31_sub(b355, b85);
    unsigned b357 = base_params[205u];
    unsigned b358 = stwo_m31_mul(b356, b357);
    unsigned b359 = base_params[206u];
    unsigned b360 = stwo_m31_mul(b359, b75);
    unsigned b361 = stwo_m31_add(b358, b360);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 162u, row_index, 0);
    unsigned b362 = stwo_m31_sub(b361, b86);
    unsigned b363 = base_params[207u];
    unsigned b364 = stwo_m31_mul(b362, b363);
    unsigned b365 = base_params[208u];
    unsigned b366 = stwo_m31_mul(b365, b76);
    unsigned b367 = stwo_m31_add(b364, b366);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 163u, row_index, 0);
    unsigned b368 = stwo_m31_sub(b367, b87);
    unsigned b369 = base_params[209u];
    unsigned b370 = stwo_m31_mul(b368, b369);
    unsigned b371 = base_params[210u];
    unsigned b372 = stwo_m31_mul(b371, b77);
    unsigned b373 = stwo_m31_add(b370, b372);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 164u, row_index, 0);
    unsigned b374 = stwo_m31_sub(b373, b88);
    unsigned b375 = base_params[211u];
    unsigned b376 = stwo_m31_mul(b91, b375);
    unsigned b377 = stwo_m31_sub(b374, b376);
    unsigned b378 = base_params[212u];
    unsigned b379 = stwo_m31_mul(b377, b378);
    unsigned b380 = base_params[213u];
    unsigned b381 = stwo_m31_mul(b380, b78);
    unsigned b382 = stwo_m31_add(b379, b381);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 165u, row_index, 0);
    unsigned b383 = stwo_m31_sub(b382, b89);
    unsigned b384 = base_params[214u];
    unsigned b385 = stwo_m31_mul(b383, b384);
    unsigned b386 = base_params[215u];
    unsigned b387 = stwo_m31_mul(b386, b79);
    unsigned b388 = stwo_m31_add(b385, b387);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 166u, row_index, 0);
    unsigned b389 = stwo_m31_sub(b388, b90);
    unsigned b390 = base_params[216u];
    unsigned b391 = stwo_m31_mul(b91, b390);
    unsigned b392 = stwo_m31_sub(b389, b391);
    StwoCudaQm31 e9 = StwoCudaQm31{ b392, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b393 = stwo_m31_mul(b91, b91);
    unsigned b394 = stwo_m31_mul(b393, b91);
    unsigned b395 = stwo_m31_sub(b394, b91);
    StwoCudaQm31 e10 = StwoCudaQm31{ b395, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b396 = stwo_m31_mul(b334, b334);
    unsigned b397 = stwo_m31_mul(b396, b334);
    unsigned b398 = stwo_m31_sub(b397, b334);
    StwoCudaQm31 e11 = StwoCudaQm31{ b398, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b399 = stwo_m31_mul(b340, b340);
    unsigned b400 = stwo_m31_mul(b399, b340);
    unsigned b401 = stwo_m31_sub(b400, b340);
    StwoCudaQm31 e12 = StwoCudaQm31{ b401, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));
    unsigned b402 = stwo_m31_mul(b346, b346);
    unsigned b403 = stwo_m31_mul(b402, b346);
    unsigned b404 = stwo_m31_sub(b403, b346);
    StwoCudaQm31 e13 = StwoCudaQm31{ b404, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 13u)));
    unsigned b405 = stwo_m31_mul(b352, b352);
    unsigned b406 = stwo_m31_mul(b405, b352);
    unsigned b407 = stwo_m31_sub(b406, b352);
    StwoCudaQm31 e14 = StwoCudaQm31{ b407, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e14, stwo_load_qm31(random_coeff_powers, rc_base + 14u)));
    unsigned b408 = stwo_m31_mul(b358, b358);
    unsigned b409 = stwo_m31_mul(b408, b358);
    unsigned b410 = stwo_m31_sub(b409, b358);
    StwoCudaQm31 e15 = StwoCudaQm31{ b410, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 15u)));
    unsigned b411 = stwo_m31_mul(b364, b364);
    unsigned b412 = stwo_m31_mul(b411, b364);
    unsigned b413 = stwo_m31_sub(b412, b364);
    StwoCudaQm31 e16 = StwoCudaQm31{ b413, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e16, stwo_load_qm31(random_coeff_powers, rc_base + 16u)));
    unsigned b414 = stwo_m31_mul(b370, b370);
    unsigned b415 = stwo_m31_mul(b414, b370);
    unsigned b416 = stwo_m31_sub(b415, b370);
    StwoCudaQm31 e17 = StwoCudaQm31{ b416, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 17u)));
    unsigned b417 = stwo_m31_mul(b379, b379);
    unsigned b418 = stwo_m31_mul(b417, b379);
    unsigned b419 = stwo_m31_sub(b418, b379);
    StwoCudaQm31 e18 = StwoCudaQm31{ b419, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 18u)));
    unsigned b420 = stwo_m31_mul(b385, b385);
    unsigned b421 = stwo_m31_mul(b420, b385);
    unsigned b422 = stwo_m31_sub(b421, b385);
    StwoCudaQm31 e19 = StwoCudaQm31{ b422, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e19, stwo_load_qm31(random_coeff_powers, rc_base + 19u)));
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 168u, row_index, 0);
    unsigned b423 = stwo_m31_mul(b92, b92);
    unsigned b424 = stwo_m31_sub(b423, b92);
    StwoCudaQm31 e20 = StwoCudaQm31{ b424, b93, b93, b93 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e20, stwo_load_qm31(random_coeff_powers, rc_base + 20u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
