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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_75f5c569915fc45a(
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
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 62u, row_index, 0);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 63u, row_index, 0);
    unsigned b102 = base_params[37u];
    unsigned b103 = stwo_m31_mul(b1, b102);
    unsigned b104 = stwo_m31_add(b0, b103);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 64u, row_index, 0);
    unsigned b105 = base_params[38u];
    unsigned b106 = stwo_m31_mul(b2, b105);
    unsigned b107 = stwo_m31_add(b104, b106);
    unsigned b156 = base_params[97u];
    unsigned b157 = stwo_m31_add(b107, b156);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 112u, row_index, 0);
    unsigned b158 = stwo_m31_sub(b157, b28);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 122u, row_index, 0);
    unsigned b159 = stwo_m31_sub(b158, b38);
    unsigned b160 = base_params[98u];
    unsigned b161 = stwo_m31_mul(b159, b160);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 65u, row_index, 0);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 66u, row_index, 0);
    unsigned b108 = base_params[39u];
    unsigned b109 = stwo_m31_mul(b4, b108);
    unsigned b110 = stwo_m31_add(b3, b109);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 67u, row_index, 0);
    unsigned b111 = base_params[40u];
    unsigned b112 = stwo_m31_mul(b5, b111);
    unsigned b113 = stwo_m31_add(b110, b112);
    unsigned b162 = stwo_m31_add(b161, b113);
    unsigned b163 = base_params[99u];
    unsigned b164 = stwo_m31_add(b162, b163);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 113u, row_index, 0);
    unsigned b165 = stwo_m31_sub(b164, b29);
    unsigned b166 = base_params[100u];
    unsigned b167 = stwo_m31_mul(b165, b166);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 68u, row_index, 0);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 69u, row_index, 0);
    unsigned b114 = base_params[41u];
    unsigned b115 = stwo_m31_mul(b7, b114);
    unsigned b116 = stwo_m31_add(b6, b115);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 70u, row_index, 0);
    unsigned b117 = base_params[42u];
    unsigned b118 = stwo_m31_mul(b8, b117);
    unsigned b119 = stwo_m31_add(b116, b118);
    unsigned b168 = stwo_m31_add(b167, b119);
    unsigned b169 = base_params[101u];
    unsigned b170 = stwo_m31_add(b168, b169);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 114u, row_index, 0);
    unsigned b171 = stwo_m31_sub(b170, b30);
    unsigned b172 = base_params[102u];
    unsigned b173 = stwo_m31_mul(b171, b172);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 71u, row_index, 0);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 72u, row_index, 0);
    unsigned b120 = base_params[43u];
    unsigned b121 = stwo_m31_mul(b10, b120);
    unsigned b122 = stwo_m31_add(b9, b121);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 73u, row_index, 0);
    unsigned b123 = base_params[44u];
    unsigned b124 = stwo_m31_mul(b11, b123);
    unsigned b125 = stwo_m31_add(b122, b124);
    unsigned b174 = stwo_m31_add(b173, b125);
    unsigned b175 = base_params[103u];
    unsigned b176 = stwo_m31_add(b174, b175);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 115u, row_index, 0);
    unsigned b177 = stwo_m31_sub(b176, b31);
    unsigned b178 = base_params[104u];
    unsigned b179 = stwo_m31_mul(b177, b178);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 74u, row_index, 0);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 75u, row_index, 0);
    unsigned b126 = base_params[45u];
    unsigned b127 = stwo_m31_mul(b13, b126);
    unsigned b128 = stwo_m31_add(b12, b127);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 76u, row_index, 0);
    unsigned b129 = base_params[46u];
    unsigned b130 = stwo_m31_mul(b14, b129);
    unsigned b131 = stwo_m31_add(b128, b130);
    unsigned b180 = stwo_m31_add(b179, b131);
    unsigned b181 = base_params[105u];
    unsigned b182 = stwo_m31_add(b180, b181);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 116u, row_index, 0);
    unsigned b183 = stwo_m31_sub(b182, b32);
    unsigned b184 = base_params[106u];
    unsigned b185 = stwo_m31_mul(b183, b184);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 77u, row_index, 0);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 78u, row_index, 0);
    unsigned b132 = base_params[47u];
    unsigned b133 = stwo_m31_mul(b16, b132);
    unsigned b134 = stwo_m31_add(b15, b133);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 79u, row_index, 0);
    unsigned b135 = base_params[48u];
    unsigned b136 = stwo_m31_mul(b17, b135);
    unsigned b137 = stwo_m31_add(b134, b136);
    unsigned b186 = stwo_m31_add(b185, b137);
    unsigned b187 = base_params[107u];
    unsigned b188 = stwo_m31_add(b186, b187);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 117u, row_index, 0);
    unsigned b189 = stwo_m31_sub(b188, b33);
    unsigned b190 = base_params[108u];
    unsigned b191 = stwo_m31_mul(b189, b190);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 80u, row_index, 0);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 81u, row_index, 0);
    unsigned b138 = base_params[49u];
    unsigned b139 = stwo_m31_mul(b19, b138);
    unsigned b140 = stwo_m31_add(b18, b139);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 82u, row_index, 0);
    unsigned b141 = base_params[50u];
    unsigned b142 = stwo_m31_mul(b20, b141);
    unsigned b143 = stwo_m31_add(b140, b142);
    unsigned b192 = stwo_m31_add(b191, b143);
    unsigned b193 = base_params[109u];
    unsigned b194 = stwo_m31_add(b192, b193);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 118u, row_index, 0);
    unsigned b195 = stwo_m31_sub(b194, b34);
    unsigned b196 = base_params[110u];
    unsigned b197 = stwo_m31_mul(b195, b196);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 83u, row_index, 0);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 84u, row_index, 0);
    unsigned b144 = base_params[51u];
    unsigned b145 = stwo_m31_mul(b22, b144);
    unsigned b146 = stwo_m31_add(b21, b145);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 85u, row_index, 0);
    unsigned b147 = base_params[52u];
    unsigned b148 = stwo_m31_mul(b23, b147);
    unsigned b149 = stwo_m31_add(b146, b148);
    unsigned b198 = stwo_m31_add(b197, b149);
    unsigned b199 = base_params[111u];
    unsigned b200 = stwo_m31_add(b198, b199);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 119u, row_index, 0);
    unsigned b201 = stwo_m31_sub(b200, b35);
    unsigned b202 = base_params[112u];
    unsigned b203 = stwo_m31_mul(b38, b202);
    unsigned b204 = stwo_m31_sub(b201, b203);
    unsigned b205 = base_params[113u];
    unsigned b206 = stwo_m31_mul(b204, b205);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 86u, row_index, 0);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 87u, row_index, 0);
    unsigned b150 = base_params[53u];
    unsigned b151 = stwo_m31_mul(b25, b150);
    unsigned b152 = stwo_m31_add(b24, b151);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 88u, row_index, 0);
    unsigned b153 = base_params[54u];
    unsigned b154 = stwo_m31_mul(b26, b153);
    unsigned b155 = stwo_m31_add(b152, b154);
    unsigned b207 = stwo_m31_add(b206, b155);
    unsigned b208 = base_params[114u];
    unsigned b209 = stwo_m31_add(b207, b208);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 120u, row_index, 0);
    unsigned b210 = stwo_m31_sub(b209, b36);
    unsigned b211 = base_params[115u];
    unsigned b212 = stwo_m31_mul(b210, b211);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 89u, row_index, 0);
    unsigned b213 = stwo_m31_add(b212, b27);
    unsigned b214 = base_params[116u];
    unsigned b215 = stwo_m31_add(b213, b214);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 121u, row_index, 0);
    unsigned b216 = stwo_m31_sub(b215, b37);
    unsigned b217 = base_params[117u];
    unsigned b218 = stwo_m31_mul(b38, b217);
    unsigned b219 = stwo_m31_sub(b216, b218);
    unsigned b101 = base_params[0u];
    StwoCudaQm31 e0 = StwoCudaQm31{ b219, b101, b101, b101 };
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b220 = stwo_m31_mul(b38, b38);
    unsigned b221 = stwo_m31_mul(b220, b38);
    unsigned b222 = stwo_m31_sub(b221, b38);
    StwoCudaQm31 e1 = StwoCudaQm31{ b222, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b223 = stwo_m31_mul(b161, b161);
    unsigned b224 = stwo_m31_mul(b223, b161);
    unsigned b225 = stwo_m31_sub(b224, b161);
    StwoCudaQm31 e2 = StwoCudaQm31{ b225, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b226 = stwo_m31_mul(b167, b167);
    unsigned b227 = stwo_m31_mul(b226, b167);
    unsigned b228 = stwo_m31_sub(b227, b167);
    StwoCudaQm31 e3 = StwoCudaQm31{ b228, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b229 = stwo_m31_mul(b173, b173);
    unsigned b230 = stwo_m31_mul(b229, b173);
    unsigned b231 = stwo_m31_sub(b230, b173);
    StwoCudaQm31 e4 = StwoCudaQm31{ b231, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b232 = stwo_m31_mul(b179, b179);
    unsigned b233 = stwo_m31_mul(b232, b179);
    unsigned b234 = stwo_m31_sub(b233, b179);
    StwoCudaQm31 e5 = StwoCudaQm31{ b234, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b235 = stwo_m31_mul(b185, b185);
    unsigned b236 = stwo_m31_mul(b235, b185);
    unsigned b237 = stwo_m31_sub(b236, b185);
    StwoCudaQm31 e6 = StwoCudaQm31{ b237, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e6, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b238 = stwo_m31_mul(b191, b191);
    unsigned b239 = stwo_m31_mul(b238, b191);
    unsigned b240 = stwo_m31_sub(b239, b191);
    StwoCudaQm31 e7 = StwoCudaQm31{ b240, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b241 = stwo_m31_mul(b197, b197);
    unsigned b242 = stwo_m31_mul(b241, b197);
    unsigned b243 = stwo_m31_sub(b242, b197);
    StwoCudaQm31 e8 = StwoCudaQm31{ b243, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b244 = stwo_m31_mul(b206, b206);
    unsigned b245 = stwo_m31_mul(b244, b206);
    unsigned b246 = stwo_m31_sub(b245, b206);
    StwoCudaQm31 e9 = StwoCudaQm31{ b246, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b247 = stwo_m31_mul(b212, b212);
    unsigned b248 = stwo_m31_mul(b247, b212);
    unsigned b249 = stwo_m31_sub(b248, b212);
    StwoCudaQm31 e10 = StwoCudaQm31{ b249, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e10, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 123u, row_index, 0);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 133u, row_index, 0);
    unsigned b250 = stwo_m31_add(b39, b49);
    unsigned b251 = base_params[119u];
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 153u, row_index, 0);
    unsigned b252 = stwo_m31_mul(b251, b59);
    unsigned b253 = stwo_m31_sub(b250, b252);
    unsigned b254 = base_params[120u];
    unsigned b255 = stwo_m31_add(b253, b254);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 163u, row_index, 0);
    unsigned b256 = stwo_m31_sub(b255, b69);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 173u, row_index, 0);
    unsigned b257 = stwo_m31_sub(b256, b79);
    unsigned b258 = base_params[121u];
    unsigned b259 = stwo_m31_mul(b257, b258);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 124u, row_index, 0);
    unsigned b260 = stwo_m31_add(b259, b40);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 134u, row_index, 0);
    unsigned b261 = stwo_m31_add(b260, b50);
    unsigned b262 = base_params[122u];
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 154u, row_index, 0);
    unsigned b263 = stwo_m31_mul(b262, b60);
    unsigned b264 = stwo_m31_sub(b261, b263);
    unsigned b265 = base_params[123u];
    unsigned b266 = stwo_m31_add(b264, b265);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 164u, row_index, 0);
    unsigned b267 = stwo_m31_sub(b266, b70);
    unsigned b268 = base_params[124u];
    unsigned b269 = stwo_m31_mul(b267, b268);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 125u, row_index, 0);
    unsigned b270 = stwo_m31_add(b269, b41);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 135u, row_index, 0);
    unsigned b271 = stwo_m31_add(b270, b51);
    unsigned b272 = base_params[125u];
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 155u, row_index, 0);
    unsigned b273 = stwo_m31_mul(b272, b61);
    unsigned b274 = stwo_m31_sub(b271, b273);
    unsigned b275 = base_params[126u];
    unsigned b276 = stwo_m31_add(b274, b275);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 165u, row_index, 0);
    unsigned b277 = stwo_m31_sub(b276, b71);
    unsigned b278 = base_params[127u];
    unsigned b279 = stwo_m31_mul(b277, b278);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 126u, row_index, 0);
    unsigned b280 = stwo_m31_add(b279, b42);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 136u, row_index, 0);
    unsigned b281 = stwo_m31_add(b280, b52);
    unsigned b282 = base_params[128u];
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 156u, row_index, 0);
    unsigned b283 = stwo_m31_mul(b282, b62);
    unsigned b284 = stwo_m31_sub(b281, b283);
    unsigned b285 = base_params[129u];
    unsigned b286 = stwo_m31_add(b284, b285);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 166u, row_index, 0);
    unsigned b287 = stwo_m31_sub(b286, b72);
    unsigned b288 = base_params[130u];
    unsigned b289 = stwo_m31_mul(b287, b288);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 127u, row_index, 0);
    unsigned b290 = stwo_m31_add(b289, b43);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 137u, row_index, 0);
    unsigned b291 = stwo_m31_add(b290, b53);
    unsigned b292 = base_params[131u];
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 157u, row_index, 0);
    unsigned b293 = stwo_m31_mul(b292, b63);
    unsigned b294 = stwo_m31_sub(b291, b293);
    unsigned b295 = base_params[132u];
    unsigned b296 = stwo_m31_add(b294, b295);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 167u, row_index, 0);
    unsigned b297 = stwo_m31_sub(b296, b73);
    unsigned b298 = base_params[133u];
    unsigned b299 = stwo_m31_mul(b297, b298);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 128u, row_index, 0);
    unsigned b300 = stwo_m31_add(b299, b44);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 138u, row_index, 0);
    unsigned b301 = stwo_m31_add(b300, b54);
    unsigned b302 = base_params[134u];
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 158u, row_index, 0);
    unsigned b303 = stwo_m31_mul(b302, b64);
    unsigned b304 = stwo_m31_sub(b301, b303);
    unsigned b305 = base_params[135u];
    unsigned b306 = stwo_m31_add(b304, b305);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 168u, row_index, 0);
    unsigned b307 = stwo_m31_sub(b306, b74);
    unsigned b308 = base_params[136u];
    unsigned b309 = stwo_m31_mul(b307, b308);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 129u, row_index, 0);
    unsigned b310 = stwo_m31_add(b309, b45);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 139u, row_index, 0);
    unsigned b311 = stwo_m31_add(b310, b55);
    unsigned b312 = base_params[137u];
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 159u, row_index, 0);
    unsigned b313 = stwo_m31_mul(b312, b65);
    unsigned b314 = stwo_m31_sub(b311, b313);
    unsigned b315 = base_params[138u];
    unsigned b316 = stwo_m31_add(b314, b315);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 169u, row_index, 0);
    unsigned b317 = stwo_m31_sub(b316, b75);
    unsigned b318 = base_params[139u];
    unsigned b319 = stwo_m31_mul(b317, b318);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 130u, row_index, 0);
    unsigned b320 = stwo_m31_add(b319, b46);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 140u, row_index, 0);
    unsigned b321 = stwo_m31_add(b320, b56);
    unsigned b322 = base_params[140u];
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 160u, row_index, 0);
    unsigned b323 = stwo_m31_mul(b322, b66);
    unsigned b324 = stwo_m31_sub(b321, b323);
    unsigned b325 = base_params[141u];
    unsigned b326 = stwo_m31_add(b324, b325);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 170u, row_index, 0);
    unsigned b327 = stwo_m31_sub(b326, b76);
    unsigned b328 = base_params[142u];
    unsigned b329 = stwo_m31_mul(b79, b328);
    unsigned b330 = stwo_m31_sub(b327, b329);
    unsigned b331 = base_params[143u];
    unsigned b332 = stwo_m31_mul(b330, b331);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 131u, row_index, 0);
    unsigned b333 = stwo_m31_add(b332, b47);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 141u, row_index, 0);
    unsigned b334 = stwo_m31_add(b333, b57);
    unsigned b335 = base_params[144u];
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 161u, row_index, 0);
    unsigned b336 = stwo_m31_mul(b335, b67);
    unsigned b337 = stwo_m31_sub(b334, b336);
    unsigned b338 = base_params[145u];
    unsigned b339 = stwo_m31_add(b337, b338);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 171u, row_index, 0);
    unsigned b340 = stwo_m31_sub(b339, b77);
    unsigned b341 = base_params[146u];
    unsigned b342 = stwo_m31_mul(b340, b341);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 132u, row_index, 0);
    unsigned b343 = stwo_m31_add(b342, b48);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 142u, row_index, 0);
    unsigned b344 = stwo_m31_add(b343, b58);
    unsigned b345 = base_params[147u];
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 162u, row_index, 0);
    unsigned b346 = stwo_m31_mul(b345, b68);
    unsigned b347 = stwo_m31_sub(b344, b346);
    unsigned b348 = base_params[148u];
    unsigned b349 = stwo_m31_add(b347, b348);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 172u, row_index, 0);
    unsigned b350 = stwo_m31_sub(b349, b78);
    unsigned b351 = base_params[149u];
    unsigned b352 = stwo_m31_mul(b79, b351);
    unsigned b353 = stwo_m31_sub(b350, b352);
    StwoCudaQm31 e11 = StwoCudaQm31{ b353, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));
    unsigned b354 = base_params[160u];
    unsigned b355 = stwo_m31_mul(b354, b39);
    unsigned b356 = base_params[161u];
    unsigned b357 = stwo_m31_mul(b356, b59);
    unsigned b358 = stwo_m31_add(b355, b357);
    unsigned b359 = base_params[162u];
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 174u, row_index, 0);
    unsigned b360 = stwo_m31_mul(b359, b80);
    unsigned b361 = stwo_m31_sub(b358, b360);
    unsigned b362 = base_params[163u];
    unsigned b363 = stwo_m31_add(b361, b362);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 184u, row_index, 0);
    unsigned b364 = stwo_m31_sub(b363, b90);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 194u, row_index, 0);
    unsigned b365 = stwo_m31_sub(b364, b100);
    unsigned b366 = base_params[164u];
    unsigned b367 = stwo_m31_mul(b365, b366);
    unsigned b368 = base_params[165u];
    unsigned b369 = stwo_m31_mul(b368, b40);
    unsigned b370 = stwo_m31_add(b367, b369);
    unsigned b371 = base_params[166u];
    unsigned b372 = stwo_m31_mul(b371, b60);
    unsigned b373 = stwo_m31_add(b370, b372);
    unsigned b374 = base_params[167u];
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 175u, row_index, 0);
    unsigned b375 = stwo_m31_mul(b374, b81);
    unsigned b376 = stwo_m31_sub(b373, b375);
    unsigned b377 = base_params[168u];
    unsigned b378 = stwo_m31_add(b376, b377);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 185u, row_index, 0);
    unsigned b379 = stwo_m31_sub(b378, b91);
    unsigned b380 = base_params[169u];
    unsigned b381 = stwo_m31_mul(b379, b380);
    unsigned b382 = base_params[170u];
    unsigned b383 = stwo_m31_mul(b382, b41);
    unsigned b384 = stwo_m31_add(b381, b383);
    unsigned b385 = base_params[171u];
    unsigned b386 = stwo_m31_mul(b385, b61);
    unsigned b387 = stwo_m31_add(b384, b386);
    unsigned b388 = base_params[172u];
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 176u, row_index, 0);
    unsigned b389 = stwo_m31_mul(b388, b82);
    unsigned b390 = stwo_m31_sub(b387, b389);
    unsigned b391 = base_params[173u];
    unsigned b392 = stwo_m31_add(b390, b391);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 186u, row_index, 0);
    unsigned b393 = stwo_m31_sub(b392, b92);
    unsigned b394 = base_params[174u];
    unsigned b395 = stwo_m31_mul(b393, b394);
    unsigned b396 = base_params[175u];
    unsigned b397 = stwo_m31_mul(b396, b42);
    unsigned b398 = stwo_m31_add(b395, b397);
    unsigned b399 = base_params[176u];
    unsigned b400 = stwo_m31_mul(b399, b62);
    unsigned b401 = stwo_m31_add(b398, b400);
    unsigned b402 = base_params[177u];
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 177u, row_index, 0);
    unsigned b403 = stwo_m31_mul(b402, b83);
    unsigned b404 = stwo_m31_sub(b401, b403);
    unsigned b405 = base_params[178u];
    unsigned b406 = stwo_m31_add(b404, b405);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 187u, row_index, 0);
    unsigned b407 = stwo_m31_sub(b406, b93);
    unsigned b408 = base_params[179u];
    unsigned b409 = stwo_m31_mul(b407, b408);
    unsigned b410 = base_params[180u];
    unsigned b411 = stwo_m31_mul(b410, b43);
    unsigned b412 = stwo_m31_add(b409, b411);
    unsigned b413 = base_params[181u];
    unsigned b414 = stwo_m31_mul(b413, b63);
    unsigned b415 = stwo_m31_add(b412, b414);
    unsigned b416 = base_params[182u];
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 178u, row_index, 0);
    unsigned b417 = stwo_m31_mul(b416, b84);
    unsigned b418 = stwo_m31_sub(b415, b417);
    unsigned b419 = base_params[183u];
    unsigned b420 = stwo_m31_add(b418, b419);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 188u, row_index, 0);
    unsigned b421 = stwo_m31_sub(b420, b94);
    unsigned b422 = base_params[184u];
    unsigned b423 = stwo_m31_mul(b421, b422);
    unsigned b424 = base_params[185u];
    unsigned b425 = stwo_m31_mul(b424, b44);
    unsigned b426 = stwo_m31_add(b423, b425);
    unsigned b427 = base_params[186u];
    unsigned b428 = stwo_m31_mul(b427, b64);
    unsigned b429 = stwo_m31_add(b426, b428);
    unsigned b430 = base_params[187u];
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 179u, row_index, 0);
    unsigned b431 = stwo_m31_mul(b430, b85);
    unsigned b432 = stwo_m31_sub(b429, b431);
    unsigned b433 = base_params[188u];
    unsigned b434 = stwo_m31_add(b432, b433);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 189u, row_index, 0);
    unsigned b435 = stwo_m31_sub(b434, b95);
    unsigned b436 = base_params[189u];
    unsigned b437 = stwo_m31_mul(b435, b436);
    unsigned b438 = base_params[190u];
    unsigned b439 = stwo_m31_mul(b438, b45);
    unsigned b440 = stwo_m31_add(b437, b439);
    unsigned b441 = base_params[191u];
    unsigned b442 = stwo_m31_mul(b441, b65);
    unsigned b443 = stwo_m31_add(b440, b442);
    unsigned b444 = base_params[192u];
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 180u, row_index, 0);
    unsigned b445 = stwo_m31_mul(b444, b86);
    unsigned b446 = stwo_m31_sub(b443, b445);
    unsigned b447 = base_params[193u];
    unsigned b448 = stwo_m31_add(b446, b447);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 190u, row_index, 0);
    unsigned b449 = stwo_m31_sub(b448, b96);
    unsigned b450 = base_params[194u];
    unsigned b451 = stwo_m31_mul(b449, b450);
    unsigned b452 = base_params[195u];
    unsigned b453 = stwo_m31_mul(b452, b46);
    unsigned b454 = stwo_m31_add(b451, b453);
    unsigned b455 = base_params[196u];
    unsigned b456 = stwo_m31_mul(b455, b66);
    unsigned b457 = stwo_m31_add(b454, b456);
    unsigned b458 = base_params[197u];
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 181u, row_index, 0);
    unsigned b459 = stwo_m31_mul(b458, b87);
    unsigned b460 = stwo_m31_sub(b457, b459);
    unsigned b461 = base_params[198u];
    unsigned b462 = stwo_m31_add(b460, b461);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 191u, row_index, 0);
    unsigned b463 = stwo_m31_sub(b462, b97);
    unsigned b464 = base_params[199u];
    unsigned b465 = stwo_m31_mul(b100, b464);
    unsigned b466 = stwo_m31_sub(b463, b465);
    unsigned b467 = base_params[200u];
    unsigned b468 = stwo_m31_mul(b466, b467);
    unsigned b469 = base_params[201u];
    unsigned b470 = stwo_m31_mul(b469, b47);
    unsigned b471 = stwo_m31_add(b468, b470);
    unsigned b472 = base_params[202u];
    unsigned b473 = stwo_m31_mul(b472, b67);
    unsigned b474 = stwo_m31_add(b471, b473);
    unsigned b475 = base_params[203u];
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 182u, row_index, 0);
    unsigned b476 = stwo_m31_mul(b475, b88);
    unsigned b477 = stwo_m31_sub(b474, b476);
    unsigned b478 = base_params[204u];
    unsigned b479 = stwo_m31_add(b477, b478);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 192u, row_index, 0);
    unsigned b480 = stwo_m31_sub(b479, b98);
    unsigned b481 = base_params[205u];
    unsigned b482 = stwo_m31_mul(b480, b481);
    unsigned b483 = base_params[206u];
    unsigned b484 = stwo_m31_mul(b483, b48);
    unsigned b485 = stwo_m31_add(b482, b484);
    unsigned b486 = base_params[207u];
    unsigned b487 = stwo_m31_mul(b486, b68);
    unsigned b488 = stwo_m31_add(b485, b487);
    unsigned b489 = base_params[208u];
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 183u, row_index, 0);
    unsigned b490 = stwo_m31_mul(b489, b89);
    unsigned b491 = stwo_m31_sub(b488, b490);
    unsigned b492 = base_params[209u];
    unsigned b493 = stwo_m31_add(b491, b492);
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 193u, row_index, 0);
    unsigned b494 = stwo_m31_sub(b493, b99);
    unsigned b495 = base_params[210u];
    unsigned b496 = stwo_m31_mul(b100, b495);
    unsigned b497 = stwo_m31_sub(b494, b496);
    StwoCudaQm31 e12 = StwoCudaQm31{ b497, b101, b101, b101 };
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e12, stwo_load_qm31(random_coeff_powers, rc_base + 12u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
