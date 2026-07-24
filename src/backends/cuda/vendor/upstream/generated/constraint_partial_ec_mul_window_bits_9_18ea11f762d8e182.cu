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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_7d4ed83494ffd2b8(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 264u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 229u, row_index, 0);
    unsigned b25 = base_params[241u];
    unsigned b26 = stwo_m31_add(b0, b25);
    unsigned b24 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b26, b24, b24, b24 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 265u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 266u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 267u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 230u, row_index, 0);
    unsigned b27 = base_params[243u];
    unsigned b28 = stwo_m31_add(b1, b27);
    e0 = StwoCudaQm31{ b28, b24, b24, b24 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 268u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 269u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 270u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 231u, row_index, 0);
    unsigned b29 = base_params[245u];
    unsigned b30 = stwo_m31_add(b2, b29);
    e1 = StwoCudaQm31{ b30, b24, b24, b24 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 271u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(ext_params, 272u);
    e4 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 273u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 232u, row_index, 0);
    unsigned b31 = base_params[247u];
    unsigned b32 = stwo_m31_add(b3, b31);
    e0 = StwoCudaQm31{ b32, b24, b24, b24 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 274u);
    e1 = stwo_qm31_add(e0, e5);
    e0 = stwo_load_qm31(ext_params, 275u);
    e5 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 276u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 233u, row_index, 0);
    unsigned b33 = base_params[249u];
    unsigned b34 = stwo_m31_add(b4, b33);
    e1 = StwoCudaQm31{ b34, b24, b24, b24 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 277u);
    e0 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(ext_params, 278u);
    e6 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 279u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 234u, row_index, 0);
    unsigned b35 = base_params[251u];
    unsigned b36 = stwo_m31_add(b5, b35);
    e0 = StwoCudaQm31{ b36, b24, b24, b24 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 280u);
    e1 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(ext_params, 281u);
    e7 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 282u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 235u, row_index, 0);
    unsigned b37 = base_params[253u];
    unsigned b38 = stwo_m31_add(b6, b37);
    e1 = StwoCudaQm31{ b38, b24, b24, b24 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 283u);
    e0 = stwo_qm31_add(e1, e8);
    e1 = stwo_load_qm31(ext_params, 284u);
    e8 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 285u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 236u, row_index, 0);
    unsigned b39 = base_params[255u];
    unsigned b40 = stwo_m31_add(b7, b39);
    e0 = StwoCudaQm31{ b40, b24, b24, b24 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 286u);
    e1 = stwo_qm31_add(e0, e9);
    e0 = stwo_load_qm31(ext_params, 287u);
    e9 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 288u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 237u, row_index, 0);
    unsigned b41 = base_params[257u];
    unsigned b42 = stwo_m31_add(b8, b41);
    e1 = StwoCudaQm31{ b42, b24, b24, b24 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 289u);
    e0 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(ext_params, 290u);
    e10 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 291u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 238u, row_index, 0);
    unsigned b43 = base_params[259u];
    unsigned b44 = stwo_m31_add(b9, b43);
    e0 = StwoCudaQm31{ b44, b24, b24, b24 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 292u);
    e1 = stwo_qm31_add(e0, e11);
    e0 = stwo_load_qm31(ext_params, 293u);
    e11 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 294u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 239u, row_index, 0);
    unsigned b45 = base_params[261u];
    unsigned b46 = stwo_m31_add(b10, b45);
    e1 = StwoCudaQm31{ b46, b24, b24, b24 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 295u);
    e0 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(ext_params, 296u);
    e12 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 297u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 240u, row_index, 0);
    unsigned b47 = base_params[263u];
    unsigned b48 = stwo_m31_add(b11, b47);
    e0 = StwoCudaQm31{ b48, b24, b24, b24 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 298u);
    e1 = stwo_qm31_add(e0, e13);
    e0 = stwo_load_qm31(ext_params, 299u);
    e13 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 300u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 241u, row_index, 0);
    unsigned b49 = base_params[265u];
    unsigned b50 = stwo_m31_add(b12, b49);
    e1 = StwoCudaQm31{ b50, b24, b24, b24 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 301u);
    e0 = stwo_qm31_add(e1, e14);
    e1 = stwo_load_qm31(ext_params, 302u);
    e14 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 303u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 242u, row_index, 0);
    unsigned b51 = base_params[267u];
    unsigned b52 = stwo_m31_add(b13, b51);
    e0 = StwoCudaQm31{ b52, b24, b24, b24 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 304u);
    e1 = stwo_qm31_add(e0, e15);
    e0 = stwo_load_qm31(ext_params, 305u);
    e15 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 306u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 243u, row_index, 0);
    unsigned b53 = base_params[269u];
    unsigned b54 = stwo_m31_add(b14, b53);
    e1 = StwoCudaQm31{ b54, b24, b24, b24 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 307u);
    e0 = stwo_qm31_add(e1, e16);
    e1 = stwo_load_qm31(ext_params, 308u);
    e16 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 309u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 244u, row_index, 0);
    unsigned b55 = base_params[271u];
    unsigned b56 = stwo_m31_add(b15, b55);
    e0 = StwoCudaQm31{ b56, b24, b24, b24 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 310u);
    e1 = stwo_qm31_add(e0, e17);
    e0 = stwo_load_qm31(ext_params, 311u);
    e17 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 312u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 245u, row_index, 0);
    unsigned b57 = base_params[273u];
    unsigned b58 = stwo_m31_add(b16, b57);
    e1 = StwoCudaQm31{ b58, b24, b24, b24 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 313u);
    e0 = stwo_qm31_add(e1, e18);
    e1 = stwo_load_qm31(ext_params, 314u);
    e18 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 315u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 246u, row_index, 0);
    unsigned b59 = base_params[275u];
    unsigned b60 = stwo_m31_add(b17, b59);
    e0 = StwoCudaQm31{ b60, b24, b24, b24 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 316u);
    e1 = stwo_qm31_add(e0, e19);
    e0 = stwo_load_qm31(ext_params, 317u);
    e19 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 318u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 247u, row_index, 0);
    unsigned b61 = base_params[277u];
    unsigned b62 = stwo_m31_add(b18, b61);
    e1 = StwoCudaQm31{ b62, b24, b24, b24 };
    StwoCudaQm31 e20 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 319u);
    e0 = stwo_qm31_add(e1, e20);
    e1 = stwo_load_qm31(ext_params, 320u);
    e20 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 321u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 248u, row_index, 0);
    unsigned b63 = base_params[280u];
    unsigned b64 = stwo_m31_add(b19, b63);
    e0 = StwoCudaQm31{ b64, b24, b24, b24 };
    StwoCudaQm31 e21 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 322u);
    e1 = stwo_qm31_add(e0, e21);
    e0 = stwo_load_qm31(ext_params, 323u);
    e21 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 324u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 249u, row_index, 0);
    unsigned b65 = base_params[282u];
    unsigned b66 = stwo_m31_add(b20, b65);
    e1 = StwoCudaQm31{ b66, b24, b24, b24 };
    StwoCudaQm31 e22 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 325u);
    e0 = stwo_qm31_add(e1, e22);
    e1 = stwo_load_qm31(ext_params, 326u);
    e22 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 327u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 250u, row_index, 0);
    unsigned b67 = base_params[284u];
    unsigned b68 = stwo_m31_add(b21, b67);
    e0 = StwoCudaQm31{ b68, b24, b24, b24 };
    StwoCudaQm31 e23 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 328u);
    e1 = stwo_qm31_add(e0, e23);
    e0 = stwo_load_qm31(ext_params, 329u);
    e23 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 330u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 251u, row_index, 0);
    unsigned b69 = base_params[286u];
    unsigned b70 = stwo_m31_add(b22, b69);
    e1 = StwoCudaQm31{ b70, b24, b24, b24 };
    StwoCudaQm31 e24 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 331u);
    e0 = stwo_qm31_add(e1, e24);
    e1 = stwo_load_qm31(ext_params, 332u);
    e24 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 333u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 252u, row_index, 0);
    unsigned b71 = base_params[288u];
    unsigned b72 = stwo_m31_add(b23, b71);
    e0 = StwoCudaQm31{ b72, b24, b24, b24 };
    StwoCudaQm31 e25 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 334u);
    e1 = stwo_qm31_add(e0, e25);
    e0 = stwo_load_qm31(ext_params, 335u);
    e25 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 715u);
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_load_qm31(ext_params, 716u);
    StwoCudaQm31 e26 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e1, e26);
    e26 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 717u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 718u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 719u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 720u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 721u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(ext_params, 722u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 723u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(ext_params, 724u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(ext_params, 725u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(ext_params, 726u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(ext_params, 727u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(ext_params, 728u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 729u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(ext_params, 730u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(ext_params, 731u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(ext_params, 732u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(ext_params, 733u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(ext_params, 734u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e20, e21);
    e21 = stwo_load_qm31(ext_params, 735u);
    e20 = stwo_qm31_mul(e23, e21);
    e21 = stwo_load_qm31(ext_params, 736u);
    e18 = stwo_qm31_mul(e22, e21);
    e21 = stwo_qm31_add(e20, e18);
    e18 = stwo_qm31_mul(e22, e23);
    e23 = stwo_load_qm31(ext_params, 737u);
    e22 = stwo_qm31_mul(e25, e23);
    e23 = stwo_load_qm31(ext_params, 738u);
    e20 = stwo_qm31_mul(e24, e23);
    e23 = stwo_qm31_add(e22, e20);
    e20 = stwo_qm31_mul(e24, e25);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 116u, row_index, 0);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 117u, row_index, 0);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 118u, row_index, 0);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 119u, row_index, 0);
    e25 = StwoCudaQm31{ b73, b74, b75, b76 };
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 120u, row_index, 0);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 121u, row_index, 0);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 122u, row_index, 0);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 123u, row_index, 0);
    e24 = StwoCudaQm31{ b77, b78, b79, b80 };
    e22 = stwo_qm31_sub(e24, e25);
    e25 = stwo_qm31_mul(e22, e26);
    e22 = stwo_qm31_sub(e25, e0);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e22, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 124u, row_index, 0);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 125u, row_index, 0);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 126u, row_index, 0);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 127u, row_index, 0);
    e25 = StwoCudaQm31{ b81, b82, b83, b84 };
    e0 = stwo_qm31_sub(e25, e24);
    e24 = stwo_qm31_mul(e0, e1);
    e0 = stwo_qm31_sub(e24, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 128u, row_index, 0);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 129u, row_index, 0);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 130u, row_index, 0);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 131u, row_index, 0);
    e24 = StwoCudaQm31{ b85, b86, b87, b88 };
    e3 = stwo_qm31_sub(e24, e25);
    e25 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e25, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 132u, row_index, 0);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 133u, row_index, 0);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 134u, row_index, 0);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 135u, row_index, 0);
    e25 = StwoCudaQm31{ b89, b90, b91, b92 };
    e5 = stwo_qm31_sub(e25, e24);
    e24 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e24, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 136u, row_index, 0);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 137u, row_index, 0);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 138u, row_index, 0);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 139u, row_index, 0);
    e24 = StwoCudaQm31{ b93, b94, b95, b96 };
    e7 = stwo_qm31_sub(e24, e25);
    e25 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e25, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 140u, row_index, 0);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 141u, row_index, 0);
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 142u, row_index, 0);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 143u, row_index, 0);
    e25 = StwoCudaQm31{ b97, b98, b99, b100 };
    e9 = stwo_qm31_sub(e25, e24);
    e24 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e24, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 144u, row_index, 0);
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 145u, row_index, 0);
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 146u, row_index, 0);
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 147u, row_index, 0);
    e24 = StwoCudaQm31{ b101, b102, b103, b104 };
    e11 = stwo_qm31_sub(e24, e25);
    e25 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e25, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 148u, row_index, 0);
    unsigned b106 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 149u, row_index, 0);
    unsigned b107 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 150u, row_index, 0);
    unsigned b108 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 151u, row_index, 0);
    e25 = StwoCudaQm31{ b105, b106, b107, b108 };
    e13 = stwo_qm31_sub(e25, e24);
    e24 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e24, e15);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b109 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 152u, row_index, 0);
    unsigned b110 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 153u, row_index, 0);
    unsigned b111 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 154u, row_index, 0);
    unsigned b112 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 155u, row_index, 0);
    e24 = StwoCudaQm31{ b109, b110, b111, b112 };
    e15 = stwo_qm31_sub(e24, e25);
    e25 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e25, e17);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b113 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 156u, row_index, 0);
    unsigned b114 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 157u, row_index, 0);
    unsigned b115 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 158u, row_index, 0);
    unsigned b116 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 159u, row_index, 0);
    e25 = StwoCudaQm31{ b113, b114, b115, b116 };
    e17 = stwo_qm31_sub(e25, e24);
    e24 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e24, e19);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b117 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 160u, row_index, 0);
    unsigned b118 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 161u, row_index, 0);
    unsigned b119 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 162u, row_index, 0);
    unsigned b120 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 163u, row_index, 0);
    e24 = StwoCudaQm31{ b117, b118, b119, b120 };
    e19 = stwo_qm31_sub(e24, e25);
    e25 = stwo_qm31_mul(e19, e18);
    e19 = stwo_qm31_sub(e25, e21);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e19, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b121 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 164u, row_index, 0);
    unsigned b122 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 165u, row_index, 0);
    unsigned b123 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 166u, row_index, 0);
    unsigned b124 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 167u, row_index, 0);
    e25 = StwoCudaQm31{ b121, b122, b123, b124 };
    e21 = stwo_qm31_sub(e25, e24);
    e25 = stwo_qm31_mul(e21, e20);
    e21 = stwo_qm31_sub(e25, e23);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e21, stwo_load_qm31(random_coeff_powers, rc_base + 11u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
