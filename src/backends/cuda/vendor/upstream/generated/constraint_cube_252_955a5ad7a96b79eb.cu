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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_d9eb59a22046b600(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 244u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 108u, row_index, 0);
    unsigned b26 = base_params[18u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b0, b26, b26, b26 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 245u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 246u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 109u, row_index, 0);
    e2 = StwoCudaQm31{ b1, b26, b26, b26 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 247u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 248u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 110u, row_index, 0);
    e2 = StwoCudaQm31{ b2, b26, b26, b26 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 249u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 250u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 111u, row_index, 0);
    e1 = StwoCudaQm31{ b3, b26, b26, b26 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 251u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 252u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 112u, row_index, 0);
    unsigned b27 = base_params[252u];
    unsigned b28 = stwo_m31_add(b4, b27);
    e1 = StwoCudaQm31{ b28, b26, b26, b26 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 253u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 254u);
    e2 = stwo_qm31_sub(e4, e1);
    e1 = stwo_load_qm31(ext_params, 255u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 113u, row_index, 0);
    unsigned b29 = base_params[254u];
    unsigned b30 = stwo_m31_add(b5, b29);
    e4 = StwoCudaQm31{ b30, b26, b26, b26 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_load_qm31(ext_params, 256u);
    e1 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(ext_params, 257u);
    e5 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 258u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 114u, row_index, 0);
    unsigned b31 = base_params[256u];
    unsigned b32 = stwo_m31_add(b6, b31);
    e1 = StwoCudaQm31{ b32, b26, b26, b26 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 259u);
    e4 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(ext_params, 260u);
    e6 = stwo_qm31_sub(e4, e1);
    e1 = stwo_load_qm31(ext_params, 261u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 115u, row_index, 0);
    unsigned b33 = base_params[258u];
    unsigned b34 = stwo_m31_add(b7, b33);
    e4 = StwoCudaQm31{ b34, b26, b26, b26 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e4);
    e4 = stwo_load_qm31(ext_params, 262u);
    e1 = stwo_qm31_add(e4, e7);
    e4 = stwo_load_qm31(ext_params, 263u);
    e7 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 264u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 116u, row_index, 0);
    unsigned b35 = base_params[260u];
    unsigned b36 = stwo_m31_add(b8, b35);
    e1 = StwoCudaQm31{ b36, b26, b26, b26 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 265u);
    e4 = stwo_qm31_add(e1, e8);
    e1 = stwo_load_qm31(ext_params, 266u);
    e8 = stwo_qm31_sub(e4, e1);
    e1 = stwo_load_qm31(ext_params, 267u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 117u, row_index, 0);
    unsigned b37 = base_params[262u];
    unsigned b38 = stwo_m31_add(b9, b37);
    e4 = StwoCudaQm31{ b38, b26, b26, b26 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e1, e4);
    e4 = stwo_load_qm31(ext_params, 268u);
    e1 = stwo_qm31_add(e4, e9);
    e4 = stwo_load_qm31(ext_params, 269u);
    e9 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 270u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 118u, row_index, 0);
    unsigned b39 = base_params[264u];
    unsigned b40 = stwo_m31_add(b10, b39);
    e1 = StwoCudaQm31{ b40, b26, b26, b26 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 271u);
    e4 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(ext_params, 272u);
    e10 = stwo_qm31_sub(e4, e1);
    e1 = stwo_load_qm31(ext_params, 273u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 119u, row_index, 0);
    unsigned b41 = base_params[266u];
    unsigned b42 = stwo_m31_add(b11, b41);
    e4 = StwoCudaQm31{ b42, b26, b26, b26 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e1, e4);
    e4 = stwo_load_qm31(ext_params, 274u);
    e1 = stwo_qm31_add(e4, e11);
    e4 = stwo_load_qm31(ext_params, 275u);
    e11 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 276u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 120u, row_index, 0);
    unsigned b43 = base_params[268u];
    unsigned b44 = stwo_m31_add(b12, b43);
    e1 = StwoCudaQm31{ b44, b26, b26, b26 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 277u);
    e4 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(ext_params, 278u);
    e12 = stwo_qm31_sub(e4, e1);
    e1 = stwo_load_qm31(ext_params, 279u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 121u, row_index, 0);
    unsigned b45 = base_params[270u];
    unsigned b46 = stwo_m31_add(b13, b45);
    e4 = StwoCudaQm31{ b46, b26, b26, b26 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e1, e4);
    e4 = stwo_load_qm31(ext_params, 280u);
    e1 = stwo_qm31_add(e4, e13);
    e4 = stwo_load_qm31(ext_params, 281u);
    e13 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 282u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 122u, row_index, 0);
    unsigned b47 = base_params[272u];
    unsigned b48 = stwo_m31_add(b14, b47);
    e1 = StwoCudaQm31{ b48, b26, b26, b26 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 283u);
    e4 = stwo_qm31_add(e1, e14);
    e1 = stwo_load_qm31(ext_params, 284u);
    e14 = stwo_qm31_sub(e4, e1);
    e1 = stwo_load_qm31(ext_params, 285u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 123u, row_index, 0);
    unsigned b49 = base_params[274u];
    unsigned b50 = stwo_m31_add(b15, b49);
    e4 = StwoCudaQm31{ b50, b26, b26, b26 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e1, e4);
    e4 = stwo_load_qm31(ext_params, 286u);
    e1 = stwo_qm31_add(e4, e15);
    e4 = stwo_load_qm31(ext_params, 287u);
    e15 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 288u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 124u, row_index, 0);
    unsigned b51 = base_params[276u];
    unsigned b52 = stwo_m31_add(b16, b51);
    e1 = StwoCudaQm31{ b52, b26, b26, b26 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 289u);
    e4 = stwo_qm31_add(e1, e16);
    e1 = stwo_load_qm31(ext_params, 290u);
    e16 = stwo_qm31_sub(e4, e1);
    e1 = stwo_load_qm31(ext_params, 291u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 125u, row_index, 0);
    unsigned b53 = base_params[278u];
    unsigned b54 = stwo_m31_add(b17, b53);
    e4 = StwoCudaQm31{ b54, b26, b26, b26 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e1, e4);
    e4 = stwo_load_qm31(ext_params, 292u);
    e1 = stwo_qm31_add(e4, e17);
    e4 = stwo_load_qm31(ext_params, 293u);
    e17 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 294u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 126u, row_index, 0);
    unsigned b55 = base_params[280u];
    unsigned b56 = stwo_m31_add(b18, b55);
    e1 = StwoCudaQm31{ b56, b26, b26, b26 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 295u);
    e4 = stwo_qm31_add(e1, e18);
    e1 = stwo_load_qm31(ext_params, 296u);
    e18 = stwo_qm31_sub(e4, e1);
    e1 = stwo_load_qm31(ext_params, 297u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 127u, row_index, 0);
    unsigned b57 = base_params[282u];
    unsigned b58 = stwo_m31_add(b19, b57);
    e4 = StwoCudaQm31{ b58, b26, b26, b26 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e1, e4);
    e4 = stwo_load_qm31(ext_params, 298u);
    e1 = stwo_qm31_add(e4, e19);
    e4 = stwo_load_qm31(ext_params, 299u);
    e19 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 300u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 128u, row_index, 0);
    unsigned b59 = base_params[284u];
    unsigned b60 = stwo_m31_add(b20, b59);
    e1 = StwoCudaQm31{ b60, b26, b26, b26 };
    StwoCudaQm31 e20 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 301u);
    e4 = stwo_qm31_add(e1, e20);
    e1 = stwo_load_qm31(ext_params, 302u);
    e20 = stwo_qm31_sub(e4, e1);
    e1 = stwo_load_qm31(ext_params, 303u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 129u, row_index, 0);
    unsigned b61 = base_params[286u];
    unsigned b62 = stwo_m31_add(b21, b61);
    e4 = StwoCudaQm31{ b62, b26, b26, b26 };
    StwoCudaQm31 e21 = stwo_qm31_mul(e1, e4);
    e4 = stwo_load_qm31(ext_params, 304u);
    e1 = stwo_qm31_add(e4, e21);
    e4 = stwo_load_qm31(ext_params, 305u);
    e21 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 306u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 130u, row_index, 0);
    unsigned b63 = base_params[288u];
    unsigned b64 = stwo_m31_add(b22, b63);
    e1 = StwoCudaQm31{ b64, b26, b26, b26 };
    StwoCudaQm31 e22 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 307u);
    e4 = stwo_qm31_add(e1, e22);
    e1 = stwo_load_qm31(ext_params, 308u);
    e22 = stwo_qm31_sub(e4, e1);
    e1 = stwo_load_qm31(ext_params, 309u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 131u, row_index, 0);
    unsigned b65 = base_params[290u];
    unsigned b66 = stwo_m31_add(b23, b65);
    e4 = StwoCudaQm31{ b66, b26, b26, b26 };
    StwoCudaQm31 e23 = stwo_qm31_mul(e1, e4);
    e4 = stwo_load_qm31(ext_params, 310u);
    e1 = stwo_qm31_add(e4, e23);
    e4 = stwo_load_qm31(ext_params, 311u);
    e23 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 312u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 132u, row_index, 0);
    unsigned b67 = base_params[292u];
    unsigned b68 = stwo_m31_add(b24, b67);
    e1 = StwoCudaQm31{ b68, b26, b26, b26 };
    StwoCudaQm31 e24 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 313u);
    e4 = stwo_qm31_add(e1, e24);
    e1 = stwo_load_qm31(ext_params, 314u);
    e24 = stwo_qm31_sub(e4, e1);
    e1 = stwo_load_qm31(ext_params, 315u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 133u, row_index, 0);
    unsigned b69 = base_params[294u];
    unsigned b70 = stwo_m31_add(b25, b69);
    e4 = StwoCudaQm31{ b70, b26, b26, b26 };
    StwoCudaQm31 e25 = stwo_qm31_mul(e1, e4);
    e4 = stwo_load_qm31(ext_params, 316u);
    e1 = stwo_qm31_add(e4, e25);
    e4 = stwo_load_qm31(ext_params, 317u);
    e25 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 426u);
    e1 = stwo_qm31_mul(e3, e4);
    e4 = stwo_load_qm31(ext_params, 427u);
    StwoCudaQm31 e26 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e1, e26);
    e26 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(ext_params, 428u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 429u);
    e1 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e1);
    e1 = stwo_qm31_mul(e2, e5);
    e5 = stwo_load_qm31(ext_params, 430u);
    e2 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 431u);
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e2, e0);
    e0 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 432u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(ext_params, 433u);
    e2 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e2);
    e2 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 434u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(ext_params, 435u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(ext_params, 436u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(ext_params, 437u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(ext_params, 438u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(ext_params, 439u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 440u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(ext_params, 441u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(ext_params, 442u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(ext_params, 443u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(ext_params, 444u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(ext_params, 445u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e20, e21);
    e21 = stwo_load_qm31(ext_params, 446u);
    e20 = stwo_qm31_mul(e23, e21);
    e21 = stwo_load_qm31(ext_params, 447u);
    e18 = stwo_qm31_mul(e22, e21);
    e21 = stwo_qm31_add(e20, e18);
    e18 = stwo_qm31_mul(e22, e23);
    e23 = stwo_load_qm31(ext_params, 448u);
    e22 = stwo_qm31_mul(e25, e23);
    e23 = stwo_load_qm31(ext_params, 449u);
    e20 = stwo_qm31_mul(e24, e23);
    e23 = stwo_qm31_add(e22, e20);
    e20 = stwo_qm31_mul(e24, e25);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 132u, row_index, 0);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 133u, row_index, 0);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 134u, row_index, 0);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 135u, row_index, 0);
    e25 = StwoCudaQm31{ b71, b72, b73, b74 };
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 136u, row_index, 0);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 137u, row_index, 0);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 138u, row_index, 0);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 139u, row_index, 0);
    e24 = StwoCudaQm31{ b75, b76, b77, b78 };
    e22 = stwo_qm31_sub(e24, e25);
    e25 = stwo_qm31_mul(e22, e26);
    e22 = stwo_qm31_sub(e25, e4);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e22, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 140u, row_index, 0);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 141u, row_index, 0);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 142u, row_index, 0);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 143u, row_index, 0);
    e25 = StwoCudaQm31{ b79, b80, b81, b82 };
    e4 = stwo_qm31_sub(e25, e24);
    e24 = stwo_qm31_mul(e4, e1);
    e4 = stwo_qm31_sub(e24, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 144u, row_index, 0);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 145u, row_index, 0);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 146u, row_index, 0);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 147u, row_index, 0);
    e24 = StwoCudaQm31{ b83, b84, b85, b86 };
    e3 = stwo_qm31_sub(e24, e25);
    e25 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e25, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 148u, row_index, 0);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 149u, row_index, 0);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 150u, row_index, 0);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 151u, row_index, 0);
    e25 = StwoCudaQm31{ b87, b88, b89, b90 };
    e5 = stwo_qm31_sub(e25, e24);
    e24 = stwo_qm31_mul(e5, e2);
    e5 = stwo_qm31_sub(e24, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 152u, row_index, 0);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 153u, row_index, 0);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 154u, row_index, 0);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 155u, row_index, 0);
    e24 = StwoCudaQm31{ b91, b92, b93, b94 };
    e7 = stwo_qm31_sub(e24, e25);
    e25 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e25, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 156u, row_index, 0);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 157u, row_index, 0);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 158u, row_index, 0);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 159u, row_index, 0);
    e25 = StwoCudaQm31{ b95, b96, b97, b98 };
    e9 = stwo_qm31_sub(e25, e24);
    e24 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e24, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 160u, row_index, 0);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 161u, row_index, 0);
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 162u, row_index, 0);
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 163u, row_index, 0);
    e24 = StwoCudaQm31{ b99, b100, b101, b102 };
    e11 = stwo_qm31_sub(e24, e25);
    e25 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e25, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 164u, row_index, 0);
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 165u, row_index, 0);
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 166u, row_index, 0);
    unsigned b106 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 167u, row_index, 0);
    e25 = StwoCudaQm31{ b103, b104, b105, b106 };
    e13 = stwo_qm31_sub(e25, e24);
    e24 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e24, e15);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b107 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 168u, row_index, 0);
    unsigned b108 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 169u, row_index, 0);
    unsigned b109 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 170u, row_index, 0);
    unsigned b110 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 171u, row_index, 0);
    e24 = StwoCudaQm31{ b107, b108, b109, b110 };
    e15 = stwo_qm31_sub(e24, e25);
    e25 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e25, e17);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b111 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 172u, row_index, 0);
    unsigned b112 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 173u, row_index, 0);
    unsigned b113 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 174u, row_index, 0);
    unsigned b114 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 175u, row_index, 0);
    e25 = StwoCudaQm31{ b111, b112, b113, b114 };
    e17 = stwo_qm31_sub(e25, e24);
    e24 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e24, e19);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b115 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 176u, row_index, 0);
    unsigned b116 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 177u, row_index, 0);
    unsigned b117 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 178u, row_index, 0);
    unsigned b118 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 179u, row_index, 0);
    e24 = StwoCudaQm31{ b115, b116, b117, b118 };
    e19 = stwo_qm31_sub(e24, e25);
    e25 = stwo_qm31_mul(e19, e18);
    e19 = stwo_qm31_sub(e25, e21);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e19, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b119 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 180u, row_index, 0);
    unsigned b120 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 181u, row_index, 0);
    unsigned b121 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 182u, row_index, 0);
    unsigned b122 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 183u, row_index, 0);
    e25 = StwoCudaQm31{ b119, b120, b121, b122 };
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
