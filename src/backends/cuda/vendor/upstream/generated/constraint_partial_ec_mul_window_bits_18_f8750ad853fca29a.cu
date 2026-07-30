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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_685e87360a58dec5(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 336u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 239u, row_index, 0);
    unsigned b37 = base_params[290u];
    unsigned b38 = stwo_m31_add(b0, b37);
    unsigned b36 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b38, b36, b36, b36 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 337u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 338u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 339u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 240u, row_index, 0);
    e0 = StwoCudaQm31{ b1, b36, b36, b36 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 340u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 341u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 241u, row_index, 0);
    e3 = StwoCudaQm31{ b2, b36, b36, b36 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(ext_params, 342u);
    e1 = stwo_qm31_sub(e3, e4);
    e4 = stwo_load_qm31(ext_params, 343u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 242u, row_index, 0);
    e3 = StwoCudaQm31{ b3, b36, b36, b36 };
    e0 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(ext_params, 344u);
    e4 = stwo_qm31_add(e3, e0);
    e3 = stwo_load_qm31(ext_params, 345u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 243u, row_index, 0);
    e0 = StwoCudaQm31{ b4, b36, b36, b36 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 346u);
    e4 = stwo_qm31_sub(e0, e5);
    e5 = stwo_load_qm31(ext_params, 347u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 244u, row_index, 0);
    e0 = StwoCudaQm31{ b5, b36, b36, b36 };
    e3 = stwo_qm31_mul(e5, e0);
    e0 = stwo_load_qm31(ext_params, 348u);
    e5 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 349u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 245u, row_index, 0);
    e3 = StwoCudaQm31{ b6, b36, b36, b36 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 350u);
    e5 = stwo_qm31_sub(e3, e6);
    e6 = stwo_load_qm31(ext_params, 351u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 246u, row_index, 0);
    e3 = StwoCudaQm31{ b7, b36, b36, b36 };
    e0 = stwo_qm31_mul(e6, e3);
    e3 = stwo_load_qm31(ext_params, 352u);
    e6 = stwo_qm31_add(e3, e0);
    e3 = stwo_load_qm31(ext_params, 353u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 247u, row_index, 0);
    e0 = StwoCudaQm31{ b8, b36, b36, b36 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 354u);
    e6 = stwo_qm31_sub(e0, e7);
    e7 = stwo_load_qm31(ext_params, 355u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 248u, row_index, 0);
    e0 = StwoCudaQm31{ b9, b36, b36, b36 };
    e3 = stwo_qm31_mul(e7, e0);
    e0 = stwo_load_qm31(ext_params, 356u);
    e7 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 357u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 249u, row_index, 0);
    e3 = StwoCudaQm31{ b10, b36, b36, b36 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 358u);
    e7 = stwo_qm31_sub(e3, e8);
    e8 = stwo_load_qm31(ext_params, 359u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 250u, row_index, 0);
    e3 = StwoCudaQm31{ b11, b36, b36, b36 };
    e0 = stwo_qm31_mul(e8, e3);
    e3 = stwo_load_qm31(ext_params, 360u);
    e8 = stwo_qm31_add(e3, e0);
    e3 = stwo_load_qm31(ext_params, 361u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 251u, row_index, 0);
    e0 = StwoCudaQm31{ b12, b36, b36, b36 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 362u);
    e8 = stwo_qm31_sub(e0, e9);
    e9 = stwo_load_qm31(ext_params, 363u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 252u, row_index, 0);
    e0 = StwoCudaQm31{ b13, b36, b36, b36 };
    e3 = stwo_qm31_mul(e9, e0);
    e0 = stwo_load_qm31(ext_params, 364u);
    e9 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 365u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 253u, row_index, 0);
    e3 = StwoCudaQm31{ b14, b36, b36, b36 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 366u);
    e9 = stwo_qm31_sub(e3, e10);
    e10 = stwo_load_qm31(ext_params, 367u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 254u, row_index, 0);
    e3 = StwoCudaQm31{ b15, b36, b36, b36 };
    e0 = stwo_qm31_mul(e10, e3);
    e3 = stwo_load_qm31(ext_params, 368u);
    e10 = stwo_qm31_add(e3, e0);
    e3 = stwo_load_qm31(ext_params, 369u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 255u, row_index, 0);
    e0 = StwoCudaQm31{ b16, b36, b36, b36 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 370u);
    e10 = stwo_qm31_sub(e0, e11);
    e11 = stwo_load_qm31(ext_params, 371u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 256u, row_index, 0);
    e0 = StwoCudaQm31{ b17, b36, b36, b36 };
    e3 = stwo_qm31_mul(e11, e0);
    e0 = stwo_load_qm31(ext_params, 372u);
    e11 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 373u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 257u, row_index, 0);
    e3 = StwoCudaQm31{ b18, b36, b36, b36 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 374u);
    e11 = stwo_qm31_sub(e3, e12);
    e12 = stwo_load_qm31(ext_params, 375u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 258u, row_index, 0);
    e3 = StwoCudaQm31{ b19, b36, b36, b36 };
    e0 = stwo_qm31_mul(e12, e3);
    e3 = stwo_load_qm31(ext_params, 376u);
    e12 = stwo_qm31_add(e3, e0);
    e3 = stwo_load_qm31(ext_params, 377u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 259u, row_index, 0);
    e0 = StwoCudaQm31{ b20, b36, b36, b36 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 378u);
    e12 = stwo_qm31_sub(e0, e13);
    e13 = stwo_load_qm31(ext_params, 379u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 260u, row_index, 0);
    e0 = StwoCudaQm31{ b21, b36, b36, b36 };
    e3 = stwo_qm31_mul(e13, e0);
    e0 = stwo_load_qm31(ext_params, 380u);
    e13 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 381u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 261u, row_index, 0);
    e3 = StwoCudaQm31{ b22, b36, b36, b36 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(ext_params, 382u);
    e13 = stwo_qm31_sub(e3, e14);
    e14 = stwo_load_qm31(ext_params, 383u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 262u, row_index, 0);
    e3 = StwoCudaQm31{ b23, b36, b36, b36 };
    e0 = stwo_qm31_mul(e14, e3);
    e3 = stwo_load_qm31(ext_params, 384u);
    e14 = stwo_qm31_add(e3, e0);
    e3 = stwo_load_qm31(ext_params, 385u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 263u, row_index, 0);
    e0 = StwoCudaQm31{ b24, b36, b36, b36 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 386u);
    e14 = stwo_qm31_sub(e0, e15);
    e15 = stwo_load_qm31(ext_params, 387u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 264u, row_index, 0);
    e0 = StwoCudaQm31{ b25, b36, b36, b36 };
    e3 = stwo_qm31_mul(e15, e0);
    e0 = stwo_load_qm31(ext_params, 388u);
    e15 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 389u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 265u, row_index, 0);
    e3 = StwoCudaQm31{ b26, b36, b36, b36 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e15, e16);
    e16 = stwo_load_qm31(ext_params, 390u);
    e15 = stwo_qm31_sub(e3, e16);
    e16 = stwo_load_qm31(ext_params, 391u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 266u, row_index, 0);
    e3 = StwoCudaQm31{ b27, b36, b36, b36 };
    e0 = stwo_qm31_mul(e16, e3);
    e3 = stwo_load_qm31(ext_params, 392u);
    e16 = stwo_qm31_add(e3, e0);
    e3 = stwo_load_qm31(ext_params, 393u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 267u, row_index, 0);
    e0 = StwoCudaQm31{ b28, b36, b36, b36 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 394u);
    e16 = stwo_qm31_sub(e0, e17);
    e17 = stwo_load_qm31(ext_params, 395u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 268u, row_index, 0);
    unsigned b39 = base_params[380u];
    unsigned b40 = stwo_m31_add(b29, b39);
    e0 = StwoCudaQm31{ b40, b36, b36, b36 };
    e3 = stwo_qm31_mul(e17, e0);
    e0 = stwo_load_qm31(ext_params, 396u);
    e17 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 397u);
    e3 = stwo_qm31_sub(e17, e0);
    e0 = stwo_load_qm31(ext_params, 398u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 269u, row_index, 0);
    unsigned b41 = base_params[382u];
    unsigned b42 = stwo_m31_add(b30, b41);
    e17 = StwoCudaQm31{ b42, b36, b36, b36 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e0, e17);
    e17 = stwo_load_qm31(ext_params, 399u);
    e0 = stwo_qm31_add(e17, e18);
    e17 = stwo_load_qm31(ext_params, 400u);
    e18 = stwo_qm31_sub(e0, e17);
    e17 = stwo_load_qm31(ext_params, 401u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 270u, row_index, 0);
    unsigned b43 = base_params[384u];
    unsigned b44 = stwo_m31_add(b31, b43);
    e0 = StwoCudaQm31{ b44, b36, b36, b36 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e17, e0);
    e0 = stwo_load_qm31(ext_params, 402u);
    e17 = stwo_qm31_add(e0, e19);
    e0 = stwo_load_qm31(ext_params, 403u);
    e19 = stwo_qm31_sub(e17, e0);
    e0 = stwo_load_qm31(ext_params, 404u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 271u, row_index, 0);
    unsigned b45 = base_params[386u];
    unsigned b46 = stwo_m31_add(b32, b45);
    e17 = StwoCudaQm31{ b46, b36, b36, b36 };
    StwoCudaQm31 e20 = stwo_qm31_mul(e0, e17);
    e17 = stwo_load_qm31(ext_params, 405u);
    e0 = stwo_qm31_add(e17, e20);
    e17 = stwo_load_qm31(ext_params, 406u);
    e20 = stwo_qm31_sub(e0, e17);
    e17 = stwo_load_qm31(ext_params, 407u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 272u, row_index, 0);
    unsigned b47 = base_params[388u];
    unsigned b48 = stwo_m31_add(b33, b47);
    e0 = StwoCudaQm31{ b48, b36, b36, b36 };
    StwoCudaQm31 e21 = stwo_qm31_mul(e17, e0);
    e0 = stwo_load_qm31(ext_params, 408u);
    e17 = stwo_qm31_add(e0, e21);
    e0 = stwo_load_qm31(ext_params, 409u);
    e21 = stwo_qm31_sub(e17, e0);
    e0 = stwo_load_qm31(ext_params, 410u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 273u, row_index, 0);
    unsigned b49 = base_params[390u];
    unsigned b50 = stwo_m31_add(b34, b49);
    e17 = StwoCudaQm31{ b50, b36, b36, b36 };
    StwoCudaQm31 e22 = stwo_qm31_mul(e0, e17);
    e17 = stwo_load_qm31(ext_params, 411u);
    e0 = stwo_qm31_add(e17, e22);
    e17 = stwo_load_qm31(ext_params, 412u);
    e22 = stwo_qm31_sub(e0, e17);
    e17 = stwo_load_qm31(ext_params, 413u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 274u, row_index, 0);
    unsigned b51 = base_params[392u];
    unsigned b52 = stwo_m31_add(b35, b51);
    e0 = StwoCudaQm31{ b52, b36, b36, b36 };
    StwoCudaQm31 e23 = stwo_qm31_mul(e17, e0);
    e0 = stwo_load_qm31(ext_params, 414u);
    e17 = stwo_qm31_add(e0, e23);
    e0 = stwo_load_qm31(ext_params, 415u);
    e23 = stwo_qm31_sub(e17, e0);
    e0 = stwo_load_qm31(ext_params, 711u);
    e17 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 712u);
    StwoCudaQm31 e24 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e17, e24);
    e24 = stwo_qm31_mul(e2, e1);
    e1 = stwo_load_qm31(ext_params, 713u);
    e2 = stwo_qm31_mul(e5, e1);
    e1 = stwo_load_qm31(ext_params, 714u);
    e17 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e2, e17);
    e17 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 715u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 716u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 717u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(ext_params, 718u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 719u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(ext_params, 720u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(ext_params, 721u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(ext_params, 722u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(ext_params, 723u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(ext_params, 724u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 725u);
    e14 = stwo_qm31_mul(e3, e15);
    e15 = stwo_load_qm31(ext_params, 726u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e3);
    e3 = stwo_load_qm31(ext_params, 727u);
    e16 = stwo_qm31_mul(e19, e3);
    e3 = stwo_load_qm31(ext_params, 728u);
    e14 = stwo_qm31_mul(e18, e3);
    e3 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(ext_params, 729u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(ext_params, 730u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e20, e21);
    e21 = stwo_load_qm31(ext_params, 731u);
    e20 = stwo_qm31_mul(e23, e21);
    e21 = stwo_load_qm31(ext_params, 732u);
    e18 = stwo_qm31_mul(e22, e21);
    e21 = stwo_qm31_add(e20, e18);
    e18 = stwo_qm31_mul(e22, e23);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 164u, row_index, 0);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 165u, row_index, 0);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 166u, row_index, 0);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 167u, row_index, 0);
    e23 = StwoCudaQm31{ b53, b54, b55, b56 };
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 168u, row_index, 0);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 169u, row_index, 0);
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 170u, row_index, 0);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 171u, row_index, 0);
    e22 = StwoCudaQm31{ b57, b58, b59, b60 };
    e20 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e20, e24);
    e20 = stwo_qm31_sub(e23, e0);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e20, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 172u, row_index, 0);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 173u, row_index, 0);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 174u, row_index, 0);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 175u, row_index, 0);
    e23 = StwoCudaQm31{ b61, b62, b63, b64 };
    e0 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e0, e17);
    e0 = stwo_qm31_sub(e22, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 176u, row_index, 0);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 177u, row_index, 0);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 178u, row_index, 0);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 179u, row_index, 0);
    e22 = StwoCudaQm31{ b65, b66, b67, b68 };
    e1 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e1, e2);
    e1 = stwo_qm31_sub(e23, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 180u, row_index, 0);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 181u, row_index, 0);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 182u, row_index, 0);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 183u, row_index, 0);
    e23 = StwoCudaQm31{ b69, b70, b71, b72 };
    e5 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e22, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 184u, row_index, 0);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 185u, row_index, 0);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 186u, row_index, 0);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 187u, row_index, 0);
    e22 = StwoCudaQm31{ b73, b74, b75, b76 };
    e7 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e23, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 188u, row_index, 0);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 189u, row_index, 0);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 190u, row_index, 0);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 191u, row_index, 0);
    e23 = StwoCudaQm31{ b77, b78, b79, b80 };
    e9 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e22, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 192u, row_index, 0);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 193u, row_index, 0);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 194u, row_index, 0);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 195u, row_index, 0);
    e22 = StwoCudaQm31{ b81, b82, b83, b84 };
    e11 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e23, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 196u, row_index, 0);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 197u, row_index, 0);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 198u, row_index, 0);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 199u, row_index, 0);
    e23 = StwoCudaQm31{ b85, b86, b87, b88 };
    e13 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e22, e15);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 200u, row_index, 0);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 201u, row_index, 0);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 202u, row_index, 0);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 203u, row_index, 0);
    e22 = StwoCudaQm31{ b89, b90, b91, b92 };
    e15 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e23, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 204u, row_index, 0);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 205u, row_index, 0);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 206u, row_index, 0);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 207u, row_index, 0);
    e23 = StwoCudaQm31{ b93, b94, b95, b96 };
    e3 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e3, e16);
    e3 = stwo_qm31_sub(e22, e19);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 208u, row_index, 0);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 209u, row_index, 0);
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 210u, row_index, 0);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 211u, row_index, 0);
    e22 = StwoCudaQm31{ b97, b98, b99, b100 };
    e19 = stwo_qm31_sub(e22, e23);
    e22 = stwo_qm31_mul(e19, e18);
    e19 = stwo_qm31_sub(e22, e21);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e19, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
