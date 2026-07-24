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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_1bc767b18808252b(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 416u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 275u, row_index, 0);
    unsigned b21 = base_params[394u];
    unsigned b22 = stwo_m31_add(b0, b21);
    unsigned b20 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b22, b20, b20, b20 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 417u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 418u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 419u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 276u, row_index, 0);
    unsigned b23 = base_params[396u];
    unsigned b24 = stwo_m31_add(b1, b23);
    e0 = StwoCudaQm31{ b24, b20, b20, b20 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 420u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 421u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 422u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 277u, row_index, 0);
    unsigned b25 = base_params[398u];
    unsigned b26 = stwo_m31_add(b2, b25);
    e1 = StwoCudaQm31{ b26, b20, b20, b20 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 423u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(ext_params, 424u);
    e4 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 425u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 278u, row_index, 0);
    unsigned b27 = base_params[400u];
    unsigned b28 = stwo_m31_add(b3, b27);
    e0 = StwoCudaQm31{ b28, b20, b20, b20 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 426u);
    e1 = stwo_qm31_add(e0, e5);
    e0 = stwo_load_qm31(ext_params, 427u);
    e5 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 428u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 279u, row_index, 0);
    unsigned b29 = base_params[402u];
    unsigned b30 = stwo_m31_add(b4, b29);
    e1 = StwoCudaQm31{ b30, b20, b20, b20 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 429u);
    e0 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(ext_params, 430u);
    e6 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 431u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 280u, row_index, 0);
    unsigned b31 = base_params[404u];
    unsigned b32 = stwo_m31_add(b5, b31);
    e0 = StwoCudaQm31{ b32, b20, b20, b20 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 432u);
    e1 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(ext_params, 433u);
    e7 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 434u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 281u, row_index, 0);
    unsigned b33 = base_params[406u];
    unsigned b34 = stwo_m31_add(b6, b33);
    e1 = StwoCudaQm31{ b34, b20, b20, b20 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 435u);
    e0 = stwo_qm31_add(e1, e8);
    e1 = stwo_load_qm31(ext_params, 436u);
    e8 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 437u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 282u, row_index, 0);
    unsigned b35 = base_params[408u];
    unsigned b36 = stwo_m31_add(b7, b35);
    e0 = StwoCudaQm31{ b36, b20, b20, b20 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 438u);
    e1 = stwo_qm31_add(e0, e9);
    e0 = stwo_load_qm31(ext_params, 439u);
    e9 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 440u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 283u, row_index, 0);
    unsigned b37 = base_params[410u];
    unsigned b38 = stwo_m31_add(b8, b37);
    e1 = StwoCudaQm31{ b38, b20, b20, b20 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 441u);
    e0 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(ext_params, 442u);
    e10 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 443u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 284u, row_index, 0);
    unsigned b39 = base_params[412u];
    unsigned b40 = stwo_m31_add(b9, b39);
    e0 = StwoCudaQm31{ b40, b20, b20, b20 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 444u);
    e1 = stwo_qm31_add(e0, e11);
    e0 = stwo_load_qm31(ext_params, 445u);
    e11 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 446u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 285u, row_index, 0);
    unsigned b41 = base_params[414u];
    unsigned b42 = stwo_m31_add(b10, b41);
    e1 = StwoCudaQm31{ b42, b20, b20, b20 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 447u);
    e0 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(ext_params, 448u);
    e12 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 449u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 286u, row_index, 0);
    unsigned b43 = base_params[416u];
    unsigned b44 = stwo_m31_add(b11, b43);
    e0 = StwoCudaQm31{ b44, b20, b20, b20 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 450u);
    e1 = stwo_qm31_add(e0, e13);
    e0 = stwo_load_qm31(ext_params, 451u);
    e13 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 452u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 287u, row_index, 0);
    unsigned b45 = base_params[418u];
    unsigned b46 = stwo_m31_add(b12, b45);
    e1 = StwoCudaQm31{ b46, b20, b20, b20 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 453u);
    e0 = stwo_qm31_add(e1, e14);
    e1 = stwo_load_qm31(ext_params, 454u);
    e14 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 455u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 288u, row_index, 0);
    unsigned b47 = base_params[420u];
    unsigned b48 = stwo_m31_add(b13, b47);
    e0 = StwoCudaQm31{ b48, b20, b20, b20 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 456u);
    e1 = stwo_qm31_add(e0, e15);
    e0 = stwo_load_qm31(ext_params, 457u);
    e15 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 458u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 289u, row_index, 0);
    unsigned b49 = base_params[422u];
    unsigned b50 = stwo_m31_add(b14, b49);
    e1 = StwoCudaQm31{ b50, b20, b20, b20 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 459u);
    e0 = stwo_qm31_add(e1, e16);
    e1 = stwo_load_qm31(ext_params, 460u);
    e16 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 461u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 290u, row_index, 0);
    unsigned b51 = base_params[425u];
    unsigned b52 = stwo_m31_add(b15, b51);
    e0 = StwoCudaQm31{ b52, b20, b20, b20 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 462u);
    e1 = stwo_qm31_add(e0, e17);
    e0 = stwo_load_qm31(ext_params, 463u);
    e17 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 464u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 291u, row_index, 0);
    unsigned b53 = base_params[427u];
    unsigned b54 = stwo_m31_add(b16, b53);
    e1 = StwoCudaQm31{ b54, b20, b20, b20 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 465u);
    e0 = stwo_qm31_add(e1, e18);
    e1 = stwo_load_qm31(ext_params, 466u);
    e18 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 467u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 292u, row_index, 0);
    unsigned b55 = base_params[429u];
    unsigned b56 = stwo_m31_add(b17, b55);
    e0 = StwoCudaQm31{ b56, b20, b20, b20 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 468u);
    e1 = stwo_qm31_add(e0, e19);
    e0 = stwo_load_qm31(ext_params, 469u);
    e19 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 470u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 293u, row_index, 0);
    unsigned b57 = base_params[431u];
    unsigned b58 = stwo_m31_add(b18, b57);
    e1 = StwoCudaQm31{ b58, b20, b20, b20 };
    StwoCudaQm31 e20 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 471u);
    e0 = stwo_qm31_add(e1, e20);
    e1 = stwo_load_qm31(ext_params, 472u);
    e20 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 473u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 294u, row_index, 0);
    unsigned b59 = base_params[433u];
    unsigned b60 = stwo_m31_add(b19, b59);
    e0 = StwoCudaQm31{ b60, b20, b20, b20 };
    StwoCudaQm31 e21 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 474u);
    e1 = stwo_qm31_add(e0, e21);
    e0 = stwo_load_qm31(ext_params, 475u);
    e21 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 733u);
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_load_qm31(ext_params, 734u);
    StwoCudaQm31 e22 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e1, e22);
    e22 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 735u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 736u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 737u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 738u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 739u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(ext_params, 740u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 741u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(ext_params, 742u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(ext_params, 743u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(ext_params, 744u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(ext_params, 745u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(ext_params, 746u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 747u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(ext_params, 748u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(ext_params, 749u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(ext_params, 750u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(ext_params, 751u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(ext_params, 752u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e20, e21);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 208u, row_index, 0);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 209u, row_index, 0);
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 210u, row_index, 0);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 211u, row_index, 0);
    e21 = StwoCudaQm31{ b61, b62, b63, b64 };
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 212u, row_index, 0);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 213u, row_index, 0);
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 214u, row_index, 0);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 215u, row_index, 0);
    e20 = StwoCudaQm31{ b65, b66, b67, b68 };
    e18 = stwo_qm31_sub(e20, e21);
    e21 = stwo_qm31_mul(e18, e22);
    e18 = stwo_qm31_sub(e21, e0);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 216u, row_index, 0);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 217u, row_index, 0);
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 218u, row_index, 0);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 219u, row_index, 0);
    e21 = StwoCudaQm31{ b69, b70, b71, b72 };
    e0 = stwo_qm31_sub(e21, e20);
    e20 = stwo_qm31_mul(e0, e1);
    e0 = stwo_qm31_sub(e20, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e0, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 220u, row_index, 0);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 221u, row_index, 0);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 222u, row_index, 0);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 223u, row_index, 0);
    e20 = StwoCudaQm31{ b73, b74, b75, b76 };
    e3 = stwo_qm31_sub(e20, e21);
    e21 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e21, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 224u, row_index, 0);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 225u, row_index, 0);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 226u, row_index, 0);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 227u, row_index, 0);
    e21 = StwoCudaQm31{ b77, b78, b79, b80 };
    e5 = stwo_qm31_sub(e21, e20);
    e20 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e20, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 228u, row_index, 0);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 229u, row_index, 0);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 230u, row_index, 0);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 231u, row_index, 0);
    e20 = StwoCudaQm31{ b81, b82, b83, b84 };
    e7 = stwo_qm31_sub(e20, e21);
    e21 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e21, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 232u, row_index, 0);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 233u, row_index, 0);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 234u, row_index, 0);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 235u, row_index, 0);
    e21 = StwoCudaQm31{ b85, b86, b87, b88 };
    e9 = stwo_qm31_sub(e21, e20);
    e20 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e20, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 236u, row_index, 0);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 237u, row_index, 0);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 238u, row_index, 0);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 239u, row_index, 0);
    e20 = StwoCudaQm31{ b89, b90, b91, b92 };
    e11 = stwo_qm31_sub(e20, e21);
    e21 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e21, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 240u, row_index, 0);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 241u, row_index, 0);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 242u, row_index, 0);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 243u, row_index, 0);
    e21 = StwoCudaQm31{ b93, b94, b95, b96 };
    e13 = stwo_qm31_sub(e21, e20);
    e20 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e20, e15);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 244u, row_index, 0);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 245u, row_index, 0);
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 246u, row_index, 0);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 247u, row_index, 0);
    e20 = StwoCudaQm31{ b97, b98, b99, b100 };
    e15 = stwo_qm31_sub(e20, e21);
    e21 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e21, e17);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 248u, row_index, 0);
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 249u, row_index, 0);
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 250u, row_index, 0);
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 251u, row_index, 0);
    e21 = StwoCudaQm31{ b101, b102, b103, b104 };
    e17 = stwo_qm31_sub(e21, e20);
    e21 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e21, e19);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
