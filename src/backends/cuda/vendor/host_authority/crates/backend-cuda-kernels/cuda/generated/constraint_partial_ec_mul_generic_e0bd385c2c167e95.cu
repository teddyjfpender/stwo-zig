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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_0ed3a4ef3ca45adb(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 6u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 39u, row_index, 0);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 142u, row_index, 0);
    unsigned b38 = stwo_m31_sub(b0, b1);
    unsigned b37 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b38, b37, b37, b37 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 7u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 8u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(ext_params, 9u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 144u, row_index, 0);
    e0 = StwoCudaQm31{ b2, b37, b37, b37 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(ext_params, 10u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(ext_params, 11u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(ext_params, 12u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 146u, row_index, 0);
    e1 = StwoCudaQm31{ b3, b37, b37, b37 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 13u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(ext_params, 14u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 147u, row_index, 0);
    e4 = StwoCudaQm31{ b4, b37, b37, b37 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(ext_params, 15u);
    e0 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(ext_params, 16u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 148u, row_index, 0);
    e4 = StwoCudaQm31{ b5, b37, b37, b37 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(ext_params, 17u);
    e5 = stwo_qm31_add(e4, e1);
    e4 = stwo_load_qm31(ext_params, 18u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 149u, row_index, 0);
    e1 = StwoCudaQm31{ b6, b37, b37, b37 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 19u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(ext_params, 20u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 150u, row_index, 0);
    e1 = StwoCudaQm31{ b7, b37, b37, b37 };
    e4 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(ext_params, 21u);
    e6 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(ext_params, 22u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 151u, row_index, 0);
    e4 = StwoCudaQm31{ b8, b37, b37, b37 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 23u);
    e6 = stwo_qm31_sub(e4, e7);
    e7 = stwo_load_qm31(ext_params, 24u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 152u, row_index, 0);
    e4 = StwoCudaQm31{ b9, b37, b37, b37 };
    e1 = stwo_qm31_mul(e7, e4);
    e4 = stwo_load_qm31(ext_params, 25u);
    e7 = stwo_qm31_add(e4, e1);
    e4 = stwo_load_qm31(ext_params, 26u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 153u, row_index, 0);
    e1 = StwoCudaQm31{ b10, b37, b37, b37 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 27u);
    e7 = stwo_qm31_sub(e1, e8);
    e8 = stwo_load_qm31(ext_params, 28u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 154u, row_index, 0);
    e1 = StwoCudaQm31{ b11, b37, b37, b37 };
    e4 = stwo_qm31_mul(e8, e1);
    e1 = stwo_load_qm31(ext_params, 29u);
    e8 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(ext_params, 30u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 155u, row_index, 0);
    e4 = StwoCudaQm31{ b12, b37, b37, b37 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 31u);
    e8 = stwo_qm31_sub(e4, e9);
    e9 = stwo_load_qm31(ext_params, 32u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 156u, row_index, 0);
    e4 = StwoCudaQm31{ b13, b37, b37, b37 };
    e1 = stwo_qm31_mul(e9, e4);
    e4 = stwo_load_qm31(ext_params, 33u);
    e9 = stwo_qm31_add(e4, e1);
    e4 = stwo_load_qm31(ext_params, 34u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 157u, row_index, 0);
    e1 = StwoCudaQm31{ b14, b37, b37, b37 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(ext_params, 35u);
    e9 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(ext_params, 36u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 158u, row_index, 0);
    e1 = StwoCudaQm31{ b15, b37, b37, b37 };
    e4 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(ext_params, 37u);
    e10 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(ext_params, 38u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 159u, row_index, 0);
    e4 = StwoCudaQm31{ b16, b37, b37, b37 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(ext_params, 39u);
    e10 = stwo_qm31_sub(e4, e11);
    e11 = stwo_load_qm31(ext_params, 40u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 160u, row_index, 0);
    e4 = StwoCudaQm31{ b17, b37, b37, b37 };
    e1 = stwo_qm31_mul(e11, e4);
    e4 = stwo_load_qm31(ext_params, 41u);
    e11 = stwo_qm31_add(e4, e1);
    e4 = stwo_load_qm31(ext_params, 42u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 161u, row_index, 0);
    e1 = StwoCudaQm31{ b18, b37, b37, b37 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(ext_params, 43u);
    e11 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(ext_params, 44u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 162u, row_index, 0);
    e1 = StwoCudaQm31{ b19, b37, b37, b37 };
    e4 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(ext_params, 45u);
    e12 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(ext_params, 46u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 163u, row_index, 0);
    e4 = StwoCudaQm31{ b20, b37, b37, b37 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(ext_params, 47u);
    e12 = stwo_qm31_sub(e4, e13);
    e13 = stwo_load_qm31(ext_params, 48u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 164u, row_index, 0);
    e4 = StwoCudaQm31{ b21, b37, b37, b37 };
    e1 = stwo_qm31_mul(e13, e4);
    e4 = stwo_load_qm31(ext_params, 49u);
    e13 = stwo_qm31_add(e4, e1);
    e4 = stwo_load_qm31(ext_params, 50u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 165u, row_index, 0);
    e1 = StwoCudaQm31{ b22, b37, b37, b37 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(ext_params, 51u);
    e13 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(ext_params, 52u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 166u, row_index, 0);
    e1 = StwoCudaQm31{ b23, b37, b37, b37 };
    e4 = stwo_qm31_mul(e14, e1);
    e1 = stwo_load_qm31(ext_params, 53u);
    e14 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(ext_params, 54u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 167u, row_index, 0);
    e4 = StwoCudaQm31{ b24, b37, b37, b37 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(ext_params, 55u);
    e14 = stwo_qm31_sub(e4, e15);
    e15 = stwo_load_qm31(ext_params, 56u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 168u, row_index, 0);
    e4 = StwoCudaQm31{ b25, b37, b37, b37 };
    e1 = stwo_qm31_mul(e15, e4);
    e4 = stwo_load_qm31(ext_params, 57u);
    e15 = stwo_qm31_add(e4, e1);
    e4 = stwo_load_qm31(ext_params, 58u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 169u, row_index, 0);
    e1 = StwoCudaQm31{ b26, b37, b37, b37 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e15, e16);
    e16 = stwo_load_qm31(ext_params, 59u);
    e15 = stwo_qm31_sub(e1, e16);
    e16 = stwo_load_qm31(ext_params, 60u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 170u, row_index, 0);
    e1 = StwoCudaQm31{ b27, b37, b37, b37 };
    e4 = stwo_qm31_mul(e16, e1);
    e1 = stwo_load_qm31(ext_params, 61u);
    e16 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(ext_params, 62u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 171u, row_index, 0);
    e4 = StwoCudaQm31{ b28, b37, b37, b37 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(ext_params, 63u);
    e16 = stwo_qm31_sub(e4, e17);
    e17 = stwo_load_qm31(ext_params, 64u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 172u, row_index, 0);
    e4 = StwoCudaQm31{ b29, b37, b37, b37 };
    e1 = stwo_qm31_mul(e17, e4);
    e4 = stwo_load_qm31(ext_params, 65u);
    e17 = stwo_qm31_add(e4, e1);
    e4 = stwo_load_qm31(ext_params, 66u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 173u, row_index, 0);
    e1 = StwoCudaQm31{ b30, b37, b37, b37 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(ext_params, 67u);
    e17 = stwo_qm31_sub(e1, e18);
    e18 = stwo_load_qm31(ext_params, 68u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 174u, row_index, 0);
    unsigned b39 = base_params[103u];
    unsigned b40 = stwo_m31_add(b31, b39);
    e1 = StwoCudaQm31{ b40, b37, b37, b37 };
    e4 = stwo_qm31_mul(e18, e1);
    e1 = stwo_load_qm31(ext_params, 69u);
    e18 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(ext_params, 70u);
    e4 = stwo_qm31_sub(e18, e1);
    e1 = stwo_load_qm31(ext_params, 71u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 175u, row_index, 0);
    unsigned b41 = base_params[105u];
    unsigned b42 = stwo_m31_add(b32, b41);
    e18 = StwoCudaQm31{ b42, b37, b37, b37 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e1, e18);
    e18 = stwo_load_qm31(ext_params, 72u);
    e1 = stwo_qm31_add(e18, e19);
    e18 = stwo_load_qm31(ext_params, 73u);
    e19 = stwo_qm31_sub(e1, e18);
    e18 = stwo_load_qm31(ext_params, 74u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 176u, row_index, 0);
    unsigned b43 = base_params[107u];
    unsigned b44 = stwo_m31_add(b33, b43);
    e1 = StwoCudaQm31{ b44, b37, b37, b37 };
    StwoCudaQm31 e20 = stwo_qm31_mul(e18, e1);
    e1 = stwo_load_qm31(ext_params, 75u);
    e18 = stwo_qm31_add(e1, e20);
    e1 = stwo_load_qm31(ext_params, 76u);
    e20 = stwo_qm31_sub(e18, e1);
    e1 = stwo_load_qm31(ext_params, 77u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 177u, row_index, 0);
    unsigned b45 = base_params[109u];
    unsigned b46 = stwo_m31_add(b34, b45);
    e18 = StwoCudaQm31{ b46, b37, b37, b37 };
    StwoCudaQm31 e21 = stwo_qm31_mul(e1, e18);
    e18 = stwo_load_qm31(ext_params, 78u);
    e1 = stwo_qm31_add(e18, e21);
    e18 = stwo_load_qm31(ext_params, 79u);
    e21 = stwo_qm31_sub(e1, e18);
    e18 = stwo_load_qm31(ext_params, 80u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 178u, row_index, 0);
    unsigned b47 = base_params[111u];
    unsigned b48 = stwo_m31_add(b35, b47);
    e1 = StwoCudaQm31{ b48, b37, b37, b37 };
    StwoCudaQm31 e22 = stwo_qm31_mul(e18, e1);
    e1 = stwo_load_qm31(ext_params, 81u);
    e18 = stwo_qm31_add(e1, e22);
    e1 = stwo_load_qm31(ext_params, 82u);
    e22 = stwo_qm31_sub(e18, e1);
    e1 = stwo_load_qm31(ext_params, 83u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 179u, row_index, 0);
    unsigned b49 = base_params[113u];
    unsigned b50 = stwo_m31_add(b36, b49);
    e18 = StwoCudaQm31{ b50, b37, b37, b37 };
    StwoCudaQm31 e23 = stwo_qm31_mul(e1, e18);
    e18 = stwo_load_qm31(ext_params, 84u);
    e1 = stwo_qm31_add(e18, e23);
    e18 = stwo_load_qm31(ext_params, 85u);
    e23 = stwo_qm31_sub(e1, e18);
    e18 = stwo_load_qm31(ext_params, 1304u);
    e1 = stwo_qm31_mul(e3, e18);
    e18 = stwo_load_qm31(ext_params, 1305u);
    StwoCudaQm31 e24 = stwo_qm31_mul(e2, e18);
    e18 = stwo_qm31_add(e1, e24);
    e24 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 1306u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 1307u);
    e1 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e2, e1);
    e1 = stwo_qm31_mul(e0, e5);
    e5 = stwo_load_qm31(ext_params, 1308u);
    e0 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 1309u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e0, e2);
    e2 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 1310u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(ext_params, 1311u);
    e0 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e0);
    e0 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 1312u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(ext_params, 1313u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(ext_params, 1314u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(ext_params, 1315u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(ext_params, 1316u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(ext_params, 1317u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 1318u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(ext_params, 1319u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(ext_params, 1320u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(ext_params, 1321u);
    e14 = stwo_qm31_mul(e4, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e4, e19);
    e19 = stwo_load_qm31(ext_params, 1322u);
    e4 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(ext_params, 1323u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e4, e16);
    e16 = stwo_qm31_mul(e20, e21);
    e21 = stwo_load_qm31(ext_params, 1324u);
    e20 = stwo_qm31_mul(e23, e21);
    e21 = stwo_load_qm31(ext_params, 1325u);
    e4 = stwo_qm31_mul(e22, e21);
    e21 = stwo_qm31_add(e20, e4);
    e4 = stwo_qm31_mul(e22, e23);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 0u, row_index, 0);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 1u, row_index, 0);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 2u, row_index, 0);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 3u, row_index, 0);
    e23 = StwoCudaQm31{ b51, b52, b53, b54 };
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 4u, row_index, 0);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 5u, row_index, 0);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 6u, row_index, 0);
    unsigned b58 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 7u, row_index, 0);
    e22 = StwoCudaQm31{ b55, b56, b57, b58 };
    e20 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e20, e24);
    e20 = stwo_qm31_sub(e23, e18);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e20, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b59 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 8u, row_index, 0);
    unsigned b60 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 9u, row_index, 0);
    unsigned b61 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 10u, row_index, 0);
    unsigned b62 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 11u, row_index, 0);
    e23 = StwoCudaQm31{ b59, b60, b61, b62 };
    e18 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e18, e1);
    e18 = stwo_qm31_sub(e22, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e18, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b63 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 12u, row_index, 0);
    unsigned b64 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 13u, row_index, 0);
    unsigned b65 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 14u, row_index, 0);
    unsigned b66 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 15u, row_index, 0);
    e22 = StwoCudaQm31{ b63, b64, b65, b66 };
    e3 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e23, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b67 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 16u, row_index, 0);
    unsigned b68 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 17u, row_index, 0);
    unsigned b69 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 18u, row_index, 0);
    unsigned b70 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 19u, row_index, 0);
    e23 = StwoCudaQm31{ b67, b68, b69, b70 };
    e5 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e5, e0);
    e5 = stwo_qm31_sub(e22, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b71 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 20u, row_index, 0);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 21u, row_index, 0);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 22u, row_index, 0);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 23u, row_index, 0);
    e22 = StwoCudaQm31{ b71, b72, b73, b74 };
    e7 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e23, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 24u, row_index, 0);
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 25u, row_index, 0);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 26u, row_index, 0);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 27u, row_index, 0);
    e23 = StwoCudaQm31{ b75, b76, b77, b78 };
    e9 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e22, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 28u, row_index, 0);
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 29u, row_index, 0);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 30u, row_index, 0);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 31u, row_index, 0);
    e22 = StwoCudaQm31{ b79, b80, b81, b82 };
    e11 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e23, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 32u, row_index, 0);
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 33u, row_index, 0);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 34u, row_index, 0);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 35u, row_index, 0);
    e23 = StwoCudaQm31{ b83, b84, b85, b86 };
    e13 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e22, e15);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 36u, row_index, 0);
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 37u, row_index, 0);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 38u, row_index, 0);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 39u, row_index, 0);
    e22 = StwoCudaQm31{ b87, b88, b89, b90 };
    e15 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e23, e17);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 40u, row_index, 0);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 41u, row_index, 0);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 42u, row_index, 0);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 43u, row_index, 0);
    e23 = StwoCudaQm31{ b91, b92, b93, b94 };
    e17 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e22, e19);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 44u, row_index, 0);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 45u, row_index, 0);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 46u, row_index, 0);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 47u, row_index, 0);
    e22 = StwoCudaQm31{ b95, b96, b97, b98 };
    e19 = stwo_qm31_sub(e22, e23);
    e22 = stwo_qm31_mul(e19, e4);
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
