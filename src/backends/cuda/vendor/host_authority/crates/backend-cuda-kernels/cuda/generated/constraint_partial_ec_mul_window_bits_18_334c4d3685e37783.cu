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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_66d5d5120c7abce1(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 111u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 154u, row_index, 0);
    unsigned b25 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b0, b25, b25, b25 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 112u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 113u);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 155u, row_index, 0);
    e2 = StwoCudaQm31{ b1, b25, b25, b25 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 114u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 115u);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 156u, row_index, 0);
    unsigned b26 = base_params[90u];
    unsigned b27 = stwo_m31_add(b2, b26);
    e2 = StwoCudaQm31{ b27, b25, b25, b25 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 116u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 117u);
    e1 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(ext_params, 118u);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 157u, row_index, 0);
    unsigned b28 = base_params[92u];
    unsigned b29 = stwo_m31_add(b3, b28);
    e3 = StwoCudaQm31{ b29, b25, b25, b25 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 119u);
    e2 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(ext_params, 120u);
    e4 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 121u);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 158u, row_index, 0);
    unsigned b30 = base_params[94u];
    unsigned b31 = stwo_m31_add(b4, b30);
    e2 = StwoCudaQm31{ b31, b25, b25, b25 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 122u);
    e3 = stwo_qm31_add(e2, e5);
    e2 = stwo_load_qm31(ext_params, 123u);
    e5 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(ext_params, 124u);
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 159u, row_index, 0);
    unsigned b32 = base_params[96u];
    unsigned b33 = stwo_m31_add(b5, b32);
    e3 = StwoCudaQm31{ b33, b25, b25, b25 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 125u);
    e2 = stwo_qm31_add(e3, e6);
    e3 = stwo_load_qm31(ext_params, 126u);
    e6 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 127u);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 160u, row_index, 0);
    unsigned b34 = base_params[98u];
    unsigned b35 = stwo_m31_add(b6, b34);
    e2 = StwoCudaQm31{ b35, b25, b25, b25 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 128u);
    e3 = stwo_qm31_add(e2, e7);
    e2 = stwo_load_qm31(ext_params, 129u);
    e7 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(ext_params, 130u);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 161u, row_index, 0);
    unsigned b36 = base_params[100u];
    unsigned b37 = stwo_m31_add(b7, b36);
    e3 = StwoCudaQm31{ b37, b25, b25, b25 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 131u);
    e2 = stwo_qm31_add(e3, e8);
    e3 = stwo_load_qm31(ext_params, 132u);
    e8 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 133u);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 162u, row_index, 0);
    unsigned b38 = base_params[102u];
    unsigned b39 = stwo_m31_add(b8, b38);
    e2 = StwoCudaQm31{ b39, b25, b25, b25 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 134u);
    e3 = stwo_qm31_add(e2, e9);
    e2 = stwo_load_qm31(ext_params, 135u);
    e9 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(ext_params, 136u);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 163u, row_index, 0);
    unsigned b40 = base_params[104u];
    unsigned b41 = stwo_m31_add(b9, b40);
    e3 = StwoCudaQm31{ b41, b25, b25, b25 };
    StwoCudaQm31 e10 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 137u);
    e2 = stwo_qm31_add(e3, e10);
    e3 = stwo_load_qm31(ext_params, 138u);
    e10 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 139u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 164u, row_index, 0);
    unsigned b42 = base_params[106u];
    unsigned b43 = stwo_m31_add(b10, b42);
    e2 = StwoCudaQm31{ b43, b25, b25, b25 };
    StwoCudaQm31 e11 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 140u);
    e3 = stwo_qm31_add(e2, e11);
    e2 = stwo_load_qm31(ext_params, 141u);
    e11 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(ext_params, 142u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 165u, row_index, 0);
    unsigned b44 = base_params[108u];
    unsigned b45 = stwo_m31_add(b11, b44);
    e3 = StwoCudaQm31{ b45, b25, b25, b25 };
    StwoCudaQm31 e12 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 143u);
    e2 = stwo_qm31_add(e3, e12);
    e3 = stwo_load_qm31(ext_params, 144u);
    e12 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 145u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 166u, row_index, 0);
    unsigned b46 = base_params[110u];
    unsigned b47 = stwo_m31_add(b12, b46);
    e2 = StwoCudaQm31{ b47, b25, b25, b25 };
    StwoCudaQm31 e13 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 146u);
    e3 = stwo_qm31_add(e2, e13);
    e2 = stwo_load_qm31(ext_params, 147u);
    e13 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(ext_params, 148u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 167u, row_index, 0);
    unsigned b48 = base_params[112u];
    unsigned b49 = stwo_m31_add(b13, b48);
    e3 = StwoCudaQm31{ b49, b25, b25, b25 };
    StwoCudaQm31 e14 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 149u);
    e2 = stwo_qm31_add(e3, e14);
    e3 = stwo_load_qm31(ext_params, 150u);
    e14 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 151u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 168u, row_index, 0);
    unsigned b50 = base_params[114u];
    unsigned b51 = stwo_m31_add(b14, b50);
    e2 = StwoCudaQm31{ b51, b25, b25, b25 };
    StwoCudaQm31 e15 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 152u);
    e3 = stwo_qm31_add(e2, e15);
    e2 = stwo_load_qm31(ext_params, 153u);
    e15 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(ext_params, 154u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 169u, row_index, 0);
    unsigned b52 = base_params[116u];
    unsigned b53 = stwo_m31_add(b15, b52);
    e3 = StwoCudaQm31{ b53, b25, b25, b25 };
    StwoCudaQm31 e16 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 155u);
    e2 = stwo_qm31_add(e3, e16);
    e3 = stwo_load_qm31(ext_params, 156u);
    e16 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 157u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 170u, row_index, 0);
    unsigned b54 = base_params[118u];
    unsigned b55 = stwo_m31_add(b16, b54);
    e2 = StwoCudaQm31{ b55, b25, b25, b25 };
    StwoCudaQm31 e17 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 158u);
    e3 = stwo_qm31_add(e2, e17);
    e2 = stwo_load_qm31(ext_params, 159u);
    e17 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(ext_params, 160u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 171u, row_index, 0);
    unsigned b56 = base_params[120u];
    unsigned b57 = stwo_m31_add(b17, b56);
    e3 = StwoCudaQm31{ b57, b25, b25, b25 };
    StwoCudaQm31 e18 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 161u);
    e2 = stwo_qm31_add(e3, e18);
    e3 = stwo_load_qm31(ext_params, 162u);
    e18 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 163u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 172u, row_index, 0);
    unsigned b58 = base_params[122u];
    unsigned b59 = stwo_m31_add(b18, b58);
    e2 = StwoCudaQm31{ b59, b25, b25, b25 };
    StwoCudaQm31 e19 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 164u);
    e3 = stwo_qm31_add(e2, e19);
    e2 = stwo_load_qm31(ext_params, 165u);
    e19 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(ext_params, 166u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 173u, row_index, 0);
    unsigned b60 = base_params[124u];
    unsigned b61 = stwo_m31_add(b19, b60);
    e3 = StwoCudaQm31{ b61, b25, b25, b25 };
    StwoCudaQm31 e20 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 167u);
    e2 = stwo_qm31_add(e3, e20);
    e3 = stwo_load_qm31(ext_params, 168u);
    e20 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 169u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 174u, row_index, 0);
    unsigned b62 = base_params[126u];
    unsigned b63 = stwo_m31_add(b20, b62);
    e2 = StwoCudaQm31{ b63, b25, b25, b25 };
    StwoCudaQm31 e21 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 170u);
    e3 = stwo_qm31_add(e2, e21);
    e2 = stwo_load_qm31(ext_params, 171u);
    e21 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(ext_params, 172u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 175u, row_index, 0);
    unsigned b64 = base_params[128u];
    unsigned b65 = stwo_m31_add(b21, b64);
    e3 = StwoCudaQm31{ b65, b25, b25, b25 };
    StwoCudaQm31 e22 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 173u);
    e2 = stwo_qm31_add(e3, e22);
    e3 = stwo_load_qm31(ext_params, 174u);
    e22 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 175u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 176u, row_index, 0);
    unsigned b66 = base_params[130u];
    unsigned b67 = stwo_m31_add(b22, b66);
    e2 = StwoCudaQm31{ b67, b25, b25, b25 };
    StwoCudaQm31 e23 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 176u);
    e3 = stwo_qm31_add(e2, e23);
    e2 = stwo_load_qm31(ext_params, 177u);
    e23 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(ext_params, 178u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 177u, row_index, 0);
    unsigned b68 = base_params[132u];
    unsigned b69 = stwo_m31_add(b23, b68);
    e3 = StwoCudaQm31{ b69, b25, b25, b25 };
    StwoCudaQm31 e24 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(ext_params, 179u);
    e2 = stwo_qm31_add(e3, e24);
    e3 = stwo_load_qm31(ext_params, 180u);
    e24 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 181u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 178u, row_index, 0);
    unsigned b70 = base_params[135u];
    unsigned b71 = stwo_m31_add(b24, b70);
    e2 = StwoCudaQm31{ b71, b25, b25, b25 };
    StwoCudaQm31 e25 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 182u);
    e3 = stwo_qm31_add(e2, e25);
    e2 = stwo_load_qm31(ext_params, 183u);
    e25 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(ext_params, 641u);
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_load_qm31(ext_params, 642u);
    StwoCudaQm31 e26 = stwo_qm31_mul(e0, e2);
    e2 = stwo_qm31_add(e3, e26);
    e26 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 643u);
    e0 = stwo_qm31_mul(e5, e1);
    e1 = stwo_load_qm31(ext_params, 644u);
    e3 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e0, e3);
    e3 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 645u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 646u);
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(ext_params, 647u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(ext_params, 648u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(ext_params, 649u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(ext_params, 650u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(ext_params, 651u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(ext_params, 652u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(ext_params, 653u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(ext_params, 654u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(ext_params, 655u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(ext_params, 656u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(ext_params, 657u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(ext_params, 658u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(ext_params, 659u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(ext_params, 660u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e20, e21);
    e21 = stwo_load_qm31(ext_params, 661u);
    e20 = stwo_qm31_mul(e23, e21);
    e21 = stwo_load_qm31(ext_params, 662u);
    e18 = stwo_qm31_mul(e22, e21);
    e21 = stwo_qm31_add(e20, e18);
    e18 = stwo_qm31_mul(e22, e23);
    e23 = stwo_load_qm31(ext_params, 663u);
    e22 = stwo_qm31_mul(e25, e23);
    e23 = stwo_load_qm31(ext_params, 664u);
    e20 = stwo_qm31_mul(e24, e23);
    e23 = stwo_qm31_add(e22, e20);
    e20 = stwo_qm31_mul(e24, e25);
    unsigned b72 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 24u, row_index, 0);
    unsigned b73 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 25u, row_index, 0);
    unsigned b74 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 26u, row_index, 0);
    unsigned b75 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 27u, row_index, 0);
    e25 = StwoCudaQm31{ b72, b73, b74, b75 };
    unsigned b76 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 28u, row_index, 0);
    unsigned b77 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 29u, row_index, 0);
    unsigned b78 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 30u, row_index, 0);
    unsigned b79 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 31u, row_index, 0);
    e24 = StwoCudaQm31{ b76, b77, b78, b79 };
    e22 = stwo_qm31_sub(e24, e25);
    e25 = stwo_qm31_mul(e22, e26);
    e22 = stwo_qm31_sub(e25, e2);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e22, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b80 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 32u, row_index, 0);
    unsigned b81 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 33u, row_index, 0);
    unsigned b82 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 34u, row_index, 0);
    unsigned b83 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 35u, row_index, 0);
    e25 = StwoCudaQm31{ b80, b81, b82, b83 };
    e2 = stwo_qm31_sub(e25, e24);
    e24 = stwo_qm31_mul(e2, e3);
    e2 = stwo_qm31_sub(e24, e1);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e2, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b84 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 36u, row_index, 0);
    unsigned b85 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 37u, row_index, 0);
    unsigned b86 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 38u, row_index, 0);
    unsigned b87 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 39u, row_index, 0);
    e24 = StwoCudaQm31{ b84, b85, b86, b87 };
    e1 = stwo_qm31_sub(e24, e25);
    e25 = stwo_qm31_mul(e1, e0);
    e1 = stwo_qm31_sub(e25, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e1, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b88 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 40u, row_index, 0);
    unsigned b89 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 41u, row_index, 0);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 42u, row_index, 0);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 43u, row_index, 0);
    e25 = StwoCudaQm31{ b88, b89, b90, b91 };
    e5 = stwo_qm31_sub(e25, e24);
    e24 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e24, e7);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e5, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 44u, row_index, 0);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 45u, row_index, 0);
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 46u, row_index, 0);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 47u, row_index, 0);
    e24 = StwoCudaQm31{ b92, b93, b94, b95 };
    e7 = stwo_qm31_sub(e24, e25);
    e25 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e25, e9);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e7, stwo_load_qm31(random_coeff_powers, rc_base + 4u)));
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 48u, row_index, 0);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 49u, row_index, 0);
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 50u, row_index, 0);
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 51u, row_index, 0);
    e25 = StwoCudaQm31{ b96, b97, b98, b99 };
    e9 = stwo_qm31_sub(e25, e24);
    e24 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e24, e11);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 5u)));
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 52u, row_index, 0);
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 53u, row_index, 0);
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 54u, row_index, 0);
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 55u, row_index, 0);
    e24 = StwoCudaQm31{ b100, b101, b102, b103 };
    e11 = stwo_qm31_sub(e24, e25);
    e25 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e25, e13);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e11, stwo_load_qm31(random_coeff_powers, rc_base + 6u)));
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 56u, row_index, 0);
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 57u, row_index, 0);
    unsigned b106 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 58u, row_index, 0);
    unsigned b107 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 59u, row_index, 0);
    e25 = StwoCudaQm31{ b104, b105, b106, b107 };
    e13 = stwo_qm31_sub(e25, e24);
    e24 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e24, e15);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e13, stwo_load_qm31(random_coeff_powers, rc_base + 7u)));
    unsigned b108 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 60u, row_index, 0);
    unsigned b109 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 61u, row_index, 0);
    unsigned b110 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 62u, row_index, 0);
    unsigned b111 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 63u, row_index, 0);
    e24 = StwoCudaQm31{ b108, b109, b110, b111 };
    e15 = stwo_qm31_sub(e24, e25);
    e25 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e25, e17);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e15, stwo_load_qm31(random_coeff_powers, rc_base + 8u)));
    unsigned b112 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 64u, row_index, 0);
    unsigned b113 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 65u, row_index, 0);
    unsigned b114 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 66u, row_index, 0);
    unsigned b115 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 67u, row_index, 0);
    e25 = StwoCudaQm31{ b112, b113, b114, b115 };
    e17 = stwo_qm31_sub(e25, e24);
    e24 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e24, e19);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e17, stwo_load_qm31(random_coeff_powers, rc_base + 9u)));
    unsigned b116 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 68u, row_index, 0);
    unsigned b117 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 69u, row_index, 0);
    unsigned b118 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 70u, row_index, 0);
    unsigned b119 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 71u, row_index, 0);
    e24 = StwoCudaQm31{ b116, b117, b118, b119 };
    e19 = stwo_qm31_sub(e24, e25);
    e25 = stwo_qm31_mul(e19, e18);
    e19 = stwo_qm31_sub(e25, e21);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e19, stwo_load_qm31(random_coeff_powers, rc_base + 10u)));
    unsigned b120 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 72u, row_index, 0);
    unsigned b121 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 73u, row_index, 0);
    unsigned b122 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 74u, row_index, 0);
    unsigned b123 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 75u, row_index, 0);
    e25 = StwoCudaQm31{ b120, b121, b122, b123 };
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
