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

extern "C" __global__ void __launch_bounds__(128) stwo_jit_fused_64d371ea6e77b237(
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
    StwoCudaQm31 e0 = stwo_load_qm31(ext_params, 400u);
    unsigned b10 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 204u, row_index, 0);
    unsigned b58 = base_params[1u];
    StwoCudaQm31 e1 = StwoCudaQm31{ b10, b58, b58, b58 };
    StwoCudaQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(ext_params, 401u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 402u);
    unsigned b11 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 205u, row_index, 0);
    e2 = StwoCudaQm31{ b11, b58, b58, b58 };
    StwoCudaQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 403u);
    unsigned b12 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 206u, row_index, 0);
    e0 = StwoCudaQm31{ b12, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 404u);
    unsigned b13 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 207u, row_index, 0);
    e2 = StwoCudaQm31{ b13, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 405u);
    unsigned b14 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 208u, row_index, 0);
    e0 = StwoCudaQm31{ b14, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 406u);
    unsigned b15 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 209u, row_index, 0);
    e2 = StwoCudaQm31{ b15, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 407u);
    unsigned b16 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 210u, row_index, 0);
    e0 = StwoCudaQm31{ b16, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 408u);
    unsigned b17 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 211u, row_index, 0);
    e2 = StwoCudaQm31{ b17, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 409u);
    unsigned b18 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 212u, row_index, 0);
    e0 = StwoCudaQm31{ b18, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 410u);
    unsigned b19 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 213u, row_index, 0);
    e2 = StwoCudaQm31{ b19, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 411u);
    unsigned b20 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 214u, row_index, 0);
    e0 = StwoCudaQm31{ b20, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 412u);
    unsigned b21 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 215u, row_index, 0);
    e2 = StwoCudaQm31{ b21, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(ext_params, 413u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(ext_params, 414u);
    unsigned b0 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 50u, row_index, 0);
    unsigned b1 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 51u, row_index, 0);
    unsigned b72 = base_params[107u];
    unsigned b73 = stwo_m31_mul(b1, b72);
    unsigned b74 = stwo_m31_add(b0, b73);
    unsigned b2 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 52u, row_index, 0);
    unsigned b75 = base_params[108u];
    unsigned b76 = stwo_m31_mul(b2, b75);
    unsigned b77 = stwo_m31_add(b74, b76);
    unsigned b3 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 53u, row_index, 0);
    unsigned b78 = base_params[109u];
    unsigned b79 = stwo_m31_mul(b3, b78);
    unsigned b80 = stwo_m31_add(b77, b79);
    unsigned b6 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 103u, row_index, 0);
    unsigned b7 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 104u, row_index, 0);
    unsigned b59 = base_params[103u];
    unsigned b60 = stwo_m31_mul(b7, b59);
    unsigned b61 = stwo_m31_add(b6, b60);
    unsigned b8 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 105u, row_index, 0);
    unsigned b62 = base_params[104u];
    unsigned b63 = stwo_m31_mul(b8, b62);
    unsigned b64 = stwo_m31_add(b61, b63);
    unsigned b9 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 106u, row_index, 0);
    unsigned b65 = base_params[105u];
    unsigned b66 = stwo_m31_mul(b9, b65);
    unsigned b67 = stwo_m31_add(b64, b66);
    unsigned b4 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 101u, row_index, 0);
    unsigned b68 = stwo_m31_sub(b67, b4);
    unsigned b69 = base_params[106u];
    unsigned b5 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 102u, row_index, 0);
    unsigned b70 = stwo_m31_mul(b69, b5);
    unsigned b71 = stwo_m31_sub(b68, b70);
    unsigned b81 = stwo_m31_add(b80, b71);
    unsigned b82 = base_params[116u];
    unsigned b83 = stwo_m31_add(b81, b82);
    e2 = StwoCudaQm31{ b83, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(ext_params, 415u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 416u);
    unsigned b22 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 216u, row_index, 0);
    e1 = StwoCudaQm31{ b22, b58, b58, b58 };
    StwoCudaQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(ext_params, 417u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(ext_params, 418u);
    e1 = StwoCudaQm31{ b22, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(ext_params, 419u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 420u);
    unsigned b23 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 217u, row_index, 0);
    e2 = StwoCudaQm31{ b23, b58, b58, b58 };
    StwoCudaQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 421u);
    unsigned b24 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 218u, row_index, 0);
    e4 = StwoCudaQm31{ b24, b58, b58, b58 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 422u);
    unsigned b25 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 219u, row_index, 0);
    e2 = StwoCudaQm31{ b25, b58, b58, b58 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 423u);
    unsigned b26 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 220u, row_index, 0);
    e4 = StwoCudaQm31{ b26, b58, b58, b58 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 424u);
    unsigned b27 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 221u, row_index, 0);
    e2 = StwoCudaQm31{ b27, b58, b58, b58 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 425u);
    unsigned b28 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 222u, row_index, 0);
    e4 = StwoCudaQm31{ b28, b58, b58, b58 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 426u);
    unsigned b29 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 223u, row_index, 0);
    e2 = StwoCudaQm31{ b29, b58, b58, b58 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 427u);
    unsigned b30 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 224u, row_index, 0);
    e4 = StwoCudaQm31{ b30, b58, b58, b58 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 428u);
    unsigned b31 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 225u, row_index, 0);
    e2 = StwoCudaQm31{ b31, b58, b58, b58 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 429u);
    unsigned b32 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 226u, row_index, 0);
    e4 = StwoCudaQm31{ b32, b58, b58, b58 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 430u);
    unsigned b33 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 227u, row_index, 0);
    e2 = StwoCudaQm31{ b33, b58, b58, b58 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(ext_params, 431u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(ext_params, 432u);
    unsigned b84 = stwo_m31_add(b80, b71);
    unsigned b85 = base_params[117u];
    unsigned b86 = stwo_m31_add(b84, b85);
    e2 = StwoCudaQm31{ b86, b58, b58, b58 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(ext_params, 433u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 434u);
    unsigned b34 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 228u, row_index, 0);
    e1 = StwoCudaQm31{ b34, b58, b58, b58 };
    StwoCudaQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(ext_params, 435u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(ext_params, 436u);
    e1 = StwoCudaQm31{ b34, b58, b58, b58 };
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(ext_params, 437u);
    e6 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 438u);
    unsigned b35 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 229u, row_index, 0);
    e2 = StwoCudaQm31{ b35, b58, b58, b58 };
    StwoCudaQm31 e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 439u);
    unsigned b36 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 230u, row_index, 0);
    e6 = StwoCudaQm31{ b36, b58, b58, b58 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 440u);
    unsigned b37 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 231u, row_index, 0);
    e2 = StwoCudaQm31{ b37, b58, b58, b58 };
    e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 441u);
    unsigned b38 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 232u, row_index, 0);
    e6 = StwoCudaQm31{ b38, b58, b58, b58 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 442u);
    unsigned b39 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 233u, row_index, 0);
    e2 = StwoCudaQm31{ b39, b58, b58, b58 };
    e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 443u);
    unsigned b40 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 234u, row_index, 0);
    e6 = StwoCudaQm31{ b40, b58, b58, b58 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 444u);
    unsigned b41 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 235u, row_index, 0);
    e2 = StwoCudaQm31{ b41, b58, b58, b58 };
    e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 445u);
    unsigned b42 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 236u, row_index, 0);
    e6 = StwoCudaQm31{ b42, b58, b58, b58 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 446u);
    unsigned b43 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 237u, row_index, 0);
    e2 = StwoCudaQm31{ b43, b58, b58, b58 };
    e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 447u);
    unsigned b44 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 238u, row_index, 0);
    e6 = StwoCudaQm31{ b44, b58, b58, b58 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 448u);
    unsigned b45 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 239u, row_index, 0);
    e2 = StwoCudaQm31{ b45, b58, b58, b58 };
    e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(ext_params, 449u);
    e6 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(ext_params, 450u);
    unsigned b87 = stwo_m31_add(b80, b71);
    unsigned b88 = base_params[118u];
    unsigned b89 = stwo_m31_add(b87, b88);
    e2 = StwoCudaQm31{ b89, b58, b58, b58 };
    e1 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(ext_params, 451u);
    e7 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(ext_params, 452u);
    unsigned b46 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 240u, row_index, 0);
    e1 = StwoCudaQm31{ b46, b58, b58, b58 };
    StwoCudaQm31 e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(ext_params, 453u);
    e7 = stwo_qm31_sub(e1, e8);
    e8 = stwo_load_qm31(ext_params, 454u);
    e1 = StwoCudaQm31{ b46, b58, b58, b58 };
    e2 = stwo_qm31_mul(e8, e1);
    e1 = stwo_load_qm31(ext_params, 455u);
    e8 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(ext_params, 456u);
    unsigned b47 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 241u, row_index, 0);
    e2 = StwoCudaQm31{ b47, b58, b58, b58 };
    StwoCudaQm31 e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 457u);
    unsigned b48 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 242u, row_index, 0);
    e8 = StwoCudaQm31{ b48, b58, b58, b58 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 458u);
    unsigned b49 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 243u, row_index, 0);
    e2 = StwoCudaQm31{ b49, b58, b58, b58 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 459u);
    unsigned b50 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 244u, row_index, 0);
    e8 = StwoCudaQm31{ b50, b58, b58, b58 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 460u);
    unsigned b51 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 245u, row_index, 0);
    e2 = StwoCudaQm31{ b51, b58, b58, b58 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 461u);
    unsigned b52 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 246u, row_index, 0);
    e8 = StwoCudaQm31{ b52, b58, b58, b58 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 462u);
    unsigned b53 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 247u, row_index, 0);
    e2 = StwoCudaQm31{ b53, b58, b58, b58 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 463u);
    unsigned b54 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 248u, row_index, 0);
    e8 = StwoCudaQm31{ b54, b58, b58, b58 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 464u);
    unsigned b55 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 249u, row_index, 0);
    e2 = StwoCudaQm31{ b55, b58, b58, b58 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 465u);
    unsigned b56 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 250u, row_index, 0);
    e8 = StwoCudaQm31{ b56, b58, b58, b58 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(ext_params, 466u);
    unsigned b57 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 1u, 251u, row_index, 0);
    e2 = StwoCudaQm31{ b57, b58, b58, b58 };
    e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(ext_params, 467u);
    e8 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(ext_params, 514u);
    e2 = stwo_qm31_mul(e3, e9);
    e9 = stwo_load_qm31(ext_params, 515u);
    e1 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e2, e1);
    e1 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(ext_params, 516u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(ext_params, 517u);
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(ext_params, 518u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(ext_params, 519u);
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e6, e7);
    unsigned b90 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 88u, row_index, 0);
    unsigned b91 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 89u, row_index, 0);
    unsigned b92 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 90u, row_index, 0);
    unsigned b93 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 91u, row_index, 0);
    e7 = StwoCudaQm31{ b90, b91, b92, b93 };
    unsigned b94 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 92u, row_index, 0);
    unsigned b95 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 93u, row_index, 0);
    unsigned b96 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 94u, row_index, 0);
    unsigned b97 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 95u, row_index, 0);
    e6 = StwoCudaQm31{ b94, b95, b96, b97 };
    e4 = stwo_qm31_sub(e6, e7);
    e7 = stwo_qm31_mul(e4, e1);
    e4 = stwo_qm31_sub(e7, e9);
    // Canonical root accumulation begins at first readiness.
    StwoCudaQm31 acc = StwoCudaQm31{0u, 0u, 0u, 0u};
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e4, stwo_load_qm31(random_coeff_powers, rc_base + 0u)));
    unsigned b98 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 96u, row_index, 0);
    unsigned b99 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 97u, row_index, 0);
    unsigned b100 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 98u, row_index, 0);
    unsigned b101 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 99u, row_index, 0);
    e7 = StwoCudaQm31{ b98, b99, b100, b101 };
    e9 = stwo_qm31_sub(e7, e6);
    e6 = stwo_qm31_mul(e9, e2);
    e9 = stwo_qm31_sub(e6, e3);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e9, stwo_load_qm31(random_coeff_powers, rc_base + 1u)));
    unsigned b102 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 100u, row_index, 0);
    unsigned b103 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 101u, row_index, 0);
    unsigned b104 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 102u, row_index, 0);
    unsigned b105 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 103u, row_index, 0);
    e6 = StwoCudaQm31{ b102, b103, b104, b105 };
    e3 = stwo_qm31_sub(e6, e7);
    e7 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e7, e5);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e3, stwo_load_qm31(random_coeff_powers, rc_base + 2u)));
    unsigned b106 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 104u, row_index, -1);
    unsigned b108 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 105u, row_index, -1);
    unsigned b110 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 106u, row_index, -1);
    unsigned b112 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 107u, row_index, -1);
    e7 = StwoCudaQm31{ b106, b108, b110, b112 };
    unsigned b107 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 104u, row_index, 0);
    unsigned b109 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 105u, row_index, 0);
    unsigned b111 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 106u, row_index, 0);
    unsigned b113 = stwo_trace_value(trace_cols, interaction_offsets, row_count, log_n_rows, 2u, 107u, row_index, 0);
    e5 = StwoCudaQm31{ b107, b109, b111, b113 };
    e0 = stwo_qm31_sub(e5, e7);
    e5 = stwo_qm31_sub(e0, e6);
    e0 = stwo_load_qm31(ext_params, 520u);
    e6 = stwo_qm31_add(e5, e0);
    e0 = stwo_qm31_mul(e6, e8);
    e6 = stwo_load_qm31(ext_params, 521u);
    e8 = stwo_qm31_sub(e0, e6);
    acc = stwo_qm31_add(acc, stwo_qm31_mul(e8, stwo_load_qm31(random_coeff_powers, rc_base + 3u)));

    // Fused denom_inv multiply + in-place accumulator update.
    unsigned denom_idx = row_index >> log_n_rows;
    StwoCudaQm31 result = stwo_qm31_mul_base(acc, denom_inv[denom_idx]);
    coord_0[row_index] = stwo_m31_add(coord_0[row_index], result.a);
    coord_1[row_index] = stwo_m31_add(coord_1[row_index], result.b);
    coord_2[row_index] = stwo_m31_add(coord_2[row_index], result.c);
    coord_3[row_index] = stwo_m31_add(coord_3[row_index], result.d);
}
