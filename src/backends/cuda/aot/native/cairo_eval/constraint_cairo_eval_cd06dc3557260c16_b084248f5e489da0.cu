// stwo-zig Cairo CUDA evaluation codegen v1.
typedef unsigned long long u64;
#define STWO_M31_P 2147483647u
struct StwoCairoQm31 { unsigned a, b, c, d; };
struct StwoCairoEvalArgs {
    u64 trace_offsets;
    u64 interaction_offsets;
    u64 base_params;
    u64 ext_params;
    u64 random_coeffs;
    u64 denom_inv;
    u64 coord_0;
    u64 coord_1;
    u64 coord_2;
    u64 coord_3;
    unsigned row_count;
    unsigned trace_log_size;
    unsigned domain_log_size;
    unsigned rc_base;
};
__device__ __forceinline__ unsigned stwo_m31_reduce(u64 value) {
    value = (value & STWO_M31_P) + (value >> 31u);
    value = (value & STWO_M31_P) + (value >> 31u);
    return value == STWO_M31_P ? 0u : (unsigned)value;
}
__device__ __forceinline__ unsigned stwo_m31_add(
    unsigned lhs, unsigned rhs) {
    return stwo_m31_reduce((u64)lhs + rhs);
}
__device__ __forceinline__ unsigned stwo_m31_sub(
    unsigned lhs, unsigned rhs) {
    return lhs >= rhs ? lhs - rhs : lhs + STWO_M31_P - rhs;
}
__device__ __forceinline__ unsigned stwo_m31_mul(
    unsigned lhs, unsigned rhs) {
    return stwo_m31_reduce((u64)lhs * rhs);
}
__device__ __forceinline__ unsigned stwo_m31_neg(unsigned value) {
    return value == 0u ? 0u : STWO_M31_P - value;
}
__device__ __forceinline__ unsigned stwo_m31_inv(unsigned value) {
    unsigned result = 1u, base = value, exponent = STWO_M31_P - 2u;
    while (exponent != 0u) {
        if ((exponent & 1u) != 0u)
            result = stwo_m31_mul(result, base);
        base = stwo_m31_mul(base, base);
        exponent >>= 1u;
    }
    return result;
}
__device__ __forceinline__ StwoCairoQm31 stwo_qm31_add(
    StwoCairoQm31 lhs, StwoCairoQm31 rhs) {
    return {
        stwo_m31_add(lhs.a, rhs.a), stwo_m31_add(lhs.b, rhs.b),
        stwo_m31_add(lhs.c, rhs.c), stwo_m31_add(lhs.d, rhs.d)
    };
}
__device__ __forceinline__ StwoCairoQm31 stwo_qm31_sub(
    StwoCairoQm31 lhs, StwoCairoQm31 rhs) {
    return {
        stwo_m31_sub(lhs.a, rhs.a), stwo_m31_sub(lhs.b, rhs.b),
        stwo_m31_sub(lhs.c, rhs.c), stwo_m31_sub(lhs.d, rhs.d)
    };
}
__device__ __forceinline__ StwoCairoQm31 stwo_qm31_neg(
    StwoCairoQm31 value) {
    return {
        stwo_m31_neg(value.a), stwo_m31_neg(value.b),
        stwo_m31_neg(value.c), stwo_m31_neg(value.d)
    };
}
__device__ __forceinline__ StwoCairoQm31 stwo_qm31_mul_base(
    StwoCairoQm31 value, unsigned scalar) {
    return {
        stwo_m31_mul(value.a, scalar), stwo_m31_mul(value.b, scalar),
        stwo_m31_mul(value.c, scalar), stwo_m31_mul(value.d, scalar)
    };
}
__device__ __forceinline__ StwoCairoQm31 stwo_qm31_mul(
    StwoCairoQm31 lhs, StwoCairoQm31 rhs) {
    unsigned x0 = stwo_m31_sub(
        stwo_m31_mul(lhs.a, rhs.a), stwo_m31_mul(lhs.b, rhs.b));
    unsigned x1 = stwo_m31_add(
        stwo_m31_mul(lhs.a, rhs.b), stwo_m31_mul(lhs.b, rhs.a));
    unsigned y0 = stwo_m31_sub(
        stwo_m31_mul(lhs.c, rhs.c), stwo_m31_mul(lhs.d, rhs.d));
    unsigned y1 = stwo_m31_add(
        stwo_m31_mul(lhs.c, rhs.d), stwo_m31_mul(lhs.d, rhs.c));
    unsigned c0 = stwo_m31_sub(
        stwo_m31_mul(lhs.a, rhs.c), stwo_m31_mul(lhs.b, rhs.d));
    unsigned c1 = stwo_m31_add(
        stwo_m31_mul(lhs.a, rhs.d), stwo_m31_mul(lhs.b, rhs.c));
    unsigned c2 = stwo_m31_sub(
        stwo_m31_mul(lhs.c, rhs.a), stwo_m31_mul(lhs.d, rhs.b));
    unsigned c3 = stwo_m31_add(
        stwo_m31_mul(lhs.c, rhs.b), stwo_m31_mul(lhs.d, rhs.a));
    return {
        stwo_m31_add(x0, stwo_m31_sub(stwo_m31_add(y0, y0), y1)),
        stwo_m31_add(x1, stwo_m31_add(y0, stwo_m31_add(y1, y1))),
        stwo_m31_add(c0, c2), stwo_m31_add(c1, c3)
    };
}
__device__ __forceinline__ StwoCairoQm31 stwo_load_qm31(
    const unsigned *arena, u64 offset) {
    return {
        arena[offset], arena[offset + 1u],
        arena[offset + 2u], arena[offset + 3u]
    };
}
__device__ __forceinline__ unsigned stwo_bit_reverse(
    unsigned value, unsigned bits) {
    return bits == 0u ? 0u : __brev(value) >> (32u - bits);
}
__device__ __forceinline__ unsigned stwo_offset_circle(
    unsigned row, unsigned domain_log, unsigned evaluation_log,
    int offset) {
    unsigned previous = stwo_bit_reverse(row, evaluation_log);
    unsigned half_size = 1u << (evaluation_log - 1u);
    int step = offset * (int)(1u <<
        (evaluation_log - domain_log - 1u));
    if (previous < half_size) {
        int position = ((int)previous + step) % (int)half_size;
        if (position < 0) position += (int)half_size;
        previous = (unsigned)position;
    } else {
        int position = ((int)previous - step) % (int)half_size;
        if (position < 0) position += (int)half_size;
        previous = (unsigned)position + half_size;
    }
    return stwo_bit_reverse(previous, evaluation_log);
}
__device__ __forceinline__ unsigned stwo_trace_value(
    const unsigned *arena, const StwoCairoEvalArgs &args,
    unsigned interaction, unsigned column, unsigned row, int offset) {
    const unsigned evaluation_log =
        31u - (unsigned)__clz(args.row_count);
    const unsigned target = offset == 0 ? row : stwo_offset_circle(
        row, args.domain_log_size, evaluation_log, offset);
    const u64 global =
        (u64)arena[args.interaction_offsets + interaction] + column;
    return arena[(u64)arena[args.trace_offsets + global] + target];
}
extern "C" __global__ void __launch_bounds__(256)
stwo_cairo_cuda_eval_v1_26c874f658656cd5(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 19u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 25u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 41u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 42u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 43u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 47u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 48u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 49u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 51u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 52u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 53u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 54u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 55u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 58u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 59u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 60u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 61u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 62u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 63u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 64u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 65u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 66u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 67u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 389u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 390u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 398u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 424u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 425u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 426u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 427u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 428u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 429u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 430u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 431u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 432u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 433u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 434u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 435u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 436u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 437u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 438u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 439u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 440u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 441u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 442u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 443u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 444u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 445u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 446u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 447u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 448u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 449u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 1u, 450u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 1u, 451u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 1u, 452u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 1u, 453u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 1u, 454u, row, 0);
    unsigned b90 = 0u;
    unsigned b91 = stwo_m31_mul(b0, b5);
    unsigned b92 = stwo_m31_mul(b1, b4);
    unsigned b93 = stwo_m31_add(b91, b92);
    b92 = stwo_m31_mul(b2, b3);
    b91 = stwo_m31_add(b93, b92);
    b92 = stwo_m31_mul(b3, b2);
    b93 = stwo_m31_add(b91, b92);
    b92 = stwo_m31_mul(b4, b1);
    b91 = stwo_m31_add(b93, b92);
    b92 = stwo_m31_mul(b5, b0);
    b93 = stwo_m31_add(b91, b92);
    b92 = stwo_m31_mul(b0, b6);
    b91 = stwo_m31_mul(b1, b5);
    unsigned b94 = stwo_m31_add(b92, b91);
    b91 = stwo_m31_mul(b2, b4);
    b92 = stwo_m31_add(b94, b91);
    b91 = stwo_m31_mul(b3, b3);
    b94 = stwo_m31_add(b92, b91);
    b91 = stwo_m31_mul(b4, b2);
    b92 = stwo_m31_add(b94, b91);
    b91 = stwo_m31_mul(b5, b1);
    b94 = stwo_m31_add(b92, b91);
    b91 = stwo_m31_mul(b6, b0);
    b92 = stwo_m31_add(b94, b91);
    b91 = stwo_m31_mul(b6, b6);
    b94 = stwo_m31_mul(b7, b12);
    unsigned b95 = stwo_m31_mul(b8, b11);
    unsigned b96 = stwo_m31_add(b94, b95);
    b95 = stwo_m31_mul(b9, b10);
    b94 = stwo_m31_add(b96, b95);
    b95 = stwo_m31_mul(b10, b9);
    b96 = stwo_m31_add(b94, b95);
    b95 = stwo_m31_mul(b11, b8);
    b94 = stwo_m31_add(b96, b95);
    b95 = stwo_m31_mul(b12, b7);
    b96 = stwo_m31_add(b94, b95);
    b95 = stwo_m31_mul(b7, b13);
    b94 = stwo_m31_mul(b8, b12);
    unsigned b97 = stwo_m31_add(b95, b94);
    b94 = stwo_m31_mul(b9, b11);
    b95 = stwo_m31_add(b97, b94);
    b94 = stwo_m31_mul(b10, b10);
    b10 = stwo_m31_add(b95, b94);
    b94 = stwo_m31_mul(b11, b9);
    b11 = stwo_m31_add(b10, b94);
    b94 = stwo_m31_mul(b12, b8);
    b12 = stwo_m31_add(b11, b94);
    b94 = stwo_m31_mul(b13, b7);
    b7 = stwo_m31_add(b12, b94);
    b94 = stwo_m31_mul(b13, b13);
    b12 = stwo_m31_add(b6, b13);
    b11 = stwo_m31_add(b6, b13);
    b13 = stwo_m31_mul(b12, b11);
    b11 = stwo_m31_sub(b13, b91);
    b13 = stwo_m31_sub(b11, b94);
    b11 = stwo_m31_add(b96, b13);
    b13 = stwo_m31_mul(b14, b19);
    b96 = stwo_m31_mul(b15, b18);
    b94 = stwo_m31_add(b13, b96);
    b96 = stwo_m31_mul(b16, b17);
    b13 = stwo_m31_add(b94, b96);
    b96 = stwo_m31_mul(b17, b16);
    b94 = stwo_m31_add(b13, b96);
    b96 = stwo_m31_mul(b18, b15);
    b13 = stwo_m31_add(b94, b96);
    b96 = stwo_m31_mul(b19, b14);
    b94 = stwo_m31_add(b13, b96);
    b96 = stwo_m31_mul(b14, b20);
    b13 = stwo_m31_mul(b15, b19);
    b91 = stwo_m31_add(b96, b13);
    b13 = stwo_m31_mul(b16, b18);
    b96 = stwo_m31_add(b91, b13);
    b13 = stwo_m31_mul(b17, b17);
    b91 = stwo_m31_add(b96, b13);
    b13 = stwo_m31_mul(b18, b16);
    b96 = stwo_m31_add(b91, b13);
    b13 = stwo_m31_mul(b19, b15);
    b91 = stwo_m31_add(b96, b13);
    b13 = stwo_m31_mul(b20, b14);
    b96 = stwo_m31_add(b91, b13);
    b13 = stwo_m31_mul(b20, b20);
    b91 = stwo_m31_mul(b21, b26);
    b12 = stwo_m31_mul(b22, b25);
    b8 = stwo_m31_add(b91, b12);
    b12 = stwo_m31_mul(b23, b24);
    b91 = stwo_m31_add(b8, b12);
    b12 = stwo_m31_mul(b24, b23);
    b8 = stwo_m31_add(b91, b12);
    b12 = stwo_m31_mul(b25, b22);
    b91 = stwo_m31_add(b8, b12);
    b12 = stwo_m31_mul(b26, b21);
    b8 = stwo_m31_add(b91, b12);
    b12 = stwo_m31_mul(b21, b27);
    b91 = stwo_m31_mul(b22, b26);
    b10 = stwo_m31_add(b12, b91);
    b91 = stwo_m31_mul(b23, b25);
    b12 = stwo_m31_add(b10, b91);
    b91 = stwo_m31_mul(b24, b24);
    b24 = stwo_m31_add(b12, b91);
    b91 = stwo_m31_mul(b25, b23);
    b25 = stwo_m31_add(b24, b91);
    b91 = stwo_m31_mul(b26, b22);
    b22 = stwo_m31_add(b25, b91);
    b91 = stwo_m31_mul(b27, b21);
    b21 = stwo_m31_add(b22, b91);
    b91 = stwo_m31_mul(b26, b27);
    b22 = stwo_m31_mul(b27, b26);
    b26 = stwo_m31_add(b91, b22);
    b22 = stwo_m31_mul(b27, b27);
    b91 = stwo_m31_add(b20, b27);
    b25 = stwo_m31_add(b20, b27);
    b27 = stwo_m31_mul(b91, b25);
    b25 = stwo_m31_sub(b27, b13);
    b27 = stwo_m31_sub(b25, b22);
    b25 = stwo_m31_add(b8, b27);
    b27 = stwo_m31_add(b0, b14);
    b8 = stwo_m31_add(b1, b15);
    b13 = stwo_m31_add(b2, b16);
    b91 = stwo_m31_add(b3, b17);
    b24 = stwo_m31_add(b4, b18);
    b23 = stwo_m31_add(b5, b19);
    b12 = stwo_m31_add(b6, b20);
    b10 = stwo_m31_add(b0, b14);
    b14 = stwo_m31_add(b1, b15);
    b15 = stwo_m31_add(b2, b16);
    b16 = stwo_m31_add(b3, b17);
    b17 = stwo_m31_add(b4, b18);
    b18 = stwo_m31_add(b5, b19);
    b19 = stwo_m31_add(b6, b20);
    b20 = stwo_m31_mul(b27, b18);
    b6 = stwo_m31_mul(b8, b17);
    b5 = stwo_m31_add(b20, b6);
    b6 = stwo_m31_mul(b13, b16);
    b20 = stwo_m31_add(b5, b6);
    b6 = stwo_m31_mul(b91, b15);
    b5 = stwo_m31_add(b20, b6);
    b6 = stwo_m31_mul(b24, b14);
    b20 = stwo_m31_add(b5, b6);
    b6 = stwo_m31_mul(b23, b10);
    b5 = stwo_m31_add(b20, b6);
    b6 = stwo_m31_mul(b27, b19);
    b19 = stwo_m31_mul(b8, b18);
    b18 = stwo_m31_add(b6, b19);
    b19 = stwo_m31_mul(b13, b17);
    b17 = stwo_m31_add(b18, b19);
    b19 = stwo_m31_mul(b91, b16);
    b16 = stwo_m31_add(b17, b19);
    b19 = stwo_m31_mul(b24, b15);
    b15 = stwo_m31_add(b16, b19);
    b19 = stwo_m31_mul(b23, b14);
    b14 = stwo_m31_add(b15, b19);
    b19 = stwo_m31_mul(b12, b10);
    b10 = stwo_m31_add(b14, b19);
    b19 = stwo_m31_sub(b5, b93);
    b5 = stwo_m31_sub(b19, b94);
    b19 = stwo_m31_add(b11, b5);
    b5 = stwo_m31_sub(b10, b92);
    b10 = stwo_m31_sub(b5, b96);
    b5 = stwo_m31_add(b7, b10);
    b10 = stwo_m31_sub(b19, b56);
    b19 = stwo_m31_sub(b5, b57);
    b5 = 2u;
    b57 = stwo_m31_mul(b5, b10);
    b5 = 4u;
    b10 = stwo_m31_mul(b5, b25);
    b5 = stwo_m31_sub(b57, b10);
    b10 = 2u;
    b57 = stwo_m31_mul(b10, b26);
    b10 = stwo_m31_add(b5, b57);
    b57 = 64u;
    b5 = stwo_m31_mul(b57, b22);
    b57 = stwo_m31_add(b10, b5);
    b5 = 2u;
    b10 = stwo_m31_mul(b5, b19);
    b5 = 4u;
    b19 = stwo_m31_mul(b5, b21);
    b5 = stwo_m31_sub(b10, b19);
    b19 = 2u;
    b10 = stwo_m31_mul(b19, b22);
    b19 = stwo_m31_add(b5, b10);
    b10 = 512u;
    b5 = stwo_m31_mul(b60, b10);
    b10 = stwo_m31_add(b57, b59);
    b57 = stwo_m31_sub(b5, b10);
    b10 = 256u;
    b5 = stwo_m31_mul(b10, b58);
    b10 = stwo_m31_sub(b19, b5);
    b5 = stwo_m31_add(b10, b60);
    b10 = 1u;
    b60 = stwo_m31_sub(b89, b10);
    b10 = stwo_m31_mul(b89, b60);
    b60 = stwo_m31_add(b30, b30);
    b30 = stwo_m31_add(b29, b29);
    b29 = stwo_m31_add(b28, b28);
    b28 = stwo_m31_sub(b29, b61);
    b29 = stwo_m31_sub(b28, b89);
    b28 = 4194304u;
    b61 = stwo_m31_mul(b29, b28);
    b28 = stwo_m31_add(b30, b61);
    b61 = stwo_m31_sub(b28, b62);
    b28 = 4194304u;
    b62 = stwo_m31_mul(b61, b28);
    b28 = stwo_m31_add(b60, b62);
    b62 = stwo_m31_sub(b28, b63);
    b28 = 4194304u;
    b63 = stwo_m31_mul(b62, b28);
    b28 = stwo_m31_mul(b63, b63);
    b62 = 1u;
    b60 = stwo_m31_sub(b28, b62);
    b62 = stwo_m31_mul(b63, b60);
    b60 = stwo_m31_add(b33, b33);
    b33 = stwo_m31_add(b32, b32);
    b32 = stwo_m31_add(b31, b31);
    b31 = stwo_m31_add(b32, b63);
    b32 = stwo_m31_sub(b31, b64);
    b31 = 4194304u;
    b64 = stwo_m31_mul(b32, b31);
    b31 = stwo_m31_add(b33, b64);
    b64 = stwo_m31_sub(b31, b65);
    b31 = 4194304u;
    b65 = stwo_m31_mul(b64, b31);
    b31 = stwo_m31_add(b60, b65);
    b65 = stwo_m31_sub(b31, b66);
    b31 = 4194304u;
    b66 = stwo_m31_mul(b65, b31);
    b31 = stwo_m31_mul(b66, b66);
    b65 = 1u;
    b60 = stwo_m31_sub(b31, b65);
    b65 = stwo_m31_mul(b66, b60);
    b60 = stwo_m31_add(b36, b36);
    b36 = stwo_m31_add(b35, b35);
    b35 = stwo_m31_add(b34, b34);
    b34 = stwo_m31_add(b35, b66);
    b35 = stwo_m31_sub(b34, b67);
    b34 = 4194304u;
    b67 = stwo_m31_mul(b35, b34);
    b34 = stwo_m31_add(b36, b67);
    b67 = stwo_m31_sub(b34, b68);
    b34 = 4194304u;
    b68 = stwo_m31_mul(b67, b34);
    b34 = stwo_m31_add(b60, b68);
    b68 = stwo_m31_sub(b34, b69);
    b34 = 4194304u;
    b69 = stwo_m31_mul(b68, b34);
    b34 = stwo_m31_mul(b69, b69);
    b68 = 1u;
    b60 = stwo_m31_sub(b34, b68);
    b68 = stwo_m31_mul(b69, b60);
    b60 = stwo_m31_add(b39, b39);
    b39 = stwo_m31_add(b38, b38);
    b38 = stwo_m31_add(b37, b37);
    b37 = stwo_m31_add(b38, b69);
    b38 = stwo_m31_sub(b37, b70);
    b37 = 4194304u;
    b70 = stwo_m31_mul(b38, b37);
    b37 = stwo_m31_add(b39, b70);
    b70 = stwo_m31_sub(b37, b71);
    b37 = 4194304u;
    b71 = stwo_m31_mul(b70, b37);
    b37 = stwo_m31_add(b60, b71);
    b71 = stwo_m31_sub(b37, b72);
    b37 = 4194304u;
    b72 = stwo_m31_mul(b71, b37);
    b37 = stwo_m31_mul(b72, b72);
    b71 = 1u;
    b60 = stwo_m31_sub(b37, b71);
    b71 = stwo_m31_mul(b72, b60);
    b60 = stwo_m31_add(b42, b42);
    b42 = stwo_m31_add(b41, b41);
    b41 = stwo_m31_add(b40, b40);
    b40 = stwo_m31_add(b41, b72);
    b41 = stwo_m31_sub(b40, b73);
    b40 = 4194304u;
    b73 = stwo_m31_mul(b41, b40);
    b40 = stwo_m31_add(b42, b73);
    b73 = stwo_m31_sub(b40, b74);
    b40 = 4194304u;
    b74 = stwo_m31_mul(b73, b40);
    b40 = stwo_m31_add(b60, b74);
    b74 = stwo_m31_sub(b40, b75);
    b40 = 4194304u;
    b75 = stwo_m31_mul(b74, b40);
    b40 = stwo_m31_mul(b75, b75);
    b74 = 1u;
    b60 = stwo_m31_sub(b40, b74);
    b74 = stwo_m31_mul(b75, b60);
    b60 = stwo_m31_add(b45, b45);
    b45 = stwo_m31_add(b44, b44);
    b44 = stwo_m31_add(b43, b43);
    b43 = stwo_m31_add(b44, b75);
    b44 = stwo_m31_sub(b43, b76);
    b43 = 4194304u;
    b76 = stwo_m31_mul(b44, b43);
    b43 = stwo_m31_add(b45, b76);
    b76 = stwo_m31_sub(b43, b77);
    b43 = 4194304u;
    b77 = stwo_m31_mul(b76, b43);
    b43 = stwo_m31_add(b60, b77);
    b77 = stwo_m31_sub(b43, b78);
    b43 = 4194304u;
    b78 = stwo_m31_mul(b77, b43);
    b43 = stwo_m31_mul(b78, b78);
    b77 = 1u;
    b60 = stwo_m31_sub(b43, b77);
    b77 = stwo_m31_mul(b78, b60);
    b60 = stwo_m31_add(b48, b48);
    b48 = stwo_m31_add(b47, b47);
    b47 = stwo_m31_add(b46, b46);
    b46 = stwo_m31_add(b47, b78);
    b47 = stwo_m31_sub(b46, b79);
    b46 = 4194304u;
    b79 = stwo_m31_mul(b47, b46);
    b46 = stwo_m31_add(b48, b79);
    b79 = stwo_m31_sub(b46, b80);
    b46 = 4194304u;
    b80 = stwo_m31_mul(b79, b46);
    b46 = stwo_m31_add(b60, b80);
    b80 = stwo_m31_sub(b46, b81);
    b46 = 4194304u;
    b81 = stwo_m31_mul(b80, b46);
    b46 = stwo_m31_mul(b81, b81);
    b80 = 1u;
    b60 = stwo_m31_sub(b46, b80);
    b80 = stwo_m31_mul(b81, b60);
    b60 = stwo_m31_add(b51, b51);
    b51 = stwo_m31_add(b50, b50);
    b50 = stwo_m31_add(b49, b49);
    b49 = stwo_m31_add(b50, b81);
    b50 = stwo_m31_sub(b49, b82);
    b49 = 136u;
    b82 = stwo_m31_mul(b49, b89);
    b49 = stwo_m31_sub(b50, b82);
    b82 = 4194304u;
    b50 = stwo_m31_mul(b49, b82);
    b82 = stwo_m31_add(b51, b50);
    b50 = stwo_m31_sub(b82, b83);
    b82 = 4194304u;
    b83 = stwo_m31_mul(b50, b82);
    b82 = stwo_m31_add(b60, b83);
    b83 = stwo_m31_sub(b82, b84);
    b82 = 4194304u;
    b84 = stwo_m31_mul(b83, b82);
    b82 = stwo_m31_mul(b84, b84);
    b83 = 1u;
    b60 = stwo_m31_sub(b82, b83);
    b83 = stwo_m31_mul(b84, b60);
    b60 = stwo_m31_add(b54, b54);
    b54 = stwo_m31_add(b53, b53);
    b53 = stwo_m31_add(b52, b52);
    b52 = stwo_m31_add(b53, b84);
    b53 = stwo_m31_sub(b52, b85);
    b52 = 4194304u;
    b85 = stwo_m31_mul(b53, b52);
    b52 = stwo_m31_add(b54, b85);
    b85 = stwo_m31_sub(b52, b86);
    b52 = 4194304u;
    b86 = stwo_m31_mul(b85, b52);
    b52 = stwo_m31_add(b60, b86);
    b86 = stwo_m31_sub(b52, b87);
    b52 = 4194304u;
    b87 = stwo_m31_mul(b86, b52);
    b52 = stwo_m31_mul(b87, b87);
    b86 = 1u;
    b60 = stwo_m31_sub(b52, b86);
    b86 = stwo_m31_mul(b87, b60);
    b60 = stwo_m31_add(b55, b55);
    b55 = stwo_m31_add(b60, b87);
    b60 = stwo_m31_sub(b55, b88);
    b55 = 256u;
    b88 = stwo_m31_mul(b55, b89);
    b55 = stwo_m31_sub(b60, b88);
    StwoCairoQm31 e0 = { b57, b90, b90, b90 };
    StwoCairoQm31 e1 = { b5, b90, b90, b90 };
    StwoCairoQm31 e2 = { b10, b90, b90, b90 };
    StwoCairoQm31 e3 = { b62, b90, b90, b90 };
    StwoCairoQm31 e4 = { b65, b90, b90, b90 };
    StwoCairoQm31 e5 = { b68, b90, b90, b90 };
    StwoCairoQm31 e6 = { b71, b90, b90, b90 };
    StwoCairoQm31 e7 = { b74, b90, b90, b90 };
    StwoCairoQm31 e8 = { b77, b90, b90, b90 };
    StwoCairoQm31 e9 = { b80, b90, b90, b90 };
    StwoCairoQm31 e10 = { b83, b90, b90, b90 };
    StwoCairoQm31 e11 = { b86, b90, b90, b90 };
    StwoCairoQm31 e12 = { b55, b90, b90, b90 };
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e4, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e6, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e8, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 8u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e9, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 9u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e10, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 10u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e11, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 11u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e12, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 12u) * 4u)));
    StwoCairoQm31 result = stwo_qm31_mul_base(
        part_acc,
        arena[args->denom_inv +
            (row >> args->trace_log_size)]);
    StwoCairoQm31 cumulative = {
        arena[args->coord_0 + row],
        arena[args->coord_1 + row],
        arena[args->coord_2 + row],
        arena[args->coord_3 + row]
    };
    cumulative = stwo_qm31_add(cumulative, result);
    arena[args->coord_0 + row] = cumulative.a;
    arena[args->coord_1 + row] = cumulative.b;
    arena[args->coord_2 + row] = cumulative.c;
    arena[args->coord_3 + row] = cumulative.d;
    (void)arena_words;
}
