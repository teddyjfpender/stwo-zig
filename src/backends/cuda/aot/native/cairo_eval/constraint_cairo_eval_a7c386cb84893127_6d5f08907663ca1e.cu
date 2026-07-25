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
stwo_cairo_cuda_eval_v1_18bc0122a1f5780e(
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
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 376u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 377u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 378u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 382u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 383u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 384u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 385u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 411u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 412u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 413u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 414u, row, 0);
    unsigned b39 = 0u;
    unsigned b40 = stwo_m31_mul(b0, b0);
    unsigned b41 = stwo_m31_mul(b0, b1);
    unsigned b42 = stwo_m31_mul(b1, b0);
    unsigned b43 = stwo_m31_add(b41, b42);
    b42 = stwo_m31_mul(b0, b5);
    b41 = stwo_m31_mul(b1, b4);
    unsigned b44 = stwo_m31_add(b42, b41);
    b41 = stwo_m31_mul(b2, b3);
    b42 = stwo_m31_add(b44, b41);
    b41 = stwo_m31_mul(b3, b2);
    b44 = stwo_m31_add(b42, b41);
    b41 = stwo_m31_mul(b4, b1);
    b42 = stwo_m31_add(b44, b41);
    b41 = stwo_m31_mul(b5, b0);
    b44 = stwo_m31_add(b42, b41);
    b41 = stwo_m31_mul(b0, b6);
    b42 = stwo_m31_mul(b1, b5);
    unsigned b45 = stwo_m31_add(b41, b42);
    b42 = stwo_m31_mul(b2, b4);
    b41 = stwo_m31_add(b45, b42);
    b42 = stwo_m31_mul(b3, b3);
    b45 = stwo_m31_add(b41, b42);
    b42 = stwo_m31_mul(b4, b2);
    b41 = stwo_m31_add(b45, b42);
    b42 = stwo_m31_mul(b5, b1);
    b45 = stwo_m31_add(b41, b42);
    b42 = stwo_m31_mul(b6, b0);
    b41 = stwo_m31_add(b45, b42);
    b42 = stwo_m31_mul(b1, b6);
    b45 = stwo_m31_mul(b2, b5);
    unsigned b46 = stwo_m31_add(b42, b45);
    b45 = stwo_m31_mul(b3, b4);
    b42 = stwo_m31_add(b46, b45);
    b45 = stwo_m31_mul(b4, b3);
    b46 = stwo_m31_add(b42, b45);
    b45 = stwo_m31_mul(b5, b2);
    b42 = stwo_m31_add(b46, b45);
    b45 = stwo_m31_mul(b6, b1);
    b46 = stwo_m31_add(b42, b45);
    b45 = stwo_m31_mul(b2, b6);
    b42 = stwo_m31_mul(b3, b5);
    unsigned b47 = stwo_m31_add(b45, b42);
    b42 = stwo_m31_mul(b4, b4);
    b45 = stwo_m31_add(b47, b42);
    b42 = stwo_m31_mul(b5, b3);
    b47 = stwo_m31_add(b45, b42);
    b42 = stwo_m31_mul(b6, b2);
    b45 = stwo_m31_add(b47, b42);
    b42 = stwo_m31_mul(b6, b6);
    b47 = stwo_m31_mul(b7, b7);
    unsigned b48 = stwo_m31_mul(b7, b8);
    unsigned b49 = stwo_m31_mul(b8, b7);
    unsigned b50 = stwo_m31_add(b48, b49);
    b49 = stwo_m31_mul(b7, b12);
    b48 = stwo_m31_mul(b8, b11);
    unsigned b51 = stwo_m31_add(b49, b48);
    b48 = stwo_m31_mul(b9, b10);
    b49 = stwo_m31_add(b51, b48);
    b48 = stwo_m31_mul(b10, b9);
    b51 = stwo_m31_add(b49, b48);
    b48 = stwo_m31_mul(b11, b8);
    b49 = stwo_m31_add(b51, b48);
    b48 = stwo_m31_mul(b12, b7);
    b51 = stwo_m31_add(b49, b48);
    b48 = stwo_m31_mul(b7, b13);
    b49 = stwo_m31_mul(b8, b12);
    unsigned b52 = stwo_m31_add(b48, b49);
    b49 = stwo_m31_mul(b9, b11);
    b48 = stwo_m31_add(b52, b49);
    b49 = stwo_m31_mul(b10, b10);
    b52 = stwo_m31_add(b48, b49);
    b49 = stwo_m31_mul(b11, b9);
    b48 = stwo_m31_add(b52, b49);
    b49 = stwo_m31_mul(b12, b8);
    b52 = stwo_m31_add(b48, b49);
    b49 = stwo_m31_mul(b13, b7);
    b48 = stwo_m31_add(b52, b49);
    b49 = stwo_m31_mul(b8, b13);
    b52 = stwo_m31_mul(b9, b12);
    unsigned b53 = stwo_m31_add(b49, b52);
    b52 = stwo_m31_mul(b10, b11);
    b49 = stwo_m31_add(b53, b52);
    b52 = stwo_m31_mul(b11, b10);
    b53 = stwo_m31_add(b49, b52);
    b52 = stwo_m31_mul(b12, b9);
    b49 = stwo_m31_add(b53, b52);
    b52 = stwo_m31_mul(b13, b8);
    b53 = stwo_m31_add(b49, b52);
    b52 = stwo_m31_mul(b9, b13);
    b49 = stwo_m31_mul(b10, b12);
    unsigned b54 = stwo_m31_add(b52, b49);
    b49 = stwo_m31_mul(b11, b11);
    b52 = stwo_m31_add(b54, b49);
    b49 = stwo_m31_mul(b12, b10);
    b54 = stwo_m31_add(b52, b49);
    b49 = stwo_m31_mul(b13, b9);
    b52 = stwo_m31_add(b54, b49);
    b49 = stwo_m31_add(b0, b7);
    b54 = stwo_m31_add(b1, b8);
    unsigned b55 = stwo_m31_add(b2, b9);
    unsigned b56 = stwo_m31_add(b3, b10);
    unsigned b57 = stwo_m31_add(b4, b11);
    unsigned b58 = stwo_m31_add(b5, b12);
    unsigned b59 = stwo_m31_add(b6, b13);
    unsigned b60 = stwo_m31_add(b0, b7);
    unsigned b61 = stwo_m31_add(b1, b8);
    unsigned b62 = stwo_m31_add(b2, b9);
    b2 = stwo_m31_add(b3, b10);
    b3 = stwo_m31_add(b4, b11);
    b4 = stwo_m31_add(b5, b12);
    b5 = stwo_m31_add(b6, b13);
    b6 = stwo_m31_mul(b49, b60);
    unsigned b63 = stwo_m31_sub(b6, b40);
    b6 = stwo_m31_sub(b63, b47);
    b63 = stwo_m31_add(b46, b6);
    b6 = stwo_m31_mul(b49, b61);
    unsigned b64 = stwo_m31_mul(b54, b60);
    unsigned b65 = stwo_m31_add(b6, b64);
    b64 = stwo_m31_sub(b65, b43);
    b65 = stwo_m31_sub(b64, b50);
    b64 = stwo_m31_add(b45, b65);
    b65 = stwo_m31_mul(b49, b4);
    b6 = stwo_m31_mul(b54, b3);
    unsigned b66 = stwo_m31_add(b65, b6);
    b6 = stwo_m31_mul(b55, b2);
    b65 = stwo_m31_add(b66, b6);
    b6 = stwo_m31_mul(b56, b62);
    b66 = stwo_m31_add(b65, b6);
    b6 = stwo_m31_mul(b57, b61);
    b65 = stwo_m31_add(b66, b6);
    b6 = stwo_m31_mul(b58, b60);
    b66 = stwo_m31_add(b65, b6);
    b6 = stwo_m31_sub(b66, b44);
    b66 = stwo_m31_sub(b6, b51);
    b6 = stwo_m31_add(b42, b66);
    b66 = stwo_m31_mul(b49, b5);
    b49 = stwo_m31_mul(b54, b4);
    b42 = stwo_m31_add(b66, b49);
    b49 = stwo_m31_mul(b55, b3);
    b66 = stwo_m31_add(b42, b49);
    b49 = stwo_m31_mul(b56, b2);
    b42 = stwo_m31_add(b66, b49);
    b49 = stwo_m31_mul(b57, b62);
    b66 = stwo_m31_add(b42, b49);
    b49 = stwo_m31_mul(b58, b61);
    b42 = stwo_m31_add(b66, b49);
    b49 = stwo_m31_mul(b59, b60);
    b60 = stwo_m31_add(b42, b49);
    b49 = stwo_m31_sub(b60, b41);
    b60 = stwo_m31_sub(b49, b48);
    b49 = stwo_m31_mul(b54, b5);
    b54 = stwo_m31_mul(b55, b4);
    b42 = stwo_m31_add(b49, b54);
    b54 = stwo_m31_mul(b56, b3);
    b49 = stwo_m31_add(b42, b54);
    b54 = stwo_m31_mul(b57, b2);
    b42 = stwo_m31_add(b49, b54);
    b54 = stwo_m31_mul(b58, b62);
    b49 = stwo_m31_add(b42, b54);
    b54 = stwo_m31_mul(b59, b61);
    b61 = stwo_m31_add(b49, b54);
    b54 = stwo_m31_sub(b61, b46);
    b61 = stwo_m31_sub(b54, b53);
    b54 = stwo_m31_add(b47, b61);
    b61 = stwo_m31_mul(b55, b5);
    b5 = stwo_m31_mul(b56, b4);
    b4 = stwo_m31_add(b61, b5);
    b5 = stwo_m31_mul(b57, b3);
    b3 = stwo_m31_add(b4, b5);
    b5 = stwo_m31_mul(b58, b2);
    b2 = stwo_m31_add(b3, b5);
    b5 = stwo_m31_mul(b59, b62);
    b62 = stwo_m31_add(b2, b5);
    b5 = stwo_m31_sub(b62, b45);
    b62 = stwo_m31_sub(b5, b52);
    b5 = stwo_m31_add(b50, b62);
    b62 = stwo_m31_mul(b14, b14);
    b50 = stwo_m31_mul(b14, b15);
    b45 = stwo_m31_mul(b15, b14);
    b2 = stwo_m31_add(b50, b45);
    b45 = stwo_m31_mul(b14, b20);
    b50 = stwo_m31_mul(b15, b19);
    b59 = stwo_m31_add(b45, b50);
    b50 = stwo_m31_mul(b16, b18);
    b45 = stwo_m31_add(b59, b50);
    b50 = stwo_m31_mul(b17, b17);
    b59 = stwo_m31_add(b45, b50);
    b50 = stwo_m31_mul(b18, b16);
    b45 = stwo_m31_add(b59, b50);
    b50 = stwo_m31_mul(b19, b15);
    b59 = stwo_m31_add(b45, b50);
    b50 = stwo_m31_mul(b20, b14);
    b45 = stwo_m31_add(b59, b50);
    b50 = stwo_m31_mul(b15, b20);
    b59 = stwo_m31_mul(b16, b19);
    b3 = stwo_m31_add(b50, b59);
    b59 = stwo_m31_mul(b17, b18);
    b50 = stwo_m31_add(b3, b59);
    b59 = stwo_m31_mul(b18, b17);
    b3 = stwo_m31_add(b50, b59);
    b59 = stwo_m31_mul(b19, b16);
    b50 = stwo_m31_add(b3, b59);
    b59 = stwo_m31_mul(b20, b15);
    b3 = stwo_m31_add(b50, b59);
    b59 = stwo_m31_mul(b16, b20);
    b50 = stwo_m31_mul(b17, b19);
    b58 = stwo_m31_add(b59, b50);
    b50 = stwo_m31_mul(b18, b18);
    b18 = stwo_m31_add(b58, b50);
    b50 = stwo_m31_mul(b19, b17);
    b19 = stwo_m31_add(b18, b50);
    b50 = stwo_m31_mul(b20, b16);
    b20 = stwo_m31_add(b19, b50);
    b50 = stwo_m31_mul(b21, b21);
    b19 = stwo_m31_mul(b21, b22);
    b16 = stwo_m31_mul(b22, b21);
    b18 = stwo_m31_add(b19, b16);
    b16 = stwo_m31_mul(b21, b27);
    b19 = stwo_m31_mul(b22, b26);
    b17 = stwo_m31_add(b16, b19);
    b19 = stwo_m31_mul(b23, b25);
    b16 = stwo_m31_add(b17, b19);
    b19 = stwo_m31_mul(b24, b24);
    b17 = stwo_m31_add(b16, b19);
    b19 = stwo_m31_mul(b25, b23);
    b16 = stwo_m31_add(b17, b19);
    b19 = stwo_m31_mul(b26, b22);
    b17 = stwo_m31_add(b16, b19);
    b19 = stwo_m31_mul(b27, b21);
    b16 = stwo_m31_add(b17, b19);
    b19 = stwo_m31_mul(b22, b27);
    b17 = stwo_m31_mul(b23, b26);
    b58 = stwo_m31_add(b19, b17);
    b17 = stwo_m31_mul(b24, b25);
    b19 = stwo_m31_add(b58, b17);
    b17 = stwo_m31_mul(b25, b24);
    b58 = stwo_m31_add(b19, b17);
    b17 = stwo_m31_mul(b26, b23);
    b19 = stwo_m31_add(b58, b17);
    b17 = stwo_m31_mul(b27, b22);
    b58 = stwo_m31_add(b19, b17);
    b17 = stwo_m31_mul(b23, b27);
    b19 = stwo_m31_mul(b24, b26);
    b59 = stwo_m31_add(b17, b19);
    b19 = stwo_m31_mul(b25, b25);
    b17 = stwo_m31_add(b59, b19);
    b19 = stwo_m31_mul(b26, b24);
    b59 = stwo_m31_add(b17, b19);
    b19 = stwo_m31_mul(b27, b23);
    b17 = stwo_m31_add(b59, b19);
    b19 = stwo_m31_add(b14, b21);
    b59 = stwo_m31_add(b15, b22);
    b4 = stwo_m31_add(b14, b21);
    b57 = stwo_m31_add(b15, b22);
    b61 = stwo_m31_mul(b19, b4);
    b56 = stwo_m31_sub(b61, b62);
    b61 = stwo_m31_sub(b56, b50);
    b56 = stwo_m31_add(b3, b61);
    b61 = stwo_m31_mul(b19, b57);
    b57 = stwo_m31_mul(b59, b4);
    b4 = stwo_m31_add(b61, b57);
    b57 = stwo_m31_sub(b4, b2);
    b4 = stwo_m31_sub(b57, b18);
    b57 = stwo_m31_add(b20, b4);
    b4 = stwo_m31_add(b0, b14);
    b20 = stwo_m31_add(b1, b15);
    b18 = stwo_m31_add(b7, b21);
    b61 = stwo_m31_add(b8, b22);
    b59 = stwo_m31_add(b9, b23);
    b19 = stwo_m31_add(b10, b24);
    b3 = stwo_m31_add(b11, b25);
    b50 = stwo_m31_add(b12, b26);
    b55 = stwo_m31_add(b13, b27);
    b47 = stwo_m31_add(b0, b14);
    b14 = stwo_m31_add(b1, b15);
    b15 = stwo_m31_add(b7, b21);
    b21 = stwo_m31_add(b8, b22);
    b22 = stwo_m31_add(b9, b23);
    b23 = stwo_m31_add(b10, b24);
    b24 = stwo_m31_add(b11, b25);
    b25 = stwo_m31_add(b12, b26);
    b26 = stwo_m31_add(b13, b27);
    b27 = stwo_m31_mul(b4, b47);
    b13 = stwo_m31_mul(b4, b14);
    b14 = stwo_m31_mul(b20, b47);
    b47 = stwo_m31_add(b13, b14);
    b14 = stwo_m31_mul(b18, b26);
    b18 = stwo_m31_mul(b61, b25);
    b13 = stwo_m31_add(b14, b18);
    b18 = stwo_m31_mul(b59, b24);
    b14 = stwo_m31_add(b13, b18);
    b18 = stwo_m31_mul(b19, b23);
    b13 = stwo_m31_add(b14, b18);
    b18 = stwo_m31_mul(b3, b22);
    b14 = stwo_m31_add(b13, b18);
    b18 = stwo_m31_mul(b50, b21);
    b13 = stwo_m31_add(b14, b18);
    b18 = stwo_m31_mul(b55, b15);
    b15 = stwo_m31_add(b13, b18);
    b18 = stwo_m31_mul(b61, b26);
    b61 = stwo_m31_mul(b59, b25);
    b13 = stwo_m31_add(b18, b61);
    b61 = stwo_m31_mul(b19, b24);
    b18 = stwo_m31_add(b13, b61);
    b61 = stwo_m31_mul(b3, b23);
    b13 = stwo_m31_add(b18, b61);
    b61 = stwo_m31_mul(b50, b22);
    b18 = stwo_m31_add(b13, b61);
    b61 = stwo_m31_mul(b55, b21);
    b21 = stwo_m31_add(b18, b61);
    b61 = stwo_m31_mul(b59, b26);
    b26 = stwo_m31_mul(b19, b25);
    b25 = stwo_m31_add(b61, b26);
    b26 = stwo_m31_mul(b3, b24);
    b24 = stwo_m31_add(b25, b26);
    b26 = stwo_m31_mul(b50, b23);
    b23 = stwo_m31_add(b24, b26);
    b26 = stwo_m31_mul(b55, b22);
    b22 = stwo_m31_add(b23, b26);
    b26 = stwo_m31_sub(b27, b40);
    b27 = stwo_m31_sub(b26, b62);
    b26 = stwo_m31_add(b54, b27);
    b27 = stwo_m31_sub(b47, b43);
    b47 = stwo_m31_sub(b27, b2);
    b27 = stwo_m31_add(b5, b47);
    b47 = stwo_m31_sub(b15, b48);
    b15 = stwo_m31_sub(b47, b16);
    b47 = stwo_m31_add(b45, b15);
    b15 = stwo_m31_sub(b21, b53);
    b21 = stwo_m31_sub(b15, b58);
    b15 = stwo_m31_add(b56, b21);
    b21 = stwo_m31_sub(b22, b52);
    b22 = stwo_m31_sub(b21, b17);
    b21 = stwo_m31_add(b57, b22);
    b22 = stwo_m31_sub(b41, b28);
    b41 = stwo_m31_sub(b63, b29);
    b63 = stwo_m31_sub(b64, b30);
    b64 = stwo_m31_sub(b6, b31);
    b6 = stwo_m31_sub(b60, b32);
    b60 = stwo_m31_sub(b26, b33);
    b26 = stwo_m31_sub(b27, b34);
    b27 = 2u;
    b34 = stwo_m31_mul(b27, b22);
    b27 = stwo_m31_add(b34, b64);
    b34 = 32u;
    b64 = stwo_m31_mul(b34, b6);
    b34 = stwo_m31_add(b27, b64);
    b64 = 4u;
    b27 = stwo_m31_mul(b64, b47);
    b64 = stwo_m31_sub(b34, b27);
    b27 = 2u;
    b34 = stwo_m31_mul(b27, b41);
    b27 = stwo_m31_add(b34, b6);
    b34 = 32u;
    b6 = stwo_m31_mul(b34, b60);
    b34 = stwo_m31_add(b27, b6);
    b6 = 4u;
    b27 = stwo_m31_mul(b6, b15);
    b6 = stwo_m31_sub(b34, b27);
    b27 = 2u;
    b34 = stwo_m31_mul(b27, b63);
    b27 = stwo_m31_add(b34, b60);
    b34 = 32u;
    b60 = stwo_m31_mul(b34, b26);
    b34 = stwo_m31_add(b27, b60);
    b60 = 4u;
    b27 = stwo_m31_mul(b60, b21);
    b60 = stwo_m31_sub(b34, b27);
    b27 = 512u;
    b34 = stwo_m31_mul(b36, b27);
    b27 = stwo_m31_add(b64, b35);
    b64 = stwo_m31_sub(b34, b27);
    b27 = 512u;
    b34 = stwo_m31_mul(b37, b27);
    b27 = stwo_m31_add(b6, b36);
    b6 = stwo_m31_sub(b34, b27);
    b27 = 512u;
    b34 = stwo_m31_mul(b38, b27);
    b27 = stwo_m31_add(b60, b37);
    b60 = stwo_m31_sub(b34, b27);
    StwoCairoQm31 e0 = { b64, b39, b39, b39 };
    StwoCairoQm31 e1 = { b6, b39, b39, b39 };
    StwoCairoQm31 e2 = { b60, b39, b39, b39 };
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
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
