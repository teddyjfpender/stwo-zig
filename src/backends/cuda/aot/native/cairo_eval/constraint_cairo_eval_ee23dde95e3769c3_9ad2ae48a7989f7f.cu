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
stwo_cairo_cuda_eval_v1_6ee567d71333077a(
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
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 370u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 371u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 372u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 373u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 392u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 393u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 394u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 399u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 400u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 401u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 402u, row, 0);
    unsigned b39 = 0u;
    unsigned b40 = stwo_m31_mul(b0, b0);
    unsigned b41 = stwo_m31_mul(b0, b1);
    unsigned b42 = stwo_m31_mul(b1, b0);
    unsigned b43 = stwo_m31_add(b41, b42);
    b42 = stwo_m31_mul(b0, b2);
    b41 = stwo_m31_mul(b1, b1);
    unsigned b44 = stwo_m31_add(b42, b41);
    b41 = stwo_m31_mul(b2, b0);
    b42 = stwo_m31_add(b44, b41);
    b41 = stwo_m31_mul(b0, b3);
    b44 = stwo_m31_mul(b1, b2);
    unsigned b45 = stwo_m31_add(b41, b44);
    b44 = stwo_m31_mul(b2, b1);
    b41 = stwo_m31_add(b45, b44);
    b44 = stwo_m31_mul(b3, b0);
    b45 = stwo_m31_add(b41, b44);
    b44 = stwo_m31_mul(b2, b6);
    b41 = stwo_m31_mul(b3, b5);
    unsigned b46 = stwo_m31_add(b44, b41);
    b41 = stwo_m31_mul(b4, b4);
    b44 = stwo_m31_add(b46, b41);
    b41 = stwo_m31_mul(b5, b3);
    b46 = stwo_m31_add(b44, b41);
    b41 = stwo_m31_mul(b6, b2);
    b44 = stwo_m31_add(b46, b41);
    b41 = stwo_m31_mul(b3, b6);
    b46 = stwo_m31_mul(b4, b5);
    unsigned b47 = stwo_m31_add(b41, b46);
    b46 = stwo_m31_mul(b5, b4);
    b41 = stwo_m31_add(b47, b46);
    b46 = stwo_m31_mul(b6, b3);
    b47 = stwo_m31_add(b41, b46);
    b46 = stwo_m31_mul(b4, b6);
    b41 = stwo_m31_mul(b5, b5);
    unsigned b48 = stwo_m31_add(b46, b41);
    b41 = stwo_m31_mul(b6, b4);
    b46 = stwo_m31_add(b48, b41);
    b41 = stwo_m31_mul(b7, b8);
    b48 = stwo_m31_mul(b8, b7);
    unsigned b49 = stwo_m31_add(b41, b48);
    b48 = stwo_m31_mul(b7, b9);
    b41 = stwo_m31_mul(b8, b8);
    unsigned b50 = stwo_m31_add(b48, b41);
    b41 = stwo_m31_mul(b9, b7);
    b48 = stwo_m31_add(b50, b41);
    b41 = stwo_m31_mul(b7, b10);
    b50 = stwo_m31_mul(b8, b9);
    unsigned b51 = stwo_m31_add(b41, b50);
    b50 = stwo_m31_mul(b9, b8);
    b41 = stwo_m31_add(b51, b50);
    b50 = stwo_m31_mul(b10, b7);
    b51 = stwo_m31_add(b41, b50);
    b50 = stwo_m31_mul(b9, b13);
    b41 = stwo_m31_mul(b10, b12);
    unsigned b52 = stwo_m31_add(b50, b41);
    b41 = stwo_m31_mul(b11, b11);
    b50 = stwo_m31_add(b52, b41);
    b41 = stwo_m31_mul(b12, b10);
    b52 = stwo_m31_add(b50, b41);
    b41 = stwo_m31_mul(b13, b9);
    b50 = stwo_m31_add(b52, b41);
    b41 = stwo_m31_mul(b10, b13);
    b52 = stwo_m31_mul(b11, b12);
    unsigned b53 = stwo_m31_add(b41, b52);
    b52 = stwo_m31_mul(b12, b11);
    b41 = stwo_m31_add(b53, b52);
    b52 = stwo_m31_mul(b13, b10);
    b53 = stwo_m31_add(b41, b52);
    b52 = stwo_m31_mul(b11, b13);
    b41 = stwo_m31_mul(b12, b12);
    b12 = stwo_m31_add(b52, b41);
    b41 = stwo_m31_mul(b13, b11);
    b13 = stwo_m31_add(b12, b41);
    b41 = stwo_m31_add(b0, b7);
    b12 = stwo_m31_add(b1, b8);
    b11 = stwo_m31_add(b2, b9);
    b52 = stwo_m31_add(b3, b10);
    unsigned b54 = stwo_m31_add(b0, b7);
    unsigned b55 = stwo_m31_add(b1, b8);
    unsigned b56 = stwo_m31_add(b2, b9);
    unsigned b57 = stwo_m31_add(b3, b10);
    unsigned b58 = stwo_m31_mul(b41, b55);
    unsigned b59 = stwo_m31_mul(b12, b54);
    unsigned b60 = stwo_m31_add(b58, b59);
    b59 = stwo_m31_sub(b60, b43);
    b60 = stwo_m31_sub(b59, b49);
    b59 = stwo_m31_add(b44, b60);
    b60 = stwo_m31_mul(b41, b56);
    b44 = stwo_m31_mul(b12, b55);
    b49 = stwo_m31_add(b60, b44);
    b44 = stwo_m31_mul(b11, b54);
    b60 = stwo_m31_add(b49, b44);
    b44 = stwo_m31_sub(b60, b42);
    b60 = stwo_m31_sub(b44, b48);
    b44 = stwo_m31_add(b47, b60);
    b60 = stwo_m31_mul(b41, b57);
    b57 = stwo_m31_mul(b12, b56);
    b56 = stwo_m31_add(b60, b57);
    b57 = stwo_m31_mul(b11, b55);
    b55 = stwo_m31_add(b56, b57);
    b57 = stwo_m31_mul(b52, b54);
    b54 = stwo_m31_add(b55, b57);
    b57 = stwo_m31_sub(b54, b45);
    b54 = stwo_m31_sub(b57, b51);
    b57 = stwo_m31_add(b46, b54);
    b54 = stwo_m31_mul(b14, b15);
    b46 = stwo_m31_mul(b15, b14);
    b51 = stwo_m31_add(b54, b46);
    b46 = stwo_m31_mul(b14, b16);
    b54 = stwo_m31_mul(b15, b15);
    b55 = stwo_m31_add(b46, b54);
    b54 = stwo_m31_mul(b16, b14);
    b46 = stwo_m31_add(b55, b54);
    b54 = stwo_m31_mul(b14, b17);
    b55 = stwo_m31_mul(b15, b16);
    b52 = stwo_m31_add(b54, b55);
    b55 = stwo_m31_mul(b16, b15);
    b54 = stwo_m31_add(b52, b55);
    b55 = stwo_m31_mul(b17, b14);
    b52 = stwo_m31_add(b54, b55);
    b55 = stwo_m31_mul(b16, b20);
    b54 = stwo_m31_mul(b17, b19);
    b56 = stwo_m31_add(b55, b54);
    b54 = stwo_m31_mul(b18, b18);
    b55 = stwo_m31_add(b56, b54);
    b54 = stwo_m31_mul(b19, b17);
    b56 = stwo_m31_add(b55, b54);
    b54 = stwo_m31_mul(b20, b16);
    b55 = stwo_m31_add(b56, b54);
    b54 = stwo_m31_mul(b17, b20);
    b56 = stwo_m31_mul(b18, b19);
    b11 = stwo_m31_add(b54, b56);
    b56 = stwo_m31_mul(b19, b18);
    b54 = stwo_m31_add(b11, b56);
    b56 = stwo_m31_mul(b20, b17);
    b11 = stwo_m31_add(b54, b56);
    b56 = stwo_m31_mul(b18, b20);
    b54 = stwo_m31_mul(b19, b19);
    b60 = stwo_m31_add(b56, b54);
    b54 = stwo_m31_mul(b20, b18);
    b56 = stwo_m31_add(b60, b54);
    b54 = stwo_m31_mul(b21, b22);
    b60 = stwo_m31_mul(b22, b21);
    b12 = stwo_m31_add(b54, b60);
    b60 = stwo_m31_mul(b21, b23);
    b54 = stwo_m31_mul(b22, b22);
    b41 = stwo_m31_add(b60, b54);
    b54 = stwo_m31_mul(b23, b21);
    b60 = stwo_m31_add(b41, b54);
    b54 = stwo_m31_mul(b21, b24);
    b41 = stwo_m31_mul(b22, b23);
    b47 = stwo_m31_add(b54, b41);
    b41 = stwo_m31_mul(b23, b22);
    b54 = stwo_m31_add(b47, b41);
    b41 = stwo_m31_mul(b24, b21);
    b47 = stwo_m31_add(b54, b41);
    b41 = stwo_m31_mul(b23, b27);
    b54 = stwo_m31_mul(b24, b26);
    b48 = stwo_m31_add(b41, b54);
    b54 = stwo_m31_mul(b25, b25);
    b41 = stwo_m31_add(b48, b54);
    b54 = stwo_m31_mul(b26, b24);
    b48 = stwo_m31_add(b41, b54);
    b54 = stwo_m31_mul(b27, b23);
    b41 = stwo_m31_add(b48, b54);
    b54 = stwo_m31_mul(b24, b27);
    b48 = stwo_m31_mul(b25, b26);
    b49 = stwo_m31_add(b54, b48);
    b48 = stwo_m31_mul(b26, b25);
    b54 = stwo_m31_add(b49, b48);
    b48 = stwo_m31_mul(b27, b24);
    b49 = stwo_m31_add(b54, b48);
    b48 = stwo_m31_mul(b25, b27);
    b54 = stwo_m31_mul(b26, b26);
    b26 = stwo_m31_add(b48, b54);
    b54 = stwo_m31_mul(b27, b25);
    b27 = stwo_m31_add(b26, b54);
    b54 = stwo_m31_add(b14, b21);
    b26 = stwo_m31_add(b15, b22);
    b25 = stwo_m31_add(b16, b23);
    b48 = stwo_m31_add(b17, b24);
    b58 = stwo_m31_add(b14, b21);
    unsigned b61 = stwo_m31_add(b15, b22);
    unsigned b62 = stwo_m31_add(b16, b23);
    unsigned b63 = stwo_m31_add(b17, b24);
    unsigned b64 = stwo_m31_mul(b54, b61);
    unsigned b65 = stwo_m31_mul(b26, b58);
    unsigned b66 = stwo_m31_add(b64, b65);
    b65 = stwo_m31_sub(b66, b51);
    b66 = stwo_m31_sub(b65, b12);
    b65 = stwo_m31_add(b55, b66);
    b66 = stwo_m31_mul(b54, b62);
    b55 = stwo_m31_mul(b26, b61);
    b12 = stwo_m31_add(b66, b55);
    b55 = stwo_m31_mul(b25, b58);
    b66 = stwo_m31_add(b12, b55);
    b55 = stwo_m31_sub(b66, b46);
    b66 = stwo_m31_sub(b55, b60);
    b55 = stwo_m31_add(b11, b66);
    b66 = stwo_m31_mul(b54, b63);
    b63 = stwo_m31_mul(b26, b62);
    b62 = stwo_m31_add(b66, b63);
    b63 = stwo_m31_mul(b25, b61);
    b61 = stwo_m31_add(b62, b63);
    b63 = stwo_m31_mul(b48, b58);
    b58 = stwo_m31_add(b61, b63);
    b63 = stwo_m31_sub(b58, b52);
    b58 = stwo_m31_sub(b63, b47);
    b63 = stwo_m31_add(b56, b58);
    b58 = stwo_m31_add(b0, b14);
    b56 = stwo_m31_add(b1, b15);
    b47 = stwo_m31_add(b2, b16);
    b52 = stwo_m31_add(b3, b17);
    b61 = stwo_m31_add(b4, b18);
    b48 = stwo_m31_add(b5, b19);
    b62 = stwo_m31_add(b6, b20);
    b25 = stwo_m31_add(b7, b21);
    b66 = stwo_m31_add(b8, b22);
    b26 = stwo_m31_add(b9, b23);
    b54 = stwo_m31_add(b10, b24);
    b11 = stwo_m31_add(b0, b14);
    b14 = stwo_m31_add(b1, b15);
    b15 = stwo_m31_add(b2, b16);
    b16 = stwo_m31_add(b3, b17);
    b17 = stwo_m31_add(b4, b18);
    b18 = stwo_m31_add(b5, b19);
    b19 = stwo_m31_add(b6, b20);
    b20 = stwo_m31_add(b7, b21);
    b21 = stwo_m31_add(b8, b22);
    b22 = stwo_m31_add(b9, b23);
    b23 = stwo_m31_add(b10, b24);
    b24 = stwo_m31_mul(b58, b14);
    b10 = stwo_m31_mul(b56, b11);
    b9 = stwo_m31_add(b24, b10);
    b10 = stwo_m31_mul(b58, b15);
    b24 = stwo_m31_mul(b56, b14);
    b8 = stwo_m31_add(b10, b24);
    b24 = stwo_m31_mul(b47, b11);
    b10 = stwo_m31_add(b8, b24);
    b24 = stwo_m31_mul(b58, b16);
    b8 = stwo_m31_mul(b56, b15);
    b7 = stwo_m31_add(b24, b8);
    b8 = stwo_m31_mul(b47, b14);
    b24 = stwo_m31_add(b7, b8);
    b8 = stwo_m31_mul(b52, b11);
    b7 = stwo_m31_add(b24, b8);
    b8 = stwo_m31_mul(b47, b19);
    b24 = stwo_m31_mul(b52, b18);
    b6 = stwo_m31_add(b8, b24);
    b24 = stwo_m31_mul(b61, b17);
    b8 = stwo_m31_add(b6, b24);
    b24 = stwo_m31_mul(b48, b16);
    b6 = stwo_m31_add(b8, b24);
    b24 = stwo_m31_mul(b62, b15);
    b8 = stwo_m31_add(b6, b24);
    b24 = stwo_m31_mul(b52, b19);
    b6 = stwo_m31_mul(b61, b18);
    b5 = stwo_m31_add(b24, b6);
    b6 = stwo_m31_mul(b48, b17);
    b24 = stwo_m31_add(b5, b6);
    b6 = stwo_m31_mul(b62, b16);
    b5 = stwo_m31_add(b24, b6);
    b6 = stwo_m31_mul(b61, b19);
    b19 = stwo_m31_mul(b48, b18);
    b18 = stwo_m31_add(b6, b19);
    b19 = stwo_m31_mul(b62, b17);
    b17 = stwo_m31_add(b18, b19);
    b19 = stwo_m31_mul(b25, b21);
    b18 = stwo_m31_mul(b66, b20);
    b62 = stwo_m31_add(b19, b18);
    b18 = stwo_m31_mul(b25, b22);
    b19 = stwo_m31_mul(b66, b21);
    b6 = stwo_m31_add(b18, b19);
    b19 = stwo_m31_mul(b26, b20);
    b18 = stwo_m31_add(b6, b19);
    b19 = stwo_m31_mul(b25, b23);
    b6 = stwo_m31_mul(b66, b22);
    b48 = stwo_m31_add(b19, b6);
    b6 = stwo_m31_mul(b26, b21);
    b19 = stwo_m31_add(b48, b6);
    b6 = stwo_m31_mul(b54, b20);
    b48 = stwo_m31_add(b19, b6);
    b6 = stwo_m31_add(b58, b25);
    b25 = stwo_m31_add(b56, b66);
    b66 = stwo_m31_add(b47, b26);
    b26 = stwo_m31_add(b52, b54);
    b54 = stwo_m31_add(b11, b20);
    b20 = stwo_m31_add(b14, b21);
    b21 = stwo_m31_add(b15, b22);
    b22 = stwo_m31_add(b16, b23);
    b23 = stwo_m31_mul(b6, b20);
    b16 = stwo_m31_mul(b25, b54);
    b15 = stwo_m31_add(b23, b16);
    b16 = stwo_m31_sub(b15, b9);
    b15 = stwo_m31_sub(b16, b62);
    b16 = stwo_m31_add(b8, b15);
    b15 = stwo_m31_mul(b6, b21);
    b8 = stwo_m31_mul(b25, b20);
    b62 = stwo_m31_add(b15, b8);
    b8 = stwo_m31_mul(b66, b54);
    b15 = stwo_m31_add(b62, b8);
    b8 = stwo_m31_sub(b15, b10);
    b15 = stwo_m31_sub(b8, b18);
    b8 = stwo_m31_add(b5, b15);
    b15 = stwo_m31_mul(b6, b22);
    b22 = stwo_m31_mul(b25, b21);
    b21 = stwo_m31_add(b15, b22);
    b22 = stwo_m31_mul(b66, b20);
    b20 = stwo_m31_add(b21, b22);
    b22 = stwo_m31_mul(b26, b54);
    b54 = stwo_m31_add(b20, b22);
    b22 = stwo_m31_sub(b54, b7);
    b54 = stwo_m31_sub(b22, b48);
    b22 = stwo_m31_add(b17, b54);
    b54 = stwo_m31_sub(b16, b59);
    b16 = stwo_m31_sub(b54, b65);
    b54 = stwo_m31_add(b50, b16);
    b16 = stwo_m31_sub(b8, b44);
    b8 = stwo_m31_sub(b16, b55);
    b16 = stwo_m31_add(b53, b8);
    b8 = stwo_m31_sub(b22, b57);
    b22 = stwo_m31_sub(b8, b63);
    b8 = stwo_m31_add(b13, b22);
    b22 = stwo_m31_sub(b40, b28);
    b40 = stwo_m31_sub(b43, b29);
    b43 = stwo_m31_sub(b42, b30);
    b42 = stwo_m31_sub(b45, b31);
    b45 = stwo_m31_sub(b54, b32);
    b54 = stwo_m31_sub(b16, b33);
    b16 = stwo_m31_sub(b8, b34);
    b8 = 32u;
    b34 = stwo_m31_mul(b8, b40);
    b8 = stwo_m31_add(b22, b34);
    b34 = 4u;
    b22 = stwo_m31_mul(b34, b45);
    b34 = stwo_m31_sub(b8, b22);
    b22 = 8u;
    b8 = stwo_m31_mul(b22, b41);
    b22 = stwo_m31_add(b34, b8);
    b8 = 32u;
    b34 = stwo_m31_mul(b8, b43);
    b8 = stwo_m31_add(b40, b34);
    b34 = 4u;
    b40 = stwo_m31_mul(b34, b54);
    b34 = stwo_m31_sub(b8, b40);
    b40 = 8u;
    b8 = stwo_m31_mul(b40, b49);
    b40 = stwo_m31_add(b34, b8);
    b8 = 32u;
    b34 = stwo_m31_mul(b8, b42);
    b8 = stwo_m31_add(b43, b34);
    b34 = 4u;
    b43 = stwo_m31_mul(b34, b16);
    b34 = stwo_m31_sub(b8, b43);
    b43 = 8u;
    b8 = stwo_m31_mul(b43, b27);
    b43 = stwo_m31_add(b34, b8);
    b8 = 512u;
    b34 = stwo_m31_mul(b36, b8);
    b8 = stwo_m31_add(b22, b35);
    b22 = stwo_m31_sub(b34, b8);
    b8 = 512u;
    b34 = stwo_m31_mul(b37, b8);
    b8 = stwo_m31_add(b40, b36);
    b40 = stwo_m31_sub(b34, b8);
    b8 = 512u;
    b34 = stwo_m31_mul(b38, b8);
    b8 = stwo_m31_add(b43, b37);
    b43 = stwo_m31_sub(b34, b8);
    StwoCairoQm31 e0 = { b22, b39, b39, b39 };
    StwoCairoQm31 e1 = { b40, b39, b39, b39 };
    StwoCairoQm31 e2 = { b43, b39, b39, b39 };
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
