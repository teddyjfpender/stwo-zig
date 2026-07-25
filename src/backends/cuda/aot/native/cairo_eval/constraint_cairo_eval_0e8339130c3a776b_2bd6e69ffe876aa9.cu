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
stwo_cairo_cuda_eval_v1_2a25a45264394d6d(
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
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 379u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 380u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 381u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 385u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 386u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 387u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 388u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 414u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 415u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 416u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 417u, row, 0);
    unsigned b39 = 0u;
    unsigned b40 = stwo_m31_mul(b0, b1);
    unsigned b41 = stwo_m31_mul(b1, b0);
    unsigned b42 = stwo_m31_add(b40, b41);
    b41 = stwo_m31_mul(b0, b2);
    b40 = stwo_m31_mul(b1, b1);
    unsigned b43 = stwo_m31_add(b41, b40);
    b40 = stwo_m31_mul(b2, b0);
    b41 = stwo_m31_add(b43, b40);
    b40 = stwo_m31_mul(b0, b3);
    b43 = stwo_m31_mul(b1, b2);
    unsigned b44 = stwo_m31_add(b40, b43);
    b43 = stwo_m31_mul(b2, b1);
    b40 = stwo_m31_add(b44, b43);
    b43 = stwo_m31_mul(b3, b0);
    b44 = stwo_m31_add(b40, b43);
    b43 = stwo_m31_mul(b0, b4);
    b40 = stwo_m31_mul(b1, b3);
    unsigned b45 = stwo_m31_add(b43, b40);
    b40 = stwo_m31_mul(b2, b2);
    b43 = stwo_m31_add(b45, b40);
    b40 = stwo_m31_mul(b3, b1);
    b45 = stwo_m31_add(b43, b40);
    b40 = stwo_m31_mul(b4, b0);
    b43 = stwo_m31_add(b45, b40);
    b40 = stwo_m31_mul(b2, b6);
    b45 = stwo_m31_mul(b3, b5);
    unsigned b46 = stwo_m31_add(b40, b45);
    b45 = stwo_m31_mul(b4, b4);
    b40 = stwo_m31_add(b46, b45);
    b45 = stwo_m31_mul(b5, b3);
    b46 = stwo_m31_add(b40, b45);
    b45 = stwo_m31_mul(b6, b2);
    b40 = stwo_m31_add(b46, b45);
    b45 = stwo_m31_mul(b3, b6);
    b46 = stwo_m31_mul(b4, b5);
    unsigned b47 = stwo_m31_add(b45, b46);
    b46 = stwo_m31_mul(b5, b4);
    b45 = stwo_m31_add(b47, b46);
    b46 = stwo_m31_mul(b6, b3);
    b47 = stwo_m31_add(b45, b46);
    b46 = stwo_m31_mul(b4, b6);
    b45 = stwo_m31_mul(b5, b5);
    unsigned b48 = stwo_m31_add(b46, b45);
    b45 = stwo_m31_mul(b6, b4);
    b46 = stwo_m31_add(b48, b45);
    b45 = stwo_m31_mul(b5, b6);
    b48 = stwo_m31_mul(b6, b5);
    unsigned b49 = stwo_m31_add(b45, b48);
    b48 = stwo_m31_mul(b7, b8);
    b45 = stwo_m31_mul(b8, b7);
    unsigned b50 = stwo_m31_add(b48, b45);
    b45 = stwo_m31_mul(b7, b9);
    b48 = stwo_m31_mul(b8, b8);
    unsigned b51 = stwo_m31_add(b45, b48);
    b48 = stwo_m31_mul(b9, b7);
    b45 = stwo_m31_add(b51, b48);
    b48 = stwo_m31_mul(b7, b10);
    b51 = stwo_m31_mul(b8, b9);
    unsigned b52 = stwo_m31_add(b48, b51);
    b51 = stwo_m31_mul(b9, b8);
    b48 = stwo_m31_add(b52, b51);
    b51 = stwo_m31_mul(b10, b7);
    b52 = stwo_m31_add(b48, b51);
    b51 = stwo_m31_mul(b7, b11);
    b48 = stwo_m31_mul(b8, b10);
    unsigned b53 = stwo_m31_add(b51, b48);
    b48 = stwo_m31_mul(b9, b9);
    b51 = stwo_m31_add(b53, b48);
    b48 = stwo_m31_mul(b10, b8);
    b53 = stwo_m31_add(b51, b48);
    b48 = stwo_m31_mul(b11, b7);
    b51 = stwo_m31_add(b53, b48);
    b48 = stwo_m31_mul(b9, b13);
    b53 = stwo_m31_mul(b10, b12);
    unsigned b54 = stwo_m31_add(b48, b53);
    b53 = stwo_m31_mul(b11, b11);
    b48 = stwo_m31_add(b54, b53);
    b53 = stwo_m31_mul(b12, b10);
    b54 = stwo_m31_add(b48, b53);
    b53 = stwo_m31_mul(b13, b9);
    b48 = stwo_m31_add(b54, b53);
    b53 = stwo_m31_mul(b10, b13);
    b54 = stwo_m31_mul(b11, b12);
    unsigned b55 = stwo_m31_add(b53, b54);
    b54 = stwo_m31_mul(b12, b11);
    b53 = stwo_m31_add(b55, b54);
    b54 = stwo_m31_mul(b13, b10);
    b55 = stwo_m31_add(b53, b54);
    b54 = stwo_m31_mul(b11, b13);
    b53 = stwo_m31_mul(b12, b12);
    unsigned b56 = stwo_m31_add(b54, b53);
    b53 = stwo_m31_mul(b13, b11);
    b54 = stwo_m31_add(b56, b53);
    b53 = stwo_m31_mul(b12, b13);
    b56 = stwo_m31_mul(b13, b12);
    unsigned b57 = stwo_m31_add(b53, b56);
    b56 = stwo_m31_add(b0, b7);
    b53 = stwo_m31_add(b1, b8);
    unsigned b58 = stwo_m31_add(b2, b9);
    unsigned b59 = stwo_m31_add(b3, b10);
    unsigned b60 = stwo_m31_add(b4, b11);
    unsigned b61 = stwo_m31_add(b5, b12);
    unsigned b62 = stwo_m31_add(b6, b13);
    unsigned b63 = stwo_m31_add(b0, b7);
    b7 = stwo_m31_add(b1, b8);
    b8 = stwo_m31_add(b2, b9);
    b9 = stwo_m31_add(b3, b10);
    unsigned b64 = stwo_m31_add(b4, b11);
    unsigned b65 = stwo_m31_add(b5, b12);
    b5 = stwo_m31_add(b6, b13);
    b6 = stwo_m31_mul(b56, b8);
    unsigned b66 = stwo_m31_mul(b53, b7);
    unsigned b67 = stwo_m31_add(b6, b66);
    b66 = stwo_m31_mul(b58, b63);
    b6 = stwo_m31_add(b67, b66);
    b66 = stwo_m31_sub(b6, b41);
    b6 = stwo_m31_sub(b66, b45);
    b66 = stwo_m31_add(b47, b6);
    b6 = stwo_m31_mul(b56, b9);
    b67 = stwo_m31_mul(b53, b8);
    unsigned b68 = stwo_m31_add(b6, b67);
    b67 = stwo_m31_mul(b58, b7);
    b6 = stwo_m31_add(b68, b67);
    b67 = stwo_m31_mul(b59, b63);
    b68 = stwo_m31_add(b6, b67);
    b67 = stwo_m31_sub(b68, b44);
    b68 = stwo_m31_sub(b67, b52);
    b67 = stwo_m31_add(b46, b68);
    b68 = stwo_m31_mul(b56, b64);
    b56 = stwo_m31_mul(b53, b9);
    b53 = stwo_m31_add(b68, b56);
    b56 = stwo_m31_mul(b58, b8);
    b68 = stwo_m31_add(b53, b56);
    b56 = stwo_m31_mul(b59, b7);
    b7 = stwo_m31_add(b68, b56);
    b56 = stwo_m31_mul(b60, b63);
    b63 = stwo_m31_add(b7, b56);
    b56 = stwo_m31_sub(b63, b43);
    b63 = stwo_m31_sub(b56, b51);
    b56 = stwo_m31_add(b49, b63);
    b63 = stwo_m31_mul(b58, b5);
    b58 = stwo_m31_mul(b59, b65);
    b7 = stwo_m31_add(b63, b58);
    b58 = stwo_m31_mul(b60, b64);
    b63 = stwo_m31_add(b7, b58);
    b58 = stwo_m31_mul(b61, b9);
    b7 = stwo_m31_add(b63, b58);
    b58 = stwo_m31_mul(b62, b8);
    b8 = stwo_m31_add(b7, b58);
    b58 = stwo_m31_sub(b8, b40);
    b8 = stwo_m31_sub(b58, b48);
    b58 = stwo_m31_add(b50, b8);
    b8 = stwo_m31_mul(b59, b5);
    b59 = stwo_m31_mul(b60, b65);
    b50 = stwo_m31_add(b8, b59);
    b59 = stwo_m31_mul(b61, b64);
    b8 = stwo_m31_add(b50, b59);
    b59 = stwo_m31_mul(b62, b9);
    b9 = stwo_m31_add(b8, b59);
    b59 = stwo_m31_sub(b9, b47);
    b9 = stwo_m31_sub(b59, b55);
    b59 = stwo_m31_add(b45, b9);
    b9 = stwo_m31_mul(b60, b5);
    b60 = stwo_m31_mul(b61, b65);
    b45 = stwo_m31_add(b9, b60);
    b60 = stwo_m31_mul(b62, b64);
    b64 = stwo_m31_add(b45, b60);
    b60 = stwo_m31_sub(b64, b46);
    b64 = stwo_m31_sub(b60, b54);
    b60 = stwo_m31_add(b52, b64);
    b64 = stwo_m31_mul(b61, b5);
    b5 = stwo_m31_mul(b62, b65);
    b65 = stwo_m31_add(b64, b5);
    b5 = stwo_m31_sub(b65, b49);
    b65 = stwo_m31_sub(b5, b57);
    b5 = stwo_m31_add(b51, b65);
    b65 = stwo_m31_mul(b14, b15);
    b51 = stwo_m31_mul(b15, b14);
    b49 = stwo_m31_add(b65, b51);
    b51 = stwo_m31_mul(b14, b16);
    b65 = stwo_m31_mul(b15, b15);
    b64 = stwo_m31_add(b51, b65);
    b65 = stwo_m31_mul(b16, b14);
    b51 = stwo_m31_add(b64, b65);
    b65 = stwo_m31_mul(b14, b17);
    b64 = stwo_m31_mul(b15, b16);
    b62 = stwo_m31_add(b65, b64);
    b64 = stwo_m31_mul(b16, b15);
    b65 = stwo_m31_add(b62, b64);
    b64 = stwo_m31_mul(b17, b14);
    b62 = stwo_m31_add(b65, b64);
    b64 = stwo_m31_mul(b14, b18);
    b65 = stwo_m31_mul(b15, b17);
    b61 = stwo_m31_add(b64, b65);
    b65 = stwo_m31_mul(b16, b16);
    b64 = stwo_m31_add(b61, b65);
    b65 = stwo_m31_mul(b17, b15);
    b61 = stwo_m31_add(b64, b65);
    b65 = stwo_m31_mul(b18, b14);
    b64 = stwo_m31_add(b61, b65);
    b65 = stwo_m31_mul(b17, b20);
    b61 = stwo_m31_mul(b18, b19);
    b52 = stwo_m31_add(b65, b61);
    b61 = stwo_m31_mul(b19, b18);
    b65 = stwo_m31_add(b52, b61);
    b61 = stwo_m31_mul(b20, b17);
    b52 = stwo_m31_add(b65, b61);
    b61 = stwo_m31_mul(b18, b20);
    b65 = stwo_m31_mul(b19, b19);
    b46 = stwo_m31_add(b61, b65);
    b65 = stwo_m31_mul(b20, b18);
    b61 = stwo_m31_add(b46, b65);
    b65 = stwo_m31_mul(b19, b20);
    b46 = stwo_m31_mul(b20, b19);
    b20 = stwo_m31_add(b65, b46);
    b46 = stwo_m31_mul(b21, b23);
    b65 = stwo_m31_mul(b22, b22);
    b19 = stwo_m31_add(b46, b65);
    b65 = stwo_m31_mul(b23, b21);
    b46 = stwo_m31_add(b19, b65);
    b65 = stwo_m31_mul(b21, b24);
    b19 = stwo_m31_mul(b22, b23);
    b45 = stwo_m31_add(b65, b19);
    b19 = stwo_m31_mul(b23, b22);
    b65 = stwo_m31_add(b45, b19);
    b19 = stwo_m31_mul(b24, b21);
    b45 = stwo_m31_add(b65, b19);
    b19 = stwo_m31_mul(b21, b25);
    b65 = stwo_m31_mul(b22, b24);
    b9 = stwo_m31_add(b19, b65);
    b65 = stwo_m31_mul(b23, b23);
    b19 = stwo_m31_add(b9, b65);
    b65 = stwo_m31_mul(b24, b22);
    b9 = stwo_m31_add(b19, b65);
    b65 = stwo_m31_mul(b25, b21);
    b19 = stwo_m31_add(b9, b65);
    b65 = stwo_m31_mul(b24, b27);
    b9 = stwo_m31_mul(b25, b26);
    b47 = stwo_m31_add(b65, b9);
    b9 = stwo_m31_mul(b26, b25);
    b65 = stwo_m31_add(b47, b9);
    b9 = stwo_m31_mul(b27, b24);
    b47 = stwo_m31_add(b65, b9);
    b9 = stwo_m31_mul(b25, b27);
    b65 = stwo_m31_mul(b26, b26);
    b8 = stwo_m31_add(b9, b65);
    b65 = stwo_m31_mul(b27, b25);
    b9 = stwo_m31_add(b8, b65);
    b65 = stwo_m31_mul(b26, b27);
    b8 = stwo_m31_mul(b27, b26);
    b50 = stwo_m31_add(b65, b8);
    b8 = stwo_m31_add(b14, b21);
    b65 = stwo_m31_add(b15, b22);
    b48 = stwo_m31_add(b16, b23);
    b40 = stwo_m31_add(b17, b24);
    b7 = stwo_m31_add(b18, b25);
    b63 = stwo_m31_add(b14, b21);
    b21 = stwo_m31_add(b15, b22);
    b22 = stwo_m31_add(b16, b23);
    b23 = stwo_m31_add(b17, b24);
    b68 = stwo_m31_add(b18, b25);
    b53 = stwo_m31_mul(b8, b22);
    b6 = stwo_m31_mul(b65, b21);
    unsigned b69 = stwo_m31_add(b53, b6);
    b6 = stwo_m31_mul(b48, b63);
    b53 = stwo_m31_add(b69, b6);
    b6 = stwo_m31_sub(b53, b51);
    b53 = stwo_m31_sub(b6, b46);
    b6 = stwo_m31_add(b52, b53);
    b53 = stwo_m31_mul(b8, b23);
    b52 = stwo_m31_mul(b65, b22);
    b46 = stwo_m31_add(b53, b52);
    b52 = stwo_m31_mul(b48, b21);
    b53 = stwo_m31_add(b46, b52);
    b52 = stwo_m31_mul(b40, b63);
    b46 = stwo_m31_add(b53, b52);
    b52 = stwo_m31_sub(b46, b62);
    b46 = stwo_m31_sub(b52, b45);
    b52 = stwo_m31_add(b61, b46);
    b46 = stwo_m31_mul(b8, b68);
    b68 = stwo_m31_mul(b65, b23);
    b23 = stwo_m31_add(b46, b68);
    b68 = stwo_m31_mul(b48, b22);
    b22 = stwo_m31_add(b23, b68);
    b68 = stwo_m31_mul(b40, b21);
    b21 = stwo_m31_add(b22, b68);
    b68 = stwo_m31_mul(b7, b63);
    b63 = stwo_m31_add(b21, b68);
    b68 = stwo_m31_sub(b63, b64);
    b63 = stwo_m31_sub(b68, b19);
    b68 = stwo_m31_add(b20, b63);
    b63 = stwo_m31_add(b0, b14);
    b20 = stwo_m31_add(b1, b15);
    b19 = stwo_m31_add(b2, b16);
    b21 = stwo_m31_add(b3, b17);
    b7 = stwo_m31_add(b4, b18);
    b22 = stwo_m31_add(b10, b24);
    b40 = stwo_m31_add(b11, b25);
    b23 = stwo_m31_add(b12, b26);
    b48 = stwo_m31_add(b13, b27);
    b46 = stwo_m31_add(b0, b14);
    b14 = stwo_m31_add(b1, b15);
    b15 = stwo_m31_add(b2, b16);
    b16 = stwo_m31_add(b3, b17);
    b17 = stwo_m31_add(b4, b18);
    b18 = stwo_m31_add(b10, b24);
    b24 = stwo_m31_add(b11, b25);
    b25 = stwo_m31_add(b12, b26);
    b26 = stwo_m31_add(b13, b27);
    b27 = stwo_m31_mul(b63, b14);
    b13 = stwo_m31_mul(b20, b46);
    b12 = stwo_m31_add(b27, b13);
    b13 = stwo_m31_mul(b63, b15);
    b27 = stwo_m31_mul(b20, b14);
    b11 = stwo_m31_add(b13, b27);
    b27 = stwo_m31_mul(b19, b46);
    b13 = stwo_m31_add(b11, b27);
    b27 = stwo_m31_mul(b63, b16);
    b11 = stwo_m31_mul(b20, b15);
    b10 = stwo_m31_add(b27, b11);
    b11 = stwo_m31_mul(b19, b14);
    b27 = stwo_m31_add(b10, b11);
    b11 = stwo_m31_mul(b21, b46);
    b10 = stwo_m31_add(b27, b11);
    b11 = stwo_m31_mul(b63, b17);
    b17 = stwo_m31_mul(b20, b16);
    b16 = stwo_m31_add(b11, b17);
    b17 = stwo_m31_mul(b19, b15);
    b15 = stwo_m31_add(b16, b17);
    b17 = stwo_m31_mul(b21, b14);
    b14 = stwo_m31_add(b15, b17);
    b17 = stwo_m31_mul(b7, b46);
    b46 = stwo_m31_add(b14, b17);
    b17 = stwo_m31_mul(b22, b26);
    b22 = stwo_m31_mul(b40, b25);
    b14 = stwo_m31_add(b17, b22);
    b22 = stwo_m31_mul(b23, b24);
    b17 = stwo_m31_add(b14, b22);
    b22 = stwo_m31_mul(b48, b18);
    b18 = stwo_m31_add(b17, b22);
    b22 = stwo_m31_mul(b40, b26);
    b40 = stwo_m31_mul(b23, b25);
    b17 = stwo_m31_add(b22, b40);
    b40 = stwo_m31_mul(b48, b24);
    b24 = stwo_m31_add(b17, b40);
    b40 = stwo_m31_mul(b23, b26);
    b26 = stwo_m31_mul(b48, b25);
    b25 = stwo_m31_add(b40, b26);
    b26 = stwo_m31_sub(b12, b42);
    b12 = stwo_m31_sub(b26, b49);
    b26 = stwo_m31_add(b58, b12);
    b12 = stwo_m31_sub(b13, b41);
    b13 = stwo_m31_sub(b12, b51);
    b12 = stwo_m31_add(b59, b13);
    b13 = stwo_m31_sub(b10, b44);
    b10 = stwo_m31_sub(b13, b62);
    b13 = stwo_m31_add(b60, b10);
    b10 = stwo_m31_sub(b46, b43);
    b46 = stwo_m31_sub(b10, b64);
    b10 = stwo_m31_add(b5, b46);
    b46 = stwo_m31_sub(b18, b55);
    b18 = stwo_m31_sub(b46, b47);
    b46 = stwo_m31_add(b6, b18);
    b18 = stwo_m31_sub(b24, b54);
    b24 = stwo_m31_sub(b18, b9);
    b18 = stwo_m31_add(b52, b24);
    b24 = stwo_m31_sub(b25, b57);
    b25 = stwo_m31_sub(b24, b50);
    b24 = stwo_m31_add(b68, b25);
    b25 = stwo_m31_sub(b66, b28);
    b66 = stwo_m31_sub(b67, b29);
    b67 = stwo_m31_sub(b56, b30);
    b56 = stwo_m31_sub(b26, b31);
    b26 = stwo_m31_sub(b12, b32);
    b12 = stwo_m31_sub(b13, b33);
    b13 = stwo_m31_sub(b10, b34);
    b10 = 2u;
    b34 = stwo_m31_mul(b10, b25);
    b10 = stwo_m31_add(b34, b56);
    b34 = 32u;
    b56 = stwo_m31_mul(b34, b26);
    b34 = stwo_m31_add(b10, b56);
    b56 = 4u;
    b10 = stwo_m31_mul(b56, b46);
    b56 = stwo_m31_sub(b34, b10);
    b10 = 2u;
    b34 = stwo_m31_mul(b10, b66);
    b10 = stwo_m31_add(b34, b26);
    b34 = 32u;
    b26 = stwo_m31_mul(b34, b12);
    b34 = stwo_m31_add(b10, b26);
    b26 = 4u;
    b10 = stwo_m31_mul(b26, b18);
    b26 = stwo_m31_sub(b34, b10);
    b10 = 2u;
    b34 = stwo_m31_mul(b10, b67);
    b10 = stwo_m31_add(b34, b12);
    b34 = 32u;
    b12 = stwo_m31_mul(b34, b13);
    b34 = stwo_m31_add(b10, b12);
    b12 = 4u;
    b10 = stwo_m31_mul(b12, b24);
    b12 = stwo_m31_sub(b34, b10);
    b10 = 512u;
    b34 = stwo_m31_mul(b36, b10);
    b10 = stwo_m31_add(b56, b35);
    b56 = stwo_m31_sub(b34, b10);
    b10 = 512u;
    b34 = stwo_m31_mul(b37, b10);
    b10 = stwo_m31_add(b26, b36);
    b26 = stwo_m31_sub(b34, b10);
    b10 = 512u;
    b34 = stwo_m31_mul(b38, b10);
    b10 = stwo_m31_add(b12, b37);
    b12 = stwo_m31_sub(b34, b10);
    StwoCairoQm31 e0 = { b56, b39, b39, b39 };
    StwoCairoQm31 e1 = { b26, b39, b39, b39 };
    StwoCairoQm31 e2 = { b12, b39, b39, b39 };
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
