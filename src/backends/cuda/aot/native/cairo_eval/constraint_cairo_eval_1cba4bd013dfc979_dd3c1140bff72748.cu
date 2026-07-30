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
stwo_cairo_cuda_eval_v1_8d65a27b7a8ade8f(
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
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 376u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 377u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 378u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 379u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 405u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 406u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 407u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 408u, row, 0);
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
    b41 = stwo_m31_mul(b0, b6);
    b44 = stwo_m31_mul(b1, b5);
    unsigned b45 = stwo_m31_add(b41, b44);
    b44 = stwo_m31_mul(b2, b4);
    b41 = stwo_m31_add(b45, b44);
    b44 = stwo_m31_mul(b3, b3);
    b45 = stwo_m31_add(b41, b44);
    b44 = stwo_m31_mul(b4, b2);
    b41 = stwo_m31_add(b45, b44);
    b44 = stwo_m31_mul(b5, b1);
    b45 = stwo_m31_add(b41, b44);
    b44 = stwo_m31_mul(b6, b0);
    b41 = stwo_m31_add(b45, b44);
    b44 = stwo_m31_mul(b1, b6);
    b45 = stwo_m31_mul(b2, b5);
    unsigned b46 = stwo_m31_add(b44, b45);
    b45 = stwo_m31_mul(b3, b4);
    b44 = stwo_m31_add(b46, b45);
    b45 = stwo_m31_mul(b4, b3);
    b46 = stwo_m31_add(b44, b45);
    b45 = stwo_m31_mul(b5, b2);
    b44 = stwo_m31_add(b46, b45);
    b45 = stwo_m31_mul(b6, b1);
    b46 = stwo_m31_add(b44, b45);
    b45 = stwo_m31_mul(b2, b6);
    b44 = stwo_m31_mul(b3, b5);
    unsigned b47 = stwo_m31_add(b45, b44);
    b44 = stwo_m31_mul(b4, b4);
    b45 = stwo_m31_add(b47, b44);
    b44 = stwo_m31_mul(b5, b3);
    b47 = stwo_m31_add(b45, b44);
    b44 = stwo_m31_mul(b6, b2);
    b45 = stwo_m31_add(b47, b44);
    b44 = stwo_m31_mul(b3, b6);
    b47 = stwo_m31_mul(b4, b5);
    unsigned b48 = stwo_m31_add(b44, b47);
    b47 = stwo_m31_mul(b5, b4);
    b44 = stwo_m31_add(b48, b47);
    b47 = stwo_m31_mul(b6, b3);
    b48 = stwo_m31_add(b44, b47);
    b47 = stwo_m31_mul(b7, b7);
    b44 = stwo_m31_mul(b7, b8);
    unsigned b49 = stwo_m31_mul(b8, b7);
    unsigned b50 = stwo_m31_add(b44, b49);
    b49 = stwo_m31_mul(b7, b9);
    b44 = stwo_m31_mul(b8, b8);
    unsigned b51 = stwo_m31_add(b49, b44);
    b44 = stwo_m31_mul(b9, b7);
    b49 = stwo_m31_add(b51, b44);
    b44 = stwo_m31_mul(b8, b13);
    b51 = stwo_m31_mul(b9, b12);
    unsigned b52 = stwo_m31_add(b44, b51);
    b51 = stwo_m31_mul(b10, b11);
    b44 = stwo_m31_add(b52, b51);
    b51 = stwo_m31_mul(b11, b10);
    b52 = stwo_m31_add(b44, b51);
    b51 = stwo_m31_mul(b12, b9);
    b44 = stwo_m31_add(b52, b51);
    b51 = stwo_m31_mul(b13, b8);
    b52 = stwo_m31_add(b44, b51);
    b51 = stwo_m31_mul(b9, b13);
    b44 = stwo_m31_mul(b10, b12);
    unsigned b53 = stwo_m31_add(b51, b44);
    b44 = stwo_m31_mul(b11, b11);
    b51 = stwo_m31_add(b53, b44);
    b44 = stwo_m31_mul(b12, b10);
    b53 = stwo_m31_add(b51, b44);
    b44 = stwo_m31_mul(b13, b9);
    b51 = stwo_m31_add(b53, b44);
    b44 = stwo_m31_mul(b10, b13);
    b53 = stwo_m31_mul(b11, b12);
    unsigned b54 = stwo_m31_add(b44, b53);
    b53 = stwo_m31_mul(b12, b11);
    b44 = stwo_m31_add(b54, b53);
    b53 = stwo_m31_mul(b13, b10);
    b54 = stwo_m31_add(b44, b53);
    b53 = stwo_m31_add(b0, b7);
    b44 = stwo_m31_add(b1, b8);
    unsigned b55 = stwo_m31_add(b2, b9);
    unsigned b56 = stwo_m31_add(b3, b10);
    unsigned b57 = stwo_m31_add(b4, b11);
    unsigned b58 = stwo_m31_add(b5, b12);
    unsigned b59 = stwo_m31_add(b6, b13);
    unsigned b60 = stwo_m31_add(b0, b7);
    b0 = stwo_m31_add(b1, b8);
    unsigned b61 = stwo_m31_add(b2, b9);
    unsigned b62 = stwo_m31_add(b3, b10);
    unsigned b63 = stwo_m31_add(b4, b11);
    unsigned b64 = stwo_m31_add(b5, b12);
    unsigned b65 = stwo_m31_add(b6, b13);
    unsigned b66 = stwo_m31_mul(b53, b60);
    unsigned b67 = stwo_m31_sub(b66, b40);
    b66 = stwo_m31_sub(b67, b47);
    b67 = stwo_m31_add(b46, b66);
    b66 = stwo_m31_mul(b53, b0);
    unsigned b68 = stwo_m31_mul(b44, b60);
    unsigned b69 = stwo_m31_add(b66, b68);
    b68 = stwo_m31_sub(b69, b43);
    b69 = stwo_m31_sub(b68, b50);
    b68 = stwo_m31_add(b45, b69);
    b69 = stwo_m31_mul(b53, b61);
    b53 = stwo_m31_mul(b44, b0);
    b66 = stwo_m31_add(b69, b53);
    b53 = stwo_m31_mul(b55, b60);
    b60 = stwo_m31_add(b66, b53);
    b53 = stwo_m31_sub(b60, b42);
    b60 = stwo_m31_sub(b53, b49);
    b53 = stwo_m31_add(b48, b60);
    b60 = stwo_m31_mul(b44, b65);
    b44 = stwo_m31_mul(b55, b64);
    b66 = stwo_m31_add(b60, b44);
    b44 = stwo_m31_mul(b56, b63);
    b60 = stwo_m31_add(b66, b44);
    b44 = stwo_m31_mul(b57, b62);
    b66 = stwo_m31_add(b60, b44);
    b44 = stwo_m31_mul(b58, b61);
    b60 = stwo_m31_add(b66, b44);
    b44 = stwo_m31_mul(b59, b0);
    b0 = stwo_m31_add(b60, b44);
    b44 = stwo_m31_sub(b0, b46);
    b0 = stwo_m31_sub(b44, b52);
    b44 = stwo_m31_add(b47, b0);
    b0 = stwo_m31_mul(b55, b65);
    b55 = stwo_m31_mul(b56, b64);
    b47 = stwo_m31_add(b0, b55);
    b55 = stwo_m31_mul(b57, b63);
    b0 = stwo_m31_add(b47, b55);
    b55 = stwo_m31_mul(b58, b62);
    b47 = stwo_m31_add(b0, b55);
    b55 = stwo_m31_mul(b59, b61);
    b61 = stwo_m31_add(b47, b55);
    b55 = stwo_m31_sub(b61, b45);
    b61 = stwo_m31_sub(b55, b51);
    b55 = stwo_m31_add(b50, b61);
    b61 = stwo_m31_mul(b56, b65);
    b65 = stwo_m31_mul(b57, b64);
    b64 = stwo_m31_add(b61, b65);
    b65 = stwo_m31_mul(b58, b63);
    b63 = stwo_m31_add(b64, b65);
    b65 = stwo_m31_mul(b59, b62);
    b62 = stwo_m31_add(b63, b65);
    b65 = stwo_m31_sub(b62, b48);
    b62 = stwo_m31_sub(b65, b54);
    b65 = stwo_m31_add(b49, b62);
    b62 = stwo_m31_mul(b14, b14);
    b49 = stwo_m31_mul(b14, b15);
    b54 = stwo_m31_mul(b15, b14);
    b48 = stwo_m31_add(b49, b54);
    b54 = stwo_m31_mul(b14, b16);
    b49 = stwo_m31_mul(b15, b15);
    b63 = stwo_m31_add(b54, b49);
    b49 = stwo_m31_mul(b16, b14);
    b14 = stwo_m31_add(b63, b49);
    b49 = stwo_m31_mul(b15, b20);
    b63 = stwo_m31_mul(b16, b19);
    b54 = stwo_m31_add(b49, b63);
    b63 = stwo_m31_mul(b17, b18);
    b49 = stwo_m31_add(b54, b63);
    b63 = stwo_m31_mul(b18, b17);
    b54 = stwo_m31_add(b49, b63);
    b63 = stwo_m31_mul(b19, b16);
    b49 = stwo_m31_add(b54, b63);
    b63 = stwo_m31_mul(b20, b15);
    b54 = stwo_m31_add(b49, b63);
    b63 = stwo_m31_mul(b16, b20);
    b49 = stwo_m31_mul(b17, b19);
    b59 = stwo_m31_add(b63, b49);
    b49 = stwo_m31_mul(b18, b18);
    b63 = stwo_m31_add(b59, b49);
    b49 = stwo_m31_mul(b19, b17);
    b59 = stwo_m31_add(b63, b49);
    b49 = stwo_m31_mul(b20, b16);
    b63 = stwo_m31_add(b59, b49);
    b49 = stwo_m31_mul(b17, b20);
    b59 = stwo_m31_mul(b18, b19);
    b64 = stwo_m31_add(b49, b59);
    b59 = stwo_m31_mul(b19, b18);
    b49 = stwo_m31_add(b64, b59);
    b59 = stwo_m31_mul(b20, b17);
    b64 = stwo_m31_add(b49, b59);
    b59 = stwo_m31_mul(b21, b21);
    b49 = stwo_m31_mul(b21, b22);
    b58 = stwo_m31_mul(b22, b21);
    b61 = stwo_m31_add(b49, b58);
    b58 = stwo_m31_mul(b21, b23);
    b49 = stwo_m31_mul(b22, b22);
    b57 = stwo_m31_add(b58, b49);
    b49 = stwo_m31_mul(b23, b21);
    b58 = stwo_m31_add(b57, b49);
    b49 = stwo_m31_mul(b22, b27);
    b57 = stwo_m31_mul(b23, b26);
    b56 = stwo_m31_add(b49, b57);
    b57 = stwo_m31_mul(b24, b25);
    b49 = stwo_m31_add(b56, b57);
    b57 = stwo_m31_mul(b25, b24);
    b56 = stwo_m31_add(b49, b57);
    b57 = stwo_m31_mul(b26, b23);
    b49 = stwo_m31_add(b56, b57);
    b57 = stwo_m31_mul(b27, b22);
    b56 = stwo_m31_add(b49, b57);
    b57 = stwo_m31_mul(b23, b27);
    b49 = stwo_m31_mul(b24, b26);
    b50 = stwo_m31_add(b57, b49);
    b49 = stwo_m31_mul(b25, b25);
    b57 = stwo_m31_add(b50, b49);
    b49 = stwo_m31_mul(b26, b24);
    b50 = stwo_m31_add(b57, b49);
    b49 = stwo_m31_mul(b27, b23);
    b57 = stwo_m31_add(b50, b49);
    b49 = stwo_m31_mul(b24, b27);
    b50 = stwo_m31_mul(b25, b26);
    b51 = stwo_m31_add(b49, b50);
    b50 = stwo_m31_mul(b26, b25);
    b49 = stwo_m31_add(b51, b50);
    b50 = stwo_m31_mul(b27, b24);
    b51 = stwo_m31_add(b49, b50);
    b50 = stwo_m31_add(b15, b22);
    b49 = stwo_m31_add(b16, b23);
    b45 = stwo_m31_add(b17, b24);
    b47 = stwo_m31_add(b18, b25);
    b0 = stwo_m31_add(b19, b26);
    b52 = stwo_m31_add(b20, b27);
    b46 = stwo_m31_add(b15, b22);
    b60 = stwo_m31_add(b16, b23);
    b66 = stwo_m31_add(b17, b24);
    b69 = stwo_m31_add(b18, b25);
    unsigned b70 = stwo_m31_add(b19, b26);
    unsigned b71 = stwo_m31_add(b20, b27);
    unsigned b72 = stwo_m31_mul(b50, b71);
    b50 = stwo_m31_mul(b49, b70);
    unsigned b73 = stwo_m31_add(b72, b50);
    b50 = stwo_m31_mul(b45, b69);
    b72 = stwo_m31_add(b73, b50);
    b50 = stwo_m31_mul(b47, b66);
    b73 = stwo_m31_add(b72, b50);
    b50 = stwo_m31_mul(b0, b60);
    b72 = stwo_m31_add(b73, b50);
    b50 = stwo_m31_mul(b52, b46);
    b46 = stwo_m31_add(b72, b50);
    b50 = stwo_m31_sub(b46, b54);
    b46 = stwo_m31_sub(b50, b56);
    b50 = stwo_m31_add(b59, b46);
    b46 = stwo_m31_mul(b49, b71);
    b49 = stwo_m31_mul(b45, b70);
    b59 = stwo_m31_add(b46, b49);
    b49 = stwo_m31_mul(b47, b69);
    b46 = stwo_m31_add(b59, b49);
    b49 = stwo_m31_mul(b0, b66);
    b59 = stwo_m31_add(b46, b49);
    b49 = stwo_m31_mul(b52, b60);
    b60 = stwo_m31_add(b59, b49);
    b49 = stwo_m31_sub(b60, b63);
    b60 = stwo_m31_sub(b49, b57);
    b49 = stwo_m31_add(b61, b60);
    b60 = stwo_m31_mul(b45, b71);
    b71 = stwo_m31_mul(b47, b70);
    b70 = stwo_m31_add(b60, b71);
    b71 = stwo_m31_mul(b0, b69);
    b69 = stwo_m31_add(b70, b71);
    b71 = stwo_m31_mul(b52, b66);
    b66 = stwo_m31_add(b69, b71);
    b71 = stwo_m31_sub(b66, b64);
    b66 = stwo_m31_sub(b71, b51);
    b71 = stwo_m31_add(b58, b66);
    b66 = stwo_m31_add(b1, b15);
    b58 = stwo_m31_add(b2, b16);
    b51 = stwo_m31_add(b3, b17);
    b64 = stwo_m31_add(b4, b18);
    b69 = stwo_m31_add(b5, b19);
    b52 = stwo_m31_add(b6, b20);
    b70 = stwo_m31_add(b7, b21);
    b0 = stwo_m31_add(b8, b22);
    b60 = stwo_m31_add(b9, b23);
    b47 = stwo_m31_add(b10, b24);
    b45 = stwo_m31_add(b11, b25);
    b61 = stwo_m31_add(b12, b26);
    b57 = stwo_m31_add(b13, b27);
    b63 = stwo_m31_add(b1, b15);
    b15 = stwo_m31_add(b2, b16);
    b16 = stwo_m31_add(b3, b17);
    b17 = stwo_m31_add(b4, b18);
    b18 = stwo_m31_add(b5, b19);
    b19 = stwo_m31_add(b6, b20);
    b20 = stwo_m31_add(b7, b21);
    b21 = stwo_m31_add(b8, b22);
    b22 = stwo_m31_add(b9, b23);
    b23 = stwo_m31_add(b10, b24);
    b24 = stwo_m31_add(b11, b25);
    b25 = stwo_m31_add(b12, b26);
    b26 = stwo_m31_add(b13, b27);
    b27 = stwo_m31_mul(b66, b19);
    b13 = stwo_m31_mul(b58, b18);
    b12 = stwo_m31_add(b27, b13);
    b13 = stwo_m31_mul(b51, b17);
    b27 = stwo_m31_add(b12, b13);
    b13 = stwo_m31_mul(b64, b16);
    b12 = stwo_m31_add(b27, b13);
    b13 = stwo_m31_mul(b69, b15);
    b27 = stwo_m31_add(b12, b13);
    b13 = stwo_m31_mul(b52, b63);
    b12 = stwo_m31_add(b27, b13);
    b13 = stwo_m31_mul(b58, b19);
    b27 = stwo_m31_mul(b51, b18);
    b11 = stwo_m31_add(b13, b27);
    b27 = stwo_m31_mul(b64, b17);
    b13 = stwo_m31_add(b11, b27);
    b27 = stwo_m31_mul(b69, b16);
    b11 = stwo_m31_add(b13, b27);
    b27 = stwo_m31_mul(b52, b15);
    b13 = stwo_m31_add(b11, b27);
    b27 = stwo_m31_mul(b51, b19);
    b11 = stwo_m31_mul(b64, b18);
    b10 = stwo_m31_add(b27, b11);
    b11 = stwo_m31_mul(b69, b17);
    b27 = stwo_m31_add(b10, b11);
    b11 = stwo_m31_mul(b52, b16);
    b10 = stwo_m31_add(b27, b11);
    b11 = stwo_m31_mul(b70, b20);
    b27 = stwo_m31_mul(b70, b21);
    b9 = stwo_m31_mul(b0, b20);
    b8 = stwo_m31_add(b27, b9);
    b9 = stwo_m31_mul(b70, b22);
    b70 = stwo_m31_mul(b0, b21);
    b27 = stwo_m31_add(b9, b70);
    b70 = stwo_m31_mul(b60, b20);
    b20 = stwo_m31_add(b27, b70);
    b70 = stwo_m31_mul(b0, b26);
    b27 = stwo_m31_mul(b60, b25);
    b9 = stwo_m31_add(b70, b27);
    b27 = stwo_m31_mul(b47, b24);
    b70 = stwo_m31_add(b9, b27);
    b27 = stwo_m31_mul(b45, b23);
    b9 = stwo_m31_add(b70, b27);
    b27 = stwo_m31_mul(b61, b22);
    b70 = stwo_m31_add(b9, b27);
    b27 = stwo_m31_mul(b57, b21);
    b9 = stwo_m31_add(b70, b27);
    b27 = stwo_m31_mul(b60, b26);
    b70 = stwo_m31_mul(b47, b25);
    b7 = stwo_m31_add(b27, b70);
    b70 = stwo_m31_mul(b45, b24);
    b27 = stwo_m31_add(b7, b70);
    b70 = stwo_m31_mul(b61, b23);
    b7 = stwo_m31_add(b27, b70);
    b70 = stwo_m31_mul(b57, b22);
    b27 = stwo_m31_add(b7, b70);
    b70 = stwo_m31_mul(b47, b26);
    b7 = stwo_m31_mul(b45, b25);
    b6 = stwo_m31_add(b70, b7);
    b7 = stwo_m31_mul(b61, b24);
    b70 = stwo_m31_add(b6, b7);
    b7 = stwo_m31_mul(b57, b23);
    b6 = stwo_m31_add(b70, b7);
    b7 = stwo_m31_add(b66, b0);
    b0 = stwo_m31_add(b58, b60);
    b60 = stwo_m31_add(b51, b47);
    b47 = stwo_m31_add(b64, b45);
    b45 = stwo_m31_add(b69, b61);
    b61 = stwo_m31_add(b52, b57);
    b57 = stwo_m31_add(b63, b21);
    b21 = stwo_m31_add(b15, b22);
    b22 = stwo_m31_add(b16, b23);
    b23 = stwo_m31_add(b17, b24);
    b24 = stwo_m31_add(b18, b25);
    b25 = stwo_m31_add(b19, b26);
    b26 = stwo_m31_mul(b7, b25);
    b7 = stwo_m31_mul(b0, b24);
    b19 = stwo_m31_add(b26, b7);
    b7 = stwo_m31_mul(b60, b23);
    b26 = stwo_m31_add(b19, b7);
    b7 = stwo_m31_mul(b47, b22);
    b19 = stwo_m31_add(b26, b7);
    b7 = stwo_m31_mul(b45, b21);
    b26 = stwo_m31_add(b19, b7);
    b7 = stwo_m31_mul(b61, b57);
    b57 = stwo_m31_add(b26, b7);
    b7 = stwo_m31_sub(b57, b12);
    b57 = stwo_m31_sub(b7, b9);
    b7 = stwo_m31_add(b11, b57);
    b57 = stwo_m31_mul(b0, b25);
    b0 = stwo_m31_mul(b60, b24);
    b11 = stwo_m31_add(b57, b0);
    b0 = stwo_m31_mul(b47, b23);
    b57 = stwo_m31_add(b11, b0);
    b0 = stwo_m31_mul(b45, b22);
    b11 = stwo_m31_add(b57, b0);
    b0 = stwo_m31_mul(b61, b21);
    b21 = stwo_m31_add(b11, b0);
    b0 = stwo_m31_sub(b21, b13);
    b21 = stwo_m31_sub(b0, b27);
    b0 = stwo_m31_add(b8, b21);
    b21 = stwo_m31_mul(b60, b25);
    b25 = stwo_m31_mul(b47, b24);
    b24 = stwo_m31_add(b21, b25);
    b25 = stwo_m31_mul(b45, b23);
    b23 = stwo_m31_add(b24, b25);
    b25 = stwo_m31_mul(b61, b22);
    b22 = stwo_m31_add(b23, b25);
    b25 = stwo_m31_sub(b22, b10);
    b22 = stwo_m31_sub(b25, b6);
    b25 = stwo_m31_add(b20, b22);
    b22 = stwo_m31_sub(b7, b44);
    b7 = stwo_m31_sub(b22, b50);
    b22 = stwo_m31_add(b62, b7);
    b7 = stwo_m31_sub(b0, b55);
    b0 = stwo_m31_sub(b7, b49);
    b7 = stwo_m31_add(b48, b0);
    b0 = stwo_m31_sub(b25, b65);
    b25 = stwo_m31_sub(b0, b71);
    b0 = stwo_m31_add(b14, b25);
    b25 = stwo_m31_sub(b40, b28);
    b40 = stwo_m31_sub(b43, b29);
    b43 = stwo_m31_sub(b42, b30);
    b42 = stwo_m31_sub(b41, b31);
    b41 = stwo_m31_sub(b67, b32);
    b67 = stwo_m31_sub(b68, b33);
    b68 = stwo_m31_sub(b53, b34);
    b53 = 2u;
    b34 = stwo_m31_mul(b53, b25);
    b53 = stwo_m31_add(b34, b42);
    b34 = 32u;
    b42 = stwo_m31_mul(b34, b41);
    b34 = stwo_m31_add(b53, b42);
    b42 = 4u;
    b53 = stwo_m31_mul(b42, b22);
    b42 = stwo_m31_sub(b34, b53);
    b53 = 2u;
    b34 = stwo_m31_mul(b53, b40);
    b53 = stwo_m31_add(b34, b41);
    b34 = 32u;
    b41 = stwo_m31_mul(b34, b67);
    b34 = stwo_m31_add(b53, b41);
    b41 = 4u;
    b53 = stwo_m31_mul(b41, b7);
    b41 = stwo_m31_sub(b34, b53);
    b53 = 2u;
    b34 = stwo_m31_mul(b53, b43);
    b53 = stwo_m31_add(b34, b67);
    b34 = 32u;
    b67 = stwo_m31_mul(b34, b68);
    b34 = stwo_m31_add(b53, b67);
    b67 = 4u;
    b53 = stwo_m31_mul(b67, b0);
    b67 = stwo_m31_sub(b34, b53);
    b53 = 512u;
    b34 = stwo_m31_mul(b36, b53);
    b53 = stwo_m31_add(b42, b35);
    b42 = stwo_m31_sub(b34, b53);
    b53 = 512u;
    b34 = stwo_m31_mul(b37, b53);
    b53 = stwo_m31_add(b41, b36);
    b41 = stwo_m31_sub(b34, b53);
    b53 = 512u;
    b34 = stwo_m31_mul(b38, b53);
    b53 = stwo_m31_add(b67, b37);
    b67 = stwo_m31_sub(b34, b53);
    StwoCairoQm31 e0 = { b42, b39, b39, b39 };
    StwoCairoQm31 e1 = { b41, b39, b39, b39 };
    StwoCairoQm31 e2 = { b67, b39, b39, b39 };
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
