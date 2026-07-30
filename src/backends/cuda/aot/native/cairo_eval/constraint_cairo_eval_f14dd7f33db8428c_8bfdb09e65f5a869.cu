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
stwo_cairo_cuda_eval_v1_012cbbe917d3ec29(
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
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 373u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 374u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 375u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 376u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 395u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 396u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 397u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 402u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 403u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 404u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 405u, row, 0);
    unsigned b39 = 0u;
    unsigned b40 = stwo_m31_mul(b0, b3);
    unsigned b41 = stwo_m31_mul(b1, b2);
    unsigned b42 = stwo_m31_add(b40, b41);
    b41 = stwo_m31_mul(b2, b1);
    b40 = stwo_m31_add(b42, b41);
    b41 = stwo_m31_mul(b3, b0);
    b42 = stwo_m31_add(b40, b41);
    b41 = stwo_m31_mul(b0, b4);
    b40 = stwo_m31_mul(b1, b3);
    unsigned b43 = stwo_m31_add(b41, b40);
    b40 = stwo_m31_mul(b2, b2);
    b41 = stwo_m31_add(b43, b40);
    b40 = stwo_m31_mul(b3, b1);
    b43 = stwo_m31_add(b41, b40);
    b40 = stwo_m31_mul(b4, b0);
    b41 = stwo_m31_add(b43, b40);
    b40 = stwo_m31_mul(b0, b5);
    b43 = stwo_m31_mul(b1, b4);
    unsigned b44 = stwo_m31_add(b40, b43);
    b43 = stwo_m31_mul(b2, b3);
    b40 = stwo_m31_add(b44, b43);
    b43 = stwo_m31_mul(b3, b2);
    b44 = stwo_m31_add(b40, b43);
    b43 = stwo_m31_mul(b4, b1);
    b40 = stwo_m31_add(b44, b43);
    b43 = stwo_m31_mul(b5, b0);
    b44 = stwo_m31_add(b40, b43);
    b43 = stwo_m31_mul(b0, b6);
    b40 = stwo_m31_mul(b1, b5);
    unsigned b45 = stwo_m31_add(b43, b40);
    b40 = stwo_m31_mul(b2, b4);
    b43 = stwo_m31_add(b45, b40);
    b40 = stwo_m31_mul(b3, b3);
    b45 = stwo_m31_add(b43, b40);
    b40 = stwo_m31_mul(b4, b2);
    b43 = stwo_m31_add(b45, b40);
    b40 = stwo_m31_mul(b5, b1);
    b45 = stwo_m31_add(b43, b40);
    b40 = stwo_m31_mul(b6, b0);
    b43 = stwo_m31_add(b45, b40);
    b40 = stwo_m31_mul(b5, b6);
    b45 = stwo_m31_mul(b6, b5);
    unsigned b46 = stwo_m31_add(b40, b45);
    b45 = stwo_m31_mul(b6, b6);
    b40 = stwo_m31_mul(b7, b11);
    unsigned b47 = stwo_m31_mul(b8, b10);
    unsigned b48 = stwo_m31_add(b40, b47);
    b47 = stwo_m31_mul(b9, b9);
    b40 = stwo_m31_add(b48, b47);
    b47 = stwo_m31_mul(b10, b8);
    b48 = stwo_m31_add(b40, b47);
    b47 = stwo_m31_mul(b11, b7);
    b40 = stwo_m31_add(b48, b47);
    b47 = stwo_m31_mul(b7, b12);
    b48 = stwo_m31_mul(b8, b11);
    unsigned b49 = stwo_m31_add(b47, b48);
    b48 = stwo_m31_mul(b9, b10);
    b47 = stwo_m31_add(b49, b48);
    b48 = stwo_m31_mul(b10, b9);
    b49 = stwo_m31_add(b47, b48);
    b48 = stwo_m31_mul(b11, b8);
    b47 = stwo_m31_add(b49, b48);
    b48 = stwo_m31_mul(b12, b7);
    b49 = stwo_m31_add(b47, b48);
    b48 = stwo_m31_mul(b7, b13);
    b47 = stwo_m31_mul(b8, b12);
    unsigned b50 = stwo_m31_add(b48, b47);
    b47 = stwo_m31_mul(b9, b11);
    b48 = stwo_m31_add(b50, b47);
    b47 = stwo_m31_mul(b10, b10);
    b50 = stwo_m31_add(b48, b47);
    b47 = stwo_m31_mul(b11, b9);
    b48 = stwo_m31_add(b50, b47);
    b47 = stwo_m31_mul(b12, b8);
    b50 = stwo_m31_add(b48, b47);
    b47 = stwo_m31_mul(b13, b7);
    b48 = stwo_m31_add(b50, b47);
    b47 = stwo_m31_mul(b12, b13);
    b50 = stwo_m31_mul(b13, b12);
    unsigned b51 = stwo_m31_add(b47, b50);
    b50 = stwo_m31_mul(b13, b13);
    b47 = stwo_m31_add(b0, b7);
    unsigned b52 = stwo_m31_add(b1, b8);
    unsigned b53 = stwo_m31_add(b2, b9);
    unsigned b54 = stwo_m31_add(b3, b10);
    unsigned b55 = stwo_m31_add(b4, b11);
    unsigned b56 = stwo_m31_add(b5, b12);
    unsigned b57 = stwo_m31_add(b6, b13);
    unsigned b58 = stwo_m31_add(b0, b7);
    unsigned b59 = stwo_m31_add(b1, b8);
    unsigned b60 = stwo_m31_add(b2, b9);
    unsigned b61 = stwo_m31_add(b3, b10);
    unsigned b62 = stwo_m31_add(b4, b11);
    unsigned b63 = stwo_m31_add(b5, b12);
    unsigned b64 = stwo_m31_add(b6, b13);
    unsigned b65 = stwo_m31_mul(b47, b62);
    unsigned b66 = stwo_m31_mul(b52, b61);
    unsigned b67 = stwo_m31_add(b65, b66);
    b66 = stwo_m31_mul(b53, b60);
    b65 = stwo_m31_add(b67, b66);
    b66 = stwo_m31_mul(b54, b59);
    b67 = stwo_m31_add(b65, b66);
    b66 = stwo_m31_mul(b55, b58);
    b65 = stwo_m31_add(b67, b66);
    b66 = stwo_m31_sub(b65, b41);
    b65 = stwo_m31_sub(b66, b40);
    b66 = stwo_m31_add(b46, b65);
    b65 = stwo_m31_mul(b47, b63);
    b46 = stwo_m31_mul(b52, b62);
    b40 = stwo_m31_add(b65, b46);
    b46 = stwo_m31_mul(b53, b61);
    b65 = stwo_m31_add(b40, b46);
    b46 = stwo_m31_mul(b54, b60);
    b40 = stwo_m31_add(b65, b46);
    b46 = stwo_m31_mul(b55, b59);
    b65 = stwo_m31_add(b40, b46);
    b46 = stwo_m31_mul(b56, b58);
    b40 = stwo_m31_add(b65, b46);
    b46 = stwo_m31_sub(b40, b44);
    b40 = stwo_m31_sub(b46, b49);
    b46 = stwo_m31_add(b45, b40);
    b40 = stwo_m31_mul(b47, b64);
    b64 = stwo_m31_mul(b52, b63);
    b63 = stwo_m31_add(b40, b64);
    b64 = stwo_m31_mul(b53, b62);
    b62 = stwo_m31_add(b63, b64);
    b64 = stwo_m31_mul(b54, b61);
    b61 = stwo_m31_add(b62, b64);
    b64 = stwo_m31_mul(b55, b60);
    b60 = stwo_m31_add(b61, b64);
    b64 = stwo_m31_mul(b56, b59);
    b59 = stwo_m31_add(b60, b64);
    b64 = stwo_m31_mul(b57, b58);
    b58 = stwo_m31_add(b59, b64);
    b64 = stwo_m31_sub(b58, b43);
    b58 = stwo_m31_sub(b64, b48);
    b64 = stwo_m31_mul(b14, b18);
    b48 = stwo_m31_mul(b15, b17);
    b59 = stwo_m31_add(b64, b48);
    b48 = stwo_m31_mul(b16, b16);
    b64 = stwo_m31_add(b59, b48);
    b48 = stwo_m31_mul(b17, b15);
    b59 = stwo_m31_add(b64, b48);
    b48 = stwo_m31_mul(b18, b14);
    b64 = stwo_m31_add(b59, b48);
    b48 = stwo_m31_mul(b14, b19);
    b59 = stwo_m31_mul(b15, b18);
    b57 = stwo_m31_add(b48, b59);
    b59 = stwo_m31_mul(b16, b17);
    b48 = stwo_m31_add(b57, b59);
    b59 = stwo_m31_mul(b17, b16);
    b57 = stwo_m31_add(b48, b59);
    b59 = stwo_m31_mul(b18, b15);
    b48 = stwo_m31_add(b57, b59);
    b59 = stwo_m31_mul(b19, b14);
    b57 = stwo_m31_add(b48, b59);
    b59 = stwo_m31_mul(b14, b20);
    b48 = stwo_m31_mul(b15, b19);
    b60 = stwo_m31_add(b59, b48);
    b48 = stwo_m31_mul(b16, b18);
    b59 = stwo_m31_add(b60, b48);
    b48 = stwo_m31_mul(b17, b17);
    b60 = stwo_m31_add(b59, b48);
    b48 = stwo_m31_mul(b18, b16);
    b59 = stwo_m31_add(b60, b48);
    b48 = stwo_m31_mul(b19, b15);
    b60 = stwo_m31_add(b59, b48);
    b48 = stwo_m31_mul(b20, b14);
    b59 = stwo_m31_add(b60, b48);
    b48 = stwo_m31_mul(b19, b20);
    b60 = stwo_m31_mul(b20, b19);
    b56 = stwo_m31_add(b48, b60);
    b60 = stwo_m31_mul(b20, b20);
    b48 = stwo_m31_mul(b21, b25);
    b61 = stwo_m31_mul(b22, b24);
    b55 = stwo_m31_add(b48, b61);
    b61 = stwo_m31_mul(b23, b23);
    b48 = stwo_m31_add(b55, b61);
    b61 = stwo_m31_mul(b24, b22);
    b55 = stwo_m31_add(b48, b61);
    b61 = stwo_m31_mul(b25, b21);
    b48 = stwo_m31_add(b55, b61);
    b61 = stwo_m31_mul(b21, b26);
    b55 = stwo_m31_mul(b22, b25);
    b62 = stwo_m31_add(b61, b55);
    b55 = stwo_m31_mul(b23, b24);
    b61 = stwo_m31_add(b62, b55);
    b55 = stwo_m31_mul(b24, b23);
    b62 = stwo_m31_add(b61, b55);
    b55 = stwo_m31_mul(b25, b22);
    b61 = stwo_m31_add(b62, b55);
    b55 = stwo_m31_mul(b26, b21);
    b62 = stwo_m31_add(b61, b55);
    b55 = stwo_m31_mul(b21, b27);
    b61 = stwo_m31_mul(b22, b26);
    b54 = stwo_m31_add(b55, b61);
    b61 = stwo_m31_mul(b23, b25);
    b55 = stwo_m31_add(b54, b61);
    b61 = stwo_m31_mul(b24, b24);
    b54 = stwo_m31_add(b55, b61);
    b61 = stwo_m31_mul(b25, b23);
    b55 = stwo_m31_add(b54, b61);
    b61 = stwo_m31_mul(b26, b22);
    b54 = stwo_m31_add(b55, b61);
    b61 = stwo_m31_mul(b27, b21);
    b55 = stwo_m31_add(b54, b61);
    b61 = stwo_m31_mul(b26, b27);
    b54 = stwo_m31_mul(b27, b26);
    b63 = stwo_m31_add(b61, b54);
    b54 = stwo_m31_mul(b27, b27);
    b61 = stwo_m31_add(b14, b21);
    b53 = stwo_m31_add(b15, b22);
    b40 = stwo_m31_add(b16, b23);
    b52 = stwo_m31_add(b17, b24);
    b47 = stwo_m31_add(b18, b25);
    b45 = stwo_m31_add(b19, b26);
    b49 = stwo_m31_add(b20, b27);
    b65 = stwo_m31_add(b14, b21);
    b67 = stwo_m31_add(b15, b22);
    unsigned b68 = stwo_m31_add(b16, b23);
    unsigned b69 = stwo_m31_add(b17, b24);
    unsigned b70 = stwo_m31_add(b18, b25);
    unsigned b71 = stwo_m31_add(b19, b26);
    unsigned b72 = stwo_m31_add(b20, b27);
    unsigned b73 = stwo_m31_mul(b61, b70);
    unsigned b74 = stwo_m31_mul(b53, b69);
    unsigned b75 = stwo_m31_add(b73, b74);
    b74 = stwo_m31_mul(b40, b68);
    b73 = stwo_m31_add(b75, b74);
    b74 = stwo_m31_mul(b52, b67);
    b75 = stwo_m31_add(b73, b74);
    b74 = stwo_m31_mul(b47, b65);
    b73 = stwo_m31_add(b75, b74);
    b74 = stwo_m31_sub(b73, b64);
    b73 = stwo_m31_sub(b74, b48);
    b74 = stwo_m31_add(b56, b73);
    b73 = stwo_m31_mul(b61, b71);
    b56 = stwo_m31_mul(b53, b70);
    b48 = stwo_m31_add(b73, b56);
    b56 = stwo_m31_mul(b40, b69);
    b73 = stwo_m31_add(b48, b56);
    b56 = stwo_m31_mul(b52, b68);
    b48 = stwo_m31_add(b73, b56);
    b56 = stwo_m31_mul(b47, b67);
    b73 = stwo_m31_add(b48, b56);
    b56 = stwo_m31_mul(b45, b65);
    b48 = stwo_m31_add(b73, b56);
    b56 = stwo_m31_sub(b48, b57);
    b48 = stwo_m31_sub(b56, b62);
    b56 = stwo_m31_add(b60, b48);
    b48 = stwo_m31_mul(b61, b72);
    b72 = stwo_m31_mul(b53, b71);
    b71 = stwo_m31_add(b48, b72);
    b72 = stwo_m31_mul(b40, b70);
    b70 = stwo_m31_add(b71, b72);
    b72 = stwo_m31_mul(b52, b69);
    b69 = stwo_m31_add(b70, b72);
    b72 = stwo_m31_mul(b47, b68);
    b68 = stwo_m31_add(b69, b72);
    b72 = stwo_m31_mul(b45, b67);
    b67 = stwo_m31_add(b68, b72);
    b72 = stwo_m31_mul(b49, b65);
    b65 = stwo_m31_add(b67, b72);
    b72 = stwo_m31_sub(b65, b59);
    b65 = stwo_m31_sub(b72, b55);
    b72 = stwo_m31_add(b0, b14);
    b55 = stwo_m31_add(b1, b15);
    b59 = stwo_m31_add(b2, b16);
    b67 = stwo_m31_add(b3, b17);
    b49 = stwo_m31_add(b4, b18);
    b68 = stwo_m31_add(b5, b19);
    b45 = stwo_m31_add(b6, b20);
    b69 = stwo_m31_add(b7, b21);
    b47 = stwo_m31_add(b8, b22);
    b70 = stwo_m31_add(b9, b23);
    b52 = stwo_m31_add(b10, b24);
    b71 = stwo_m31_add(b11, b25);
    b40 = stwo_m31_add(b12, b26);
    b48 = stwo_m31_add(b13, b27);
    b53 = stwo_m31_add(b0, b14);
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
    b24 = stwo_m31_add(b11, b25);
    b25 = stwo_m31_add(b12, b26);
    b26 = stwo_m31_add(b13, b27);
    b27 = stwo_m31_mul(b72, b17);
    b13 = stwo_m31_mul(b55, b16);
    b12 = stwo_m31_add(b27, b13);
    b13 = stwo_m31_mul(b59, b15);
    b27 = stwo_m31_add(b12, b13);
    b13 = stwo_m31_mul(b67, b14);
    b12 = stwo_m31_add(b27, b13);
    b13 = stwo_m31_mul(b49, b53);
    b27 = stwo_m31_add(b12, b13);
    b13 = stwo_m31_mul(b72, b18);
    b12 = stwo_m31_mul(b55, b17);
    b11 = stwo_m31_add(b13, b12);
    b12 = stwo_m31_mul(b59, b16);
    b13 = stwo_m31_add(b11, b12);
    b12 = stwo_m31_mul(b67, b15);
    b11 = stwo_m31_add(b13, b12);
    b12 = stwo_m31_mul(b49, b14);
    b13 = stwo_m31_add(b11, b12);
    b12 = stwo_m31_mul(b68, b53);
    b11 = stwo_m31_add(b13, b12);
    b12 = stwo_m31_mul(b72, b19);
    b13 = stwo_m31_mul(b55, b18);
    b10 = stwo_m31_add(b12, b13);
    b13 = stwo_m31_mul(b59, b17);
    b12 = stwo_m31_add(b10, b13);
    b13 = stwo_m31_mul(b67, b16);
    b10 = stwo_m31_add(b12, b13);
    b13 = stwo_m31_mul(b49, b15);
    b12 = stwo_m31_add(b10, b13);
    b13 = stwo_m31_mul(b68, b14);
    b10 = stwo_m31_add(b12, b13);
    b13 = stwo_m31_mul(b45, b53);
    b12 = stwo_m31_add(b10, b13);
    b13 = stwo_m31_mul(b68, b19);
    b10 = stwo_m31_mul(b45, b18);
    b9 = stwo_m31_add(b13, b10);
    b10 = stwo_m31_mul(b45, b19);
    b13 = stwo_m31_mul(b69, b24);
    b8 = stwo_m31_mul(b47, b23);
    b7 = stwo_m31_add(b13, b8);
    b8 = stwo_m31_mul(b70, b22);
    b13 = stwo_m31_add(b7, b8);
    b8 = stwo_m31_mul(b52, b21);
    b7 = stwo_m31_add(b13, b8);
    b8 = stwo_m31_mul(b71, b20);
    b13 = stwo_m31_add(b7, b8);
    b8 = stwo_m31_mul(b69, b25);
    b7 = stwo_m31_mul(b47, b24);
    b6 = stwo_m31_add(b8, b7);
    b7 = stwo_m31_mul(b70, b23);
    b8 = stwo_m31_add(b6, b7);
    b7 = stwo_m31_mul(b52, b22);
    b6 = stwo_m31_add(b8, b7);
    b7 = stwo_m31_mul(b71, b21);
    b8 = stwo_m31_add(b6, b7);
    b7 = stwo_m31_mul(b40, b20);
    b6 = stwo_m31_add(b8, b7);
    b7 = stwo_m31_mul(b69, b26);
    b8 = stwo_m31_mul(b47, b25);
    b5 = stwo_m31_add(b7, b8);
    b8 = stwo_m31_mul(b70, b24);
    b7 = stwo_m31_add(b5, b8);
    b8 = stwo_m31_mul(b52, b23);
    b5 = stwo_m31_add(b7, b8);
    b8 = stwo_m31_mul(b71, b22);
    b7 = stwo_m31_add(b5, b8);
    b8 = stwo_m31_mul(b40, b21);
    b5 = stwo_m31_add(b7, b8);
    b8 = stwo_m31_mul(b48, b20);
    b7 = stwo_m31_add(b5, b8);
    b8 = stwo_m31_add(b72, b69);
    b69 = stwo_m31_add(b55, b47);
    b47 = stwo_m31_add(b59, b70);
    b70 = stwo_m31_add(b67, b52);
    b52 = stwo_m31_add(b49, b71);
    b71 = stwo_m31_add(b68, b40);
    b40 = stwo_m31_add(b45, b48);
    b48 = stwo_m31_add(b53, b20);
    b20 = stwo_m31_add(b14, b21);
    b21 = stwo_m31_add(b15, b22);
    b22 = stwo_m31_add(b16, b23);
    b23 = stwo_m31_add(b17, b24);
    b24 = stwo_m31_add(b18, b25);
    b25 = stwo_m31_add(b19, b26);
    b26 = stwo_m31_mul(b8, b23);
    b19 = stwo_m31_mul(b69, b22);
    b18 = stwo_m31_add(b26, b19);
    b19 = stwo_m31_mul(b47, b21);
    b26 = stwo_m31_add(b18, b19);
    b19 = stwo_m31_mul(b70, b20);
    b18 = stwo_m31_add(b26, b19);
    b19 = stwo_m31_mul(b52, b48);
    b26 = stwo_m31_add(b18, b19);
    b19 = stwo_m31_sub(b26, b27);
    b26 = stwo_m31_sub(b19, b13);
    b19 = stwo_m31_add(b9, b26);
    b26 = stwo_m31_mul(b8, b24);
    b9 = stwo_m31_mul(b69, b23);
    b13 = stwo_m31_add(b26, b9);
    b9 = stwo_m31_mul(b47, b22);
    b26 = stwo_m31_add(b13, b9);
    b9 = stwo_m31_mul(b70, b21);
    b13 = stwo_m31_add(b26, b9);
    b9 = stwo_m31_mul(b52, b20);
    b26 = stwo_m31_add(b13, b9);
    b9 = stwo_m31_mul(b71, b48);
    b13 = stwo_m31_add(b26, b9);
    b9 = stwo_m31_sub(b13, b11);
    b13 = stwo_m31_sub(b9, b6);
    b9 = stwo_m31_add(b10, b13);
    b13 = stwo_m31_mul(b8, b25);
    b25 = stwo_m31_mul(b69, b24);
    b24 = stwo_m31_add(b13, b25);
    b25 = stwo_m31_mul(b47, b23);
    b23 = stwo_m31_add(b24, b25);
    b25 = stwo_m31_mul(b70, b22);
    b22 = stwo_m31_add(b23, b25);
    b25 = stwo_m31_mul(b52, b21);
    b21 = stwo_m31_add(b22, b25);
    b25 = stwo_m31_mul(b71, b20);
    b20 = stwo_m31_add(b21, b25);
    b25 = stwo_m31_mul(b40, b48);
    b48 = stwo_m31_add(b20, b25);
    b25 = stwo_m31_sub(b48, b12);
    b48 = stwo_m31_sub(b25, b7);
    b25 = stwo_m31_sub(b19, b66);
    b19 = stwo_m31_sub(b25, b74);
    b25 = stwo_m31_add(b51, b19);
    b19 = stwo_m31_sub(b9, b46);
    b9 = stwo_m31_sub(b19, b56);
    b19 = stwo_m31_add(b50, b9);
    b9 = stwo_m31_sub(b48, b58);
    b48 = stwo_m31_sub(b9, b65);
    b9 = stwo_m31_sub(b42, b28);
    b42 = stwo_m31_sub(b41, b29);
    b41 = stwo_m31_sub(b44, b30);
    b44 = stwo_m31_sub(b43, b31);
    b43 = stwo_m31_sub(b25, b32);
    b25 = stwo_m31_sub(b19, b33);
    b19 = stwo_m31_sub(b48, b34);
    b48 = 32u;
    b34 = stwo_m31_mul(b48, b42);
    b48 = stwo_m31_add(b9, b34);
    b34 = 4u;
    b9 = stwo_m31_mul(b34, b43);
    b34 = stwo_m31_sub(b48, b9);
    b9 = 8u;
    b48 = stwo_m31_mul(b9, b63);
    b9 = stwo_m31_add(b34, b48);
    b48 = 32u;
    b34 = stwo_m31_mul(b48, b41);
    b48 = stwo_m31_add(b42, b34);
    b34 = 4u;
    b42 = stwo_m31_mul(b34, b25);
    b34 = stwo_m31_sub(b48, b42);
    b42 = 8u;
    b48 = stwo_m31_mul(b42, b54);
    b42 = stwo_m31_add(b34, b48);
    b48 = 32u;
    b34 = stwo_m31_mul(b48, b44);
    b48 = stwo_m31_add(b41, b34);
    b34 = 4u;
    b41 = stwo_m31_mul(b34, b19);
    b34 = stwo_m31_sub(b48, b41);
    b41 = 512u;
    b48 = stwo_m31_mul(b36, b41);
    b41 = stwo_m31_add(b9, b35);
    b9 = stwo_m31_sub(b48, b41);
    b41 = 512u;
    b48 = stwo_m31_mul(b37, b41);
    b41 = stwo_m31_add(b42, b36);
    b42 = stwo_m31_sub(b48, b41);
    b41 = 512u;
    b48 = stwo_m31_mul(b38, b41);
    b41 = stwo_m31_add(b34, b37);
    b34 = stwo_m31_sub(b48, b41);
    StwoCairoQm31 e0 = { b9, b39, b39, b39 };
    StwoCairoQm31 e1 = { b42, b39, b39, b39 };
    StwoCairoQm31 e2 = { b34, b39, b39, b39 };
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
