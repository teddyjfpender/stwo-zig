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
stwo_cairo_cuda_eval_v1_348e9f4ec22faea3(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 0u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 1u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 2u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 3u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 4u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 5u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 6u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 7u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 8u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 9u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 10u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 11u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 19u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 25u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 41u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 42u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 43u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 47u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 48u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 49u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 51u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 52u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 53u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 54u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 55u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 126u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 127u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b64 = stwo_m31_sub(b0, b10);
    b0 = 512u;
    unsigned b65 = stwo_m31_mul(b11, b0);
    b0 = stwo_m31_sub(b64, b65);
    b65 = 8192u;
    b64 = stwo_m31_mul(b0, b65);
    b65 = stwo_m31_sub(b1, b12);
    b1 = 512u;
    b0 = stwo_m31_mul(b13, b1);
    b1 = stwo_m31_sub(b65, b0);
    b0 = 8192u;
    b65 = stwo_m31_mul(b1, b0);
    b0 = stwo_m31_sub(b2, b14);
    b2 = 512u;
    b1 = stwo_m31_mul(b15, b2);
    b2 = stwo_m31_sub(b0, b1);
    b1 = 8192u;
    b0 = stwo_m31_mul(b2, b1);
    b1 = stwo_m31_sub(b3, b16);
    b3 = 512u;
    b2 = stwo_m31_mul(b17, b3);
    b3 = stwo_m31_sub(b1, b2);
    b2 = 8192u;
    b1 = stwo_m31_mul(b3, b2);
    b2 = stwo_m31_sub(b4, b18);
    b4 = 512u;
    b3 = stwo_m31_mul(b19, b4);
    b4 = stwo_m31_sub(b2, b3);
    b3 = 8192u;
    b2 = stwo_m31_mul(b4, b3);
    b3 = stwo_m31_sub(b5, b20);
    b5 = 512u;
    b4 = stwo_m31_mul(b21, b5);
    b5 = stwo_m31_sub(b3, b4);
    b4 = 8192u;
    b3 = stwo_m31_mul(b5, b4);
    b4 = stwo_m31_sub(b6, b22);
    b6 = 512u;
    b5 = stwo_m31_mul(b23, b6);
    b6 = stwo_m31_sub(b4, b5);
    b5 = 8192u;
    b4 = stwo_m31_mul(b6, b5);
    b5 = stwo_m31_sub(b7, b24);
    b7 = 512u;
    b6 = stwo_m31_mul(b25, b7);
    b7 = stwo_m31_sub(b5, b6);
    b6 = 8192u;
    b5 = stwo_m31_mul(b7, b6);
    b6 = stwo_m31_sub(b8, b26);
    b8 = 512u;
    b7 = stwo_m31_mul(b27, b8);
    b8 = stwo_m31_sub(b6, b7);
    b7 = 8192u;
    b6 = stwo_m31_mul(b8, b7);
    b7 = 0u;
    b8 = stwo_m31_mul(b10, b28);
    unsigned b66 = stwo_m31_mul(b10, b29);
    unsigned b67 = stwo_m31_mul(b11, b28);
    unsigned b68 = stwo_m31_add(b66, b67);
    b67 = stwo_m31_mul(b10, b34);
    b66 = stwo_m31_mul(b11, b33);
    unsigned b69 = stwo_m31_add(b67, b66);
    b66 = stwo_m31_mul(b64, b32);
    b67 = stwo_m31_add(b69, b66);
    b66 = stwo_m31_mul(b12, b31);
    b69 = stwo_m31_add(b67, b66);
    b66 = stwo_m31_mul(b13, b30);
    b67 = stwo_m31_add(b69, b66);
    b66 = stwo_m31_mul(b65, b29);
    b69 = stwo_m31_add(b67, b66);
    b66 = stwo_m31_mul(b14, b28);
    b67 = stwo_m31_add(b69, b66);
    b66 = stwo_m31_mul(b11, b34);
    b69 = stwo_m31_mul(b64, b33);
    unsigned b70 = stwo_m31_add(b66, b69);
    b69 = stwo_m31_mul(b12, b32);
    b66 = stwo_m31_add(b70, b69);
    b69 = stwo_m31_mul(b13, b31);
    b70 = stwo_m31_add(b66, b69);
    b69 = stwo_m31_mul(b65, b30);
    b66 = stwo_m31_add(b70, b69);
    b69 = stwo_m31_mul(b14, b29);
    b70 = stwo_m31_add(b66, b69);
    b69 = stwo_m31_mul(b64, b34);
    b66 = stwo_m31_mul(b12, b33);
    unsigned b71 = stwo_m31_add(b69, b66);
    b66 = stwo_m31_mul(b13, b32);
    b69 = stwo_m31_add(b71, b66);
    b66 = stwo_m31_mul(b65, b31);
    b71 = stwo_m31_add(b69, b66);
    b66 = stwo_m31_mul(b14, b30);
    b69 = stwo_m31_add(b71, b66);
    b66 = stwo_m31_mul(b15, b35);
    b71 = stwo_m31_mul(b15, b36);
    unsigned b72 = stwo_m31_mul(b0, b35);
    unsigned b73 = stwo_m31_add(b71, b72);
    b72 = stwo_m31_mul(b15, b41);
    b71 = stwo_m31_mul(b0, b40);
    unsigned b74 = stwo_m31_add(b72, b71);
    b71 = stwo_m31_mul(b16, b39);
    b72 = stwo_m31_add(b74, b71);
    b71 = stwo_m31_mul(b17, b38);
    b74 = stwo_m31_add(b72, b71);
    b71 = stwo_m31_mul(b1, b37);
    b72 = stwo_m31_add(b74, b71);
    b71 = stwo_m31_mul(b18, b36);
    b74 = stwo_m31_add(b72, b71);
    b71 = stwo_m31_mul(b19, b35);
    b72 = stwo_m31_add(b74, b71);
    b71 = stwo_m31_mul(b0, b41);
    b74 = stwo_m31_mul(b16, b40);
    unsigned b75 = stwo_m31_add(b71, b74);
    b74 = stwo_m31_mul(b17, b39);
    b71 = stwo_m31_add(b75, b74);
    b74 = stwo_m31_mul(b1, b38);
    b75 = stwo_m31_add(b71, b74);
    b74 = stwo_m31_mul(b18, b37);
    b71 = stwo_m31_add(b75, b74);
    b74 = stwo_m31_mul(b19, b36);
    b75 = stwo_m31_add(b71, b74);
    b74 = stwo_m31_mul(b16, b41);
    b71 = stwo_m31_mul(b17, b40);
    unsigned b76 = stwo_m31_add(b74, b71);
    b71 = stwo_m31_mul(b1, b39);
    b74 = stwo_m31_add(b76, b71);
    b71 = stwo_m31_mul(b18, b38);
    b76 = stwo_m31_add(b74, b71);
    b71 = stwo_m31_mul(b19, b37);
    b74 = stwo_m31_add(b76, b71);
    b71 = stwo_m31_add(b10, b15);
    b15 = stwo_m31_add(b11, b0);
    b76 = stwo_m31_add(b64, b16);
    b64 = stwo_m31_add(b12, b17);
    b12 = stwo_m31_add(b13, b1);
    b13 = stwo_m31_add(b65, b18);
    b65 = stwo_m31_add(b14, b19);
    b14 = stwo_m31_add(b28, b35);
    b35 = stwo_m31_add(b29, b36);
    unsigned b77 = stwo_m31_add(b30, b37);
    b30 = stwo_m31_add(b31, b38);
    b31 = stwo_m31_add(b32, b39);
    b32 = stwo_m31_add(b33, b40);
    b33 = stwo_m31_add(b34, b41);
    b34 = stwo_m31_mul(b71, b14);
    unsigned b78 = stwo_m31_sub(b34, b8);
    b34 = stwo_m31_sub(b78, b66);
    b78 = stwo_m31_add(b70, b34);
    b34 = stwo_m31_mul(b71, b35);
    unsigned b79 = stwo_m31_mul(b15, b14);
    unsigned b80 = stwo_m31_add(b34, b79);
    b79 = stwo_m31_sub(b80, b68);
    b80 = stwo_m31_sub(b79, b73);
    b79 = stwo_m31_add(b69, b80);
    b80 = stwo_m31_mul(b71, b33);
    b71 = stwo_m31_mul(b15, b32);
    b34 = stwo_m31_add(b80, b71);
    b71 = stwo_m31_mul(b76, b31);
    b80 = stwo_m31_add(b34, b71);
    b71 = stwo_m31_mul(b64, b30);
    b34 = stwo_m31_add(b80, b71);
    b71 = stwo_m31_mul(b12, b77);
    b80 = stwo_m31_add(b34, b71);
    b71 = stwo_m31_mul(b13, b35);
    b34 = stwo_m31_add(b80, b71);
    b71 = stwo_m31_mul(b65, b14);
    b14 = stwo_m31_add(b34, b71);
    b71 = stwo_m31_sub(b14, b67);
    b14 = stwo_m31_sub(b71, b72);
    b71 = stwo_m31_mul(b15, b33);
    b15 = stwo_m31_mul(b76, b32);
    b72 = stwo_m31_add(b71, b15);
    b15 = stwo_m31_mul(b64, b31);
    b71 = stwo_m31_add(b72, b15);
    b15 = stwo_m31_mul(b12, b30);
    b72 = stwo_m31_add(b71, b15);
    b15 = stwo_m31_mul(b13, b77);
    b71 = stwo_m31_add(b72, b15);
    b15 = stwo_m31_mul(b65, b35);
    b35 = stwo_m31_add(b71, b15);
    b15 = stwo_m31_sub(b35, b70);
    b35 = stwo_m31_sub(b15, b75);
    b15 = stwo_m31_add(b66, b35);
    b35 = stwo_m31_mul(b76, b33);
    b33 = stwo_m31_mul(b64, b32);
    b32 = stwo_m31_add(b35, b33);
    b33 = stwo_m31_mul(b12, b31);
    b31 = stwo_m31_add(b32, b33);
    b33 = stwo_m31_mul(b13, b30);
    b30 = stwo_m31_add(b31, b33);
    b33 = stwo_m31_mul(b65, b77);
    b77 = stwo_m31_add(b30, b33);
    b33 = stwo_m31_sub(b77, b69);
    b77 = stwo_m31_sub(b33, b74);
    b33 = stwo_m31_add(b73, b77);
    b77 = stwo_m31_mul(b2, b42);
    b73 = stwo_m31_mul(b2, b43);
    b69 = stwo_m31_mul(b20, b42);
    b30 = stwo_m31_add(b73, b69);
    b69 = stwo_m31_mul(b20, b48);
    b73 = stwo_m31_mul(b21, b47);
    b65 = stwo_m31_add(b69, b73);
    b73 = stwo_m31_mul(b3, b46);
    b69 = stwo_m31_add(b65, b73);
    b73 = stwo_m31_mul(b22, b45);
    b65 = stwo_m31_add(b69, b73);
    b73 = stwo_m31_mul(b23, b44);
    b69 = stwo_m31_add(b65, b73);
    b73 = stwo_m31_mul(b4, b43);
    b65 = stwo_m31_add(b69, b73);
    b73 = stwo_m31_mul(b21, b48);
    b48 = stwo_m31_mul(b3, b47);
    b3 = stwo_m31_add(b73, b48);
    b48 = stwo_m31_mul(b22, b46);
    b46 = stwo_m31_add(b3, b48);
    b48 = stwo_m31_mul(b23, b45);
    b45 = stwo_m31_add(b46, b48);
    b48 = stwo_m31_mul(b4, b44);
    b4 = stwo_m31_add(b45, b48);
    b48 = stwo_m31_mul(b24, b49);
    b45 = stwo_m31_mul(b24, b50);
    b44 = stwo_m31_mul(b25, b49);
    b46 = stwo_m31_add(b45, b44);
    b44 = stwo_m31_mul(b25, b55);
    b45 = stwo_m31_mul(b5, b54);
    b23 = stwo_m31_add(b44, b45);
    b45 = stwo_m31_mul(b26, b53);
    b44 = stwo_m31_add(b23, b45);
    b45 = stwo_m31_mul(b27, b52);
    b23 = stwo_m31_add(b44, b45);
    b45 = stwo_m31_mul(b6, b51);
    b44 = stwo_m31_add(b23, b45);
    b45 = stwo_m31_mul(b9, b50);
    b23 = stwo_m31_add(b44, b45);
    b45 = stwo_m31_mul(b5, b55);
    b44 = stwo_m31_mul(b26, b54);
    b3 = stwo_m31_add(b45, b44);
    b44 = stwo_m31_mul(b27, b53);
    b45 = stwo_m31_add(b3, b44);
    b44 = stwo_m31_mul(b6, b52);
    b3 = stwo_m31_add(b45, b44);
    b44 = stwo_m31_mul(b9, b51);
    b45 = stwo_m31_add(b3, b44);
    b44 = stwo_m31_add(b2, b24);
    b24 = stwo_m31_add(b20, b25);
    b3 = stwo_m31_add(b42, b49);
    b49 = stwo_m31_add(b43, b50);
    b22 = stwo_m31_mul(b44, b3);
    b73 = stwo_m31_sub(b22, b77);
    b22 = stwo_m31_sub(b73, b48);
    b73 = stwo_m31_add(b65, b22);
    b22 = stwo_m31_mul(b44, b49);
    b49 = stwo_m31_mul(b24, b3);
    b3 = stwo_m31_add(b22, b49);
    b49 = stwo_m31_sub(b3, b30);
    b3 = stwo_m31_sub(b49, b46);
    b49 = stwo_m31_add(b4, b3);
    b3 = stwo_m31_add(b10, b2);
    b2 = stwo_m31_add(b11, b20);
    b20 = stwo_m31_add(b0, b25);
    b0 = stwo_m31_add(b16, b5);
    b5 = stwo_m31_add(b17, b26);
    b26 = stwo_m31_add(b1, b27);
    b1 = stwo_m31_add(b18, b6);
    b6 = stwo_m31_add(b19, b9);
    b19 = stwo_m31_add(b28, b42);
    b42 = stwo_m31_add(b29, b43);
    b43 = stwo_m31_add(b36, b50);
    b50 = stwo_m31_add(b37, b51);
    b51 = stwo_m31_add(b38, b52);
    b52 = stwo_m31_add(b39, b53);
    b53 = stwo_m31_add(b40, b54);
    b54 = stwo_m31_add(b41, b55);
    b55 = stwo_m31_mul(b3, b19);
    b41 = stwo_m31_mul(b3, b42);
    b42 = stwo_m31_mul(b2, b19);
    b19 = stwo_m31_add(b41, b42);
    b42 = stwo_m31_mul(b20, b54);
    b20 = stwo_m31_mul(b0, b53);
    b41 = stwo_m31_add(b42, b20);
    b20 = stwo_m31_mul(b5, b52);
    b42 = stwo_m31_add(b41, b20);
    b20 = stwo_m31_mul(b26, b51);
    b41 = stwo_m31_add(b42, b20);
    b20 = stwo_m31_mul(b1, b50);
    b42 = stwo_m31_add(b41, b20);
    b20 = stwo_m31_mul(b6, b43);
    b43 = stwo_m31_add(b42, b20);
    b20 = stwo_m31_mul(b0, b54);
    b54 = stwo_m31_mul(b5, b53);
    b53 = stwo_m31_add(b20, b54);
    b54 = stwo_m31_mul(b26, b52);
    b52 = stwo_m31_add(b53, b54);
    b54 = stwo_m31_mul(b1, b51);
    b51 = stwo_m31_add(b52, b54);
    b54 = stwo_m31_mul(b6, b50);
    b50 = stwo_m31_add(b51, b54);
    b54 = stwo_m31_sub(b55, b8);
    b55 = stwo_m31_sub(b54, b77);
    b54 = stwo_m31_add(b15, b55);
    b55 = stwo_m31_sub(b19, b68);
    b19 = stwo_m31_sub(b55, b30);
    b55 = stwo_m31_add(b33, b19);
    b19 = stwo_m31_sub(b43, b75);
    b43 = stwo_m31_sub(b19, b23);
    b19 = stwo_m31_add(b73, b43);
    b43 = stwo_m31_sub(b50, b74);
    b50 = stwo_m31_sub(b43, b45);
    b43 = stwo_m31_add(b49, b50);
    b50 = stwo_m31_sub(b78, b56);
    b78 = stwo_m31_sub(b79, b57);
    b79 = stwo_m31_sub(b14, b58);
    b14 = stwo_m31_sub(b54, b59);
    b54 = stwo_m31_sub(b55, b60);
    b55 = 2u;
    b60 = stwo_m31_mul(b55, b50);
    b55 = stwo_m31_add(b60, b79);
    b60 = 32u;
    b79 = stwo_m31_mul(b60, b14);
    b60 = stwo_m31_add(b55, b79);
    b79 = 4u;
    b55 = stwo_m31_mul(b79, b19);
    b79 = stwo_m31_sub(b60, b55);
    b55 = 2u;
    b60 = stwo_m31_mul(b55, b78);
    b55 = stwo_m31_add(b60, b14);
    b60 = 32u;
    b14 = stwo_m31_mul(b60, b54);
    b60 = stwo_m31_add(b55, b14);
    b14 = 4u;
    b55 = stwo_m31_mul(b14, b43);
    b14 = stwo_m31_sub(b60, b55);
    b55 = 512u;
    b60 = stwo_m31_mul(b62, b55);
    b55 = stwo_m31_add(b79, b61);
    b79 = stwo_m31_sub(b60, b55);
    b55 = 512u;
    b60 = stwo_m31_mul(b63, b55);
    b55 = stwo_m31_add(b14, b62);
    b14 = stwo_m31_sub(b60, b55);
    StwoCairoQm31 e0 = { b79, b7, b7, b7 };
    StwoCairoQm31 e1 = { b14, b7, b7, b7 };
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
