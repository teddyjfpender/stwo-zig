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
stwo_cairo_cuda_eval_v1_57909c65c0bbb41e(
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
    unsigned b25 = 1u;
    unsigned b26 = stwo_m31_sub(b25, b4);
    b25 = stwo_m31_mul(b4, b26);
    b26 = 0u;
    unsigned b27 = 64u;
    unsigned b28 = stwo_m31_mul(b4, b27);
    b27 = 1u;
    unsigned b29 = stwo_m31_sub(b27, b4);
    b27 = 128u;
    unsigned b30 = stwo_m31_mul(b29, b27);
    b27 = stwo_m31_add(b28, b30);
    b30 = 32768u;
    b28 = stwo_m31_sub(b3, b30);
    b30 = 1u;
    b29 = stwo_m31_sub(b30, b4);
    b30 = 1u;
    unsigned b31 = stwo_m31_sub(b30, b10);
    b30 = stwo_m31_mul(b10, b31);
    b31 = 1u;
    unsigned b32 = stwo_m31_mul(b30, b31);
    b31 = 2u;
    b30 = stwo_m31_mul(b10, b31);
    b31 = stwo_m31_sub(b9, b30);
    b30 = 1u;
    b10 = stwo_m31_sub(b30, b31);
    b30 = stwo_m31_mul(b31, b10);
    b10 = 1u;
    b31 = stwo_m31_mul(b30, b10);
    b10 = 512u;
    b30 = stwo_m31_mul(b7, b10);
    b10 = stwo_m31_add(b6, b30);
    b30 = 262144u;
    unsigned b33 = stwo_m31_mul(b8, b30);
    b30 = stwo_m31_add(b10, b33);
    b33 = 134217728u;
    b10 = stwo_m31_mul(b9, b33);
    b33 = stwo_m31_add(b30, b10);
    b10 = stwo_m31_sub(b33, b2);
    b33 = 1u;
    b30 = stwo_m31_add(b1, b33);
    b33 = 1u;
    unsigned b34 = stwo_m31_sub(b33, b16);
    b33 = stwo_m31_mul(b16, b34);
    b34 = 1u;
    unsigned b35 = stwo_m31_mul(b33, b34);
    b34 = 2u;
    b33 = stwo_m31_mul(b16, b34);
    b34 = stwo_m31_sub(b15, b33);
    b33 = 1u;
    b16 = stwo_m31_sub(b33, b34);
    b33 = stwo_m31_mul(b34, b16);
    b16 = 1u;
    b34 = stwo_m31_mul(b33, b16);
    b16 = 512u;
    b33 = stwo_m31_mul(b13, b16);
    b16 = stwo_m31_add(b12, b33);
    b33 = 262144u;
    unsigned b36 = stwo_m31_mul(b14, b33);
    b33 = stwo_m31_add(b16, b36);
    b36 = 134217728u;
    b16 = stwo_m31_mul(b15, b36);
    b36 = stwo_m31_add(b33, b16);
    b16 = 1u;
    b33 = stwo_m31_add(b0, b16);
    b16 = stwo_m31_sub(b36, b33);
    b33 = stwo_m31_mul(b4, b2);
    b4 = stwo_m31_mul(b29, b1);
    b29 = stwo_m31_add(b33, b4);
    b4 = stwo_m31_sub(b17, b29);
    b29 = stwo_m31_add(b17, b28);
    b28 = 1u;
    b17 = stwo_m31_sub(b28, b23);
    b28 = stwo_m31_mul(b23, b17);
    b17 = 1u;
    b33 = stwo_m31_mul(b28, b17);
    b17 = 2u;
    b28 = stwo_m31_mul(b23, b17);
    b17 = stwo_m31_sub(b22, b28);
    b28 = 1u;
    b23 = stwo_m31_sub(b28, b17);
    b28 = stwo_m31_mul(b17, b23);
    b23 = 1u;
    b17 = stwo_m31_mul(b28, b23);
    b23 = stwo_m31_mul(b24, b24);
    b28 = stwo_m31_sub(b23, b24);
    b23 = 512u;
    b36 = stwo_m31_mul(b20, b23);
    b23 = stwo_m31_add(b19, b36);
    b36 = 262144u;
    unsigned b37 = stwo_m31_mul(b21, b36);
    b36 = stwo_m31_add(b23, b37);
    b37 = 134217728u;
    b23 = stwo_m31_mul(b22, b37);
    b37 = stwo_m31_add(b36, b23);
    b23 = 2u;
    b36 = stwo_m31_add(b1, b23);
    b23 = 2u;
    unsigned b38 = stwo_m31_add(b1, b23);
    b23 = stwo_trace_value(arena, *args, 2u, 0u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 1u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 2u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 3u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 4u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 5u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 6u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 2u, 7u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 2u, 8u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 2u, 9u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 2u, 10u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 2u, 11u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 2u, 16u, row, -1);
    unsigned b55 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 2u, 17u, row, -1);
    unsigned b57 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 2u, 18u, row, -1);
    unsigned b59 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 2u, 19u, row, -1);
    unsigned b61 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    StwoCairoQm31 e0 = { b25, b26, b26, b26 };
    StwoCairoQm31 e1 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e2 = { b0, b26, b26, b26 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    e1 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    e3 = { b3, b26, b26, b26 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 5u * 4u);
    e1 = { b27, b26, b26, b26 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 6u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 7u * 4u);
    e1 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 8u * 4u);
    e3 = { b1, b26, b26, b26 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 9u * 4u);
    e2 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(arena, args->ext_params + 10u * 4u);
    e4 = { b5, b26, b26, b26 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 11u * 4u);
    e2 = stwo_qm31_sub(e4, e5);
    e5 = { b32, b26, b26, b26 };
    e4 = { b31, b26, b26, b26 };
    e3 = stwo_load_qm31(arena, args->ext_params + 12u * 4u);
    StwoCairoQm31 e6 = { b5, b26, b26, b26 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 13u * 4u);
    e3 = stwo_qm31_add(e6, e7);
    e6 = stwo_load_qm31(arena, args->ext_params + 14u * 4u);
    e7 = { b6, b26, b26, b26 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e3, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 15u * 4u);
    e3 = { b7, b26, b26, b26 };
    e6 = stwo_qm31_mul(e8, e3);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 16u * 4u);
    e7 = { b8, b26, b26, b26 };
    e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e3, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 17u * 4u);
    e3 = { b9, b26, b26, b26 };
    e6 = stwo_qm31_mul(e8, e3);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 18u * 4u);
    e7 = stwo_qm31_sub(e3, e6);
    e6 = { b10, b26, b26, b26 };
    e3 = stwo_load_qm31(arena, args->ext_params + 19u * 4u);
    e8 = { b30, b26, b26, b26 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e3, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 20u * 4u);
    e3 = stwo_qm31_add(e8, e9);
    e8 = stwo_load_qm31(arena, args->ext_params + 21u * 4u);
    e9 = { b11, b26, b26, b26 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e3, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 22u * 4u);
    e3 = stwo_qm31_sub(e9, e10);
    e10 = { b35, b26, b26, b26 };
    e9 = { b34, b26, b26, b26 };
    e8 = stwo_load_qm31(arena, args->ext_params + 23u * 4u);
    StwoCairoQm31 e11 = { b11, b26, b26, b26 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e8, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 24u * 4u);
    e8 = stwo_qm31_add(e11, e12);
    e11 = stwo_load_qm31(arena, args->ext_params + 25u * 4u);
    e12 = { b12, b26, b26, b26 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e11, e12);
    e12 = stwo_qm31_add(e8, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 26u * 4u);
    e8 = { b13, b26, b26, b26 };
    e11 = stwo_qm31_mul(e13, e8);
    e8 = stwo_qm31_add(e12, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 27u * 4u);
    e12 = { b14, b26, b26, b26 };
    e13 = stwo_qm31_mul(e11, e12);
    e12 = stwo_qm31_add(e8, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 28u * 4u);
    e8 = { b15, b26, b26, b26 };
    e11 = stwo_qm31_mul(e13, e8);
    e8 = stwo_qm31_add(e12, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 29u * 4u);
    e12 = stwo_qm31_sub(e8, e11);
    e11 = { b16, b26, b26, b26 };
    e8 = { b4, b26, b26, b26 };
    e13 = stwo_load_qm31(arena, args->ext_params + 30u * 4u);
    StwoCairoQm31 e14 = { b29, b26, b26, b26 };
    StwoCairoQm31 e15 = stwo_qm31_mul(e13, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 31u * 4u);
    e13 = stwo_qm31_add(e14, e15);
    e14 = stwo_load_qm31(arena, args->ext_params + 32u * 4u);
    e15 = { b18, b26, b26, b26 };
    StwoCairoQm31 e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(arena, args->ext_params + 33u * 4u);
    e13 = stwo_qm31_sub(e15, e16);
    e16 = { b33, b26, b26, b26 };
    e15 = { b17, b26, b26, b26 };
    e14 = stwo_load_qm31(arena, args->ext_params + 34u * 4u);
    StwoCairoQm31 e17 = { b18, b26, b26, b26 };
    StwoCairoQm31 e18 = stwo_qm31_mul(e14, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 35u * 4u);
    e14 = stwo_qm31_add(e17, e18);
    e17 = stwo_load_qm31(arena, args->ext_params + 36u * 4u);
    e18 = { b19, b26, b26, b26 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e17, e18);
    e18 = stwo_qm31_add(e14, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 37u * 4u);
    e14 = { b20, b26, b26, b26 };
    e17 = stwo_qm31_mul(e19, e14);
    e14 = stwo_qm31_add(e18, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 38u * 4u);
    e18 = { b21, b26, b26, b26 };
    e19 = stwo_qm31_mul(e17, e18);
    e18 = stwo_qm31_add(e14, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 39u * 4u);
    e14 = { b22, b26, b26, b26 };
    e17 = stwo_qm31_mul(e19, e14);
    e14 = stwo_qm31_add(e18, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 40u * 4u);
    e18 = stwo_qm31_sub(e14, e17);
    e17 = { b28, b26, b26, b26 };
    e14 = stwo_load_qm31(arena, args->ext_params + 41u * 4u);
    e19 = { b0, b26, b26, b26 };
    StwoCairoQm31 e20 = stwo_qm31_mul(e14, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 42u * 4u);
    e14 = stwo_qm31_add(e19, e20);
    e19 = stwo_load_qm31(arena, args->ext_params + 43u * 4u);
    e20 = { b1, b26, b26, b26 };
    StwoCairoQm31 e21 = stwo_qm31_mul(e19, e20);
    e20 = stwo_qm31_add(e14, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 44u * 4u);
    e14 = { b2, b26, b26, b26 };
    e19 = stwo_qm31_mul(e21, e14);
    e14 = stwo_qm31_add(e20, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 45u * 4u);
    e20 = stwo_qm31_sub(e14, e19);
    e19 = { b24, b26, b26, b26 };
    e14 = stwo_qm31_neg(e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 46u * 4u);
    e21 = { b37, b26, b26, b26 };
    StwoCairoQm31 e22 = stwo_qm31_mul(e19, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 47u * 4u);
    e19 = stwo_qm31_add(e21, e22);
    e21 = stwo_load_qm31(arena, args->ext_params + 48u * 4u);
    e22 = { b36, b26, b26, b26 };
    StwoCairoQm31 e23 = stwo_qm31_mul(e21, e22);
    e22 = stwo_qm31_add(e19, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 49u * 4u);
    e19 = { b38, b26, b26, b26 };
    e21 = stwo_qm31_mul(e23, e19);
    e19 = stwo_qm31_add(e22, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 50u * 4u);
    e22 = stwo_qm31_sub(e19, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 51u * 4u);
    e19 = stwo_qm31_mul(e2, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 52u * 4u);
    e23 = stwo_qm31_mul(e1, e21);
    e21 = stwo_qm31_add(e19, e23);
    e23 = stwo_qm31_mul(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 53u * 4u);
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 54u * 4u);
    e19 = stwo_qm31_mul(e7, e2);
    e2 = stwo_qm31_add(e1, e19);
    e19 = stwo_qm31_mul(e7, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 55u * 4u);
    e7 = stwo_qm31_mul(e13, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 56u * 4u);
    e1 = stwo_qm31_mul(e12, e3);
    e3 = stwo_qm31_add(e7, e1);
    e1 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 57u * 4u);
    e12 = stwo_qm31_mul(e20, e13);
    e13 = { b24, b26, b26, b26 };
    e7 = stwo_qm31_mul(e18, e13);
    e13 = stwo_qm31_add(e12, e7);
    e7 = stwo_qm31_mul(e18, e20);
    e20 = { b23, b39, b40, b41 };
    e18 = stwo_qm31_mul(e20, e23);
    e23 = stwo_qm31_sub(e18, e21);
    e18 = { b42, b43, b44, b45 };
    e21 = stwo_qm31_sub(e18, e20);
    e20 = stwo_qm31_mul(e21, e19);
    e21 = stwo_qm31_sub(e20, e2);
    e20 = { b46, b47, b48, b49 };
    e2 = stwo_qm31_sub(e20, e18);
    e18 = stwo_qm31_mul(e2, e1);
    e2 = stwo_qm31_sub(e18, e3);
    e18 = { b50, b51, b52, b53 };
    e3 = stwo_qm31_sub(e18, e20);
    e20 = stwo_qm31_mul(e3, e7);
    e3 = stwo_qm31_sub(e20, e13);
    e20 = { b54, b56, b58, b60 };
    e13 = { b55, b57, b59, b61 };
    e7 = stwo_qm31_sub(e13, e20);
    e13 = stwo_qm31_sub(e7, e18);
    e7 = stwo_load_qm31(arena, args->ext_params + 58u * 4u);
    e18 = stwo_qm31_add(e13, e7);
    e7 = stwo_qm31_mul(e18, e22);
    e18 = stwo_qm31_sub(e7, e14);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e4, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e6, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e10, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e9, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e11, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e8, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e16, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 8u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e15, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 9u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e17, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 10u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e23, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 11u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e21, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 12u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 13u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 14u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e18, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 15u) * 4u)));
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
