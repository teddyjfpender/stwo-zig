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
stwo_cairo_cuda_eval_v1_71ae7b287af0b638(
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
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b38 = 1u;
    unsigned b39 = stwo_m31_sub(b38, b6);
    b38 = stwo_m31_mul(b6, b39);
    b39 = 0u;
    unsigned b40 = 1u;
    unsigned b41 = stwo_m31_sub(b40, b7);
    b40 = stwo_m31_mul(b7, b41);
    b41 = 1u;
    unsigned b42 = stwo_m31_sub(b41, b8);
    b41 = stwo_m31_mul(b8, b42);
    b42 = 1u;
    unsigned b43 = stwo_m31_sub(b42, b9);
    b42 = stwo_m31_mul(b9, b43);
    b43 = 1u;
    unsigned b44 = stwo_m31_sub(b43, b8);
    b43 = stwo_m31_sub(b44, b9);
    b44 = 1u;
    unsigned b45 = stwo_m31_sub(b44, b43);
    b44 = stwo_m31_mul(b43, b45);
    b45 = 1u;
    unsigned b46 = stwo_m31_sub(b45, b10);
    b45 = stwo_m31_mul(b10, b46);
    b46 = 8u;
    unsigned b47 = stwo_m31_mul(b6, b46);
    b46 = 16u;
    unsigned b48 = stwo_m31_mul(b7, b46);
    b46 = stwo_m31_add(b47, b48);
    b48 = 32u;
    b47 = stwo_m31_mul(b8, b48);
    b48 = stwo_m31_add(b46, b47);
    b47 = 64u;
    b46 = stwo_m31_mul(b9, b47);
    b47 = stwo_m31_add(b48, b46);
    b46 = 128u;
    b48 = stwo_m31_mul(b43, b46);
    b46 = stwo_m31_add(b47, b48);
    b48 = 256u;
    b47 = stwo_m31_add(b46, b48);
    b48 = 32u;
    b46 = stwo_m31_mul(b10, b48);
    b48 = 256u;
    b10 = stwo_m31_add(b46, b48);
    b48 = 32768u;
    b46 = stwo_m31_sub(b3, b48);
    b48 = 32768u;
    unsigned b49 = stwo_m31_sub(b4, b48);
    b48 = 32768u;
    unsigned b50 = stwo_m31_sub(b5, b48);
    b48 = 1u;
    unsigned b51 = stwo_m31_sub(b48, b50);
    b48 = stwo_m31_mul(b8, b51);
    b51 = stwo_m31_mul(b6, b2);
    b50 = 1u;
    unsigned b52 = stwo_m31_sub(b50, b6);
    b50 = stwo_m31_mul(b52, b1);
    b52 = stwo_m31_add(b51, b50);
    b50 = stwo_m31_sub(b11, b52);
    b52 = stwo_m31_mul(b7, b2);
    b51 = 1u;
    b6 = stwo_m31_sub(b51, b7);
    b51 = stwo_m31_mul(b6, b1);
    b6 = stwo_m31_add(b52, b51);
    b51 = stwo_m31_sub(b12, b6);
    b6 = stwo_m31_mul(b8, b0);
    b8 = stwo_m31_mul(b9, b2);
    b9 = stwo_m31_add(b6, b8);
    b8 = stwo_m31_mul(b43, b1);
    b43 = stwo_m31_add(b9, b8);
    b8 = stwo_m31_sub(b13, b43);
    b43 = stwo_m31_add(b11, b46);
    b46 = 1u;
    b11 = stwo_m31_sub(b15, b46);
    b46 = stwo_m31_mul(b15, b11);
    b11 = 1u;
    b13 = stwo_m31_sub(b16, b11);
    b11 = stwo_m31_mul(b16, b13);
    b13 = 1u;
    b9 = stwo_m31_sub(b15, b13);
    b13 = stwo_m31_mul(b16, b9);
    b9 = 508u;
    b1 = stwo_m31_mul(b16, b9);
    b9 = 511u;
    b6 = stwo_m31_mul(b16, b9);
    b9 = 136u;
    b2 = stwo_m31_mul(b15, b9);
    b9 = stwo_m31_sub(b2, b16);
    b2 = 256u;
    b52 = stwo_m31_mul(b15, b2);
    b2 = 1u;
    b7 = stwo_m31_sub(b2, b21);
    b2 = stwo_m31_mul(b21, b7);
    b7 = 1u;
    unsigned b53 = stwo_m31_mul(b2, b7);
    b7 = 2u;
    b2 = stwo_m31_mul(b21, b7);
    b7 = stwo_m31_sub(b20, b2);
    b2 = 1u;
    b21 = stwo_m31_sub(b2, b7);
    b2 = stwo_m31_mul(b7, b21);
    b21 = 1u;
    b7 = stwo_m31_mul(b2, b21);
    b21 = stwo_m31_add(b20, b1);
    b1 = 512u;
    b2 = stwo_m31_mul(b18, b1);
    b1 = stwo_m31_add(b17, b2);
    b2 = 262144u;
    unsigned b54 = stwo_m31_mul(b19, b2);
    b2 = stwo_m31_add(b1, b54);
    b54 = 134217728u;
    b1 = stwo_m31_mul(b20, b54);
    b54 = stwo_m31_add(b2, b1);
    b1 = stwo_m31_sub(b54, b15);
    b54 = 536870912u;
    b15 = stwo_m31_mul(b54, b16);
    b54 = stwo_m31_sub(b1, b15);
    b15 = stwo_m31_add(b12, b49);
    b49 = 1u;
    b12 = stwo_m31_sub(b23, b49);
    b49 = stwo_m31_mul(b23, b12);
    b12 = 1u;
    b1 = stwo_m31_sub(b24, b12);
    b12 = stwo_m31_mul(b24, b1);
    b1 = 1u;
    b16 = stwo_m31_sub(b23, b1);
    b1 = stwo_m31_mul(b24, b16);
    b16 = 1u;
    b2 = stwo_m31_sub(b16, b29);
    b16 = stwo_m31_mul(b29, b2);
    b2 = 1u;
    b20 = stwo_m31_mul(b16, b2);
    b2 = 2u;
    b16 = stwo_m31_mul(b29, b2);
    b2 = stwo_m31_sub(b28, b16);
    b16 = 1u;
    b29 = stwo_m31_sub(b16, b2);
    b16 = stwo_m31_mul(b2, b29);
    b29 = 1u;
    b2 = stwo_m31_mul(b16, b29);
    b29 = 512u;
    b16 = stwo_m31_mul(b26, b29);
    b29 = stwo_m31_add(b25, b16);
    b16 = 262144u;
    b25 = stwo_m31_mul(b27, b16);
    b16 = stwo_m31_add(b29, b25);
    b25 = 134217728u;
    b29 = stwo_m31_mul(b28, b25);
    b25 = stwo_m31_add(b16, b29);
    b29 = stwo_m31_sub(b25, b23);
    b25 = 536870912u;
    b23 = stwo_m31_mul(b25, b24);
    b25 = stwo_m31_sub(b29, b23);
    b23 = 1u;
    b29 = stwo_m31_sub(b30, b23);
    b23 = stwo_m31_mul(b30, b29);
    b29 = 1u;
    b24 = stwo_m31_sub(b31, b29);
    b29 = stwo_m31_mul(b31, b24);
    b24 = 1u;
    b16 = stwo_m31_sub(b30, b24);
    b24 = stwo_m31_mul(b31, b16);
    b16 = 1u;
    b28 = stwo_m31_sub(b16, b36);
    b16 = stwo_m31_mul(b36, b28);
    b28 = 1u;
    b27 = stwo_m31_mul(b16, b28);
    b28 = 2u;
    b16 = stwo_m31_mul(b36, b28);
    b28 = stwo_m31_sub(b35, b16);
    b16 = 1u;
    b36 = stwo_m31_sub(b16, b28);
    b16 = stwo_m31_mul(b28, b36);
    b36 = 1u;
    b28 = stwo_m31_mul(b16, b36);
    b36 = 512u;
    b16 = stwo_m31_mul(b33, b36);
    b36 = stwo_m31_add(b32, b16);
    b16 = 262144u;
    b32 = stwo_m31_mul(b34, b16);
    b16 = stwo_m31_add(b36, b32);
    b32 = 134217728u;
    b36 = stwo_m31_mul(b35, b32);
    b32 = stwo_m31_add(b16, b36);
    b36 = stwo_m31_sub(b32, b30);
    b32 = 536870912u;
    b30 = stwo_m31_mul(b32, b31);
    b32 = stwo_m31_sub(b36, b30);
    b30 = stwo_m31_add(b25, b32);
    b32 = stwo_m31_sub(b54, b30);
    b30 = stwo_m31_mul(b37, b37);
    b54 = stwo_m31_sub(b30, b37);
    b30 = stwo_trace_value(arena, *args, 2u, 0u, row, 0);
    b37 = stwo_trace_value(arena, *args, 2u, 1u, row, 0);
    b25 = stwo_trace_value(arena, *args, 2u, 2u, row, 0);
    b36 = stwo_trace_value(arena, *args, 2u, 3u, row, 0);
    b31 = stwo_trace_value(arena, *args, 2u, 4u, row, 0);
    b16 = stwo_trace_value(arena, *args, 2u, 5u, row, 0);
    b35 = stwo_trace_value(arena, *args, 2u, 6u, row, 0);
    b34 = stwo_trace_value(arena, *args, 2u, 7u, row, 0);
    StwoCairoQm31 e0 = { b38, b39, b39, b39 };
    StwoCairoQm31 e1 = { b40, b39, b39, b39 };
    StwoCairoQm31 e2 = { b41, b39, b39, b39 };
    StwoCairoQm31 e3 = { b42, b39, b39, b39 };
    StwoCairoQm31 e4 = { b44, b39, b39, b39 };
    StwoCairoQm31 e5 = { b45, b39, b39, b39 };
    StwoCairoQm31 e6 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e7 = { b0, b39, b39, b39 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    e6 = stwo_qm31_add(e7, e8);
    e7 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    e8 = { b3, b39, b39, b39 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    e6 = { b4, b39, b39, b39 };
    e7 = stwo_qm31_mul(e9, e6);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    e8 = { b5, b39, b39, b39 };
    e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 5u * 4u);
    e6 = { b47, b39, b39, b39 };
    e7 = stwo_qm31_mul(e9, e6);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 6u * 4u);
    e8 = { b10, b39, b39, b39 };
    e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 7u * 4u);
    e6 = stwo_qm31_sub(e8, e9);
    e9 = { b48, b39, b39, b39 };
    e8 = { b50, b39, b39, b39 };
    e7 = { b51, b39, b39, b39 };
    StwoCairoQm31 e10 = { b8, b39, b39, b39 };
    StwoCairoQm31 e11 = stwo_load_qm31(arena, args->ext_params + 8u * 4u);
    StwoCairoQm31 e12 = { b43, b39, b39, b39 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e11, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 9u * 4u);
    e11 = stwo_qm31_add(e12, e13);
    e12 = stwo_load_qm31(arena, args->ext_params + 10u * 4u);
    e13 = { b14, b39, b39, b39 };
    StwoCairoQm31 e14 = stwo_qm31_mul(e12, e13);
    e13 = stwo_qm31_add(e11, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 11u * 4u);
    e11 = stwo_qm31_sub(e13, e14);
    e14 = { b46, b39, b39, b39 };
    e13 = { b11, b39, b39, b39 };
    e12 = { b13, b39, b39, b39 };
    StwoCairoQm31 e15 = { b53, b39, b39, b39 };
    StwoCairoQm31 e16 = { b7, b39, b39, b39 };
    StwoCairoQm31 e17 = stwo_load_qm31(arena, args->ext_params + 12u * 4u);
    StwoCairoQm31 e18 = { b14, b39, b39, b39 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e17, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 13u * 4u);
    e17 = stwo_qm31_add(e18, e19);
    e18 = stwo_load_qm31(arena, args->ext_params + 14u * 4u);
    e19 = { b17, b39, b39, b39 };
    StwoCairoQm31 e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 15u * 4u);
    e17 = { b18, b39, b39, b39 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 16u * 4u);
    e19 = { b19, b39, b39, b39 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 17u * 4u);
    e17 = { b21, b39, b39, b39 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 18u * 4u);
    e19 = { b6, b39, b39, b39 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 19u * 4u);
    e17 = { b6, b39, b39, b39 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 20u * 4u);
    e19 = { b6, b39, b39, b39 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 21u * 4u);
    e17 = { b6, b39, b39, b39 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 22u * 4u);
    e19 = { b6, b39, b39, b39 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 23u * 4u);
    e17 = { b6, b39, b39, b39 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 24u * 4u);
    e19 = { b6, b39, b39, b39 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 25u * 4u);
    e17 = { b6, b39, b39, b39 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 26u * 4u);
    e19 = { b6, b39, b39, b39 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 27u * 4u);
    e17 = { b6, b39, b39, b39 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 28u * 4u);
    e19 = { b6, b39, b39, b39 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 29u * 4u);
    e17 = { b6, b39, b39, b39 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 30u * 4u);
    e19 = { b6, b39, b39, b39 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 31u * 4u);
    e17 = { b6, b39, b39, b39 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 32u * 4u);
    e19 = { b6, b39, b39, b39 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 33u * 4u);
    e17 = { b6, b39, b39, b39 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 34u * 4u);
    e19 = { b6, b39, b39, b39 };
    e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e17, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 35u * 4u);
    e17 = { b9, b39, b39, b39 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 36u * 4u);
    e19 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 37u * 4u);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 38u * 4u);
    e19 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 39u * 4u);
    e17 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 40u * 4u);
    e19 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 41u * 4u);
    e17 = { b52, b39, b39, b39 };
    e20 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e19, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 42u * 4u);
    e19 = stwo_qm31_sub(e17, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 43u * 4u);
    e17 = { b15, b39, b39, b39 };
    e18 = stwo_qm31_mul(e20, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 44u * 4u);
    e20 = stwo_qm31_add(e17, e18);
    e17 = stwo_load_qm31(arena, args->ext_params + 45u * 4u);
    e18 = { b22, b39, b39, b39 };
    StwoCairoQm31 e21 = stwo_qm31_mul(e17, e18);
    e18 = stwo_qm31_add(e20, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 46u * 4u);
    e20 = stwo_qm31_sub(e18, e21);
    e21 = { b49, b39, b39, b39 };
    e18 = { b12, b39, b39, b39 };
    e17 = { b1, b39, b39, b39 };
    StwoCairoQm31 e22 = { b20, b39, b39, b39 };
    StwoCairoQm31 e23 = { b2, b39, b39, b39 };
    StwoCairoQm31 e24 = { b23, b39, b39, b39 };
    StwoCairoQm31 e25 = { b29, b39, b39, b39 };
    StwoCairoQm31 e26 = { b24, b39, b39, b39 };
    StwoCairoQm31 e27 = { b27, b39, b39, b39 };
    StwoCairoQm31 e28 = { b28, b39, b39, b39 };
    StwoCairoQm31 e29 = { b32, b39, b39, b39 };
    StwoCairoQm31 e30 = { b54, b39, b39, b39 };
    StwoCairoQm31 e31 = stwo_load_qm31(arena, args->ext_params + 123u * 4u);
    StwoCairoQm31 e32 = stwo_qm31_mul(e11, e31);
    e31 = stwo_load_qm31(arena, args->ext_params + 124u * 4u);
    StwoCairoQm31 e33 = stwo_qm31_mul(e6, e31);
    e31 = stwo_qm31_add(e32, e33);
    e33 = stwo_qm31_mul(e6, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 125u * 4u);
    e6 = stwo_qm31_mul(e20, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 126u * 4u);
    e32 = stwo_qm31_mul(e19, e11);
    e11 = stwo_qm31_add(e6, e32);
    e32 = stwo_qm31_mul(e19, e20);
    e20 = { b30, b37, b25, b36 };
    e19 = stwo_qm31_mul(e20, e33);
    e33 = stwo_qm31_sub(e19, e31);
    e19 = { b31, b16, b35, b34 };
    e31 = stwo_qm31_sub(e19, e20);
    e19 = stwo_qm31_mul(e31, e32);
    e31 = stwo_qm31_sub(e19, e11);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e4, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e9, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e8, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 8u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e10, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 9u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e14, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 10u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e13, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 11u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e12, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 12u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e15, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 13u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e16, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 14u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e21, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 15u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e18, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 16u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e17, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 17u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e22, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 18u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e23, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 19u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e24, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 20u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e25, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 21u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e26, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 22u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e27, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 23u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e28, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 24u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e29, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 25u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e30, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 26u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e33, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 27u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e31, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 28u) * 4u)));
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
