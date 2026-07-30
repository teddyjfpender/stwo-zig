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
stwo_cairo_cuda_eval_v1_ba28409956fb2ad0(
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
    unsigned b37 = 1u;
    unsigned b38 = stwo_m31_sub(b37, b6);
    b37 = stwo_m31_mul(b6, b38);
    b38 = 0u;
    unsigned b39 = 1u;
    unsigned b40 = stwo_m31_sub(b39, b7);
    b39 = stwo_m31_mul(b7, b40);
    b40 = 1u;
    unsigned b41 = stwo_m31_sub(b40, b8);
    b40 = stwo_m31_mul(b8, b41);
    b41 = 1u;
    unsigned b42 = stwo_m31_sub(b41, b9);
    b41 = stwo_m31_mul(b9, b42);
    b42 = 1u;
    unsigned b43 = stwo_m31_sub(b42, b8);
    b42 = stwo_m31_sub(b43, b9);
    b43 = 1u;
    unsigned b44 = stwo_m31_sub(b43, b42);
    b43 = stwo_m31_mul(b42, b44);
    b44 = 1u;
    unsigned b45 = stwo_m31_sub(b44, b10);
    b44 = stwo_m31_mul(b10, b45);
    b45 = 8u;
    unsigned b46 = stwo_m31_mul(b6, b45);
    b45 = 16u;
    unsigned b47 = stwo_m31_mul(b7, b45);
    b45 = stwo_m31_add(b46, b47);
    b47 = 32u;
    b46 = stwo_m31_mul(b8, b47);
    b47 = stwo_m31_add(b45, b46);
    b46 = 64u;
    b45 = stwo_m31_mul(b9, b46);
    b46 = stwo_m31_add(b47, b45);
    b45 = 128u;
    b47 = stwo_m31_mul(b42, b45);
    b45 = stwo_m31_add(b46, b47);
    b47 = 32u;
    b46 = stwo_m31_mul(b10, b47);
    b47 = 1u;
    unsigned b48 = stwo_m31_add(b47, b46);
    b47 = 256u;
    b46 = stwo_m31_add(b48, b47);
    b47 = 32768u;
    b48 = stwo_m31_sub(b3, b47);
    b47 = 32768u;
    unsigned b49 = stwo_m31_sub(b4, b47);
    b47 = 32768u;
    unsigned b50 = stwo_m31_sub(b5, b47);
    b47 = 1u;
    unsigned b51 = stwo_m31_sub(b47, b50);
    b47 = stwo_m31_mul(b8, b51);
    b51 = stwo_m31_mul(b6, b2);
    unsigned b52 = 1u;
    unsigned b53 = stwo_m31_sub(b52, b6);
    b52 = stwo_m31_mul(b53, b1);
    b53 = stwo_m31_add(b51, b52);
    b52 = stwo_m31_sub(b11, b53);
    b53 = stwo_m31_mul(b7, b2);
    b51 = 1u;
    b6 = stwo_m31_sub(b51, b7);
    b51 = stwo_m31_mul(b6, b1);
    b6 = stwo_m31_add(b53, b51);
    b51 = stwo_m31_sub(b12, b6);
    b6 = stwo_m31_mul(b8, b0);
    b53 = stwo_m31_mul(b9, b2);
    b9 = stwo_m31_add(b6, b53);
    b53 = stwo_m31_mul(b42, b1);
    b42 = stwo_m31_add(b9, b53);
    b53 = stwo_m31_sub(b13, b42);
    b42 = stwo_m31_add(b11, b48);
    b48 = stwo_m31_add(b12, b49);
    b49 = stwo_m31_add(b13, b50);
    b50 = 262144u;
    b13 = stwo_m31_mul(b33, b50);
    b50 = stwo_m31_mul(b24, b29);
    b12 = stwo_m31_sub(b50, b15);
    b50 = stwo_m31_mul(b24, b30);
    b11 = stwo_m31_mul(b25, b29);
    b9 = stwo_m31_add(b50, b11);
    b11 = stwo_m31_sub(b9, b16);
    b9 = 512u;
    b50 = stwo_m31_mul(b11, b9);
    b9 = stwo_m31_add(b12, b50);
    b50 = stwo_m31_sub(b13, b9);
    b9 = 262144u;
    b13 = stwo_m31_mul(b34, b9);
    b9 = stwo_m31_mul(b24, b31);
    b12 = stwo_m31_mul(b25, b30);
    b11 = stwo_m31_add(b9, b12);
    b12 = stwo_m31_mul(b26, b29);
    b9 = stwo_m31_add(b11, b12);
    b12 = stwo_m31_sub(b9, b17);
    b9 = stwo_m31_add(b33, b12);
    b12 = stwo_m31_mul(b24, b32);
    b11 = stwo_m31_mul(b25, b31);
    b6 = stwo_m31_add(b12, b11);
    b11 = stwo_m31_mul(b26, b30);
    b12 = stwo_m31_add(b6, b11);
    b11 = stwo_m31_mul(b27, b29);
    b6 = stwo_m31_add(b12, b11);
    b11 = stwo_m31_sub(b6, b18);
    b6 = 512u;
    b12 = stwo_m31_mul(b11, b6);
    b6 = stwo_m31_add(b9, b12);
    b12 = stwo_m31_sub(b13, b6);
    b6 = 262144u;
    b13 = stwo_m31_mul(b35, b6);
    b6 = stwo_m31_mul(b25, b32);
    b9 = stwo_m31_mul(b26, b31);
    b11 = stwo_m31_add(b6, b9);
    b9 = stwo_m31_mul(b27, b30);
    b6 = stwo_m31_add(b11, b9);
    b9 = stwo_m31_sub(b6, b19);
    b6 = stwo_m31_add(b34, b9);
    b9 = stwo_m31_mul(b26, b32);
    b11 = stwo_m31_mul(b27, b31);
    b7 = stwo_m31_add(b9, b11);
    b11 = stwo_m31_sub(b7, b20);
    b7 = 512u;
    b9 = stwo_m31_mul(b11, b7);
    b7 = stwo_m31_add(b6, b9);
    b9 = stwo_m31_sub(b13, b7);
    b7 = stwo_m31_mul(b27, b32);
    b13 = stwo_m31_add(b35, b7);
    b7 = 512u;
    b6 = stwo_m31_mul(b22, b7);
    b7 = stwo_m31_sub(b13, b6);
    b6 = stwo_m31_sub(b7, b21);
    b7 = stwo_m31_mul(b36, b36);
    b13 = stwo_m31_sub(b7, b36);
    b7 = 1u;
    b11 = stwo_m31_add(b0, b7);
    b7 = stwo_m31_add(b11, b8);
    b11 = stwo_m31_add(b1, b10);
    b10 = stwo_trace_value(arena, *args, 2u, 0u, row, 0);
    b8 = stwo_trace_value(arena, *args, 2u, 1u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 2u, 2u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 2u, 3u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 2u, 4u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 2u, 5u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 2u, 6u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 2u, 7u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 2u, 8u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 2u, 9u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 2u, 10u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 2u, 11u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 2u, 20u, row, -1);
    unsigned b73 = stwo_trace_value(arena, *args, 2u, 20u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 2u, 21u, row, -1);
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 21u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 22u, row, -1);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 22u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 2u, 23u, row, -1);
    unsigned b79 = stwo_trace_value(arena, *args, 2u, 23u, row, 0);
    StwoCairoQm31 e0 = { b37, b38, b38, b38 };
    StwoCairoQm31 e1 = { b39, b38, b38, b38 };
    StwoCairoQm31 e2 = { b40, b38, b38, b38 };
    StwoCairoQm31 e3 = { b41, b38, b38, b38 };
    StwoCairoQm31 e4 = { b43, b38, b38, b38 };
    StwoCairoQm31 e5 = { b44, b38, b38, b38 };
    StwoCairoQm31 e6 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e7 = { b0, b38, b38, b38 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    e6 = stwo_qm31_add(e7, e8);
    e7 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    e8 = { b3, b38, b38, b38 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    e6 = { b4, b38, b38, b38 };
    e7 = stwo_qm31_mul(e9, e6);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    e8 = { b5, b38, b38, b38 };
    e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 5u * 4u);
    e6 = { b45, b38, b38, b38 };
    e7 = stwo_qm31_mul(e9, e6);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 6u * 4u);
    e8 = { b46, b38, b38, b38 };
    e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 7u * 4u);
    e6 = stwo_qm31_sub(e8, e9);
    e9 = { b47, b38, b38, b38 };
    e8 = { b52, b38, b38, b38 };
    e7 = { b51, b38, b38, b38 };
    StwoCairoQm31 e10 = { b53, b38, b38, b38 };
    StwoCairoQm31 e11 = stwo_load_qm31(arena, args->ext_params + 8u * 4u);
    StwoCairoQm31 e12 = { b42, b38, b38, b38 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e11, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 9u * 4u);
    e11 = stwo_qm31_add(e12, e13);
    e12 = stwo_load_qm31(arena, args->ext_params + 10u * 4u);
    e13 = { b14, b38, b38, b38 };
    StwoCairoQm31 e14 = stwo_qm31_mul(e12, e13);
    e13 = stwo_qm31_add(e11, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 11u * 4u);
    e11 = stwo_qm31_sub(e13, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 12u * 4u);
    e13 = { b14, b38, b38, b38 };
    e12 = stwo_qm31_mul(e14, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 13u * 4u);
    e14 = stwo_qm31_add(e13, e12);
    e13 = stwo_load_qm31(arena, args->ext_params + 14u * 4u);
    e12 = { b15, b38, b38, b38 };
    StwoCairoQm31 e15 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 15u * 4u);
    e14 = { b16, b38, b38, b38 };
    e13 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 16u * 4u);
    e12 = { b17, b38, b38, b38 };
    e15 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 17u * 4u);
    e14 = { b18, b38, b38, b38 };
    e13 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 18u * 4u);
    e12 = { b19, b38, b38, b38 };
    e15 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 19u * 4u);
    e14 = { b20, b38, b38, b38 };
    e13 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 20u * 4u);
    e12 = { b21, b38, b38, b38 };
    e15 = stwo_qm31_mul(e13, e12);
    e12 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 21u * 4u);
    e14 = { b22, b38, b38, b38 };
    e13 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 22u * 4u);
    e12 = stwo_qm31_sub(e14, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 23u * 4u);
    e14 = { b48, b38, b38, b38 };
    e15 = stwo_qm31_mul(e13, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 24u * 4u);
    e13 = stwo_qm31_add(e14, e15);
    e14 = stwo_load_qm31(arena, args->ext_params + 25u * 4u);
    e15 = { b23, b38, b38, b38 };
    StwoCairoQm31 e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e13, e16);
    e16 = stwo_load_qm31(arena, args->ext_params + 26u * 4u);
    e13 = stwo_qm31_sub(e15, e16);
    e16 = stwo_load_qm31(arena, args->ext_params + 27u * 4u);
    e15 = { b23, b38, b38, b38 };
    e14 = stwo_qm31_mul(e16, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 28u * 4u);
    e16 = stwo_qm31_add(e15, e14);
    e15 = stwo_load_qm31(arena, args->ext_params + 29u * 4u);
    e14 = { b24, b38, b38, b38 };
    StwoCairoQm31 e17 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 30u * 4u);
    e16 = { b25, b38, b38, b38 };
    e15 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 31u * 4u);
    e14 = { b26, b38, b38, b38 };
    e17 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 32u * 4u);
    e16 = { b27, b38, b38, b38 };
    e15 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 33u * 4u);
    e14 = stwo_qm31_sub(e16, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 34u * 4u);
    e16 = { b49, b38, b38, b38 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_load_qm31(arena, args->ext_params + 35u * 4u);
    e15 = stwo_qm31_add(e16, e17);
    e16 = stwo_load_qm31(arena, args->ext_params + 36u * 4u);
    e17 = { b28, b38, b38, b38 };
    StwoCairoQm31 e18 = stwo_qm31_mul(e16, e17);
    e17 = stwo_qm31_add(e15, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 37u * 4u);
    e15 = stwo_qm31_sub(e17, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 38u * 4u);
    e17 = { b28, b38, b38, b38 };
    e16 = stwo_qm31_mul(e18, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 39u * 4u);
    e18 = stwo_qm31_add(e17, e16);
    e17 = stwo_load_qm31(arena, args->ext_params + 40u * 4u);
    e16 = { b29, b38, b38, b38 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 41u * 4u);
    e18 = { b30, b38, b38, b38 };
    e17 = stwo_qm31_mul(e19, e18);
    e18 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 42u * 4u);
    e16 = { b31, b38, b38, b38 };
    e19 = stwo_qm31_mul(e17, e16);
    e16 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 43u * 4u);
    e18 = { b32, b38, b38, b38 };
    e17 = stwo_qm31_mul(e19, e18);
    e18 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 44u * 4u);
    e16 = stwo_qm31_sub(e18, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 45u * 4u);
    e18 = { b33, b38, b38, b38 };
    e19 = stwo_qm31_mul(e17, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 46u * 4u);
    e17 = stwo_qm31_add(e18, e19);
    e18 = stwo_load_qm31(arena, args->ext_params + 47u * 4u);
    e19 = stwo_qm31_sub(e17, e18);
    e18 = { b50, b38, b38, b38 };
    e17 = stwo_load_qm31(arena, args->ext_params + 48u * 4u);
    StwoCairoQm31 e20 = { b34, b38, b38, b38 };
    StwoCairoQm31 e21 = stwo_qm31_mul(e17, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 49u * 4u);
    e17 = stwo_qm31_add(e20, e21);
    e20 = stwo_load_qm31(arena, args->ext_params + 50u * 4u);
    e21 = stwo_qm31_sub(e17, e20);
    e20 = { b12, b38, b38, b38 };
    e17 = stwo_load_qm31(arena, args->ext_params + 51u * 4u);
    StwoCairoQm31 e22 = { b35, b38, b38, b38 };
    StwoCairoQm31 e23 = stwo_qm31_mul(e17, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 52u * 4u);
    e17 = stwo_qm31_add(e22, e23);
    e22 = stwo_load_qm31(arena, args->ext_params + 53u * 4u);
    e23 = stwo_qm31_sub(e17, e22);
    e22 = { b9, b38, b38, b38 };
    e17 = { b6, b38, b38, b38 };
    StwoCairoQm31 e24 = { b13, b38, b38, b38 };
    StwoCairoQm31 e25 = stwo_load_qm31(arena, args->ext_params + 54u * 4u);
    StwoCairoQm31 e26 = { b0, b38, b38, b38 };
    StwoCairoQm31 e27 = stwo_qm31_mul(e25, e26);
    e26 = stwo_load_qm31(arena, args->ext_params + 55u * 4u);
    e25 = stwo_qm31_add(e26, e27);
    e26 = stwo_load_qm31(arena, args->ext_params + 56u * 4u);
    e27 = { b1, b38, b38, b38 };
    StwoCairoQm31 e28 = stwo_qm31_mul(e26, e27);
    e27 = stwo_qm31_add(e25, e28);
    e28 = stwo_load_qm31(arena, args->ext_params + 57u * 4u);
    e25 = { b2, b38, b38, b38 };
    e26 = stwo_qm31_mul(e28, e25);
    e25 = stwo_qm31_add(e27, e26);
    e26 = stwo_load_qm31(arena, args->ext_params + 58u * 4u);
    e27 = stwo_qm31_sub(e25, e26);
    e26 = { b36, b38, b38, b38 };
    e25 = stwo_qm31_neg(e26);
    e26 = stwo_load_qm31(arena, args->ext_params + 59u * 4u);
    e28 = { b7, b38, b38, b38 };
    StwoCairoQm31 e29 = stwo_qm31_mul(e26, e28);
    e28 = stwo_load_qm31(arena, args->ext_params + 60u * 4u);
    e26 = stwo_qm31_add(e28, e29);
    e28 = stwo_load_qm31(arena, args->ext_params + 61u * 4u);
    e29 = { b11, b38, b38, b38 };
    StwoCairoQm31 e30 = stwo_qm31_mul(e28, e29);
    e29 = stwo_qm31_add(e26, e30);
    e30 = stwo_load_qm31(arena, args->ext_params + 62u * 4u);
    e26 = { b2, b38, b38, b38 };
    e28 = stwo_qm31_mul(e30, e26);
    e26 = stwo_qm31_add(e29, e28);
    e28 = stwo_load_qm31(arena, args->ext_params + 63u * 4u);
    e29 = stwo_qm31_sub(e26, e28);
    e28 = stwo_load_qm31(arena, args->ext_params + 64u * 4u);
    e26 = stwo_qm31_mul(e11, e28);
    e28 = stwo_load_qm31(arena, args->ext_params + 65u * 4u);
    e30 = stwo_qm31_mul(e6, e28);
    e28 = stwo_qm31_add(e26, e30);
    e30 = stwo_qm31_mul(e6, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 66u * 4u);
    e6 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 67u * 4u);
    e26 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e6, e26);
    e26 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 68u * 4u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 69u * 4u);
    e6 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e6);
    e6 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 70u * 4u);
    e14 = stwo_qm31_mul(e19, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 71u * 4u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 72u * 4u);
    e16 = stwo_qm31_mul(e23, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 73u * 4u);
    e14 = stwo_qm31_mul(e21, e19);
    e19 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e21, e23);
    e23 = { b36, b38, b38, b38 };
    e21 = stwo_qm31_mul(e29, e23);
    e23 = stwo_qm31_mul(e27, e25);
    e25 = stwo_qm31_add(e21, e23);
    e23 = stwo_qm31_mul(e27, e29);
    e29 = { b10, b8, b54, b55 };
    e27 = stwo_qm31_mul(e29, e30);
    e30 = stwo_qm31_sub(e27, e28);
    e27 = { b56, b57, b58, b59 };
    e28 = stwo_qm31_sub(e27, e29);
    e29 = stwo_qm31_mul(e28, e26);
    e28 = stwo_qm31_sub(e29, e11);
    e29 = { b60, b61, b62, b63 };
    e11 = stwo_qm31_sub(e29, e27);
    e27 = stwo_qm31_mul(e11, e6);
    e11 = stwo_qm31_sub(e27, e13);
    e27 = { b64, b65, b66, b67 };
    e13 = stwo_qm31_sub(e27, e29);
    e29 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e29, e15);
    e29 = { b68, b69, b70, b71 };
    e15 = stwo_qm31_sub(e29, e27);
    e27 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e27, e19);
    e27 = { b72, b74, b76, b78 };
    e19 = { b73, b75, b77, b79 };
    e14 = stwo_qm31_sub(e19, e27);
    e19 = stwo_qm31_sub(e14, e29);
    e14 = stwo_load_qm31(arena, args->ext_params + 74u * 4u);
    e29 = stwo_qm31_add(e19, e14);
    e14 = stwo_qm31_mul(e29, e23);
    e29 = stwo_qm31_sub(e14, e25);
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
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e18, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 10u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e20, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 11u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e22, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 12u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e17, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 13u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e24, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 14u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e30, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 15u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e28, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 16u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e11, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 17u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e13, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 18u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e15, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 19u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e29, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 20u) * 4u)));
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
