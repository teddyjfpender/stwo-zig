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
stwo_cairo_cuda_eval_v1_5958dc9162ea27e4(
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
    unsigned b47 = 1u;
    unsigned b48 = stwo_m31_sub(b47, b4);
    b47 = stwo_m31_mul(b4, b48);
    b48 = 0u;
    unsigned b49 = 1u;
    unsigned b50 = stwo_m31_sub(b49, b5);
    b49 = stwo_m31_mul(b5, b50);
    b50 = 8u;
    unsigned b51 = stwo_m31_mul(b4, b50);
    b50 = 16u;
    unsigned b52 = stwo_m31_add(b51, b50);
    b50 = 32u;
    b51 = stwo_m31_add(b52, b50);
    b50 = 32u;
    b52 = stwo_m31_mul(b5, b50);
    b50 = 8u;
    b5 = stwo_m31_add(b50, b52);
    b50 = 32768u;
    b52 = stwo_m31_sub(b3, b50);
    b50 = stwo_m31_mul(b4, b2);
    unsigned b53 = 1u;
    unsigned b54 = stwo_m31_sub(b53, b4);
    b53 = stwo_m31_mul(b54, b1);
    b54 = stwo_m31_add(b50, b53);
    b53 = stwo_m31_sub(b6, b54);
    b54 = stwo_m31_add(b6, b52);
    b52 = stwo_m31_add(b9, b10);
    b6 = stwo_m31_add(b52, b11);
    b52 = stwo_m31_add(b6, b12);
    b6 = stwo_m31_add(b52, b13);
    b52 = stwo_m31_add(b6, b14);
    b6 = stwo_m31_add(b52, b15);
    b52 = stwo_m31_add(b6, b16);
    b6 = stwo_m31_add(b52, b17);
    b52 = stwo_m31_add(b6, b18);
    b6 = stwo_m31_add(b52, b19);
    b52 = stwo_m31_add(b6, b20);
    b6 = stwo_m31_add(b52, b21);
    b52 = stwo_m31_add(b6, b22);
    b6 = stwo_m31_add(b52, b23);
    b52 = stwo_m31_add(b6, b24);
    b6 = stwo_m31_add(b52, b25);
    b52 = stwo_m31_add(b6, b26);
    b6 = stwo_m31_add(b52, b27);
    b52 = stwo_m31_add(b6, b28);
    b6 = stwo_m31_add(b52, b30);
    b52 = stwo_m31_add(b6, b31);
    b6 = stwo_m31_add(b52, b32);
    b52 = stwo_m31_add(b6, b33);
    b6 = stwo_m31_add(b52, b34);
    b52 = stwo_m31_add(b8, b29);
    b50 = stwo_m31_add(b52, b35);
    b52 = stwo_m31_add(b6, b50);
    b50 = stwo_m31_mul(b52, b36);
    b52 = 1u;
    b36 = stwo_m31_sub(b50, b52);
    b52 = 1u;
    b50 = stwo_m31_sub(b8, b52);
    b52 = 136u;
    b4 = stwo_m31_sub(b29, b52);
    b52 = 256u;
    unsigned b55 = stwo_m31_sub(b35, b52);
    b52 = stwo_m31_mul(b50, b50);
    b50 = stwo_m31_mul(b4, b4);
    b4 = stwo_m31_add(b52, b50);
    b50 = stwo_m31_mul(b55, b55);
    b55 = stwo_m31_add(b4, b50);
    b50 = stwo_m31_add(b6, b55);
    b55 = stwo_m31_mul(b50, b37);
    b50 = 1u;
    b37 = stwo_m31_sub(b55, b50);
    b50 = 1u;
    b55 = stwo_m31_add(b0, b50);
    b50 = 1u;
    b6 = stwo_m31_sub(b39, b50);
    b50 = stwo_m31_mul(b39, b6);
    b6 = 1u;
    b4 = stwo_m31_sub(b40, b6);
    b6 = stwo_m31_mul(b40, b4);
    b4 = 1u;
    b52 = stwo_m31_sub(b39, b4);
    b4 = stwo_m31_mul(b40, b52);
    b52 = 508u;
    unsigned b56 = stwo_m31_mul(b40, b52);
    b52 = 511u;
    unsigned b57 = stwo_m31_mul(b40, b52);
    b52 = 136u;
    unsigned b58 = stwo_m31_mul(b39, b52);
    b52 = stwo_m31_sub(b58, b40);
    b58 = 256u;
    b40 = stwo_m31_mul(b39, b58);
    b58 = 1u;
    b39 = stwo_m31_sub(b58, b45);
    b58 = stwo_m31_mul(b45, b39);
    b39 = 1u;
    unsigned b59 = stwo_m31_mul(b58, b39);
    b39 = 2u;
    b58 = stwo_m31_mul(b45, b39);
    b39 = stwo_m31_sub(b44, b58);
    b58 = 1u;
    b45 = stwo_m31_sub(b58, b39);
    b58 = stwo_m31_mul(b39, b45);
    b45 = 1u;
    b39 = stwo_m31_mul(b58, b45);
    b45 = stwo_m31_add(b44, b56);
    b56 = stwo_m31_mul(b46, b46);
    b44 = stwo_m31_sub(b56, b46);
    b56 = stwo_trace_value(arena, *args, 2u, 0u, row, 0);
    b58 = stwo_trace_value(arena, *args, 2u, 1u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 2u, 2u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 2u, 3u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 2u, 4u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 2u, 5u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 2u, 6u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 7u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 8u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 9u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 10u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 11u, row, 0);
    StwoCairoQm31 e0 = { b47, b48, b48, b48 };
    StwoCairoQm31 e1 = { b49, b48, b48, b48 };
    StwoCairoQm31 e2 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e3 = { b0, b48, b48, b48 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    e2 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    e4 = { b3, b48, b48, b48 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 5u * 4u);
    e2 = { b51, b48, b48, b48 };
    e3 = stwo_qm31_mul(e5, e2);
    e2 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 6u * 4u);
    e4 = { b5, b48, b48, b48 };
    e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 7u * 4u);
    e2 = stwo_qm31_sub(e4, e5);
    e5 = { b53, b48, b48, b48 };
    e4 = stwo_load_qm31(arena, args->ext_params + 8u * 4u);
    e3 = { b54, b48, b48, b48 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 9u * 4u);
    e4 = stwo_qm31_add(e3, e6);
    e3 = stwo_load_qm31(arena, args->ext_params + 10u * 4u);
    e6 = { b7, b48, b48, b48 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e3, e6);
    e6 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 11u * 4u);
    e4 = stwo_qm31_sub(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 12u * 4u);
    e6 = { b7, b48, b48, b48 };
    e3 = stwo_qm31_mul(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 13u * 4u);
    e7 = stwo_qm31_add(e6, e3);
    e6 = stwo_load_qm31(arena, args->ext_params + 14u * 4u);
    e3 = { b8, b48, b48, b48 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 15u * 4u);
    e7 = { b9, b48, b48, b48 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 16u * 4u);
    e3 = { b10, b48, b48, b48 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 17u * 4u);
    e7 = { b11, b48, b48, b48 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 18u * 4u);
    e3 = { b12, b48, b48, b48 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 19u * 4u);
    e7 = { b13, b48, b48, b48 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 20u * 4u);
    e3 = { b14, b48, b48, b48 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 21u * 4u);
    e7 = { b15, b48, b48, b48 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 22u * 4u);
    e3 = { b16, b48, b48, b48 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 23u * 4u);
    e7 = { b17, b48, b48, b48 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 24u * 4u);
    e3 = { b18, b48, b48, b48 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 25u * 4u);
    e7 = { b19, b48, b48, b48 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 26u * 4u);
    e3 = { b20, b48, b48, b48 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 27u * 4u);
    e7 = { b21, b48, b48, b48 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 28u * 4u);
    e3 = { b22, b48, b48, b48 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 29u * 4u);
    e7 = { b23, b48, b48, b48 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 30u * 4u);
    e3 = { b24, b48, b48, b48 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 31u * 4u);
    e7 = { b25, b48, b48, b48 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 32u * 4u);
    e3 = { b26, b48, b48, b48 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 33u * 4u);
    e7 = { b27, b48, b48, b48 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 34u * 4u);
    e3 = { b28, b48, b48, b48 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 35u * 4u);
    e7 = { b29, b48, b48, b48 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 36u * 4u);
    e3 = { b30, b48, b48, b48 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 37u * 4u);
    e7 = { b31, b48, b48, b48 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 38u * 4u);
    e3 = { b32, b48, b48, b48 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 39u * 4u);
    e7 = { b33, b48, b48, b48 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 40u * 4u);
    e3 = { b34, b48, b48, b48 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 41u * 4u);
    e7 = { b35, b48, b48, b48 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 42u * 4u);
    e3 = stwo_qm31_sub(e7, e6);
    e6 = { b36, b48, b48, b48 };
    e7 = { b37, b48, b48, b48 };
    e8 = stwo_load_qm31(arena, args->ext_params + 43u * 4u);
    StwoCairoQm31 e9 = { b55, b48, b48, b48 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 44u * 4u);
    e8 = stwo_qm31_add(e9, e10);
    e9 = stwo_load_qm31(arena, args->ext_params + 45u * 4u);
    e10 = { b38, b48, b48, b48 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 46u * 4u);
    e8 = stwo_qm31_sub(e10, e11);
    e11 = { b50, b48, b48, b48 };
    e10 = { b6, b48, b48, b48 };
    e9 = { b4, b48, b48, b48 };
    StwoCairoQm31 e12 = { b59, b48, b48, b48 };
    StwoCairoQm31 e13 = { b39, b48, b48, b48 };
    StwoCairoQm31 e14 = stwo_load_qm31(arena, args->ext_params + 47u * 4u);
    StwoCairoQm31 e15 = { b38, b48, b48, b48 };
    StwoCairoQm31 e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 48u * 4u);
    e14 = stwo_qm31_add(e15, e16);
    e15 = stwo_load_qm31(arena, args->ext_params + 49u * 4u);
    e16 = { b41, b48, b48, b48 };
    StwoCairoQm31 e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 50u * 4u);
    e14 = { b42, b48, b48, b48 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 51u * 4u);
    e16 = { b43, b48, b48, b48 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 52u * 4u);
    e14 = { b45, b48, b48, b48 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 53u * 4u);
    e16 = { b57, b48, b48, b48 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 54u * 4u);
    e14 = { b57, b48, b48, b48 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 55u * 4u);
    e16 = { b57, b48, b48, b48 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 56u * 4u);
    e14 = { b57, b48, b48, b48 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 57u * 4u);
    e16 = { b57, b48, b48, b48 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 58u * 4u);
    e14 = { b57, b48, b48, b48 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 59u * 4u);
    e16 = { b57, b48, b48, b48 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 60u * 4u);
    e14 = { b57, b48, b48, b48 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 61u * 4u);
    e16 = { b57, b48, b48, b48 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 62u * 4u);
    e14 = { b57, b48, b48, b48 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 63u * 4u);
    e16 = { b57, b48, b48, b48 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 64u * 4u);
    e14 = { b57, b48, b48, b48 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 65u * 4u);
    e16 = { b57, b48, b48, b48 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 66u * 4u);
    e14 = { b57, b48, b48, b48 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 67u * 4u);
    e16 = { b57, b48, b48, b48 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 68u * 4u);
    e14 = { b57, b48, b48, b48 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 69u * 4u);
    e16 = { b57, b48, b48, b48 };
    e17 = stwo_qm31_mul(e15, e16);
    e16 = stwo_qm31_add(e14, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 70u * 4u);
    e14 = { b52, b48, b48, b48 };
    e15 = stwo_qm31_mul(e17, e14);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 71u * 4u);
    e16 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 72u * 4u);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 73u * 4u);
    e16 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 74u * 4u);
    e14 = stwo_qm31_add(e16, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 75u * 4u);
    e16 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 76u * 4u);
    e14 = { b40, b48, b48, b48 };
    e17 = stwo_qm31_mul(e15, e14);
    e14 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 77u * 4u);
    e16 = stwo_qm31_sub(e14, e17);
    e17 = { b44, b48, b48, b48 };
    e14 = stwo_load_qm31(arena, args->ext_params + 78u * 4u);
    e15 = { b0, b48, b48, b48 };
    StwoCairoQm31 e18 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 79u * 4u);
    e14 = stwo_qm31_add(e15, e18);
    e15 = stwo_load_qm31(arena, args->ext_params + 80u * 4u);
    e18 = { b1, b48, b48, b48 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e15, e18);
    e18 = stwo_qm31_add(e14, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 81u * 4u);
    e14 = { b2, b48, b48, b48 };
    e15 = stwo_qm31_mul(e19, e14);
    e14 = stwo_qm31_add(e18, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 82u * 4u);
    e18 = stwo_qm31_sub(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 88u * 4u);
    e14 = stwo_qm31_mul(e4, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 89u * 4u);
    e19 = stwo_qm31_mul(e2, e15);
    e15 = stwo_qm31_add(e14, e19);
    e19 = stwo_qm31_mul(e2, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 90u * 4u);
    e2 = stwo_qm31_mul(e8, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 91u * 4u);
    e14 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e14);
    e14 = stwo_qm31_mul(e3, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 92u * 4u);
    e3 = stwo_qm31_mul(e18, e8);
    e8 = { b46, b48, b48, b48 };
    e2 = stwo_qm31_mul(e16, e8);
    e8 = stwo_qm31_add(e3, e2);
    e2 = stwo_qm31_mul(e16, e18);
    e18 = { b56, b58, b60, b61 };
    e16 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_sub(e16, e15);
    e16 = { b62, b63, b64, b65 };
    e15 = stwo_qm31_sub(e16, e18);
    e18 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e18, e4);
    e18 = { b66, b67, b68, b69 };
    e4 = stwo_qm31_sub(e18, e16);
    e18 = stwo_qm31_mul(e4, e2);
    e4 = stwo_qm31_sub(e18, e8);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e6, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e11, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e10, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e9, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e12, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 8u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e13, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 9u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e17, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 10u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e19, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 11u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e15, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 12u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e4, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 13u) * 4u)));
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
