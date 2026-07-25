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
stwo_cairo_cuda_eval_v1_11efcf3da2e1ba22(
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
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 5u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 8u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 10u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 25u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b22 = 0u;
    unsigned b23 = 32768u;
    unsigned b24 = stwo_m31_sub(b3, b23);
    b23 = 508u;
    b3 = stwo_m31_mul(b9, b23);
    b23 = 511u;
    unsigned b25 = stwo_m31_mul(b9, b23);
    b23 = 136u;
    unsigned b26 = stwo_m31_mul(b8, b23);
    b23 = stwo_m31_sub(b26, b9);
    b26 = 256u;
    b9 = stwo_m31_mul(b8, b26);
    b26 = stwo_m31_add(b13, b3);
    b3 = stwo_m31_add(b6, b24);
    b24 = 508u;
    b6 = stwo_m31_mul(b16, b24);
    b24 = 511u;
    b13 = stwo_m31_mul(b16, b24);
    b24 = 136u;
    b8 = stwo_m31_mul(b15, b24);
    b24 = stwo_m31_sub(b8, b16);
    b8 = 256u;
    b16 = stwo_m31_mul(b15, b8);
    b8 = stwo_m31_add(b20, b6);
    b6 = 1u;
    b20 = stwo_m31_add(b0, b6);
    b6 = stwo_m31_add(b20, b4);
    b20 = stwo_m31_add(b1, b5);
    b5 = stwo_trace_value(arena, *args, 2u, 4u, row, 0);
    b4 = stwo_trace_value(arena, *args, 2u, 5u, row, 0);
    b15 = stwo_trace_value(arena, *args, 2u, 6u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 2u, 7u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 2u, 8u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 2u, 9u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 2u, 10u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 2u, 11u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 2u, 16u, row, -1);
    unsigned b37 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 2u, 17u, row, -1);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 18u, row, -1);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 19u, row, -1);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 47u * 4u);
    StwoCairoQm31 e1 = { b7, b22, b22, b22 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 48u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 49u * 4u);
    e2 = { b10, b22, b22, b22 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 50u * 4u);
    e0 = { b11, b22, b22, b22 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 51u * 4u);
    e2 = { b12, b22, b22, b22 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 52u * 4u);
    e0 = { b26, b22, b22, b22 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 53u * 4u);
    e2 = { b25, b22, b22, b22 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 54u * 4u);
    e0 = { b25, b22, b22, b22 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 55u * 4u);
    e2 = { b25, b22, b22, b22 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 56u * 4u);
    e0 = { b25, b22, b22, b22 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 57u * 4u);
    e2 = { b25, b22, b22, b22 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 58u * 4u);
    e0 = { b25, b22, b22, b22 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 59u * 4u);
    e2 = { b25, b22, b22, b22 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 60u * 4u);
    e0 = { b25, b22, b22, b22 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 61u * 4u);
    e2 = { b25, b22, b22, b22 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 62u * 4u);
    e0 = { b25, b22, b22, b22 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 63u * 4u);
    e2 = { b25, b22, b22, b22 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 64u * 4u);
    e0 = { b25, b22, b22, b22 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 65u * 4u);
    e2 = { b25, b22, b22, b22 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 66u * 4u);
    e0 = { b25, b22, b22, b22 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 67u * 4u);
    e2 = { b25, b22, b22, b22 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 68u * 4u);
    e0 = { b25, b22, b22, b22 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 69u * 4u);
    e2 = { b25, b22, b22, b22 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 70u * 4u);
    e0 = { b23, b22, b22, b22 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 71u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 72u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 73u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 74u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 75u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 76u * 4u);
    e0 = { b9, b22, b22, b22 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 77u * 4u);
    e2 = stwo_qm31_sub(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 78u * 4u);
    e0 = { b3, b22, b22, b22 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 79u * 4u);
    e3 = stwo_qm31_add(e0, e1);
    e0 = stwo_load_qm31(arena, args->ext_params + 80u * 4u);
    e1 = { b14, b22, b22, b22 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 81u * 4u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 82u * 4u);
    e1 = { b14, b22, b22, b22 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 83u * 4u);
    e4 = stwo_qm31_add(e1, e0);
    e1 = stwo_load_qm31(arena, args->ext_params + 84u * 4u);
    e0 = { b17, b22, b22, b22 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 85u * 4u);
    e4 = { b18, b22, b22, b22 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 86u * 4u);
    e0 = { b19, b22, b22, b22 };
    e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 87u * 4u);
    e4 = { b8, b22, b22, b22 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 88u * 4u);
    e0 = { b13, b22, b22, b22 };
    e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 89u * 4u);
    e4 = { b13, b22, b22, b22 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 90u * 4u);
    e0 = { b13, b22, b22, b22 };
    e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 91u * 4u);
    e4 = { b13, b22, b22, b22 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 92u * 4u);
    e0 = { b13, b22, b22, b22 };
    e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 93u * 4u);
    e4 = { b13, b22, b22, b22 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 94u * 4u);
    e0 = { b13, b22, b22, b22 };
    e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 95u * 4u);
    e4 = { b13, b22, b22, b22 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 96u * 4u);
    e0 = { b13, b22, b22, b22 };
    e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 97u * 4u);
    e4 = { b13, b22, b22, b22 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 98u * 4u);
    e0 = { b13, b22, b22, b22 };
    e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 99u * 4u);
    e4 = { b13, b22, b22, b22 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 100u * 4u);
    e0 = { b13, b22, b22, b22 };
    e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 101u * 4u);
    e4 = { b13, b22, b22, b22 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 102u * 4u);
    e0 = { b13, b22, b22, b22 };
    e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 103u * 4u);
    e4 = { b13, b22, b22, b22 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 104u * 4u);
    e0 = { b13, b22, b22, b22 };
    e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 105u * 4u);
    e4 = { b24, b22, b22, b22 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 106u * 4u);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 107u * 4u);
    e4 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 108u * 4u);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 109u * 4u);
    e4 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 110u * 4u);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 111u * 4u);
    e4 = { b16, b22, b22, b22 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 112u * 4u);
    e0 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 113u * 4u);
    e4 = { b0, b22, b22, b22 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 114u * 4u);
    e5 = stwo_qm31_add(e4, e1);
    e4 = stwo_load_qm31(arena, args->ext_params + 115u * 4u);
    e1 = { b1, b22, b22, b22 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 116u * 4u);
    e5 = { b2, b22, b22, b22 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 117u * 4u);
    e1 = stwo_qm31_sub(e5, e4);
    e4 = { b21, b22, b22, b22 };
    e5 = stwo_qm31_neg(e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 118u * 4u);
    e6 = { b6, b22, b22, b22 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e4, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 119u * 4u);
    e4 = stwo_qm31_add(e6, e7);
    e6 = stwo_load_qm31(arena, args->ext_params + 120u * 4u);
    e7 = { b20, b22, b22, b22 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e4, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 121u * 4u);
    e4 = { b2, b22, b22, b22 };
    e6 = stwo_qm31_mul(e8, e4);
    e4 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 122u * 4u);
    e7 = stwo_qm31_sub(e4, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 127u * 4u);
    e4 = stwo_qm31_mul(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 128u * 4u);
    e8 = stwo_qm31_mul(e2, e6);
    e6 = stwo_qm31_add(e4, e8);
    e8 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 129u * 4u);
    e2 = stwo_qm31_mul(e1, e3);
    e3 = { b21, b22, b22, b22 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e2, e4);
    e4 = stwo_qm31_mul(e0, e1);
    e1 = { b5, b4, b15, b27 };
    e0 = { b28, b29, b30, b31 };
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_qm31_mul(e2, e8);
    e2 = stwo_qm31_sub(e1, e6);
    e1 = { b32, b33, b34, b35 };
    e6 = stwo_qm31_sub(e1, e0);
    e0 = stwo_qm31_mul(e6, e4);
    e6 = stwo_qm31_sub(e0, e3);
    e0 = { b36, b38, b40, b42 };
    e3 = { b37, b39, b41, b43 };
    e4 = stwo_qm31_sub(e3, e0);
    e3 = stwo_qm31_sub(e4, e1);
    e4 = stwo_load_qm31(arena, args->ext_params + 130u * 4u);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_qm31_mul(e1, e7);
    e1 = stwo_qm31_sub(e4, e5);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e6, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
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
