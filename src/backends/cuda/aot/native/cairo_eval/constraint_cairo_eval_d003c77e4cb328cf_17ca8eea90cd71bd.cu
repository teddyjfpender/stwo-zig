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
stwo_cairo_cuda_eval_v1_d01429a86a6bb270(
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
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 8u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 10u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b35 = 0u;
    unsigned b36 = 1u;
    unsigned b37 = stwo_m31_add(b0, b36);
    b36 = stwo_m31_add(b37, b3);
    b37 = stwo_m31_add(b1, b4);
    b4 = stwo_trace_value(arena, *args, 2u, 8u, row, 0);
    b3 = stwo_trace_value(arena, *args, 2u, 9u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 2u, 10u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 11u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 16u, row, -1);
    unsigned b45 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 2u, 17u, row, -1);
    unsigned b47 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 2u, 18u, row, -1);
    unsigned b49 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 2u, 19u, row, -1);
    unsigned b51 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 82u * 4u);
    StwoCairoQm31 e1 = { b5, b35, b35, b35 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 83u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 84u * 4u);
    e2 = { b6, b35, b35, b35 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 85u * 4u);
    e0 = { b7, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 86u * 4u);
    e2 = { b8, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 87u * 4u);
    e0 = { b9, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 88u * 4u);
    e2 = { b10, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 89u * 4u);
    e0 = { b11, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 90u * 4u);
    e2 = { b12, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 91u * 4u);
    e0 = { b13, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 92u * 4u);
    e2 = { b14, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 93u * 4u);
    e0 = { b15, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 94u * 4u);
    e2 = { b16, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 95u * 4u);
    e0 = { b17, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 96u * 4u);
    e2 = { b18, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 97u * 4u);
    e0 = { b19, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 98u * 4u);
    e2 = { b20, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 99u * 4u);
    e0 = { b21, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 100u * 4u);
    e2 = { b22, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 101u * 4u);
    e0 = { b23, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 102u * 4u);
    e2 = { b24, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 103u * 4u);
    e0 = { b25, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 104u * 4u);
    e2 = { b26, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 105u * 4u);
    e0 = { b27, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 106u * 4u);
    e2 = { b28, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 107u * 4u);
    e0 = { b29, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 108u * 4u);
    e2 = { b30, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 109u * 4u);
    e0 = { b31, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 110u * 4u);
    e2 = { b32, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 111u * 4u);
    e0 = { b33, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 112u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 113u * 4u);
    e0 = { b0, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 114u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 115u * 4u);
    e3 = { b1, b35, b35, b35 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 116u * 4u);
    e1 = { b2, b35, b35, b35 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 117u * 4u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = { b34, b35, b35, b35 };
    e1 = stwo_qm31_neg(e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 118u * 4u);
    e4 = { b36, b35, b35, b35 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 119u * 4u);
    e0 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(arena, args->ext_params + 120u * 4u);
    e5 = { b37, b35, b35, b35 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e0, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 121u * 4u);
    e0 = { b2, b35, b35, b35 };
    e4 = stwo_qm31_mul(e6, e0);
    e0 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 122u * 4u);
    e5 = stwo_qm31_sub(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 129u * 4u);
    e0 = stwo_qm31_mul(e3, e4);
    e4 = { b34, b35, b35, b35 };
    e6 = stwo_qm31_mul(e2, e4);
    e4 = stwo_qm31_add(e0, e6);
    e6 = stwo_qm31_mul(e2, e3);
    e3 = { b4, b3, b38, b39 };
    e2 = { b40, b41, b42, b43 };
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_qm31_mul(e0, e6);
    e0 = stwo_qm31_sub(e3, e4);
    e3 = { b44, b46, b48, b50 };
    e4 = { b45, b47, b49, b51 };
    e6 = stwo_qm31_sub(e4, e3);
    e4 = stwo_qm31_sub(e6, e2);
    e6 = stwo_load_qm31(arena, args->ext_params + 130u * 4u);
    e2 = stwo_qm31_add(e4, e6);
    e6 = stwo_qm31_mul(e2, e5);
    e2 = stwo_qm31_sub(e6, e1);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
