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
stwo_cairo_cuda_eval_v1_b80cc8561f87e17e(
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
    unsigned b17 = 512u;
    unsigned b18 = stwo_m31_mul(b8, b17);
    b17 = stwo_m31_add(b7, b18);
    b18 = stwo_m31_sub(b17, b1);
    b17 = 0u;
    unsigned b19 = 4u;
    unsigned b20 = stwo_m31_mul(b10, b19);
    b19 = stwo_m31_add(b9, b20);
    b20 = 2048u;
    unsigned b21 = stwo_m31_mul(b11, b20);
    b20 = stwo_m31_add(b19, b21);
    b21 = stwo_m31_sub(b20, b2);
    b20 = 16u;
    b19 = stwo_m31_mul(b13, b20);
    b20 = stwo_m31_add(b12, b19);
    b19 = 8192u;
    unsigned b22 = stwo_m31_mul(b14, b19);
    b19 = stwo_m31_add(b20, b22);
    b22 = stwo_m31_sub(b19, b3);
    b19 = 128u;
    b20 = stwo_m31_mul(b9, b19);
    b19 = stwo_m31_add(b8, b20);
    b20 = 32u;
    unsigned b23 = stwo_m31_mul(b12, b20);
    b20 = stwo_m31_add(b11, b23);
    b23 = stwo_m31_add(b14, b4);
    unsigned b24 = stwo_trace_value(arena, *args, 2u, 0u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 2u, 1u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 2u, 2u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 2u, 3u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 2u, 4u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 2u, 5u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 2u, 6u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 2u, 7u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 2u, 8u, row, -1);
    unsigned b33 = stwo_trace_value(arena, *args, 2u, 8u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 2u, 9u, row, -1);
    unsigned b35 = stwo_trace_value(arena, *args, 2u, 9u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 2u, 10u, row, -1);
    unsigned b37 = stwo_trace_value(arena, *args, 2u, 10u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 2u, 11u, row, -1);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 11u, row, 0);
    StwoCairoQm31 e0 = { b18, b17, b17, b17 };
    StwoCairoQm31 e1 = { b21, b17, b17, b17 };
    StwoCairoQm31 e2 = { b22, b17, b17, b17 };
    StwoCairoQm31 e3 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e4 = { b8, b17, b17, b17 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    e3 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    e5 = { b9, b17, b17, b17 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    e3 = { b11, b17, b17, b17 };
    e4 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    e5 = stwo_qm31_sub(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 5u * 4u);
    e3 = { b12, b17, b17, b17 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 6u * 4u);
    e4 = stwo_qm31_add(e3, e6);
    e3 = stwo_load_qm31(arena, args->ext_params + 7u * 4u);
    e6 = { b14, b17, b17, b17 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e3, e6);
    e6 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 8u * 4u);
    e4 = stwo_qm31_sub(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 9u * 4u);
    e6 = { b0, b17, b17, b17 };
    e3 = stwo_qm31_mul(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 10u * 4u);
    e7 = stwo_qm31_add(e6, e3);
    e6 = stwo_load_qm31(arena, args->ext_params + 11u * 4u);
    e3 = { b15, b17, b17, b17 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 12u * 4u);
    e7 = stwo_qm31_sub(e3, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 13u * 4u);
    e3 = { b15, b17, b17, b17 };
    e6 = stwo_qm31_mul(e8, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 14u * 4u);
    e8 = stwo_qm31_add(e3, e6);
    e3 = stwo_load_qm31(arena, args->ext_params + 15u * 4u);
    e6 = { b7, b17, b17, b17 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e3, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 16u * 4u);
    e8 = { b19, b17, b17, b17 };
    e3 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 17u * 4u);
    e6 = { b10, b17, b17, b17 };
    e9 = stwo_qm31_mul(e3, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 18u * 4u);
    e8 = { b20, b17, b17, b17 };
    e3 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 19u * 4u);
    e6 = { b13, b17, b17, b17 };
    e9 = stwo_qm31_mul(e3, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 20u * 4u);
    e8 = { b23, b17, b17, b17 };
    e3 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 21u * 4u);
    e6 = { b5, b17, b17, b17 };
    e9 = stwo_qm31_mul(e3, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 22u * 4u);
    e8 = { b6, b17, b17, b17 };
    e3 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 23u * 4u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 24u * 4u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 25u * 4u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 26u * 4u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 27u * 4u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 28u * 4u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 29u * 4u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 30u * 4u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 31u * 4u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 32u * 4u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 33u * 4u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 34u * 4u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 35u * 4u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 36u * 4u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 37u * 4u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 38u * 4u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 39u * 4u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 40u * 4u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 41u * 4u);
    e6 = stwo_qm31_add(e8, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 42u * 4u);
    e8 = stwo_qm31_add(e6, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 43u * 4u);
    e6 = stwo_qm31_sub(e8, e3);
    e3 = { b16, b17, b17, b17 };
    e8 = stwo_qm31_neg(e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 44u * 4u);
    e9 = { b0, b17, b17, b17 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e3, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 45u * 4u);
    e3 = stwo_qm31_add(e9, e10);
    e9 = stwo_load_qm31(arena, args->ext_params + 46u * 4u);
    e10 = { b1, b17, b17, b17 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e3, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 47u * 4u);
    e3 = { b2, b17, b17, b17 };
    e9 = stwo_qm31_mul(e11, e3);
    e3 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 48u * 4u);
    e10 = { b3, b17, b17, b17 };
    e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e3, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 49u * 4u);
    e3 = { b4, b17, b17, b17 };
    e9 = stwo_qm31_mul(e11, e3);
    e3 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 50u * 4u);
    e10 = { b5, b17, b17, b17 };
    e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e3, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 51u * 4u);
    e3 = { b6, b17, b17, b17 };
    e9 = stwo_qm31_mul(e11, e3);
    e3 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 52u * 4u);
    e10 = stwo_qm31_sub(e3, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 53u * 4u);
    e3 = stwo_qm31_mul(e4, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 54u * 4u);
    e11 = stwo_qm31_mul(e5, e9);
    e9 = stwo_qm31_add(e3, e11);
    e11 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 55u * 4u);
    e5 = stwo_qm31_mul(e6, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 56u * 4u);
    e3 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e5, e3);
    e3 = stwo_qm31_mul(e7, e6);
    e6 = { b24, b25, b26, b27 };
    e7 = stwo_qm31_mul(e6, e11);
    e11 = stwo_qm31_sub(e7, e9);
    e7 = { b28, b29, b30, b31 };
    e9 = stwo_qm31_sub(e7, e6);
    e6 = stwo_qm31_mul(e9, e3);
    e9 = stwo_qm31_sub(e6, e4);
    e6 = { b32, b34, b36, b38 };
    e4 = { b33, b35, b37, b39 };
    e3 = stwo_qm31_sub(e4, e6);
    e4 = stwo_qm31_sub(e3, e7);
    e3 = stwo_load_qm31(arena, args->ext_params + 57u * 4u);
    e7 = stwo_qm31_add(e4, e3);
    e3 = stwo_qm31_mul(e7, e10);
    e7 = stwo_qm31_sub(e3, e8);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e11, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e9, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
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
