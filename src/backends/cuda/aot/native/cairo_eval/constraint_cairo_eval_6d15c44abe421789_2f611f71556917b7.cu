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
stwo_cairo_cuda_eval_v1_f0493ead71fe40fc(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 0u, 0u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 0u, 1u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 0u, 2u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 0u, 3u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 0u, 4u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 0u, 5u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 0u, 6u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 0u, 7u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 0u, 8u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 0u, 9u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 0u, 10u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 0u, 11u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 0u, 12u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 0u, 13u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 0u, 14u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 0u, 15u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 0u, 16u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 0u, 17u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 0u, 18u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 0u, 19u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 0u, 20u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 0u, 21u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 0u, 22u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 0u, 23u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 0u, 24u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 0u, 25u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 0u, 26u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 0u, 27u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 0u, 28u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 0u, 29u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 0u, 30u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 0u, 31u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 0u, 32u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 0u, 33u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 0u, 34u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 0u, 35u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 0u, 36u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 0u, 37u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 0u, 38u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 0u, 39u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 0u, 40u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 0u, 41u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 0u, 42u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 0u, 43u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 0u, 44u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 0u, 45u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 0u, 46u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 0u, 47u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 0u, 48u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 0u, 49u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 0u, 50u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 0u, 51u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 0u, 52u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 0u, 53u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 0u, 54u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 0u, 55u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 0u, 56u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 0u, row, 0);
    unsigned b58 = 0u;
    unsigned b59 = stwo_trace_value(arena, *args, 2u, 0u, row, -1);
    unsigned b60 = stwo_trace_value(arena, *args, 2u, 0u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 2u, 1u, row, -1);
    unsigned b62 = stwo_trace_value(arena, *args, 2u, 1u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 2u, 2u, row, -1);
    unsigned b64 = stwo_trace_value(arena, *args, 2u, 2u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 3u, row, -1);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 3u, row, 0);
    StwoCairoQm31 e0 = { b57, b58, b58, b58 };
    StwoCairoQm31 e1 = stwo_qm31_neg(e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e2 = { b0, b58, b58, b58 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    e0 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    e3 = { b1, b58, b58, b58 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    e0 = { b2, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    e3 = { b3, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 5u * 4u);
    e0 = { b4, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 6u * 4u);
    e3 = { b5, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 7u * 4u);
    e0 = { b6, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 8u * 4u);
    e3 = { b7, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 9u * 4u);
    e0 = { b8, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 10u * 4u);
    e3 = { b9, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 11u * 4u);
    e0 = { b10, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 12u * 4u);
    e3 = { b11, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 13u * 4u);
    e0 = { b12, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 14u * 4u);
    e3 = { b13, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 15u * 4u);
    e0 = { b14, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 16u * 4u);
    e3 = { b15, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 17u * 4u);
    e0 = { b16, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 18u * 4u);
    e3 = { b17, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 19u * 4u);
    e0 = { b18, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 20u * 4u);
    e3 = { b19, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 21u * 4u);
    e0 = { b20, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 22u * 4u);
    e3 = { b21, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 23u * 4u);
    e0 = { b22, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 24u * 4u);
    e3 = { b23, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 25u * 4u);
    e0 = { b24, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 26u * 4u);
    e3 = { b25, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 27u * 4u);
    e0 = { b26, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 28u * 4u);
    e3 = { b27, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 29u * 4u);
    e0 = { b28, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 30u * 4u);
    e3 = { b29, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 31u * 4u);
    e0 = { b30, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 32u * 4u);
    e3 = { b31, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 33u * 4u);
    e0 = { b32, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 34u * 4u);
    e3 = { b33, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 35u * 4u);
    e0 = { b34, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 36u * 4u);
    e3 = { b35, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 37u * 4u);
    e0 = { b36, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 38u * 4u);
    e3 = { b37, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 39u * 4u);
    e0 = { b38, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 40u * 4u);
    e3 = { b39, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 41u * 4u);
    e0 = { b40, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 42u * 4u);
    e3 = { b41, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 43u * 4u);
    e0 = { b42, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 44u * 4u);
    e3 = { b43, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 45u * 4u);
    e0 = { b44, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 46u * 4u);
    e3 = { b45, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 47u * 4u);
    e0 = { b46, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 48u * 4u);
    e3 = { b47, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 49u * 4u);
    e0 = { b48, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 50u * 4u);
    e3 = { b49, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 51u * 4u);
    e0 = { b50, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 52u * 4u);
    e3 = { b51, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 53u * 4u);
    e0 = { b52, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 54u * 4u);
    e3 = { b53, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 55u * 4u);
    e0 = { b54, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 56u * 4u);
    e3 = { b55, b58, b58, b58 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 57u * 4u);
    e0 = { b56, b58, b58, b58 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 58u * 4u);
    e3 = stwo_qm31_sub(e0, e2);
    e2 = { b59, b61, b63, b65 };
    e0 = { b60, b62, b64, b66 };
    e4 = stwo_qm31_sub(e0, e2);
    e0 = stwo_load_qm31(arena, args->ext_params + 59u * 4u);
    e2 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e2, e3);
    e2 = stwo_qm31_sub(e0, e1);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
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
