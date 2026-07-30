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
stwo_cairo_cuda_eval_v1_9961ce1a5111fbec(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 2u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 3u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 4u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 5u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 6u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 7u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 8u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 9u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 19u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 25u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 41u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 42u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 43u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 47u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 48u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 49u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 51u, row, 0);
    unsigned b46 = stwo_m31_sub(b0, b8);
    b8 = 512u;
    b0 = stwo_m31_mul(b9, b8);
    b8 = stwo_m31_sub(b46, b0);
    b0 = 8192u;
    b46 = stwo_m31_mul(b8, b0);
    b0 = stwo_m31_sub(b1, b10);
    b1 = 512u;
    b8 = stwo_m31_mul(b11, b1);
    b1 = stwo_m31_sub(b0, b8);
    b8 = 8192u;
    b0 = stwo_m31_mul(b1, b8);
    b8 = stwo_m31_sub(b2, b12);
    b2 = 512u;
    b1 = stwo_m31_mul(b13, b2);
    b2 = stwo_m31_sub(b8, b1);
    b1 = 8192u;
    b8 = stwo_m31_mul(b2, b1);
    b1 = stwo_m31_sub(b3, b14);
    b3 = 512u;
    b2 = stwo_m31_mul(b15, b3);
    b3 = stwo_m31_sub(b1, b2);
    b2 = 8192u;
    b1 = stwo_m31_mul(b3, b2);
    b2 = stwo_m31_sub(b4, b16);
    b4 = 512u;
    b3 = stwo_m31_mul(b17, b4);
    b4 = stwo_m31_sub(b2, b3);
    b3 = 8192u;
    b2 = stwo_m31_mul(b4, b3);
    b3 = stwo_m31_sub(b5, b18);
    b5 = 512u;
    b4 = stwo_m31_mul(b19, b5);
    b5 = stwo_m31_sub(b3, b4);
    b4 = 8192u;
    b3 = stwo_m31_mul(b5, b4);
    b4 = stwo_m31_sub(b6, b20);
    b6 = 512u;
    b5 = stwo_m31_mul(b21, b6);
    b6 = stwo_m31_sub(b4, b5);
    b5 = 8192u;
    b4 = stwo_m31_mul(b6, b5);
    b5 = 0u;
    b6 = stwo_trace_value(arena, *args, 2u, 4u, row, 0);
    b9 = stwo_trace_value(arena, *args, 2u, 5u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 2u, 6u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 2u, 7u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 2u, 8u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 2u, 9u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 2u, 10u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 2u, 11u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 2u, 20u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 2u, 21u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 2u, 22u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 2u, 23u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 24u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 25u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 26u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 27u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 28u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 2u, 29u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 2u, 30u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 2u, 31u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 2u, 32u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 2u, 33u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 34u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 35u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 36u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 2u, 37u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 2u, 38u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 2u, 39u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 2u, 40u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 2u, 41u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 42u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 43u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 2u, 44u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 45u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 2u, 46u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 2u, 47u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 2u, 48u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 2u, 49u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 2u, 50u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 2u, 51u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 16u * 4u);
    StwoCairoQm31 e1 = { b46, b5, b5, b5 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 17u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 18u * 4u);
    e2 = { b10, b5, b5, b5 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 19u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 20u * 4u);
    e2 = { b11, b5, b5, b5 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 21u * 4u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 22u * 4u);
    e1 = { b0, b5, b5, b5 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 23u * 4u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 24u * 4u);
    e1 = { b12, b5, b5, b5 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 25u * 4u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 26u * 4u);
    e2 = { b13, b5, b5, b5 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 27u * 4u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 28u * 4u);
    e2 = { b8, b5, b5, b5 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 29u * 4u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 30u * 4u);
    e1 = { b14, b5, b5, b5 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 31u * 4u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 32u * 4u);
    e1 = { b15, b5, b5, b5 };
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 33u * 4u);
    e6 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 34u * 4u);
    e2 = { b1, b5, b5, b5 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 35u * 4u);
    e6 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 36u * 4u);
    e2 = { b16, b5, b5, b5 };
    e1 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 37u * 4u);
    e7 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 38u * 4u);
    e1 = { b17, b5, b5, b5 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 39u * 4u);
    e7 = stwo_qm31_sub(e1, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 40u * 4u);
    e1 = { b2, b5, b5, b5 };
    e2 = stwo_qm31_mul(e8, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 41u * 4u);
    e8 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 42u * 4u);
    e2 = { b18, b5, b5, b5 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 43u * 4u);
    e8 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 44u * 4u);
    e2 = { b19, b5, b5, b5 };
    e1 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 45u * 4u);
    e9 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 46u * 4u);
    e1 = { b3, b5, b5, b5 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 47u * 4u);
    e9 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 48u * 4u);
    e1 = { b20, b5, b5, b5 };
    e2 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 49u * 4u);
    e10 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 50u * 4u);
    e2 = { b21, b5, b5, b5 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 51u * 4u);
    e10 = stwo_qm31_sub(e2, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 52u * 4u);
    e2 = { b4, b5, b5, b5 };
    e1 = stwo_qm31_mul(e11, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 53u * 4u);
    e11 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 54u * 4u);
    e1 = { b7, b5, b5, b5 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 55u * 4u);
    e11 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 56u * 4u);
    e1 = { b22, b5, b5, b5 };
    e2 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 57u * 4u);
    e12 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 58u * 4u);
    e2 = { b23, b5, b5, b5 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 59u * 4u);
    e12 = stwo_qm31_sub(e2, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 60u * 4u);
    e2 = { b24, b5, b5, b5 };
    e1 = stwo_qm31_mul(e13, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 61u * 4u);
    e13 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 62u * 4u);
    e1 = { b25, b5, b5, b5 };
    StwoCairoQm31 e14 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 63u * 4u);
    e13 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 64u * 4u);
    e1 = { b26, b5, b5, b5 };
    e2 = stwo_qm31_mul(e14, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 65u * 4u);
    e14 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 66u * 4u);
    e2 = { b27, b5, b5, b5 };
    StwoCairoQm31 e15 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 67u * 4u);
    e14 = stwo_qm31_sub(e2, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 68u * 4u);
    e2 = { b28, b5, b5, b5 };
    e1 = stwo_qm31_mul(e15, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 69u * 4u);
    e15 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 70u * 4u);
    e1 = { b29, b5, b5, b5 };
    StwoCairoQm31 e16 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e15, e16);
    e16 = stwo_load_qm31(arena, args->ext_params + 71u * 4u);
    e15 = stwo_qm31_sub(e1, e16);
    e16 = stwo_load_qm31(arena, args->ext_params + 72u * 4u);
    e1 = { b30, b5, b5, b5 };
    e2 = stwo_qm31_mul(e16, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 73u * 4u);
    e16 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 74u * 4u);
    e2 = { b31, b5, b5, b5 };
    StwoCairoQm31 e17 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 75u * 4u);
    e16 = stwo_qm31_sub(e2, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 76u * 4u);
    e2 = { b32, b5, b5, b5 };
    e1 = stwo_qm31_mul(e17, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 77u * 4u);
    e17 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 78u * 4u);
    e1 = { b33, b5, b5, b5 };
    StwoCairoQm31 e18 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 79u * 4u);
    e17 = stwo_qm31_sub(e1, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 80u * 4u);
    e1 = { b34, b5, b5, b5 };
    e2 = stwo_qm31_mul(e18, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 81u * 4u);
    e18 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 82u * 4u);
    e2 = { b35, b5, b5, b5 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 83u * 4u);
    e18 = stwo_qm31_sub(e2, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 84u * 4u);
    e2 = { b36, b5, b5, b5 };
    e1 = stwo_qm31_mul(e19, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 85u * 4u);
    e19 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 86u * 4u);
    e1 = { b37, b5, b5, b5 };
    StwoCairoQm31 e20 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e19, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 87u * 4u);
    e19 = stwo_qm31_sub(e1, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 88u * 4u);
    e1 = { b38, b5, b5, b5 };
    e2 = stwo_qm31_mul(e20, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 89u * 4u);
    e20 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 90u * 4u);
    e2 = { b39, b5, b5, b5 };
    StwoCairoQm31 e21 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e20, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 91u * 4u);
    e20 = stwo_qm31_sub(e2, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 92u * 4u);
    e2 = { b40, b5, b5, b5 };
    e1 = stwo_qm31_mul(e21, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 93u * 4u);
    e21 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 94u * 4u);
    e1 = { b41, b5, b5, b5 };
    StwoCairoQm31 e22 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e21, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 95u * 4u);
    e21 = stwo_qm31_sub(e1, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 96u * 4u);
    e1 = { b42, b5, b5, b5 };
    e2 = stwo_qm31_mul(e22, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 97u * 4u);
    e22 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 98u * 4u);
    e2 = { b43, b5, b5, b5 };
    StwoCairoQm31 e23 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e22, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 99u * 4u);
    e22 = stwo_qm31_sub(e2, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 100u * 4u);
    e2 = { b44, b5, b5, b5 };
    e1 = stwo_qm31_mul(e23, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 101u * 4u);
    e23 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 102u * 4u);
    e1 = { b45, b5, b5, b5 };
    StwoCairoQm31 e24 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e23, e24);
    e24 = stwo_load_qm31(arena, args->ext_params + 103u * 4u);
    e23 = stwo_qm31_sub(e1, e24);
    e24 = stwo_load_qm31(arena, args->ext_params + 362u * 4u);
    e1 = stwo_qm31_mul(e3, e24);
    e24 = stwo_load_qm31(arena, args->ext_params + 363u * 4u);
    e2 = stwo_qm31_mul(e0, e24);
    e24 = stwo_qm31_add(e1, e2);
    e2 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 364u * 4u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 365u * 4u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 366u * 4u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 367u * 4u);
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 368u * 4u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 369u * 4u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 370u * 4u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 371u * 4u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 372u * 4u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 373u * 4u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 374u * 4u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 375u * 4u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 376u * 4u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 377u * 4u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 378u * 4u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 379u * 4u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 380u * 4u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 381u * 4u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e20, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 382u * 4u);
    e20 = stwo_qm31_mul(e23, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 383u * 4u);
    e18 = stwo_qm31_mul(e22, e21);
    e21 = stwo_qm31_add(e20, e18);
    e18 = stwo_qm31_mul(e22, e23);
    e23 = { b6, b9, b47, b48 };
    e22 = { b49, b50, b51, b52 };
    e20 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e20, e2);
    e20 = stwo_qm31_sub(e23, e24);
    e23 = { b53, b54, b55, b56 };
    e24 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e24, e1);
    e24 = stwo_qm31_sub(e22, e3);
    e22 = { b57, b58, b59, b60 };
    e3 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e23, e5);
    e23 = { b61, b62, b63, b64 };
    e5 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e22, e7);
    e22 = { b65, b66, b67, b68 };
    e7 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e23, e9);
    e23 = { b69, b70, b71, b72 };
    e9 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e22, e11);
    e22 = { b73, b74, b75, b76 };
    e11 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e23, e13);
    e23 = { b77, b78, b79, b80 };
    e13 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e22, e15);
    e22 = { b81, b82, b83, b84 };
    e15 = stwo_qm31_sub(e22, e23);
    e23 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e23, e17);
    e23 = { b85, b86, b87, b88 };
    e17 = stwo_qm31_sub(e23, e22);
    e22 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e22, e19);
    e22 = { b89, b90, b91, b92 };
    e19 = stwo_qm31_sub(e22, e23);
    e22 = stwo_qm31_mul(e19, e18);
    e19 = stwo_qm31_sub(e22, e21);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e20, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e24, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e9, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e11, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e13, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e15, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 8u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e17, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 9u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e19, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 10u) * 4u)));
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
