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
stwo_cairo_cuda_eval_v1_1f3814489c8445b9(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 144u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 156u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 157u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 158u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 159u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 160u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 161u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 162u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 163u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 164u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 165u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 166u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 167u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 168u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 169u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 170u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 171u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 172u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 173u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 174u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 175u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 176u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 177u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 178u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 179u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 180u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 181u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 623u, row, 0);
    unsigned b43 = 0u;
    unsigned b44 = stwo_m31_sub(b1, b2);
    b2 = stwo_m31_sub(b0, b4);
    b4 = 524288u;
    b0 = stwo_m31_add(b34, b4);
    b4 = 524288u;
    b34 = stwo_m31_add(b35, b4);
    b4 = 524288u;
    b35 = stwo_m31_add(b36, b4);
    b4 = 524288u;
    b36 = stwo_m31_add(b37, b4);
    b4 = 524288u;
    b37 = stwo_m31_add(b38, b4);
    b4 = 524288u;
    b38 = stwo_m31_add(b39, b4);
    b4 = 524288u;
    b39 = stwo_m31_add(b40, b4);
    b4 = 524288u;
    b40 = stwo_m31_add(b41, b4);
    b4 = stwo_m31_mul(b42, b42);
    b41 = stwo_m31_sub(b4, b42);
    b4 = stwo_trace_value(arena, *args, 2u, 0u, row, 0);
    b42 = stwo_trace_value(arena, *args, 2u, 1u, row, 0);
    b1 = stwo_trace_value(arena, *args, 2u, 2u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 2u, 3u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 2u, 4u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 2u, 5u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 2u, 6u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 2u, 7u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 2u, 8u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 2u, 9u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 2u, 10u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 2u, 11u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 2u, 20u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 2u, 21u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 2u, 22u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 23u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 24u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 25u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 26u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 27u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 2u, 28u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 2u, 29u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 2u, 30u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 2u, 31u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 2u, 32u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 33u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 34u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 35u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 2u, 36u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 2u, 37u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 2u, 38u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 2u, 39u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 2u, 40u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 41u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 42u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 2u, 43u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 44u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 2u, 45u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 2u, 46u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 2u, 47u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 2u, 48u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 2u, 49u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 2u, 50u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 2u, 51u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e1 = { b44, b43, b43, b43 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    e0 = { b3, b43, b43, b43 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 5u * 4u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 6u * 4u);
    e1 = { b2, b43, b43, b43 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 7u * 4u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(arena, args->ext_params + 8u * 4u);
    e4 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 9u * 4u);
    e0 = { b5, b43, b43, b43 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 10u * 4u);
    e1 = stwo_qm31_add(e0, e5);
    e0 = stwo_load_qm31(arena, args->ext_params + 11u * 4u);
    e5 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 12u * 4u);
    e1 = { b6, b43, b43, b43 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 13u * 4u);
    e0 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(arena, args->ext_params + 14u * 4u);
    e6 = { b7, b43, b43, b43 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e0, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 15u * 4u);
    e0 = stwo_qm31_sub(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 16u * 4u);
    e6 = { b8, b43, b43, b43 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 17u * 4u);
    e7 = stwo_qm31_add(e6, e1);
    e6 = stwo_load_qm31(arena, args->ext_params + 18u * 4u);
    e1 = { b9, b43, b43, b43 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e6, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 19u * 4u);
    e7 = stwo_qm31_sub(e1, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 20u * 4u);
    e1 = { b10, b43, b43, b43 };
    e6 = stwo_qm31_mul(e8, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 21u * 4u);
    e8 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(arena, args->ext_params + 22u * 4u);
    e6 = { b11, b43, b43, b43 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 23u * 4u);
    e8 = stwo_qm31_sub(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 24u * 4u);
    e6 = { b12, b43, b43, b43 };
    e1 = stwo_qm31_mul(e9, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 25u * 4u);
    e9 = stwo_qm31_add(e6, e1);
    e6 = stwo_load_qm31(arena, args->ext_params + 26u * 4u);
    e1 = { b13, b43, b43, b43 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e6, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 27u * 4u);
    e9 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 28u * 4u);
    e1 = { b14, b43, b43, b43 };
    e6 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 29u * 4u);
    e10 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(arena, args->ext_params + 30u * 4u);
    e6 = { b15, b43, b43, b43 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 31u * 4u);
    e10 = stwo_qm31_sub(e6, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 32u * 4u);
    e6 = { b16, b43, b43, b43 };
    e1 = stwo_qm31_mul(e11, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 33u * 4u);
    e11 = stwo_qm31_add(e6, e1);
    e6 = stwo_load_qm31(arena, args->ext_params + 34u * 4u);
    e1 = { b17, b43, b43, b43 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e6, e1);
    e1 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 35u * 4u);
    e11 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 36u * 4u);
    e1 = { b18, b43, b43, b43 };
    e6 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 37u * 4u);
    e12 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(arena, args->ext_params + 38u * 4u);
    e6 = { b19, b43, b43, b43 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 39u * 4u);
    e12 = stwo_qm31_sub(e6, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 40u * 4u);
    e6 = { b20, b43, b43, b43 };
    e1 = stwo_qm31_mul(e13, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 41u * 4u);
    e13 = stwo_qm31_add(e6, e1);
    e6 = stwo_load_qm31(arena, args->ext_params + 42u * 4u);
    e1 = { b21, b43, b43, b43 };
    StwoCairoQm31 e14 = stwo_qm31_mul(e6, e1);
    e1 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 43u * 4u);
    e13 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 44u * 4u);
    e1 = { b22, b43, b43, b43 };
    e6 = stwo_qm31_mul(e14, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 45u * 4u);
    e14 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(arena, args->ext_params + 46u * 4u);
    e6 = { b23, b43, b43, b43 };
    StwoCairoQm31 e15 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 47u * 4u);
    e14 = stwo_qm31_sub(e6, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 48u * 4u);
    e6 = { b24, b43, b43, b43 };
    e1 = stwo_qm31_mul(e15, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 49u * 4u);
    e15 = stwo_qm31_add(e6, e1);
    e6 = stwo_load_qm31(arena, args->ext_params + 50u * 4u);
    e1 = { b25, b43, b43, b43 };
    StwoCairoQm31 e16 = stwo_qm31_mul(e6, e1);
    e1 = stwo_qm31_add(e15, e16);
    e16 = stwo_load_qm31(arena, args->ext_params + 51u * 4u);
    e15 = stwo_qm31_sub(e1, e16);
    e16 = stwo_load_qm31(arena, args->ext_params + 52u * 4u);
    e1 = { b26, b43, b43, b43 };
    e6 = stwo_qm31_mul(e16, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 53u * 4u);
    e16 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(arena, args->ext_params + 54u * 4u);
    e6 = { b27, b43, b43, b43 };
    StwoCairoQm31 e17 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 55u * 4u);
    e16 = stwo_qm31_sub(e6, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 56u * 4u);
    e6 = { b28, b43, b43, b43 };
    e1 = stwo_qm31_mul(e17, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 57u * 4u);
    e17 = stwo_qm31_add(e6, e1);
    e6 = stwo_load_qm31(arena, args->ext_params + 58u * 4u);
    e1 = { b29, b43, b43, b43 };
    StwoCairoQm31 e18 = stwo_qm31_mul(e6, e1);
    e1 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 59u * 4u);
    e17 = stwo_qm31_sub(e1, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 60u * 4u);
    e1 = { b30, b43, b43, b43 };
    e6 = stwo_qm31_mul(e18, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 61u * 4u);
    e18 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(arena, args->ext_params + 62u * 4u);
    e6 = { b31, b43, b43, b43 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e1, e6);
    e6 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 63u * 4u);
    e18 = stwo_qm31_sub(e6, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 64u * 4u);
    e6 = { b32, b43, b43, b43 };
    e1 = stwo_qm31_mul(e19, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 65u * 4u);
    e19 = stwo_qm31_add(e6, e1);
    e6 = stwo_load_qm31(arena, args->ext_params + 66u * 4u);
    e1 = { b33, b43, b43, b43 };
    StwoCairoQm31 e20 = stwo_qm31_mul(e6, e1);
    e1 = stwo_qm31_add(e19, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 67u * 4u);
    e19 = stwo_qm31_sub(e1, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 68u * 4u);
    e1 = { b0, b43, b43, b43 };
    e6 = stwo_qm31_mul(e20, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 69u * 4u);
    e20 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(arena, args->ext_params + 70u * 4u);
    e6 = stwo_qm31_sub(e20, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 71u * 4u);
    e20 = { b34, b43, b43, b43 };
    StwoCairoQm31 e21 = stwo_qm31_mul(e1, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 72u * 4u);
    e1 = stwo_qm31_add(e20, e21);
    e20 = stwo_load_qm31(arena, args->ext_params + 73u * 4u);
    e21 = stwo_qm31_sub(e1, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 74u * 4u);
    e1 = { b35, b43, b43, b43 };
    StwoCairoQm31 e22 = stwo_qm31_mul(e20, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 75u * 4u);
    e20 = stwo_qm31_add(e1, e22);
    e1 = stwo_load_qm31(arena, args->ext_params + 76u * 4u);
    e22 = stwo_qm31_sub(e20, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 77u * 4u);
    e20 = { b36, b43, b43, b43 };
    StwoCairoQm31 e23 = stwo_qm31_mul(e1, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 78u * 4u);
    e1 = stwo_qm31_add(e20, e23);
    e20 = stwo_load_qm31(arena, args->ext_params + 79u * 4u);
    e23 = stwo_qm31_sub(e1, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 80u * 4u);
    e1 = { b37, b43, b43, b43 };
    StwoCairoQm31 e24 = stwo_qm31_mul(e20, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 81u * 4u);
    e20 = stwo_qm31_add(e1, e24);
    e1 = stwo_load_qm31(arena, args->ext_params + 82u * 4u);
    e24 = stwo_qm31_sub(e20, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 83u * 4u);
    e20 = { b38, b43, b43, b43 };
    StwoCairoQm31 e25 = stwo_qm31_mul(e1, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 84u * 4u);
    e1 = stwo_qm31_add(e20, e25);
    e20 = stwo_load_qm31(arena, args->ext_params + 85u * 4u);
    e25 = stwo_qm31_sub(e1, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 86u * 4u);
    e1 = { b39, b43, b43, b43 };
    StwoCairoQm31 e26 = stwo_qm31_mul(e20, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 87u * 4u);
    e20 = stwo_qm31_add(e1, e26);
    e1 = stwo_load_qm31(arena, args->ext_params + 88u * 4u);
    e26 = stwo_qm31_sub(e20, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 89u * 4u);
    e20 = { b40, b43, b43, b43 };
    StwoCairoQm31 e27 = stwo_qm31_mul(e1, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 90u * 4u);
    e1 = stwo_qm31_add(e20, e27);
    e20 = stwo_load_qm31(arena, args->ext_params + 91u * 4u);
    e27 = stwo_qm31_sub(e1, e20);
    e20 = { b41, b43, b43, b43 };
    e1 = stwo_load_qm31(arena, args->ext_params + 1302u * 4u);
    StwoCairoQm31 e28 = stwo_qm31_mul(e3, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1303u * 4u);
    StwoCairoQm31 e29 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e28, e29);
    e29 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 1304u * 4u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 1305u * 4u);
    e28 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e28);
    e28 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 1306u * 4u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 1307u * 4u);
    e2 = stwo_qm31_mul(e0, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e0, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 1308u * 4u);
    e0 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 1309u * 4u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e0, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 1310u * 4u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 1311u * 4u);
    e0 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e0);
    e0 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 1312u * 4u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 1313u * 4u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 1314u * 4u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 1315u * 4u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 1316u * 4u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 1317u * 4u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 1318u * 4u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 1319u * 4u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 1320u * 4u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 1321u * 4u);
    e16 = stwo_qm31_mul(e6, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e6, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 1322u * 4u);
    e6 = stwo_qm31_mul(e23, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 1323u * 4u);
    e18 = stwo_qm31_mul(e22, e21);
    e21 = stwo_qm31_add(e6, e18);
    e18 = stwo_qm31_mul(e22, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 1324u * 4u);
    e22 = stwo_qm31_mul(e25, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 1325u * 4u);
    e6 = stwo_qm31_mul(e24, e23);
    e23 = stwo_qm31_add(e22, e6);
    e6 = stwo_qm31_mul(e24, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 1326u * 4u);
    e24 = stwo_qm31_mul(e27, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 1327u * 4u);
    e22 = stwo_qm31_mul(e26, e25);
    e25 = stwo_qm31_add(e24, e22);
    e22 = stwo_qm31_mul(e26, e27);
    e27 = { b4, b42, b1, b45 };
    e26 = stwo_qm31_mul(e27, e29);
    e29 = stwo_qm31_sub(e26, e1);
    e26 = { b46, b47, b48, b49 };
    e1 = stwo_qm31_sub(e26, e27);
    e27 = stwo_qm31_mul(e1, e28);
    e1 = stwo_qm31_sub(e27, e3);
    e27 = { b50, b51, b52, b53 };
    e3 = stwo_qm31_sub(e27, e26);
    e26 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e26, e5);
    e26 = { b54, b55, b56, b57 };
    e5 = stwo_qm31_sub(e26, e27);
    e27 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e27, e7);
    e27 = { b58, b59, b60, b61 };
    e7 = stwo_qm31_sub(e27, e26);
    e26 = stwo_qm31_mul(e7, e0);
    e7 = stwo_qm31_sub(e26, e9);
    e26 = { b62, b63, b64, b65 };
    e9 = stwo_qm31_sub(e26, e27);
    e27 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e27, e11);
    e27 = { b66, b67, b68, b69 };
    e11 = stwo_qm31_sub(e27, e26);
    e26 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e26, e13);
    e26 = { b70, b71, b72, b73 };
    e13 = stwo_qm31_sub(e26, e27);
    e27 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e27, e15);
    e27 = { b74, b75, b76, b77 };
    e15 = stwo_qm31_sub(e27, e26);
    e26 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e26, e17);
    e26 = { b78, b79, b80, b81 };
    e17 = stwo_qm31_sub(e26, e27);
    e27 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e27, e19);
    e27 = { b82, b83, b84, b85 };
    e19 = stwo_qm31_sub(e27, e26);
    e26 = stwo_qm31_mul(e19, e18);
    e19 = stwo_qm31_sub(e26, e21);
    e26 = { b86, b87, b88, b89 };
    e21 = stwo_qm31_sub(e26, e27);
    e27 = stwo_qm31_mul(e21, e6);
    e21 = stwo_qm31_sub(e27, e23);
    e27 = { b90, b91, b92, b93 };
    e23 = stwo_qm31_sub(e27, e26);
    e27 = stwo_qm31_mul(e23, e22);
    e23 = stwo_qm31_sub(e27, e25);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e20, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e29, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e9, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e11, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e13, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 8u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e15, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 9u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e17, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 10u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e19, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 11u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e21, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 12u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e23, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 13u) * 4u)));
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
