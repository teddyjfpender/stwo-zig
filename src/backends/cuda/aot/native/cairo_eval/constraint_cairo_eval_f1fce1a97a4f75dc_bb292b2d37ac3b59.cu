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
stwo_cairo_cuda_eval_v1_f7cb1b29ef4abdeb(
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
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 0u, row, 0);
    unsigned b4 = 0u;
    unsigned b5 = stwo_m31_add(b0, b4);
    unsigned b6 = 0u;
    unsigned b7 = stwo_m31_add(b1, b6);
    b6 = 0u;
    unsigned b8 = stwo_m31_add(b2, b6);
    b6 = stwo_trace_value(arena, *args, 1u, 1u, row, 0);
    unsigned b9 = 0u;
    unsigned b10 = stwo_m31_add(b0, b9);
    b9 = 1024u;
    unsigned b11 = stwo_m31_add(b1, b9);
    b9 = 1024u;
    unsigned b12 = stwo_m31_add(b2, b9);
    b9 = stwo_trace_value(arena, *args, 1u, 2u, row, 0);
    unsigned b13 = 0u;
    unsigned b14 = stwo_m31_add(b0, b13);
    b13 = 2048u;
    unsigned b15 = stwo_m31_add(b1, b13);
    b13 = 2048u;
    unsigned b16 = stwo_m31_add(b2, b13);
    b13 = stwo_trace_value(arena, *args, 1u, 3u, row, 0);
    unsigned b17 = 0u;
    unsigned b18 = stwo_m31_add(b0, b17);
    b17 = 3072u;
    unsigned b19 = stwo_m31_add(b1, b17);
    b17 = 3072u;
    unsigned b20 = stwo_m31_add(b2, b17);
    b17 = stwo_trace_value(arena, *args, 1u, 4u, row, 0);
    unsigned b21 = 1024u;
    unsigned b22 = stwo_m31_add(b0, b21);
    b21 = 0u;
    unsigned b23 = stwo_m31_add(b1, b21);
    b21 = 1024u;
    unsigned b24 = stwo_m31_add(b2, b21);
    b21 = stwo_trace_value(arena, *args, 1u, 5u, row, 0);
    unsigned b25 = 1024u;
    unsigned b26 = stwo_m31_add(b0, b25);
    b25 = 1024u;
    unsigned b27 = stwo_m31_add(b1, b25);
    b25 = 0u;
    unsigned b28 = stwo_m31_add(b2, b25);
    b25 = stwo_trace_value(arena, *args, 1u, 6u, row, 0);
    unsigned b29 = 1024u;
    unsigned b30 = stwo_m31_add(b0, b29);
    b29 = 2048u;
    unsigned b31 = stwo_m31_add(b1, b29);
    b29 = 3072u;
    unsigned b32 = stwo_m31_add(b2, b29);
    b29 = stwo_trace_value(arena, *args, 1u, 7u, row, 0);
    unsigned b33 = 1024u;
    unsigned b34 = stwo_m31_add(b0, b33);
    b33 = 3072u;
    unsigned b35 = stwo_m31_add(b1, b33);
    b33 = 2048u;
    unsigned b36 = stwo_m31_add(b2, b33);
    b33 = stwo_trace_value(arena, *args, 1u, 8u, row, 0);
    unsigned b37 = 2048u;
    unsigned b38 = stwo_m31_add(b0, b37);
    b37 = 0u;
    unsigned b39 = stwo_m31_add(b1, b37);
    b37 = 2048u;
    unsigned b40 = stwo_m31_add(b2, b37);
    b37 = stwo_trace_value(arena, *args, 1u, 9u, row, 0);
    unsigned b41 = 2048u;
    unsigned b42 = stwo_m31_add(b0, b41);
    b41 = 1024u;
    unsigned b43 = stwo_m31_add(b1, b41);
    b41 = 3072u;
    unsigned b44 = stwo_m31_add(b2, b41);
    b41 = stwo_trace_value(arena, *args, 1u, 10u, row, 0);
    unsigned b45 = 2048u;
    unsigned b46 = stwo_m31_add(b0, b45);
    b45 = 2048u;
    unsigned b47 = stwo_m31_add(b1, b45);
    b45 = 0u;
    unsigned b48 = stwo_m31_add(b2, b45);
    b45 = stwo_trace_value(arena, *args, 1u, 11u, row, 0);
    unsigned b49 = 2048u;
    unsigned b50 = stwo_m31_add(b0, b49);
    b49 = 3072u;
    unsigned b51 = stwo_m31_add(b1, b49);
    b49 = 1024u;
    unsigned b52 = stwo_m31_add(b2, b49);
    b49 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b53 = 3072u;
    unsigned b54 = stwo_m31_add(b0, b53);
    b53 = 0u;
    unsigned b55 = stwo_m31_add(b1, b53);
    b53 = 3072u;
    unsigned b56 = stwo_m31_add(b2, b53);
    b53 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b57 = 3072u;
    unsigned b58 = stwo_m31_add(b0, b57);
    b57 = 1024u;
    unsigned b59 = stwo_m31_add(b1, b57);
    b57 = 2048u;
    unsigned b60 = stwo_m31_add(b2, b57);
    b57 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b61 = 3072u;
    unsigned b62 = stwo_m31_add(b0, b61);
    b61 = 2048u;
    unsigned b63 = stwo_m31_add(b1, b61);
    b61 = 1024u;
    unsigned b64 = stwo_m31_add(b2, b61);
    b61 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b65 = 3072u;
    unsigned b66 = stwo_m31_add(b0, b65);
    b65 = 3072u;
    b0 = stwo_m31_add(b1, b65);
    b65 = 0u;
    b1 = stwo_m31_add(b2, b65);
    b65 = stwo_trace_value(arena, *args, 2u, 0u, row, 0);
    b2 = stwo_trace_value(arena, *args, 2u, 1u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 2u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 3u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 4u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 2u, 5u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 2u, 6u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 2u, 7u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 2u, 8u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 2u, 9u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 10u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 11u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 2u, 20u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 21u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 2u, 22u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 2u, 23u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 2u, 24u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 2u, 25u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 2u, 26u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 2u, 27u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 2u, 28u, row, -1);
    unsigned b94 = stwo_trace_value(arena, *args, 2u, 28u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 2u, 29u, row, -1);
    unsigned b96 = stwo_trace_value(arena, *args, 2u, 29u, row, 0);
    unsigned b97 = stwo_trace_value(arena, *args, 2u, 30u, row, -1);
    unsigned b98 = stwo_trace_value(arena, *args, 2u, 30u, row, 0);
    unsigned b99 = stwo_trace_value(arena, *args, 2u, 31u, row, -1);
    unsigned b100 = stwo_trace_value(arena, *args, 2u, 31u, row, 0);
    StwoCairoQm31 e0 = { b3, b4, b4, b4 };
    StwoCairoQm31 e1 = stwo_qm31_neg(e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e2 = { b5, b4, b4, b4 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    e0 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    e3 = { b7, b4, b4, b4 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    e0 = { b8, b4, b4, b4 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    e3 = stwo_qm31_sub(e0, e2);
    e2 = { b6, b4, b4, b4 };
    e0 = stwo_qm31_neg(e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 5u * 4u);
    e4 = { b10, b4, b4, b4 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e2, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 6u * 4u);
    e2 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(arena, args->ext_params + 7u * 4u);
    e5 = { b11, b4, b4, b4 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 8u * 4u);
    e2 = { b12, b4, b4, b4 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 9u * 4u);
    e5 = stwo_qm31_sub(e2, e4);
    e4 = { b9, b4, b4, b4 };
    e2 = stwo_qm31_neg(e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 10u * 4u);
    e6 = { b14, b4, b4, b4 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e4, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 11u * 4u);
    e4 = stwo_qm31_add(e6, e7);
    e6 = stwo_load_qm31(arena, args->ext_params + 12u * 4u);
    e7 = { b15, b4, b4, b4 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e4, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 13u * 4u);
    e4 = { b16, b4, b4, b4 };
    e6 = stwo_qm31_mul(e8, e4);
    e4 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 14u * 4u);
    e7 = stwo_qm31_sub(e4, e6);
    e6 = { b13, b4, b4, b4 };
    e4 = stwo_qm31_neg(e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 15u * 4u);
    e8 = { b18, b4, b4, b4 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e6, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 16u * 4u);
    e6 = stwo_qm31_add(e8, e9);
    e8 = stwo_load_qm31(arena, args->ext_params + 17u * 4u);
    e9 = { b19, b4, b4, b4 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e6, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 18u * 4u);
    e6 = { b20, b4, b4, b4 };
    e8 = stwo_qm31_mul(e10, e6);
    e6 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 19u * 4u);
    e9 = stwo_qm31_sub(e6, e8);
    e8 = { b17, b4, b4, b4 };
    e6 = stwo_qm31_neg(e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 20u * 4u);
    e10 = { b22, b4, b4, b4 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e8, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 21u * 4u);
    e8 = stwo_qm31_add(e10, e11);
    e10 = stwo_load_qm31(arena, args->ext_params + 22u * 4u);
    e11 = { b23, b4, b4, b4 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e10, e11);
    e11 = stwo_qm31_add(e8, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 23u * 4u);
    e8 = { b24, b4, b4, b4 };
    e10 = stwo_qm31_mul(e12, e8);
    e8 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 24u * 4u);
    e11 = stwo_qm31_sub(e8, e10);
    e10 = { b21, b4, b4, b4 };
    e8 = stwo_qm31_neg(e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 25u * 4u);
    e12 = { b26, b4, b4, b4 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e10, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 26u * 4u);
    e10 = stwo_qm31_add(e12, e13);
    e12 = stwo_load_qm31(arena, args->ext_params + 27u * 4u);
    e13 = { b27, b4, b4, b4 };
    StwoCairoQm31 e14 = stwo_qm31_mul(e12, e13);
    e13 = stwo_qm31_add(e10, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 28u * 4u);
    e10 = { b28, b4, b4, b4 };
    e12 = stwo_qm31_mul(e14, e10);
    e10 = stwo_qm31_add(e13, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 29u * 4u);
    e13 = stwo_qm31_sub(e10, e12);
    e12 = { b25, b4, b4, b4 };
    e10 = stwo_qm31_neg(e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 30u * 4u);
    e14 = { b30, b4, b4, b4 };
    StwoCairoQm31 e15 = stwo_qm31_mul(e12, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 31u * 4u);
    e12 = stwo_qm31_add(e14, e15);
    e14 = stwo_load_qm31(arena, args->ext_params + 32u * 4u);
    e15 = { b31, b4, b4, b4 };
    StwoCairoQm31 e16 = stwo_qm31_mul(e14, e15);
    e15 = stwo_qm31_add(e12, e16);
    e16 = stwo_load_qm31(arena, args->ext_params + 33u * 4u);
    e12 = { b32, b4, b4, b4 };
    e14 = stwo_qm31_mul(e16, e12);
    e12 = stwo_qm31_add(e15, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 34u * 4u);
    e15 = stwo_qm31_sub(e12, e14);
    e14 = { b29, b4, b4, b4 };
    e12 = stwo_qm31_neg(e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 35u * 4u);
    e16 = { b34, b4, b4, b4 };
    StwoCairoQm31 e17 = stwo_qm31_mul(e14, e16);
    e16 = stwo_load_qm31(arena, args->ext_params + 36u * 4u);
    e14 = stwo_qm31_add(e16, e17);
    e16 = stwo_load_qm31(arena, args->ext_params + 37u * 4u);
    e17 = { b35, b4, b4, b4 };
    StwoCairoQm31 e18 = stwo_qm31_mul(e16, e17);
    e17 = stwo_qm31_add(e14, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 38u * 4u);
    e14 = { b36, b4, b4, b4 };
    e16 = stwo_qm31_mul(e18, e14);
    e14 = stwo_qm31_add(e17, e16);
    e16 = stwo_load_qm31(arena, args->ext_params + 39u * 4u);
    e17 = stwo_qm31_sub(e14, e16);
    e16 = { b33, b4, b4, b4 };
    e14 = stwo_qm31_neg(e16);
    e16 = stwo_load_qm31(arena, args->ext_params + 40u * 4u);
    e18 = { b38, b4, b4, b4 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e16, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 41u * 4u);
    e16 = stwo_qm31_add(e18, e19);
    e18 = stwo_load_qm31(arena, args->ext_params + 42u * 4u);
    e19 = { b39, b4, b4, b4 };
    StwoCairoQm31 e20 = stwo_qm31_mul(e18, e19);
    e19 = stwo_qm31_add(e16, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 43u * 4u);
    e16 = { b40, b4, b4, b4 };
    e18 = stwo_qm31_mul(e20, e16);
    e16 = stwo_qm31_add(e19, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 44u * 4u);
    e19 = stwo_qm31_sub(e16, e18);
    e18 = { b37, b4, b4, b4 };
    e16 = stwo_qm31_neg(e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 45u * 4u);
    e20 = { b42, b4, b4, b4 };
    StwoCairoQm31 e21 = stwo_qm31_mul(e18, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 46u * 4u);
    e18 = stwo_qm31_add(e20, e21);
    e20 = stwo_load_qm31(arena, args->ext_params + 47u * 4u);
    e21 = { b43, b4, b4, b4 };
    StwoCairoQm31 e22 = stwo_qm31_mul(e20, e21);
    e21 = stwo_qm31_add(e18, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 48u * 4u);
    e18 = { b44, b4, b4, b4 };
    e20 = stwo_qm31_mul(e22, e18);
    e18 = stwo_qm31_add(e21, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 49u * 4u);
    e21 = stwo_qm31_sub(e18, e20);
    e20 = { b41, b4, b4, b4 };
    e18 = stwo_qm31_neg(e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 50u * 4u);
    e22 = { b46, b4, b4, b4 };
    StwoCairoQm31 e23 = stwo_qm31_mul(e20, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 51u * 4u);
    e20 = stwo_qm31_add(e22, e23);
    e22 = stwo_load_qm31(arena, args->ext_params + 52u * 4u);
    e23 = { b47, b4, b4, b4 };
    StwoCairoQm31 e24 = stwo_qm31_mul(e22, e23);
    e23 = stwo_qm31_add(e20, e24);
    e24 = stwo_load_qm31(arena, args->ext_params + 53u * 4u);
    e20 = { b48, b4, b4, b4 };
    e22 = stwo_qm31_mul(e24, e20);
    e20 = stwo_qm31_add(e23, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 54u * 4u);
    e23 = stwo_qm31_sub(e20, e22);
    e22 = { b45, b4, b4, b4 };
    e20 = stwo_qm31_neg(e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 55u * 4u);
    e24 = { b50, b4, b4, b4 };
    StwoCairoQm31 e25 = stwo_qm31_mul(e22, e24);
    e24 = stwo_load_qm31(arena, args->ext_params + 56u * 4u);
    e22 = stwo_qm31_add(e24, e25);
    e24 = stwo_load_qm31(arena, args->ext_params + 57u * 4u);
    e25 = { b51, b4, b4, b4 };
    StwoCairoQm31 e26 = stwo_qm31_mul(e24, e25);
    e25 = stwo_qm31_add(e22, e26);
    e26 = stwo_load_qm31(arena, args->ext_params + 58u * 4u);
    e22 = { b52, b4, b4, b4 };
    e24 = stwo_qm31_mul(e26, e22);
    e22 = stwo_qm31_add(e25, e24);
    e24 = stwo_load_qm31(arena, args->ext_params + 59u * 4u);
    e25 = stwo_qm31_sub(e22, e24);
    e24 = { b49, b4, b4, b4 };
    e22 = stwo_qm31_neg(e24);
    e24 = stwo_load_qm31(arena, args->ext_params + 60u * 4u);
    e26 = { b54, b4, b4, b4 };
    StwoCairoQm31 e27 = stwo_qm31_mul(e24, e26);
    e26 = stwo_load_qm31(arena, args->ext_params + 61u * 4u);
    e24 = stwo_qm31_add(e26, e27);
    e26 = stwo_load_qm31(arena, args->ext_params + 62u * 4u);
    e27 = { b55, b4, b4, b4 };
    StwoCairoQm31 e28 = stwo_qm31_mul(e26, e27);
    e27 = stwo_qm31_add(e24, e28);
    e28 = stwo_load_qm31(arena, args->ext_params + 63u * 4u);
    e24 = { b56, b4, b4, b4 };
    e26 = stwo_qm31_mul(e28, e24);
    e24 = stwo_qm31_add(e27, e26);
    e26 = stwo_load_qm31(arena, args->ext_params + 64u * 4u);
    e27 = stwo_qm31_sub(e24, e26);
    e26 = { b53, b4, b4, b4 };
    e24 = stwo_qm31_neg(e26);
    e26 = stwo_load_qm31(arena, args->ext_params + 65u * 4u);
    e28 = { b58, b4, b4, b4 };
    StwoCairoQm31 e29 = stwo_qm31_mul(e26, e28);
    e28 = stwo_load_qm31(arena, args->ext_params + 66u * 4u);
    e26 = stwo_qm31_add(e28, e29);
    e28 = stwo_load_qm31(arena, args->ext_params + 67u * 4u);
    e29 = { b59, b4, b4, b4 };
    StwoCairoQm31 e30 = stwo_qm31_mul(e28, e29);
    e29 = stwo_qm31_add(e26, e30);
    e30 = stwo_load_qm31(arena, args->ext_params + 68u * 4u);
    e26 = { b60, b4, b4, b4 };
    e28 = stwo_qm31_mul(e30, e26);
    e26 = stwo_qm31_add(e29, e28);
    e28 = stwo_load_qm31(arena, args->ext_params + 69u * 4u);
    e29 = stwo_qm31_sub(e26, e28);
    e28 = { b57, b4, b4, b4 };
    e26 = stwo_qm31_neg(e28);
    e28 = stwo_load_qm31(arena, args->ext_params + 70u * 4u);
    e30 = { b62, b4, b4, b4 };
    StwoCairoQm31 e31 = stwo_qm31_mul(e28, e30);
    e30 = stwo_load_qm31(arena, args->ext_params + 71u * 4u);
    e28 = stwo_qm31_add(e30, e31);
    e30 = stwo_load_qm31(arena, args->ext_params + 72u * 4u);
    e31 = { b63, b4, b4, b4 };
    StwoCairoQm31 e32 = stwo_qm31_mul(e30, e31);
    e31 = stwo_qm31_add(e28, e32);
    e32 = stwo_load_qm31(arena, args->ext_params + 73u * 4u);
    e28 = { b64, b4, b4, b4 };
    e30 = stwo_qm31_mul(e32, e28);
    e28 = stwo_qm31_add(e31, e30);
    e30 = stwo_load_qm31(arena, args->ext_params + 74u * 4u);
    e31 = stwo_qm31_sub(e28, e30);
    e30 = { b61, b4, b4, b4 };
    e28 = stwo_qm31_neg(e30);
    e30 = stwo_load_qm31(arena, args->ext_params + 75u * 4u);
    e32 = { b66, b4, b4, b4 };
    StwoCairoQm31 e33 = stwo_qm31_mul(e30, e32);
    e32 = stwo_load_qm31(arena, args->ext_params + 76u * 4u);
    e30 = stwo_qm31_add(e32, e33);
    e32 = stwo_load_qm31(arena, args->ext_params + 77u * 4u);
    e33 = { b0, b4, b4, b4 };
    StwoCairoQm31 e34 = stwo_qm31_mul(e32, e33);
    e33 = stwo_qm31_add(e30, e34);
    e34 = stwo_load_qm31(arena, args->ext_params + 78u * 4u);
    e30 = { b1, b4, b4, b4 };
    e32 = stwo_qm31_mul(e34, e30);
    e30 = stwo_qm31_add(e33, e32);
    e32 = stwo_load_qm31(arena, args->ext_params + 79u * 4u);
    e33 = stwo_qm31_sub(e30, e32);
    e32 = stwo_qm31_mul(e5, e1);
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e32, e1);
    e1 = stwo_qm31_mul(e3, e5);
    e5 = stwo_qm31_mul(e9, e2);
    e2 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e5, e2);
    e2 = stwo_qm31_mul(e7, e9);
    e9 = stwo_qm31_mul(e13, e6);
    e6 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e9, e6);
    e6 = stwo_qm31_mul(e11, e13);
    e13 = stwo_qm31_mul(e17, e10);
    e10 = stwo_qm31_mul(e15, e12);
    e12 = stwo_qm31_add(e13, e10);
    e10 = stwo_qm31_mul(e15, e17);
    e17 = stwo_qm31_mul(e21, e14);
    e14 = stwo_qm31_mul(e19, e16);
    e16 = stwo_qm31_add(e17, e14);
    e14 = stwo_qm31_mul(e19, e21);
    e21 = stwo_qm31_mul(e25, e18);
    e18 = stwo_qm31_mul(e23, e20);
    e20 = stwo_qm31_add(e21, e18);
    e18 = stwo_qm31_mul(e23, e25);
    e25 = stwo_qm31_mul(e29, e22);
    e22 = stwo_qm31_mul(e27, e24);
    e24 = stwo_qm31_add(e25, e22);
    e22 = stwo_qm31_mul(e27, e29);
    e29 = stwo_qm31_mul(e33, e26);
    e26 = stwo_qm31_mul(e31, e28);
    e28 = stwo_qm31_add(e29, e26);
    e26 = stwo_qm31_mul(e31, e33);
    e33 = { b65, b2, b67, b68 };
    e31 = stwo_qm31_mul(e33, e1);
    e1 = stwo_qm31_sub(e31, e0);
    e31 = { b69, b70, b71, b72 };
    e0 = stwo_qm31_sub(e31, e33);
    e33 = stwo_qm31_mul(e0, e2);
    e0 = stwo_qm31_sub(e33, e4);
    e33 = { b73, b74, b75, b76 };
    e4 = stwo_qm31_sub(e33, e31);
    e31 = stwo_qm31_mul(e4, e6);
    e4 = stwo_qm31_sub(e31, e8);
    e31 = { b77, b78, b79, b80 };
    e8 = stwo_qm31_sub(e31, e33);
    e33 = stwo_qm31_mul(e8, e10);
    e8 = stwo_qm31_sub(e33, e12);
    e33 = { b81, b82, b83, b84 };
    e12 = stwo_qm31_sub(e33, e31);
    e31 = stwo_qm31_mul(e12, e14);
    e12 = stwo_qm31_sub(e31, e16);
    e31 = { b85, b86, b87, b88 };
    e16 = stwo_qm31_sub(e31, e33);
    e33 = stwo_qm31_mul(e16, e18);
    e16 = stwo_qm31_sub(e33, e20);
    e33 = { b89, b90, b91, b92 };
    e20 = stwo_qm31_sub(e33, e31);
    e31 = stwo_qm31_mul(e20, e22);
    e20 = stwo_qm31_sub(e31, e24);
    e31 = { b93, b95, b97, b99 };
    e24 = { b94, b96, b98, b100 };
    e22 = stwo_qm31_sub(e24, e31);
    e24 = stwo_qm31_sub(e22, e33);
    e22 = stwo_load_qm31(arena, args->ext_params + 80u * 4u);
    e33 = stwo_qm31_add(e24, e22);
    e22 = stwo_qm31_mul(e33, e26);
    e33 = stwo_qm31_sub(e22, e28);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e4, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e8, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e12, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e16, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e20, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e33, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
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
