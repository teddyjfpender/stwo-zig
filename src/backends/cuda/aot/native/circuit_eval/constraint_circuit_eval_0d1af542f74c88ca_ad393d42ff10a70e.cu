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
__device__ __forceinline__ unsigned stwo_m31_add(
    unsigned lhs, unsigned rhs) {
    const unsigned sum = lhs + rhs;
    return sum < STWO_M31_P ? sum : sum - STWO_M31_P;
}
__device__ __forceinline__ unsigned stwo_m31_sub(
    unsigned lhs, unsigned rhs) {
    return lhs >= rhs ? lhs - rhs : lhs + STWO_M31_P - rhs;
}
__device__ __forceinline__ unsigned stwo_m31_mul(
    unsigned lhs, unsigned rhs) {
    const u64 product = (u64)lhs * rhs;
    const unsigned folded = (unsigned)(product & STWO_M31_P) +
        (unsigned)(product >> 31u);
    return folded < STWO_M31_P ? folded : folded - STWO_M31_P;
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
    #if defined(STWO_CUMETAL)
    value = ((value >> 1u) & 0x55555555u) | ((value & 0x55555555u) << 1u);
    value = ((value >> 2u) & 0x33333333u) | ((value & 0x33333333u) << 2u);
    value = ((value >> 4u) & 0x0f0f0f0fu) | ((value & 0x0f0f0f0fu) << 4u);
    value = ((value >> 8u) & 0x00ff00ffu) | ((value & 0x00ff00ffu) << 8u);
    value = (value >> 16u) | (value << 16u);
    return bits == 0u ? 0u : value >> (32u - bits);
#else
    return bits == 0u ? 0u : __brev(value) >> (32u - bits);
#endif
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
    const u64 address = (u64)arena[args.trace_offsets + 2u * global] | ((u64)arena[args.trace_offsets + 2u * global + 1u] << 32u); return arena[address + target];
}
extern "C" __global__ void __launch_bounds__(256)
stwo_cairo_cuda_eval_v6_0d1af542f74c88ca(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    unsigned b0 = stwo_trace_value(arena, *args, 0u, 0u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 0u, 1u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 0u, 2u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 0u, 3u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 0u, 4u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 0u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 1u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 2u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 3u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 4u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 5u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 6u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 7u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 8u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 9u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 10u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 11u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 19u, row, 0);
    unsigned b25 = arena[args->base_params + 0u];
    unsigned b26 = stwo_m31_mul(b13, b25);
    unsigned b27 = stwo_m31_sub(b5, b26);
    unsigned b28 = arena[args->base_params + 1u];
    unsigned b29 = stwo_m31_mul(b14, b28);
    unsigned b30 = stwo_m31_sub(b6, b29);
    unsigned b31 = arena[args->base_params + 2u];
    unsigned b32 = stwo_m31_mul(b15, b31);
    unsigned b33 = stwo_m31_sub(b7, b32);
    unsigned b34 = arena[args->base_params + 3u];
    unsigned b35 = stwo_m31_mul(b16, b34);
    unsigned b36 = stwo_m31_sub(b8, b35);
    unsigned b37 = arena[args->base_params + 4u];
    unsigned b38 = stwo_m31_mul(b17, b37);
    unsigned b39 = stwo_m31_sub(b9, b38);
    unsigned b40 = arena[args->base_params + 5u];
    unsigned b41 = stwo_m31_mul(b18, b40);
    unsigned b42 = stwo_m31_sub(b10, b41);
    unsigned b43 = arena[args->base_params + 6u];
    unsigned b44 = stwo_m31_mul(b19, b43);
    unsigned b45 = stwo_m31_sub(b11, b44);
    unsigned b46 = arena[args->base_params + 7u];
    unsigned b47 = stwo_m31_mul(b20, b46);
    unsigned b48 = stwo_m31_sub(b12, b47);
    unsigned b49 = arena[args->base_params + 8u];
    unsigned b50 = stwo_trace_value(arena, *args, 2u, 0u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 2u, 1u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 2u, 2u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 2u, 3u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 2u, 4u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 2u, 5u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 2u, 6u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 2u, 7u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 2u, 8u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 2u, 9u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 2u, 10u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 2u, 11u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 2u, 20u, row, -1);
    unsigned b71 = stwo_trace_value(arena, *args, 2u, 20u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 2u, 21u, row, -1);
    unsigned b73 = stwo_trace_value(arena, *args, 2u, 21u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 2u, 22u, row, -1);
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 22u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 23u, row, -1);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 23u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e1 = { b27, b49, b49, b49 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    StwoCairoQm31 e3 = { 112558620u, 0u, 0u, 0u };
    StwoCairoQm31 e4 = stwo_qm31_add(e3, e2);
    StwoCairoQm31 e5 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e6 = { b33, b49, b49, b49 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e5, e6);
    StwoCairoQm31 e8 = stwo_qm31_add(e4, e7);
    StwoCairoQm31 e9 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e10 = { b21, b49, b49, b49 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e9, e10);
    StwoCairoQm31 e12 = stwo_qm31_add(e8, e11);
    StwoCairoQm31 e13 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e14 = stwo_qm31_sub(e12, e13);
    StwoCairoQm31 e15 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e16 = { b13, b49, b49, b49 };
    StwoCairoQm31 e17 = stwo_qm31_mul(e15, e16);
    StwoCairoQm31 e18 = { 112558620u, 0u, 0u, 0u };
    StwoCairoQm31 e19 = stwo_qm31_add(e18, e17);
    StwoCairoQm31 e20 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e21 = { b15, b49, b49, b49 };
    StwoCairoQm31 e22 = stwo_qm31_mul(e20, e21);
    StwoCairoQm31 e23 = stwo_qm31_add(e19, e22);
    StwoCairoQm31 e24 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e25 = { b22, b49, b49, b49 };
    StwoCairoQm31 e26 = stwo_qm31_mul(e24, e25);
    StwoCairoQm31 e27 = stwo_qm31_add(e23, e26);
    StwoCairoQm31 e28 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e29 = stwo_qm31_sub(e27, e28);
    StwoCairoQm31 e30 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e31 = { b30, b49, b49, b49 };
    StwoCairoQm31 e32 = stwo_qm31_mul(e30, e31);
    StwoCairoQm31 e33 = { 112558620u, 0u, 0u, 0u };
    StwoCairoQm31 e34 = stwo_qm31_add(e33, e32);
    StwoCairoQm31 e35 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e36 = { b36, b49, b49, b49 };
    StwoCairoQm31 e37 = stwo_qm31_mul(e35, e36);
    StwoCairoQm31 e38 = stwo_qm31_add(e34, e37);
    StwoCairoQm31 e39 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e40 = { b23, b49, b49, b49 };
    StwoCairoQm31 e41 = stwo_qm31_mul(e39, e40);
    StwoCairoQm31 e42 = stwo_qm31_add(e38, e41);
    StwoCairoQm31 e43 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e44 = stwo_qm31_sub(e42, e43);
    StwoCairoQm31 e45 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e46 = { b14, b49, b49, b49 };
    StwoCairoQm31 e47 = stwo_qm31_mul(e45, e46);
    StwoCairoQm31 e48 = { 112558620u, 0u, 0u, 0u };
    StwoCairoQm31 e49 = stwo_qm31_add(e48, e47);
    StwoCairoQm31 e50 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e51 = { b16, b49, b49, b49 };
    StwoCairoQm31 e52 = stwo_qm31_mul(e50, e51);
    StwoCairoQm31 e53 = stwo_qm31_add(e49, e52);
    StwoCairoQm31 e54 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e55 = { b24, b49, b49, b49 };
    StwoCairoQm31 e56 = stwo_qm31_mul(e54, e55);
    StwoCairoQm31 e57 = stwo_qm31_add(e53, e56);
    StwoCairoQm31 e58 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e59 = stwo_qm31_sub(e57, e58);
    StwoCairoQm31 e60 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e61 = { b21, b49, b49, b49 };
    StwoCairoQm31 e62 = stwo_qm31_mul(e60, e61);
    StwoCairoQm31 e63 = { 112558620u, 0u, 0u, 0u };
    StwoCairoQm31 e64 = stwo_qm31_add(e63, e62);
    StwoCairoQm31 e65 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e66 = { b39, b49, b49, b49 };
    StwoCairoQm31 e67 = stwo_qm31_mul(e65, e66);
    StwoCairoQm31 e68 = stwo_qm31_add(e64, e67);
    StwoCairoQm31 e69 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e70 = { b45, b49, b49, b49 };
    StwoCairoQm31 e71 = stwo_qm31_mul(e69, e70);
    StwoCairoQm31 e72 = stwo_qm31_add(e68, e71);
    StwoCairoQm31 e73 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e74 = stwo_qm31_sub(e72, e73);
    StwoCairoQm31 e75 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e76 = { b22, b49, b49, b49 };
    StwoCairoQm31 e77 = stwo_qm31_mul(e75, e76);
    StwoCairoQm31 e78 = { 112558620u, 0u, 0u, 0u };
    StwoCairoQm31 e79 = stwo_qm31_add(e78, e77);
    StwoCairoQm31 e80 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e81 = { b17, b49, b49, b49 };
    StwoCairoQm31 e82 = stwo_qm31_mul(e80, e81);
    StwoCairoQm31 e83 = stwo_qm31_add(e79, e82);
    StwoCairoQm31 e84 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e85 = { b19, b49, b49, b49 };
    StwoCairoQm31 e86 = stwo_qm31_mul(e84, e85);
    StwoCairoQm31 e87 = stwo_qm31_add(e83, e86);
    StwoCairoQm31 e88 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e89 = stwo_qm31_sub(e87, e88);
    StwoCairoQm31 e90 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e91 = { b23, b49, b49, b49 };
    StwoCairoQm31 e92 = stwo_qm31_mul(e90, e91);
    StwoCairoQm31 e93 = { 112558620u, 0u, 0u, 0u };
    StwoCairoQm31 e94 = stwo_qm31_add(e93, e92);
    StwoCairoQm31 e95 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e96 = { b42, b49, b49, b49 };
    StwoCairoQm31 e97 = stwo_qm31_mul(e95, e96);
    StwoCairoQm31 e98 = stwo_qm31_add(e94, e97);
    StwoCairoQm31 e99 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e100 = { b48, b49, b49, b49 };
    StwoCairoQm31 e101 = stwo_qm31_mul(e99, e100);
    StwoCairoQm31 e102 = stwo_qm31_add(e98, e101);
    StwoCairoQm31 e103 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e104 = stwo_qm31_sub(e102, e103);
    StwoCairoQm31 e105 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e106 = { b24, b49, b49, b49 };
    StwoCairoQm31 e107 = stwo_qm31_mul(e105, e106);
    StwoCairoQm31 e108 = { 112558620u, 0u, 0u, 0u };
    StwoCairoQm31 e109 = stwo_qm31_add(e108, e107);
    StwoCairoQm31 e110 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e111 = { b18, b49, b49, b49 };
    StwoCairoQm31 e112 = stwo_qm31_mul(e110, e111);
    StwoCairoQm31 e113 = stwo_qm31_add(e109, e112);
    StwoCairoQm31 e114 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e115 = { b20, b49, b49, b49 };
    StwoCairoQm31 e116 = stwo_qm31_mul(e114, e115);
    StwoCairoQm31 e117 = stwo_qm31_add(e113, e116);
    StwoCairoQm31 e118 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e119 = stwo_qm31_sub(e117, e118);
    StwoCairoQm31 e120 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e121 = { b0, b49, b49, b49 };
    StwoCairoQm31 e122 = stwo_qm31_mul(e120, e121);
    StwoCairoQm31 e123 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e124 = stwo_qm31_add(e123, e122);
    StwoCairoQm31 e125 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e126 = { b5, b49, b49, b49 };
    StwoCairoQm31 e127 = stwo_qm31_mul(e125, e126);
    StwoCairoQm31 e128 = stwo_qm31_add(e124, e127);
    StwoCairoQm31 e129 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e130 = { b6, b49, b49, b49 };
    StwoCairoQm31 e131 = stwo_qm31_mul(e129, e130);
    StwoCairoQm31 e132 = stwo_qm31_add(e128, e131);
    StwoCairoQm31 e133 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e134 = stwo_qm31_sub(e132, e133);
    StwoCairoQm31 e135 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e136 = { b1, b49, b49, b49 };
    StwoCairoQm31 e137 = stwo_qm31_mul(e135, e136);
    StwoCairoQm31 e138 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e139 = stwo_qm31_add(e138, e137);
    StwoCairoQm31 e140 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e141 = { b7, b49, b49, b49 };
    StwoCairoQm31 e142 = stwo_qm31_mul(e140, e141);
    StwoCairoQm31 e143 = stwo_qm31_add(e139, e142);
    StwoCairoQm31 e144 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e145 = { b8, b49, b49, b49 };
    StwoCairoQm31 e146 = stwo_qm31_mul(e144, e145);
    StwoCairoQm31 e147 = stwo_qm31_add(e143, e146);
    StwoCairoQm31 e148 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e149 = stwo_qm31_sub(e147, e148);
    StwoCairoQm31 e150 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e151 = { b2, b49, b49, b49 };
    StwoCairoQm31 e152 = stwo_qm31_mul(e150, e151);
    StwoCairoQm31 e153 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e154 = stwo_qm31_add(e153, e152);
    StwoCairoQm31 e155 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e156 = { b9, b49, b49, b49 };
    StwoCairoQm31 e157 = stwo_qm31_mul(e155, e156);
    StwoCairoQm31 e158 = stwo_qm31_add(e154, e157);
    StwoCairoQm31 e159 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e160 = { b10, b49, b49, b49 };
    StwoCairoQm31 e161 = stwo_qm31_mul(e159, e160);
    StwoCairoQm31 e162 = stwo_qm31_add(e158, e161);
    StwoCairoQm31 e163 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e164 = stwo_qm31_sub(e162, e163);
    StwoCairoQm31 e165 = { b4, b49, b49, b49 };
    StwoCairoQm31 e166 = stwo_qm31_neg(e165);
    StwoCairoQm31 e167 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e168 = { b3, b49, b49, b49 };
    StwoCairoQm31 e169 = stwo_qm31_mul(e167, e168);
    StwoCairoQm31 e170 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e171 = stwo_qm31_add(e170, e169);
    StwoCairoQm31 e172 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e173 = { b11, b49, b49, b49 };
    StwoCairoQm31 e174 = stwo_qm31_mul(e172, e173);
    StwoCairoQm31 e175 = stwo_qm31_add(e171, e174);
    StwoCairoQm31 e176 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e177 = { b12, b49, b49, b49 };
    StwoCairoQm31 e178 = stwo_qm31_mul(e176, e177);
    StwoCairoQm31 e179 = stwo_qm31_add(e175, e178);
    StwoCairoQm31 e180 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e181 = stwo_qm31_sub(e179, e180);
    StwoCairoQm31 e182 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e183 = e29;
    StwoCairoQm31 e184 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e185 = e14;
    StwoCairoQm31 e186 = stwo_qm31_add(e183, e185);
    StwoCairoQm31 e187 = stwo_qm31_mul(e14, e29);
    StwoCairoQm31 e188 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e189 = e59;
    StwoCairoQm31 e190 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e191 = e44;
    StwoCairoQm31 e192 = stwo_qm31_add(e189, e191);
    StwoCairoQm31 e193 = stwo_qm31_mul(e44, e59);
    StwoCairoQm31 e194 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e195 = e89;
    StwoCairoQm31 e196 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e197 = e74;
    StwoCairoQm31 e198 = stwo_qm31_add(e195, e197);
    StwoCairoQm31 e199 = stwo_qm31_mul(e74, e89);
    StwoCairoQm31 e200 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e201 = e119;
    StwoCairoQm31 e202 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e203 = e104;
    StwoCairoQm31 e204 = stwo_qm31_add(e201, e203);
    StwoCairoQm31 e205 = stwo_qm31_mul(e104, e119);
    StwoCairoQm31 e206 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e207 = e149;
    StwoCairoQm31 e208 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e209 = e134;
    StwoCairoQm31 e210 = stwo_qm31_add(e207, e209);
    StwoCairoQm31 e211 = stwo_qm31_mul(e134, e149);
    StwoCairoQm31 e212 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e213 = e181;
    StwoCairoQm31 e214 = stwo_qm31_mul(e164, e166);
    StwoCairoQm31 e215 = stwo_qm31_add(e213, e214);
    StwoCairoQm31 e216 = stwo_qm31_mul(e164, e181);
    StwoCairoQm31 e217 = { b50, b51, b52, b53 };
    StwoCairoQm31 e218 = stwo_qm31_mul(e217, e187);
    StwoCairoQm31 e219 = stwo_qm31_sub(e218, e186);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e219, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    StwoCairoQm31 e220 = { b54, b55, b56, b57 };
    StwoCairoQm31 e221 = stwo_qm31_sub(e220, e217);
    StwoCairoQm31 e222 = stwo_qm31_mul(e221, e193);
    StwoCairoQm31 e223 = stwo_qm31_sub(e222, e192);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e223, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    StwoCairoQm31 e224 = { b58, b59, b60, b61 };
    StwoCairoQm31 e225 = stwo_qm31_sub(e224, e220);
    StwoCairoQm31 e226 = stwo_qm31_mul(e225, e199);
    StwoCairoQm31 e227 = stwo_qm31_sub(e226, e198);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e227, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    StwoCairoQm31 e228 = { b62, b63, b64, b65 };
    StwoCairoQm31 e229 = stwo_qm31_sub(e228, e224);
    StwoCairoQm31 e230 = stwo_qm31_mul(e229, e205);
    StwoCairoQm31 e231 = stwo_qm31_sub(e230, e204);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e231, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    StwoCairoQm31 e232 = { b66, b67, b68, b69 };
    StwoCairoQm31 e233 = stwo_qm31_sub(e232, e228);
    StwoCairoQm31 e234 = stwo_qm31_mul(e233, e211);
    StwoCairoQm31 e235 = stwo_qm31_sub(e234, e210);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e235, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    StwoCairoQm31 e236 = { b70, b72, b74, b76 };
    StwoCairoQm31 e237 = { b71, b73, b75, b77 };
    StwoCairoQm31 e238 = stwo_qm31_sub(e237, e236);
    StwoCairoQm31 e239 = stwo_qm31_sub(e238, e232);
    StwoCairoQm31 e240 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    StwoCairoQm31 e241 = stwo_qm31_add(e239, e240);
    StwoCairoQm31 e242 = stwo_qm31_mul(e241, e216);
    StwoCairoQm31 e243 = stwo_qm31_sub(e242, e215);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e243, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
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
