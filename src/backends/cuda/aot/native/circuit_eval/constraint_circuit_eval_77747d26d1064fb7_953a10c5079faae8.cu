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
stwo_cairo_cuda_eval_v6_77747d26d1064fb7(
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
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 0u, row, 0);
    unsigned b4 = arena[args->base_params + 0u];
    unsigned b5 = stwo_m31_add(b0, b4);
    unsigned b6 = arena[args->base_params + 1u];
    unsigned b7 = stwo_m31_add(b1, b6);
    unsigned b8 = arena[args->base_params + 2u];
    unsigned b9 = stwo_m31_add(b2, b8);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 1u, row, 0);
    unsigned b11 = arena[args->base_params + 3u];
    unsigned b12 = stwo_m31_add(b0, b11);
    unsigned b13 = arena[args->base_params + 4u];
    unsigned b14 = stwo_m31_add(b1, b13);
    unsigned b15 = arena[args->base_params + 5u];
    unsigned b16 = stwo_m31_add(b2, b15);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 2u, row, 0);
    unsigned b18 = arena[args->base_params + 6u];
    unsigned b19 = stwo_m31_add(b0, b18);
    unsigned b20 = arena[args->base_params + 7u];
    unsigned b21 = stwo_m31_add(b1, b20);
    unsigned b22 = arena[args->base_params + 8u];
    unsigned b23 = stwo_m31_add(b2, b22);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 3u, row, 0);
    unsigned b25 = arena[args->base_params + 9u];
    unsigned b26 = stwo_m31_add(b0, b25);
    unsigned b27 = arena[args->base_params + 10u];
    unsigned b28 = stwo_m31_add(b1, b27);
    unsigned b29 = arena[args->base_params + 11u];
    unsigned b30 = stwo_m31_add(b2, b29);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 4u, row, 0);
    unsigned b32 = arena[args->base_params + 12u];
    unsigned b33 = stwo_m31_add(b0, b32);
    unsigned b34 = arena[args->base_params + 13u];
    unsigned b35 = stwo_m31_add(b1, b34);
    unsigned b36 = arena[args->base_params + 14u];
    unsigned b37 = stwo_m31_add(b2, b36);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 5u, row, 0);
    unsigned b39 = arena[args->base_params + 15u];
    unsigned b40 = stwo_m31_add(b0, b39);
    unsigned b41 = arena[args->base_params + 16u];
    unsigned b42 = stwo_m31_add(b1, b41);
    unsigned b43 = arena[args->base_params + 17u];
    unsigned b44 = stwo_m31_add(b2, b43);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 6u, row, 0);
    unsigned b46 = arena[args->base_params + 18u];
    unsigned b47 = stwo_m31_add(b0, b46);
    unsigned b48 = arena[args->base_params + 19u];
    unsigned b49 = stwo_m31_add(b1, b48);
    unsigned b50 = arena[args->base_params + 20u];
    unsigned b51 = stwo_m31_add(b2, b50);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 7u, row, 0);
    unsigned b53 = arena[args->base_params + 21u];
    unsigned b54 = stwo_m31_add(b0, b53);
    unsigned b55 = arena[args->base_params + 22u];
    unsigned b56 = stwo_m31_add(b1, b55);
    unsigned b57 = arena[args->base_params + 23u];
    unsigned b58 = stwo_m31_add(b2, b57);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 8u, row, 0);
    unsigned b60 = arena[args->base_params + 24u];
    unsigned b61 = stwo_m31_add(b0, b60);
    unsigned b62 = arena[args->base_params + 25u];
    unsigned b63 = stwo_m31_add(b1, b62);
    unsigned b64 = arena[args->base_params + 26u];
    unsigned b65 = stwo_m31_add(b2, b64);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 9u, row, 0);
    unsigned b67 = arena[args->base_params + 27u];
    unsigned b68 = stwo_m31_add(b0, b67);
    unsigned b69 = arena[args->base_params + 28u];
    unsigned b70 = stwo_m31_add(b1, b69);
    unsigned b71 = arena[args->base_params + 29u];
    unsigned b72 = stwo_m31_add(b2, b71);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 10u, row, 0);
    unsigned b74 = arena[args->base_params + 30u];
    unsigned b75 = stwo_m31_add(b0, b74);
    unsigned b76 = arena[args->base_params + 31u];
    unsigned b77 = stwo_m31_add(b1, b76);
    unsigned b78 = arena[args->base_params + 32u];
    unsigned b79 = stwo_m31_add(b2, b78);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 11u, row, 0);
    unsigned b81 = arena[args->base_params + 33u];
    unsigned b82 = stwo_m31_add(b0, b81);
    unsigned b83 = arena[args->base_params + 34u];
    unsigned b84 = stwo_m31_add(b1, b83);
    unsigned b85 = arena[args->base_params + 35u];
    unsigned b86 = stwo_m31_add(b2, b85);
    unsigned b87 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b88 = arena[args->base_params + 36u];
    unsigned b89 = stwo_m31_add(b0, b88);
    unsigned b90 = arena[args->base_params + 37u];
    unsigned b91 = stwo_m31_add(b1, b90);
    unsigned b92 = arena[args->base_params + 38u];
    unsigned b93 = stwo_m31_add(b2, b92);
    unsigned b94 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b95 = arena[args->base_params + 39u];
    unsigned b96 = stwo_m31_add(b0, b95);
    unsigned b97 = arena[args->base_params + 40u];
    unsigned b98 = stwo_m31_add(b1, b97);
    unsigned b99 = arena[args->base_params + 41u];
    unsigned b100 = stwo_m31_add(b2, b99);
    unsigned b101 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b102 = arena[args->base_params + 42u];
    unsigned b103 = stwo_m31_add(b0, b102);
    unsigned b104 = arena[args->base_params + 43u];
    unsigned b105 = stwo_m31_add(b1, b104);
    unsigned b106 = arena[args->base_params + 44u];
    unsigned b107 = stwo_m31_add(b2, b106);
    unsigned b108 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b109 = arena[args->base_params + 45u];
    unsigned b110 = stwo_m31_add(b0, b109);
    unsigned b111 = arena[args->base_params + 46u];
    unsigned b112 = stwo_m31_add(b1, b111);
    unsigned b113 = arena[args->base_params + 47u];
    unsigned b114 = stwo_m31_add(b2, b113);
    unsigned b115 = stwo_trace_value(arena, *args, 2u, 0u, row, 0);
    unsigned b116 = stwo_trace_value(arena, *args, 2u, 1u, row, 0);
    unsigned b117 = stwo_trace_value(arena, *args, 2u, 2u, row, 0);
    unsigned b118 = stwo_trace_value(arena, *args, 2u, 3u, row, 0);
    unsigned b119 = stwo_trace_value(arena, *args, 2u, 4u, row, 0);
    unsigned b120 = stwo_trace_value(arena, *args, 2u, 5u, row, 0);
    unsigned b121 = stwo_trace_value(arena, *args, 2u, 6u, row, 0);
    unsigned b122 = stwo_trace_value(arena, *args, 2u, 7u, row, 0);
    unsigned b123 = stwo_trace_value(arena, *args, 2u, 8u, row, 0);
    unsigned b124 = stwo_trace_value(arena, *args, 2u, 9u, row, 0);
    unsigned b125 = stwo_trace_value(arena, *args, 2u, 10u, row, 0);
    unsigned b126 = stwo_trace_value(arena, *args, 2u, 11u, row, 0);
    unsigned b127 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    unsigned b128 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    unsigned b129 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    unsigned b130 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    unsigned b131 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    unsigned b132 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    unsigned b133 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    unsigned b134 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    unsigned b135 = stwo_trace_value(arena, *args, 2u, 20u, row, 0);
    unsigned b136 = stwo_trace_value(arena, *args, 2u, 21u, row, 0);
    unsigned b137 = stwo_trace_value(arena, *args, 2u, 22u, row, 0);
    unsigned b138 = stwo_trace_value(arena, *args, 2u, 23u, row, 0);
    unsigned b139 = stwo_trace_value(arena, *args, 2u, 24u, row, 0);
    unsigned b140 = stwo_trace_value(arena, *args, 2u, 25u, row, 0);
    unsigned b141 = stwo_trace_value(arena, *args, 2u, 26u, row, 0);
    unsigned b142 = stwo_trace_value(arena, *args, 2u, 27u, row, 0);
    unsigned b143 = stwo_trace_value(arena, *args, 2u, 28u, row, -1);
    unsigned b144 = stwo_trace_value(arena, *args, 2u, 28u, row, 0);
    unsigned b145 = stwo_trace_value(arena, *args, 2u, 29u, row, -1);
    unsigned b146 = stwo_trace_value(arena, *args, 2u, 29u, row, 0);
    unsigned b147 = stwo_trace_value(arena, *args, 2u, 30u, row, -1);
    unsigned b148 = stwo_trace_value(arena, *args, 2u, 30u, row, 0);
    unsigned b149 = stwo_trace_value(arena, *args, 2u, 31u, row, -1);
    unsigned b150 = stwo_trace_value(arena, *args, 2u, 31u, row, 0);
    StwoCairoQm31 e0 = { b3, b4, b4, b4 };
    StwoCairoQm31 e1 = stwo_qm31_neg(e0);
    StwoCairoQm31 e2 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e3 = { b5, b4, b4, b4 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e3);
    StwoCairoQm31 e5 = { 648362599u, 0u, 0u, 0u };
    StwoCairoQm31 e6 = stwo_qm31_add(e5, e4);
    StwoCairoQm31 e7 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e8 = { b7, b4, b4, b4 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e7, e8);
    StwoCairoQm31 e10 = stwo_qm31_add(e6, e9);
    StwoCairoQm31 e11 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e12 = { b9, b4, b4, b4 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e11, e12);
    StwoCairoQm31 e14 = stwo_qm31_add(e10, e13);
    StwoCairoQm31 e15 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e16 = stwo_qm31_sub(e14, e15);
    StwoCairoQm31 e17 = { b10, b4, b4, b4 };
    StwoCairoQm31 e18 = stwo_qm31_neg(e17);
    StwoCairoQm31 e19 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e20 = { b12, b4, b4, b4 };
    StwoCairoQm31 e21 = stwo_qm31_mul(e19, e20);
    StwoCairoQm31 e22 = { 648362599u, 0u, 0u, 0u };
    StwoCairoQm31 e23 = stwo_qm31_add(e22, e21);
    StwoCairoQm31 e24 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e25 = { b14, b4, b4, b4 };
    StwoCairoQm31 e26 = stwo_qm31_mul(e24, e25);
    StwoCairoQm31 e27 = stwo_qm31_add(e23, e26);
    StwoCairoQm31 e28 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e29 = { b16, b4, b4, b4 };
    StwoCairoQm31 e30 = stwo_qm31_mul(e28, e29);
    StwoCairoQm31 e31 = stwo_qm31_add(e27, e30);
    StwoCairoQm31 e32 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e33 = stwo_qm31_sub(e31, e32);
    StwoCairoQm31 e34 = { b17, b4, b4, b4 };
    StwoCairoQm31 e35 = stwo_qm31_neg(e34);
    StwoCairoQm31 e36 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e37 = { b19, b4, b4, b4 };
    StwoCairoQm31 e38 = stwo_qm31_mul(e36, e37);
    StwoCairoQm31 e39 = { 648362599u, 0u, 0u, 0u };
    StwoCairoQm31 e40 = stwo_qm31_add(e39, e38);
    StwoCairoQm31 e41 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e42 = { b21, b4, b4, b4 };
    StwoCairoQm31 e43 = stwo_qm31_mul(e41, e42);
    StwoCairoQm31 e44 = stwo_qm31_add(e40, e43);
    StwoCairoQm31 e45 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e46 = { b23, b4, b4, b4 };
    StwoCairoQm31 e47 = stwo_qm31_mul(e45, e46);
    StwoCairoQm31 e48 = stwo_qm31_add(e44, e47);
    StwoCairoQm31 e49 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e50 = stwo_qm31_sub(e48, e49);
    StwoCairoQm31 e51 = { b24, b4, b4, b4 };
    StwoCairoQm31 e52 = stwo_qm31_neg(e51);
    StwoCairoQm31 e53 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e54 = { b26, b4, b4, b4 };
    StwoCairoQm31 e55 = stwo_qm31_mul(e53, e54);
    StwoCairoQm31 e56 = { 648362599u, 0u, 0u, 0u };
    StwoCairoQm31 e57 = stwo_qm31_add(e56, e55);
    StwoCairoQm31 e58 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e59 = { b28, b4, b4, b4 };
    StwoCairoQm31 e60 = stwo_qm31_mul(e58, e59);
    StwoCairoQm31 e61 = stwo_qm31_add(e57, e60);
    StwoCairoQm31 e62 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e63 = { b30, b4, b4, b4 };
    StwoCairoQm31 e64 = stwo_qm31_mul(e62, e63);
    StwoCairoQm31 e65 = stwo_qm31_add(e61, e64);
    StwoCairoQm31 e66 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e67 = stwo_qm31_sub(e65, e66);
    StwoCairoQm31 e68 = { b31, b4, b4, b4 };
    StwoCairoQm31 e69 = stwo_qm31_neg(e68);
    StwoCairoQm31 e70 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e71 = { b33, b4, b4, b4 };
    StwoCairoQm31 e72 = stwo_qm31_mul(e70, e71);
    StwoCairoQm31 e73 = { 648362599u, 0u, 0u, 0u };
    StwoCairoQm31 e74 = stwo_qm31_add(e73, e72);
    StwoCairoQm31 e75 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e76 = { b35, b4, b4, b4 };
    StwoCairoQm31 e77 = stwo_qm31_mul(e75, e76);
    StwoCairoQm31 e78 = stwo_qm31_add(e74, e77);
    StwoCairoQm31 e79 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e80 = { b37, b4, b4, b4 };
    StwoCairoQm31 e81 = stwo_qm31_mul(e79, e80);
    StwoCairoQm31 e82 = stwo_qm31_add(e78, e81);
    StwoCairoQm31 e83 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e84 = stwo_qm31_sub(e82, e83);
    StwoCairoQm31 e85 = { b38, b4, b4, b4 };
    StwoCairoQm31 e86 = stwo_qm31_neg(e85);
    StwoCairoQm31 e87 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e88 = { b40, b4, b4, b4 };
    StwoCairoQm31 e89 = stwo_qm31_mul(e87, e88);
    StwoCairoQm31 e90 = { 648362599u, 0u, 0u, 0u };
    StwoCairoQm31 e91 = stwo_qm31_add(e90, e89);
    StwoCairoQm31 e92 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e93 = { b42, b4, b4, b4 };
    StwoCairoQm31 e94 = stwo_qm31_mul(e92, e93);
    StwoCairoQm31 e95 = stwo_qm31_add(e91, e94);
    StwoCairoQm31 e96 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e97 = { b44, b4, b4, b4 };
    StwoCairoQm31 e98 = stwo_qm31_mul(e96, e97);
    StwoCairoQm31 e99 = stwo_qm31_add(e95, e98);
    StwoCairoQm31 e100 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e101 = stwo_qm31_sub(e99, e100);
    StwoCairoQm31 e102 = { b45, b4, b4, b4 };
    StwoCairoQm31 e103 = stwo_qm31_neg(e102);
    StwoCairoQm31 e104 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e105 = { b47, b4, b4, b4 };
    StwoCairoQm31 e106 = stwo_qm31_mul(e104, e105);
    StwoCairoQm31 e107 = { 648362599u, 0u, 0u, 0u };
    StwoCairoQm31 e108 = stwo_qm31_add(e107, e106);
    StwoCairoQm31 e109 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e110 = { b49, b4, b4, b4 };
    StwoCairoQm31 e111 = stwo_qm31_mul(e109, e110);
    StwoCairoQm31 e112 = stwo_qm31_add(e108, e111);
    StwoCairoQm31 e113 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e114 = { b51, b4, b4, b4 };
    StwoCairoQm31 e115 = stwo_qm31_mul(e113, e114);
    StwoCairoQm31 e116 = stwo_qm31_add(e112, e115);
    StwoCairoQm31 e117 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e118 = stwo_qm31_sub(e116, e117);
    StwoCairoQm31 e119 = { b52, b4, b4, b4 };
    StwoCairoQm31 e120 = stwo_qm31_neg(e119);
    StwoCairoQm31 e121 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e122 = { b54, b4, b4, b4 };
    StwoCairoQm31 e123 = stwo_qm31_mul(e121, e122);
    StwoCairoQm31 e124 = { 648362599u, 0u, 0u, 0u };
    StwoCairoQm31 e125 = stwo_qm31_add(e124, e123);
    StwoCairoQm31 e126 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e127 = { b56, b4, b4, b4 };
    StwoCairoQm31 e128 = stwo_qm31_mul(e126, e127);
    StwoCairoQm31 e129 = stwo_qm31_add(e125, e128);
    StwoCairoQm31 e130 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e131 = { b58, b4, b4, b4 };
    StwoCairoQm31 e132 = stwo_qm31_mul(e130, e131);
    StwoCairoQm31 e133 = stwo_qm31_add(e129, e132);
    StwoCairoQm31 e134 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e135 = stwo_qm31_sub(e133, e134);
    StwoCairoQm31 e136 = { b59, b4, b4, b4 };
    StwoCairoQm31 e137 = stwo_qm31_neg(e136);
    StwoCairoQm31 e138 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e139 = { b61, b4, b4, b4 };
    StwoCairoQm31 e140 = stwo_qm31_mul(e138, e139);
    StwoCairoQm31 e141 = { 648362599u, 0u, 0u, 0u };
    StwoCairoQm31 e142 = stwo_qm31_add(e141, e140);
    StwoCairoQm31 e143 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e144 = { b63, b4, b4, b4 };
    StwoCairoQm31 e145 = stwo_qm31_mul(e143, e144);
    StwoCairoQm31 e146 = stwo_qm31_add(e142, e145);
    StwoCairoQm31 e147 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e148 = { b65, b4, b4, b4 };
    StwoCairoQm31 e149 = stwo_qm31_mul(e147, e148);
    StwoCairoQm31 e150 = stwo_qm31_add(e146, e149);
    StwoCairoQm31 e151 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e152 = stwo_qm31_sub(e150, e151);
    StwoCairoQm31 e153 = { b66, b4, b4, b4 };
    StwoCairoQm31 e154 = stwo_qm31_neg(e153);
    StwoCairoQm31 e155 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e156 = { b68, b4, b4, b4 };
    StwoCairoQm31 e157 = stwo_qm31_mul(e155, e156);
    StwoCairoQm31 e158 = { 648362599u, 0u, 0u, 0u };
    StwoCairoQm31 e159 = stwo_qm31_add(e158, e157);
    StwoCairoQm31 e160 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e161 = { b70, b4, b4, b4 };
    StwoCairoQm31 e162 = stwo_qm31_mul(e160, e161);
    StwoCairoQm31 e163 = stwo_qm31_add(e159, e162);
    StwoCairoQm31 e164 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e165 = { b72, b4, b4, b4 };
    StwoCairoQm31 e166 = stwo_qm31_mul(e164, e165);
    StwoCairoQm31 e167 = stwo_qm31_add(e163, e166);
    StwoCairoQm31 e168 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e169 = stwo_qm31_sub(e167, e168);
    StwoCairoQm31 e170 = { b73, b4, b4, b4 };
    StwoCairoQm31 e171 = stwo_qm31_neg(e170);
    StwoCairoQm31 e172 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e173 = { b75, b4, b4, b4 };
    StwoCairoQm31 e174 = stwo_qm31_mul(e172, e173);
    StwoCairoQm31 e175 = { 648362599u, 0u, 0u, 0u };
    StwoCairoQm31 e176 = stwo_qm31_add(e175, e174);
    StwoCairoQm31 e177 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e178 = { b77, b4, b4, b4 };
    StwoCairoQm31 e179 = stwo_qm31_mul(e177, e178);
    StwoCairoQm31 e180 = stwo_qm31_add(e176, e179);
    StwoCairoQm31 e181 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e182 = { b79, b4, b4, b4 };
    StwoCairoQm31 e183 = stwo_qm31_mul(e181, e182);
    StwoCairoQm31 e184 = stwo_qm31_add(e180, e183);
    StwoCairoQm31 e185 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e186 = stwo_qm31_sub(e184, e185);
    StwoCairoQm31 e187 = { b80, b4, b4, b4 };
    StwoCairoQm31 e188 = stwo_qm31_neg(e187);
    StwoCairoQm31 e189 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e190 = { b82, b4, b4, b4 };
    StwoCairoQm31 e191 = stwo_qm31_mul(e189, e190);
    StwoCairoQm31 e192 = { 648362599u, 0u, 0u, 0u };
    StwoCairoQm31 e193 = stwo_qm31_add(e192, e191);
    StwoCairoQm31 e194 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e195 = { b84, b4, b4, b4 };
    StwoCairoQm31 e196 = stwo_qm31_mul(e194, e195);
    StwoCairoQm31 e197 = stwo_qm31_add(e193, e196);
    StwoCairoQm31 e198 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e199 = { b86, b4, b4, b4 };
    StwoCairoQm31 e200 = stwo_qm31_mul(e198, e199);
    StwoCairoQm31 e201 = stwo_qm31_add(e197, e200);
    StwoCairoQm31 e202 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e203 = stwo_qm31_sub(e201, e202);
    StwoCairoQm31 e204 = { b87, b4, b4, b4 };
    StwoCairoQm31 e205 = stwo_qm31_neg(e204);
    StwoCairoQm31 e206 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e207 = { b89, b4, b4, b4 };
    StwoCairoQm31 e208 = stwo_qm31_mul(e206, e207);
    StwoCairoQm31 e209 = { 648362599u, 0u, 0u, 0u };
    StwoCairoQm31 e210 = stwo_qm31_add(e209, e208);
    StwoCairoQm31 e211 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e212 = { b91, b4, b4, b4 };
    StwoCairoQm31 e213 = stwo_qm31_mul(e211, e212);
    StwoCairoQm31 e214 = stwo_qm31_add(e210, e213);
    StwoCairoQm31 e215 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e216 = { b93, b4, b4, b4 };
    StwoCairoQm31 e217 = stwo_qm31_mul(e215, e216);
    StwoCairoQm31 e218 = stwo_qm31_add(e214, e217);
    StwoCairoQm31 e219 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e220 = stwo_qm31_sub(e218, e219);
    StwoCairoQm31 e221 = { b94, b4, b4, b4 };
    StwoCairoQm31 e222 = stwo_qm31_neg(e221);
    StwoCairoQm31 e223 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e224 = { b96, b4, b4, b4 };
    StwoCairoQm31 e225 = stwo_qm31_mul(e223, e224);
    StwoCairoQm31 e226 = { 648362599u, 0u, 0u, 0u };
    StwoCairoQm31 e227 = stwo_qm31_add(e226, e225);
    StwoCairoQm31 e228 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e229 = { b98, b4, b4, b4 };
    StwoCairoQm31 e230 = stwo_qm31_mul(e228, e229);
    StwoCairoQm31 e231 = stwo_qm31_add(e227, e230);
    StwoCairoQm31 e232 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e233 = { b100, b4, b4, b4 };
    StwoCairoQm31 e234 = stwo_qm31_mul(e232, e233);
    StwoCairoQm31 e235 = stwo_qm31_add(e231, e234);
    StwoCairoQm31 e236 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e237 = stwo_qm31_sub(e235, e236);
    StwoCairoQm31 e238 = { b101, b4, b4, b4 };
    StwoCairoQm31 e239 = stwo_qm31_neg(e238);
    StwoCairoQm31 e240 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e241 = { b103, b4, b4, b4 };
    StwoCairoQm31 e242 = stwo_qm31_mul(e240, e241);
    StwoCairoQm31 e243 = { 648362599u, 0u, 0u, 0u };
    StwoCairoQm31 e244 = stwo_qm31_add(e243, e242);
    StwoCairoQm31 e245 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e246 = { b105, b4, b4, b4 };
    StwoCairoQm31 e247 = stwo_qm31_mul(e245, e246);
    StwoCairoQm31 e248 = stwo_qm31_add(e244, e247);
    StwoCairoQm31 e249 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e250 = { b107, b4, b4, b4 };
    StwoCairoQm31 e251 = stwo_qm31_mul(e249, e250);
    StwoCairoQm31 e252 = stwo_qm31_add(e248, e251);
    StwoCairoQm31 e253 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e254 = stwo_qm31_sub(e252, e253);
    StwoCairoQm31 e255 = { b108, b4, b4, b4 };
    StwoCairoQm31 e256 = stwo_qm31_neg(e255);
    StwoCairoQm31 e257 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e258 = { b110, b4, b4, b4 };
    StwoCairoQm31 e259 = stwo_qm31_mul(e257, e258);
    StwoCairoQm31 e260 = { 648362599u, 0u, 0u, 0u };
    StwoCairoQm31 e261 = stwo_qm31_add(e260, e259);
    StwoCairoQm31 e262 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e263 = { b112, b4, b4, b4 };
    StwoCairoQm31 e264 = stwo_qm31_mul(e262, e263);
    StwoCairoQm31 e265 = stwo_qm31_add(e261, e264);
    StwoCairoQm31 e266 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e267 = { b114, b4, b4, b4 };
    StwoCairoQm31 e268 = stwo_qm31_mul(e266, e267);
    StwoCairoQm31 e269 = stwo_qm31_add(e265, e268);
    StwoCairoQm31 e270 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e271 = stwo_qm31_sub(e269, e270);
    StwoCairoQm31 e272 = stwo_qm31_mul(e33, e1);
    StwoCairoQm31 e273 = stwo_qm31_mul(e16, e18);
    StwoCairoQm31 e274 = stwo_qm31_add(e272, e273);
    StwoCairoQm31 e275 = stwo_qm31_mul(e16, e33);
    StwoCairoQm31 e276 = stwo_qm31_mul(e67, e35);
    StwoCairoQm31 e277 = stwo_qm31_mul(e50, e52);
    StwoCairoQm31 e278 = stwo_qm31_add(e276, e277);
    StwoCairoQm31 e279 = stwo_qm31_mul(e50, e67);
    StwoCairoQm31 e280 = stwo_qm31_mul(e101, e69);
    StwoCairoQm31 e281 = stwo_qm31_mul(e84, e86);
    StwoCairoQm31 e282 = stwo_qm31_add(e280, e281);
    StwoCairoQm31 e283 = stwo_qm31_mul(e84, e101);
    StwoCairoQm31 e284 = stwo_qm31_mul(e135, e103);
    StwoCairoQm31 e285 = stwo_qm31_mul(e118, e120);
    StwoCairoQm31 e286 = stwo_qm31_add(e284, e285);
    StwoCairoQm31 e287 = stwo_qm31_mul(e118, e135);
    StwoCairoQm31 e288 = stwo_qm31_mul(e169, e137);
    StwoCairoQm31 e289 = stwo_qm31_mul(e152, e154);
    StwoCairoQm31 e290 = stwo_qm31_add(e288, e289);
    StwoCairoQm31 e291 = stwo_qm31_mul(e152, e169);
    StwoCairoQm31 e292 = stwo_qm31_mul(e203, e171);
    StwoCairoQm31 e293 = stwo_qm31_mul(e186, e188);
    StwoCairoQm31 e294 = stwo_qm31_add(e292, e293);
    StwoCairoQm31 e295 = stwo_qm31_mul(e186, e203);
    StwoCairoQm31 e296 = stwo_qm31_mul(e237, e205);
    StwoCairoQm31 e297 = stwo_qm31_mul(e220, e222);
    StwoCairoQm31 e298 = stwo_qm31_add(e296, e297);
    StwoCairoQm31 e299 = stwo_qm31_mul(e220, e237);
    StwoCairoQm31 e300 = stwo_qm31_mul(e271, e239);
    StwoCairoQm31 e301 = stwo_qm31_mul(e254, e256);
    StwoCairoQm31 e302 = stwo_qm31_add(e300, e301);
    StwoCairoQm31 e303 = stwo_qm31_mul(e254, e271);
    StwoCairoQm31 e304 = { b115, b116, b117, b118 };
    StwoCairoQm31 e305 = stwo_qm31_mul(e304, e275);
    StwoCairoQm31 e306 = stwo_qm31_sub(e305, e274);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e306, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    StwoCairoQm31 e307 = { b119, b120, b121, b122 };
    StwoCairoQm31 e308 = stwo_qm31_sub(e307, e304);
    StwoCairoQm31 e309 = stwo_qm31_mul(e308, e279);
    StwoCairoQm31 e310 = stwo_qm31_sub(e309, e278);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e310, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    StwoCairoQm31 e311 = { b123, b124, b125, b126 };
    StwoCairoQm31 e312 = stwo_qm31_sub(e311, e307);
    StwoCairoQm31 e313 = stwo_qm31_mul(e312, e283);
    StwoCairoQm31 e314 = stwo_qm31_sub(e313, e282);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e314, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    StwoCairoQm31 e315 = { b127, b128, b129, b130 };
    StwoCairoQm31 e316 = stwo_qm31_sub(e315, e311);
    StwoCairoQm31 e317 = stwo_qm31_mul(e316, e287);
    StwoCairoQm31 e318 = stwo_qm31_sub(e317, e286);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e318, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    StwoCairoQm31 e319 = { b131, b132, b133, b134 };
    StwoCairoQm31 e320 = stwo_qm31_sub(e319, e315);
    StwoCairoQm31 e321 = stwo_qm31_mul(e320, e291);
    StwoCairoQm31 e322 = stwo_qm31_sub(e321, e290);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e322, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    StwoCairoQm31 e323 = { b135, b136, b137, b138 };
    StwoCairoQm31 e324 = stwo_qm31_sub(e323, e319);
    StwoCairoQm31 e325 = stwo_qm31_mul(e324, e295);
    StwoCairoQm31 e326 = stwo_qm31_sub(e325, e294);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e326, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    StwoCairoQm31 e327 = { b139, b140, b141, b142 };
    StwoCairoQm31 e328 = stwo_qm31_sub(e327, e323);
    StwoCairoQm31 e329 = stwo_qm31_mul(e328, e299);
    StwoCairoQm31 e330 = stwo_qm31_sub(e329, e298);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e330, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    StwoCairoQm31 e331 = { b143, b145, b147, b149 };
    StwoCairoQm31 e332 = { b144, b146, b148, b150 };
    StwoCairoQm31 e333 = stwo_qm31_sub(e332, e331);
    StwoCairoQm31 e334 = stwo_qm31_sub(e333, e327);
    StwoCairoQm31 e335 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    StwoCairoQm31 e336 = stwo_qm31_add(e334, e335);
    StwoCairoQm31 e337 = stwo_qm31_mul(e336, e303);
    StwoCairoQm31 e338 = stwo_qm31_sub(e337, e302);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e338, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
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
