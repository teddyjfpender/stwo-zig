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
stwo_cairo_cuda_eval_v6_ddcd65dfd013810a(
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
    unsigned b5 = stwo_trace_value(arena, *args, 0u, 5u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 0u, 6u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 0u, 7u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 0u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 1u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 2u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 3u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 4u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 5u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 6u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 7u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 8u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 9u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 10u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 11u, row, 0);
    unsigned b20 = stwo_m31_add(b0, b3);
    unsigned b21 = stwo_m31_add(b20, b1);
    unsigned b22 = stwo_m31_add(b21, b2);
    unsigned b23 = arena[args->base_params + 0u];
    unsigned b24 = stwo_m31_sub(b22, b23);
    unsigned b25 = arena[args->base_params + 1u];
    unsigned b26 = arena[args->base_params + 2u];
    unsigned b27 = stwo_m31_sub(b0, b26);
    unsigned b28 = stwo_m31_mul(b0, b27);
    unsigned b29 = arena[args->base_params + 3u];
    unsigned b30 = stwo_m31_sub(b3, b29);
    unsigned b31 = stwo_m31_mul(b3, b30);
    unsigned b32 = arena[args->base_params + 4u];
    unsigned b33 = stwo_m31_sub(b1, b32);
    unsigned b34 = stwo_m31_mul(b1, b33);
    unsigned b35 = arena[args->base_params + 5u];
    unsigned b36 = stwo_m31_sub(b2, b35);
    unsigned b37 = stwo_m31_mul(b2, b36);
    unsigned b38 = stwo_m31_mul(b8, b12);
    unsigned b39 = stwo_m31_mul(b9, b13);
    unsigned b40 = stwo_m31_sub(b38, b39);
    unsigned b41 = stwo_m31_mul(b10, b14);
    unsigned b42 = stwo_m31_mul(b11, b15);
    unsigned b43 = stwo_m31_sub(b41, b42);
    unsigned b44 = arena[args->base_params + 6u];
    unsigned b45 = stwo_m31_mul(b44, b43);
    unsigned b46 = stwo_m31_add(b40, b45);
    unsigned b47 = stwo_m31_mul(b10, b15);
    unsigned b48 = stwo_m31_sub(b46, b47);
    unsigned b49 = stwo_m31_mul(b11, b14);
    unsigned b50 = stwo_m31_sub(b48, b49);
    unsigned b51 = stwo_m31_mul(b50, b1);
    unsigned b52 = stwo_m31_add(b8, b12);
    unsigned b53 = stwo_m31_mul(b52, b0);
    unsigned b54 = stwo_m31_add(b51, b53);
    unsigned b55 = stwo_m31_sub(b8, b12);
    unsigned b56 = stwo_m31_mul(b55, b3);
    unsigned b57 = stwo_m31_add(b54, b56);
    unsigned b58 = stwo_m31_mul(b8, b12);
    unsigned b59 = stwo_m31_mul(b58, b2);
    unsigned b60 = stwo_m31_add(b57, b59);
    unsigned b61 = stwo_m31_sub(b16, b60);
    unsigned b62 = stwo_m31_mul(b8, b13);
    unsigned b63 = stwo_m31_mul(b9, b12);
    unsigned b64 = stwo_m31_add(b62, b63);
    unsigned b65 = stwo_m31_mul(b10, b15);
    unsigned b66 = stwo_m31_mul(b11, b14);
    unsigned b67 = stwo_m31_add(b65, b66);
    unsigned b68 = arena[args->base_params + 7u];
    unsigned b69 = stwo_m31_mul(b68, b67);
    unsigned b70 = stwo_m31_add(b64, b69);
    unsigned b71 = stwo_m31_mul(b10, b14);
    unsigned b72 = stwo_m31_add(b70, b71);
    unsigned b73 = stwo_m31_mul(b11, b15);
    unsigned b74 = stwo_m31_sub(b72, b73);
    unsigned b75 = stwo_m31_mul(b74, b1);
    unsigned b76 = stwo_m31_add(b9, b13);
    unsigned b77 = stwo_m31_mul(b76, b0);
    unsigned b78 = stwo_m31_add(b75, b77);
    unsigned b79 = stwo_m31_sub(b9, b13);
    unsigned b80 = stwo_m31_mul(b79, b3);
    unsigned b81 = stwo_m31_add(b78, b80);
    unsigned b82 = stwo_m31_mul(b9, b13);
    unsigned b83 = stwo_m31_mul(b82, b2);
    unsigned b84 = stwo_m31_add(b81, b83);
    unsigned b85 = stwo_m31_sub(b17, b84);
    unsigned b86 = stwo_m31_mul(b8, b14);
    unsigned b87 = stwo_m31_mul(b9, b15);
    unsigned b88 = stwo_m31_sub(b86, b87);
    unsigned b89 = stwo_m31_mul(b10, b12);
    unsigned b90 = stwo_m31_add(b88, b89);
    unsigned b91 = stwo_m31_mul(b11, b13);
    unsigned b92 = stwo_m31_sub(b90, b91);
    unsigned b93 = stwo_m31_mul(b92, b1);
    unsigned b94 = stwo_m31_add(b10, b14);
    unsigned b95 = stwo_m31_mul(b94, b0);
    unsigned b96 = stwo_m31_add(b93, b95);
    unsigned b97 = stwo_m31_sub(b10, b14);
    unsigned b98 = stwo_m31_mul(b97, b3);
    unsigned b99 = stwo_m31_add(b96, b98);
    unsigned b100 = stwo_m31_mul(b10, b14);
    unsigned b101 = stwo_m31_mul(b100, b2);
    unsigned b102 = stwo_m31_add(b99, b101);
    unsigned b103 = stwo_m31_sub(b18, b102);
    unsigned b104 = stwo_m31_mul(b8, b15);
    unsigned b105 = stwo_m31_mul(b9, b14);
    unsigned b106 = stwo_m31_add(b104, b105);
    unsigned b107 = stwo_m31_mul(b10, b13);
    unsigned b108 = stwo_m31_add(b106, b107);
    unsigned b109 = stwo_m31_mul(b11, b12);
    unsigned b110 = stwo_m31_add(b108, b109);
    unsigned b111 = stwo_m31_mul(b110, b1);
    unsigned b112 = stwo_m31_add(b11, b15);
    unsigned b113 = stwo_m31_mul(b112, b0);
    unsigned b114 = stwo_m31_add(b111, b113);
    unsigned b115 = stwo_m31_sub(b11, b15);
    unsigned b116 = stwo_m31_mul(b115, b3);
    unsigned b117 = stwo_m31_add(b114, b116);
    unsigned b118 = stwo_m31_mul(b11, b15);
    unsigned b119 = stwo_m31_mul(b118, b2);
    unsigned b120 = stwo_m31_add(b117, b119);
    unsigned b121 = stwo_m31_sub(b19, b120);
    unsigned b122 = stwo_trace_value(arena, *args, 2u, 0u, row, 0);
    unsigned b123 = stwo_trace_value(arena, *args, 2u, 1u, row, 0);
    unsigned b124 = stwo_trace_value(arena, *args, 2u, 2u, row, 0);
    unsigned b125 = stwo_trace_value(arena, *args, 2u, 3u, row, 0);
    unsigned b126 = stwo_trace_value(arena, *args, 2u, 4u, row, -1);
    unsigned b127 = stwo_trace_value(arena, *args, 2u, 4u, row, 0);
    unsigned b128 = stwo_trace_value(arena, *args, 2u, 5u, row, -1);
    unsigned b129 = stwo_trace_value(arena, *args, 2u, 5u, row, 0);
    unsigned b130 = stwo_trace_value(arena, *args, 2u, 6u, row, -1);
    unsigned b131 = stwo_trace_value(arena, *args, 2u, 6u, row, 0);
    unsigned b132 = stwo_trace_value(arena, *args, 2u, 7u, row, -1);
    unsigned b133 = stwo_trace_value(arena, *args, 2u, 7u, row, 0);
    StwoCairoQm31 e0 = { b24, b25, b25, b25 };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    StwoCairoQm31 e1 = { b28, b25, b25, b25 };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    StwoCairoQm31 e2 = { b31, b25, b25, b25 };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    StwoCairoQm31 e3 = { b34, b25, b25, b25 };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    StwoCairoQm31 e4 = { b37, b25, b25, b25 };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e4, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    StwoCairoQm31 e5 = { b61, b25, b25, b25 };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    StwoCairoQm31 e6 = { b85, b25, b25, b25 };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e6, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    StwoCairoQm31 e7 = { b103, b25, b25, b25 };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
    StwoCairoQm31 e8 = { b121, b25, b25, b25 };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e8, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 8u) * 4u)));
    StwoCairoQm31 e9 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e10 = { b4, b25, b25, b25 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e9, e10);
    StwoCairoQm31 e12 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e13 = stwo_qm31_add(e12, e11);
    StwoCairoQm31 e14 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e15 = { b8, b25, b25, b25 };
    StwoCairoQm31 e16 = stwo_qm31_mul(e14, e15);
    StwoCairoQm31 e17 = stwo_qm31_add(e13, e16);
    StwoCairoQm31 e18 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e19 = { b9, b25, b25, b25 };
    StwoCairoQm31 e20 = stwo_qm31_mul(e18, e19);
    StwoCairoQm31 e21 = stwo_qm31_add(e17, e20);
    StwoCairoQm31 e22 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e23 = { b10, b25, b25, b25 };
    StwoCairoQm31 e24 = stwo_qm31_mul(e22, e23);
    StwoCairoQm31 e25 = stwo_qm31_add(e21, e24);
    StwoCairoQm31 e26 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    StwoCairoQm31 e27 = { b11, b25, b25, b25 };
    StwoCairoQm31 e28 = stwo_qm31_mul(e26, e27);
    StwoCairoQm31 e29 = stwo_qm31_add(e25, e28);
    StwoCairoQm31 e30 = stwo_load_qm31(arena, args->ext_params + 5u * 4u);
    StwoCairoQm31 e31 = stwo_qm31_sub(e29, e30);
    StwoCairoQm31 e32 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e33 = { b5, b25, b25, b25 };
    StwoCairoQm31 e34 = stwo_qm31_mul(e32, e33);
    StwoCairoQm31 e35 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e36 = stwo_qm31_add(e35, e34);
    StwoCairoQm31 e37 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e38 = { b12, b25, b25, b25 };
    StwoCairoQm31 e39 = stwo_qm31_mul(e37, e38);
    StwoCairoQm31 e40 = stwo_qm31_add(e36, e39);
    StwoCairoQm31 e41 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e42 = { b13, b25, b25, b25 };
    StwoCairoQm31 e43 = stwo_qm31_mul(e41, e42);
    StwoCairoQm31 e44 = stwo_qm31_add(e40, e43);
    StwoCairoQm31 e45 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e46 = { b14, b25, b25, b25 };
    StwoCairoQm31 e47 = stwo_qm31_mul(e45, e46);
    StwoCairoQm31 e48 = stwo_qm31_add(e44, e47);
    StwoCairoQm31 e49 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    StwoCairoQm31 e50 = { b15, b25, b25, b25 };
    StwoCairoQm31 e51 = stwo_qm31_mul(e49, e50);
    StwoCairoQm31 e52 = stwo_qm31_add(e48, e51);
    StwoCairoQm31 e53 = stwo_load_qm31(arena, args->ext_params + 5u * 4u);
    StwoCairoQm31 e54 = stwo_qm31_sub(e52, e53);
    StwoCairoQm31 e55 = { b7, b25, b25, b25 };
    StwoCairoQm31 e56 = stwo_qm31_neg(e55);
    StwoCairoQm31 e57 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e58 = { b6, b25, b25, b25 };
    StwoCairoQm31 e59 = stwo_qm31_mul(e57, e58);
    StwoCairoQm31 e60 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e61 = stwo_qm31_add(e60, e59);
    StwoCairoQm31 e62 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e63 = { b16, b25, b25, b25 };
    StwoCairoQm31 e64 = stwo_qm31_mul(e62, e63);
    StwoCairoQm31 e65 = stwo_qm31_add(e61, e64);
    StwoCairoQm31 e66 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e67 = { b17, b25, b25, b25 };
    StwoCairoQm31 e68 = stwo_qm31_mul(e66, e67);
    StwoCairoQm31 e69 = stwo_qm31_add(e65, e68);
    StwoCairoQm31 e70 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e71 = { b18, b25, b25, b25 };
    StwoCairoQm31 e72 = stwo_qm31_mul(e70, e71);
    StwoCairoQm31 e73 = stwo_qm31_add(e69, e72);
    StwoCairoQm31 e74 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    StwoCairoQm31 e75 = { b19, b25, b25, b25 };
    StwoCairoQm31 e76 = stwo_qm31_mul(e74, e75);
    StwoCairoQm31 e77 = stwo_qm31_add(e73, e76);
    StwoCairoQm31 e78 = stwo_load_qm31(arena, args->ext_params + 5u * 4u);
    StwoCairoQm31 e79 = stwo_qm31_sub(e77, e78);
    StwoCairoQm31 e80 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e81 = e54;
    StwoCairoQm31 e82 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e83 = e31;
    StwoCairoQm31 e84 = stwo_qm31_add(e81, e83);
    StwoCairoQm31 e85 = stwo_qm31_mul(e31, e54);
    StwoCairoQm31 e86 = { b122, b123, b124, b125 };
    StwoCairoQm31 e87 = stwo_qm31_mul(e86, e85);
    StwoCairoQm31 e88 = stwo_qm31_sub(e87, e84);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e88, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 9u) * 4u)));
    StwoCairoQm31 e89 = { b126, b128, b130, b132 };
    StwoCairoQm31 e90 = { b127, b129, b131, b133 };
    StwoCairoQm31 e91 = stwo_qm31_sub(e90, e89);
    StwoCairoQm31 e92 = stwo_qm31_sub(e91, e86);
    StwoCairoQm31 e93 = stwo_load_qm31(arena, args->ext_params + 6u * 4u);
    StwoCairoQm31 e94 = stwo_qm31_add(e92, e93);
    StwoCairoQm31 e95 = stwo_qm31_mul(e94, e79);
    StwoCairoQm31 e96 = stwo_qm31_sub(e95, e56);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e96, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 10u) * 4u)));
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
