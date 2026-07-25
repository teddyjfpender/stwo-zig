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
stwo_cairo_cuda_eval_v1_3fea97544cd2c783(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 42u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 43u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 47u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 48u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 49u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 52u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 53u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 54u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 55u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 58u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 59u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 60u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 62u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 63u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 64u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 65u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 66u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 67u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 103u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 104u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 105u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 107u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 108u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 109u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 110u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 111u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 113u, row, 0);
    unsigned b65 = 0u;
    unsigned b66 = 3u;
    unsigned b67 = stwo_m31_mul(b66, b0);
    b66 = stwo_m31_add(b67, b9);
    b67 = stwo_m31_add(b66, b18);
    b66 = stwo_m31_add(b67, b27);
    b67 = stwo_m31_sub(b66, b45);
    b66 = stwo_m31_sub(b67, b54);
    b67 = 16u;
    b45 = stwo_m31_mul(b66, b67);
    b67 = 3u;
    b66 = stwo_m31_mul(b67, b1);
    b67 = stwo_m31_add(b45, b66);
    b66 = stwo_m31_add(b67, b10);
    b67 = stwo_m31_add(b66, b19);
    b66 = stwo_m31_add(b67, b28);
    b67 = stwo_m31_sub(b66, b46);
    b66 = 16u;
    b46 = stwo_m31_mul(b67, b66);
    b66 = 3u;
    b67 = stwo_m31_mul(b66, b2);
    b66 = stwo_m31_add(b46, b67);
    b67 = stwo_m31_add(b66, b11);
    b66 = stwo_m31_add(b67, b20);
    b67 = stwo_m31_add(b66, b29);
    b66 = stwo_m31_sub(b67, b47);
    b67 = 16u;
    b47 = stwo_m31_mul(b66, b67);
    b67 = 3u;
    b66 = stwo_m31_mul(b67, b3);
    b67 = stwo_m31_add(b47, b66);
    b66 = stwo_m31_add(b67, b12);
    b67 = stwo_m31_add(b66, b21);
    b66 = stwo_m31_add(b67, b30);
    b67 = stwo_m31_sub(b66, b48);
    b66 = 16u;
    b48 = stwo_m31_mul(b67, b66);
    b66 = 3u;
    b67 = stwo_m31_mul(b66, b4);
    b66 = stwo_m31_add(b48, b67);
    b67 = stwo_m31_add(b66, b13);
    b66 = stwo_m31_add(b67, b22);
    b67 = stwo_m31_add(b66, b31);
    b66 = stwo_m31_sub(b67, b49);
    b67 = 16u;
    b49 = stwo_m31_mul(b66, b67);
    b67 = 3u;
    b66 = stwo_m31_mul(b67, b5);
    b67 = stwo_m31_add(b49, b66);
    b66 = stwo_m31_add(b67, b14);
    b67 = stwo_m31_add(b66, b23);
    b66 = stwo_m31_add(b67, b32);
    b67 = stwo_m31_sub(b66, b50);
    b66 = 16u;
    b50 = stwo_m31_mul(b67, b66);
    b66 = 3u;
    b67 = stwo_m31_mul(b66, b6);
    b66 = stwo_m31_add(b50, b67);
    b67 = stwo_m31_add(b66, b15);
    b66 = stwo_m31_add(b67, b24);
    b67 = stwo_m31_add(b66, b33);
    b66 = stwo_m31_sub(b67, b51);
    b67 = 16u;
    b51 = stwo_m31_mul(b66, b67);
    b67 = 3u;
    b66 = stwo_m31_mul(b67, b7);
    b67 = stwo_m31_add(b51, b66);
    b66 = stwo_m31_add(b67, b16);
    b67 = stwo_m31_add(b66, b25);
    b66 = stwo_m31_add(b67, b34);
    b67 = stwo_m31_sub(b66, b52);
    b66 = 136u;
    b52 = stwo_m31_mul(b54, b66);
    b66 = stwo_m31_sub(b67, b52);
    b52 = 16u;
    b67 = stwo_m31_mul(b66, b52);
    b52 = 3u;
    b66 = stwo_m31_mul(b52, b8);
    b52 = stwo_m31_add(b67, b66);
    b66 = stwo_m31_add(b52, b17);
    b52 = stwo_m31_add(b66, b26);
    b66 = stwo_m31_add(b52, b35);
    b52 = stwo_m31_sub(b66, b53);
    b66 = 16u;
    b53 = stwo_m31_mul(b52, b66);
    b66 = 1u;
    b52 = stwo_m31_add(b54, b66);
    b66 = 1u;
    b54 = stwo_m31_add(b45, b66);
    b66 = 1u;
    b45 = stwo_m31_add(b46, b66);
    b66 = 1u;
    b46 = stwo_m31_add(b47, b66);
    b66 = 1u;
    b47 = stwo_m31_add(b48, b66);
    b66 = 1u;
    b48 = stwo_m31_add(b49, b66);
    b66 = 1u;
    b49 = stwo_m31_add(b50, b66);
    b66 = 1u;
    b50 = stwo_m31_add(b51, b66);
    b66 = 1u;
    b51 = stwo_m31_add(b67, b66);
    b66 = 1u;
    b67 = stwo_m31_add(b53, b66);
    b66 = stwo_m31_sub(b0, b9);
    b9 = stwo_m31_add(b66, b18);
    b66 = stwo_m31_add(b9, b36);
    b9 = stwo_m31_sub(b66, b55);
    b66 = stwo_m31_sub(b9, b64);
    b9 = 16u;
    b55 = stwo_m31_mul(b66, b9);
    b9 = stwo_m31_add(b55, b1);
    b1 = stwo_m31_sub(b9, b10);
    b9 = stwo_m31_add(b1, b19);
    b1 = stwo_m31_add(b9, b37);
    b9 = stwo_m31_sub(b1, b56);
    b1 = 16u;
    b56 = stwo_m31_mul(b9, b1);
    b1 = stwo_m31_add(b56, b2);
    b2 = stwo_m31_sub(b1, b11);
    b1 = stwo_m31_add(b2, b20);
    b2 = stwo_m31_add(b1, b38);
    b1 = stwo_m31_sub(b2, b57);
    b2 = 16u;
    b57 = stwo_m31_mul(b1, b2);
    b2 = stwo_m31_add(b57, b3);
    b3 = stwo_m31_sub(b2, b12);
    b2 = stwo_m31_add(b3, b21);
    b3 = stwo_m31_add(b2, b39);
    b2 = stwo_m31_sub(b3, b58);
    b3 = 16u;
    b58 = stwo_m31_mul(b2, b3);
    b3 = stwo_m31_add(b58, b4);
    b4 = stwo_m31_sub(b3, b13);
    b3 = stwo_m31_add(b4, b22);
    b4 = stwo_m31_add(b3, b40);
    b3 = stwo_m31_sub(b4, b59);
    b4 = 16u;
    b59 = stwo_m31_mul(b3, b4);
    b4 = stwo_m31_add(b59, b5);
    b5 = stwo_m31_sub(b4, b14);
    b4 = stwo_m31_add(b5, b23);
    b5 = stwo_m31_add(b4, b41);
    b4 = stwo_m31_sub(b5, b60);
    b5 = 16u;
    b60 = stwo_m31_mul(b4, b5);
    b5 = stwo_m31_add(b60, b6);
    b6 = stwo_m31_sub(b5, b15);
    b5 = stwo_m31_add(b6, b24);
    b6 = stwo_m31_add(b5, b42);
    b5 = stwo_m31_sub(b6, b61);
    b6 = 16u;
    b61 = stwo_m31_mul(b5, b6);
    b6 = stwo_m31_add(b61, b7);
    b7 = stwo_m31_sub(b6, b16);
    b6 = stwo_m31_add(b7, b25);
    b7 = stwo_m31_add(b6, b43);
    b6 = stwo_m31_sub(b7, b62);
    b7 = 136u;
    b62 = stwo_m31_mul(b64, b7);
    b7 = stwo_m31_sub(b6, b62);
    b62 = 16u;
    b6 = stwo_m31_mul(b7, b62);
    b62 = stwo_m31_add(b6, b8);
    b8 = stwo_m31_sub(b62, b17);
    b62 = stwo_m31_add(b8, b26);
    b8 = stwo_m31_add(b62, b44);
    b62 = stwo_m31_sub(b8, b63);
    b8 = 16u;
    b63 = stwo_m31_mul(b62, b8);
    b8 = 2u;
    b62 = stwo_m31_add(b64, b8);
    b8 = 2u;
    b64 = stwo_m31_add(b55, b8);
    b8 = 2u;
    b55 = stwo_m31_add(b56, b8);
    b8 = 2u;
    b56 = stwo_m31_add(b57, b8);
    b8 = 2u;
    b57 = stwo_m31_add(b58, b8);
    b8 = 2u;
    b58 = stwo_m31_add(b59, b8);
    b8 = 2u;
    b59 = stwo_m31_add(b60, b8);
    b8 = 2u;
    b60 = stwo_m31_add(b61, b8);
    b8 = 2u;
    b61 = stwo_m31_add(b6, b8);
    b8 = 2u;
    b6 = stwo_m31_add(b63, b8);
    b8 = stwo_trace_value(arena, *args, 2u, 4u, row, 0);
    b63 = stwo_trace_value(arena, *args, 2u, 5u, row, 0);
    b44 = stwo_trace_value(arena, *args, 2u, 6u, row, 0);
    b26 = stwo_trace_value(arena, *args, 2u, 7u, row, 0);
    b17 = stwo_trace_value(arena, *args, 2u, 8u, row, 0);
    b7 = stwo_trace_value(arena, *args, 2u, 9u, row, 0);
    b43 = stwo_trace_value(arena, *args, 2u, 10u, row, 0);
    b25 = stwo_trace_value(arena, *args, 2u, 11u, row, 0);
    b16 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    b5 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    b42 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    b24 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 99u * 4u);
    StwoCairoQm31 e1 = { b52, b65, b65, b65 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 100u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 101u * 4u);
    e2 = { b54, b65, b65, b65 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 102u * 4u);
    e0 = { b45, b65, b65, b65 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 103u * 4u);
    e2 = { b46, b65, b65, b65 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 104u * 4u);
    e0 = { b47, b65, b65, b65 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 105u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 106u * 4u);
    e0 = { b48, b65, b65, b65 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 107u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 108u * 4u);
    e3 = { b49, b65, b65, b65 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 109u * 4u);
    e1 = { b50, b65, b65, b65 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 110u * 4u);
    e3 = { b51, b65, b65, b65 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 111u * 4u);
    e1 = { b67, b65, b65, b65 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 112u * 4u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 113u * 4u);
    e1 = { b62, b65, b65, b65 };
    e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 114u * 4u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(arena, args->ext_params + 115u * 4u);
    e4 = { b64, b65, b65, b65 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 116u * 4u);
    e0 = { b55, b65, b65, b65 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 117u * 4u);
    e4 = { b56, b65, b65, b65 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 118u * 4u);
    e0 = { b57, b65, b65, b65 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 119u * 4u);
    e4 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 120u * 4u);
    e0 = { b58, b65, b65, b65 };
    e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 121u * 4u);
    e1 = stwo_qm31_add(e0, e5);
    e0 = stwo_load_qm31(arena, args->ext_params + 122u * 4u);
    e5 = { b59, b65, b65, b65 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e0, e5);
    e5 = stwo_qm31_add(e1, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 123u * 4u);
    e1 = { b60, b65, b65, b65 };
    e0 = stwo_qm31_mul(e6, e1);
    e1 = stwo_qm31_add(e5, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 124u * 4u);
    e5 = { b61, b65, b65, b65 };
    e6 = stwo_qm31_mul(e0, e5);
    e5 = stwo_qm31_add(e1, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 125u * 4u);
    e1 = { b6, b65, b65, b65 };
    e0 = stwo_qm31_mul(e6, e1);
    e1 = stwo_qm31_add(e5, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 126u * 4u);
    e5 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 213u * 4u);
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 214u * 4u);
    e6 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e1, e6);
    e6 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 215u * 4u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 216u * 4u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = { b8, b63, b44, b26 };
    e4 = { b17, b7, b43, b25 };
    e2 = stwo_qm31_sub(e4, e5);
    e5 = stwo_qm31_mul(e2, e6);
    e2 = stwo_qm31_sub(e5, e0);
    e5 = { b16, b5, b42, b24 };
    e0 = stwo_qm31_sub(e5, e4);
    e5 = stwo_qm31_mul(e0, e1);
    e0 = stwo_qm31_sub(e5, e3);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
