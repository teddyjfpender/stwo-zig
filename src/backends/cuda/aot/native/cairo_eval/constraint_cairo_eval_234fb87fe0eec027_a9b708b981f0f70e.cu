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
stwo_cairo_cuda_eval_v1_1851752a842167f4(
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
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 5u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 6u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 7u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 8u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 9u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 10u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 11u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 47u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 48u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 49u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 51u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 52u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 53u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 54u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 55u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 58u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 59u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 60u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 61u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 62u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 63u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 64u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 65u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 66u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 67u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 71u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 101u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 103u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 104u, row, 0);
    unsigned b78 = 1u;
    unsigned b79 = stwo_m31_sub(b78, b4);
    b78 = stwo_m31_mul(b4, b79);
    b79 = 0u;
    unsigned b80 = 1u;
    unsigned b81 = stwo_m31_sub(b80, b5);
    b80 = stwo_m31_mul(b5, b81);
    b81 = 1u;
    unsigned b82 = stwo_m31_sub(b81, b6);
    b81 = stwo_m31_mul(b6, b82);
    b82 = 1u;
    unsigned b83 = stwo_m31_sub(b82, b7);
    b82 = stwo_m31_mul(b7, b83);
    b83 = 1u;
    unsigned b84 = stwo_m31_sub(b83, b6);
    b83 = stwo_m31_sub(b84, b7);
    b84 = 1u;
    unsigned b85 = stwo_m31_sub(b84, b83);
    b84 = stwo_m31_mul(b83, b85);
    b85 = 1u;
    unsigned b86 = stwo_m31_sub(b85, b8);
    b85 = stwo_m31_mul(b8, b86);
    b86 = 32768u;
    b8 = stwo_m31_sub(b3, b86);
    b86 = 1u;
    b3 = stwo_m31_sub(b86, b8);
    b86 = stwo_m31_mul(b6, b3);
    b3 = stwo_m31_mul(b4, b2);
    b8 = 1u;
    unsigned b87 = stwo_m31_sub(b8, b4);
    b8 = stwo_m31_mul(b87, b1);
    b87 = stwo_m31_add(b3, b8);
    b8 = stwo_m31_sub(b9, b87);
    b87 = stwo_m31_mul(b5, b2);
    b9 = 1u;
    b3 = stwo_m31_sub(b9, b5);
    b9 = stwo_m31_mul(b3, b1);
    b3 = stwo_m31_add(b87, b9);
    b9 = stwo_m31_sub(b10, b3);
    b3 = stwo_m31_mul(b6, b0);
    b6 = stwo_m31_mul(b7, b2);
    b7 = stwo_m31_add(b3, b6);
    b6 = stwo_m31_mul(b83, b1);
    b83 = stwo_m31_add(b7, b6);
    b6 = stwo_m31_sub(b11, b83);
    b83 = stwo_m31_mul(b18, b46);
    b11 = stwo_m31_mul(b18, b47);
    b7 = stwo_m31_mul(b19, b46);
    b1 = stwo_m31_add(b11, b7);
    b7 = stwo_m31_mul(b18, b48);
    b11 = stwo_m31_mul(b19, b47);
    b3 = stwo_m31_add(b7, b11);
    b11 = stwo_m31_mul(b20, b46);
    b7 = stwo_m31_add(b3, b11);
    b11 = stwo_m31_mul(b19, b52);
    b3 = stwo_m31_mul(b20, b51);
    b2 = stwo_m31_add(b11, b3);
    b3 = stwo_m31_mul(b21, b50);
    b11 = stwo_m31_add(b2, b3);
    b3 = stwo_m31_mul(b22, b49);
    b2 = stwo_m31_add(b11, b3);
    b3 = stwo_m31_mul(b23, b48);
    b11 = stwo_m31_add(b2, b3);
    b3 = stwo_m31_mul(b24, b47);
    b2 = stwo_m31_add(b11, b3);
    b3 = stwo_m31_mul(b20, b52);
    b11 = stwo_m31_mul(b21, b51);
    b0 = stwo_m31_add(b3, b11);
    b11 = stwo_m31_mul(b22, b50);
    b3 = stwo_m31_add(b0, b11);
    b11 = stwo_m31_mul(b23, b49);
    b0 = stwo_m31_add(b3, b11);
    b11 = stwo_m31_mul(b24, b48);
    b3 = stwo_m31_add(b0, b11);
    b11 = stwo_m31_mul(b21, b52);
    b0 = stwo_m31_mul(b22, b51);
    b10 = stwo_m31_add(b11, b0);
    b0 = stwo_m31_mul(b23, b50);
    b11 = stwo_m31_add(b10, b0);
    b0 = stwo_m31_mul(b24, b49);
    b10 = stwo_m31_add(b11, b0);
    b0 = stwo_m31_mul(b25, b53);
    b11 = stwo_m31_mul(b25, b54);
    b87 = stwo_m31_mul(b26, b53);
    b5 = stwo_m31_add(b11, b87);
    b87 = stwo_m31_mul(b25, b55);
    b11 = stwo_m31_mul(b26, b54);
    b4 = stwo_m31_add(b87, b11);
    b11 = stwo_m31_mul(b27, b53);
    b87 = stwo_m31_add(b4, b11);
    b11 = stwo_m31_mul(b26, b59);
    b4 = stwo_m31_mul(b27, b58);
    unsigned b88 = stwo_m31_add(b11, b4);
    b4 = stwo_m31_mul(b28, b57);
    b11 = stwo_m31_add(b88, b4);
    b4 = stwo_m31_mul(b29, b56);
    b88 = stwo_m31_add(b11, b4);
    b4 = stwo_m31_mul(b30, b55);
    b11 = stwo_m31_add(b88, b4);
    b4 = stwo_m31_mul(b31, b54);
    b88 = stwo_m31_add(b11, b4);
    b4 = stwo_m31_mul(b27, b59);
    b11 = stwo_m31_mul(b28, b58);
    unsigned b89 = stwo_m31_add(b4, b11);
    b11 = stwo_m31_mul(b29, b57);
    b4 = stwo_m31_add(b89, b11);
    b11 = stwo_m31_mul(b30, b56);
    b89 = stwo_m31_add(b4, b11);
    b11 = stwo_m31_mul(b31, b55);
    b4 = stwo_m31_add(b89, b11);
    b11 = stwo_m31_mul(b28, b59);
    b59 = stwo_m31_mul(b29, b58);
    b58 = stwo_m31_add(b11, b59);
    b59 = stwo_m31_mul(b30, b57);
    b57 = stwo_m31_add(b58, b59);
    b59 = stwo_m31_mul(b31, b56);
    b56 = stwo_m31_add(b57, b59);
    b59 = stwo_m31_add(b18, b25);
    b57 = stwo_m31_add(b19, b26);
    b31 = stwo_m31_add(b20, b27);
    b58 = stwo_m31_add(b46, b53);
    b30 = stwo_m31_add(b47, b54);
    b11 = stwo_m31_add(b48, b55);
    b29 = stwo_m31_mul(b59, b58);
    b28 = stwo_m31_sub(b29, b83);
    b29 = stwo_m31_sub(b28, b0);
    b28 = stwo_m31_add(b2, b29);
    b29 = stwo_m31_mul(b59, b30);
    b2 = stwo_m31_mul(b57, b58);
    b0 = stwo_m31_add(b29, b2);
    b2 = stwo_m31_sub(b0, b1);
    b0 = stwo_m31_sub(b2, b5);
    b2 = stwo_m31_add(b3, b0);
    b0 = stwo_m31_mul(b59, b11);
    b11 = stwo_m31_mul(b57, b30);
    b30 = stwo_m31_add(b0, b11);
    b11 = stwo_m31_mul(b31, b58);
    b58 = stwo_m31_add(b30, b11);
    b11 = stwo_m31_sub(b58, b7);
    b58 = stwo_m31_sub(b11, b87);
    b11 = stwo_m31_add(b10, b58);
    b58 = stwo_m31_mul(b32, b60);
    b10 = stwo_m31_mul(b32, b61);
    b87 = stwo_m31_mul(b33, b60);
    b30 = stwo_m31_add(b10, b87);
    b87 = stwo_m31_mul(b32, b62);
    b10 = stwo_m31_mul(b33, b61);
    b31 = stwo_m31_add(b87, b10);
    b10 = stwo_m31_mul(b34, b60);
    b87 = stwo_m31_add(b31, b10);
    b10 = stwo_m31_mul(b33, b66);
    b31 = stwo_m31_mul(b34, b65);
    b0 = stwo_m31_add(b10, b31);
    b31 = stwo_m31_mul(b35, b64);
    b10 = stwo_m31_add(b0, b31);
    b31 = stwo_m31_mul(b36, b63);
    b0 = stwo_m31_add(b10, b31);
    b31 = stwo_m31_mul(b37, b62);
    b10 = stwo_m31_add(b0, b31);
    b31 = stwo_m31_mul(b38, b61);
    b0 = stwo_m31_add(b10, b31);
    b31 = stwo_m31_mul(b34, b66);
    b10 = stwo_m31_mul(b35, b65);
    b57 = stwo_m31_add(b31, b10);
    b10 = stwo_m31_mul(b36, b64);
    b31 = stwo_m31_add(b57, b10);
    b10 = stwo_m31_mul(b37, b63);
    b57 = stwo_m31_add(b31, b10);
    b10 = stwo_m31_mul(b38, b62);
    b31 = stwo_m31_add(b57, b10);
    b10 = stwo_m31_mul(b35, b66);
    b57 = stwo_m31_mul(b36, b65);
    b59 = stwo_m31_add(b10, b57);
    b57 = stwo_m31_mul(b37, b64);
    b10 = stwo_m31_add(b59, b57);
    b57 = stwo_m31_mul(b38, b63);
    b59 = stwo_m31_add(b10, b57);
    b57 = stwo_m31_mul(b39, b67);
    b10 = stwo_m31_mul(b39, b68);
    b3 = stwo_m31_mul(b40, b67);
    b5 = stwo_m31_add(b10, b3);
    b3 = stwo_m31_mul(b39, b69);
    b10 = stwo_m31_mul(b40, b68);
    b29 = stwo_m31_add(b3, b10);
    b10 = stwo_m31_mul(b41, b67);
    b3 = stwo_m31_add(b29, b10);
    b10 = stwo_m31_mul(b40, b73);
    b29 = stwo_m31_mul(b41, b72);
    b89 = stwo_m31_add(b10, b29);
    b29 = stwo_m31_mul(b42, b71);
    b10 = stwo_m31_add(b89, b29);
    b29 = stwo_m31_mul(b43, b70);
    b89 = stwo_m31_add(b10, b29);
    b29 = stwo_m31_mul(b44, b69);
    b10 = stwo_m31_add(b89, b29);
    b29 = stwo_m31_mul(b45, b68);
    b89 = stwo_m31_add(b10, b29);
    b29 = stwo_m31_mul(b41, b73);
    b10 = stwo_m31_mul(b42, b72);
    unsigned b90 = stwo_m31_add(b29, b10);
    b10 = stwo_m31_mul(b43, b71);
    b29 = stwo_m31_add(b90, b10);
    b10 = stwo_m31_mul(b44, b70);
    b90 = stwo_m31_add(b29, b10);
    b10 = stwo_m31_mul(b45, b69);
    b29 = stwo_m31_add(b90, b10);
    b10 = stwo_m31_mul(b42, b73);
    b73 = stwo_m31_mul(b43, b72);
    b72 = stwo_m31_add(b10, b73);
    b73 = stwo_m31_mul(b44, b71);
    b71 = stwo_m31_add(b72, b73);
    b73 = stwo_m31_mul(b45, b70);
    b70 = stwo_m31_add(b71, b73);
    b73 = stwo_m31_add(b32, b39);
    b71 = stwo_m31_add(b33, b40);
    b45 = stwo_m31_add(b34, b41);
    b72 = stwo_m31_add(b60, b67);
    b44 = stwo_m31_add(b61, b68);
    b10 = stwo_m31_add(b62, b69);
    b43 = stwo_m31_mul(b73, b72);
    b42 = stwo_m31_sub(b43, b58);
    b43 = stwo_m31_sub(b42, b57);
    b42 = stwo_m31_add(b0, b43);
    b43 = stwo_m31_mul(b73, b44);
    b0 = stwo_m31_mul(b71, b72);
    b57 = stwo_m31_add(b43, b0);
    b0 = stwo_m31_sub(b57, b30);
    b57 = stwo_m31_sub(b0, b5);
    b0 = stwo_m31_add(b31, b57);
    b57 = stwo_m31_mul(b73, b10);
    b10 = stwo_m31_mul(b71, b44);
    b44 = stwo_m31_add(b57, b10);
    b10 = stwo_m31_mul(b45, b72);
    b72 = stwo_m31_add(b44, b10);
    b10 = stwo_m31_sub(b72, b87);
    b72 = stwo_m31_sub(b10, b3);
    b10 = stwo_m31_add(b59, b72);
    b72 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_add(b19, b33);
    b33 = stwo_m31_add(b20, b34);
    b34 = stwo_m31_add(b21, b35);
    b35 = stwo_m31_add(b22, b36);
    b36 = stwo_m31_add(b23, b37);
    b37 = stwo_m31_add(b24, b38);
    b38 = stwo_m31_add(b25, b39);
    b39 = stwo_m31_add(b26, b40);
    b40 = stwo_m31_add(b27, b41);
    b41 = stwo_m31_add(b46, b60);
    b60 = stwo_m31_add(b47, b61);
    b61 = stwo_m31_add(b48, b62);
    b62 = stwo_m31_add(b49, b63);
    b63 = stwo_m31_add(b50, b64);
    b64 = stwo_m31_add(b51, b65);
    b65 = stwo_m31_add(b52, b66);
    b66 = stwo_m31_add(b53, b67);
    b67 = stwo_m31_add(b54, b68);
    b68 = stwo_m31_add(b55, b69);
    b69 = stwo_m31_mul(b72, b41);
    b55 = stwo_m31_mul(b72, b60);
    b54 = stwo_m31_mul(b32, b41);
    b53 = stwo_m31_add(b55, b54);
    b54 = stwo_m31_mul(b72, b61);
    b55 = stwo_m31_mul(b32, b60);
    b52 = stwo_m31_add(b54, b55);
    b55 = stwo_m31_mul(b33, b41);
    b54 = stwo_m31_add(b52, b55);
    b55 = stwo_m31_mul(b32, b65);
    b52 = stwo_m31_mul(b33, b64);
    b51 = stwo_m31_add(b55, b52);
    b52 = stwo_m31_mul(b34, b63);
    b55 = stwo_m31_add(b51, b52);
    b52 = stwo_m31_mul(b35, b62);
    b51 = stwo_m31_add(b55, b52);
    b52 = stwo_m31_mul(b36, b61);
    b55 = stwo_m31_add(b51, b52);
    b52 = stwo_m31_mul(b37, b60);
    b51 = stwo_m31_add(b55, b52);
    b52 = stwo_m31_mul(b33, b65);
    b55 = stwo_m31_mul(b34, b64);
    b50 = stwo_m31_add(b52, b55);
    b55 = stwo_m31_mul(b35, b63);
    b52 = stwo_m31_add(b50, b55);
    b55 = stwo_m31_mul(b36, b62);
    b50 = stwo_m31_add(b52, b55);
    b55 = stwo_m31_mul(b37, b61);
    b52 = stwo_m31_add(b50, b55);
    b55 = stwo_m31_mul(b34, b65);
    b65 = stwo_m31_mul(b35, b64);
    b64 = stwo_m31_add(b55, b65);
    b65 = stwo_m31_mul(b36, b63);
    b63 = stwo_m31_add(b64, b65);
    b65 = stwo_m31_mul(b37, b62);
    b62 = stwo_m31_add(b63, b65);
    b65 = stwo_m31_mul(b38, b66);
    b63 = stwo_m31_mul(b38, b67);
    b37 = stwo_m31_mul(b39, b66);
    b64 = stwo_m31_add(b63, b37);
    b37 = stwo_m31_mul(b38, b68);
    b63 = stwo_m31_mul(b39, b67);
    b36 = stwo_m31_add(b37, b63);
    b63 = stwo_m31_mul(b40, b66);
    b37 = stwo_m31_add(b36, b63);
    b63 = stwo_m31_add(b72, b38);
    b38 = stwo_m31_add(b32, b39);
    b39 = stwo_m31_add(b33, b40);
    b40 = stwo_m31_add(b41, b66);
    b66 = stwo_m31_add(b60, b67);
    b67 = stwo_m31_add(b61, b68);
    b68 = stwo_m31_mul(b63, b40);
    b61 = stwo_m31_sub(b68, b69);
    b68 = stwo_m31_sub(b61, b65);
    b61 = stwo_m31_add(b51, b68);
    b68 = stwo_m31_mul(b63, b66);
    b51 = stwo_m31_mul(b38, b40);
    b65 = stwo_m31_add(b68, b51);
    b51 = stwo_m31_sub(b65, b53);
    b65 = stwo_m31_sub(b51, b64);
    b51 = stwo_m31_add(b52, b65);
    b65 = stwo_m31_mul(b63, b67);
    b67 = stwo_m31_mul(b38, b66);
    b66 = stwo_m31_add(b65, b67);
    b67 = stwo_m31_mul(b39, b40);
    b40 = stwo_m31_add(b66, b67);
    b67 = stwo_m31_sub(b40, b54);
    b40 = stwo_m31_sub(b67, b37);
    b67 = stwo_m31_add(b62, b40);
    b40 = stwo_m31_sub(b61, b28);
    b61 = stwo_m31_sub(b40, b42);
    b40 = stwo_m31_add(b88, b61);
    b61 = stwo_m31_sub(b51, b2);
    b51 = stwo_m31_sub(b61, b0);
    b61 = stwo_m31_add(b4, b51);
    b51 = stwo_m31_sub(b67, b11);
    b67 = stwo_m31_sub(b51, b10);
    b51 = stwo_m31_add(b56, b67);
    b67 = stwo_m31_sub(b83, b12);
    b83 = stwo_m31_sub(b1, b13);
    b1 = stwo_m31_sub(b7, b14);
    b7 = stwo_m31_sub(b40, b15);
    b40 = stwo_m31_sub(b61, b16);
    b61 = stwo_m31_sub(b51, b17);
    b51 = 32u;
    b17 = stwo_m31_mul(b51, b67);
    b51 = 4u;
    b16 = stwo_m31_mul(b51, b7);
    b51 = stwo_m31_sub(b17, b16);
    b16 = 8u;
    b17 = stwo_m31_mul(b16, b89);
    b16 = stwo_m31_add(b51, b17);
    b17 = 32u;
    b51 = stwo_m31_mul(b17, b83);
    b17 = stwo_m31_add(b67, b51);
    b51 = 4u;
    b67 = stwo_m31_mul(b51, b40);
    b51 = stwo_m31_sub(b17, b67);
    b67 = 8u;
    b17 = stwo_m31_mul(b67, b29);
    b67 = stwo_m31_add(b51, b17);
    b17 = 32u;
    b51 = stwo_m31_mul(b17, b1);
    b17 = stwo_m31_add(b83, b51);
    b51 = 4u;
    b83 = stwo_m31_mul(b51, b61);
    b51 = stwo_m31_sub(b17, b83);
    b83 = 8u;
    b17 = stwo_m31_mul(b83, b70);
    b83 = stwo_m31_add(b51, b17);
    b17 = 512u;
    b51 = stwo_m31_mul(b75, b17);
    b17 = stwo_m31_sub(b16, b74);
    b16 = stwo_m31_sub(b51, b17);
    b17 = 512u;
    b51 = stwo_m31_mul(b76, b17);
    b17 = stwo_m31_add(b67, b75);
    b67 = stwo_m31_sub(b51, b17);
    b17 = 512u;
    b51 = stwo_m31_mul(b77, b17);
    b17 = stwo_m31_add(b83, b76);
    b83 = stwo_m31_sub(b51, b17);
    StwoCairoQm31 e0 = { b78, b79, b79, b79 };
    StwoCairoQm31 e1 = { b80, b79, b79, b79 };
    StwoCairoQm31 e2 = { b81, b79, b79, b79 };
    StwoCairoQm31 e3 = { b82, b79, b79, b79 };
    StwoCairoQm31 e4 = { b84, b79, b79, b79 };
    StwoCairoQm31 e5 = { b85, b79, b79, b79 };
    StwoCairoQm31 e6 = { b86, b79, b79, b79 };
    StwoCairoQm31 e7 = { b8, b79, b79, b79 };
    StwoCairoQm31 e8 = { b9, b79, b79, b79 };
    StwoCairoQm31 e9 = { b6, b79, b79, b79 };
    StwoCairoQm31 e10 = { b16, b79, b79, b79 };
    StwoCairoQm31 e11 = { b67, b79, b79, b79 };
    StwoCairoQm31 e12 = { b83, b79, b79, b79 };
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e4, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e6, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e8, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 8u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e9, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 9u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e10, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 10u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e11, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 11u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e12, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 12u) * 4u)));
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
