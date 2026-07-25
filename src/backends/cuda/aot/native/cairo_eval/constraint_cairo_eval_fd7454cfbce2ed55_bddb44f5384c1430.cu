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
stwo_cairo_cuda_eval_v1_ab3ed64f89df914c(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 47u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 48u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 49u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 51u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 52u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 53u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 54u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 55u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 58u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 59u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 60u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 61u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 62u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 63u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 64u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 65u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 66u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 67u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 71u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 109u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 110u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 111u, row, 0);
    unsigned b64 = 0u;
    unsigned b65 = stwo_m31_mul(b5, b33);
    unsigned b66 = stwo_m31_mul(b5, b34);
    unsigned b67 = stwo_m31_mul(b6, b33);
    unsigned b68 = stwo_m31_add(b66, b67);
    b67 = stwo_m31_mul(b5, b35);
    b66 = stwo_m31_mul(b6, b34);
    unsigned b69 = stwo_m31_add(b67, b66);
    b66 = stwo_m31_mul(b7, b33);
    b67 = stwo_m31_add(b69, b66);
    b66 = stwo_m31_mul(b6, b39);
    b69 = stwo_m31_mul(b7, b38);
    unsigned b70 = stwo_m31_add(b66, b69);
    b69 = stwo_m31_mul(b8, b37);
    b66 = stwo_m31_add(b70, b69);
    b69 = stwo_m31_mul(b9, b36);
    b70 = stwo_m31_add(b66, b69);
    b69 = stwo_m31_mul(b10, b35);
    b66 = stwo_m31_add(b70, b69);
    b69 = stwo_m31_mul(b11, b34);
    b70 = stwo_m31_add(b66, b69);
    b69 = stwo_m31_mul(b7, b39);
    b66 = stwo_m31_mul(b8, b38);
    unsigned b71 = stwo_m31_add(b69, b66);
    b66 = stwo_m31_mul(b9, b37);
    b69 = stwo_m31_add(b71, b66);
    b66 = stwo_m31_mul(b10, b36);
    b71 = stwo_m31_add(b69, b66);
    b66 = stwo_m31_mul(b11, b35);
    b69 = stwo_m31_add(b71, b66);
    b66 = stwo_m31_mul(b8, b39);
    b71 = stwo_m31_mul(b9, b38);
    unsigned b72 = stwo_m31_add(b66, b71);
    b71 = stwo_m31_mul(b10, b37);
    b66 = stwo_m31_add(b72, b71);
    b71 = stwo_m31_mul(b11, b36);
    b72 = stwo_m31_add(b66, b71);
    b71 = stwo_m31_mul(b12, b40);
    b66 = stwo_m31_mul(b12, b41);
    unsigned b73 = stwo_m31_mul(b13, b40);
    unsigned b74 = stwo_m31_add(b66, b73);
    b73 = stwo_m31_mul(b12, b42);
    b66 = stwo_m31_mul(b13, b41);
    unsigned b75 = stwo_m31_add(b73, b66);
    b66 = stwo_m31_mul(b14, b40);
    b73 = stwo_m31_add(b75, b66);
    b66 = stwo_m31_mul(b14, b46);
    b75 = stwo_m31_mul(b15, b45);
    unsigned b76 = stwo_m31_add(b66, b75);
    b75 = stwo_m31_mul(b16, b44);
    b66 = stwo_m31_add(b76, b75);
    b75 = stwo_m31_mul(b17, b43);
    b76 = stwo_m31_add(b66, b75);
    b75 = stwo_m31_mul(b18, b42);
    b66 = stwo_m31_add(b76, b75);
    b75 = stwo_m31_mul(b15, b46);
    b76 = stwo_m31_mul(b16, b45);
    unsigned b77 = stwo_m31_add(b75, b76);
    b76 = stwo_m31_mul(b17, b44);
    b75 = stwo_m31_add(b77, b76);
    b76 = stwo_m31_mul(b18, b43);
    b77 = stwo_m31_add(b75, b76);
    b76 = stwo_m31_add(b5, b12);
    b5 = stwo_m31_add(b6, b13);
    b6 = stwo_m31_add(b7, b14);
    b75 = stwo_m31_add(b8, b15);
    unsigned b78 = stwo_m31_add(b9, b16);
    unsigned b79 = stwo_m31_add(b10, b17);
    unsigned b80 = stwo_m31_add(b11, b18);
    unsigned b81 = stwo_m31_add(b33, b40);
    b33 = stwo_m31_add(b34, b41);
    b34 = stwo_m31_add(b35, b42);
    unsigned b82 = stwo_m31_add(b36, b43);
    unsigned b83 = stwo_m31_add(b37, b44);
    unsigned b84 = stwo_m31_add(b38, b45);
    unsigned b85 = stwo_m31_add(b39, b46);
    unsigned b86 = stwo_m31_mul(b76, b81);
    unsigned b87 = stwo_m31_sub(b86, b65);
    b86 = stwo_m31_sub(b87, b71);
    b87 = stwo_m31_add(b70, b86);
    b86 = stwo_m31_mul(b76, b33);
    b70 = stwo_m31_mul(b5, b81);
    b71 = stwo_m31_add(b86, b70);
    b70 = stwo_m31_sub(b71, b68);
    b71 = stwo_m31_sub(b70, b74);
    b70 = stwo_m31_add(b69, b71);
    b71 = stwo_m31_mul(b76, b34);
    b76 = stwo_m31_mul(b5, b33);
    b33 = stwo_m31_add(b71, b76);
    b76 = stwo_m31_mul(b6, b81);
    b81 = stwo_m31_add(b33, b76);
    b76 = stwo_m31_sub(b81, b67);
    b81 = stwo_m31_sub(b76, b73);
    b76 = stwo_m31_add(b72, b81);
    b81 = stwo_m31_mul(b6, b85);
    b6 = stwo_m31_mul(b75, b84);
    b33 = stwo_m31_add(b81, b6);
    b6 = stwo_m31_mul(b78, b83);
    b81 = stwo_m31_add(b33, b6);
    b6 = stwo_m31_mul(b79, b82);
    b33 = stwo_m31_add(b81, b6);
    b6 = stwo_m31_mul(b80, b34);
    b34 = stwo_m31_add(b33, b6);
    b6 = stwo_m31_sub(b34, b69);
    b34 = stwo_m31_sub(b6, b66);
    b6 = stwo_m31_add(b74, b34);
    b34 = stwo_m31_mul(b75, b85);
    b85 = stwo_m31_mul(b78, b84);
    b84 = stwo_m31_add(b34, b85);
    b85 = stwo_m31_mul(b79, b83);
    b83 = stwo_m31_add(b84, b85);
    b85 = stwo_m31_mul(b80, b82);
    b82 = stwo_m31_add(b83, b85);
    b85 = stwo_m31_sub(b82, b72);
    b82 = stwo_m31_sub(b85, b77);
    b85 = stwo_m31_add(b73, b82);
    b82 = stwo_m31_mul(b19, b48);
    b73 = stwo_m31_mul(b20, b47);
    b77 = stwo_m31_add(b82, b73);
    b73 = stwo_m31_mul(b19, b49);
    b19 = stwo_m31_mul(b20, b48);
    b48 = stwo_m31_add(b73, b19);
    b19 = stwo_m31_mul(b21, b47);
    b47 = stwo_m31_add(b48, b19);
    b19 = stwo_m31_mul(b21, b53);
    b48 = stwo_m31_mul(b22, b52);
    b73 = stwo_m31_add(b19, b48);
    b48 = stwo_m31_mul(b23, b51);
    b19 = stwo_m31_add(b73, b48);
    b48 = stwo_m31_mul(b24, b50);
    b73 = stwo_m31_add(b19, b48);
    b48 = stwo_m31_mul(b25, b49);
    b19 = stwo_m31_add(b73, b48);
    b48 = stwo_m31_mul(b22, b53);
    b73 = stwo_m31_mul(b23, b52);
    b20 = stwo_m31_add(b48, b73);
    b73 = stwo_m31_mul(b24, b51);
    b48 = stwo_m31_add(b20, b73);
    b73 = stwo_m31_mul(b25, b50);
    b20 = stwo_m31_add(b48, b73);
    b73 = stwo_m31_mul(b26, b55);
    b48 = stwo_m31_mul(b27, b54);
    b82 = stwo_m31_add(b73, b48);
    b48 = stwo_m31_mul(b26, b56);
    b73 = stwo_m31_mul(b27, b55);
    b72 = stwo_m31_add(b48, b73);
    b73 = stwo_m31_mul(b28, b54);
    b48 = stwo_m31_add(b72, b73);
    b73 = stwo_m31_mul(b28, b60);
    b72 = stwo_m31_mul(b29, b59);
    b83 = stwo_m31_add(b73, b72);
    b72 = stwo_m31_mul(b30, b58);
    b73 = stwo_m31_add(b83, b72);
    b72 = stwo_m31_mul(b31, b57);
    b83 = stwo_m31_add(b73, b72);
    b72 = stwo_m31_mul(b32, b56);
    b73 = stwo_m31_add(b83, b72);
    b72 = stwo_m31_mul(b29, b60);
    b83 = stwo_m31_mul(b30, b59);
    b80 = stwo_m31_add(b72, b83);
    b83 = stwo_m31_mul(b31, b58);
    b72 = stwo_m31_add(b80, b83);
    b83 = stwo_m31_mul(b32, b57);
    b80 = stwo_m31_add(b72, b83);
    b83 = stwo_m31_add(b21, b28);
    b72 = stwo_m31_add(b22, b29);
    b84 = stwo_m31_add(b23, b30);
    b79 = stwo_m31_add(b24, b31);
    b34 = stwo_m31_add(b25, b32);
    b78 = stwo_m31_add(b49, b56);
    b75 = stwo_m31_add(b50, b57);
    b74 = stwo_m31_add(b51, b58);
    b66 = stwo_m31_add(b52, b59);
    b69 = stwo_m31_add(b53, b60);
    b33 = stwo_m31_mul(b83, b69);
    b83 = stwo_m31_mul(b72, b66);
    b81 = stwo_m31_add(b33, b83);
    b83 = stwo_m31_mul(b84, b74);
    b33 = stwo_m31_add(b81, b83);
    b83 = stwo_m31_mul(b79, b75);
    b81 = stwo_m31_add(b33, b83);
    b83 = stwo_m31_mul(b34, b78);
    b78 = stwo_m31_add(b81, b83);
    b83 = stwo_m31_sub(b78, b19);
    b78 = stwo_m31_sub(b83, b73);
    b83 = stwo_m31_add(b82, b78);
    b78 = stwo_m31_mul(b72, b69);
    b69 = stwo_m31_mul(b84, b66);
    b66 = stwo_m31_add(b78, b69);
    b69 = stwo_m31_mul(b79, b74);
    b74 = stwo_m31_add(b66, b69);
    b69 = stwo_m31_mul(b34, b75);
    b75 = stwo_m31_add(b74, b69);
    b69 = stwo_m31_sub(b75, b20);
    b75 = stwo_m31_sub(b69, b80);
    b69 = stwo_m31_add(b48, b75);
    b75 = stwo_m31_add(b7, b21);
    b21 = stwo_m31_add(b8, b22);
    b22 = stwo_m31_add(b9, b23);
    b23 = stwo_m31_add(b10, b24);
    b24 = stwo_m31_add(b11, b25);
    b25 = stwo_m31_add(b12, b26);
    b26 = stwo_m31_add(b13, b27);
    b27 = stwo_m31_add(b14, b28);
    b28 = stwo_m31_add(b15, b29);
    b29 = stwo_m31_add(b16, b30);
    b30 = stwo_m31_add(b17, b31);
    b31 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_add(b35, b49);
    b49 = stwo_m31_add(b36, b50);
    b50 = stwo_m31_add(b37, b51);
    b51 = stwo_m31_add(b38, b52);
    b52 = stwo_m31_add(b39, b53);
    b53 = stwo_m31_add(b40, b54);
    b54 = stwo_m31_add(b41, b55);
    b55 = stwo_m31_add(b42, b56);
    b56 = stwo_m31_add(b43, b57);
    b57 = stwo_m31_add(b44, b58);
    b58 = stwo_m31_add(b45, b59);
    b59 = stwo_m31_add(b46, b60);
    b60 = stwo_m31_mul(b75, b52);
    b46 = stwo_m31_mul(b21, b51);
    b45 = stwo_m31_add(b60, b46);
    b46 = stwo_m31_mul(b22, b50);
    b60 = stwo_m31_add(b45, b46);
    b46 = stwo_m31_mul(b23, b49);
    b45 = stwo_m31_add(b60, b46);
    b46 = stwo_m31_mul(b24, b32);
    b60 = stwo_m31_add(b45, b46);
    b46 = stwo_m31_mul(b21, b52);
    b45 = stwo_m31_mul(b22, b51);
    b44 = stwo_m31_add(b46, b45);
    b45 = stwo_m31_mul(b23, b50);
    b46 = stwo_m31_add(b44, b45);
    b45 = stwo_m31_mul(b24, b49);
    b44 = stwo_m31_add(b46, b45);
    b45 = stwo_m31_mul(b25, b54);
    b46 = stwo_m31_mul(b26, b53);
    b43 = stwo_m31_add(b45, b46);
    b46 = stwo_m31_mul(b25, b55);
    b25 = stwo_m31_mul(b26, b54);
    b54 = stwo_m31_add(b46, b25);
    b25 = stwo_m31_mul(b27, b53);
    b53 = stwo_m31_add(b54, b25);
    b25 = stwo_m31_mul(b27, b59);
    b54 = stwo_m31_mul(b28, b58);
    b46 = stwo_m31_add(b25, b54);
    b54 = stwo_m31_mul(b29, b57);
    b25 = stwo_m31_add(b46, b54);
    b54 = stwo_m31_mul(b30, b56);
    b46 = stwo_m31_add(b25, b54);
    b54 = stwo_m31_mul(b31, b55);
    b25 = stwo_m31_add(b46, b54);
    b54 = stwo_m31_mul(b28, b59);
    b46 = stwo_m31_mul(b29, b58);
    b26 = stwo_m31_add(b54, b46);
    b46 = stwo_m31_mul(b30, b57);
    b54 = stwo_m31_add(b26, b46);
    b46 = stwo_m31_mul(b31, b56);
    b26 = stwo_m31_add(b54, b46);
    b46 = stwo_m31_add(b75, b27);
    b27 = stwo_m31_add(b21, b28);
    b28 = stwo_m31_add(b22, b29);
    b29 = stwo_m31_add(b23, b30);
    b30 = stwo_m31_add(b24, b31);
    b31 = stwo_m31_add(b32, b55);
    b55 = stwo_m31_add(b49, b56);
    b56 = stwo_m31_add(b50, b57);
    b57 = stwo_m31_add(b51, b58);
    b58 = stwo_m31_add(b52, b59);
    b59 = stwo_m31_mul(b46, b58);
    b46 = stwo_m31_mul(b27, b57);
    b52 = stwo_m31_add(b59, b46);
    b46 = stwo_m31_mul(b28, b56);
    b59 = stwo_m31_add(b52, b46);
    b46 = stwo_m31_mul(b29, b55);
    b52 = stwo_m31_add(b59, b46);
    b46 = stwo_m31_mul(b30, b31);
    b31 = stwo_m31_add(b52, b46);
    b46 = stwo_m31_sub(b31, b60);
    b31 = stwo_m31_sub(b46, b25);
    b46 = stwo_m31_add(b43, b31);
    b31 = stwo_m31_mul(b27, b58);
    b58 = stwo_m31_mul(b28, b57);
    b57 = stwo_m31_add(b31, b58);
    b58 = stwo_m31_mul(b29, b56);
    b56 = stwo_m31_add(b57, b58);
    b58 = stwo_m31_mul(b30, b55);
    b55 = stwo_m31_add(b56, b58);
    b58 = stwo_m31_sub(b55, b44);
    b55 = stwo_m31_sub(b58, b26);
    b58 = stwo_m31_add(b53, b55);
    b55 = stwo_m31_sub(b46, b6);
    b46 = stwo_m31_sub(b55, b83);
    b55 = stwo_m31_add(b77, b46);
    b46 = stwo_m31_sub(b58, b85);
    b58 = stwo_m31_sub(b46, b69);
    b46 = stwo_m31_add(b47, b58);
    b58 = stwo_m31_sub(b68, b0);
    b68 = stwo_m31_sub(b67, b1);
    b67 = stwo_m31_sub(b87, b2);
    b87 = stwo_m31_sub(b70, b3);
    b70 = stwo_m31_sub(b76, b4);
    b76 = 2u;
    b4 = stwo_m31_mul(b76, b58);
    b76 = stwo_m31_add(b4, b67);
    b4 = 32u;
    b67 = stwo_m31_mul(b4, b87);
    b4 = stwo_m31_add(b76, b67);
    b67 = 4u;
    b76 = stwo_m31_mul(b67, b55);
    b67 = stwo_m31_sub(b4, b76);
    b76 = 2u;
    b4 = stwo_m31_mul(b76, b68);
    b76 = stwo_m31_add(b4, b87);
    b4 = 32u;
    b87 = stwo_m31_mul(b4, b70);
    b4 = stwo_m31_add(b76, b87);
    b87 = 4u;
    b76 = stwo_m31_mul(b87, b46);
    b87 = stwo_m31_sub(b4, b76);
    b76 = 512u;
    b4 = stwo_m31_mul(b62, b76);
    b76 = stwo_m31_add(b67, b61);
    b67 = stwo_m31_sub(b4, b76);
    b76 = 512u;
    b4 = stwo_m31_mul(b63, b76);
    b76 = stwo_m31_add(b87, b62);
    b87 = stwo_m31_sub(b4, b76);
    StwoCairoQm31 e0 = { b67, b64, b64, b64 };
    StwoCairoQm31 e1 = { b87, b64, b64, b64 };
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
