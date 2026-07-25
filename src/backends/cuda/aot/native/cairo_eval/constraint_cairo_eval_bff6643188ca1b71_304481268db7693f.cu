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
stwo_cairo_cuda_eval_v1_3cb5f26b45f61bc0(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 19u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 156u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 157u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 158u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 159u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 160u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 161u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 162u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 163u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 164u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 165u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 166u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 167u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 168u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 169u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 170u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 171u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 172u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 173u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 203u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 204u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 209u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 210u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 211u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 238u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 239u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 240u, row, 0);
    unsigned b46 = 0u;
    unsigned b47 = stwo_m31_add(b5, b0);
    b5 = stwo_m31_add(b47, b38);
    b47 = stwo_m31_add(b6, b1);
    b6 = stwo_m31_add(b47, b39);
    b47 = stwo_m31_add(b7, b2);
    b7 = stwo_m31_add(b47, b40);
    b47 = stwo_m31_add(b8, b3);
    b8 = stwo_m31_add(b47, b41);
    b47 = stwo_m31_add(b9, b4);
    b9 = stwo_m31_add(b47, b42);
    b47 = stwo_m31_mul(b10, b10);
    b42 = stwo_m31_mul(b10, b11);
    b4 = stwo_m31_mul(b11, b10);
    b41 = stwo_m31_add(b42, b4);
    b4 = stwo_m31_mul(b10, b12);
    b42 = stwo_m31_mul(b11, b11);
    b3 = stwo_m31_add(b4, b42);
    b42 = stwo_m31_mul(b12, b10);
    b4 = stwo_m31_add(b3, b42);
    b42 = stwo_m31_mul(b11, b16);
    b3 = stwo_m31_mul(b12, b15);
    b40 = stwo_m31_add(b42, b3);
    b3 = stwo_m31_mul(b13, b14);
    b42 = stwo_m31_add(b40, b3);
    b3 = stwo_m31_mul(b14, b13);
    b40 = stwo_m31_add(b42, b3);
    b3 = stwo_m31_mul(b15, b12);
    b42 = stwo_m31_add(b40, b3);
    b3 = stwo_m31_mul(b16, b11);
    b40 = stwo_m31_add(b42, b3);
    b3 = stwo_m31_mul(b12, b16);
    b42 = stwo_m31_mul(b13, b15);
    b2 = stwo_m31_add(b3, b42);
    b42 = stwo_m31_mul(b14, b14);
    b3 = stwo_m31_add(b2, b42);
    b42 = stwo_m31_mul(b15, b13);
    b2 = stwo_m31_add(b3, b42);
    b42 = stwo_m31_mul(b16, b12);
    b3 = stwo_m31_add(b2, b42);
    b42 = stwo_m31_mul(b13, b16);
    b2 = stwo_m31_mul(b14, b15);
    b39 = stwo_m31_add(b42, b2);
    b2 = stwo_m31_mul(b15, b14);
    b42 = stwo_m31_add(b39, b2);
    b2 = stwo_m31_mul(b16, b13);
    b39 = stwo_m31_add(b42, b2);
    b2 = stwo_m31_mul(b17, b17);
    b42 = stwo_m31_mul(b17, b18);
    b1 = stwo_m31_mul(b18, b17);
    b38 = stwo_m31_add(b42, b1);
    b1 = stwo_m31_mul(b17, b19);
    b42 = stwo_m31_mul(b18, b18);
    b0 = stwo_m31_add(b1, b42);
    b42 = stwo_m31_mul(b19, b17);
    b1 = stwo_m31_add(b0, b42);
    b42 = stwo_m31_mul(b19, b23);
    b0 = stwo_m31_mul(b20, b22);
    unsigned b48 = stwo_m31_add(b42, b0);
    b0 = stwo_m31_mul(b21, b21);
    b42 = stwo_m31_add(b48, b0);
    b0 = stwo_m31_mul(b22, b20);
    b48 = stwo_m31_add(b42, b0);
    b0 = stwo_m31_mul(b23, b19);
    b42 = stwo_m31_add(b48, b0);
    b0 = stwo_m31_mul(b20, b23);
    b48 = stwo_m31_mul(b21, b22);
    unsigned b49 = stwo_m31_add(b0, b48);
    b48 = stwo_m31_mul(b22, b21);
    b0 = stwo_m31_add(b49, b48);
    b48 = stwo_m31_mul(b23, b20);
    b49 = stwo_m31_add(b0, b48);
    b48 = stwo_m31_add(b10, b17);
    b0 = stwo_m31_add(b11, b18);
    unsigned b50 = stwo_m31_add(b12, b19);
    unsigned b51 = stwo_m31_add(b13, b20);
    unsigned b52 = stwo_m31_add(b14, b21);
    unsigned b53 = stwo_m31_add(b15, b22);
    unsigned b54 = stwo_m31_add(b16, b23);
    unsigned b55 = stwo_m31_add(b10, b17);
    b10 = stwo_m31_add(b11, b18);
    b11 = stwo_m31_add(b12, b19);
    unsigned b56 = stwo_m31_add(b13, b20);
    unsigned b57 = stwo_m31_add(b14, b21);
    unsigned b58 = stwo_m31_add(b15, b22);
    unsigned b59 = stwo_m31_add(b16, b23);
    unsigned b60 = stwo_m31_mul(b48, b55);
    unsigned b61 = stwo_m31_sub(b60, b47);
    b60 = stwo_m31_sub(b61, b2);
    b61 = stwo_m31_add(b40, b60);
    b60 = stwo_m31_mul(b48, b10);
    b40 = stwo_m31_mul(b0, b55);
    b2 = stwo_m31_add(b60, b40);
    b40 = stwo_m31_sub(b2, b41);
    b2 = stwo_m31_sub(b40, b38);
    b40 = stwo_m31_add(b3, b2);
    b2 = stwo_m31_mul(b48, b11);
    b48 = stwo_m31_mul(b0, b10);
    b10 = stwo_m31_add(b2, b48);
    b48 = stwo_m31_mul(b50, b55);
    b55 = stwo_m31_add(b10, b48);
    b48 = stwo_m31_sub(b55, b4);
    b55 = stwo_m31_sub(b48, b1);
    b48 = stwo_m31_add(b39, b55);
    b55 = stwo_m31_mul(b50, b59);
    b50 = stwo_m31_mul(b51, b58);
    b10 = stwo_m31_add(b55, b50);
    b50 = stwo_m31_mul(b52, b57);
    b55 = stwo_m31_add(b10, b50);
    b50 = stwo_m31_mul(b53, b56);
    b10 = stwo_m31_add(b55, b50);
    b50 = stwo_m31_mul(b54, b11);
    b11 = stwo_m31_add(b10, b50);
    b50 = stwo_m31_sub(b11, b3);
    b11 = stwo_m31_sub(b50, b42);
    b50 = stwo_m31_add(b38, b11);
    b11 = stwo_m31_mul(b51, b59);
    b59 = stwo_m31_mul(b52, b58);
    b58 = stwo_m31_add(b11, b59);
    b59 = stwo_m31_mul(b53, b57);
    b57 = stwo_m31_add(b58, b59);
    b59 = stwo_m31_mul(b54, b56);
    b56 = stwo_m31_add(b57, b59);
    b59 = stwo_m31_sub(b56, b39);
    b56 = stwo_m31_sub(b59, b49);
    b59 = stwo_m31_add(b1, b56);
    b56 = stwo_m31_mul(b24, b25);
    b1 = stwo_m31_mul(b25, b24);
    b49 = stwo_m31_add(b56, b1);
    b1 = stwo_m31_mul(b24, b26);
    b56 = stwo_m31_mul(b25, b25);
    b25 = stwo_m31_add(b1, b56);
    b56 = stwo_m31_mul(b26, b24);
    b24 = stwo_m31_add(b25, b56);
    b56 = stwo_m31_mul(b26, b30);
    b25 = stwo_m31_mul(b27, b29);
    b1 = stwo_m31_add(b56, b25);
    b25 = stwo_m31_mul(b28, b28);
    b56 = stwo_m31_add(b1, b25);
    b25 = stwo_m31_mul(b29, b27);
    b1 = stwo_m31_add(b56, b25);
    b25 = stwo_m31_mul(b30, b26);
    b56 = stwo_m31_add(b1, b25);
    b25 = stwo_m31_mul(b27, b30);
    b1 = stwo_m31_mul(b28, b29);
    b39 = stwo_m31_add(b25, b1);
    b1 = stwo_m31_mul(b29, b28);
    b25 = stwo_m31_add(b39, b1);
    b1 = stwo_m31_mul(b30, b27);
    b39 = stwo_m31_add(b25, b1);
    b1 = stwo_m31_mul(b31, b32);
    b25 = stwo_m31_mul(b32, b31);
    b57 = stwo_m31_add(b1, b25);
    b25 = stwo_m31_mul(b31, b33);
    b1 = stwo_m31_mul(b32, b32);
    b54 = stwo_m31_add(b25, b1);
    b1 = stwo_m31_mul(b33, b31);
    b25 = stwo_m31_add(b54, b1);
    b1 = stwo_m31_mul(b33, b37);
    b54 = stwo_m31_mul(b34, b36);
    b58 = stwo_m31_add(b1, b54);
    b54 = stwo_m31_mul(b35, b35);
    b1 = stwo_m31_add(b58, b54);
    b54 = stwo_m31_mul(b36, b34);
    b58 = stwo_m31_add(b1, b54);
    b54 = stwo_m31_mul(b37, b33);
    b1 = stwo_m31_add(b58, b54);
    b54 = stwo_m31_mul(b34, b37);
    b58 = stwo_m31_mul(b35, b36);
    b53 = stwo_m31_add(b54, b58);
    b58 = stwo_m31_mul(b36, b35);
    b54 = stwo_m31_add(b53, b58);
    b58 = stwo_m31_mul(b37, b34);
    b53 = stwo_m31_add(b54, b58);
    b58 = stwo_m31_add(b26, b33);
    b54 = stwo_m31_add(b27, b34);
    b11 = stwo_m31_add(b28, b35);
    b52 = stwo_m31_add(b29, b36);
    b51 = stwo_m31_add(b30, b37);
    b38 = stwo_m31_add(b26, b33);
    b42 = stwo_m31_add(b27, b34);
    b3 = stwo_m31_add(b28, b35);
    b10 = stwo_m31_add(b29, b36);
    b55 = stwo_m31_add(b30, b37);
    b2 = stwo_m31_mul(b58, b55);
    b58 = stwo_m31_mul(b54, b10);
    b0 = stwo_m31_add(b2, b58);
    b58 = stwo_m31_mul(b11, b3);
    b2 = stwo_m31_add(b0, b58);
    b58 = stwo_m31_mul(b52, b42);
    b0 = stwo_m31_add(b2, b58);
    b58 = stwo_m31_mul(b51, b38);
    b38 = stwo_m31_add(b0, b58);
    b58 = stwo_m31_sub(b38, b56);
    b38 = stwo_m31_sub(b58, b1);
    b58 = stwo_m31_add(b57, b38);
    b38 = stwo_m31_mul(b54, b55);
    b55 = stwo_m31_mul(b11, b10);
    b10 = stwo_m31_add(b38, b55);
    b55 = stwo_m31_mul(b52, b3);
    b3 = stwo_m31_add(b10, b55);
    b55 = stwo_m31_mul(b51, b42);
    b42 = stwo_m31_add(b3, b55);
    b55 = stwo_m31_sub(b42, b39);
    b42 = stwo_m31_sub(b55, b53);
    b55 = stwo_m31_add(b25, b42);
    b42 = stwo_m31_add(b12, b26);
    b25 = stwo_m31_add(b13, b27);
    b53 = stwo_m31_add(b14, b28);
    b39 = stwo_m31_add(b15, b29);
    b3 = stwo_m31_add(b16, b30);
    b51 = stwo_m31_add(b17, b31);
    b10 = stwo_m31_add(b18, b32);
    b52 = stwo_m31_add(b19, b33);
    b38 = stwo_m31_add(b20, b34);
    b11 = stwo_m31_add(b21, b35);
    b54 = stwo_m31_add(b22, b36);
    b57 = stwo_m31_add(b23, b37);
    b1 = stwo_m31_add(b12, b26);
    b26 = stwo_m31_add(b13, b27);
    b27 = stwo_m31_add(b14, b28);
    b28 = stwo_m31_add(b15, b29);
    b29 = stwo_m31_add(b16, b30);
    b30 = stwo_m31_add(b17, b31);
    b31 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_add(b19, b33);
    b33 = stwo_m31_add(b20, b34);
    b34 = stwo_m31_add(b21, b35);
    b35 = stwo_m31_add(b22, b36);
    b36 = stwo_m31_add(b23, b37);
    b37 = stwo_m31_mul(b42, b29);
    b23 = stwo_m31_mul(b25, b28);
    b22 = stwo_m31_add(b37, b23);
    b23 = stwo_m31_mul(b53, b27);
    b37 = stwo_m31_add(b22, b23);
    b23 = stwo_m31_mul(b39, b26);
    b22 = stwo_m31_add(b37, b23);
    b23 = stwo_m31_mul(b3, b1);
    b37 = stwo_m31_add(b22, b23);
    b23 = stwo_m31_mul(b25, b29);
    b22 = stwo_m31_mul(b53, b28);
    b21 = stwo_m31_add(b23, b22);
    b22 = stwo_m31_mul(b39, b27);
    b23 = stwo_m31_add(b21, b22);
    b22 = stwo_m31_mul(b3, b26);
    b21 = stwo_m31_add(b23, b22);
    b22 = stwo_m31_mul(b51, b31);
    b23 = stwo_m31_mul(b10, b30);
    b20 = stwo_m31_add(b22, b23);
    b23 = stwo_m31_mul(b51, b32);
    b51 = stwo_m31_mul(b10, b31);
    b31 = stwo_m31_add(b23, b51);
    b51 = stwo_m31_mul(b52, b30);
    b30 = stwo_m31_add(b31, b51);
    b51 = stwo_m31_mul(b52, b36);
    b31 = stwo_m31_mul(b38, b35);
    b23 = stwo_m31_add(b51, b31);
    b31 = stwo_m31_mul(b11, b34);
    b51 = stwo_m31_add(b23, b31);
    b31 = stwo_m31_mul(b54, b33);
    b23 = stwo_m31_add(b51, b31);
    b31 = stwo_m31_mul(b57, b32);
    b51 = stwo_m31_add(b23, b31);
    b31 = stwo_m31_mul(b38, b36);
    b23 = stwo_m31_mul(b11, b35);
    b10 = stwo_m31_add(b31, b23);
    b23 = stwo_m31_mul(b54, b34);
    b31 = stwo_m31_add(b10, b23);
    b23 = stwo_m31_mul(b57, b33);
    b10 = stwo_m31_add(b31, b23);
    b23 = stwo_m31_add(b42, b52);
    b52 = stwo_m31_add(b25, b38);
    b38 = stwo_m31_add(b53, b11);
    b11 = stwo_m31_add(b39, b54);
    b54 = stwo_m31_add(b3, b57);
    b57 = stwo_m31_add(b1, b32);
    b32 = stwo_m31_add(b26, b33);
    b33 = stwo_m31_add(b27, b34);
    b34 = stwo_m31_add(b28, b35);
    b35 = stwo_m31_add(b29, b36);
    b36 = stwo_m31_mul(b23, b35);
    b23 = stwo_m31_mul(b52, b34);
    b29 = stwo_m31_add(b36, b23);
    b23 = stwo_m31_mul(b38, b33);
    b36 = stwo_m31_add(b29, b23);
    b23 = stwo_m31_mul(b11, b32);
    b29 = stwo_m31_add(b36, b23);
    b23 = stwo_m31_mul(b54, b57);
    b57 = stwo_m31_add(b29, b23);
    b23 = stwo_m31_sub(b57, b37);
    b57 = stwo_m31_sub(b23, b51);
    b23 = stwo_m31_add(b20, b57);
    b57 = stwo_m31_mul(b52, b35);
    b35 = stwo_m31_mul(b38, b34);
    b34 = stwo_m31_add(b57, b35);
    b35 = stwo_m31_mul(b11, b33);
    b33 = stwo_m31_add(b34, b35);
    b35 = stwo_m31_mul(b54, b32);
    b32 = stwo_m31_add(b33, b35);
    b35 = stwo_m31_sub(b32, b21);
    b32 = stwo_m31_sub(b35, b10);
    b35 = stwo_m31_add(b30, b32);
    b32 = stwo_m31_sub(b23, b50);
    b23 = stwo_m31_sub(b32, b58);
    b32 = stwo_m31_add(b49, b23);
    b23 = stwo_m31_sub(b35, b59);
    b35 = stwo_m31_sub(b23, b55);
    b23 = stwo_m31_add(b24, b35);
    b35 = stwo_m31_sub(b41, b5);
    b41 = stwo_m31_sub(b4, b6);
    b4 = stwo_m31_sub(b61, b7);
    b61 = stwo_m31_sub(b40, b8);
    b40 = stwo_m31_sub(b48, b9);
    b48 = 2u;
    b9 = stwo_m31_mul(b48, b35);
    b48 = stwo_m31_add(b9, b4);
    b9 = 32u;
    b4 = stwo_m31_mul(b9, b61);
    b9 = stwo_m31_add(b48, b4);
    b4 = 4u;
    b48 = stwo_m31_mul(b4, b32);
    b4 = stwo_m31_sub(b9, b48);
    b48 = 2u;
    b9 = stwo_m31_mul(b48, b41);
    b48 = stwo_m31_add(b9, b61);
    b9 = 32u;
    b61 = stwo_m31_mul(b9, b40);
    b9 = stwo_m31_add(b48, b61);
    b61 = 4u;
    b48 = stwo_m31_mul(b61, b23);
    b61 = stwo_m31_sub(b9, b48);
    b48 = 512u;
    b9 = stwo_m31_mul(b44, b48);
    b48 = stwo_m31_add(b4, b43);
    b4 = stwo_m31_sub(b9, b48);
    b48 = 512u;
    b9 = stwo_m31_mul(b45, b48);
    b48 = stwo_m31_add(b61, b44);
    b61 = stwo_m31_sub(b9, b48);
    StwoCairoQm31 e0 = { b4, b46, b46, b46 };
    StwoCairoQm31 e1 = { b61, b46, b46, b46 };
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
