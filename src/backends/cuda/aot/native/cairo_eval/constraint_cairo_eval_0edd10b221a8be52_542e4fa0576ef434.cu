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
stwo_cairo_cuda_eval_v1_322fb56173cde436(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 19u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
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
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 202u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 207u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 208u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 209u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 229u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 236u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 237u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 238u, row, 0);
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
    b42 = stwo_m31_mul(b10, b15);
    b4 = stwo_m31_mul(b11, b14);
    b41 = stwo_m31_add(b42, b4);
    b4 = stwo_m31_mul(b12, b13);
    b42 = stwo_m31_add(b41, b4);
    b4 = stwo_m31_mul(b13, b12);
    b41 = stwo_m31_add(b42, b4);
    b4 = stwo_m31_mul(b14, b11);
    b42 = stwo_m31_add(b41, b4);
    b4 = stwo_m31_mul(b15, b10);
    b41 = stwo_m31_add(b42, b4);
    b4 = stwo_m31_mul(b10, b16);
    b42 = stwo_m31_mul(b11, b15);
    b3 = stwo_m31_add(b4, b42);
    b42 = stwo_m31_mul(b12, b14);
    b4 = stwo_m31_add(b3, b42);
    b42 = stwo_m31_mul(b13, b13);
    b3 = stwo_m31_add(b4, b42);
    b42 = stwo_m31_mul(b14, b12);
    b4 = stwo_m31_add(b3, b42);
    b42 = stwo_m31_mul(b15, b11);
    b3 = stwo_m31_add(b4, b42);
    b42 = stwo_m31_mul(b16, b10);
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
    b3 = stwo_m31_mul(b17, b17);
    b42 = stwo_m31_mul(b17, b23);
    b2 = stwo_m31_mul(b18, b22);
    b39 = stwo_m31_add(b42, b2);
    b2 = stwo_m31_mul(b19, b21);
    b42 = stwo_m31_add(b39, b2);
    b2 = stwo_m31_mul(b20, b20);
    b39 = stwo_m31_add(b42, b2);
    b2 = stwo_m31_mul(b21, b19);
    b42 = stwo_m31_add(b39, b2);
    b2 = stwo_m31_mul(b22, b18);
    b39 = stwo_m31_add(b42, b2);
    b2 = stwo_m31_mul(b23, b17);
    b42 = stwo_m31_add(b39, b2);
    b2 = stwo_m31_mul(b18, b23);
    b39 = stwo_m31_mul(b19, b22);
    b1 = stwo_m31_add(b2, b39);
    b39 = stwo_m31_mul(b20, b21);
    b2 = stwo_m31_add(b1, b39);
    b39 = stwo_m31_mul(b21, b20);
    b1 = stwo_m31_add(b2, b39);
    b39 = stwo_m31_mul(b22, b19);
    b2 = stwo_m31_add(b1, b39);
    b39 = stwo_m31_mul(b23, b18);
    b1 = stwo_m31_add(b2, b39);
    b39 = stwo_m31_add(b10, b17);
    b2 = stwo_m31_add(b11, b18);
    b38 = stwo_m31_add(b12, b19);
    b0 = stwo_m31_add(b13, b20);
    unsigned b48 = stwo_m31_add(b14, b21);
    unsigned b49 = stwo_m31_add(b15, b22);
    unsigned b50 = stwo_m31_add(b16, b23);
    unsigned b51 = stwo_m31_add(b10, b17);
    unsigned b52 = stwo_m31_add(b11, b18);
    unsigned b53 = stwo_m31_add(b12, b19);
    unsigned b54 = stwo_m31_add(b13, b20);
    unsigned b55 = stwo_m31_add(b14, b21);
    unsigned b56 = stwo_m31_add(b15, b22);
    unsigned b57 = stwo_m31_add(b16, b23);
    unsigned b58 = stwo_m31_mul(b39, b51);
    unsigned b59 = stwo_m31_sub(b58, b47);
    b58 = stwo_m31_sub(b59, b3);
    b59 = stwo_m31_add(b40, b58);
    b58 = stwo_m31_mul(b39, b57);
    b39 = stwo_m31_mul(b2, b56);
    unsigned b60 = stwo_m31_add(b58, b39);
    b39 = stwo_m31_mul(b38, b55);
    b58 = stwo_m31_add(b60, b39);
    b39 = stwo_m31_mul(b0, b54);
    b60 = stwo_m31_add(b58, b39);
    b39 = stwo_m31_mul(b48, b53);
    b58 = stwo_m31_add(b60, b39);
    b39 = stwo_m31_mul(b49, b52);
    b60 = stwo_m31_add(b58, b39);
    b39 = stwo_m31_mul(b50, b51);
    b51 = stwo_m31_add(b60, b39);
    b39 = stwo_m31_sub(b51, b4);
    b51 = stwo_m31_sub(b39, b42);
    b39 = stwo_m31_mul(b2, b57);
    b57 = stwo_m31_mul(b38, b56);
    b56 = stwo_m31_add(b39, b57);
    b57 = stwo_m31_mul(b0, b55);
    b55 = stwo_m31_add(b56, b57);
    b57 = stwo_m31_mul(b48, b54);
    b54 = stwo_m31_add(b55, b57);
    b57 = stwo_m31_mul(b49, b53);
    b53 = stwo_m31_add(b54, b57);
    b57 = stwo_m31_mul(b50, b52);
    b52 = stwo_m31_add(b53, b57);
    b57 = stwo_m31_sub(b52, b40);
    b52 = stwo_m31_sub(b57, b1);
    b57 = stwo_m31_add(b3, b52);
    b52 = stwo_m31_mul(b24, b24);
    b3 = stwo_m31_mul(b24, b30);
    b1 = stwo_m31_mul(b25, b29);
    b40 = stwo_m31_add(b3, b1);
    b1 = stwo_m31_mul(b26, b28);
    b3 = stwo_m31_add(b40, b1);
    b1 = stwo_m31_mul(b27, b27);
    b40 = stwo_m31_add(b3, b1);
    b1 = stwo_m31_mul(b28, b26);
    b3 = stwo_m31_add(b40, b1);
    b1 = stwo_m31_mul(b29, b25);
    b40 = stwo_m31_add(b3, b1);
    b1 = stwo_m31_mul(b30, b24);
    b3 = stwo_m31_add(b40, b1);
    b1 = stwo_m31_mul(b25, b30);
    b40 = stwo_m31_mul(b26, b29);
    b53 = stwo_m31_add(b1, b40);
    b40 = stwo_m31_mul(b27, b28);
    b1 = stwo_m31_add(b53, b40);
    b40 = stwo_m31_mul(b28, b27);
    b53 = stwo_m31_add(b1, b40);
    b40 = stwo_m31_mul(b29, b26);
    b1 = stwo_m31_add(b53, b40);
    b40 = stwo_m31_mul(b30, b25);
    b53 = stwo_m31_add(b1, b40);
    b40 = stwo_m31_mul(b31, b31);
    b1 = stwo_m31_mul(b31, b37);
    b50 = stwo_m31_mul(b32, b36);
    b54 = stwo_m31_add(b1, b50);
    b50 = stwo_m31_mul(b33, b35);
    b1 = stwo_m31_add(b54, b50);
    b50 = stwo_m31_mul(b34, b34);
    b54 = stwo_m31_add(b1, b50);
    b50 = stwo_m31_mul(b35, b33);
    b1 = stwo_m31_add(b54, b50);
    b50 = stwo_m31_mul(b36, b32);
    b54 = stwo_m31_add(b1, b50);
    b50 = stwo_m31_mul(b37, b31);
    b1 = stwo_m31_add(b54, b50);
    b50 = stwo_m31_mul(b32, b37);
    b54 = stwo_m31_mul(b33, b36);
    b49 = stwo_m31_add(b50, b54);
    b54 = stwo_m31_mul(b34, b35);
    b50 = stwo_m31_add(b49, b54);
    b54 = stwo_m31_mul(b35, b34);
    b49 = stwo_m31_add(b50, b54);
    b54 = stwo_m31_mul(b36, b33);
    b50 = stwo_m31_add(b49, b54);
    b54 = stwo_m31_mul(b37, b32);
    b49 = stwo_m31_add(b50, b54);
    b54 = stwo_m31_add(b24, b31);
    b50 = stwo_m31_add(b25, b32);
    b55 = stwo_m31_add(b26, b33);
    b48 = stwo_m31_add(b27, b34);
    b56 = stwo_m31_add(b28, b35);
    b0 = stwo_m31_add(b29, b36);
    b39 = stwo_m31_add(b30, b37);
    b38 = stwo_m31_add(b24, b31);
    b2 = stwo_m31_add(b25, b32);
    b42 = stwo_m31_add(b26, b33);
    b60 = stwo_m31_add(b27, b34);
    b58 = stwo_m31_add(b28, b35);
    unsigned b61 = stwo_m31_add(b29, b36);
    unsigned b62 = stwo_m31_add(b30, b37);
    unsigned b63 = stwo_m31_mul(b54, b62);
    b54 = stwo_m31_mul(b50, b61);
    unsigned b64 = stwo_m31_add(b63, b54);
    b54 = stwo_m31_mul(b55, b58);
    b63 = stwo_m31_add(b64, b54);
    b54 = stwo_m31_mul(b48, b60);
    b64 = stwo_m31_add(b63, b54);
    b54 = stwo_m31_mul(b56, b42);
    b63 = stwo_m31_add(b64, b54);
    b54 = stwo_m31_mul(b0, b2);
    b64 = stwo_m31_add(b63, b54);
    b54 = stwo_m31_mul(b39, b38);
    b38 = stwo_m31_add(b64, b54);
    b54 = stwo_m31_sub(b38, b3);
    b38 = stwo_m31_sub(b54, b1);
    b54 = stwo_m31_mul(b50, b62);
    b62 = stwo_m31_mul(b55, b61);
    b61 = stwo_m31_add(b54, b62);
    b62 = stwo_m31_mul(b48, b58);
    b58 = stwo_m31_add(b61, b62);
    b62 = stwo_m31_mul(b56, b60);
    b60 = stwo_m31_add(b58, b62);
    b62 = stwo_m31_mul(b0, b42);
    b42 = stwo_m31_add(b60, b62);
    b62 = stwo_m31_mul(b39, b2);
    b2 = stwo_m31_add(b42, b62);
    b62 = stwo_m31_sub(b2, b53);
    b2 = stwo_m31_sub(b62, b49);
    b62 = stwo_m31_add(b40, b2);
    b2 = stwo_m31_add(b10, b24);
    b40 = stwo_m31_add(b11, b25);
    b49 = stwo_m31_add(b12, b26);
    b53 = stwo_m31_add(b13, b27);
    b42 = stwo_m31_add(b14, b28);
    b39 = stwo_m31_add(b15, b29);
    b60 = stwo_m31_add(b16, b30);
    b0 = stwo_m31_add(b17, b31);
    b58 = stwo_m31_add(b18, b32);
    b56 = stwo_m31_add(b19, b33);
    b61 = stwo_m31_add(b20, b34);
    b48 = stwo_m31_add(b21, b35);
    b54 = stwo_m31_add(b22, b36);
    b55 = stwo_m31_add(b23, b37);
    b50 = stwo_m31_add(b10, b24);
    b24 = stwo_m31_add(b11, b25);
    b25 = stwo_m31_add(b12, b26);
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
    b37 = stwo_m31_mul(b2, b29);
    b23 = stwo_m31_mul(b40, b28);
    b22 = stwo_m31_add(b37, b23);
    b23 = stwo_m31_mul(b49, b27);
    b37 = stwo_m31_add(b22, b23);
    b23 = stwo_m31_mul(b53, b26);
    b22 = stwo_m31_add(b37, b23);
    b23 = stwo_m31_mul(b42, b25);
    b37 = stwo_m31_add(b22, b23);
    b23 = stwo_m31_mul(b39, b24);
    b22 = stwo_m31_add(b37, b23);
    b23 = stwo_m31_mul(b60, b50);
    b37 = stwo_m31_add(b22, b23);
    b23 = stwo_m31_mul(b40, b29);
    b22 = stwo_m31_mul(b49, b28);
    b21 = stwo_m31_add(b23, b22);
    b22 = stwo_m31_mul(b53, b27);
    b23 = stwo_m31_add(b21, b22);
    b22 = stwo_m31_mul(b42, b26);
    b21 = stwo_m31_add(b23, b22);
    b22 = stwo_m31_mul(b39, b25);
    b23 = stwo_m31_add(b21, b22);
    b22 = stwo_m31_mul(b60, b24);
    b21 = stwo_m31_add(b23, b22);
    b22 = stwo_m31_mul(b0, b30);
    b23 = stwo_m31_mul(b0, b36);
    b20 = stwo_m31_mul(b58, b35);
    b19 = stwo_m31_add(b23, b20);
    b20 = stwo_m31_mul(b56, b34);
    b23 = stwo_m31_add(b19, b20);
    b20 = stwo_m31_mul(b61, b33);
    b19 = stwo_m31_add(b23, b20);
    b20 = stwo_m31_mul(b48, b32);
    b23 = stwo_m31_add(b19, b20);
    b20 = stwo_m31_mul(b54, b31);
    b19 = stwo_m31_add(b23, b20);
    b20 = stwo_m31_mul(b55, b30);
    b23 = stwo_m31_add(b19, b20);
    b20 = stwo_m31_mul(b58, b36);
    b19 = stwo_m31_mul(b56, b35);
    b18 = stwo_m31_add(b20, b19);
    b19 = stwo_m31_mul(b61, b34);
    b20 = stwo_m31_add(b18, b19);
    b19 = stwo_m31_mul(b48, b33);
    b18 = stwo_m31_add(b20, b19);
    b19 = stwo_m31_mul(b54, b32);
    b20 = stwo_m31_add(b18, b19);
    b19 = stwo_m31_mul(b55, b31);
    b18 = stwo_m31_add(b20, b19);
    b19 = stwo_m31_add(b2, b0);
    b0 = stwo_m31_add(b40, b58);
    b58 = stwo_m31_add(b49, b56);
    b56 = stwo_m31_add(b53, b61);
    b61 = stwo_m31_add(b42, b48);
    b48 = stwo_m31_add(b39, b54);
    b54 = stwo_m31_add(b60, b55);
    b55 = stwo_m31_add(b50, b30);
    b30 = stwo_m31_add(b24, b31);
    b31 = stwo_m31_add(b25, b32);
    b32 = stwo_m31_add(b26, b33);
    b33 = stwo_m31_add(b27, b34);
    b34 = stwo_m31_add(b28, b35);
    b35 = stwo_m31_add(b29, b36);
    b36 = stwo_m31_mul(b19, b35);
    b19 = stwo_m31_mul(b0, b34);
    b29 = stwo_m31_add(b36, b19);
    b19 = stwo_m31_mul(b58, b33);
    b36 = stwo_m31_add(b29, b19);
    b19 = stwo_m31_mul(b56, b32);
    b29 = stwo_m31_add(b36, b19);
    b19 = stwo_m31_mul(b61, b31);
    b36 = stwo_m31_add(b29, b19);
    b19 = stwo_m31_mul(b48, b30);
    b29 = stwo_m31_add(b36, b19);
    b19 = stwo_m31_mul(b54, b55);
    b55 = stwo_m31_add(b29, b19);
    b19 = stwo_m31_sub(b55, b37);
    b55 = stwo_m31_sub(b19, b23);
    b19 = stwo_m31_mul(b0, b35);
    b35 = stwo_m31_mul(b58, b34);
    b34 = stwo_m31_add(b19, b35);
    b35 = stwo_m31_mul(b56, b33);
    b33 = stwo_m31_add(b34, b35);
    b35 = stwo_m31_mul(b61, b32);
    b32 = stwo_m31_add(b33, b35);
    b35 = stwo_m31_mul(b48, b31);
    b31 = stwo_m31_add(b32, b35);
    b35 = stwo_m31_mul(b54, b30);
    b30 = stwo_m31_add(b31, b35);
    b35 = stwo_m31_sub(b30, b21);
    b30 = stwo_m31_sub(b35, b18);
    b35 = stwo_m31_add(b22, b30);
    b30 = stwo_m31_sub(b55, b51);
    b55 = stwo_m31_sub(b30, b38);
    b30 = stwo_m31_sub(b35, b57);
    b35 = stwo_m31_sub(b30, b62);
    b30 = stwo_m31_add(b52, b35);
    b35 = stwo_m31_sub(b47, b5);
    b47 = stwo_m31_sub(b41, b6);
    b41 = stwo_m31_sub(b4, b7);
    b4 = stwo_m31_sub(b59, b8);
    b59 = stwo_m31_sub(b55, b9);
    b55 = 32u;
    b9 = stwo_m31_mul(b55, b41);
    b55 = stwo_m31_add(b47, b9);
    b9 = 4u;
    b47 = stwo_m31_mul(b9, b59);
    b9 = stwo_m31_sub(b55, b47);
    b47 = 2u;
    b55 = stwo_m31_mul(b47, b35);
    b47 = stwo_m31_add(b55, b41);
    b55 = 32u;
    b41 = stwo_m31_mul(b55, b4);
    b55 = stwo_m31_add(b47, b41);
    b41 = 4u;
    b47 = stwo_m31_mul(b41, b30);
    b41 = stwo_m31_sub(b55, b47);
    b47 = 512u;
    b55 = stwo_m31_mul(b44, b47);
    b47 = stwo_m31_add(b9, b43);
    b9 = stwo_m31_sub(b55, b47);
    b47 = 512u;
    b55 = stwo_m31_mul(b45, b47);
    b47 = stwo_m31_add(b41, b44);
    b41 = stwo_m31_sub(b55, b47);
    StwoCairoQm31 e0 = { b9, b46, b46, b46 };
    StwoCairoQm31 e1 = { b41, b46, b46, b46 };
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
