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
stwo_cairo_cuda_eval_v1_6b25dde5525dde17(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 143u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 144u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 145u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 184u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 185u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 186u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 205u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 206u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 207u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 212u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 213u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 214u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 215u, row, 0);
    unsigned b50 = 0u;
    unsigned b51 = stwo_m31_add(b0, b6);
    b6 = stwo_m31_add(b51, b40);
    b51 = stwo_m31_add(b1, b7);
    b7 = stwo_m31_add(b51, b41);
    b51 = stwo_m31_add(b2, b8);
    b8 = stwo_m31_add(b51, b42);
    b51 = stwo_m31_add(b3, b9);
    b9 = stwo_m31_add(b51, b43);
    b51 = stwo_m31_add(b4, b10);
    b10 = stwo_m31_add(b51, b44);
    b51 = stwo_m31_add(b5, b11);
    b11 = stwo_m31_add(b51, b45);
    b51 = stwo_m31_mul(b12, b12);
    b45 = stwo_m31_mul(b12, b13);
    b5 = stwo_m31_mul(b13, b12);
    b44 = stwo_m31_add(b45, b5);
    b5 = stwo_m31_mul(b12, b14);
    b45 = stwo_m31_mul(b13, b13);
    b4 = stwo_m31_add(b5, b45);
    b45 = stwo_m31_mul(b14, b12);
    b5 = stwo_m31_add(b4, b45);
    b45 = stwo_m31_mul(b13, b18);
    b4 = stwo_m31_mul(b14, b17);
    b43 = stwo_m31_add(b45, b4);
    b4 = stwo_m31_mul(b15, b16);
    b45 = stwo_m31_add(b43, b4);
    b4 = stwo_m31_mul(b16, b15);
    b43 = stwo_m31_add(b45, b4);
    b4 = stwo_m31_mul(b17, b14);
    b45 = stwo_m31_add(b43, b4);
    b4 = stwo_m31_mul(b18, b13);
    b43 = stwo_m31_add(b45, b4);
    b4 = stwo_m31_mul(b14, b18);
    b45 = stwo_m31_mul(b15, b17);
    b3 = stwo_m31_add(b4, b45);
    b45 = stwo_m31_mul(b16, b16);
    b4 = stwo_m31_add(b3, b45);
    b45 = stwo_m31_mul(b17, b15);
    b3 = stwo_m31_add(b4, b45);
    b45 = stwo_m31_mul(b18, b14);
    b4 = stwo_m31_add(b3, b45);
    b45 = stwo_m31_mul(b15, b18);
    b3 = stwo_m31_mul(b16, b17);
    b42 = stwo_m31_add(b45, b3);
    b3 = stwo_m31_mul(b17, b16);
    b45 = stwo_m31_add(b42, b3);
    b3 = stwo_m31_mul(b18, b15);
    b42 = stwo_m31_add(b45, b3);
    b3 = stwo_m31_mul(b19, b19);
    b45 = stwo_m31_mul(b19, b20);
    b2 = stwo_m31_mul(b20, b19);
    b41 = stwo_m31_add(b45, b2);
    b2 = stwo_m31_mul(b19, b21);
    b45 = stwo_m31_mul(b20, b20);
    b1 = stwo_m31_add(b2, b45);
    b45 = stwo_m31_mul(b21, b19);
    b2 = stwo_m31_add(b1, b45);
    b45 = stwo_m31_mul(b20, b25);
    b1 = stwo_m31_mul(b21, b24);
    b40 = stwo_m31_add(b45, b1);
    b1 = stwo_m31_mul(b22, b23);
    b45 = stwo_m31_add(b40, b1);
    b1 = stwo_m31_mul(b23, b22);
    b40 = stwo_m31_add(b45, b1);
    b1 = stwo_m31_mul(b24, b21);
    b45 = stwo_m31_add(b40, b1);
    b1 = stwo_m31_mul(b25, b20);
    b40 = stwo_m31_add(b45, b1);
    b1 = stwo_m31_mul(b21, b25);
    b45 = stwo_m31_mul(b22, b24);
    b0 = stwo_m31_add(b1, b45);
    b45 = stwo_m31_mul(b23, b23);
    b1 = stwo_m31_add(b0, b45);
    b45 = stwo_m31_mul(b24, b22);
    b0 = stwo_m31_add(b1, b45);
    b45 = stwo_m31_mul(b25, b21);
    b1 = stwo_m31_add(b0, b45);
    b45 = stwo_m31_mul(b22, b25);
    b0 = stwo_m31_mul(b23, b24);
    unsigned b52 = stwo_m31_add(b45, b0);
    b0 = stwo_m31_mul(b24, b23);
    b24 = stwo_m31_add(b52, b0);
    b0 = stwo_m31_mul(b25, b22);
    b25 = stwo_m31_add(b24, b0);
    b0 = stwo_m31_add(b12, b19);
    b24 = stwo_m31_add(b13, b20);
    b22 = stwo_m31_add(b14, b21);
    b52 = stwo_m31_add(b12, b19);
    b23 = stwo_m31_add(b13, b20);
    b45 = stwo_m31_add(b14, b21);
    unsigned b53 = stwo_m31_mul(b0, b52);
    unsigned b54 = stwo_m31_sub(b53, b51);
    b53 = stwo_m31_sub(b54, b3);
    b54 = stwo_m31_add(b43, b53);
    b53 = stwo_m31_mul(b0, b23);
    b43 = stwo_m31_mul(b24, b52);
    b3 = stwo_m31_add(b53, b43);
    b43 = stwo_m31_sub(b3, b44);
    b3 = stwo_m31_sub(b43, b41);
    b43 = stwo_m31_add(b4, b3);
    b3 = stwo_m31_mul(b0, b45);
    b45 = stwo_m31_mul(b24, b23);
    b23 = stwo_m31_add(b3, b45);
    b45 = stwo_m31_mul(b22, b52);
    b52 = stwo_m31_add(b23, b45);
    b45 = stwo_m31_sub(b52, b5);
    b52 = stwo_m31_sub(b45, b2);
    b45 = stwo_m31_add(b42, b52);
    b52 = stwo_m31_mul(b26, b26);
    b42 = stwo_m31_mul(b26, b27);
    b2 = stwo_m31_mul(b27, b26);
    b23 = stwo_m31_add(b42, b2);
    b2 = stwo_m31_mul(b26, b28);
    b42 = stwo_m31_mul(b27, b27);
    b22 = stwo_m31_add(b2, b42);
    b42 = stwo_m31_mul(b28, b26);
    b2 = stwo_m31_add(b22, b42);
    b42 = stwo_m31_mul(b27, b32);
    b22 = stwo_m31_mul(b28, b31);
    b3 = stwo_m31_add(b42, b22);
    b22 = stwo_m31_mul(b29, b30);
    b42 = stwo_m31_add(b3, b22);
    b22 = stwo_m31_mul(b30, b29);
    b3 = stwo_m31_add(b42, b22);
    b22 = stwo_m31_mul(b31, b28);
    b42 = stwo_m31_add(b3, b22);
    b22 = stwo_m31_mul(b32, b27);
    b3 = stwo_m31_add(b42, b22);
    b22 = stwo_m31_mul(b28, b32);
    b42 = stwo_m31_mul(b29, b31);
    b24 = stwo_m31_add(b22, b42);
    b42 = stwo_m31_mul(b30, b30);
    b22 = stwo_m31_add(b24, b42);
    b42 = stwo_m31_mul(b31, b29);
    b24 = stwo_m31_add(b22, b42);
    b42 = stwo_m31_mul(b32, b28);
    b22 = stwo_m31_add(b24, b42);
    b42 = stwo_m31_mul(b29, b32);
    b24 = stwo_m31_mul(b30, b31);
    b0 = stwo_m31_add(b42, b24);
    b24 = stwo_m31_mul(b31, b30);
    b42 = stwo_m31_add(b0, b24);
    b24 = stwo_m31_mul(b32, b29);
    b0 = stwo_m31_add(b42, b24);
    b24 = stwo_m31_mul(b33, b33);
    b42 = stwo_m31_mul(b33, b34);
    b4 = stwo_m31_mul(b34, b33);
    b41 = stwo_m31_add(b42, b4);
    b4 = stwo_m31_mul(b33, b35);
    b42 = stwo_m31_mul(b34, b34);
    b53 = stwo_m31_add(b4, b42);
    b42 = stwo_m31_mul(b35, b33);
    b4 = stwo_m31_add(b53, b42);
    b42 = stwo_m31_mul(b34, b39);
    b53 = stwo_m31_mul(b35, b38);
    unsigned b55 = stwo_m31_add(b42, b53);
    b53 = stwo_m31_mul(b36, b37);
    b42 = stwo_m31_add(b55, b53);
    b53 = stwo_m31_mul(b37, b36);
    b55 = stwo_m31_add(b42, b53);
    b53 = stwo_m31_mul(b38, b35);
    b42 = stwo_m31_add(b55, b53);
    b53 = stwo_m31_mul(b39, b34);
    b55 = stwo_m31_add(b42, b53);
    b53 = stwo_m31_mul(b35, b39);
    b42 = stwo_m31_mul(b36, b38);
    unsigned b56 = stwo_m31_add(b53, b42);
    b42 = stwo_m31_mul(b37, b37);
    b53 = stwo_m31_add(b56, b42);
    b42 = stwo_m31_mul(b38, b36);
    b56 = stwo_m31_add(b53, b42);
    b42 = stwo_m31_mul(b39, b35);
    b53 = stwo_m31_add(b56, b42);
    b42 = stwo_m31_mul(b36, b39);
    b56 = stwo_m31_mul(b37, b38);
    unsigned b57 = stwo_m31_add(b42, b56);
    b56 = stwo_m31_mul(b38, b37);
    b38 = stwo_m31_add(b57, b56);
    b56 = stwo_m31_mul(b39, b36);
    b39 = stwo_m31_add(b38, b56);
    b56 = stwo_m31_add(b26, b33);
    b38 = stwo_m31_add(b27, b34);
    b36 = stwo_m31_add(b28, b35);
    b57 = stwo_m31_add(b26, b33);
    b37 = stwo_m31_add(b27, b34);
    b42 = stwo_m31_add(b28, b35);
    unsigned b58 = stwo_m31_mul(b56, b57);
    unsigned b59 = stwo_m31_sub(b58, b52);
    b58 = stwo_m31_sub(b59, b24);
    b59 = stwo_m31_add(b3, b58);
    b58 = stwo_m31_mul(b56, b37);
    b3 = stwo_m31_mul(b38, b57);
    b24 = stwo_m31_add(b58, b3);
    b3 = stwo_m31_sub(b24, b23);
    b24 = stwo_m31_sub(b3, b41);
    b3 = stwo_m31_add(b22, b24);
    b24 = stwo_m31_mul(b56, b42);
    b42 = stwo_m31_mul(b38, b37);
    b37 = stwo_m31_add(b24, b42);
    b42 = stwo_m31_mul(b36, b57);
    b57 = stwo_m31_add(b37, b42);
    b42 = stwo_m31_sub(b57, b2);
    b57 = stwo_m31_sub(b42, b4);
    b42 = stwo_m31_add(b0, b57);
    b57 = stwo_m31_add(b12, b26);
    b0 = stwo_m31_add(b13, b27);
    b4 = stwo_m31_add(b14, b28);
    b2 = stwo_m31_add(b15, b29);
    b37 = stwo_m31_add(b16, b30);
    b36 = stwo_m31_add(b17, b31);
    b24 = stwo_m31_add(b18, b32);
    b38 = stwo_m31_add(b19, b33);
    b56 = stwo_m31_add(b20, b34);
    b22 = stwo_m31_add(b21, b35);
    b41 = stwo_m31_add(b12, b26);
    b26 = stwo_m31_add(b13, b27);
    b27 = stwo_m31_add(b14, b28);
    b28 = stwo_m31_add(b15, b29);
    b29 = stwo_m31_add(b16, b30);
    b30 = stwo_m31_add(b17, b31);
    b31 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_add(b19, b33);
    b33 = stwo_m31_add(b20, b34);
    b34 = stwo_m31_add(b21, b35);
    b35 = stwo_m31_mul(b57, b41);
    b21 = stwo_m31_mul(b57, b26);
    b20 = stwo_m31_mul(b0, b41);
    b19 = stwo_m31_add(b21, b20);
    b20 = stwo_m31_mul(b57, b27);
    b21 = stwo_m31_mul(b0, b26);
    b18 = stwo_m31_add(b20, b21);
    b21 = stwo_m31_mul(b4, b41);
    b20 = stwo_m31_add(b18, b21);
    b21 = stwo_m31_mul(b0, b31);
    b18 = stwo_m31_mul(b4, b30);
    b17 = stwo_m31_add(b21, b18);
    b18 = stwo_m31_mul(b2, b29);
    b21 = stwo_m31_add(b17, b18);
    b18 = stwo_m31_mul(b37, b28);
    b17 = stwo_m31_add(b21, b18);
    b18 = stwo_m31_mul(b36, b27);
    b21 = stwo_m31_add(b17, b18);
    b18 = stwo_m31_mul(b24, b26);
    b17 = stwo_m31_add(b21, b18);
    b18 = stwo_m31_mul(b4, b31);
    b21 = stwo_m31_mul(b2, b30);
    b16 = stwo_m31_add(b18, b21);
    b21 = stwo_m31_mul(b37, b29);
    b18 = stwo_m31_add(b16, b21);
    b21 = stwo_m31_mul(b36, b28);
    b16 = stwo_m31_add(b18, b21);
    b21 = stwo_m31_mul(b24, b27);
    b18 = stwo_m31_add(b16, b21);
    b21 = stwo_m31_mul(b2, b31);
    b31 = stwo_m31_mul(b37, b30);
    b30 = stwo_m31_add(b21, b31);
    b31 = stwo_m31_mul(b36, b29);
    b29 = stwo_m31_add(b30, b31);
    b31 = stwo_m31_mul(b24, b28);
    b28 = stwo_m31_add(b29, b31);
    b31 = stwo_m31_mul(b38, b32);
    b29 = stwo_m31_mul(b38, b33);
    b24 = stwo_m31_mul(b56, b32);
    b30 = stwo_m31_add(b29, b24);
    b24 = stwo_m31_mul(b38, b34);
    b29 = stwo_m31_mul(b56, b33);
    b36 = stwo_m31_add(b24, b29);
    b29 = stwo_m31_mul(b22, b32);
    b24 = stwo_m31_add(b36, b29);
    b29 = stwo_m31_add(b57, b38);
    b38 = stwo_m31_add(b0, b56);
    b56 = stwo_m31_add(b4, b22);
    b22 = stwo_m31_add(b41, b32);
    b32 = stwo_m31_add(b26, b33);
    b33 = stwo_m31_add(b27, b34);
    b34 = stwo_m31_mul(b29, b22);
    b27 = stwo_m31_sub(b34, b35);
    b34 = stwo_m31_sub(b27, b31);
    b27 = stwo_m31_add(b17, b34);
    b34 = stwo_m31_mul(b29, b32);
    b17 = stwo_m31_mul(b38, b22);
    b31 = stwo_m31_add(b34, b17);
    b17 = stwo_m31_sub(b31, b19);
    b31 = stwo_m31_sub(b17, b30);
    b17 = stwo_m31_add(b18, b31);
    b31 = stwo_m31_mul(b29, b33);
    b33 = stwo_m31_mul(b38, b32);
    b32 = stwo_m31_add(b31, b33);
    b33 = stwo_m31_mul(b56, b22);
    b22 = stwo_m31_add(b32, b33);
    b33 = stwo_m31_sub(b22, b20);
    b22 = stwo_m31_sub(b33, b24);
    b33 = stwo_m31_add(b28, b22);
    b22 = stwo_m31_sub(b27, b54);
    b27 = stwo_m31_sub(b22, b59);
    b22 = stwo_m31_add(b40, b27);
    b27 = stwo_m31_sub(b17, b43);
    b17 = stwo_m31_sub(b27, b3);
    b27 = stwo_m31_add(b1, b17);
    b17 = stwo_m31_sub(b33, b45);
    b33 = stwo_m31_sub(b17, b42);
    b17 = stwo_m31_add(b25, b33);
    b33 = stwo_m31_sub(b51, b6);
    b51 = stwo_m31_sub(b44, b7);
    b44 = stwo_m31_sub(b5, b8);
    b5 = stwo_m31_sub(b22, b9);
    b22 = stwo_m31_sub(b27, b10);
    b27 = stwo_m31_sub(b17, b11);
    b17 = 32u;
    b11 = stwo_m31_mul(b17, b33);
    b17 = 4u;
    b10 = stwo_m31_mul(b17, b5);
    b17 = stwo_m31_sub(b11, b10);
    b10 = 8u;
    b11 = stwo_m31_mul(b10, b55);
    b10 = stwo_m31_add(b17, b11);
    b11 = 32u;
    b17 = stwo_m31_mul(b11, b51);
    b11 = stwo_m31_add(b33, b17);
    b17 = 4u;
    b33 = stwo_m31_mul(b17, b22);
    b17 = stwo_m31_sub(b11, b33);
    b33 = 8u;
    b11 = stwo_m31_mul(b33, b53);
    b33 = stwo_m31_add(b17, b11);
    b11 = 32u;
    b17 = stwo_m31_mul(b11, b44);
    b11 = stwo_m31_add(b51, b17);
    b17 = 4u;
    b51 = stwo_m31_mul(b17, b27);
    b17 = stwo_m31_sub(b11, b51);
    b51 = 8u;
    b11 = stwo_m31_mul(b51, b39);
    b51 = stwo_m31_add(b17, b11);
    b11 = 512u;
    b17 = stwo_m31_mul(b47, b11);
    b11 = stwo_m31_sub(b10, b46);
    b10 = stwo_m31_sub(b17, b11);
    b11 = 512u;
    b17 = stwo_m31_mul(b48, b11);
    b11 = stwo_m31_add(b33, b47);
    b33 = stwo_m31_sub(b17, b11);
    b11 = 512u;
    b17 = stwo_m31_mul(b49, b11);
    b11 = stwo_m31_add(b51, b48);
    b51 = stwo_m31_sub(b17, b11);
    StwoCairoQm31 e0 = { b10, b50, b50, b50 };
    StwoCairoQm31 e1 = { b33, b50, b50, b50 };
    StwoCairoQm31 e2 = { b51, b50, b50, b50 };
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
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
