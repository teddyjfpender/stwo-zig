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
stwo_cairo_cuda_eval_v1_76c741335620d6bd(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
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
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 196u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 197u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 198u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 202u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 203u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 204u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 212u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 231u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 232u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 233u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 234u, row, 0);
    unsigned b51 = 0u;
    unsigned b52 = stwo_m31_add(b0, b6);
    b6 = stwo_m31_add(b52, b40);
    b52 = stwo_m31_add(b1, b7);
    b7 = stwo_m31_add(b52, b41);
    b52 = stwo_m31_add(b2, b8);
    b8 = stwo_m31_add(b52, b42);
    b52 = stwo_m31_add(b3, b9);
    b9 = stwo_m31_add(b52, b43);
    b52 = stwo_m31_add(b4, b10);
    b10 = stwo_m31_add(b52, b44);
    b52 = stwo_m31_add(b5, b11);
    b11 = stwo_m31_add(b52, b45);
    b52 = stwo_m31_mul(b12, b12);
    b45 = stwo_m31_mul(b12, b16);
    b5 = stwo_m31_mul(b13, b15);
    b44 = stwo_m31_add(b45, b5);
    b5 = stwo_m31_mul(b14, b14);
    b45 = stwo_m31_add(b44, b5);
    b5 = stwo_m31_mul(b15, b13);
    b44 = stwo_m31_add(b45, b5);
    b5 = stwo_m31_mul(b16, b12);
    b45 = stwo_m31_add(b44, b5);
    b5 = stwo_m31_mul(b12, b17);
    b44 = stwo_m31_mul(b13, b16);
    b4 = stwo_m31_add(b5, b44);
    b44 = stwo_m31_mul(b14, b15);
    b5 = stwo_m31_add(b4, b44);
    b44 = stwo_m31_mul(b15, b14);
    b4 = stwo_m31_add(b5, b44);
    b44 = stwo_m31_mul(b16, b13);
    b5 = stwo_m31_add(b4, b44);
    b44 = stwo_m31_mul(b17, b12);
    b4 = stwo_m31_add(b5, b44);
    b44 = stwo_m31_mul(b12, b18);
    b5 = stwo_m31_mul(b13, b17);
    b43 = stwo_m31_add(b44, b5);
    b5 = stwo_m31_mul(b14, b16);
    b44 = stwo_m31_add(b43, b5);
    b5 = stwo_m31_mul(b15, b15);
    b43 = stwo_m31_add(b44, b5);
    b5 = stwo_m31_mul(b16, b14);
    b44 = stwo_m31_add(b43, b5);
    b5 = stwo_m31_mul(b17, b13);
    b43 = stwo_m31_add(b44, b5);
    b5 = stwo_m31_mul(b18, b12);
    b44 = stwo_m31_add(b43, b5);
    b5 = stwo_m31_mul(b13, b18);
    b43 = stwo_m31_mul(b14, b17);
    b3 = stwo_m31_add(b5, b43);
    b43 = stwo_m31_mul(b15, b16);
    b5 = stwo_m31_add(b3, b43);
    b43 = stwo_m31_mul(b16, b15);
    b3 = stwo_m31_add(b5, b43);
    b43 = stwo_m31_mul(b17, b14);
    b5 = stwo_m31_add(b3, b43);
    b43 = stwo_m31_mul(b18, b13);
    b3 = stwo_m31_add(b5, b43);
    b43 = stwo_m31_mul(b17, b18);
    b5 = stwo_m31_mul(b18, b17);
    b42 = stwo_m31_add(b43, b5);
    b5 = stwo_m31_mul(b18, b18);
    b43 = stwo_m31_mul(b19, b19);
    b2 = stwo_m31_mul(b19, b23);
    b41 = stwo_m31_mul(b20, b22);
    b1 = stwo_m31_add(b2, b41);
    b41 = stwo_m31_mul(b21, b21);
    b2 = stwo_m31_add(b1, b41);
    b41 = stwo_m31_mul(b22, b20);
    b1 = stwo_m31_add(b2, b41);
    b41 = stwo_m31_mul(b23, b19);
    b2 = stwo_m31_add(b1, b41);
    b41 = stwo_m31_mul(b19, b24);
    b1 = stwo_m31_mul(b20, b23);
    b40 = stwo_m31_add(b41, b1);
    b1 = stwo_m31_mul(b21, b22);
    b41 = stwo_m31_add(b40, b1);
    b1 = stwo_m31_mul(b22, b21);
    b40 = stwo_m31_add(b41, b1);
    b1 = stwo_m31_mul(b23, b20);
    b41 = stwo_m31_add(b40, b1);
    b1 = stwo_m31_mul(b24, b19);
    b40 = stwo_m31_add(b41, b1);
    b1 = stwo_m31_mul(b19, b25);
    b41 = stwo_m31_mul(b20, b24);
    b0 = stwo_m31_add(b1, b41);
    b41 = stwo_m31_mul(b21, b23);
    b1 = stwo_m31_add(b0, b41);
    b41 = stwo_m31_mul(b22, b22);
    b0 = stwo_m31_add(b1, b41);
    b41 = stwo_m31_mul(b23, b21);
    b1 = stwo_m31_add(b0, b41);
    b41 = stwo_m31_mul(b24, b20);
    b0 = stwo_m31_add(b1, b41);
    b41 = stwo_m31_mul(b25, b19);
    b1 = stwo_m31_add(b0, b41);
    b41 = stwo_m31_mul(b20, b25);
    b0 = stwo_m31_mul(b21, b24);
    unsigned b53 = stwo_m31_add(b41, b0);
    b0 = stwo_m31_mul(b22, b23);
    b41 = stwo_m31_add(b53, b0);
    b0 = stwo_m31_mul(b23, b22);
    b53 = stwo_m31_add(b41, b0);
    b0 = stwo_m31_mul(b24, b21);
    b41 = stwo_m31_add(b53, b0);
    b0 = stwo_m31_mul(b25, b20);
    b53 = stwo_m31_add(b41, b0);
    b0 = stwo_m31_mul(b24, b25);
    b41 = stwo_m31_mul(b25, b24);
    unsigned b54 = stwo_m31_add(b0, b41);
    b41 = stwo_m31_mul(b25, b25);
    b0 = stwo_m31_add(b12, b19);
    unsigned b55 = stwo_m31_add(b13, b20);
    unsigned b56 = stwo_m31_add(b14, b21);
    unsigned b57 = stwo_m31_add(b15, b22);
    unsigned b58 = stwo_m31_add(b16, b23);
    unsigned b59 = stwo_m31_add(b17, b24);
    unsigned b60 = stwo_m31_add(b18, b25);
    unsigned b61 = stwo_m31_add(b12, b19);
    b19 = stwo_m31_add(b13, b20);
    b20 = stwo_m31_add(b14, b21);
    b21 = stwo_m31_add(b15, b22);
    b22 = stwo_m31_add(b16, b23);
    b23 = stwo_m31_add(b17, b24);
    b24 = stwo_m31_add(b18, b25);
    unsigned b62 = stwo_m31_mul(b0, b23);
    unsigned b63 = stwo_m31_mul(b55, b22);
    unsigned b64 = stwo_m31_add(b62, b63);
    b63 = stwo_m31_mul(b56, b21);
    b62 = stwo_m31_add(b64, b63);
    b63 = stwo_m31_mul(b57, b20);
    b64 = stwo_m31_add(b62, b63);
    b63 = stwo_m31_mul(b58, b19);
    b62 = stwo_m31_add(b64, b63);
    b63 = stwo_m31_mul(b59, b61);
    b64 = stwo_m31_add(b62, b63);
    b63 = stwo_m31_sub(b64, b4);
    b64 = stwo_m31_sub(b63, b40);
    b63 = stwo_m31_add(b5, b64);
    b64 = stwo_m31_mul(b0, b24);
    b0 = stwo_m31_mul(b55, b23);
    b62 = stwo_m31_add(b64, b0);
    b0 = stwo_m31_mul(b56, b22);
    b64 = stwo_m31_add(b62, b0);
    b0 = stwo_m31_mul(b57, b21);
    b62 = stwo_m31_add(b64, b0);
    b0 = stwo_m31_mul(b58, b20);
    b64 = stwo_m31_add(b62, b0);
    b0 = stwo_m31_mul(b59, b19);
    b62 = stwo_m31_add(b64, b0);
    b0 = stwo_m31_mul(b60, b61);
    b61 = stwo_m31_add(b62, b0);
    b0 = stwo_m31_sub(b61, b44);
    b61 = stwo_m31_sub(b0, b1);
    b0 = stwo_m31_mul(b55, b24);
    b55 = stwo_m31_mul(b56, b23);
    b56 = stwo_m31_add(b0, b55);
    b55 = stwo_m31_mul(b57, b22);
    b22 = stwo_m31_add(b56, b55);
    b55 = stwo_m31_mul(b58, b21);
    b21 = stwo_m31_add(b22, b55);
    b55 = stwo_m31_mul(b59, b20);
    b20 = stwo_m31_add(b21, b55);
    b55 = stwo_m31_mul(b60, b19);
    b19 = stwo_m31_add(b20, b55);
    b55 = stwo_m31_sub(b19, b3);
    b19 = stwo_m31_sub(b55, b53);
    b55 = stwo_m31_add(b43, b19);
    b19 = stwo_m31_mul(b59, b24);
    b59 = stwo_m31_mul(b60, b23);
    b23 = stwo_m31_add(b19, b59);
    b59 = stwo_m31_sub(b23, b42);
    b23 = stwo_m31_sub(b59, b54);
    b59 = stwo_m31_add(b2, b23);
    b23 = stwo_m31_mul(b60, b24);
    b24 = stwo_m31_sub(b23, b5);
    b23 = stwo_m31_sub(b24, b41);
    b24 = stwo_m31_add(b40, b23);
    b23 = stwo_m31_mul(b26, b26);
    b40 = stwo_m31_mul(b26, b30);
    b5 = stwo_m31_mul(b27, b29);
    b60 = stwo_m31_add(b40, b5);
    b5 = stwo_m31_mul(b28, b28);
    b40 = stwo_m31_add(b60, b5);
    b5 = stwo_m31_mul(b29, b27);
    b60 = stwo_m31_add(b40, b5);
    b5 = stwo_m31_mul(b30, b26);
    b40 = stwo_m31_add(b60, b5);
    b5 = stwo_m31_mul(b26, b31);
    b60 = stwo_m31_mul(b27, b30);
    b2 = stwo_m31_add(b5, b60);
    b60 = stwo_m31_mul(b28, b29);
    b5 = stwo_m31_add(b2, b60);
    b60 = stwo_m31_mul(b29, b28);
    b2 = stwo_m31_add(b5, b60);
    b60 = stwo_m31_mul(b30, b27);
    b5 = stwo_m31_add(b2, b60);
    b60 = stwo_m31_mul(b31, b26);
    b2 = stwo_m31_add(b5, b60);
    b60 = stwo_m31_mul(b26, b32);
    b5 = stwo_m31_mul(b27, b31);
    b54 = stwo_m31_add(b60, b5);
    b5 = stwo_m31_mul(b28, b30);
    b60 = stwo_m31_add(b54, b5);
    b5 = stwo_m31_mul(b29, b29);
    b54 = stwo_m31_add(b60, b5);
    b5 = stwo_m31_mul(b30, b28);
    b60 = stwo_m31_add(b54, b5);
    b5 = stwo_m31_mul(b31, b27);
    b54 = stwo_m31_add(b60, b5);
    b5 = stwo_m31_mul(b32, b26);
    b60 = stwo_m31_add(b54, b5);
    b5 = stwo_m31_mul(b27, b32);
    b54 = stwo_m31_mul(b28, b31);
    b42 = stwo_m31_add(b5, b54);
    b54 = stwo_m31_mul(b29, b30);
    b5 = stwo_m31_add(b42, b54);
    b54 = stwo_m31_mul(b30, b29);
    b42 = stwo_m31_add(b5, b54);
    b54 = stwo_m31_mul(b31, b28);
    b5 = stwo_m31_add(b42, b54);
    b54 = stwo_m31_mul(b32, b27);
    b42 = stwo_m31_add(b5, b54);
    b54 = stwo_m31_mul(b32, b32);
    b5 = stwo_m31_mul(b33, b33);
    b19 = stwo_m31_mul(b33, b38);
    b43 = stwo_m31_mul(b34, b37);
    b53 = stwo_m31_add(b19, b43);
    b43 = stwo_m31_mul(b35, b36);
    b19 = stwo_m31_add(b53, b43);
    b43 = stwo_m31_mul(b36, b35);
    b53 = stwo_m31_add(b19, b43);
    b43 = stwo_m31_mul(b37, b34);
    b19 = stwo_m31_add(b53, b43);
    b43 = stwo_m31_mul(b38, b33);
    b53 = stwo_m31_add(b19, b43);
    b43 = stwo_m31_mul(b33, b39);
    b19 = stwo_m31_mul(b34, b38);
    b3 = stwo_m31_add(b43, b19);
    b19 = stwo_m31_mul(b35, b37);
    b43 = stwo_m31_add(b3, b19);
    b19 = stwo_m31_mul(b36, b36);
    b3 = stwo_m31_add(b43, b19);
    b19 = stwo_m31_mul(b37, b35);
    b43 = stwo_m31_add(b3, b19);
    b19 = stwo_m31_mul(b38, b34);
    b3 = stwo_m31_add(b43, b19);
    b19 = stwo_m31_mul(b39, b33);
    b43 = stwo_m31_add(b3, b19);
    b19 = stwo_m31_mul(b34, b39);
    b3 = stwo_m31_mul(b35, b38);
    b20 = stwo_m31_add(b19, b3);
    b3 = stwo_m31_mul(b36, b37);
    b19 = stwo_m31_add(b20, b3);
    b3 = stwo_m31_mul(b37, b36);
    b20 = stwo_m31_add(b19, b3);
    b3 = stwo_m31_mul(b38, b35);
    b19 = stwo_m31_add(b20, b3);
    b3 = stwo_m31_mul(b39, b34);
    b20 = stwo_m31_add(b19, b3);
    b3 = stwo_m31_mul(b39, b39);
    b19 = stwo_m31_add(b26, b33);
    b21 = stwo_m31_add(b27, b34);
    b22 = stwo_m31_add(b28, b35);
    b58 = stwo_m31_add(b29, b36);
    b56 = stwo_m31_add(b30, b37);
    b57 = stwo_m31_add(b31, b38);
    b0 = stwo_m31_add(b32, b39);
    b62 = stwo_m31_add(b26, b33);
    b33 = stwo_m31_add(b27, b34);
    b34 = stwo_m31_add(b28, b35);
    b35 = stwo_m31_add(b29, b36);
    b36 = stwo_m31_add(b30, b37);
    b37 = stwo_m31_add(b31, b38);
    b38 = stwo_m31_add(b32, b39);
    b64 = stwo_m31_mul(b19, b37);
    unsigned b65 = stwo_m31_mul(b21, b36);
    unsigned b66 = stwo_m31_add(b64, b65);
    b65 = stwo_m31_mul(b22, b35);
    b64 = stwo_m31_add(b66, b65);
    b65 = stwo_m31_mul(b58, b34);
    b66 = stwo_m31_add(b64, b65);
    b65 = stwo_m31_mul(b56, b33);
    b64 = stwo_m31_add(b66, b65);
    b65 = stwo_m31_mul(b57, b62);
    b66 = stwo_m31_add(b64, b65);
    b65 = stwo_m31_sub(b66, b2);
    b66 = stwo_m31_sub(b65, b53);
    b65 = stwo_m31_add(b54, b66);
    b66 = stwo_m31_mul(b19, b38);
    b19 = stwo_m31_mul(b21, b37);
    b54 = stwo_m31_add(b66, b19);
    b19 = stwo_m31_mul(b22, b36);
    b66 = stwo_m31_add(b54, b19);
    b19 = stwo_m31_mul(b58, b35);
    b54 = stwo_m31_add(b66, b19);
    b19 = stwo_m31_mul(b56, b34);
    b66 = stwo_m31_add(b54, b19);
    b19 = stwo_m31_mul(b57, b33);
    b54 = stwo_m31_add(b66, b19);
    b19 = stwo_m31_mul(b0, b62);
    b62 = stwo_m31_add(b54, b19);
    b19 = stwo_m31_sub(b62, b60);
    b62 = stwo_m31_sub(b19, b43);
    b19 = stwo_m31_mul(b21, b38);
    b38 = stwo_m31_mul(b22, b37);
    b37 = stwo_m31_add(b19, b38);
    b38 = stwo_m31_mul(b58, b36);
    b36 = stwo_m31_add(b37, b38);
    b38 = stwo_m31_mul(b56, b35);
    b35 = stwo_m31_add(b36, b38);
    b38 = stwo_m31_mul(b57, b34);
    b34 = stwo_m31_add(b35, b38);
    b38 = stwo_m31_mul(b0, b33);
    b33 = stwo_m31_add(b34, b38);
    b38 = stwo_m31_sub(b33, b42);
    b33 = stwo_m31_sub(b38, b20);
    b38 = stwo_m31_add(b5, b33);
    b33 = stwo_m31_add(b12, b26);
    b5 = stwo_m31_add(b13, b27);
    b42 = stwo_m31_add(b14, b28);
    b34 = stwo_m31_add(b15, b29);
    b0 = stwo_m31_add(b16, b30);
    b35 = stwo_m31_add(b17, b31);
    b57 = stwo_m31_add(b18, b32);
    b36 = stwo_m31_add(b25, b39);
    b56 = stwo_m31_add(b12, b26);
    b26 = stwo_m31_add(b13, b27);
    b27 = stwo_m31_add(b14, b28);
    b28 = stwo_m31_add(b15, b29);
    b29 = stwo_m31_add(b16, b30);
    b30 = stwo_m31_add(b17, b31);
    b31 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_add(b25, b39);
    b39 = stwo_m31_mul(b33, b56);
    b25 = stwo_m31_mul(b33, b29);
    b18 = stwo_m31_mul(b5, b28);
    b17 = stwo_m31_add(b25, b18);
    b18 = stwo_m31_mul(b42, b27);
    b25 = stwo_m31_add(b17, b18);
    b18 = stwo_m31_mul(b34, b26);
    b17 = stwo_m31_add(b25, b18);
    b18 = stwo_m31_mul(b0, b56);
    b25 = stwo_m31_add(b17, b18);
    b18 = stwo_m31_mul(b33, b30);
    b17 = stwo_m31_mul(b5, b29);
    b16 = stwo_m31_add(b18, b17);
    b17 = stwo_m31_mul(b42, b28);
    b18 = stwo_m31_add(b16, b17);
    b17 = stwo_m31_mul(b34, b27);
    b16 = stwo_m31_add(b18, b17);
    b17 = stwo_m31_mul(b0, b26);
    b18 = stwo_m31_add(b16, b17);
    b17 = stwo_m31_mul(b35, b56);
    b16 = stwo_m31_add(b18, b17);
    b17 = stwo_m31_mul(b33, b31);
    b31 = stwo_m31_mul(b5, b30);
    b30 = stwo_m31_add(b17, b31);
    b31 = stwo_m31_mul(b42, b29);
    b29 = stwo_m31_add(b30, b31);
    b31 = stwo_m31_mul(b34, b28);
    b28 = stwo_m31_add(b29, b31);
    b31 = stwo_m31_mul(b0, b27);
    b27 = stwo_m31_add(b28, b31);
    b31 = stwo_m31_mul(b35, b26);
    b26 = stwo_m31_add(b27, b31);
    b31 = stwo_m31_mul(b57, b56);
    b56 = stwo_m31_add(b26, b31);
    b31 = stwo_m31_mul(b36, b32);
    b32 = stwo_m31_sub(b39, b52);
    b39 = stwo_m31_sub(b32, b23);
    b32 = stwo_m31_add(b55, b39);
    b39 = stwo_m31_sub(b25, b45);
    b25 = stwo_m31_sub(b39, b40);
    b39 = stwo_m31_add(b59, b25);
    b25 = stwo_m31_sub(b16, b4);
    b16 = stwo_m31_sub(b25, b2);
    b25 = stwo_m31_add(b24, b16);
    b16 = stwo_m31_sub(b56, b44);
    b56 = stwo_m31_sub(b16, b60);
    b16 = stwo_m31_add(b1, b56);
    b56 = stwo_m31_sub(b31, b41);
    b31 = stwo_m31_sub(b56, b3);
    b56 = stwo_m31_add(b65, b31);
    b31 = stwo_m31_sub(b63, b6);
    b63 = stwo_m31_sub(b61, b7);
    b61 = stwo_m31_sub(b32, b8);
    b32 = stwo_m31_sub(b39, b9);
    b39 = stwo_m31_sub(b25, b10);
    b25 = stwo_m31_sub(b16, b11);
    b16 = 2u;
    b11 = stwo_m31_mul(b16, b31);
    b16 = stwo_m31_add(b11, b32);
    b11 = 32u;
    b32 = stwo_m31_mul(b11, b39);
    b11 = stwo_m31_add(b16, b32);
    b32 = 4u;
    b16 = stwo_m31_mul(b32, b56);
    b32 = stwo_m31_sub(b11, b16);
    b16 = 2u;
    b11 = stwo_m31_mul(b16, b63);
    b16 = stwo_m31_add(b11, b39);
    b11 = 32u;
    b39 = stwo_m31_mul(b11, b25);
    b11 = stwo_m31_add(b16, b39);
    b39 = 4u;
    b16 = stwo_m31_mul(b39, b62);
    b39 = stwo_m31_sub(b11, b16);
    b16 = 2u;
    b11 = stwo_m31_mul(b16, b61);
    b16 = stwo_m31_add(b11, b25);
    b11 = 4u;
    b25 = stwo_m31_mul(b11, b38);
    b11 = stwo_m31_sub(b16, b25);
    b25 = 64u;
    b16 = stwo_m31_mul(b25, b20);
    b25 = stwo_m31_add(b11, b16);
    b16 = 512u;
    b11 = stwo_m31_mul(b48, b16);
    b16 = stwo_m31_add(b32, b47);
    b32 = stwo_m31_sub(b11, b16);
    b16 = 512u;
    b11 = stwo_m31_mul(b49, b16);
    b16 = stwo_m31_add(b39, b48);
    b39 = stwo_m31_sub(b11, b16);
    b16 = 512u;
    b11 = stwo_m31_mul(b50, b16);
    b16 = 136u;
    b50 = stwo_m31_mul(b16, b46);
    b16 = stwo_m31_sub(b25, b50);
    b50 = stwo_m31_add(b16, b49);
    b16 = stwo_m31_sub(b11, b50);
    StwoCairoQm31 e0 = { b32, b51, b51, b51 };
    StwoCairoQm31 e1 = { b39, b51, b51, b51 };
    StwoCairoQm31 e2 = { b16, b51, b51, b51 };
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
