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
stwo_cairo_cuda_eval_v1_012eee488bb50654(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 143u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 144u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 145u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 199u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 200u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 201u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 202u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 234u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 235u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 236u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 237u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 238u, row, 0);
    unsigned b45 = 0u;
    unsigned b46 = stwo_m31_add(b0, b4);
    b4 = stwo_m31_add(b46, b36);
    b46 = stwo_m31_add(b1, b5);
    b5 = stwo_m31_add(b46, b37);
    b46 = stwo_m31_add(b2, b6);
    b6 = stwo_m31_add(b46, b38);
    b46 = stwo_m31_add(b3, b7);
    b7 = stwo_m31_add(b46, b39);
    b46 = stwo_m31_mul(b8, b9);
    b39 = stwo_m31_mul(b9, b8);
    b3 = stwo_m31_add(b46, b39);
    b39 = stwo_m31_mul(b8, b10);
    b46 = stwo_m31_mul(b9, b9);
    b38 = stwo_m31_add(b39, b46);
    b46 = stwo_m31_mul(b10, b8);
    b39 = stwo_m31_add(b38, b46);
    b46 = stwo_m31_mul(b8, b11);
    b38 = stwo_m31_mul(b9, b10);
    b2 = stwo_m31_add(b46, b38);
    b38 = stwo_m31_mul(b10, b9);
    b46 = stwo_m31_add(b2, b38);
    b38 = stwo_m31_mul(b11, b8);
    b2 = stwo_m31_add(b46, b38);
    b38 = stwo_m31_mul(b8, b12);
    b46 = stwo_m31_mul(b9, b11);
    b37 = stwo_m31_add(b38, b46);
    b46 = stwo_m31_mul(b10, b10);
    b38 = stwo_m31_add(b37, b46);
    b46 = stwo_m31_mul(b11, b9);
    b37 = stwo_m31_add(b38, b46);
    b46 = stwo_m31_mul(b12, b8);
    b38 = stwo_m31_add(b37, b46);
    b46 = stwo_m31_mul(b10, b14);
    b37 = stwo_m31_mul(b11, b13);
    b1 = stwo_m31_add(b46, b37);
    b37 = stwo_m31_mul(b12, b12);
    b46 = stwo_m31_add(b1, b37);
    b37 = stwo_m31_mul(b13, b11);
    b1 = stwo_m31_add(b46, b37);
    b37 = stwo_m31_mul(b14, b10);
    b46 = stwo_m31_add(b1, b37);
    b37 = stwo_m31_mul(b11, b14);
    b1 = stwo_m31_mul(b12, b13);
    b36 = stwo_m31_add(b37, b1);
    b1 = stwo_m31_mul(b13, b12);
    b37 = stwo_m31_add(b36, b1);
    b1 = stwo_m31_mul(b14, b11);
    b36 = stwo_m31_add(b37, b1);
    b1 = stwo_m31_mul(b12, b14);
    b37 = stwo_m31_mul(b13, b13);
    b0 = stwo_m31_add(b1, b37);
    b37 = stwo_m31_mul(b14, b12);
    b1 = stwo_m31_add(b0, b37);
    b37 = stwo_m31_mul(b13, b14);
    b0 = stwo_m31_mul(b14, b13);
    unsigned b47 = stwo_m31_add(b37, b0);
    b0 = stwo_m31_mul(b15, b16);
    b37 = stwo_m31_mul(b16, b15);
    unsigned b48 = stwo_m31_add(b0, b37);
    b37 = stwo_m31_mul(b15, b17);
    b0 = stwo_m31_mul(b16, b16);
    unsigned b49 = stwo_m31_add(b37, b0);
    b0 = stwo_m31_mul(b17, b15);
    b37 = stwo_m31_add(b49, b0);
    b0 = stwo_m31_mul(b15, b18);
    b49 = stwo_m31_mul(b16, b17);
    unsigned b50 = stwo_m31_add(b0, b49);
    b49 = stwo_m31_mul(b17, b16);
    b0 = stwo_m31_add(b50, b49);
    b49 = stwo_m31_mul(b18, b15);
    b50 = stwo_m31_add(b0, b49);
    b49 = stwo_m31_mul(b15, b19);
    b0 = stwo_m31_mul(b16, b18);
    unsigned b51 = stwo_m31_add(b49, b0);
    b0 = stwo_m31_mul(b17, b17);
    b49 = stwo_m31_add(b51, b0);
    b0 = stwo_m31_mul(b18, b16);
    b16 = stwo_m31_add(b49, b0);
    b0 = stwo_m31_mul(b19, b15);
    b15 = stwo_m31_add(b16, b0);
    b0 = stwo_m31_mul(b17, b21);
    b16 = stwo_m31_mul(b18, b20);
    b49 = stwo_m31_add(b0, b16);
    b16 = stwo_m31_mul(b19, b19);
    b0 = stwo_m31_add(b49, b16);
    b16 = stwo_m31_mul(b20, b18);
    b49 = stwo_m31_add(b0, b16);
    b16 = stwo_m31_mul(b21, b17);
    b0 = stwo_m31_add(b49, b16);
    b16 = stwo_m31_mul(b18, b21);
    b49 = stwo_m31_mul(b19, b20);
    b51 = stwo_m31_add(b16, b49);
    b49 = stwo_m31_mul(b20, b19);
    b16 = stwo_m31_add(b51, b49);
    b49 = stwo_m31_mul(b21, b18);
    b51 = stwo_m31_add(b16, b49);
    b49 = stwo_m31_mul(b19, b21);
    b16 = stwo_m31_mul(b20, b20);
    unsigned b52 = stwo_m31_add(b49, b16);
    b16 = stwo_m31_mul(b21, b19);
    b49 = stwo_m31_add(b52, b16);
    b16 = stwo_m31_mul(b20, b21);
    b52 = stwo_m31_mul(b21, b20);
    unsigned b53 = stwo_m31_add(b16, b52);
    b52 = stwo_m31_add(b10, b17);
    b16 = stwo_m31_add(b11, b18);
    unsigned b54 = stwo_m31_add(b12, b19);
    unsigned b55 = stwo_m31_add(b13, b20);
    unsigned b56 = stwo_m31_add(b14, b21);
    unsigned b57 = stwo_m31_add(b10, b17);
    b17 = stwo_m31_add(b11, b18);
    b18 = stwo_m31_add(b12, b19);
    b19 = stwo_m31_add(b13, b20);
    b20 = stwo_m31_add(b14, b21);
    b21 = stwo_m31_mul(b52, b20);
    b52 = stwo_m31_mul(b16, b19);
    b14 = stwo_m31_add(b21, b52);
    b52 = stwo_m31_mul(b54, b18);
    b21 = stwo_m31_add(b14, b52);
    b52 = stwo_m31_mul(b55, b17);
    b14 = stwo_m31_add(b21, b52);
    b52 = stwo_m31_mul(b56, b57);
    b57 = stwo_m31_add(b14, b52);
    b52 = stwo_m31_sub(b57, b46);
    b57 = stwo_m31_sub(b52, b0);
    b52 = stwo_m31_add(b48, b57);
    b57 = stwo_m31_mul(b16, b20);
    b16 = stwo_m31_mul(b54, b19);
    b48 = stwo_m31_add(b57, b16);
    b16 = stwo_m31_mul(b55, b18);
    b57 = stwo_m31_add(b48, b16);
    b16 = stwo_m31_mul(b56, b17);
    b17 = stwo_m31_add(b57, b16);
    b16 = stwo_m31_sub(b17, b36);
    b17 = stwo_m31_sub(b16, b51);
    b16 = stwo_m31_add(b37, b17);
    b17 = stwo_m31_mul(b54, b20);
    b54 = stwo_m31_mul(b55, b19);
    b37 = stwo_m31_add(b17, b54);
    b54 = stwo_m31_mul(b56, b18);
    b18 = stwo_m31_add(b37, b54);
    b54 = stwo_m31_sub(b18, b1);
    b18 = stwo_m31_sub(b54, b49);
    b54 = stwo_m31_add(b50, b18);
    b18 = stwo_m31_mul(b55, b20);
    b20 = stwo_m31_mul(b56, b19);
    b19 = stwo_m31_add(b18, b20);
    b20 = stwo_m31_sub(b19, b47);
    b19 = stwo_m31_sub(b20, b53);
    b20 = stwo_m31_add(b15, b19);
    b19 = stwo_m31_mul(b22, b23);
    b15 = stwo_m31_mul(b23, b22);
    b53 = stwo_m31_add(b19, b15);
    b15 = stwo_m31_mul(b22, b24);
    b19 = stwo_m31_mul(b23, b23);
    b47 = stwo_m31_add(b15, b19);
    b19 = stwo_m31_mul(b24, b22);
    b15 = stwo_m31_add(b47, b19);
    b19 = stwo_m31_mul(b22, b25);
    b47 = stwo_m31_mul(b23, b24);
    b18 = stwo_m31_add(b19, b47);
    b47 = stwo_m31_mul(b24, b23);
    b19 = stwo_m31_add(b18, b47);
    b47 = stwo_m31_mul(b25, b22);
    b18 = stwo_m31_add(b19, b47);
    b47 = stwo_m31_mul(b22, b26);
    b19 = stwo_m31_mul(b23, b25);
    b56 = stwo_m31_add(b47, b19);
    b19 = stwo_m31_mul(b24, b24);
    b47 = stwo_m31_add(b56, b19);
    b19 = stwo_m31_mul(b25, b23);
    b56 = stwo_m31_add(b47, b19);
    b19 = stwo_m31_mul(b26, b22);
    b47 = stwo_m31_add(b56, b19);
    b19 = stwo_m31_mul(b24, b28);
    b56 = stwo_m31_mul(b25, b27);
    b55 = stwo_m31_add(b19, b56);
    b56 = stwo_m31_mul(b26, b26);
    b19 = stwo_m31_add(b55, b56);
    b56 = stwo_m31_mul(b27, b25);
    b55 = stwo_m31_add(b19, b56);
    b56 = stwo_m31_mul(b28, b24);
    b19 = stwo_m31_add(b55, b56);
    b56 = stwo_m31_mul(b25, b28);
    b55 = stwo_m31_mul(b26, b27);
    b50 = stwo_m31_add(b56, b55);
    b55 = stwo_m31_mul(b27, b26);
    b56 = stwo_m31_add(b50, b55);
    b55 = stwo_m31_mul(b28, b25);
    b50 = stwo_m31_add(b56, b55);
    b55 = stwo_m31_mul(b26, b28);
    b56 = stwo_m31_mul(b27, b27);
    b49 = stwo_m31_add(b55, b56);
    b56 = stwo_m31_mul(b28, b26);
    b55 = stwo_m31_add(b49, b56);
    b56 = stwo_m31_mul(b27, b28);
    b49 = stwo_m31_mul(b28, b27);
    b1 = stwo_m31_add(b56, b49);
    b49 = stwo_m31_mul(b29, b30);
    b56 = stwo_m31_mul(b30, b29);
    b37 = stwo_m31_add(b49, b56);
    b56 = stwo_m31_mul(b29, b31);
    b49 = stwo_m31_mul(b30, b30);
    b17 = stwo_m31_add(b56, b49);
    b49 = stwo_m31_mul(b31, b29);
    b56 = stwo_m31_add(b17, b49);
    b49 = stwo_m31_mul(b29, b32);
    b17 = stwo_m31_mul(b30, b31);
    b51 = stwo_m31_add(b49, b17);
    b17 = stwo_m31_mul(b31, b30);
    b49 = stwo_m31_add(b51, b17);
    b17 = stwo_m31_mul(b32, b29);
    b51 = stwo_m31_add(b49, b17);
    b17 = stwo_m31_mul(b29, b33);
    b49 = stwo_m31_mul(b30, b32);
    b36 = stwo_m31_add(b17, b49);
    b49 = stwo_m31_mul(b31, b31);
    b17 = stwo_m31_add(b36, b49);
    b49 = stwo_m31_mul(b32, b30);
    b36 = stwo_m31_add(b17, b49);
    b49 = stwo_m31_mul(b33, b29);
    b29 = stwo_m31_add(b36, b49);
    b49 = stwo_m31_mul(b30, b35);
    b36 = stwo_m31_mul(b31, b34);
    b17 = stwo_m31_add(b49, b36);
    b36 = stwo_m31_mul(b32, b33);
    b49 = stwo_m31_add(b17, b36);
    b36 = stwo_m31_mul(b33, b32);
    b17 = stwo_m31_add(b49, b36);
    b36 = stwo_m31_mul(b34, b31);
    b49 = stwo_m31_add(b17, b36);
    b36 = stwo_m31_mul(b35, b30);
    b30 = stwo_m31_add(b49, b36);
    b36 = stwo_m31_mul(b31, b35);
    b49 = stwo_m31_mul(b32, b34);
    b17 = stwo_m31_add(b36, b49);
    b49 = stwo_m31_mul(b33, b33);
    b36 = stwo_m31_add(b17, b49);
    b49 = stwo_m31_mul(b34, b32);
    b17 = stwo_m31_add(b36, b49);
    b49 = stwo_m31_mul(b35, b31);
    b36 = stwo_m31_add(b17, b49);
    b49 = stwo_m31_mul(b32, b35);
    b17 = stwo_m31_mul(b33, b34);
    b57 = stwo_m31_add(b49, b17);
    b17 = stwo_m31_mul(b34, b33);
    b49 = stwo_m31_add(b57, b17);
    b17 = stwo_m31_mul(b35, b32);
    b57 = stwo_m31_add(b49, b17);
    b17 = stwo_m31_mul(b33, b35);
    b49 = stwo_m31_mul(b34, b34);
    b48 = stwo_m31_add(b17, b49);
    b49 = stwo_m31_mul(b35, b33);
    b17 = stwo_m31_add(b48, b49);
    b49 = stwo_m31_mul(b34, b35);
    b48 = stwo_m31_mul(b35, b34);
    b0 = stwo_m31_add(b49, b48);
    b48 = stwo_m31_add(b24, b31);
    b49 = stwo_m31_add(b25, b32);
    b46 = stwo_m31_add(b26, b33);
    b14 = stwo_m31_add(b27, b34);
    b21 = stwo_m31_add(b28, b35);
    b13 = stwo_m31_add(b24, b31);
    b31 = stwo_m31_add(b25, b32);
    b32 = stwo_m31_add(b26, b33);
    b33 = stwo_m31_add(b27, b34);
    b34 = stwo_m31_add(b28, b35);
    b35 = stwo_m31_mul(b48, b34);
    b48 = stwo_m31_mul(b49, b33);
    b28 = stwo_m31_add(b35, b48);
    b48 = stwo_m31_mul(b46, b32);
    b35 = stwo_m31_add(b28, b48);
    b48 = stwo_m31_mul(b14, b31);
    b28 = stwo_m31_add(b35, b48);
    b48 = stwo_m31_mul(b21, b13);
    b13 = stwo_m31_add(b28, b48);
    b48 = stwo_m31_sub(b13, b19);
    b13 = stwo_m31_sub(b48, b36);
    b48 = stwo_m31_add(b37, b13);
    b13 = stwo_m31_mul(b49, b34);
    b49 = stwo_m31_mul(b46, b33);
    b37 = stwo_m31_add(b13, b49);
    b49 = stwo_m31_mul(b14, b32);
    b13 = stwo_m31_add(b37, b49);
    b49 = stwo_m31_mul(b21, b31);
    b31 = stwo_m31_add(b13, b49);
    b49 = stwo_m31_sub(b31, b50);
    b31 = stwo_m31_sub(b49, b57);
    b49 = stwo_m31_add(b56, b31);
    b31 = stwo_m31_mul(b46, b34);
    b46 = stwo_m31_mul(b14, b33);
    b56 = stwo_m31_add(b31, b46);
    b46 = stwo_m31_mul(b21, b32);
    b32 = stwo_m31_add(b56, b46);
    b46 = stwo_m31_sub(b32, b55);
    b32 = stwo_m31_sub(b46, b17);
    b46 = stwo_m31_add(b51, b32);
    b32 = stwo_m31_mul(b14, b34);
    b34 = stwo_m31_mul(b21, b33);
    b33 = stwo_m31_add(b32, b34);
    b34 = stwo_m31_sub(b33, b1);
    b33 = stwo_m31_sub(b34, b0);
    b34 = stwo_m31_add(b29, b33);
    b33 = stwo_m31_add(b8, b22);
    b29 = stwo_m31_add(b9, b23);
    b1 = stwo_m31_add(b10, b24);
    b32 = stwo_m31_add(b11, b25);
    b21 = stwo_m31_add(b12, b26);
    b14 = stwo_m31_add(b8, b22);
    b22 = stwo_m31_add(b9, b23);
    b23 = stwo_m31_add(b10, b24);
    b24 = stwo_m31_add(b11, b25);
    b25 = stwo_m31_add(b12, b26);
    b26 = stwo_m31_mul(b33, b22);
    b12 = stwo_m31_mul(b29, b14);
    b11 = stwo_m31_add(b26, b12);
    b12 = stwo_m31_mul(b33, b23);
    b26 = stwo_m31_mul(b29, b22);
    b10 = stwo_m31_add(b12, b26);
    b26 = stwo_m31_mul(b1, b14);
    b12 = stwo_m31_add(b10, b26);
    b26 = stwo_m31_mul(b33, b24);
    b10 = stwo_m31_mul(b29, b23);
    b9 = stwo_m31_add(b26, b10);
    b10 = stwo_m31_mul(b1, b22);
    b26 = stwo_m31_add(b9, b10);
    b10 = stwo_m31_mul(b32, b14);
    b9 = stwo_m31_add(b26, b10);
    b10 = stwo_m31_mul(b33, b25);
    b25 = stwo_m31_mul(b29, b24);
    b24 = stwo_m31_add(b10, b25);
    b25 = stwo_m31_mul(b1, b23);
    b23 = stwo_m31_add(b24, b25);
    b25 = stwo_m31_mul(b32, b22);
    b22 = stwo_m31_add(b23, b25);
    b25 = stwo_m31_mul(b21, b14);
    b14 = stwo_m31_add(b22, b25);
    b25 = stwo_m31_sub(b11, b3);
    b11 = stwo_m31_sub(b25, b53);
    b25 = stwo_m31_add(b52, b11);
    b11 = stwo_m31_sub(b12, b39);
    b12 = stwo_m31_sub(b11, b15);
    b11 = stwo_m31_add(b16, b12);
    b12 = stwo_m31_sub(b9, b2);
    b9 = stwo_m31_sub(b12, b18);
    b12 = stwo_m31_add(b54, b9);
    b9 = stwo_m31_sub(b14, b38);
    b14 = stwo_m31_sub(b9, b47);
    b9 = stwo_m31_add(b20, b14);
    b14 = stwo_m31_sub(b25, b4);
    b25 = stwo_m31_sub(b11, b5);
    b11 = stwo_m31_sub(b12, b6);
    b12 = stwo_m31_sub(b9, b7);
    b9 = 2u;
    b7 = stwo_m31_mul(b9, b14);
    b9 = 4u;
    b14 = stwo_m31_mul(b9, b48);
    b9 = stwo_m31_sub(b7, b14);
    b14 = 2u;
    b7 = stwo_m31_mul(b14, b30);
    b14 = stwo_m31_add(b9, b7);
    b7 = 64u;
    b9 = stwo_m31_mul(b7, b36);
    b7 = stwo_m31_add(b14, b9);
    b9 = 2u;
    b14 = stwo_m31_mul(b9, b25);
    b9 = 4u;
    b25 = stwo_m31_mul(b9, b49);
    b9 = stwo_m31_sub(b14, b25);
    b25 = 2u;
    b14 = stwo_m31_mul(b25, b36);
    b25 = stwo_m31_add(b9, b14);
    b14 = 64u;
    b9 = stwo_m31_mul(b14, b57);
    b14 = stwo_m31_add(b25, b9);
    b9 = 2u;
    b25 = stwo_m31_mul(b9, b11);
    b9 = 4u;
    b11 = stwo_m31_mul(b9, b46);
    b9 = stwo_m31_sub(b25, b11);
    b11 = 2u;
    b25 = stwo_m31_mul(b11, b57);
    b11 = stwo_m31_add(b9, b25);
    b25 = 64u;
    b9 = stwo_m31_mul(b25, b17);
    b25 = stwo_m31_add(b11, b9);
    b9 = 2u;
    b11 = stwo_m31_mul(b9, b12);
    b9 = 4u;
    b12 = stwo_m31_mul(b9, b34);
    b9 = stwo_m31_sub(b11, b12);
    b12 = 2u;
    b11 = stwo_m31_mul(b12, b17);
    b12 = stwo_m31_add(b9, b11);
    b11 = 64u;
    b9 = stwo_m31_mul(b11, b0);
    b11 = stwo_m31_add(b12, b9);
    b9 = 512u;
    b12 = stwo_m31_mul(b41, b9);
    b9 = stwo_m31_add(b7, b40);
    b7 = stwo_m31_sub(b12, b9);
    b9 = 512u;
    b12 = stwo_m31_mul(b42, b9);
    b9 = stwo_m31_add(b14, b41);
    b14 = stwo_m31_sub(b12, b9);
    b9 = 512u;
    b12 = stwo_m31_mul(b43, b9);
    b9 = stwo_m31_add(b25, b42);
    b25 = stwo_m31_sub(b12, b9);
    b9 = 512u;
    b12 = stwo_m31_mul(b44, b9);
    b9 = stwo_m31_add(b11, b43);
    b11 = stwo_m31_sub(b12, b9);
    StwoCairoQm31 e0 = { b7, b45, b45, b45 };
    StwoCairoQm31 e1 = { b14, b45, b45, b45 };
    StwoCairoQm31 e2 = { b25, b45, b45, b45 };
    StwoCairoQm31 e3 = { b11, b45, b45, b45 };
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
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
