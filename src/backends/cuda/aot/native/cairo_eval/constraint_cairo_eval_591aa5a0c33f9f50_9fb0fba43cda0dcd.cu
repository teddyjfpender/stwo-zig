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
stwo_cairo_cuda_eval_v1_2d9fe464eb9cd2d9(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 143u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 144u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 145u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 190u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 191u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 192u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 196u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 197u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 198u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 199u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 225u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 226u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 227u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 228u, row, 0);
    unsigned b53 = 0u;
    unsigned b54 = stwo_m31_add(b0, b7);
    b7 = stwo_m31_add(b54, b42);
    b54 = stwo_m31_add(b1, b8);
    b8 = stwo_m31_add(b54, b43);
    b54 = stwo_m31_add(b2, b9);
    b9 = stwo_m31_add(b54, b44);
    b54 = stwo_m31_add(b3, b10);
    b10 = stwo_m31_add(b54, b45);
    b54 = stwo_m31_add(b4, b11);
    b11 = stwo_m31_add(b54, b46);
    b54 = stwo_m31_add(b5, b12);
    b12 = stwo_m31_add(b54, b47);
    b54 = stwo_m31_add(b6, b13);
    b13 = stwo_m31_add(b54, b48);
    b54 = stwo_m31_mul(b14, b14);
    b48 = stwo_m31_mul(b14, b15);
    b6 = stwo_m31_mul(b15, b14);
    b47 = stwo_m31_add(b48, b6);
    b6 = stwo_m31_mul(b14, b19);
    b48 = stwo_m31_mul(b15, b18);
    b5 = stwo_m31_add(b6, b48);
    b48 = stwo_m31_mul(b16, b17);
    b6 = stwo_m31_add(b5, b48);
    b48 = stwo_m31_mul(b17, b16);
    b5 = stwo_m31_add(b6, b48);
    b48 = stwo_m31_mul(b18, b15);
    b6 = stwo_m31_add(b5, b48);
    b48 = stwo_m31_mul(b19, b14);
    b5 = stwo_m31_add(b6, b48);
    b48 = stwo_m31_mul(b14, b20);
    b6 = stwo_m31_mul(b15, b19);
    b46 = stwo_m31_add(b48, b6);
    b6 = stwo_m31_mul(b16, b18);
    b48 = stwo_m31_add(b46, b6);
    b6 = stwo_m31_mul(b17, b17);
    b46 = stwo_m31_add(b48, b6);
    b6 = stwo_m31_mul(b18, b16);
    b48 = stwo_m31_add(b46, b6);
    b6 = stwo_m31_mul(b19, b15);
    b46 = stwo_m31_add(b48, b6);
    b6 = stwo_m31_mul(b20, b14);
    b48 = stwo_m31_add(b46, b6);
    b6 = stwo_m31_mul(b15, b20);
    b46 = stwo_m31_mul(b16, b19);
    b4 = stwo_m31_add(b6, b46);
    b46 = stwo_m31_mul(b17, b18);
    b6 = stwo_m31_add(b4, b46);
    b46 = stwo_m31_mul(b18, b17);
    b4 = stwo_m31_add(b6, b46);
    b46 = stwo_m31_mul(b19, b16);
    b6 = stwo_m31_add(b4, b46);
    b46 = stwo_m31_mul(b20, b15);
    b4 = stwo_m31_add(b6, b46);
    b46 = stwo_m31_mul(b16, b20);
    b6 = stwo_m31_mul(b17, b19);
    b45 = stwo_m31_add(b46, b6);
    b6 = stwo_m31_mul(b18, b18);
    b46 = stwo_m31_add(b45, b6);
    b6 = stwo_m31_mul(b19, b17);
    b45 = stwo_m31_add(b46, b6);
    b6 = stwo_m31_mul(b20, b16);
    b46 = stwo_m31_add(b45, b6);
    b6 = stwo_m31_mul(b20, b20);
    b45 = stwo_m31_mul(b21, b21);
    b3 = stwo_m31_mul(b21, b22);
    b44 = stwo_m31_mul(b22, b21);
    b2 = stwo_m31_add(b3, b44);
    b44 = stwo_m31_mul(b21, b26);
    b3 = stwo_m31_mul(b22, b25);
    b43 = stwo_m31_add(b44, b3);
    b3 = stwo_m31_mul(b23, b24);
    b44 = stwo_m31_add(b43, b3);
    b3 = stwo_m31_mul(b24, b23);
    b43 = stwo_m31_add(b44, b3);
    b3 = stwo_m31_mul(b25, b22);
    b44 = stwo_m31_add(b43, b3);
    b3 = stwo_m31_mul(b26, b21);
    b43 = stwo_m31_add(b44, b3);
    b3 = stwo_m31_mul(b21, b27);
    b44 = stwo_m31_mul(b22, b26);
    b1 = stwo_m31_add(b3, b44);
    b44 = stwo_m31_mul(b23, b25);
    b3 = stwo_m31_add(b1, b44);
    b44 = stwo_m31_mul(b24, b24);
    b1 = stwo_m31_add(b3, b44);
    b44 = stwo_m31_mul(b25, b23);
    b3 = stwo_m31_add(b1, b44);
    b44 = stwo_m31_mul(b26, b22);
    b1 = stwo_m31_add(b3, b44);
    b44 = stwo_m31_mul(b27, b21);
    b3 = stwo_m31_add(b1, b44);
    b44 = stwo_m31_mul(b22, b27);
    b1 = stwo_m31_mul(b23, b26);
    b42 = stwo_m31_add(b44, b1);
    b1 = stwo_m31_mul(b24, b25);
    b44 = stwo_m31_add(b42, b1);
    b1 = stwo_m31_mul(b25, b24);
    b42 = stwo_m31_add(b44, b1);
    b1 = stwo_m31_mul(b26, b23);
    b44 = stwo_m31_add(b42, b1);
    b1 = stwo_m31_mul(b27, b22);
    b42 = stwo_m31_add(b44, b1);
    b1 = stwo_m31_mul(b23, b27);
    b44 = stwo_m31_mul(b24, b26);
    b0 = stwo_m31_add(b1, b44);
    b44 = stwo_m31_mul(b25, b25);
    b1 = stwo_m31_add(b0, b44);
    b44 = stwo_m31_mul(b26, b24);
    b0 = stwo_m31_add(b1, b44);
    b44 = stwo_m31_mul(b27, b23);
    b1 = stwo_m31_add(b0, b44);
    b44 = stwo_m31_add(b14, b21);
    b0 = stwo_m31_add(b15, b22);
    unsigned b55 = stwo_m31_add(b16, b23);
    unsigned b56 = stwo_m31_add(b17, b24);
    unsigned b57 = stwo_m31_add(b18, b25);
    unsigned b58 = stwo_m31_add(b19, b26);
    unsigned b59 = stwo_m31_add(b20, b27);
    unsigned b60 = stwo_m31_add(b14, b21);
    unsigned b61 = stwo_m31_add(b15, b22);
    unsigned b62 = stwo_m31_add(b16, b23);
    b16 = stwo_m31_add(b17, b24);
    b17 = stwo_m31_add(b18, b25);
    b18 = stwo_m31_add(b19, b26);
    b19 = stwo_m31_add(b20, b27);
    b20 = stwo_m31_mul(b44, b60);
    unsigned b63 = stwo_m31_sub(b20, b54);
    b20 = stwo_m31_sub(b63, b45);
    b63 = stwo_m31_add(b4, b20);
    b20 = stwo_m31_mul(b44, b61);
    unsigned b64 = stwo_m31_mul(b0, b60);
    unsigned b65 = stwo_m31_add(b20, b64);
    b64 = stwo_m31_sub(b65, b47);
    b65 = stwo_m31_sub(b64, b2);
    b64 = stwo_m31_add(b46, b65);
    b65 = stwo_m31_mul(b44, b18);
    b20 = stwo_m31_mul(b0, b17);
    unsigned b66 = stwo_m31_add(b65, b20);
    b20 = stwo_m31_mul(b55, b16);
    b65 = stwo_m31_add(b66, b20);
    b20 = stwo_m31_mul(b56, b62);
    b66 = stwo_m31_add(b65, b20);
    b20 = stwo_m31_mul(b57, b61);
    b65 = stwo_m31_add(b66, b20);
    b20 = stwo_m31_mul(b58, b60);
    b66 = stwo_m31_add(b65, b20);
    b20 = stwo_m31_sub(b66, b5);
    b66 = stwo_m31_sub(b20, b43);
    b20 = stwo_m31_add(b6, b66);
    b66 = stwo_m31_mul(b44, b19);
    b44 = stwo_m31_mul(b0, b18);
    b6 = stwo_m31_add(b66, b44);
    b44 = stwo_m31_mul(b55, b17);
    b66 = stwo_m31_add(b6, b44);
    b44 = stwo_m31_mul(b56, b16);
    b6 = stwo_m31_add(b66, b44);
    b44 = stwo_m31_mul(b57, b62);
    b66 = stwo_m31_add(b6, b44);
    b44 = stwo_m31_mul(b58, b61);
    b6 = stwo_m31_add(b66, b44);
    b44 = stwo_m31_mul(b59, b60);
    b60 = stwo_m31_add(b6, b44);
    b44 = stwo_m31_sub(b60, b48);
    b60 = stwo_m31_sub(b44, b3);
    b44 = stwo_m31_mul(b0, b19);
    b0 = stwo_m31_mul(b55, b18);
    b6 = stwo_m31_add(b44, b0);
    b0 = stwo_m31_mul(b56, b17);
    b44 = stwo_m31_add(b6, b0);
    b0 = stwo_m31_mul(b57, b16);
    b6 = stwo_m31_add(b44, b0);
    b0 = stwo_m31_mul(b58, b62);
    b44 = stwo_m31_add(b6, b0);
    b0 = stwo_m31_mul(b59, b61);
    b61 = stwo_m31_add(b44, b0);
    b0 = stwo_m31_sub(b61, b4);
    b61 = stwo_m31_sub(b0, b42);
    b0 = stwo_m31_add(b45, b61);
    b61 = stwo_m31_mul(b55, b19);
    b19 = stwo_m31_mul(b56, b18);
    b18 = stwo_m31_add(b61, b19);
    b19 = stwo_m31_mul(b57, b17);
    b17 = stwo_m31_add(b18, b19);
    b19 = stwo_m31_mul(b58, b16);
    b16 = stwo_m31_add(b17, b19);
    b19 = stwo_m31_mul(b59, b62);
    b62 = stwo_m31_add(b16, b19);
    b19 = stwo_m31_sub(b62, b46);
    b62 = stwo_m31_sub(b19, b1);
    b19 = stwo_m31_add(b2, b62);
    b62 = stwo_m31_mul(b28, b28);
    b2 = stwo_m31_mul(b28, b29);
    b46 = stwo_m31_mul(b29, b28);
    b16 = stwo_m31_add(b2, b46);
    b46 = stwo_m31_mul(b28, b34);
    b2 = stwo_m31_mul(b29, b33);
    b59 = stwo_m31_add(b46, b2);
    b2 = stwo_m31_mul(b30, b32);
    b46 = stwo_m31_add(b59, b2);
    b2 = stwo_m31_mul(b31, b31);
    b59 = stwo_m31_add(b46, b2);
    b2 = stwo_m31_mul(b32, b30);
    b46 = stwo_m31_add(b59, b2);
    b2 = stwo_m31_mul(b33, b29);
    b59 = stwo_m31_add(b46, b2);
    b2 = stwo_m31_mul(b34, b28);
    b46 = stwo_m31_add(b59, b2);
    b2 = stwo_m31_mul(b29, b34);
    b59 = stwo_m31_mul(b30, b33);
    b17 = stwo_m31_add(b2, b59);
    b59 = stwo_m31_mul(b31, b32);
    b2 = stwo_m31_add(b17, b59);
    b59 = stwo_m31_mul(b32, b31);
    b17 = stwo_m31_add(b2, b59);
    b59 = stwo_m31_mul(b33, b30);
    b2 = stwo_m31_add(b17, b59);
    b59 = stwo_m31_mul(b34, b29);
    b17 = stwo_m31_add(b2, b59);
    b59 = stwo_m31_mul(b30, b34);
    b2 = stwo_m31_mul(b31, b33);
    b58 = stwo_m31_add(b59, b2);
    b2 = stwo_m31_mul(b32, b32);
    b32 = stwo_m31_add(b58, b2);
    b2 = stwo_m31_mul(b33, b31);
    b33 = stwo_m31_add(b32, b2);
    b2 = stwo_m31_mul(b34, b30);
    b34 = stwo_m31_add(b33, b2);
    b2 = stwo_m31_mul(b35, b35);
    b33 = stwo_m31_mul(b35, b36);
    b30 = stwo_m31_mul(b36, b35);
    b32 = stwo_m31_add(b33, b30);
    b30 = stwo_m31_mul(b35, b41);
    b33 = stwo_m31_mul(b36, b40);
    b31 = stwo_m31_add(b30, b33);
    b33 = stwo_m31_mul(b37, b39);
    b30 = stwo_m31_add(b31, b33);
    b33 = stwo_m31_mul(b38, b38);
    b31 = stwo_m31_add(b30, b33);
    b33 = stwo_m31_mul(b39, b37);
    b30 = stwo_m31_add(b31, b33);
    b33 = stwo_m31_mul(b40, b36);
    b31 = stwo_m31_add(b30, b33);
    b33 = stwo_m31_mul(b41, b35);
    b30 = stwo_m31_add(b31, b33);
    b33 = stwo_m31_mul(b36, b41);
    b31 = stwo_m31_mul(b37, b40);
    b58 = stwo_m31_add(b33, b31);
    b31 = stwo_m31_mul(b38, b39);
    b33 = stwo_m31_add(b58, b31);
    b31 = stwo_m31_mul(b39, b38);
    b58 = stwo_m31_add(b33, b31);
    b31 = stwo_m31_mul(b40, b37);
    b33 = stwo_m31_add(b58, b31);
    b31 = stwo_m31_mul(b41, b36);
    b58 = stwo_m31_add(b33, b31);
    b31 = stwo_m31_mul(b37, b41);
    b33 = stwo_m31_mul(b38, b40);
    b59 = stwo_m31_add(b31, b33);
    b33 = stwo_m31_mul(b39, b39);
    b31 = stwo_m31_add(b59, b33);
    b33 = stwo_m31_mul(b40, b38);
    b59 = stwo_m31_add(b31, b33);
    b33 = stwo_m31_mul(b41, b37);
    b31 = stwo_m31_add(b59, b33);
    b33 = stwo_m31_add(b28, b35);
    b59 = stwo_m31_add(b29, b36);
    b18 = stwo_m31_add(b28, b35);
    b57 = stwo_m31_add(b29, b36);
    b61 = stwo_m31_mul(b33, b18);
    b56 = stwo_m31_sub(b61, b62);
    b61 = stwo_m31_sub(b56, b2);
    b56 = stwo_m31_add(b17, b61);
    b61 = stwo_m31_mul(b33, b57);
    b57 = stwo_m31_mul(b59, b18);
    b18 = stwo_m31_add(b61, b57);
    b57 = stwo_m31_sub(b18, b16);
    b18 = stwo_m31_sub(b57, b32);
    b57 = stwo_m31_add(b34, b18);
    b18 = stwo_m31_add(b14, b28);
    b34 = stwo_m31_add(b15, b29);
    b32 = stwo_m31_add(b21, b35);
    b61 = stwo_m31_add(b22, b36);
    b59 = stwo_m31_add(b23, b37);
    b33 = stwo_m31_add(b24, b38);
    b17 = stwo_m31_add(b25, b39);
    b2 = stwo_m31_add(b26, b40);
    b55 = stwo_m31_add(b27, b41);
    b45 = stwo_m31_add(b14, b28);
    b28 = stwo_m31_add(b15, b29);
    b29 = stwo_m31_add(b21, b35);
    b35 = stwo_m31_add(b22, b36);
    b36 = stwo_m31_add(b23, b37);
    b37 = stwo_m31_add(b24, b38);
    b38 = stwo_m31_add(b25, b39);
    b39 = stwo_m31_add(b26, b40);
    b40 = stwo_m31_add(b27, b41);
    b41 = stwo_m31_mul(b18, b45);
    b27 = stwo_m31_mul(b18, b28);
    b28 = stwo_m31_mul(b34, b45);
    b45 = stwo_m31_add(b27, b28);
    b28 = stwo_m31_mul(b32, b40);
    b32 = stwo_m31_mul(b61, b39);
    b27 = stwo_m31_add(b28, b32);
    b32 = stwo_m31_mul(b59, b38);
    b28 = stwo_m31_add(b27, b32);
    b32 = stwo_m31_mul(b33, b37);
    b27 = stwo_m31_add(b28, b32);
    b32 = stwo_m31_mul(b17, b36);
    b28 = stwo_m31_add(b27, b32);
    b32 = stwo_m31_mul(b2, b35);
    b27 = stwo_m31_add(b28, b32);
    b32 = stwo_m31_mul(b55, b29);
    b29 = stwo_m31_add(b27, b32);
    b32 = stwo_m31_mul(b61, b40);
    b61 = stwo_m31_mul(b59, b39);
    b27 = stwo_m31_add(b32, b61);
    b61 = stwo_m31_mul(b33, b38);
    b32 = stwo_m31_add(b27, b61);
    b61 = stwo_m31_mul(b17, b37);
    b27 = stwo_m31_add(b32, b61);
    b61 = stwo_m31_mul(b2, b36);
    b32 = stwo_m31_add(b27, b61);
    b61 = stwo_m31_mul(b55, b35);
    b35 = stwo_m31_add(b32, b61);
    b61 = stwo_m31_mul(b59, b40);
    b40 = stwo_m31_mul(b33, b39);
    b39 = stwo_m31_add(b61, b40);
    b40 = stwo_m31_mul(b17, b38);
    b38 = stwo_m31_add(b39, b40);
    b40 = stwo_m31_mul(b2, b37);
    b37 = stwo_m31_add(b38, b40);
    b40 = stwo_m31_mul(b55, b36);
    b36 = stwo_m31_add(b37, b40);
    b40 = stwo_m31_sub(b41, b54);
    b41 = stwo_m31_sub(b40, b62);
    b40 = stwo_m31_add(b0, b41);
    b41 = stwo_m31_sub(b45, b47);
    b45 = stwo_m31_sub(b41, b16);
    b41 = stwo_m31_add(b19, b45);
    b45 = stwo_m31_sub(b29, b3);
    b29 = stwo_m31_sub(b45, b30);
    b45 = stwo_m31_add(b46, b29);
    b29 = stwo_m31_sub(b35, b42);
    b35 = stwo_m31_sub(b29, b58);
    b29 = stwo_m31_add(b56, b35);
    b35 = stwo_m31_sub(b36, b1);
    b36 = stwo_m31_sub(b35, b31);
    b35 = stwo_m31_add(b57, b36);
    b36 = stwo_m31_sub(b48, b7);
    b48 = stwo_m31_sub(b63, b8);
    b63 = stwo_m31_sub(b64, b9);
    b64 = stwo_m31_sub(b20, b10);
    b20 = stwo_m31_sub(b60, b11);
    b60 = stwo_m31_sub(b40, b12);
    b40 = stwo_m31_sub(b41, b13);
    b41 = 2u;
    b13 = stwo_m31_mul(b41, b36);
    b41 = stwo_m31_add(b13, b64);
    b13 = 32u;
    b64 = stwo_m31_mul(b13, b20);
    b13 = stwo_m31_add(b41, b64);
    b64 = 4u;
    b41 = stwo_m31_mul(b64, b45);
    b64 = stwo_m31_sub(b13, b41);
    b41 = 2u;
    b13 = stwo_m31_mul(b41, b48);
    b41 = stwo_m31_add(b13, b20);
    b13 = 32u;
    b20 = stwo_m31_mul(b13, b60);
    b13 = stwo_m31_add(b41, b20);
    b20 = 4u;
    b41 = stwo_m31_mul(b20, b29);
    b20 = stwo_m31_sub(b13, b41);
    b41 = 2u;
    b13 = stwo_m31_mul(b41, b63);
    b41 = stwo_m31_add(b13, b60);
    b13 = 32u;
    b60 = stwo_m31_mul(b13, b40);
    b13 = stwo_m31_add(b41, b60);
    b60 = 4u;
    b41 = stwo_m31_mul(b60, b35);
    b60 = stwo_m31_sub(b13, b41);
    b41 = 512u;
    b13 = stwo_m31_mul(b50, b41);
    b41 = stwo_m31_add(b64, b49);
    b64 = stwo_m31_sub(b13, b41);
    b41 = 512u;
    b13 = stwo_m31_mul(b51, b41);
    b41 = stwo_m31_add(b20, b50);
    b20 = stwo_m31_sub(b13, b41);
    b41 = 512u;
    b13 = stwo_m31_mul(b52, b41);
    b41 = stwo_m31_add(b60, b51);
    b60 = stwo_m31_sub(b13, b41);
    StwoCairoQm31 e0 = { b64, b53, b53, b53 };
    StwoCairoQm31 e1 = { b20, b53, b53, b53 };
    StwoCairoQm31 e2 = { b60, b53, b53, b53 };
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
