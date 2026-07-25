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
stwo_cairo_cuda_eval_v1_7d6ca34d2c6adcb7(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 19u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 41u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 42u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
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
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 186u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 187u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 188u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 189u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 208u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 209u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 210u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 215u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 216u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 217u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 218u, row, 0);
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
    b54 = stwo_m31_mul(b14, b16);
    b48 = stwo_m31_mul(b15, b15);
    b6 = stwo_m31_add(b54, b48);
    b48 = stwo_m31_mul(b16, b14);
    b54 = stwo_m31_add(b6, b48);
    b48 = stwo_m31_mul(b14, b17);
    b6 = stwo_m31_mul(b15, b16);
    b47 = stwo_m31_add(b48, b6);
    b6 = stwo_m31_mul(b16, b15);
    b48 = stwo_m31_add(b47, b6);
    b6 = stwo_m31_mul(b17, b14);
    b47 = stwo_m31_add(b48, b6);
    b6 = stwo_m31_mul(b14, b18);
    b48 = stwo_m31_mul(b15, b17);
    b5 = stwo_m31_add(b6, b48);
    b48 = stwo_m31_mul(b16, b16);
    b6 = stwo_m31_add(b5, b48);
    b48 = stwo_m31_mul(b17, b15);
    b5 = stwo_m31_add(b6, b48);
    b48 = stwo_m31_mul(b18, b14);
    b6 = stwo_m31_add(b5, b48);
    b48 = stwo_m31_mul(b14, b19);
    b5 = stwo_m31_mul(b15, b18);
    b46 = stwo_m31_add(b48, b5);
    b5 = stwo_m31_mul(b16, b17);
    b48 = stwo_m31_add(b46, b5);
    b5 = stwo_m31_mul(b17, b16);
    b46 = stwo_m31_add(b48, b5);
    b5 = stwo_m31_mul(b18, b15);
    b48 = stwo_m31_add(b46, b5);
    b5 = stwo_m31_mul(b19, b14);
    b46 = stwo_m31_add(b48, b5);
    b5 = stwo_m31_mul(b18, b20);
    b48 = stwo_m31_mul(b19, b19);
    b4 = stwo_m31_add(b5, b48);
    b48 = stwo_m31_mul(b20, b18);
    b5 = stwo_m31_add(b4, b48);
    b48 = stwo_m31_mul(b19, b20);
    b4 = stwo_m31_mul(b20, b19);
    b45 = stwo_m31_add(b48, b4);
    b4 = stwo_m31_mul(b20, b20);
    b48 = stwo_m31_mul(b21, b24);
    b3 = stwo_m31_mul(b22, b23);
    b44 = stwo_m31_add(b48, b3);
    b3 = stwo_m31_mul(b23, b22);
    b48 = stwo_m31_add(b44, b3);
    b3 = stwo_m31_mul(b24, b21);
    b44 = stwo_m31_add(b48, b3);
    b3 = stwo_m31_mul(b21, b25);
    b48 = stwo_m31_mul(b22, b24);
    b2 = stwo_m31_add(b3, b48);
    b48 = stwo_m31_mul(b23, b23);
    b3 = stwo_m31_add(b2, b48);
    b48 = stwo_m31_mul(b24, b22);
    b2 = stwo_m31_add(b3, b48);
    b48 = stwo_m31_mul(b25, b21);
    b3 = stwo_m31_add(b2, b48);
    b48 = stwo_m31_mul(b21, b26);
    b2 = stwo_m31_mul(b22, b25);
    b43 = stwo_m31_add(b48, b2);
    b2 = stwo_m31_mul(b23, b24);
    b48 = stwo_m31_add(b43, b2);
    b2 = stwo_m31_mul(b24, b23);
    b43 = stwo_m31_add(b48, b2);
    b2 = stwo_m31_mul(b25, b22);
    b48 = stwo_m31_add(b43, b2);
    b2 = stwo_m31_mul(b26, b21);
    b43 = stwo_m31_add(b48, b2);
    b2 = stwo_m31_mul(b25, b27);
    b48 = stwo_m31_mul(b26, b26);
    b1 = stwo_m31_add(b2, b48);
    b48 = stwo_m31_mul(b27, b25);
    b2 = stwo_m31_add(b1, b48);
    b48 = stwo_m31_mul(b26, b27);
    b1 = stwo_m31_mul(b27, b26);
    b42 = stwo_m31_add(b48, b1);
    b1 = stwo_m31_mul(b27, b27);
    b27 = stwo_m31_add(b14, b21);
    b48 = stwo_m31_add(b15, b22);
    b0 = stwo_m31_add(b16, b23);
    unsigned b55 = stwo_m31_add(b17, b24);
    unsigned b56 = stwo_m31_add(b18, b25);
    unsigned b57 = stwo_m31_add(b19, b26);
    unsigned b58 = stwo_m31_add(b14, b21);
    unsigned b59 = stwo_m31_add(b15, b22);
    unsigned b60 = stwo_m31_add(b16, b23);
    unsigned b61 = stwo_m31_add(b17, b24);
    unsigned b62 = stwo_m31_add(b18, b25);
    unsigned b63 = stwo_m31_add(b19, b26);
    unsigned b64 = stwo_m31_mul(b27, b61);
    unsigned b65 = stwo_m31_mul(b48, b60);
    unsigned b66 = stwo_m31_add(b64, b65);
    b65 = stwo_m31_mul(b0, b59);
    b64 = stwo_m31_add(b66, b65);
    b65 = stwo_m31_mul(b55, b58);
    b66 = stwo_m31_add(b64, b65);
    b65 = stwo_m31_sub(b66, b47);
    b66 = stwo_m31_sub(b65, b44);
    b65 = stwo_m31_add(b5, b66);
    b66 = stwo_m31_mul(b27, b62);
    b5 = stwo_m31_mul(b48, b61);
    b44 = stwo_m31_add(b66, b5);
    b5 = stwo_m31_mul(b0, b60);
    b66 = stwo_m31_add(b44, b5);
    b5 = stwo_m31_mul(b55, b59);
    b44 = stwo_m31_add(b66, b5);
    b5 = stwo_m31_mul(b56, b58);
    b66 = stwo_m31_add(b44, b5);
    b5 = stwo_m31_sub(b66, b6);
    b66 = stwo_m31_sub(b5, b3);
    b5 = stwo_m31_add(b45, b66);
    b66 = stwo_m31_mul(b27, b63);
    b63 = stwo_m31_mul(b48, b62);
    b62 = stwo_m31_add(b66, b63);
    b63 = stwo_m31_mul(b0, b61);
    b61 = stwo_m31_add(b62, b63);
    b63 = stwo_m31_mul(b55, b60);
    b60 = stwo_m31_add(b61, b63);
    b63 = stwo_m31_mul(b56, b59);
    b59 = stwo_m31_add(b60, b63);
    b63 = stwo_m31_mul(b57, b58);
    b58 = stwo_m31_add(b59, b63);
    b63 = stwo_m31_sub(b58, b46);
    b58 = stwo_m31_sub(b63, b43);
    b63 = stwo_m31_add(b4, b58);
    b58 = stwo_m31_mul(b28, b31);
    b4 = stwo_m31_mul(b29, b30);
    b43 = stwo_m31_add(b58, b4);
    b4 = stwo_m31_mul(b30, b29);
    b58 = stwo_m31_add(b43, b4);
    b4 = stwo_m31_mul(b31, b28);
    b43 = stwo_m31_add(b58, b4);
    b4 = stwo_m31_mul(b28, b32);
    b58 = stwo_m31_mul(b29, b31);
    b59 = stwo_m31_add(b4, b58);
    b58 = stwo_m31_mul(b30, b30);
    b4 = stwo_m31_add(b59, b58);
    b58 = stwo_m31_mul(b31, b29);
    b59 = stwo_m31_add(b4, b58);
    b58 = stwo_m31_mul(b32, b28);
    b4 = stwo_m31_add(b59, b58);
    b58 = stwo_m31_mul(b28, b33);
    b59 = stwo_m31_mul(b29, b32);
    b57 = stwo_m31_add(b58, b59);
    b59 = stwo_m31_mul(b30, b31);
    b58 = stwo_m31_add(b57, b59);
    b59 = stwo_m31_mul(b31, b30);
    b57 = stwo_m31_add(b58, b59);
    b59 = stwo_m31_mul(b32, b29);
    b58 = stwo_m31_add(b57, b59);
    b59 = stwo_m31_mul(b33, b28);
    b57 = stwo_m31_add(b58, b59);
    b59 = stwo_m31_mul(b32, b34);
    b58 = stwo_m31_mul(b33, b33);
    b60 = stwo_m31_add(b59, b58);
    b58 = stwo_m31_mul(b34, b32);
    b59 = stwo_m31_add(b60, b58);
    b58 = stwo_m31_mul(b33, b34);
    b60 = stwo_m31_mul(b34, b33);
    b56 = stwo_m31_add(b58, b60);
    b60 = stwo_m31_mul(b34, b34);
    b58 = stwo_m31_mul(b35, b38);
    b61 = stwo_m31_mul(b36, b37);
    b55 = stwo_m31_add(b58, b61);
    b61 = stwo_m31_mul(b37, b36);
    b58 = stwo_m31_add(b55, b61);
    b61 = stwo_m31_mul(b38, b35);
    b55 = stwo_m31_add(b58, b61);
    b61 = stwo_m31_mul(b35, b39);
    b58 = stwo_m31_mul(b36, b38);
    b62 = stwo_m31_add(b61, b58);
    b58 = stwo_m31_mul(b37, b37);
    b61 = stwo_m31_add(b62, b58);
    b58 = stwo_m31_mul(b38, b36);
    b62 = stwo_m31_add(b61, b58);
    b58 = stwo_m31_mul(b39, b35);
    b61 = stwo_m31_add(b62, b58);
    b58 = stwo_m31_mul(b35, b40);
    b62 = stwo_m31_mul(b36, b39);
    b0 = stwo_m31_add(b58, b62);
    b62 = stwo_m31_mul(b37, b38);
    b58 = stwo_m31_add(b0, b62);
    b62 = stwo_m31_mul(b38, b37);
    b0 = stwo_m31_add(b58, b62);
    b62 = stwo_m31_mul(b39, b36);
    b58 = stwo_m31_add(b0, b62);
    b62 = stwo_m31_mul(b40, b35);
    b0 = stwo_m31_add(b58, b62);
    b62 = stwo_m31_mul(b39, b41);
    b58 = stwo_m31_mul(b40, b40);
    b66 = stwo_m31_add(b62, b58);
    b58 = stwo_m31_mul(b41, b39);
    b62 = stwo_m31_add(b66, b58);
    b58 = stwo_m31_mul(b40, b41);
    b66 = stwo_m31_mul(b41, b40);
    b48 = stwo_m31_add(b58, b66);
    b66 = stwo_m31_mul(b41, b41);
    b41 = stwo_m31_add(b28, b35);
    b58 = stwo_m31_add(b29, b36);
    b27 = stwo_m31_add(b30, b37);
    b45 = stwo_m31_add(b31, b38);
    b3 = stwo_m31_add(b32, b39);
    b44 = stwo_m31_add(b33, b40);
    b64 = stwo_m31_add(b28, b35);
    unsigned b67 = stwo_m31_add(b29, b36);
    unsigned b68 = stwo_m31_add(b30, b37);
    unsigned b69 = stwo_m31_add(b31, b38);
    unsigned b70 = stwo_m31_add(b32, b39);
    unsigned b71 = stwo_m31_add(b33, b40);
    unsigned b72 = stwo_m31_mul(b41, b69);
    unsigned b73 = stwo_m31_mul(b58, b68);
    unsigned b74 = stwo_m31_add(b72, b73);
    b73 = stwo_m31_mul(b27, b67);
    b72 = stwo_m31_add(b74, b73);
    b73 = stwo_m31_mul(b45, b64);
    b74 = stwo_m31_add(b72, b73);
    b73 = stwo_m31_sub(b74, b43);
    b74 = stwo_m31_sub(b73, b55);
    b73 = stwo_m31_add(b59, b74);
    b74 = stwo_m31_mul(b41, b70);
    b59 = stwo_m31_mul(b58, b69);
    b55 = stwo_m31_add(b74, b59);
    b59 = stwo_m31_mul(b27, b68);
    b74 = stwo_m31_add(b55, b59);
    b59 = stwo_m31_mul(b45, b67);
    b55 = stwo_m31_add(b74, b59);
    b59 = stwo_m31_mul(b3, b64);
    b74 = stwo_m31_add(b55, b59);
    b59 = stwo_m31_sub(b74, b4);
    b74 = stwo_m31_sub(b59, b61);
    b59 = stwo_m31_add(b56, b74);
    b74 = stwo_m31_mul(b41, b71);
    b71 = stwo_m31_mul(b58, b70);
    b70 = stwo_m31_add(b74, b71);
    b71 = stwo_m31_mul(b27, b69);
    b69 = stwo_m31_add(b70, b71);
    b71 = stwo_m31_mul(b45, b68);
    b68 = stwo_m31_add(b69, b71);
    b71 = stwo_m31_mul(b3, b67);
    b67 = stwo_m31_add(b68, b71);
    b71 = stwo_m31_mul(b44, b64);
    b64 = stwo_m31_add(b67, b71);
    b71 = stwo_m31_sub(b64, b57);
    b64 = stwo_m31_sub(b71, b0);
    b71 = stwo_m31_add(b60, b64);
    b64 = stwo_m31_add(b14, b28);
    b60 = stwo_m31_add(b15, b29);
    b0 = stwo_m31_add(b16, b30);
    b57 = stwo_m31_add(b17, b31);
    b67 = stwo_m31_add(b18, b32);
    b44 = stwo_m31_add(b19, b33);
    b68 = stwo_m31_add(b20, b34);
    b3 = stwo_m31_add(b21, b35);
    b69 = stwo_m31_add(b22, b36);
    b45 = stwo_m31_add(b23, b37);
    b70 = stwo_m31_add(b24, b38);
    b27 = stwo_m31_add(b25, b39);
    b74 = stwo_m31_add(b26, b40);
    b58 = stwo_m31_add(b14, b28);
    b28 = stwo_m31_add(b15, b29);
    b29 = stwo_m31_add(b16, b30);
    b30 = stwo_m31_add(b17, b31);
    b31 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_add(b19, b33);
    b33 = stwo_m31_add(b20, b34);
    b34 = stwo_m31_add(b21, b35);
    b35 = stwo_m31_add(b22, b36);
    b36 = stwo_m31_add(b23, b37);
    b37 = stwo_m31_add(b24, b38);
    b38 = stwo_m31_add(b25, b39);
    b39 = stwo_m31_add(b26, b40);
    b40 = stwo_m31_mul(b64, b30);
    b26 = stwo_m31_mul(b60, b29);
    b25 = stwo_m31_add(b40, b26);
    b26 = stwo_m31_mul(b0, b28);
    b40 = stwo_m31_add(b25, b26);
    b26 = stwo_m31_mul(b57, b58);
    b25 = stwo_m31_add(b40, b26);
    b26 = stwo_m31_mul(b64, b31);
    b40 = stwo_m31_mul(b60, b30);
    b24 = stwo_m31_add(b26, b40);
    b40 = stwo_m31_mul(b0, b29);
    b26 = stwo_m31_add(b24, b40);
    b40 = stwo_m31_mul(b57, b28);
    b24 = stwo_m31_add(b26, b40);
    b40 = stwo_m31_mul(b67, b58);
    b26 = stwo_m31_add(b24, b40);
    b40 = stwo_m31_mul(b64, b32);
    b24 = stwo_m31_mul(b60, b31);
    b23 = stwo_m31_add(b40, b24);
    b24 = stwo_m31_mul(b0, b30);
    b40 = stwo_m31_add(b23, b24);
    b24 = stwo_m31_mul(b57, b29);
    b23 = stwo_m31_add(b40, b24);
    b24 = stwo_m31_mul(b67, b28);
    b40 = stwo_m31_add(b23, b24);
    b24 = stwo_m31_mul(b44, b58);
    b23 = stwo_m31_add(b40, b24);
    b24 = stwo_m31_mul(b67, b33);
    b40 = stwo_m31_mul(b44, b32);
    b22 = stwo_m31_add(b24, b40);
    b40 = stwo_m31_mul(b68, b31);
    b24 = stwo_m31_add(b22, b40);
    b40 = stwo_m31_mul(b44, b33);
    b22 = stwo_m31_mul(b68, b32);
    b21 = stwo_m31_add(b40, b22);
    b22 = stwo_m31_mul(b68, b33);
    b33 = stwo_m31_mul(b3, b37);
    b68 = stwo_m31_mul(b69, b36);
    b40 = stwo_m31_add(b33, b68);
    b68 = stwo_m31_mul(b45, b35);
    b33 = stwo_m31_add(b40, b68);
    b68 = stwo_m31_mul(b70, b34);
    b40 = stwo_m31_add(b33, b68);
    b68 = stwo_m31_mul(b3, b38);
    b33 = stwo_m31_mul(b69, b37);
    b20 = stwo_m31_add(b68, b33);
    b33 = stwo_m31_mul(b45, b36);
    b68 = stwo_m31_add(b20, b33);
    b33 = stwo_m31_mul(b70, b35);
    b20 = stwo_m31_add(b68, b33);
    b33 = stwo_m31_mul(b27, b34);
    b68 = stwo_m31_add(b20, b33);
    b33 = stwo_m31_mul(b3, b39);
    b20 = stwo_m31_mul(b69, b38);
    b19 = stwo_m31_add(b33, b20);
    b20 = stwo_m31_mul(b45, b37);
    b33 = stwo_m31_add(b19, b20);
    b20 = stwo_m31_mul(b70, b36);
    b19 = stwo_m31_add(b33, b20);
    b20 = stwo_m31_mul(b27, b35);
    b33 = stwo_m31_add(b19, b20);
    b20 = stwo_m31_mul(b74, b34);
    b19 = stwo_m31_add(b33, b20);
    b20 = stwo_m31_add(b64, b3);
    b3 = stwo_m31_add(b60, b69);
    b69 = stwo_m31_add(b0, b45);
    b45 = stwo_m31_add(b57, b70);
    b70 = stwo_m31_add(b67, b27);
    b27 = stwo_m31_add(b44, b74);
    b74 = stwo_m31_add(b58, b34);
    b34 = stwo_m31_add(b28, b35);
    b35 = stwo_m31_add(b29, b36);
    b36 = stwo_m31_add(b30, b37);
    b37 = stwo_m31_add(b31, b38);
    b38 = stwo_m31_add(b32, b39);
    b39 = stwo_m31_mul(b20, b36);
    b32 = stwo_m31_mul(b3, b35);
    b31 = stwo_m31_add(b39, b32);
    b32 = stwo_m31_mul(b69, b34);
    b39 = stwo_m31_add(b31, b32);
    b32 = stwo_m31_mul(b45, b74);
    b31 = stwo_m31_add(b39, b32);
    b32 = stwo_m31_sub(b31, b25);
    b31 = stwo_m31_sub(b32, b40);
    b32 = stwo_m31_add(b24, b31);
    b31 = stwo_m31_mul(b20, b37);
    b24 = stwo_m31_mul(b3, b36);
    b40 = stwo_m31_add(b31, b24);
    b24 = stwo_m31_mul(b69, b35);
    b31 = stwo_m31_add(b40, b24);
    b24 = stwo_m31_mul(b45, b34);
    b40 = stwo_m31_add(b31, b24);
    b24 = stwo_m31_mul(b70, b74);
    b31 = stwo_m31_add(b40, b24);
    b24 = stwo_m31_sub(b31, b26);
    b31 = stwo_m31_sub(b24, b68);
    b24 = stwo_m31_add(b21, b31);
    b31 = stwo_m31_mul(b20, b38);
    b38 = stwo_m31_mul(b3, b37);
    b37 = stwo_m31_add(b31, b38);
    b38 = stwo_m31_mul(b69, b36);
    b36 = stwo_m31_add(b37, b38);
    b38 = stwo_m31_mul(b45, b35);
    b35 = stwo_m31_add(b36, b38);
    b38 = stwo_m31_mul(b70, b34);
    b34 = stwo_m31_add(b35, b38);
    b38 = stwo_m31_mul(b27, b74);
    b74 = stwo_m31_add(b34, b38);
    b38 = stwo_m31_sub(b74, b23);
    b74 = stwo_m31_sub(b38, b19);
    b38 = stwo_m31_add(b22, b74);
    b74 = stwo_m31_sub(b32, b65);
    b32 = stwo_m31_sub(b74, b73);
    b74 = stwo_m31_add(b2, b32);
    b32 = stwo_m31_sub(b24, b5);
    b24 = stwo_m31_sub(b32, b59);
    b32 = stwo_m31_add(b42, b24);
    b24 = stwo_m31_sub(b38, b63);
    b38 = stwo_m31_sub(b24, b71);
    b24 = stwo_m31_add(b1, b38);
    b38 = stwo_m31_sub(b54, b7);
    b54 = stwo_m31_sub(b47, b8);
    b47 = stwo_m31_sub(b6, b9);
    b6 = stwo_m31_sub(b46, b10);
    b46 = stwo_m31_sub(b74, b11);
    b74 = stwo_m31_sub(b32, b12);
    b32 = stwo_m31_sub(b24, b13);
    b24 = 32u;
    b13 = stwo_m31_mul(b24, b54);
    b24 = stwo_m31_add(b38, b13);
    b13 = 4u;
    b38 = stwo_m31_mul(b13, b46);
    b13 = stwo_m31_sub(b24, b38);
    b38 = 8u;
    b24 = stwo_m31_mul(b38, b62);
    b38 = stwo_m31_add(b13, b24);
    b24 = 32u;
    b13 = stwo_m31_mul(b24, b47);
    b24 = stwo_m31_add(b54, b13);
    b13 = 4u;
    b54 = stwo_m31_mul(b13, b74);
    b13 = stwo_m31_sub(b24, b54);
    b54 = 8u;
    b24 = stwo_m31_mul(b54, b48);
    b54 = stwo_m31_add(b13, b24);
    b24 = 32u;
    b13 = stwo_m31_mul(b24, b6);
    b24 = stwo_m31_add(b47, b13);
    b13 = 4u;
    b47 = stwo_m31_mul(b13, b32);
    b13 = stwo_m31_sub(b24, b47);
    b47 = 8u;
    b24 = stwo_m31_mul(b47, b66);
    b47 = stwo_m31_add(b13, b24);
    b24 = 512u;
    b13 = stwo_m31_mul(b50, b24);
    b24 = stwo_m31_add(b38, b49);
    b38 = stwo_m31_sub(b13, b24);
    b24 = 512u;
    b13 = stwo_m31_mul(b51, b24);
    b24 = stwo_m31_add(b54, b50);
    b54 = stwo_m31_sub(b13, b24);
    b24 = 512u;
    b13 = stwo_m31_mul(b52, b24);
    b24 = stwo_m31_add(b47, b51);
    b47 = stwo_m31_sub(b13, b24);
    StwoCairoQm31 e0 = { b38, b53, b53, b53 };
    StwoCairoQm31 e1 = { b54, b53, b53, b53 };
    StwoCairoQm31 e2 = { b47, b53, b53, b53 };
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
