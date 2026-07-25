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
stwo_cairo_cuda_eval_v1_8ddba4f2b2b754db(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 195u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 196u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 197u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 198u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 199u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 200u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 201u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 202u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 203u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 205u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 206u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 207u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 208u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 209u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 210u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 211u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 212u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 213u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 215u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 216u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 217u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 218u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 219u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 220u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 221u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 222u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 223u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 225u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 226u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 227u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 228u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 229u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 230u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 231u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 232u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 233u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 235u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 236u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 237u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 238u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 239u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 240u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 241u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 242u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 243u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 245u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 246u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 247u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 248u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 249u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 250u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 251u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 252u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 253u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 254u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 256u, row, 0);
    unsigned b56 = 0u;
    unsigned b57 = 4u;
    unsigned b58 = stwo_m31_mul(b57, b0);
    b57 = 2u;
    b0 = stwo_m31_mul(b57, b9);
    b57 = stwo_m31_add(b58, b0);
    b0 = stwo_m31_add(b57, b18);
    b57 = 40454143u;
    b58 = stwo_m31_add(b0, b57);
    b57 = stwo_m31_sub(b58, b36);
    b58 = stwo_m31_sub(b57, b45);
    b57 = 16u;
    b0 = stwo_m31_mul(b58, b57);
    b57 = 4u;
    b58 = stwo_m31_mul(b57, b1);
    b57 = stwo_m31_add(b0, b58);
    b58 = 2u;
    b1 = stwo_m31_mul(b58, b10);
    b58 = stwo_m31_add(b57, b1);
    b1 = stwo_m31_add(b58, b19);
    b58 = 49554771u;
    b57 = stwo_m31_add(b1, b58);
    b58 = stwo_m31_sub(b57, b37);
    b57 = 16u;
    b1 = stwo_m31_mul(b58, b57);
    b57 = 4u;
    b58 = stwo_m31_mul(b57, b2);
    b57 = stwo_m31_add(b1, b58);
    b58 = 2u;
    b2 = stwo_m31_mul(b58, b11);
    b58 = stwo_m31_add(b57, b2);
    b2 = stwo_m31_add(b58, b20);
    b58 = 55508188u;
    b57 = stwo_m31_add(b2, b58);
    b58 = stwo_m31_sub(b57, b38);
    b57 = 16u;
    b2 = stwo_m31_mul(b58, b57);
    b57 = 4u;
    b58 = stwo_m31_mul(b57, b3);
    b57 = stwo_m31_add(b2, b58);
    b58 = 2u;
    b3 = stwo_m31_mul(b58, b12);
    b58 = stwo_m31_add(b57, b3);
    b3 = stwo_m31_add(b58, b21);
    b58 = 116986206u;
    b57 = stwo_m31_add(b3, b58);
    b58 = stwo_m31_sub(b57, b39);
    b57 = 16u;
    b3 = stwo_m31_mul(b58, b57);
    b57 = 4u;
    b58 = stwo_m31_mul(b57, b4);
    b57 = stwo_m31_add(b3, b58);
    b58 = 2u;
    b4 = stwo_m31_mul(b58, b13);
    b58 = stwo_m31_add(b57, b4);
    b4 = stwo_m31_add(b58, b22);
    b58 = 88680813u;
    b57 = stwo_m31_add(b4, b58);
    b58 = stwo_m31_sub(b57, b40);
    b57 = 16u;
    b4 = stwo_m31_mul(b58, b57);
    b57 = 4u;
    b58 = stwo_m31_mul(b57, b5);
    b57 = stwo_m31_add(b4, b58);
    b58 = 2u;
    b5 = stwo_m31_mul(b58, b14);
    b58 = stwo_m31_add(b57, b5);
    b5 = stwo_m31_add(b58, b23);
    b58 = 45553283u;
    b57 = stwo_m31_add(b5, b58);
    b58 = stwo_m31_sub(b57, b41);
    b57 = 16u;
    b5 = stwo_m31_mul(b58, b57);
    b57 = 4u;
    b58 = stwo_m31_mul(b57, b6);
    b57 = stwo_m31_add(b5, b58);
    b58 = 2u;
    b6 = stwo_m31_mul(b58, b15);
    b58 = stwo_m31_add(b57, b6);
    b6 = stwo_m31_add(b58, b24);
    b58 = 62360091u;
    b57 = stwo_m31_add(b6, b58);
    b58 = stwo_m31_sub(b57, b42);
    b57 = 16u;
    b6 = stwo_m31_mul(b58, b57);
    b57 = 4u;
    b58 = stwo_m31_mul(b57, b7);
    b57 = stwo_m31_add(b6, b58);
    b58 = 2u;
    b7 = stwo_m31_mul(b58, b16);
    b58 = stwo_m31_add(b57, b7);
    b7 = stwo_m31_add(b58, b25);
    b58 = 77099918u;
    b57 = stwo_m31_add(b7, b58);
    b58 = stwo_m31_sub(b57, b43);
    b57 = 136u;
    b7 = stwo_m31_mul(b45, b57);
    b57 = stwo_m31_sub(b58, b7);
    b7 = 16u;
    b58 = stwo_m31_mul(b57, b7);
    b7 = 4u;
    b57 = stwo_m31_mul(b7, b8);
    b7 = stwo_m31_add(b58, b57);
    b57 = 2u;
    b8 = stwo_m31_mul(b57, b17);
    b57 = stwo_m31_add(b7, b8);
    b8 = stwo_m31_add(b57, b26);
    b57 = 22899501u;
    b7 = stwo_m31_add(b8, b57);
    b57 = stwo_m31_sub(b7, b44);
    b7 = 16u;
    b8 = stwo_m31_mul(b57, b7);
    b7 = 1u;
    b57 = stwo_m31_add(b45, b7);
    b7 = 1u;
    b45 = stwo_m31_add(b0, b7);
    b7 = 1u;
    b0 = stwo_m31_add(b1, b7);
    b7 = 1u;
    b1 = stwo_m31_add(b2, b7);
    b7 = 1u;
    b2 = stwo_m31_add(b3, b7);
    b7 = 1u;
    b3 = stwo_m31_add(b4, b7);
    b7 = 1u;
    b4 = stwo_m31_add(b5, b7);
    b7 = 1u;
    b5 = stwo_m31_add(b6, b7);
    b7 = 1u;
    b6 = stwo_m31_add(b58, b7);
    b7 = 1u;
    b58 = stwo_m31_add(b8, b7);
    b7 = 4u;
    b8 = stwo_m31_mul(b7, b18);
    b7 = 2u;
    b18 = stwo_m31_mul(b7, b27);
    b7 = stwo_m31_add(b8, b18);
    b18 = stwo_m31_add(b7, b36);
    b7 = 48383197u;
    b36 = stwo_m31_add(b18, b7);
    b7 = stwo_m31_sub(b36, b46);
    b36 = stwo_m31_sub(b7, b55);
    b7 = 16u;
    b46 = stwo_m31_mul(b36, b7);
    b7 = 4u;
    b36 = stwo_m31_mul(b7, b19);
    b7 = stwo_m31_add(b46, b36);
    b36 = 2u;
    b19 = stwo_m31_mul(b36, b28);
    b36 = stwo_m31_add(b7, b19);
    b19 = stwo_m31_add(b36, b37);
    b36 = 48193339u;
    b37 = stwo_m31_add(b19, b36);
    b36 = stwo_m31_sub(b37, b47);
    b37 = 16u;
    b47 = stwo_m31_mul(b36, b37);
    b37 = 4u;
    b36 = stwo_m31_mul(b37, b20);
    b37 = stwo_m31_add(b47, b36);
    b36 = 2u;
    b20 = stwo_m31_mul(b36, b29);
    b36 = stwo_m31_add(b37, b20);
    b20 = stwo_m31_add(b36, b38);
    b36 = 55955004u;
    b38 = stwo_m31_add(b20, b36);
    b36 = stwo_m31_sub(b38, b48);
    b38 = 16u;
    b48 = stwo_m31_mul(b36, b38);
    b38 = 4u;
    b36 = stwo_m31_mul(b38, b21);
    b38 = stwo_m31_add(b48, b36);
    b36 = 2u;
    b21 = stwo_m31_mul(b36, b30);
    b36 = stwo_m31_add(b38, b21);
    b21 = stwo_m31_add(b36, b39);
    b36 = 65659846u;
    b39 = stwo_m31_add(b21, b36);
    b36 = stwo_m31_sub(b39, b49);
    b39 = 16u;
    b49 = stwo_m31_mul(b36, b39);
    b39 = 4u;
    b36 = stwo_m31_mul(b39, b22);
    b39 = stwo_m31_add(b49, b36);
    b36 = 2u;
    b22 = stwo_m31_mul(b36, b31);
    b36 = stwo_m31_add(b39, b22);
    b22 = stwo_m31_add(b36, b40);
    b36 = 68491350u;
    b40 = stwo_m31_add(b22, b36);
    b36 = stwo_m31_sub(b40, b50);
    b40 = 16u;
    b50 = stwo_m31_mul(b36, b40);
    b40 = 4u;
    b36 = stwo_m31_mul(b40, b23);
    b40 = stwo_m31_add(b50, b36);
    b36 = 2u;
    b23 = stwo_m31_mul(b36, b32);
    b36 = stwo_m31_add(b40, b23);
    b23 = stwo_m31_add(b36, b41);
    b36 = 119023582u;
    b41 = stwo_m31_add(b23, b36);
    b36 = stwo_m31_sub(b41, b51);
    b41 = 16u;
    b51 = stwo_m31_mul(b36, b41);
    b41 = 4u;
    b36 = stwo_m31_mul(b41, b24);
    b41 = stwo_m31_add(b51, b36);
    b36 = 2u;
    b24 = stwo_m31_mul(b36, b33);
    b36 = stwo_m31_add(b41, b24);
    b24 = stwo_m31_add(b36, b42);
    b36 = 33439011u;
    b42 = stwo_m31_add(b24, b36);
    b36 = stwo_m31_sub(b42, b52);
    b42 = 16u;
    b52 = stwo_m31_mul(b36, b42);
    b42 = 4u;
    b36 = stwo_m31_mul(b42, b25);
    b42 = stwo_m31_add(b52, b36);
    b36 = 2u;
    b25 = stwo_m31_mul(b36, b34);
    b36 = stwo_m31_add(b42, b25);
    b25 = stwo_m31_add(b36, b43);
    b36 = 58475513u;
    b43 = stwo_m31_add(b25, b36);
    b36 = stwo_m31_sub(b43, b53);
    b43 = 136u;
    b53 = stwo_m31_mul(b55, b43);
    b43 = stwo_m31_sub(b36, b53);
    b53 = 16u;
    b36 = stwo_m31_mul(b43, b53);
    b53 = 4u;
    b43 = stwo_m31_mul(b53, b26);
    b53 = stwo_m31_add(b36, b43);
    b43 = 2u;
    b26 = stwo_m31_mul(b43, b35);
    b43 = stwo_m31_add(b53, b26);
    b26 = stwo_m31_add(b43, b44);
    b43 = 18765944u;
    b44 = stwo_m31_add(b26, b43);
    b43 = stwo_m31_sub(b44, b54);
    b44 = 16u;
    b54 = stwo_m31_mul(b43, b44);
    b44 = 1u;
    b43 = stwo_m31_add(b55, b44);
    b44 = 1u;
    b55 = stwo_m31_add(b46, b44);
    b44 = 1u;
    b46 = stwo_m31_add(b47, b44);
    b44 = 1u;
    b47 = stwo_m31_add(b48, b44);
    b44 = 1u;
    b48 = stwo_m31_add(b49, b44);
    b44 = 1u;
    b49 = stwo_m31_add(b50, b44);
    b44 = 1u;
    b50 = stwo_m31_add(b51, b44);
    b44 = 1u;
    b51 = stwo_m31_add(b52, b44);
    b44 = 1u;
    b52 = stwo_m31_add(b36, b44);
    b44 = 1u;
    b36 = stwo_m31_add(b54, b44);
    b44 = stwo_trace_value(arena, *args, 2u, 28u, row, 0);
    b54 = stwo_trace_value(arena, *args, 2u, 29u, row, 0);
    b26 = stwo_trace_value(arena, *args, 2u, 30u, row, 0);
    b53 = stwo_trace_value(arena, *args, 2u, 31u, row, 0);
    b35 = stwo_trace_value(arena, *args, 2u, 32u, row, 0);
    b25 = stwo_trace_value(arena, *args, 2u, 33u, row, 0);
    b42 = stwo_trace_value(arena, *args, 2u, 34u, row, 0);
    b34 = stwo_trace_value(arena, *args, 2u, 35u, row, 0);
    b24 = stwo_trace_value(arena, *args, 2u, 36u, row, 0);
    b41 = stwo_trace_value(arena, *args, 2u, 37u, row, 0);
    b33 = stwo_trace_value(arena, *args, 2u, 38u, row, 0);
    b23 = stwo_trace_value(arena, *args, 2u, 39u, row, 0);
    b40 = stwo_trace_value(arena, *args, 2u, 40u, row, 0);
    b32 = stwo_trace_value(arena, *args, 2u, 41u, row, 0);
    b22 = stwo_trace_value(arena, *args, 2u, 42u, row, 0);
    b39 = stwo_trace_value(arena, *args, 2u, 43u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 347u * 4u);
    StwoCairoQm31 e1 = { b57, b56, b56, b56 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 348u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 349u * 4u);
    e2 = { b45, b56, b56, b56 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 350u * 4u);
    e0 = { b0, b56, b56, b56 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 351u * 4u);
    e2 = { b1, b56, b56, b56 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 352u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 353u * 4u);
    e2 = { b2, b56, b56, b56 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 354u * 4u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 355u * 4u);
    e1 = { b3, b56, b56, b56 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 356u * 4u);
    e3 = { b4, b56, b56, b56 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 357u * 4u);
    e1 = { b5, b56, b56, b56 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 358u * 4u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 359u * 4u);
    e1 = { b6, b56, b56, b56 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 360u * 4u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 361u * 4u);
    e2 = { b58, b56, b56, b56 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 362u * 4u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 363u * 4u);
    e2 = { b43, b56, b56, b56 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 364u * 4u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 365u * 4u);
    e1 = { b55, b56, b56, b56 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 366u * 4u);
    e5 = { b46, b56, b56, b56 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 367u * 4u);
    e1 = { b47, b56, b56, b56 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 368u * 4u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 369u * 4u);
    e1 = { b48, b56, b56, b56 };
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 370u * 4u);
    e6 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 371u * 4u);
    e2 = { b49, b56, b56, b56 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 372u * 4u);
    e6 = { b50, b56, b56, b56 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 373u * 4u);
    e2 = { b51, b56, b56, b56 };
    e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 374u * 4u);
    e6 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 375u * 4u);
    e2 = { b52, b56, b56, b56 };
    e1 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 376u * 4u);
    e7 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 377u * 4u);
    e1 = { b36, b56, b56, b56 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 378u * 4u);
    e7 = stwo_qm31_sub(e1, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 564u * 4u);
    e1 = stwo_qm31_mul(e3, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 565u * 4u);
    e2 = stwo_qm31_mul(e0, e8);
    e8 = stwo_qm31_add(e1, e2);
    e2 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 566u * 4u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 567u * 4u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 568u * 4u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 569u * 4u);
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e6, e7);
    e7 = { b44, b54, b26, b53 };
    e6 = { b35, b25, b42, b34 };
    e4 = stwo_qm31_sub(e6, e7);
    e7 = stwo_qm31_mul(e4, e2);
    e4 = stwo_qm31_sub(e7, e8);
    e7 = { b24, b41, b33, b23 };
    e8 = stwo_qm31_sub(e7, e6);
    e6 = stwo_qm31_mul(e8, e1);
    e8 = stwo_qm31_sub(e6, e3);
    e6 = { b40, b32, b22, b39 };
    e3 = stwo_qm31_sub(e6, e7);
    e6 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e6, e5);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e4, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e8, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
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
