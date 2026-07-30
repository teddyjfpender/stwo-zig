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
stwo_cairo_cuda_eval_v1_3504b59f675007a3(
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
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 204u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 205u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 206u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 207u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 208u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 209u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 210u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 211u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 212u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 213u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 214u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 215u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 216u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 217u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 218u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 219u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 220u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 221u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 222u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 223u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 224u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 225u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 226u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 227u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 228u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 229u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 230u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 231u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 232u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 233u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 234u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 235u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 236u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 237u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 238u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 239u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 240u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 241u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 242u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 243u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 244u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 245u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 246u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 247u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 248u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 249u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 250u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 251u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 252u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 253u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 254u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 255u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 256u, row, 0);
    unsigned b62 = 0u;
    unsigned b63 = 4u;
    unsigned b64 = stwo_m31_mul(b63, b0);
    b63 = 2u;
    b0 = stwo_m31_mul(b63, b10);
    b63 = stwo_m31_add(b64, b0);
    b0 = stwo_m31_add(b63, b20);
    b63 = 40454143u;
    b64 = stwo_m31_add(b0, b63);
    b63 = stwo_m31_sub(b64, b40);
    b64 = stwo_m31_sub(b63, b50);
    b63 = 16u;
    b0 = stwo_m31_mul(b64, b63);
    b63 = 4u;
    b64 = stwo_m31_mul(b63, b1);
    b63 = stwo_m31_add(b0, b64);
    b64 = 2u;
    b0 = stwo_m31_mul(b64, b11);
    b64 = stwo_m31_add(b63, b0);
    b0 = stwo_m31_add(b64, b21);
    b64 = 49554771u;
    b63 = stwo_m31_add(b0, b64);
    b64 = stwo_m31_sub(b63, b41);
    b63 = 16u;
    b0 = stwo_m31_mul(b64, b63);
    b63 = 4u;
    b64 = stwo_m31_mul(b63, b2);
    b63 = stwo_m31_add(b0, b64);
    b64 = 2u;
    b0 = stwo_m31_mul(b64, b12);
    b64 = stwo_m31_add(b63, b0);
    b0 = stwo_m31_add(b64, b22);
    b64 = 55508188u;
    b63 = stwo_m31_add(b0, b64);
    b64 = stwo_m31_sub(b63, b42);
    b63 = 16u;
    b0 = stwo_m31_mul(b64, b63);
    b63 = 4u;
    b64 = stwo_m31_mul(b63, b3);
    b63 = stwo_m31_add(b0, b64);
    b64 = 2u;
    b0 = stwo_m31_mul(b64, b13);
    b64 = stwo_m31_add(b63, b0);
    b0 = stwo_m31_add(b64, b23);
    b64 = 116986206u;
    b63 = stwo_m31_add(b0, b64);
    b64 = stwo_m31_sub(b63, b43);
    b63 = 16u;
    b0 = stwo_m31_mul(b64, b63);
    b63 = 4u;
    b64 = stwo_m31_mul(b63, b4);
    b63 = stwo_m31_add(b0, b64);
    b64 = 2u;
    b0 = stwo_m31_mul(b64, b14);
    b64 = stwo_m31_add(b63, b0);
    b0 = stwo_m31_add(b64, b24);
    b64 = 88680813u;
    b63 = stwo_m31_add(b0, b64);
    b64 = stwo_m31_sub(b63, b44);
    b63 = 16u;
    b0 = stwo_m31_mul(b64, b63);
    b63 = 4u;
    b64 = stwo_m31_mul(b63, b5);
    b63 = stwo_m31_add(b0, b64);
    b64 = 2u;
    b0 = stwo_m31_mul(b64, b15);
    b64 = stwo_m31_add(b63, b0);
    b0 = stwo_m31_add(b64, b25);
    b64 = 45553283u;
    b63 = stwo_m31_add(b0, b64);
    b64 = stwo_m31_sub(b63, b45);
    b63 = 16u;
    b0 = stwo_m31_mul(b64, b63);
    b63 = 4u;
    b64 = stwo_m31_mul(b63, b6);
    b63 = stwo_m31_add(b0, b64);
    b64 = 2u;
    b0 = stwo_m31_mul(b64, b16);
    b64 = stwo_m31_add(b63, b0);
    b0 = stwo_m31_add(b64, b26);
    b64 = 62360091u;
    b63 = stwo_m31_add(b0, b64);
    b64 = stwo_m31_sub(b63, b46);
    b63 = 16u;
    b0 = stwo_m31_mul(b64, b63);
    b63 = 4u;
    b64 = stwo_m31_mul(b63, b7);
    b63 = stwo_m31_add(b0, b64);
    b64 = 2u;
    b0 = stwo_m31_mul(b64, b17);
    b64 = stwo_m31_add(b63, b0);
    b0 = stwo_m31_add(b64, b27);
    b64 = 77099918u;
    b63 = stwo_m31_add(b0, b64);
    b64 = stwo_m31_sub(b63, b47);
    b63 = 136u;
    b0 = stwo_m31_mul(b50, b63);
    b63 = stwo_m31_sub(b64, b0);
    b0 = 16u;
    b64 = stwo_m31_mul(b63, b0);
    b0 = 4u;
    b63 = stwo_m31_mul(b0, b8);
    b0 = stwo_m31_add(b64, b63);
    b63 = 2u;
    b64 = stwo_m31_mul(b63, b18);
    b63 = stwo_m31_add(b0, b64);
    b64 = stwo_m31_add(b63, b28);
    b63 = 22899501u;
    b0 = stwo_m31_add(b64, b63);
    b63 = stwo_m31_sub(b0, b48);
    b0 = 16u;
    b64 = stwo_m31_mul(b63, b0);
    b0 = 4u;
    b63 = stwo_m31_mul(b0, b9);
    b0 = stwo_m31_add(b64, b63);
    b63 = 2u;
    b64 = stwo_m31_mul(b63, b19);
    b63 = stwo_m31_add(b0, b64);
    b64 = stwo_m31_add(b63, b29);
    b63 = 99u;
    b0 = stwo_m31_add(b64, b63);
    b63 = stwo_m31_sub(b0, b49);
    b0 = 256u;
    b64 = stwo_m31_mul(b50, b0);
    b0 = stwo_m31_sub(b63, b64);
    b64 = 4u;
    b63 = stwo_m31_mul(b64, b20);
    b64 = 2u;
    b20 = stwo_m31_mul(b64, b30);
    b64 = stwo_m31_add(b63, b20);
    b20 = stwo_m31_add(b64, b40);
    b64 = 48383197u;
    b40 = stwo_m31_add(b20, b64);
    b64 = stwo_m31_sub(b40, b51);
    b40 = stwo_m31_sub(b64, b61);
    b64 = 16u;
    b51 = stwo_m31_mul(b40, b64);
    b64 = 4u;
    b40 = stwo_m31_mul(b64, b21);
    b64 = stwo_m31_add(b51, b40);
    b40 = 2u;
    b51 = stwo_m31_mul(b40, b31);
    b40 = stwo_m31_add(b64, b51);
    b51 = stwo_m31_add(b40, b41);
    b40 = 48193339u;
    b41 = stwo_m31_add(b51, b40);
    b40 = stwo_m31_sub(b41, b52);
    b41 = 16u;
    b52 = stwo_m31_mul(b40, b41);
    b41 = 4u;
    b40 = stwo_m31_mul(b41, b22);
    b41 = stwo_m31_add(b52, b40);
    b40 = 2u;
    b52 = stwo_m31_mul(b40, b32);
    b40 = stwo_m31_add(b41, b52);
    b52 = stwo_m31_add(b40, b42);
    b40 = 55955004u;
    b42 = stwo_m31_add(b52, b40);
    b40 = stwo_m31_sub(b42, b53);
    b42 = 16u;
    b53 = stwo_m31_mul(b40, b42);
    b42 = 4u;
    b40 = stwo_m31_mul(b42, b23);
    b42 = stwo_m31_add(b53, b40);
    b40 = 2u;
    b53 = stwo_m31_mul(b40, b33);
    b40 = stwo_m31_add(b42, b53);
    b53 = stwo_m31_add(b40, b43);
    b40 = 65659846u;
    b43 = stwo_m31_add(b53, b40);
    b40 = stwo_m31_sub(b43, b54);
    b43 = 16u;
    b54 = stwo_m31_mul(b40, b43);
    b43 = 4u;
    b40 = stwo_m31_mul(b43, b24);
    b43 = stwo_m31_add(b54, b40);
    b40 = 2u;
    b54 = stwo_m31_mul(b40, b34);
    b40 = stwo_m31_add(b43, b54);
    b54 = stwo_m31_add(b40, b44);
    b40 = 68491350u;
    b44 = stwo_m31_add(b54, b40);
    b40 = stwo_m31_sub(b44, b55);
    b44 = 16u;
    b55 = stwo_m31_mul(b40, b44);
    b44 = 4u;
    b40 = stwo_m31_mul(b44, b25);
    b44 = stwo_m31_add(b55, b40);
    b40 = 2u;
    b55 = stwo_m31_mul(b40, b35);
    b40 = stwo_m31_add(b44, b55);
    b55 = stwo_m31_add(b40, b45);
    b40 = 119023582u;
    b45 = stwo_m31_add(b55, b40);
    b40 = stwo_m31_sub(b45, b56);
    b45 = 16u;
    b56 = stwo_m31_mul(b40, b45);
    b45 = 4u;
    b40 = stwo_m31_mul(b45, b26);
    b45 = stwo_m31_add(b56, b40);
    b40 = 2u;
    b56 = stwo_m31_mul(b40, b36);
    b40 = stwo_m31_add(b45, b56);
    b56 = stwo_m31_add(b40, b46);
    b40 = 33439011u;
    b46 = stwo_m31_add(b56, b40);
    b40 = stwo_m31_sub(b46, b57);
    b46 = 16u;
    b57 = stwo_m31_mul(b40, b46);
    b46 = 4u;
    b40 = stwo_m31_mul(b46, b27);
    b46 = stwo_m31_add(b57, b40);
    b40 = 2u;
    b57 = stwo_m31_mul(b40, b37);
    b40 = stwo_m31_add(b46, b57);
    b57 = stwo_m31_add(b40, b47);
    b40 = 58475513u;
    b47 = stwo_m31_add(b57, b40);
    b40 = stwo_m31_sub(b47, b58);
    b47 = 136u;
    b58 = stwo_m31_mul(b61, b47);
    b47 = stwo_m31_sub(b40, b58);
    b58 = 16u;
    b40 = stwo_m31_mul(b47, b58);
    b58 = 4u;
    b47 = stwo_m31_mul(b58, b28);
    b58 = stwo_m31_add(b40, b47);
    b47 = 2u;
    b40 = stwo_m31_mul(b47, b38);
    b47 = stwo_m31_add(b58, b40);
    b40 = stwo_m31_add(b47, b48);
    b47 = 18765944u;
    b48 = stwo_m31_add(b40, b47);
    b47 = stwo_m31_sub(b48, b59);
    b48 = 16u;
    b59 = stwo_m31_mul(b47, b48);
    b48 = 4u;
    b47 = stwo_m31_mul(b48, b29);
    b48 = stwo_m31_add(b59, b47);
    b47 = 2u;
    b59 = stwo_m31_mul(b47, b39);
    b47 = stwo_m31_add(b48, b59);
    b59 = stwo_m31_add(b47, b49);
    b47 = 20u;
    b49 = stwo_m31_add(b59, b47);
    b47 = stwo_m31_sub(b49, b60);
    b49 = 256u;
    b60 = stwo_m31_mul(b61, b49);
    b49 = stwo_m31_sub(b47, b60);
    StwoCairoQm31 e0 = { b0, b62, b62, b62 };
    StwoCairoQm31 e1 = { b49, b62, b62, b62 };
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
