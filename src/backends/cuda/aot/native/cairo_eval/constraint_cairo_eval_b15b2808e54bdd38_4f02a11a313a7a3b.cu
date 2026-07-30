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
stwo_cairo_cuda_eval_v1_42707fc50382d5bb(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 58u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 59u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 60u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 61u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 62u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 63u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 64u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 65u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 66u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 67u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 71u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b27 = 0u;
    unsigned b28 = 512u;
    unsigned b29 = stwo_m31_mul(b1, b28);
    b28 = stwo_m31_add(b0, b29);
    b29 = 262144u;
    b0 = stwo_m31_mul(b2, b29);
    b29 = stwo_m31_add(b28, b0);
    b0 = 134217728u;
    b28 = stwo_m31_mul(b3, b0);
    b0 = stwo_m31_add(b29, b28);
    b28 = 3u;
    b29 = stwo_m31_add(b0, b28);
    b28 = 4u;
    b3 = stwo_m31_mul(b7, b28);
    b28 = stwo_m31_sub(b5, b3);
    b3 = 512u;
    b5 = stwo_m31_mul(b6, b3);
    b3 = stwo_m31_sub(b4, b5);
    b5 = 128u;
    b4 = stwo_m31_mul(b28, b5);
    b5 = stwo_m31_add(b6, b4);
    b4 = 512u;
    b6 = stwo_m31_mul(b8, b4);
    b4 = stwo_m31_sub(b7, b6);
    b6 = 4u;
    b7 = stwo_m31_add(b0, b6);
    b6 = 4u;
    b28 = stwo_m31_mul(b13, b6);
    b6 = stwo_m31_sub(b11, b28);
    b28 = 512u;
    b11 = stwo_m31_mul(b12, b28);
    b28 = stwo_m31_sub(b10, b11);
    b11 = 128u;
    b10 = stwo_m31_mul(b6, b11);
    b11 = stwo_m31_add(b12, b10);
    b10 = 512u;
    b2 = stwo_m31_mul(b14, b10);
    b10 = stwo_m31_sub(b13, b2);
    b2 = 5u;
    b13 = stwo_m31_add(b0, b2);
    b2 = 4u;
    b1 = stwo_m31_mul(b19, b2);
    b2 = stwo_m31_sub(b17, b1);
    b1 = 512u;
    b17 = stwo_m31_mul(b18, b1);
    b1 = stwo_m31_sub(b16, b17);
    b17 = 128u;
    b16 = stwo_m31_mul(b2, b17);
    b17 = stwo_m31_add(b18, b16);
    b16 = 512u;
    unsigned b30 = stwo_m31_mul(b20, b16);
    b16 = stwo_m31_sub(b19, b30);
    b30 = 6u;
    b19 = stwo_m31_add(b0, b30);
    b30 = 4u;
    b0 = stwo_m31_mul(b24, b30);
    b30 = stwo_m31_sub(b22, b0);
    b0 = stwo_trace_value(arena, *args, 2u, 36u, row, 0);
    b22 = stwo_trace_value(arena, *args, 2u, 37u, row, 0);
    b24 = stwo_trace_value(arena, *args, 2u, 38u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 2u, 39u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 2u, 40u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 2u, 41u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 2u, 42u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 2u, 43u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 2u, 44u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 2u, 45u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 2u, 46u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 47u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 48u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 49u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 50u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 51u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 52u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 2u, 53u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 2u, 54u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 2u, 55u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 2u, 56u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 2u, 57u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 2u, 58u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 2u, 59u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 207u * 4u);
    StwoCairoQm31 e1 = { b29, b27, b27, b27 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 208u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 209u * 4u);
    e2 = { b9, b27, b27, b27 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 210u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 211u * 4u);
    e2 = { b9, b27, b27, b27 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 212u * 4u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 213u * 4u);
    e1 = { b3, b27, b27, b27 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 214u * 4u);
    e3 = { b5, b27, b27, b27 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 215u * 4u);
    e1 = { b4, b27, b27, b27 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 216u * 4u);
    e3 = { b8, b27, b27, b27 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 217u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 218u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 219u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 220u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 221u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 222u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 223u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 224u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 225u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 226u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 227u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 228u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 229u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 230u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 231u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 232u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 233u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 234u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 235u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 236u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 237u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 238u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 239u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 240u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 241u * 4u);
    e1 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 242u * 4u);
    e3 = { b12, b27, b27, b27 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 243u * 4u);
    e2 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(arena, args->ext_params + 244u * 4u);
    e4 = { b6, b27, b27, b27 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 245u * 4u);
    e2 = { b14, b27, b27, b27 };
    e3 = stwo_qm31_mul(e5, e2);
    e2 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 246u * 4u);
    e4 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 247u * 4u);
    e2 = { b7, b27, b27, b27 };
    e5 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 248u * 4u);
    e3 = stwo_qm31_add(e2, e5);
    e2 = stwo_load_qm31(arena, args->ext_params + 249u * 4u);
    e5 = { b15, b27, b27, b27 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e2, e5);
    e5 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 250u * 4u);
    e3 = stwo_qm31_sub(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 251u * 4u);
    e5 = { b15, b27, b27, b27 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 252u * 4u);
    e6 = stwo_qm31_add(e5, e2);
    e5 = stwo_load_qm31(arena, args->ext_params + 253u * 4u);
    e2 = { b28, b27, b27, b27 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e5, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 254u * 4u);
    e6 = { b11, b27, b27, b27 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 255u * 4u);
    e2 = { b10, b27, b27, b27 };
    e7 = stwo_qm31_mul(e5, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 256u * 4u);
    e6 = { b14, b27, b27, b27 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 257u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 258u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 259u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 260u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 261u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 262u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 263u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 264u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 265u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 266u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 267u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 268u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 269u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 270u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 271u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 272u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 273u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 274u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 275u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 276u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 277u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 278u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 279u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 280u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 281u * 4u);
    e2 = stwo_qm31_sub(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 282u * 4u);
    e6 = { b18, b27, b27, b27 };
    e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 283u * 4u);
    e5 = stwo_qm31_add(e6, e7);
    e6 = stwo_load_qm31(arena, args->ext_params + 284u * 4u);
    e7 = { b2, b27, b27, b27 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 285u * 4u);
    e5 = { b20, b27, b27, b27 };
    e6 = stwo_qm31_mul(e8, e5);
    e5 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 286u * 4u);
    e7 = stwo_qm31_sub(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 287u * 4u);
    e5 = { b13, b27, b27, b27 };
    e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 288u * 4u);
    e6 = stwo_qm31_add(e5, e8);
    e5 = stwo_load_qm31(arena, args->ext_params + 289u * 4u);
    e8 = { b21, b27, b27, b27 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e5, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 290u * 4u);
    e6 = stwo_qm31_sub(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 291u * 4u);
    e8 = { b21, b27, b27, b27 };
    e5 = stwo_qm31_mul(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 292u * 4u);
    e9 = stwo_qm31_add(e8, e5);
    e8 = stwo_load_qm31(arena, args->ext_params + 293u * 4u);
    e5 = { b1, b27, b27, b27 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e8, e5);
    e5 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 294u * 4u);
    e9 = { b17, b27, b27, b27 };
    e8 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 295u * 4u);
    e5 = { b16, b27, b27, b27 };
    e10 = stwo_qm31_mul(e8, e5);
    e5 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 296u * 4u);
    e9 = { b20, b27, b27, b27 };
    e8 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 297u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 298u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 299u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 300u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 301u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 302u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 303u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 304u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 305u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 306u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 307u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 308u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 309u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 310u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 311u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 312u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 313u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 314u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 315u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 316u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 317u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 318u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 319u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 320u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 321u * 4u);
    e5 = stwo_qm31_sub(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 322u * 4u);
    e9 = { b23, b27, b27, b27 };
    e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 323u * 4u);
    e8 = stwo_qm31_add(e9, e10);
    e9 = stwo_load_qm31(arena, args->ext_params + 324u * 4u);
    e10 = { b30, b27, b27, b27 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 325u * 4u);
    e8 = { b25, b27, b27, b27 };
    e9 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 326u * 4u);
    e10 = stwo_qm31_sub(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 327u * 4u);
    e8 = { b19, b27, b27, b27 };
    e11 = stwo_qm31_mul(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 328u * 4u);
    e9 = stwo_qm31_add(e8, e11);
    e8 = stwo_load_qm31(arena, args->ext_params + 329u * 4u);
    e11 = { b26, b27, b27, b27 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e8, e11);
    e11 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 330u * 4u);
    e9 = stwo_qm31_sub(e11, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 926u * 4u);
    e11 = stwo_qm31_mul(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 927u * 4u);
    e8 = stwo_qm31_mul(e0, e12);
    e12 = stwo_qm31_add(e11, e8);
    e8 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 928u * 4u);
    e0 = stwo_qm31_mul(e3, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 929u * 4u);
    e11 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e0, e11);
    e11 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 930u * 4u);
    e4 = stwo_qm31_mul(e7, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 931u * 4u);
    e0 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 932u * 4u);
    e2 = stwo_qm31_mul(e5, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 933u * 4u);
    e4 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e2, e4);
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 934u * 4u);
    e6 = stwo_qm31_mul(e9, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 935u * 4u);
    e2 = stwo_qm31_mul(e10, e5);
    e5 = stwo_qm31_add(e6, e2);
    e2 = stwo_qm31_mul(e10, e9);
    e9 = { b0, b22, b24, b31 };
    e10 = { b32, b33, b34, b35 };
    e6 = stwo_qm31_sub(e10, e9);
    e9 = stwo_qm31_mul(e6, e8);
    e6 = stwo_qm31_sub(e9, e12);
    e9 = { b36, b37, b38, b39 };
    e12 = stwo_qm31_sub(e9, e10);
    e10 = stwo_qm31_mul(e12, e11);
    e12 = stwo_qm31_sub(e10, e1);
    e10 = { b40, b41, b42, b43 };
    e1 = stwo_qm31_sub(e10, e9);
    e9 = stwo_qm31_mul(e1, e0);
    e1 = stwo_qm31_sub(e9, e3);
    e9 = { b44, b45, b46, b47 };
    e3 = stwo_qm31_sub(e9, e10);
    e10 = stwo_qm31_mul(e3, e4);
    e3 = stwo_qm31_sub(e10, e7);
    e10 = { b48, b49, b50, b51 };
    e7 = stwo_qm31_sub(e10, e9);
    e10 = stwo_qm31_mul(e7, e2);
    e7 = stwo_qm31_sub(e10, e5);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e6, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e12, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
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
