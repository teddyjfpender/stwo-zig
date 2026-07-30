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
stwo_cairo_cuda_eval_v1_02055560ac37db92(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 0u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 1u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 3u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 4u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 5u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 6u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 7u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 8u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 9u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 10u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 11u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 184u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 185u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 186u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 187u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 188u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 189u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 190u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 191u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 192u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 193u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 194u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 195u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 196u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 197u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 198u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 199u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 200u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 201u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 202u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 203u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 204u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 205u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 206u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 207u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 208u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 209u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 210u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 211u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 240u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 241u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 242u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 243u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 244u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 245u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 246u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 247u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 248u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 249u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 250u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 251u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 252u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 253u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 254u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 255u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 256u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 257u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 258u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 259u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 260u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 261u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 262u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 263u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 264u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 265u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 266u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 267u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 296u, row, 0);
    unsigned b72 = 0u;
    unsigned b73 = 1u;
    unsigned b74 = stwo_m31_add(b1, b73);
    b73 = stwo_trace_value(arena, *args, 2u, 252u, row, 0);
    b1 = stwo_trace_value(arena, *args, 2u, 253u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 254u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 255u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 256u, row, -1);
    unsigned b78 = stwo_trace_value(arena, *args, 2u, 256u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 2u, 257u, row, -1);
    unsigned b80 = stwo_trace_value(arena, *args, 2u, 257u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 2u, 258u, row, -1);
    unsigned b82 = stwo_trace_value(arena, *args, 2u, 258u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 259u, row, -1);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 259u, row, 0);
    StwoCairoQm31 e0 = { b71, b72, b72, b72 };
    StwoCairoQm31 e1 = stwo_qm31_neg(e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 553u * 4u);
    StwoCairoQm31 e2 = { b0, b72, b72, b72 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 554u * 4u);
    e0 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(arena, args->ext_params + 555u * 4u);
    e3 = { b74, b72, b72, b72 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 556u * 4u);
    e0 = { b2, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 557u * 4u);
    e3 = { b3, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 558u * 4u);
    e0 = { b4, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 559u * 4u);
    e3 = { b5, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 560u * 4u);
    e0 = { b6, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 561u * 4u);
    e3 = { b7, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 562u * 4u);
    e0 = { b8, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 563u * 4u);
    e3 = { b9, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 564u * 4u);
    e0 = { b10, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 565u * 4u);
    e3 = { b11, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 566u * 4u);
    e0 = { b12, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 567u * 4u);
    e3 = { b13, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e0, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 568u * 4u);
    e0 = { b14, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e0);
    e0 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 569u * 4u);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 570u * 4u);
    e0 = { b15, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 571u * 4u);
    e3 = { b16, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 572u * 4u);
    e0 = { b17, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 573u * 4u);
    e3 = { b18, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 574u * 4u);
    e0 = { b19, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 575u * 4u);
    e3 = { b20, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 576u * 4u);
    e0 = { b21, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 577u * 4u);
    e3 = { b22, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 578u * 4u);
    e0 = { b23, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 579u * 4u);
    e3 = { b24, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 580u * 4u);
    e0 = { b25, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 581u * 4u);
    e3 = { b26, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 582u * 4u);
    e0 = { b27, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 583u * 4u);
    e3 = { b28, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 584u * 4u);
    e0 = { b29, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 585u * 4u);
    e3 = { b30, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 586u * 4u);
    e0 = { b31, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 587u * 4u);
    e3 = { b32, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 588u * 4u);
    e0 = { b33, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 589u * 4u);
    e3 = { b34, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 590u * 4u);
    e0 = { b35, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 591u * 4u);
    e3 = { b36, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 592u * 4u);
    e0 = { b37, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 593u * 4u);
    e3 = { b38, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 594u * 4u);
    e0 = { b39, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 595u * 4u);
    e3 = { b40, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 596u * 4u);
    e0 = { b41, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 597u * 4u);
    e3 = { b42, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 598u * 4u);
    e0 = { b43, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 599u * 4u);
    e3 = { b44, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 600u * 4u);
    e0 = { b45, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 601u * 4u);
    e3 = { b46, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 602u * 4u);
    e0 = { b47, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 603u * 4u);
    e3 = { b48, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 604u * 4u);
    e0 = { b49, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 605u * 4u);
    e3 = { b50, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 606u * 4u);
    e0 = { b51, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 607u * 4u);
    e3 = { b52, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 608u * 4u);
    e0 = { b53, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 609u * 4u);
    e3 = { b54, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 610u * 4u);
    e0 = { b55, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 611u * 4u);
    e3 = { b56, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 612u * 4u);
    e0 = { b57, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 613u * 4u);
    e3 = { b58, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 614u * 4u);
    e0 = { b59, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 615u * 4u);
    e3 = { b60, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 616u * 4u);
    e0 = { b61, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 617u * 4u);
    e3 = { b62, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 618u * 4u);
    e0 = { b63, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 619u * 4u);
    e3 = { b64, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 620u * 4u);
    e0 = { b65, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 621u * 4u);
    e3 = { b66, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 622u * 4u);
    e0 = { b67, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 623u * 4u);
    e3 = { b68, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 624u * 4u);
    e0 = { b69, b72, b72, b72 };
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 625u * 4u);
    e3 = { b70, b72, b72, b72 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 626u * 4u);
    e0 = stwo_qm31_sub(e3, e2);
    e2 = { b73, b1, b75, b76 };
    e3 = { b77, b79, b81, b83 };
    e4 = { b78, b80, b82, b84 };
    StwoCairoQm31 e5 = stwo_qm31_sub(e4, e3);
    e4 = stwo_qm31_sub(e5, e2);
    e5 = stwo_load_qm31(arena, args->ext_params + 754u * 4u);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_qm31_mul(e2, e0);
    e2 = stwo_qm31_sub(e5, e1);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
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
