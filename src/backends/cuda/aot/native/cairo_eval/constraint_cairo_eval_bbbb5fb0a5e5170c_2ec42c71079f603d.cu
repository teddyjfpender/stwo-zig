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
stwo_cairo_cuda_eval_v1_6247d46c0b9d70a0(
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
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b24 = 0u;
    unsigned b25 = 512u;
    unsigned b26 = stwo_m31_mul(b1, b25);
    b25 = stwo_m31_add(b0, b26);
    b26 = 262144u;
    b0 = stwo_m31_mul(b2, b26);
    b26 = stwo_m31_add(b25, b0);
    b0 = 134217728u;
    b25 = stwo_m31_mul(b3, b0);
    b0 = stwo_m31_add(b26, b25);
    b25 = 4u;
    b26 = stwo_m31_mul(b9, b25);
    b25 = stwo_m31_sub(b7, b26);
    b26 = 512u;
    b7 = stwo_m31_mul(b8, b26);
    b26 = stwo_m31_sub(b6, b7);
    b7 = 128u;
    b6 = stwo_m31_mul(b25, b7);
    b7 = stwo_m31_add(b8, b6);
    b6 = 512u;
    b8 = stwo_m31_mul(b10, b6);
    b6 = stwo_m31_sub(b9, b8);
    b8 = 7u;
    b9 = stwo_m31_add(b0, b8);
    b8 = 4u;
    b0 = stwo_m31_mul(b15, b8);
    b8 = stwo_m31_sub(b13, b0);
    b0 = 512u;
    b13 = stwo_m31_mul(b14, b0);
    b0 = stwo_m31_sub(b12, b13);
    b13 = 128u;
    b12 = stwo_m31_mul(b8, b13);
    b13 = stwo_m31_add(b14, b12);
    b12 = 512u;
    b25 = stwo_m31_mul(b16, b12);
    b12 = stwo_m31_sub(b15, b25);
    b25 = 256u;
    b15 = stwo_m31_mul(b18, b25);
    b25 = stwo_m31_sub(b4, b15);
    b15 = 256u;
    b4 = stwo_m31_mul(b19, b15);
    b15 = stwo_m31_sub(b5, b4);
    b4 = stwo_trace_value(arena, *args, 2u, 56u, row, 0);
    b5 = stwo_trace_value(arena, *args, 2u, 57u, row, 0);
    b3 = stwo_trace_value(arena, *args, 2u, 58u, row, 0);
    b2 = stwo_trace_value(arena, *args, 2u, 59u, row, 0);
    b1 = stwo_trace_value(arena, *args, 2u, 60u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 2u, 61u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 2u, 62u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 2u, 63u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 2u, 64u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 2u, 65u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 2u, 66u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 2u, 67u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 2u, 68u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 2u, 69u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 2u, 70u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 2u, 71u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 2u, 72u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 73u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 74u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 75u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 331u * 4u);
    StwoCairoQm31 e1 = { b11, b24, b24, b24 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 332u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 333u * 4u);
    e2 = { b26, b24, b24, b24 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 334u * 4u);
    e0 = { b7, b24, b24, b24 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 335u * 4u);
    e2 = { b6, b24, b24, b24 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 336u * 4u);
    e0 = { b10, b24, b24, b24 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 337u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 338u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 339u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 340u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 341u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 342u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 343u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 344u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 345u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 346u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 347u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 348u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 349u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 350u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 351u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 352u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 353u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 354u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 355u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 356u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 357u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 358u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 359u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 360u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 361u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 362u * 4u);
    e0 = { b14, b24, b24, b24 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 363u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 364u * 4u);
    e3 = { b8, b24, b24, b24 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 365u * 4u);
    e1 = { b16, b24, b24, b24 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 366u * 4u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 367u * 4u);
    e1 = { b9, b24, b24, b24 };
    e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 368u * 4u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(arena, args->ext_params + 369u * 4u);
    e4 = { b17, b24, b24, b24 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 370u * 4u);
    e0 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 371u * 4u);
    e4 = { b17, b24, b24, b24 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 372u * 4u);
    e5 = stwo_qm31_add(e4, e1);
    e4 = stwo_load_qm31(arena, args->ext_params + 373u * 4u);
    e1 = { b0, b24, b24, b24 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 374u * 4u);
    e5 = { b13, b24, b24, b24 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 375u * 4u);
    e1 = { b12, b24, b24, b24 };
    e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 376u * 4u);
    e5 = { b16, b24, b24, b24 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 377u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 378u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 379u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 380u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 381u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 382u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 383u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 384u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 385u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 386u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 387u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 388u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 389u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 390u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 391u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 392u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 393u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 394u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 395u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 396u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 397u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 398u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 399u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 400u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 401u * 4u);
    e1 = stwo_qm31_sub(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 402u * 4u);
    e5 = { b25, b24, b24, b24 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 403u * 4u);
    e4 = stwo_qm31_add(e5, e6);
    e5 = stwo_load_qm31(arena, args->ext_params + 404u * 4u);
    e6 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 405u * 4u);
    e4 = { b20, b24, b24, b24 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 406u * 4u);
    e6 = stwo_qm31_sub(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 407u * 4u);
    e4 = { b18, b24, b24, b24 };
    e5 = stwo_qm31_mul(e7, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 408u * 4u);
    e7 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(arena, args->ext_params + 409u * 4u);
    e5 = stwo_qm31_add(e7, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 410u * 4u);
    e7 = { b21, b24, b24, b24 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e4, e7);
    e7 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 411u * 4u);
    e5 = stwo_qm31_sub(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 412u * 4u);
    e7 = { b15, b24, b24, b24 };
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 413u * 4u);
    e8 = stwo_qm31_add(e7, e4);
    e7 = stwo_load_qm31(arena, args->ext_params + 414u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 415u * 4u);
    e8 = { b22, b24, b24, b24 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e4, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 416u * 4u);
    e4 = stwo_qm31_sub(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 417u * 4u);
    e8 = { b19, b24, b24, b24 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 418u * 4u);
    e9 = stwo_qm31_add(e8, e7);
    e8 = stwo_load_qm31(arena, args->ext_params + 419u * 4u);
    e7 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 420u * 4u);
    e9 = { b23, b24, b24, b24 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 421u * 4u);
    e7 = stwo_qm31_sub(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 936u * 4u);
    e9 = stwo_qm31_mul(e3, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 937u * 4u);
    e8 = stwo_qm31_mul(e2, e10);
    e10 = stwo_qm31_add(e9, e8);
    e8 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 938u * 4u);
    e2 = stwo_qm31_mul(e1, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 939u * 4u);
    e9 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e2, e9);
    e9 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 940u * 4u);
    e0 = stwo_qm31_mul(e5, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 941u * 4u);
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_qm31_add(e0, e2);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 942u * 4u);
    e6 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 943u * 4u);
    e0 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e6, e0);
    e0 = stwo_qm31_mul(e4, e7);
    e7 = { b4, b5, b3, b2 };
    e4 = { b1, b27, b28, b29 };
    e6 = stwo_qm31_sub(e4, e7);
    e7 = stwo_qm31_mul(e6, e8);
    e6 = stwo_qm31_sub(e7, e10);
    e7 = { b30, b31, b32, b33 };
    e10 = stwo_qm31_sub(e7, e4);
    e4 = stwo_qm31_mul(e10, e9);
    e10 = stwo_qm31_sub(e4, e3);
    e4 = { b34, b35, b36, b37 };
    e3 = stwo_qm31_sub(e4, e7);
    e7 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e7, e1);
    e7 = { b38, b39, b40, b41 };
    e1 = stwo_qm31_sub(e7, e4);
    e7 = stwo_qm31_mul(e1, e0);
    e1 = stwo_qm31_sub(e7, e5);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e6, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e10, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
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
