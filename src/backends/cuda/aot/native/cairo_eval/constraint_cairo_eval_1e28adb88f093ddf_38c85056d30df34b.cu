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
stwo_cairo_cuda_eval_v1_feeb1f48145116cd(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 0u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 1u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 2u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 3u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 4u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 5u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 277u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 278u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 279u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 280u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 281u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 282u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 283u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 284u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 285u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 286u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 323u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 324u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 325u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 326u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 327u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 328u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 329u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 330u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 331u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 332u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 333u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 334u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 335u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 336u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 337u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 338u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 339u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 340u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 341u, row, 0);
    unsigned b35 = 0u;
    unsigned b36 = stwo_m31_sub(b6, b16);
    b6 = 512u;
    unsigned b37 = stwo_m31_mul(b17, b6);
    b6 = stwo_m31_sub(b36, b37);
    b37 = 8192u;
    b36 = stwo_m31_mul(b6, b37);
    b37 = stwo_m31_sub(b7, b18);
    b7 = 512u;
    b6 = stwo_m31_mul(b19, b7);
    b7 = stwo_m31_sub(b37, b6);
    b6 = 8192u;
    b37 = stwo_m31_mul(b7, b6);
    b6 = stwo_m31_sub(b8, b20);
    b8 = 512u;
    b7 = stwo_m31_mul(b21, b8);
    b8 = stwo_m31_sub(b6, b7);
    b7 = 8192u;
    b6 = stwo_m31_mul(b8, b7);
    b7 = stwo_m31_sub(b9, b22);
    b9 = 512u;
    b8 = stwo_m31_mul(b23, b9);
    b9 = stwo_m31_sub(b7, b8);
    b8 = 8192u;
    b7 = stwo_m31_mul(b9, b8);
    b8 = stwo_m31_sub(b10, b24);
    b10 = 512u;
    b9 = stwo_m31_mul(b25, b10);
    b10 = stwo_m31_sub(b8, b9);
    b9 = 8192u;
    b8 = stwo_m31_mul(b10, b9);
    b9 = stwo_m31_sub(b11, b26);
    b11 = 512u;
    b10 = stwo_m31_mul(b27, b11);
    b11 = stwo_m31_sub(b9, b10);
    b10 = 8192u;
    b9 = stwo_m31_mul(b11, b10);
    b10 = stwo_m31_sub(b12, b28);
    b12 = 512u;
    b11 = stwo_m31_mul(b29, b12);
    b12 = stwo_m31_sub(b10, b11);
    b11 = 8192u;
    b10 = stwo_m31_mul(b12, b11);
    b11 = stwo_m31_sub(b13, b30);
    b13 = 512u;
    b12 = stwo_m31_mul(b31, b13);
    b13 = stwo_m31_sub(b11, b12);
    b12 = 8192u;
    b11 = stwo_m31_mul(b13, b12);
    b12 = stwo_m31_sub(b14, b32);
    b14 = 512u;
    b13 = stwo_m31_mul(b33, b14);
    b14 = stwo_m31_sub(b12, b13);
    b13 = 8192u;
    b12 = stwo_m31_mul(b14, b13);
    b13 = stwo_trace_value(arena, *args, 2u, 48u, row, 0);
    b14 = stwo_trace_value(arena, *args, 2u, 49u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 2u, 50u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 51u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 52u, row, -1);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 52u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 53u, row, -1);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 53u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 54u, row, -1);
    unsigned b45 = stwo_trace_value(arena, *args, 2u, 54u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 2u, 55u, row, -1);
    unsigned b47 = stwo_trace_value(arena, *args, 2u, 55u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 509u * 4u);
    StwoCairoQm31 e1 = { b5, b35, b35, b35 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 510u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 511u * 4u);
    e2 = { b16, b35, b35, b35 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 512u * 4u);
    e0 = { b17, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 513u * 4u);
    e2 = { b36, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 514u * 4u);
    e0 = { b18, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 515u * 4u);
    e2 = { b19, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 516u * 4u);
    e0 = { b37, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 517u * 4u);
    e2 = { b20, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 518u * 4u);
    e0 = { b21, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 519u * 4u);
    e2 = { b6, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 520u * 4u);
    e0 = { b22, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 521u * 4u);
    e2 = { b23, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 522u * 4u);
    e0 = { b7, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 523u * 4u);
    e2 = { b24, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 524u * 4u);
    e0 = { b25, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 525u * 4u);
    e2 = { b8, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 526u * 4u);
    e0 = { b26, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 527u * 4u);
    e2 = { b27, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 528u * 4u);
    e0 = { b9, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 529u * 4u);
    e2 = { b28, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 530u * 4u);
    e0 = { b29, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 531u * 4u);
    e2 = { b10, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 532u * 4u);
    e0 = { b30, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 533u * 4u);
    e2 = { b31, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 534u * 4u);
    e0 = { b11, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 535u * 4u);
    e2 = { b32, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 536u * 4u);
    e0 = { b33, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 537u * 4u);
    e2 = { b12, b35, b35, b35 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 538u * 4u);
    e0 = { b15, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 539u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = { b34, b35, b35, b35 };
    e0 = stwo_qm31_neg(e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 540u * 4u);
    e3 = { b0, b35, b35, b35 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e1, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 541u * 4u);
    e1 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(arena, args->ext_params + 542u * 4u);
    e4 = { b1, b35, b35, b35 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e1, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 543u * 4u);
    e1 = { b2, b35, b35, b35 };
    e3 = stwo_qm31_mul(e5, e1);
    e1 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 544u * 4u);
    e4 = { b3, b35, b35, b35 };
    e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e1, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 545u * 4u);
    e1 = { b4, b35, b35, b35 };
    e3 = stwo_qm31_mul(e5, e1);
    e1 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 546u * 4u);
    e4 = { b5, b35, b35, b35 };
    e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e1, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 547u * 4u);
    e1 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 574u * 4u);
    e4 = stwo_qm31_mul(e1, e5);
    e5 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_qm31_mul(e2, e1);
    e1 = { b13, b14, b38, b39 };
    e2 = { b40, b42, b44, b46 };
    e4 = { b41, b43, b45, b47 };
    e3 = stwo_qm31_sub(e4, e2);
    e4 = stwo_qm31_sub(e3, e1);
    e3 = stwo_load_qm31(arena, args->ext_params + 575u * 4u);
    e1 = stwo_qm31_add(e4, e3);
    e3 = stwo_qm31_mul(e1, e5);
    e1 = stwo_qm31_sub(e3, e0);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
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
