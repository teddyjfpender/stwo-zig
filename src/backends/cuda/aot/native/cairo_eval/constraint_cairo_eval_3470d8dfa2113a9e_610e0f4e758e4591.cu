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
stwo_cairo_cuda_eval_v1_36b90e52847d585c(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 47u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 48u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 49u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 123u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 124u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 126u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 127u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 143u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 144u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 145u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b28 = 0u;
    unsigned b29 = stwo_m31_add(b0, b1);
    b1 = 4u;
    unsigned b30 = stwo_m31_mul(b8, b1);
    b1 = stwo_m31_sub(b6, b30);
    b30 = 512u;
    b6 = stwo_m31_mul(b7, b30);
    b30 = stwo_m31_sub(b5, b6);
    b6 = 128u;
    b5 = stwo_m31_mul(b1, b6);
    b6 = stwo_m31_add(b7, b5);
    b5 = 512u;
    b7 = stwo_m31_mul(b9, b5);
    b5 = stwo_m31_sub(b8, b7);
    b7 = stwo_m31_add(b0, b2);
    b2 = 4u;
    b8 = stwo_m31_mul(b14, b2);
    b2 = stwo_m31_sub(b12, b8);
    b8 = 512u;
    b12 = stwo_m31_mul(b13, b8);
    b8 = stwo_m31_sub(b11, b12);
    b12 = 128u;
    b11 = stwo_m31_mul(b2, b12);
    b12 = stwo_m31_add(b13, b11);
    b11 = 512u;
    b1 = stwo_m31_mul(b15, b11);
    b11 = stwo_m31_sub(b14, b1);
    b1 = stwo_m31_add(b0, b3);
    b3 = 4u;
    b14 = stwo_m31_mul(b20, b3);
    b3 = stwo_m31_sub(b18, b14);
    b14 = 512u;
    b18 = stwo_m31_mul(b19, b14);
    b14 = stwo_m31_sub(b17, b18);
    b18 = 128u;
    b17 = stwo_m31_mul(b3, b18);
    b18 = stwo_m31_add(b19, b17);
    b17 = 512u;
    unsigned b31 = stwo_m31_mul(b21, b17);
    b17 = stwo_m31_sub(b20, b31);
    b31 = stwo_m31_add(b0, b4);
    b4 = 4u;
    b0 = stwo_m31_mul(b25, b4);
    b4 = stwo_m31_sub(b23, b0);
    b0 = stwo_trace_value(arena, *args, 2u, 72u, row, 0);
    b23 = stwo_trace_value(arena, *args, 2u, 73u, row, 0);
    b25 = stwo_trace_value(arena, *args, 2u, 74u, row, 0);
    b20 = stwo_trace_value(arena, *args, 2u, 75u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 2u, 76u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 2u, 77u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 2u, 78u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 2u, 79u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 2u, 80u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 2u, 81u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 2u, 82u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 83u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 84u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 85u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 86u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 87u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 88u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 2u, 89u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 2u, 90u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 2u, 91u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 2u, 92u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 2u, 93u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 2u, 94u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 2u, 95u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 504u * 4u);
    StwoCairoQm31 e1 = { b29, b28, b28, b28 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 505u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 506u * 4u);
    e2 = { b10, b28, b28, b28 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 507u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 508u * 4u);
    e2 = { b10, b28, b28, b28 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 509u * 4u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 510u * 4u);
    e1 = { b30, b28, b28, b28 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 511u * 4u);
    e3 = { b6, b28, b28, b28 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 512u * 4u);
    e1 = { b5, b28, b28, b28 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 513u * 4u);
    e3 = { b9, b28, b28, b28 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 514u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 515u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 516u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 517u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 518u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 519u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 520u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 521u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 522u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 523u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 524u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 525u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 526u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 527u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 528u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 529u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 530u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 531u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 532u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 533u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 534u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 535u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 536u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 537u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 538u * 4u);
    e1 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 539u * 4u);
    e3 = { b13, b28, b28, b28 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 540u * 4u);
    e2 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(arena, args->ext_params + 541u * 4u);
    e4 = { b2, b28, b28, b28 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 542u * 4u);
    e2 = { b15, b28, b28, b28 };
    e3 = stwo_qm31_mul(e5, e2);
    e2 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 543u * 4u);
    e4 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 544u * 4u);
    e2 = { b7, b28, b28, b28 };
    e5 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 545u * 4u);
    e3 = stwo_qm31_add(e2, e5);
    e2 = stwo_load_qm31(arena, args->ext_params + 546u * 4u);
    e5 = { b16, b28, b28, b28 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e2, e5);
    e5 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 547u * 4u);
    e3 = stwo_qm31_sub(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 548u * 4u);
    e5 = { b16, b28, b28, b28 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 549u * 4u);
    e6 = stwo_qm31_add(e5, e2);
    e5 = stwo_load_qm31(arena, args->ext_params + 550u * 4u);
    e2 = { b8, b28, b28, b28 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e5, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 551u * 4u);
    e6 = { b12, b28, b28, b28 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 552u * 4u);
    e2 = { b11, b28, b28, b28 };
    e7 = stwo_qm31_mul(e5, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 553u * 4u);
    e6 = { b15, b28, b28, b28 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 554u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 555u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 556u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 557u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 558u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 559u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 560u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 561u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 562u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 563u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 564u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 565u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 566u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 567u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 568u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 569u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 570u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 571u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 572u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 573u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 574u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 575u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 576u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 577u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 578u * 4u);
    e2 = stwo_qm31_sub(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 579u * 4u);
    e6 = { b19, b28, b28, b28 };
    e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 580u * 4u);
    e5 = stwo_qm31_add(e6, e7);
    e6 = stwo_load_qm31(arena, args->ext_params + 581u * 4u);
    e7 = { b3, b28, b28, b28 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 582u * 4u);
    e5 = { b21, b28, b28, b28 };
    e6 = stwo_qm31_mul(e8, e5);
    e5 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 583u * 4u);
    e7 = stwo_qm31_sub(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 584u * 4u);
    e5 = { b1, b28, b28, b28 };
    e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 585u * 4u);
    e6 = stwo_qm31_add(e5, e8);
    e5 = stwo_load_qm31(arena, args->ext_params + 586u * 4u);
    e8 = { b22, b28, b28, b28 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e5, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 587u * 4u);
    e6 = stwo_qm31_sub(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 588u * 4u);
    e8 = { b22, b28, b28, b28 };
    e5 = stwo_qm31_mul(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 589u * 4u);
    e9 = stwo_qm31_add(e8, e5);
    e8 = stwo_load_qm31(arena, args->ext_params + 590u * 4u);
    e5 = { b14, b28, b28, b28 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e8, e5);
    e5 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 591u * 4u);
    e9 = { b18, b28, b28, b28 };
    e8 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 592u * 4u);
    e5 = { b17, b28, b28, b28 };
    e10 = stwo_qm31_mul(e8, e5);
    e5 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 593u * 4u);
    e9 = { b21, b28, b28, b28 };
    e8 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 594u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 595u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 596u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 597u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 598u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 599u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 600u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 601u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 602u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 603u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 604u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 605u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 606u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 607u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 608u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 609u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 610u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 611u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 612u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 613u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 614u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 615u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 616u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 617u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 618u * 4u);
    e5 = stwo_qm31_sub(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 619u * 4u);
    e9 = { b24, b28, b28, b28 };
    e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 620u * 4u);
    e8 = stwo_qm31_add(e9, e10);
    e9 = stwo_load_qm31(arena, args->ext_params + 621u * 4u);
    e10 = { b4, b28, b28, b28 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 622u * 4u);
    e8 = { b26, b28, b28, b28 };
    e9 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 623u * 4u);
    e10 = stwo_qm31_sub(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 624u * 4u);
    e8 = { b31, b28, b28, b28 };
    e11 = stwo_qm31_mul(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 625u * 4u);
    e9 = stwo_qm31_add(e8, e11);
    e8 = stwo_load_qm31(arena, args->ext_params + 626u * 4u);
    e11 = { b27, b28, b28, b28 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e8, e11);
    e11 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 627u * 4u);
    e9 = stwo_qm31_sub(e11, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 947u * 4u);
    e11 = stwo_qm31_mul(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 948u * 4u);
    e8 = stwo_qm31_mul(e0, e12);
    e12 = stwo_qm31_add(e11, e8);
    e8 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 949u * 4u);
    e0 = stwo_qm31_mul(e3, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 950u * 4u);
    e11 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e0, e11);
    e11 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 951u * 4u);
    e4 = stwo_qm31_mul(e7, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 952u * 4u);
    e0 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 953u * 4u);
    e2 = stwo_qm31_mul(e5, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 954u * 4u);
    e4 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e2, e4);
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 955u * 4u);
    e6 = stwo_qm31_mul(e9, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 956u * 4u);
    e2 = stwo_qm31_mul(e10, e5);
    e5 = stwo_qm31_add(e6, e2);
    e2 = stwo_qm31_mul(e10, e9);
    e9 = { b0, b23, b25, b20 };
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
