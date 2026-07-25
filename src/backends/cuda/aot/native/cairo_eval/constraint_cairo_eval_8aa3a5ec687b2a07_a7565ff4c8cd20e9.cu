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
stwo_cairo_cuda_eval_v1_f993f616f4573c5c(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 571u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 572u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 573u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 574u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 575u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 576u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 577u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 578u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 579u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 580u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 581u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 582u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 583u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 584u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 585u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 586u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 587u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 588u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 589u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 590u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 591u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 592u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 593u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 594u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 595u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 596u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 597u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 598u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 599u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 600u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 601u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 602u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 603u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 604u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 605u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 606u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 607u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 608u, row, 0);
    unsigned b38 = 0u;
    unsigned b39 = 524288u;
    unsigned b40 = stwo_m31_add(b24, b39);
    b39 = 524288u;
    b24 = stwo_m31_add(b25, b39);
    b39 = 524288u;
    b25 = stwo_m31_add(b26, b39);
    b39 = 524288u;
    b26 = stwo_m31_add(b27, b39);
    b39 = 524288u;
    b27 = stwo_m31_add(b28, b39);
    b39 = 524288u;
    b28 = stwo_m31_add(b29, b39);
    b39 = 524288u;
    b29 = stwo_m31_add(b30, b39);
    b39 = 524288u;
    b30 = stwo_m31_add(b31, b39);
    b39 = 524288u;
    b31 = stwo_m31_add(b32, b39);
    b39 = 524288u;
    b32 = stwo_m31_add(b33, b39);
    b39 = 524288u;
    b33 = stwo_m31_add(b34, b39);
    b39 = 524288u;
    b34 = stwo_m31_add(b35, b39);
    b39 = 524288u;
    b35 = stwo_m31_add(b36, b39);
    b39 = 524288u;
    b36 = stwo_m31_add(b37, b39);
    b39 = stwo_trace_value(arena, *args, 2u, 540u, row, 0);
    b37 = stwo_trace_value(arena, *args, 2u, 541u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 542u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 543u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 544u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 545u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 2u, 546u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 2u, 547u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 2u, 548u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 2u, 549u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 2u, 550u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 2u, 551u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 2u, 552u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 2u, 553u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 2u, 554u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 2u, 555u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 2u, 556u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 2u, 557u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 2u, 558u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 2u, 559u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 2u, 560u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 2u, 561u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 2u, 562u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 2u, 563u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 2u, 564u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 2u, 565u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 566u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 567u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 568u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 569u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 570u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 2u, 571u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 2u, 572u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 2u, 573u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 2u, 574u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 2u, 575u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 576u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 577u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 578u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 2u, 579u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 2u, 580u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 2u, 581u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 2u, 582u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 2u, 583u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 584u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 585u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 2u, 586u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 587u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 2u, 588u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 2u, 589u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 2u, 590u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 2u, 591u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 2u, 592u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 2u, 593u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 2u, 594u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 2u, 595u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 916u * 4u);
    StwoCairoQm31 e1 = { b0, b38, b38, b38 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 917u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 918u * 4u);
    e2 = { b1, b38, b38, b38 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 919u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 920u * 4u);
    e2 = { b2, b38, b38, b38 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 921u * 4u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 922u * 4u);
    e1 = { b3, b38, b38, b38 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 923u * 4u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 924u * 4u);
    e1 = { b4, b38, b38, b38 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 925u * 4u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 926u * 4u);
    e2 = { b5, b38, b38, b38 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 927u * 4u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 928u * 4u);
    e2 = { b6, b38, b38, b38 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 929u * 4u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 930u * 4u);
    e1 = { b7, b38, b38, b38 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 931u * 4u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 932u * 4u);
    e1 = { b8, b38, b38, b38 };
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 933u * 4u);
    e6 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 934u * 4u);
    e2 = { b9, b38, b38, b38 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 935u * 4u);
    e6 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 936u * 4u);
    e2 = { b10, b38, b38, b38 };
    e1 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 937u * 4u);
    e7 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 938u * 4u);
    e1 = { b11, b38, b38, b38 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 939u * 4u);
    e7 = stwo_qm31_sub(e1, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 940u * 4u);
    e1 = { b12, b38, b38, b38 };
    e2 = stwo_qm31_mul(e8, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 941u * 4u);
    e8 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 942u * 4u);
    e2 = { b13, b38, b38, b38 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 943u * 4u);
    e8 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 944u * 4u);
    e2 = { b14, b38, b38, b38 };
    e1 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 945u * 4u);
    e9 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 946u * 4u);
    e1 = { b15, b38, b38, b38 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 947u * 4u);
    e9 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 948u * 4u);
    e1 = { b16, b38, b38, b38 };
    e2 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 949u * 4u);
    e10 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 950u * 4u);
    e2 = { b17, b38, b38, b38 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 951u * 4u);
    e10 = stwo_qm31_sub(e2, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 952u * 4u);
    e2 = { b18, b38, b38, b38 };
    e1 = stwo_qm31_mul(e11, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 953u * 4u);
    e11 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 954u * 4u);
    e1 = { b19, b38, b38, b38 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 955u * 4u);
    e11 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 956u * 4u);
    e1 = { b20, b38, b38, b38 };
    e2 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 957u * 4u);
    e12 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 958u * 4u);
    e2 = { b21, b38, b38, b38 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 959u * 4u);
    e12 = stwo_qm31_sub(e2, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 960u * 4u);
    e2 = { b22, b38, b38, b38 };
    e1 = stwo_qm31_mul(e13, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 961u * 4u);
    e13 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 962u * 4u);
    e1 = { b23, b38, b38, b38 };
    StwoCairoQm31 e14 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 963u * 4u);
    e13 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 964u * 4u);
    e1 = { b40, b38, b38, b38 };
    e2 = stwo_qm31_mul(e14, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 965u * 4u);
    e14 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 966u * 4u);
    e2 = stwo_qm31_sub(e14, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 967u * 4u);
    e14 = { b24, b38, b38, b38 };
    StwoCairoQm31 e15 = stwo_qm31_mul(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 968u * 4u);
    e1 = stwo_qm31_add(e14, e15);
    e14 = stwo_load_qm31(arena, args->ext_params + 969u * 4u);
    e15 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 970u * 4u);
    e1 = { b25, b38, b38, b38 };
    StwoCairoQm31 e16 = stwo_qm31_mul(e14, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 971u * 4u);
    e14 = stwo_qm31_add(e1, e16);
    e1 = stwo_load_qm31(arena, args->ext_params + 972u * 4u);
    e16 = stwo_qm31_sub(e14, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 973u * 4u);
    e14 = { b26, b38, b38, b38 };
    StwoCairoQm31 e17 = stwo_qm31_mul(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 974u * 4u);
    e1 = stwo_qm31_add(e14, e17);
    e14 = stwo_load_qm31(arena, args->ext_params + 975u * 4u);
    e17 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 976u * 4u);
    e1 = { b27, b38, b38, b38 };
    StwoCairoQm31 e18 = stwo_qm31_mul(e14, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 977u * 4u);
    e14 = stwo_qm31_add(e1, e18);
    e1 = stwo_load_qm31(arena, args->ext_params + 978u * 4u);
    e18 = stwo_qm31_sub(e14, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 979u * 4u);
    e14 = { b28, b38, b38, b38 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 980u * 4u);
    e1 = stwo_qm31_add(e14, e19);
    e14 = stwo_load_qm31(arena, args->ext_params + 981u * 4u);
    e19 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 982u * 4u);
    e1 = { b29, b38, b38, b38 };
    StwoCairoQm31 e20 = stwo_qm31_mul(e14, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 983u * 4u);
    e14 = stwo_qm31_add(e1, e20);
    e1 = stwo_load_qm31(arena, args->ext_params + 984u * 4u);
    e20 = stwo_qm31_sub(e14, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 985u * 4u);
    e14 = { b30, b38, b38, b38 };
    StwoCairoQm31 e21 = stwo_qm31_mul(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 986u * 4u);
    e1 = stwo_qm31_add(e14, e21);
    e14 = stwo_load_qm31(arena, args->ext_params + 987u * 4u);
    e21 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 988u * 4u);
    e1 = { b31, b38, b38, b38 };
    StwoCairoQm31 e22 = stwo_qm31_mul(e14, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 989u * 4u);
    e14 = stwo_qm31_add(e1, e22);
    e1 = stwo_load_qm31(arena, args->ext_params + 990u * 4u);
    e22 = stwo_qm31_sub(e14, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 991u * 4u);
    e14 = { b32, b38, b38, b38 };
    StwoCairoQm31 e23 = stwo_qm31_mul(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 992u * 4u);
    e1 = stwo_qm31_add(e14, e23);
    e14 = stwo_load_qm31(arena, args->ext_params + 993u * 4u);
    e23 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 994u * 4u);
    e1 = { b33, b38, b38, b38 };
    StwoCairoQm31 e24 = stwo_qm31_mul(e14, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 995u * 4u);
    e14 = stwo_qm31_add(e1, e24);
    e1 = stwo_load_qm31(arena, args->ext_params + 996u * 4u);
    e24 = stwo_qm31_sub(e14, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 997u * 4u);
    e14 = { b34, b38, b38, b38 };
    StwoCairoQm31 e25 = stwo_qm31_mul(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 998u * 4u);
    e1 = stwo_qm31_add(e14, e25);
    e14 = stwo_load_qm31(arena, args->ext_params + 999u * 4u);
    e25 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 1000u * 4u);
    e1 = { b35, b38, b38, b38 };
    StwoCairoQm31 e26 = stwo_qm31_mul(e14, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1001u * 4u);
    e14 = stwo_qm31_add(e1, e26);
    e1 = stwo_load_qm31(arena, args->ext_params + 1002u * 4u);
    e26 = stwo_qm31_sub(e14, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1003u * 4u);
    e14 = { b36, b38, b38, b38 };
    StwoCairoQm31 e27 = stwo_qm31_mul(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 1004u * 4u);
    e1 = stwo_qm31_add(e14, e27);
    e14 = stwo_load_qm31(arena, args->ext_params + 1005u * 4u);
    e27 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 1574u * 4u);
    e1 = stwo_qm31_mul(e3, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 1575u * 4u);
    StwoCairoQm31 e28 = stwo_qm31_mul(e0, e14);
    e14 = stwo_qm31_add(e1, e28);
    e28 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 1576u * 4u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 1577u * 4u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 1578u * 4u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 1579u * 4u);
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 1580u * 4u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 1581u * 4u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 1582u * 4u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 1583u * 4u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 1584u * 4u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 1585u * 4u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 1586u * 4u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 1587u * 4u);
    e10 = stwo_qm31_mul(e2, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e2, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 1588u * 4u);
    e2 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 1589u * 4u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e2, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 1590u * 4u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 1591u * 4u);
    e2 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e2);
    e2 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 1592u * 4u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 1593u * 4u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e20, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 1594u * 4u);
    e20 = stwo_qm31_mul(e23, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 1595u * 4u);
    e18 = stwo_qm31_mul(e22, e21);
    e21 = stwo_qm31_add(e20, e18);
    e18 = stwo_qm31_mul(e22, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 1596u * 4u);
    e22 = stwo_qm31_mul(e25, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 1597u * 4u);
    e20 = stwo_qm31_mul(e24, e23);
    e23 = stwo_qm31_add(e22, e20);
    e20 = stwo_qm31_mul(e24, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 1598u * 4u);
    e24 = stwo_qm31_mul(e27, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 1599u * 4u);
    e22 = stwo_qm31_mul(e26, e25);
    e25 = stwo_qm31_add(e24, e22);
    e22 = stwo_qm31_mul(e26, e27);
    e27 = { b39, b37, b41, b42 };
    e26 = { b43, b44, b45, b46 };
    e24 = stwo_qm31_sub(e26, e27);
    e27 = stwo_qm31_mul(e24, e28);
    e24 = stwo_qm31_sub(e27, e14);
    e27 = { b47, b48, b49, b50 };
    e14 = stwo_qm31_sub(e27, e26);
    e26 = stwo_qm31_mul(e14, e1);
    e14 = stwo_qm31_sub(e26, e3);
    e26 = { b51, b52, b53, b54 };
    e3 = stwo_qm31_sub(e26, e27);
    e27 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e27, e5);
    e27 = { b55, b56, b57, b58 };
    e5 = stwo_qm31_sub(e27, e26);
    e26 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e26, e7);
    e26 = { b59, b60, b61, b62 };
    e7 = stwo_qm31_sub(e26, e27);
    e27 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e27, e9);
    e27 = { b63, b64, b65, b66 };
    e9 = stwo_qm31_sub(e27, e26);
    e26 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e26, e11);
    e26 = { b67, b68, b69, b70 };
    e11 = stwo_qm31_sub(e26, e27);
    e27 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e27, e13);
    e27 = { b71, b72, b73, b74 };
    e13 = stwo_qm31_sub(e27, e26);
    e26 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e26, e15);
    e26 = { b75, b76, b77, b78 };
    e15 = stwo_qm31_sub(e26, e27);
    e27 = stwo_qm31_mul(e15, e2);
    e15 = stwo_qm31_sub(e27, e17);
    e27 = { b79, b80, b81, b82 };
    e17 = stwo_qm31_sub(e27, e26);
    e26 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e26, e19);
    e26 = { b83, b84, b85, b86 };
    e19 = stwo_qm31_sub(e26, e27);
    e27 = stwo_qm31_mul(e19, e18);
    e19 = stwo_qm31_sub(e27, e21);
    e27 = { b87, b88, b89, b90 };
    e21 = stwo_qm31_sub(e27, e26);
    e26 = stwo_qm31_mul(e21, e20);
    e21 = stwo_qm31_sub(e26, e23);
    e26 = { b91, b92, b93, b94 };
    e23 = stwo_qm31_sub(e26, e27);
    e26 = stwo_qm31_mul(e23, e22);
    e23 = stwo_qm31_sub(e26, e25);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e24, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e14, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e9, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e11, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e13, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e15, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 8u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e17, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 9u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e19, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 10u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e21, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 11u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e23, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 12u) * 4u)));
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
