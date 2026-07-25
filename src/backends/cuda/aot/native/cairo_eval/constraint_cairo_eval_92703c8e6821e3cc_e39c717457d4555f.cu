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
stwo_cairo_cuda_eval_v1_39aa4b3a77212358(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 609u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 610u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 611u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 612u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 613u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 614u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 615u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 616u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 617u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 618u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 619u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 620u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 621u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 622u, row, 0);
    unsigned b14 = 0u;
    unsigned b15 = 524288u;
    unsigned b16 = stwo_m31_add(b0, b15);
    b15 = 524288u;
    b0 = stwo_m31_add(b1, b15);
    b15 = 524288u;
    b1 = stwo_m31_add(b2, b15);
    b15 = 524288u;
    b2 = stwo_m31_add(b3, b15);
    b15 = 524288u;
    b3 = stwo_m31_add(b4, b15);
    b15 = 524288u;
    b4 = stwo_m31_add(b5, b15);
    b15 = 524288u;
    b5 = stwo_m31_add(b6, b15);
    b15 = 524288u;
    b6 = stwo_m31_add(b7, b15);
    b15 = 524288u;
    b7 = stwo_m31_add(b8, b15);
    b15 = 524288u;
    b8 = stwo_m31_add(b9, b15);
    b15 = 524288u;
    b9 = stwo_m31_add(b10, b15);
    b15 = 524288u;
    b10 = stwo_m31_add(b11, b15);
    b15 = 524288u;
    b11 = stwo_m31_add(b12, b15);
    b15 = 524288u;
    b12 = stwo_m31_add(b13, b15);
    b15 = stwo_trace_value(arena, *args, 2u, 592u, row, 0);
    b13 = stwo_trace_value(arena, *args, 2u, 593u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 2u, 594u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 2u, 595u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 2u, 596u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 2u, 597u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 2u, 598u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 2u, 599u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 2u, 600u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 2u, 601u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 2u, 602u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 2u, 603u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 2u, 604u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 2u, 605u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 2u, 606u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 2u, 607u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 2u, 608u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 2u, 609u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 2u, 610u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 2u, 611u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 2u, 612u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 2u, 613u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 2u, 614u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 2u, 615u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 616u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 617u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 618u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 619u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 620u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 621u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 2u, 622u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 2u, 623u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 1006u * 4u);
    StwoCairoQm31 e1 = { b16, b14, b14, b14 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1007u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 1008u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1009u * 4u);
    e0 = { b0, b14, b14, b14 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 1010u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 1011u * 4u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 1012u * 4u);
    e1 = { b1, b14, b14, b14 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1013u * 4u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(arena, args->ext_params + 1014u * 4u);
    e4 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1015u * 4u);
    e0 = { b2, b14, b14, b14 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 1016u * 4u);
    e1 = stwo_qm31_add(e0, e5);
    e0 = stwo_load_qm31(arena, args->ext_params + 1017u * 4u);
    e5 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 1018u * 4u);
    e1 = { b3, b14, b14, b14 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1019u * 4u);
    e0 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(arena, args->ext_params + 1020u * 4u);
    e6 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1021u * 4u);
    e0 = { b4, b14, b14, b14 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 1022u * 4u);
    e1 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(arena, args->ext_params + 1023u * 4u);
    e7 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 1024u * 4u);
    e1 = { b5, b14, b14, b14 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1025u * 4u);
    e0 = stwo_qm31_add(e1, e8);
    e1 = stwo_load_qm31(arena, args->ext_params + 1026u * 4u);
    e8 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1027u * 4u);
    e0 = { b6, b14, b14, b14 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 1028u * 4u);
    e1 = stwo_qm31_add(e0, e9);
    e0 = stwo_load_qm31(arena, args->ext_params + 1029u * 4u);
    e9 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 1030u * 4u);
    e1 = { b7, b14, b14, b14 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1031u * 4u);
    e0 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(arena, args->ext_params + 1032u * 4u);
    e10 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1033u * 4u);
    e0 = { b8, b14, b14, b14 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 1034u * 4u);
    e1 = stwo_qm31_add(e0, e11);
    e0 = stwo_load_qm31(arena, args->ext_params + 1035u * 4u);
    e11 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 1036u * 4u);
    e1 = { b9, b14, b14, b14 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1037u * 4u);
    e0 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(arena, args->ext_params + 1038u * 4u);
    e12 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1039u * 4u);
    e0 = { b10, b14, b14, b14 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 1040u * 4u);
    e1 = stwo_qm31_add(e0, e13);
    e0 = stwo_load_qm31(arena, args->ext_params + 1041u * 4u);
    e13 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 1042u * 4u);
    e1 = { b11, b14, b14, b14 };
    StwoCairoQm31 e14 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1043u * 4u);
    e0 = stwo_qm31_add(e1, e14);
    e1 = stwo_load_qm31(arena, args->ext_params + 1044u * 4u);
    e14 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1045u * 4u);
    e0 = { b12, b14, b14, b14 };
    StwoCairoQm31 e15 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 1046u * 4u);
    e1 = stwo_qm31_add(e0, e15);
    e0 = stwo_load_qm31(arena, args->ext_params + 1047u * 4u);
    e15 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 1600u * 4u);
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 1601u * 4u);
    StwoCairoQm31 e16 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e1, e16);
    e16 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 1602u * 4u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 1603u * 4u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 1604u * 4u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 1605u * 4u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 1606u * 4u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 1607u * 4u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 1608u * 4u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 1609u * 4u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 1610u * 4u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 1611u * 4u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 1612u * 4u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 1613u * 4u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = { b15, b13, b17, b18 };
    e14 = { b19, b20, b21, b22 };
    e12 = stwo_qm31_sub(e14, e15);
    e15 = stwo_qm31_mul(e12, e16);
    e12 = stwo_qm31_sub(e15, e0);
    e15 = { b23, b24, b25, b26 };
    e0 = stwo_qm31_sub(e15, e14);
    e14 = stwo_qm31_mul(e0, e1);
    e0 = stwo_qm31_sub(e14, e3);
    e14 = { b27, b28, b29, b30 };
    e3 = stwo_qm31_sub(e14, e15);
    e15 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e15, e5);
    e15 = { b31, b32, b33, b34 };
    e5 = stwo_qm31_sub(e15, e14);
    e14 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e14, e7);
    e14 = { b35, b36, b37, b38 };
    e7 = stwo_qm31_sub(e14, e15);
    e15 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e15, e9);
    e15 = { b39, b40, b41, b42 };
    e9 = stwo_qm31_sub(e15, e14);
    e14 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e14, e11);
    e14 = { b43, b44, b45, b46 };
    e11 = stwo_qm31_sub(e14, e15);
    e14 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e14, e13);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e12, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e9, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e11, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
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
