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
stwo_cairo_cuda_eval_v1_d3da4f9f86ae1e5a(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 127u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 145u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 156u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 157u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 158u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 159u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 160u, row, 0);
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
    b28 = 1u;
    b29 = stwo_m31_add(b0, b28);
    b28 = 4u;
    b3 = stwo_m31_mul(b12, b28);
    b28 = stwo_m31_sub(b5, b3);
    b3 = 512u;
    b5 = stwo_m31_mul(b11, b3);
    b3 = stwo_m31_sub(b4, b5);
    b5 = 128u;
    b4 = stwo_m31_mul(b28, b5);
    b5 = stwo_m31_add(b11, b4);
    b4 = 512u;
    b11 = stwo_m31_mul(b13, b4);
    b4 = stwo_m31_sub(b12, b11);
    b11 = 2u;
    b12 = stwo_m31_add(b0, b11);
    b11 = 4u;
    b28 = stwo_m31_mul(b16, b11);
    b11 = stwo_m31_sub(b7, b28);
    b28 = 512u;
    b7 = stwo_m31_mul(b15, b28);
    b28 = stwo_m31_sub(b6, b7);
    b7 = 128u;
    b6 = stwo_m31_mul(b11, b7);
    b7 = stwo_m31_add(b15, b6);
    b6 = 512u;
    b2 = stwo_m31_mul(b17, b6);
    b6 = stwo_m31_sub(b16, b2);
    b2 = 3u;
    b16 = stwo_m31_add(b0, b2);
    b2 = 4u;
    b1 = stwo_m31_mul(b20, b2);
    b2 = stwo_m31_sub(b9, b1);
    b1 = 512u;
    b9 = stwo_m31_mul(b19, b1);
    b1 = stwo_m31_sub(b8, b9);
    b9 = 128u;
    b8 = stwo_m31_mul(b2, b9);
    b9 = stwo_m31_add(b19, b8);
    b8 = 512u;
    unsigned b30 = stwo_m31_mul(b21, b8);
    b8 = stwo_m31_sub(b20, b30);
    b30 = 4u;
    b20 = stwo_m31_add(b0, b30);
    b30 = 4u;
    b0 = stwo_m31_mul(b24, b30);
    b30 = stwo_m31_sub(b10, b0);
    b0 = stwo_trace_value(arena, *args, 2u, 100u, row, 0);
    b10 = stwo_trace_value(arena, *args, 2u, 101u, row, 0);
    b24 = stwo_trace_value(arena, *args, 2u, 102u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 2u, 103u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 2u, 104u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 2u, 105u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 2u, 106u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 2u, 107u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 2u, 108u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 2u, 109u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 2u, 110u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 111u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 112u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 113u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 114u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 115u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 116u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 2u, 117u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 2u, 118u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 2u, 119u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 2u, 120u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 2u, 121u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 2u, 122u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 2u, 123u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 621u * 4u);
    StwoCairoQm31 e1 = { b29, b27, b27, b27 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 622u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 623u * 4u);
    e2 = { b14, b27, b27, b27 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 624u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 625u * 4u);
    e2 = { b14, b27, b27, b27 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 626u * 4u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 627u * 4u);
    e1 = { b3, b27, b27, b27 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 628u * 4u);
    e3 = { b5, b27, b27, b27 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 629u * 4u);
    e1 = { b4, b27, b27, b27 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 630u * 4u);
    e3 = { b13, b27, b27, b27 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 631u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 632u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 633u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 634u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 635u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 636u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 637u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 638u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 639u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 640u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 641u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 642u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 643u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 644u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 645u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 646u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 647u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 648u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 649u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 650u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 651u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 652u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 653u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 654u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 655u * 4u);
    e1 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 656u * 4u);
    e3 = { b15, b27, b27, b27 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 657u * 4u);
    e2 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(arena, args->ext_params + 658u * 4u);
    e4 = { b11, b27, b27, b27 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 659u * 4u);
    e2 = { b17, b27, b27, b27 };
    e3 = stwo_qm31_mul(e5, e2);
    e2 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 660u * 4u);
    e4 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 661u * 4u);
    e2 = { b12, b27, b27, b27 };
    e5 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 662u * 4u);
    e3 = stwo_qm31_add(e2, e5);
    e2 = stwo_load_qm31(arena, args->ext_params + 663u * 4u);
    e5 = { b18, b27, b27, b27 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e2, e5);
    e5 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 664u * 4u);
    e3 = stwo_qm31_sub(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 665u * 4u);
    e5 = { b18, b27, b27, b27 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 666u * 4u);
    e6 = stwo_qm31_add(e5, e2);
    e5 = stwo_load_qm31(arena, args->ext_params + 667u * 4u);
    e2 = { b28, b27, b27, b27 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e5, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 668u * 4u);
    e6 = { b7, b27, b27, b27 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 669u * 4u);
    e2 = { b6, b27, b27, b27 };
    e7 = stwo_qm31_mul(e5, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 670u * 4u);
    e6 = { b17, b27, b27, b27 };
    e5 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 671u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 672u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 673u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 674u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 675u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 676u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 677u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 678u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 679u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 680u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 681u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 682u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 683u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 684u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 685u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 686u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 687u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 688u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 689u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 690u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 691u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 692u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 693u * 4u);
    e2 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 694u * 4u);
    e6 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 695u * 4u);
    e2 = stwo_qm31_sub(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 696u * 4u);
    e6 = { b19, b27, b27, b27 };
    e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 697u * 4u);
    e5 = stwo_qm31_add(e6, e7);
    e6 = stwo_load_qm31(arena, args->ext_params + 698u * 4u);
    e7 = { b2, b27, b27, b27 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 699u * 4u);
    e5 = { b21, b27, b27, b27 };
    e6 = stwo_qm31_mul(e8, e5);
    e5 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 700u * 4u);
    e7 = stwo_qm31_sub(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 701u * 4u);
    e5 = { b16, b27, b27, b27 };
    e8 = stwo_qm31_mul(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 702u * 4u);
    e6 = stwo_qm31_add(e5, e8);
    e5 = stwo_load_qm31(arena, args->ext_params + 703u * 4u);
    e8 = { b22, b27, b27, b27 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e5, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 704u * 4u);
    e6 = stwo_qm31_sub(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 705u * 4u);
    e8 = { b22, b27, b27, b27 };
    e5 = stwo_qm31_mul(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 706u * 4u);
    e9 = stwo_qm31_add(e8, e5);
    e8 = stwo_load_qm31(arena, args->ext_params + 707u * 4u);
    e5 = { b1, b27, b27, b27 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e8, e5);
    e5 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 708u * 4u);
    e9 = { b9, b27, b27, b27 };
    e8 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 709u * 4u);
    e5 = { b8, b27, b27, b27 };
    e10 = stwo_qm31_mul(e8, e5);
    e5 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 710u * 4u);
    e9 = { b21, b27, b27, b27 };
    e8 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 711u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 712u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 713u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 714u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 715u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 716u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 717u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 718u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 719u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 720u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 721u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 722u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 723u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 724u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 725u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 726u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 727u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 728u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 729u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 730u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 731u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 732u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 733u * 4u);
    e5 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 734u * 4u);
    e9 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 735u * 4u);
    e5 = stwo_qm31_sub(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 736u * 4u);
    e9 = { b23, b27, b27, b27 };
    e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 737u * 4u);
    e8 = stwo_qm31_add(e9, e10);
    e9 = stwo_load_qm31(arena, args->ext_params + 738u * 4u);
    e10 = { b30, b27, b27, b27 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_qm31_add(e8, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 739u * 4u);
    e8 = { b25, b27, b27, b27 };
    e9 = stwo_qm31_mul(e11, e8);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 740u * 4u);
    e10 = stwo_qm31_sub(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 741u * 4u);
    e8 = { b20, b27, b27, b27 };
    e11 = stwo_qm31_mul(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 742u * 4u);
    e9 = stwo_qm31_add(e8, e11);
    e8 = stwo_load_qm31(arena, args->ext_params + 743u * 4u);
    e11 = { b26, b27, b27, b27 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e8, e11);
    e11 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 744u * 4u);
    e9 = stwo_qm31_sub(e11, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 958u * 4u);
    e11 = stwo_qm31_mul(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 959u * 4u);
    e8 = stwo_qm31_mul(e0, e12);
    e12 = stwo_qm31_add(e11, e8);
    e8 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 960u * 4u);
    e0 = stwo_qm31_mul(e3, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 961u * 4u);
    e11 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e0, e11);
    e11 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 962u * 4u);
    e4 = stwo_qm31_mul(e7, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 963u * 4u);
    e0 = stwo_qm31_mul(e2, e3);
    e3 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 964u * 4u);
    e2 = stwo_qm31_mul(e5, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 965u * 4u);
    e4 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e2, e4);
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 966u * 4u);
    e6 = stwo_qm31_mul(e9, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 967u * 4u);
    e2 = stwo_qm31_mul(e10, e5);
    e5 = stwo_qm31_add(e6, e2);
    e2 = stwo_qm31_mul(e10, e9);
    e9 = { b0, b10, b24, b31 };
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
