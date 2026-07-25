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
stwo_cairo_cuda_eval_v1_616f123b49570e5b(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 2u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 3u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 4u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 5u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 6u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 7u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 10u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 11u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 19u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 51u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 52u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 58u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 63u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 64u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 143u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 144u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 145u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 156u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 157u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 158u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 159u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 160u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 161u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 162u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 163u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 164u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 165u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 166u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 167u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 168u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 169u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 170u, row, 0);
    unsigned b66 = 0u;
    unsigned b67 = 4u;
    unsigned b68 = stwo_m31_mul(b39, b67);
    b67 = stwo_m31_sub(b37, b68);
    b68 = 512u;
    b37 = stwo_m31_mul(b38, b68);
    b68 = stwo_m31_sub(b36, b37);
    b37 = 128u;
    b36 = stwo_m31_mul(b67, b37);
    b37 = stwo_m31_add(b38, b36);
    b36 = 512u;
    b38 = stwo_m31_mul(b40, b36);
    b36 = stwo_m31_sub(b39, b38);
    b38 = stwo_trace_value(arena, *args, 2u, 92u, row, 0);
    b39 = stwo_trace_value(arena, *args, 2u, 93u, row, 0);
    b67 = stwo_trace_value(arena, *args, 2u, 94u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 95u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 2u, 96u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 2u, 97u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 2u, 98u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 2u, 99u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 2u, 100u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 101u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 102u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 103u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 628u * 4u);
    StwoCairoQm31 e1 = { b41, b66, b66, b66 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 629u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 630u * 4u);
    e2 = { b68, b66, b66, b66 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 631u * 4u);
    e0 = { b37, b66, b66, b66 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 632u * 4u);
    e2 = { b36, b66, b66, b66 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 633u * 4u);
    e0 = { b40, b66, b66, b66 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 634u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 635u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 636u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 637u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 638u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 639u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 640u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 641u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 642u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 643u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 644u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 645u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 646u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 647u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 648u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 649u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 650u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 651u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 652u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 653u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 654u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 655u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 656u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 657u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 658u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 659u * 4u);
    e0 = { b0, b66, b66, b66 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 660u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 661u * 4u);
    e3 = { b1, b66, b66, b66 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 662u * 4u);
    e1 = { b6, b66, b66, b66 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 663u * 4u);
    e3 = { b7, b66, b66, b66 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 664u * 4u);
    e1 = { b12, b66, b66, b66 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 665u * 4u);
    e3 = { b13, b66, b66, b66 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 666u * 4u);
    e1 = { b18, b66, b66, b66 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 667u * 4u);
    e3 = { b19, b66, b66, b66 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 668u * 4u);
    e1 = { b24, b66, b66, b66 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 669u * 4u);
    e3 = { b25, b66, b66, b66 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 670u * 4u);
    e1 = { b26, b66, b66, b66 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 671u * 4u);
    e3 = { b27, b66, b66, b66 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 672u * 4u);
    e1 = { b42, b66, b66, b66 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 673u * 4u);
    e3 = { b43, b66, b66, b66 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 674u * 4u);
    e1 = { b44, b66, b66, b66 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 675u * 4u);
    e3 = { b45, b66, b66, b66 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 676u * 4u);
    e1 = { b46, b66, b66, b66 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 677u * 4u);
    e3 = { b47, b66, b66, b66 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 678u * 4u);
    e1 = { b48, b66, b66, b66 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 679u * 4u);
    e3 = { b49, b66, b66, b66 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 680u * 4u);
    e1 = stwo_qm31_sub(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 681u * 4u);
    e3 = { b2, b66, b66, b66 };
    e0 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 682u * 4u);
    e4 = stwo_qm31_add(e3, e0);
    e3 = stwo_load_qm31(arena, args->ext_params + 683u * 4u);
    e0 = { b3, b66, b66, b66 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 684u * 4u);
    e4 = { b8, b66, b66, b66 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 685u * 4u);
    e0 = { b9, b66, b66, b66 };
    e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 686u * 4u);
    e4 = { b14, b66, b66, b66 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 687u * 4u);
    e0 = { b15, b66, b66, b66 };
    e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 688u * 4u);
    e4 = { b20, b66, b66, b66 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 689u * 4u);
    e0 = { b21, b66, b66, b66 };
    e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 690u * 4u);
    e4 = { b28, b66, b66, b66 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 691u * 4u);
    e0 = { b29, b66, b66, b66 };
    e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 692u * 4u);
    e4 = { b30, b66, b66, b66 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 693u * 4u);
    e0 = { b31, b66, b66, b66 };
    e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 694u * 4u);
    e4 = { b50, b66, b66, b66 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 695u * 4u);
    e0 = { b51, b66, b66, b66 };
    e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 696u * 4u);
    e4 = { b52, b66, b66, b66 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 697u * 4u);
    e0 = { b53, b66, b66, b66 };
    e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 698u * 4u);
    e4 = { b54, b66, b66, b66 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 699u * 4u);
    e0 = { b55, b66, b66, b66 };
    e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 700u * 4u);
    e4 = { b56, b66, b66, b66 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 701u * 4u);
    e0 = { b57, b66, b66, b66 };
    e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 702u * 4u);
    e4 = stwo_qm31_sub(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 703u * 4u);
    e0 = { b4, b66, b66, b66 };
    e3 = stwo_qm31_mul(e5, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 704u * 4u);
    e5 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 705u * 4u);
    e3 = { b5, b66, b66, b66 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 706u * 4u);
    e5 = { b10, b66, b66, b66 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 707u * 4u);
    e3 = { b11, b66, b66, b66 };
    e6 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 708u * 4u);
    e5 = { b16, b66, b66, b66 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 709u * 4u);
    e3 = { b17, b66, b66, b66 };
    e6 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 710u * 4u);
    e5 = { b22, b66, b66, b66 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 711u * 4u);
    e3 = { b23, b66, b66, b66 };
    e6 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 712u * 4u);
    e5 = { b32, b66, b66, b66 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 713u * 4u);
    e3 = { b33, b66, b66, b66 };
    e6 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 714u * 4u);
    e5 = { b34, b66, b66, b66 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 715u * 4u);
    e3 = { b35, b66, b66, b66 };
    e6 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 716u * 4u);
    e5 = { b58, b66, b66, b66 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 717u * 4u);
    e3 = { b59, b66, b66, b66 };
    e6 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 718u * 4u);
    e5 = { b60, b66, b66, b66 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 719u * 4u);
    e3 = { b61, b66, b66, b66 };
    e6 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 720u * 4u);
    e5 = { b62, b66, b66, b66 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 721u * 4u);
    e3 = { b63, b66, b66, b66 };
    e6 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 722u * 4u);
    e5 = { b64, b66, b66, b66 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 723u * 4u);
    e3 = { b65, b66, b66, b66 };
    e6 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 724u * 4u);
    e5 = stwo_qm31_sub(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 957u * 4u);
    e3 = stwo_qm31_mul(e1, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 958u * 4u);
    e0 = stwo_qm31_mul(e2, e6);
    e6 = stwo_qm31_add(e3, e0);
    e0 = stwo_qm31_mul(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 959u * 4u);
    e2 = stwo_qm31_mul(e5, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 960u * 4u);
    e3 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e2, e3);
    e3 = stwo_qm31_mul(e4, e5);
    e5 = { b38, b39, b67, b69 };
    e4 = { b70, b71, b72, b73 };
    e2 = stwo_qm31_sub(e4, e5);
    e5 = stwo_qm31_mul(e2, e0);
    e2 = stwo_qm31_sub(e5, e6);
    e5 = { b74, b75, b76, b77 };
    e6 = stwo_qm31_sub(e5, e4);
    e5 = stwo_qm31_mul(e6, e3);
    e6 = stwo_qm31_sub(e5, e1);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e6, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
