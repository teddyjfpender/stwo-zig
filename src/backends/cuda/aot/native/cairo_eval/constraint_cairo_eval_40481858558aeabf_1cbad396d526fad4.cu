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
stwo_cairo_cuda_eval_v1_a534837de72f25ec(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 105u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 107u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 108u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 109u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 110u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 111u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 112u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 113u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 114u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 115u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 116u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 117u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 118u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 119u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 120u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 121u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 122u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 124u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 126u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 127u, row, 0);
    unsigned b25 = 0u;
    unsigned b26 = 4u;
    unsigned b27 = stwo_m31_mul(b6, b26);
    b26 = stwo_m31_sub(b4, b27);
    b27 = 512u;
    b4 = stwo_m31_mul(b5, b27);
    b27 = stwo_m31_sub(b3, b4);
    b4 = 128u;
    b3 = stwo_m31_mul(b26, b4);
    b4 = stwo_m31_add(b5, b3);
    b3 = 512u;
    b5 = stwo_m31_mul(b7, b3);
    b3 = stwo_m31_sub(b6, b5);
    b5 = stwo_m31_add(b0, b1);
    b1 = 4u;
    b6 = stwo_m31_mul(b12, b1);
    b1 = stwo_m31_sub(b10, b6);
    b6 = 512u;
    b10 = stwo_m31_mul(b11, b6);
    b6 = stwo_m31_sub(b9, b10);
    b10 = 128u;
    b9 = stwo_m31_mul(b1, b10);
    b10 = stwo_m31_add(b11, b9);
    b9 = 512u;
    b26 = stwo_m31_mul(b13, b9);
    b9 = stwo_m31_sub(b12, b26);
    b26 = stwo_m31_add(b0, b2);
    b2 = 4u;
    b0 = stwo_m31_mul(b18, b2);
    b2 = stwo_m31_sub(b16, b0);
    b0 = 512u;
    b16 = stwo_m31_mul(b17, b0);
    b0 = stwo_m31_sub(b15, b16);
    b16 = 128u;
    b15 = stwo_m31_mul(b2, b16);
    b16 = stwo_m31_add(b17, b15);
    b15 = 512u;
    b12 = stwo_m31_mul(b19, b15);
    b15 = stwo_m31_sub(b18, b12);
    b12 = 4u;
    b18 = stwo_m31_mul(b23, b12);
    b12 = stwo_m31_sub(b21, b18);
    b18 = stwo_trace_value(arena, *args, 2u, 56u, row, 0);
    b21 = stwo_trace_value(arena, *args, 2u, 57u, row, 0);
    b23 = stwo_trace_value(arena, *args, 2u, 58u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 2u, 59u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 2u, 60u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 2u, 61u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 2u, 62u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 2u, 63u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 2u, 64u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 2u, 65u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 2u, 66u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 2u, 67u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 2u, 68u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 2u, 69u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 70u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 71u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 72u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 73u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 74u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 75u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 388u * 4u);
    StwoCairoQm31 e1 = { b8, b25, b25, b25 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 389u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 390u * 4u);
    e2 = { b27, b25, b25, b25 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 391u * 4u);
    e0 = { b4, b25, b25, b25 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 392u * 4u);
    e2 = { b3, b25, b25, b25 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 393u * 4u);
    e0 = { b7, b25, b25, b25 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 394u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 395u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 396u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 397u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 398u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 399u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 400u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 401u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 402u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 403u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 404u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 405u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 406u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 407u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 408u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 409u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 410u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 411u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 412u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 413u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 414u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 415u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 416u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 417u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 418u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 419u * 4u);
    e0 = { b11, b25, b25, b25 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 420u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 421u * 4u);
    e3 = { b1, b25, b25, b25 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 422u * 4u);
    e1 = { b13, b25, b25, b25 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 423u * 4u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 424u * 4u);
    e1 = { b5, b25, b25, b25 };
    e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 425u * 4u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(arena, args->ext_params + 426u * 4u);
    e4 = { b14, b25, b25, b25 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 427u * 4u);
    e0 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 428u * 4u);
    e4 = { b14, b25, b25, b25 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 429u * 4u);
    e5 = stwo_qm31_add(e4, e1);
    e4 = stwo_load_qm31(arena, args->ext_params + 430u * 4u);
    e1 = { b6, b25, b25, b25 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 431u * 4u);
    e5 = { b10, b25, b25, b25 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 432u * 4u);
    e1 = { b9, b25, b25, b25 };
    e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 433u * 4u);
    e5 = { b13, b25, b25, b25 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 434u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 435u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 436u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 437u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 438u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 439u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 440u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 441u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 442u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 443u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 444u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 445u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 446u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 447u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 448u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 449u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 450u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 451u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 452u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 453u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 454u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 455u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 456u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 457u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 458u * 4u);
    e1 = stwo_qm31_sub(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 459u * 4u);
    e5 = { b17, b25, b25, b25 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 460u * 4u);
    e4 = stwo_qm31_add(e5, e6);
    e5 = stwo_load_qm31(arena, args->ext_params + 461u * 4u);
    e6 = { b2, b25, b25, b25 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 462u * 4u);
    e4 = { b19, b25, b25, b25 };
    e5 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 463u * 4u);
    e6 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 464u * 4u);
    e4 = { b26, b25, b25, b25 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 465u * 4u);
    e5 = stwo_qm31_add(e4, e7);
    e4 = stwo_load_qm31(arena, args->ext_params + 466u * 4u);
    e7 = { b20, b25, b25, b25 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e4, e7);
    e7 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 467u * 4u);
    e5 = stwo_qm31_sub(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 468u * 4u);
    e7 = { b20, b25, b25, b25 };
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 469u * 4u);
    e8 = stwo_qm31_add(e7, e4);
    e7 = stwo_load_qm31(arena, args->ext_params + 470u * 4u);
    e4 = { b0, b25, b25, b25 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 471u * 4u);
    e8 = { b16, b25, b25, b25 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 472u * 4u);
    e4 = { b15, b25, b25, b25 };
    e9 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 473u * 4u);
    e8 = { b19, b25, b25, b25 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 474u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 475u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 476u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 477u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 478u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 479u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 480u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 481u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 482u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 483u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 484u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 485u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 486u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 487u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 488u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 489u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 490u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 491u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 492u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 493u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 494u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 495u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 496u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 497u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 498u * 4u);
    e4 = stwo_qm31_sub(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 499u * 4u);
    e8 = { b22, b25, b25, b25 };
    e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 500u * 4u);
    e7 = stwo_qm31_add(e8, e9);
    e8 = stwo_load_qm31(arena, args->ext_params + 501u * 4u);
    e9 = { b12, b25, b25, b25 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 502u * 4u);
    e7 = { b24, b25, b25, b25 };
    e8 = stwo_qm31_mul(e10, e7);
    e7 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 503u * 4u);
    e9 = stwo_qm31_sub(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 939u * 4u);
    e7 = stwo_qm31_mul(e3, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 940u * 4u);
    e10 = stwo_qm31_mul(e2, e8);
    e8 = stwo_qm31_add(e7, e10);
    e10 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 941u * 4u);
    e2 = stwo_qm31_mul(e1, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 942u * 4u);
    e7 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e2, e7);
    e7 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 943u * 4u);
    e0 = stwo_qm31_mul(e5, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 944u * 4u);
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_qm31_add(e0, e2);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 945u * 4u);
    e6 = stwo_qm31_mul(e9, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 946u * 4u);
    e0 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e6, e0);
    e0 = stwo_qm31_mul(e4, e9);
    e9 = { b18, b21, b23, b28 };
    e4 = { b29, b30, b31, b32 };
    e6 = stwo_qm31_sub(e4, e9);
    e9 = stwo_qm31_mul(e6, e10);
    e6 = stwo_qm31_sub(e9, e8);
    e9 = { b33, b34, b35, b36 };
    e8 = stwo_qm31_sub(e9, e4);
    e4 = stwo_qm31_mul(e8, e7);
    e8 = stwo_qm31_sub(e4, e3);
    e4 = { b37, b38, b39, b40 };
    e3 = stwo_qm31_sub(e4, e9);
    e9 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e9, e1);
    e9 = { b41, b42, b43, b44 };
    e1 = stwo_qm31_sub(e9, e4);
    e9 = stwo_qm31_mul(e1, e0);
    e1 = stwo_qm31_sub(e9, e5);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e6, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e8, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
