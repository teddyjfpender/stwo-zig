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
stwo_cairo_cuda_eval_v1_1792a962139529f1(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 463u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 464u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 465u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 466u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 467u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 468u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 469u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 470u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 471u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 472u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 473u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 474u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 475u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 476u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 477u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 478u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 479u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 480u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 481u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 482u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 483u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 484u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 485u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 486u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 487u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 488u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 489u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 490u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 491u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 492u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 493u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 494u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 495u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 496u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 497u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 498u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 499u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 500u, row, 0);
    unsigned b38 = 0u;
    unsigned b39 = 524288u;
    unsigned b40 = stwo_m31_add(b20, b39);
    b39 = 524288u;
    b20 = stwo_m31_add(b21, b39);
    b39 = 524288u;
    b21 = stwo_m31_add(b22, b39);
    b39 = 524288u;
    b22 = stwo_m31_add(b23, b39);
    b39 = 524288u;
    b23 = stwo_m31_add(b24, b39);
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
    b39 = stwo_trace_value(arena, *args, 2u, 376u, row, 0);
    b37 = stwo_trace_value(arena, *args, 2u, 377u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 378u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 379u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 380u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 381u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 2u, 382u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 2u, 383u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 2u, 384u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 2u, 385u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 2u, 386u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 2u, 387u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 2u, 388u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 2u, 389u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 2u, 390u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 2u, 391u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 2u, 392u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 2u, 393u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 2u, 394u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 2u, 395u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 2u, 396u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 2u, 397u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 2u, 398u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 2u, 399u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 2u, 400u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 2u, 401u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 402u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 403u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 404u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 405u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 406u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 2u, 407u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 2u, 408u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 2u, 409u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 2u, 410u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 2u, 411u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 412u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 413u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 414u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 2u, 415u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 2u, 416u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 2u, 417u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 2u, 418u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 2u, 419u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 420u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 421u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 2u, 422u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 423u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 2u, 424u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 2u, 425u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 2u, 426u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 2u, 427u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 2u, 428u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 2u, 429u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 2u, 430u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 2u, 431u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 2u, 432u, row, 0);
    unsigned b96 = stwo_trace_value(arena, *args, 2u, 433u, row, 0);
    unsigned b97 = stwo_trace_value(arena, *args, 2u, 434u, row, 0);
    unsigned b98 = stwo_trace_value(arena, *args, 2u, 435u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 644u * 4u);
    StwoCairoQm31 e1 = { b0, b38, b38, b38 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 645u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 646u * 4u);
    e2 = { b1, b38, b38, b38 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 647u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 648u * 4u);
    e2 = { b2, b38, b38, b38 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 649u * 4u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 650u * 4u);
    e1 = { b3, b38, b38, b38 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 651u * 4u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 652u * 4u);
    e1 = { b4, b38, b38, b38 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 653u * 4u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 654u * 4u);
    e2 = { b5, b38, b38, b38 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 655u * 4u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 656u * 4u);
    e2 = { b6, b38, b38, b38 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 657u * 4u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 658u * 4u);
    e1 = { b7, b38, b38, b38 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 659u * 4u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 660u * 4u);
    e1 = { b8, b38, b38, b38 };
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 661u * 4u);
    e6 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 662u * 4u);
    e2 = { b9, b38, b38, b38 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 663u * 4u);
    e6 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 664u * 4u);
    e2 = { b10, b38, b38, b38 };
    e1 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 665u * 4u);
    e7 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 666u * 4u);
    e1 = { b11, b38, b38, b38 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 667u * 4u);
    e7 = stwo_qm31_sub(e1, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 668u * 4u);
    e1 = { b12, b38, b38, b38 };
    e2 = stwo_qm31_mul(e8, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 669u * 4u);
    e8 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 670u * 4u);
    e2 = { b13, b38, b38, b38 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 671u * 4u);
    e8 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 672u * 4u);
    e2 = { b14, b38, b38, b38 };
    e1 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 673u * 4u);
    e9 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 674u * 4u);
    e1 = { b15, b38, b38, b38 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 675u * 4u);
    e9 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 676u * 4u);
    e1 = { b16, b38, b38, b38 };
    e2 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 677u * 4u);
    e10 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 678u * 4u);
    e2 = { b17, b38, b38, b38 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 679u * 4u);
    e10 = stwo_qm31_sub(e2, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 680u * 4u);
    e2 = { b18, b38, b38, b38 };
    e1 = stwo_qm31_mul(e11, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 681u * 4u);
    e11 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 682u * 4u);
    e1 = { b19, b38, b38, b38 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 683u * 4u);
    e11 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 684u * 4u);
    e1 = { b40, b38, b38, b38 };
    e2 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 685u * 4u);
    e12 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 686u * 4u);
    e2 = stwo_qm31_sub(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 687u * 4u);
    e12 = { b20, b38, b38, b38 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 688u * 4u);
    e1 = stwo_qm31_add(e12, e13);
    e12 = stwo_load_qm31(arena, args->ext_params + 689u * 4u);
    e13 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 690u * 4u);
    e1 = { b21, b38, b38, b38 };
    StwoCairoQm31 e14 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 691u * 4u);
    e12 = stwo_qm31_add(e1, e14);
    e1 = stwo_load_qm31(arena, args->ext_params + 692u * 4u);
    e14 = stwo_qm31_sub(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 693u * 4u);
    e12 = { b22, b38, b38, b38 };
    StwoCairoQm31 e15 = stwo_qm31_mul(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 694u * 4u);
    e1 = stwo_qm31_add(e12, e15);
    e12 = stwo_load_qm31(arena, args->ext_params + 695u * 4u);
    e15 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 696u * 4u);
    e1 = { b23, b38, b38, b38 };
    StwoCairoQm31 e16 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 697u * 4u);
    e12 = stwo_qm31_add(e1, e16);
    e1 = stwo_load_qm31(arena, args->ext_params + 698u * 4u);
    e16 = stwo_qm31_sub(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 699u * 4u);
    e12 = { b24, b38, b38, b38 };
    StwoCairoQm31 e17 = stwo_qm31_mul(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 700u * 4u);
    e1 = stwo_qm31_add(e12, e17);
    e12 = stwo_load_qm31(arena, args->ext_params + 701u * 4u);
    e17 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 702u * 4u);
    e1 = { b25, b38, b38, b38 };
    StwoCairoQm31 e18 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 703u * 4u);
    e12 = stwo_qm31_add(e1, e18);
    e1 = stwo_load_qm31(arena, args->ext_params + 704u * 4u);
    e18 = stwo_qm31_sub(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 705u * 4u);
    e12 = { b26, b38, b38, b38 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 706u * 4u);
    e1 = stwo_qm31_add(e12, e19);
    e12 = stwo_load_qm31(arena, args->ext_params + 707u * 4u);
    e19 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 708u * 4u);
    e1 = { b27, b38, b38, b38 };
    StwoCairoQm31 e20 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 709u * 4u);
    e12 = stwo_qm31_add(e1, e20);
    e1 = stwo_load_qm31(arena, args->ext_params + 710u * 4u);
    e20 = stwo_qm31_sub(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 711u * 4u);
    e12 = { b28, b38, b38, b38 };
    StwoCairoQm31 e21 = stwo_qm31_mul(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 712u * 4u);
    e1 = stwo_qm31_add(e12, e21);
    e12 = stwo_load_qm31(arena, args->ext_params + 713u * 4u);
    e21 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 714u * 4u);
    e1 = { b29, b38, b38, b38 };
    StwoCairoQm31 e22 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 715u * 4u);
    e12 = stwo_qm31_add(e1, e22);
    e1 = stwo_load_qm31(arena, args->ext_params + 716u * 4u);
    e22 = stwo_qm31_sub(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 717u * 4u);
    e12 = { b30, b38, b38, b38 };
    StwoCairoQm31 e23 = stwo_qm31_mul(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 718u * 4u);
    e1 = stwo_qm31_add(e12, e23);
    e12 = stwo_load_qm31(arena, args->ext_params + 719u * 4u);
    e23 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 720u * 4u);
    e1 = { b31, b38, b38, b38 };
    StwoCairoQm31 e24 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 721u * 4u);
    e12 = stwo_qm31_add(e1, e24);
    e1 = stwo_load_qm31(arena, args->ext_params + 722u * 4u);
    e24 = stwo_qm31_sub(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 723u * 4u);
    e12 = { b32, b38, b38, b38 };
    StwoCairoQm31 e25 = stwo_qm31_mul(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 724u * 4u);
    e1 = stwo_qm31_add(e12, e25);
    e12 = stwo_load_qm31(arena, args->ext_params + 725u * 4u);
    e25 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 726u * 4u);
    e1 = { b33, b38, b38, b38 };
    StwoCairoQm31 e26 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 727u * 4u);
    e12 = stwo_qm31_add(e1, e26);
    e1 = stwo_load_qm31(arena, args->ext_params + 728u * 4u);
    e26 = stwo_qm31_sub(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 729u * 4u);
    e12 = { b34, b38, b38, b38 };
    StwoCairoQm31 e27 = stwo_qm31_mul(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 730u * 4u);
    e1 = stwo_qm31_add(e12, e27);
    e12 = stwo_load_qm31(arena, args->ext_params + 731u * 4u);
    e27 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 732u * 4u);
    e1 = { b35, b38, b38, b38 };
    StwoCairoQm31 e28 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 733u * 4u);
    e12 = stwo_qm31_add(e1, e28);
    e1 = stwo_load_qm31(arena, args->ext_params + 734u * 4u);
    e28 = stwo_qm31_sub(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 735u * 4u);
    e12 = { b36, b38, b38, b38 };
    StwoCairoQm31 e29 = stwo_qm31_mul(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 736u * 4u);
    e1 = stwo_qm31_add(e12, e29);
    e12 = stwo_load_qm31(arena, args->ext_params + 737u * 4u);
    e29 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 1492u * 4u);
    e1 = stwo_qm31_mul(e3, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 1493u * 4u);
    StwoCairoQm31 e30 = stwo_qm31_mul(e0, e12);
    e12 = stwo_qm31_add(e1, e30);
    e30 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 1494u * 4u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 1495u * 4u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 1496u * 4u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 1497u * 4u);
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 1498u * 4u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 1499u * 4u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 1500u * 4u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 1501u * 4u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 1502u * 4u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 1503u * 4u);
    e8 = stwo_qm31_mul(e2, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e2, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 1504u * 4u);
    e2 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 1505u * 4u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e2, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 1506u * 4u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 1507u * 4u);
    e2 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e2);
    e2 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 1508u * 4u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 1509u * 4u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 1510u * 4u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 1511u * 4u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e20, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 1512u * 4u);
    e20 = stwo_qm31_mul(e23, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 1513u * 4u);
    e18 = stwo_qm31_mul(e22, e21);
    e21 = stwo_qm31_add(e20, e18);
    e18 = stwo_qm31_mul(e22, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 1514u * 4u);
    e22 = stwo_qm31_mul(e25, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 1515u * 4u);
    e20 = stwo_qm31_mul(e24, e23);
    e23 = stwo_qm31_add(e22, e20);
    e20 = stwo_qm31_mul(e24, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 1516u * 4u);
    e24 = stwo_qm31_mul(e27, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 1517u * 4u);
    e22 = stwo_qm31_mul(e26, e25);
    e25 = stwo_qm31_add(e24, e22);
    e22 = stwo_qm31_mul(e26, e27);
    e27 = stwo_load_qm31(arena, args->ext_params + 1518u * 4u);
    e26 = stwo_qm31_mul(e29, e27);
    e27 = stwo_load_qm31(arena, args->ext_params + 1519u * 4u);
    e24 = stwo_qm31_mul(e28, e27);
    e27 = stwo_qm31_add(e26, e24);
    e24 = stwo_qm31_mul(e28, e29);
    e29 = { b39, b37, b41, b42 };
    e28 = { b43, b44, b45, b46 };
    e26 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e26, e30);
    e26 = stwo_qm31_sub(e29, e12);
    e29 = { b47, b48, b49, b50 };
    e12 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e12, e1);
    e12 = stwo_qm31_sub(e28, e3);
    e28 = { b51, b52, b53, b54 };
    e3 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e29, e5);
    e29 = { b55, b56, b57, b58 };
    e5 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e28, e7);
    e28 = { b59, b60, b61, b62 };
    e7 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e29, e9);
    e29 = { b63, b64, b65, b66 };
    e9 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e28, e11);
    e28 = { b67, b68, b69, b70 };
    e11 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e29, e13);
    e29 = { b71, b72, b73, b74 };
    e13 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e13, e2);
    e13 = stwo_qm31_sub(e28, e15);
    e28 = { b75, b76, b77, b78 };
    e15 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e29, e17);
    e29 = { b79, b80, b81, b82 };
    e17 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e28, e19);
    e28 = { b83, b84, b85, b86 };
    e19 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e19, e18);
    e19 = stwo_qm31_sub(e29, e21);
    e29 = { b87, b88, b89, b90 };
    e21 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e21, e20);
    e21 = stwo_qm31_sub(e28, e23);
    e28 = { b91, b92, b93, b94 };
    e23 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e23, e22);
    e23 = stwo_qm31_sub(e29, e25);
    e29 = { b95, b96, b97, b98 };
    e25 = stwo_qm31_sub(e29, e28);
    e29 = stwo_qm31_mul(e25, e24);
    e25 = stwo_qm31_sub(e29, e27);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e26, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e12, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e25, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 13u) * 4u)));
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
