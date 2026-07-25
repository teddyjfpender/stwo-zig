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
stwo_cairo_cuda_eval_v1_1aad6d61e7f35888(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 418u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 419u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 420u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 421u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 422u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 423u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 424u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 425u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 426u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 427u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 428u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 429u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 430u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 431u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 432u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 433u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 434u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 435u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 436u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 437u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 438u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 439u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 440u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 441u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 442u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 443u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 444u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 445u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 446u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 447u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 448u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 449u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 450u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 451u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 452u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 453u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 455u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 456u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 457u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 458u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 459u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 460u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 461u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 462u, row, 0);
    unsigned b44 = 0u;
    unsigned b45 = 524288u;
    unsigned b46 = stwo_m31_add(b0, b45);
    b45 = 524288u;
    b0 = stwo_m31_add(b1, b45);
    b45 = 524288u;
    b1 = stwo_m31_add(b2, b45);
    b45 = 524288u;
    b2 = stwo_m31_add(b3, b45);
    b45 = 524288u;
    b3 = stwo_m31_add(b4, b45);
    b45 = 524288u;
    b4 = stwo_m31_add(b5, b45);
    b45 = 524288u;
    b5 = stwo_m31_add(b6, b45);
    b45 = 524288u;
    b6 = stwo_m31_add(b7, b45);
    b45 = stwo_trace_value(arena, *args, 2u, 324u, row, 0);
    b7 = stwo_trace_value(arena, *args, 2u, 325u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 2u, 326u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 2u, 327u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 2u, 328u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 2u, 329u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 2u, 330u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 2u, 331u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 2u, 332u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 2u, 333u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 2u, 334u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 2u, 335u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 2u, 336u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 2u, 337u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 2u, 338u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 2u, 339u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 2u, 340u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 2u, 341u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 2u, 342u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 2u, 343u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 344u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 345u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 346u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 347u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 348u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 2u, 349u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 2u, 350u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 2u, 351u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 2u, 352u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 2u, 353u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 354u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 355u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 356u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 2u, 357u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 2u, 358u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 2u, 359u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 2u, 360u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 2u, 361u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 362u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 363u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 2u, 364u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 365u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 2u, 366u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 2u, 367u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 2u, 368u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 2u, 369u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 2u, 370u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 2u, 371u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 2u, 372u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 2u, 373u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 2u, 374u, row, 0);
    unsigned b96 = stwo_trace_value(arena, *args, 2u, 375u, row, 0);
    unsigned b97 = stwo_trace_value(arena, *args, 2u, 376u, row, 0);
    unsigned b98 = stwo_trace_value(arena, *args, 2u, 377u, row, 0);
    unsigned b99 = stwo_trace_value(arena, *args, 2u, 378u, row, 0);
    unsigned b100 = stwo_trace_value(arena, *args, 2u, 379u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 548u * 4u);
    StwoCairoQm31 e1 = { b46, b44, b44, b44 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 549u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 550u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 551u * 4u);
    e0 = { b0, b44, b44, b44 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 552u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 553u * 4u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 554u * 4u);
    e1 = { b1, b44, b44, b44 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 555u * 4u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(arena, args->ext_params + 556u * 4u);
    e4 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 557u * 4u);
    e0 = { b2, b44, b44, b44 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 558u * 4u);
    e1 = stwo_qm31_add(e0, e5);
    e0 = stwo_load_qm31(arena, args->ext_params + 559u * 4u);
    e5 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 560u * 4u);
    e1 = { b3, b44, b44, b44 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 561u * 4u);
    e0 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(arena, args->ext_params + 562u * 4u);
    e6 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 563u * 4u);
    e0 = { b4, b44, b44, b44 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 564u * 4u);
    e1 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(arena, args->ext_params + 565u * 4u);
    e7 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 566u * 4u);
    e1 = { b5, b44, b44, b44 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 567u * 4u);
    e0 = stwo_qm31_add(e1, e8);
    e1 = stwo_load_qm31(arena, args->ext_params + 568u * 4u);
    e8 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 569u * 4u);
    e0 = { b6, b44, b44, b44 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 570u * 4u);
    e1 = stwo_qm31_add(e0, e9);
    e0 = stwo_load_qm31(arena, args->ext_params + 571u * 4u);
    e9 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 572u * 4u);
    e1 = { b8, b44, b44, b44 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 573u * 4u);
    e0 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(arena, args->ext_params + 574u * 4u);
    e10 = { b9, b44, b44, b44 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e0, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 575u * 4u);
    e0 = stwo_qm31_sub(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 576u * 4u);
    e10 = { b10, b44, b44, b44 };
    e1 = stwo_qm31_mul(e11, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 577u * 4u);
    e11 = stwo_qm31_add(e10, e1);
    e10 = stwo_load_qm31(arena, args->ext_params + 578u * 4u);
    e1 = { b11, b44, b44, b44 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 579u * 4u);
    e11 = stwo_qm31_sub(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 580u * 4u);
    e1 = { b12, b44, b44, b44 };
    e10 = stwo_qm31_mul(e12, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 581u * 4u);
    e12 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(arena, args->ext_params + 582u * 4u);
    e10 = { b13, b44, b44, b44 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 583u * 4u);
    e12 = stwo_qm31_sub(e10, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 584u * 4u);
    e10 = { b14, b44, b44, b44 };
    e1 = stwo_qm31_mul(e13, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 585u * 4u);
    e13 = stwo_qm31_add(e10, e1);
    e10 = stwo_load_qm31(arena, args->ext_params + 586u * 4u);
    e1 = { b15, b44, b44, b44 };
    StwoCairoQm31 e14 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 587u * 4u);
    e13 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 588u * 4u);
    e1 = { b16, b44, b44, b44 };
    e10 = stwo_qm31_mul(e14, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 589u * 4u);
    e14 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(arena, args->ext_params + 590u * 4u);
    e10 = { b17, b44, b44, b44 };
    StwoCairoQm31 e15 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 591u * 4u);
    e14 = stwo_qm31_sub(e10, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 592u * 4u);
    e10 = { b18, b44, b44, b44 };
    e1 = stwo_qm31_mul(e15, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 593u * 4u);
    e15 = stwo_qm31_add(e10, e1);
    e10 = stwo_load_qm31(arena, args->ext_params + 594u * 4u);
    e1 = { b19, b44, b44, b44 };
    StwoCairoQm31 e16 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e15, e16);
    e16 = stwo_load_qm31(arena, args->ext_params + 595u * 4u);
    e15 = stwo_qm31_sub(e1, e16);
    e16 = stwo_load_qm31(arena, args->ext_params + 596u * 4u);
    e1 = { b20, b44, b44, b44 };
    e10 = stwo_qm31_mul(e16, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 597u * 4u);
    e16 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(arena, args->ext_params + 598u * 4u);
    e10 = { b21, b44, b44, b44 };
    StwoCairoQm31 e17 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 599u * 4u);
    e16 = stwo_qm31_sub(e10, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 600u * 4u);
    e10 = { b22, b44, b44, b44 };
    e1 = stwo_qm31_mul(e17, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 601u * 4u);
    e17 = stwo_qm31_add(e10, e1);
    e10 = stwo_load_qm31(arena, args->ext_params + 602u * 4u);
    e1 = { b23, b44, b44, b44 };
    StwoCairoQm31 e18 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 603u * 4u);
    e17 = stwo_qm31_sub(e1, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 604u * 4u);
    e1 = { b24, b44, b44, b44 };
    e10 = stwo_qm31_mul(e18, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 605u * 4u);
    e18 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(arena, args->ext_params + 606u * 4u);
    e10 = { b25, b44, b44, b44 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 607u * 4u);
    e18 = stwo_qm31_sub(e10, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 608u * 4u);
    e10 = { b26, b44, b44, b44 };
    e1 = stwo_qm31_mul(e19, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 609u * 4u);
    e19 = stwo_qm31_add(e10, e1);
    e10 = stwo_load_qm31(arena, args->ext_params + 610u * 4u);
    e1 = { b27, b44, b44, b44 };
    StwoCairoQm31 e20 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e19, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 611u * 4u);
    e19 = stwo_qm31_sub(e1, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 612u * 4u);
    e1 = { b28, b44, b44, b44 };
    e10 = stwo_qm31_mul(e20, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 613u * 4u);
    e20 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(arena, args->ext_params + 614u * 4u);
    e10 = { b29, b44, b44, b44 };
    StwoCairoQm31 e21 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e20, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 615u * 4u);
    e20 = stwo_qm31_sub(e10, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 616u * 4u);
    e10 = { b30, b44, b44, b44 };
    e1 = stwo_qm31_mul(e21, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 617u * 4u);
    e21 = stwo_qm31_add(e10, e1);
    e10 = stwo_load_qm31(arena, args->ext_params + 618u * 4u);
    e1 = { b31, b44, b44, b44 };
    StwoCairoQm31 e22 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e21, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 619u * 4u);
    e21 = stwo_qm31_sub(e1, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 620u * 4u);
    e1 = { b32, b44, b44, b44 };
    e10 = stwo_qm31_mul(e22, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 621u * 4u);
    e22 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(arena, args->ext_params + 622u * 4u);
    e10 = { b33, b44, b44, b44 };
    StwoCairoQm31 e23 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e22, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 623u * 4u);
    e22 = stwo_qm31_sub(e10, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 624u * 4u);
    e10 = { b34, b44, b44, b44 };
    e1 = stwo_qm31_mul(e23, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 625u * 4u);
    e23 = stwo_qm31_add(e10, e1);
    e10 = stwo_load_qm31(arena, args->ext_params + 626u * 4u);
    e1 = { b35, b44, b44, b44 };
    StwoCairoQm31 e24 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e23, e24);
    e24 = stwo_load_qm31(arena, args->ext_params + 627u * 4u);
    e23 = stwo_qm31_sub(e1, e24);
    e24 = stwo_load_qm31(arena, args->ext_params + 628u * 4u);
    e1 = { b36, b44, b44, b44 };
    e10 = stwo_qm31_mul(e24, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 629u * 4u);
    e24 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(arena, args->ext_params + 630u * 4u);
    e10 = { b37, b44, b44, b44 };
    StwoCairoQm31 e25 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e24, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 631u * 4u);
    e24 = stwo_qm31_sub(e10, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 632u * 4u);
    e10 = { b38, b44, b44, b44 };
    e1 = stwo_qm31_mul(e25, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 633u * 4u);
    e25 = stwo_qm31_add(e10, e1);
    e10 = stwo_load_qm31(arena, args->ext_params + 634u * 4u);
    e1 = { b39, b44, b44, b44 };
    StwoCairoQm31 e26 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e25, e26);
    e26 = stwo_load_qm31(arena, args->ext_params + 635u * 4u);
    e25 = stwo_qm31_sub(e1, e26);
    e26 = stwo_load_qm31(arena, args->ext_params + 636u * 4u);
    e1 = { b40, b44, b44, b44 };
    e10 = stwo_qm31_mul(e26, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 637u * 4u);
    e26 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(arena, args->ext_params + 638u * 4u);
    e10 = { b41, b44, b44, b44 };
    StwoCairoQm31 e27 = stwo_qm31_mul(e1, e10);
    e10 = stwo_qm31_add(e26, e27);
    e27 = stwo_load_qm31(arena, args->ext_params + 639u * 4u);
    e26 = stwo_qm31_sub(e10, e27);
    e27 = stwo_load_qm31(arena, args->ext_params + 640u * 4u);
    e10 = { b42, b44, b44, b44 };
    e1 = stwo_qm31_mul(e27, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 641u * 4u);
    e27 = stwo_qm31_add(e10, e1);
    e10 = stwo_load_qm31(arena, args->ext_params + 642u * 4u);
    e1 = { b43, b44, b44, b44 };
    StwoCairoQm31 e28 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e27, e28);
    e28 = stwo_load_qm31(arena, args->ext_params + 643u * 4u);
    e27 = stwo_qm31_sub(e1, e28);
    e28 = stwo_load_qm31(arena, args->ext_params + 1466u * 4u);
    e1 = stwo_qm31_mul(e3, e28);
    e28 = stwo_load_qm31(arena, args->ext_params + 1467u * 4u);
    e10 = stwo_qm31_mul(e2, e28);
    e28 = stwo_qm31_add(e1, e10);
    e10 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 1468u * 4u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 1469u * 4u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 1470u * 4u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 1471u * 4u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 1472u * 4u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 1473u * 4u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 1474u * 4u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 1475u * 4u);
    e6 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e0, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 1476u * 4u);
    e0 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 1477u * 4u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e0, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 1478u * 4u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 1479u * 4u);
    e0 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e0);
    e0 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 1480u * 4u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 1481u * 4u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 1482u * 4u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 1483u * 4u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 1484u * 4u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 1485u * 4u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e20, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 1486u * 4u);
    e20 = stwo_qm31_mul(e23, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 1487u * 4u);
    e18 = stwo_qm31_mul(e22, e21);
    e21 = stwo_qm31_add(e20, e18);
    e18 = stwo_qm31_mul(e22, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 1488u * 4u);
    e22 = stwo_qm31_mul(e25, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 1489u * 4u);
    e20 = stwo_qm31_mul(e24, e23);
    e23 = stwo_qm31_add(e22, e20);
    e20 = stwo_qm31_mul(e24, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 1490u * 4u);
    e24 = stwo_qm31_mul(e27, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 1491u * 4u);
    e22 = stwo_qm31_mul(e26, e25);
    e25 = stwo_qm31_add(e24, e22);
    e22 = stwo_qm31_mul(e26, e27);
    e27 = { b45, b7, b47, b48 };
    e26 = { b49, b50, b51, b52 };
    e24 = stwo_qm31_sub(e26, e27);
    e27 = stwo_qm31_mul(e24, e10);
    e24 = stwo_qm31_sub(e27, e28);
    e27 = { b53, b54, b55, b56 };
    e28 = stwo_qm31_sub(e27, e26);
    e26 = stwo_qm31_mul(e28, e1);
    e28 = stwo_qm31_sub(e26, e3);
    e26 = { b57, b58, b59, b60 };
    e3 = stwo_qm31_sub(e26, e27);
    e27 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e27, e5);
    e27 = { b61, b62, b63, b64 };
    e5 = stwo_qm31_sub(e27, e26);
    e26 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e26, e7);
    e26 = { b65, b66, b67, b68 };
    e7 = stwo_qm31_sub(e26, e27);
    e27 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e27, e9);
    e27 = { b69, b70, b71, b72 };
    e9 = stwo_qm31_sub(e27, e26);
    e26 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e26, e11);
    e26 = { b73, b74, b75, b76 };
    e11 = stwo_qm31_sub(e26, e27);
    e27 = stwo_qm31_mul(e11, e0);
    e11 = stwo_qm31_sub(e27, e13);
    e27 = { b77, b78, b79, b80 };
    e13 = stwo_qm31_sub(e27, e26);
    e26 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e26, e15);
    e26 = { b81, b82, b83, b84 };
    e15 = stwo_qm31_sub(e26, e27);
    e27 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e27, e17);
    e27 = { b85, b86, b87, b88 };
    e17 = stwo_qm31_sub(e27, e26);
    e26 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e26, e19);
    e26 = { b89, b90, b91, b92 };
    e19 = stwo_qm31_sub(e26, e27);
    e27 = stwo_qm31_mul(e19, e18);
    e19 = stwo_qm31_sub(e27, e21);
    e27 = { b93, b94, b95, b96 };
    e21 = stwo_qm31_sub(e27, e26);
    e26 = stwo_qm31_mul(e21, e20);
    e21 = stwo_qm31_sub(e26, e23);
    e26 = { b97, b98, b99, b100 };
    e23 = stwo_qm31_sub(e26, e27);
    e26 = stwo_qm31_mul(e23, e22);
    e23 = stwo_qm31_sub(e26, e25);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e24, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e28, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
