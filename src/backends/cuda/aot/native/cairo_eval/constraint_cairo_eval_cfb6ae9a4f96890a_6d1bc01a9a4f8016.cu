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
stwo_cairo_cuda_eval_v1_b38b55fa8c5b3b1d(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 501u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 502u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 503u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 504u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 505u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 506u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 507u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 508u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 509u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 510u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 511u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 512u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 513u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 514u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 515u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 516u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 517u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 518u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 519u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 520u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 521u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 522u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 523u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 524u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 525u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 526u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 527u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 528u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 529u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 530u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 531u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 532u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 533u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 534u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 535u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 536u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 537u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 538u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 539u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 540u, row, 0);
    unsigned b40 = 0u;
    unsigned b41 = 524288u;
    unsigned b42 = stwo_m31_add(b0, b41);
    b41 = 524288u;
    b0 = stwo_m31_add(b1, b41);
    b41 = 524288u;
    b1 = stwo_m31_add(b2, b41);
    b41 = 524288u;
    b2 = stwo_m31_add(b3, b41);
    b41 = 524288u;
    b3 = stwo_m31_add(b4, b41);
    b41 = 524288u;
    b4 = stwo_m31_add(b5, b41);
    b41 = 524288u;
    b5 = stwo_m31_add(b6, b41);
    b41 = 524288u;
    b6 = stwo_m31_add(b7, b41);
    b41 = 524288u;
    b7 = stwo_m31_add(b8, b41);
    b41 = 524288u;
    b8 = stwo_m31_add(b9, b41);
    b41 = 524288u;
    b9 = stwo_m31_add(b38, b41);
    b41 = 524288u;
    b38 = stwo_m31_add(b39, b41);
    b41 = stwo_trace_value(arena, *args, 2u, 432u, row, 0);
    b39 = stwo_trace_value(arena, *args, 2u, 433u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 434u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 435u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 2u, 436u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 2u, 437u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 2u, 438u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 2u, 439u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 2u, 440u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 2u, 441u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 2u, 442u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 2u, 443u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 2u, 444u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 2u, 445u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 2u, 446u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 2u, 447u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 2u, 448u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 2u, 449u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 2u, 450u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 2u, 451u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 2u, 452u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 2u, 453u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 2u, 454u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 2u, 455u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 456u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 457u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 458u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 459u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 460u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 2u, 461u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 2u, 462u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 2u, 463u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 2u, 464u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 2u, 465u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 466u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 467u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 468u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 2u, 469u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 2u, 470u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 2u, 471u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 2u, 472u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 2u, 473u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 474u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 475u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 2u, 476u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 477u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 2u, 478u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 2u, 479u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 2u, 480u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 2u, 481u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 2u, 482u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 2u, 483u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 2u, 484u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 2u, 485u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 2u, 486u, row, 0);
    unsigned b96 = stwo_trace_value(arena, *args, 2u, 487u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 738u * 4u);
    StwoCairoQm31 e1 = { b42, b40, b40, b40 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 739u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 740u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 741u * 4u);
    e0 = { b0, b40, b40, b40 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 742u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 743u * 4u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 744u * 4u);
    e1 = { b1, b40, b40, b40 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 745u * 4u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(arena, args->ext_params + 746u * 4u);
    e4 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 747u * 4u);
    e0 = { b2, b40, b40, b40 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 748u * 4u);
    e1 = stwo_qm31_add(e0, e5);
    e0 = stwo_load_qm31(arena, args->ext_params + 749u * 4u);
    e5 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 750u * 4u);
    e1 = { b3, b40, b40, b40 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 751u * 4u);
    e0 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(arena, args->ext_params + 752u * 4u);
    e6 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 753u * 4u);
    e0 = { b4, b40, b40, b40 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 754u * 4u);
    e1 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(arena, args->ext_params + 755u * 4u);
    e7 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 756u * 4u);
    e1 = { b5, b40, b40, b40 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 757u * 4u);
    e0 = stwo_qm31_add(e1, e8);
    e1 = stwo_load_qm31(arena, args->ext_params + 758u * 4u);
    e8 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 759u * 4u);
    e0 = { b6, b40, b40, b40 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 760u * 4u);
    e1 = stwo_qm31_add(e0, e9);
    e0 = stwo_load_qm31(arena, args->ext_params + 761u * 4u);
    e9 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 762u * 4u);
    e1 = { b7, b40, b40, b40 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 763u * 4u);
    e0 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(arena, args->ext_params + 764u * 4u);
    e10 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 765u * 4u);
    e0 = { b8, b40, b40, b40 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 766u * 4u);
    e1 = stwo_qm31_add(e0, e11);
    e0 = stwo_load_qm31(arena, args->ext_params + 767u * 4u);
    e11 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 768u * 4u);
    e1 = { b10, b40, b40, b40 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 769u * 4u);
    e0 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(arena, args->ext_params + 770u * 4u);
    e12 = { b11, b40, b40, b40 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e0, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 771u * 4u);
    e0 = stwo_qm31_sub(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 772u * 4u);
    e12 = { b12, b40, b40, b40 };
    e1 = stwo_qm31_mul(e13, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 773u * 4u);
    e13 = stwo_qm31_add(e12, e1);
    e12 = stwo_load_qm31(arena, args->ext_params + 774u * 4u);
    e1 = { b13, b40, b40, b40 };
    StwoCairoQm31 e14 = stwo_qm31_mul(e12, e1);
    e1 = stwo_qm31_add(e13, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 775u * 4u);
    e13 = stwo_qm31_sub(e1, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 776u * 4u);
    e1 = { b14, b40, b40, b40 };
    e12 = stwo_qm31_mul(e14, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 777u * 4u);
    e14 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(arena, args->ext_params + 778u * 4u);
    e12 = { b15, b40, b40, b40 };
    StwoCairoQm31 e15 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 779u * 4u);
    e14 = stwo_qm31_sub(e12, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 780u * 4u);
    e12 = { b16, b40, b40, b40 };
    e1 = stwo_qm31_mul(e15, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 781u * 4u);
    e15 = stwo_qm31_add(e12, e1);
    e12 = stwo_load_qm31(arena, args->ext_params + 782u * 4u);
    e1 = { b17, b40, b40, b40 };
    StwoCairoQm31 e16 = stwo_qm31_mul(e12, e1);
    e1 = stwo_qm31_add(e15, e16);
    e16 = stwo_load_qm31(arena, args->ext_params + 783u * 4u);
    e15 = stwo_qm31_sub(e1, e16);
    e16 = stwo_load_qm31(arena, args->ext_params + 784u * 4u);
    e1 = { b18, b40, b40, b40 };
    e12 = stwo_qm31_mul(e16, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 785u * 4u);
    e16 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(arena, args->ext_params + 786u * 4u);
    e12 = { b19, b40, b40, b40 };
    StwoCairoQm31 e17 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 787u * 4u);
    e16 = stwo_qm31_sub(e12, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 788u * 4u);
    e12 = { b20, b40, b40, b40 };
    e1 = stwo_qm31_mul(e17, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 789u * 4u);
    e17 = stwo_qm31_add(e12, e1);
    e12 = stwo_load_qm31(arena, args->ext_params + 790u * 4u);
    e1 = { b21, b40, b40, b40 };
    StwoCairoQm31 e18 = stwo_qm31_mul(e12, e1);
    e1 = stwo_qm31_add(e17, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 791u * 4u);
    e17 = stwo_qm31_sub(e1, e18);
    e18 = stwo_load_qm31(arena, args->ext_params + 792u * 4u);
    e1 = { b22, b40, b40, b40 };
    e12 = stwo_qm31_mul(e18, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 793u * 4u);
    e18 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(arena, args->ext_params + 794u * 4u);
    e12 = { b23, b40, b40, b40 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e18, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 795u * 4u);
    e18 = stwo_qm31_sub(e12, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 796u * 4u);
    e12 = { b24, b40, b40, b40 };
    e1 = stwo_qm31_mul(e19, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 797u * 4u);
    e19 = stwo_qm31_add(e12, e1);
    e12 = stwo_load_qm31(arena, args->ext_params + 798u * 4u);
    e1 = { b25, b40, b40, b40 };
    StwoCairoQm31 e20 = stwo_qm31_mul(e12, e1);
    e1 = stwo_qm31_add(e19, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 799u * 4u);
    e19 = stwo_qm31_sub(e1, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 800u * 4u);
    e1 = { b26, b40, b40, b40 };
    e12 = stwo_qm31_mul(e20, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 801u * 4u);
    e20 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(arena, args->ext_params + 802u * 4u);
    e12 = { b27, b40, b40, b40 };
    StwoCairoQm31 e21 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e20, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 803u * 4u);
    e20 = stwo_qm31_sub(e12, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 804u * 4u);
    e12 = { b28, b40, b40, b40 };
    e1 = stwo_qm31_mul(e21, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 805u * 4u);
    e21 = stwo_qm31_add(e12, e1);
    e12 = stwo_load_qm31(arena, args->ext_params + 806u * 4u);
    e1 = { b29, b40, b40, b40 };
    StwoCairoQm31 e22 = stwo_qm31_mul(e12, e1);
    e1 = stwo_qm31_add(e21, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 807u * 4u);
    e21 = stwo_qm31_sub(e1, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 808u * 4u);
    e1 = { b30, b40, b40, b40 };
    e12 = stwo_qm31_mul(e22, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 809u * 4u);
    e22 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(arena, args->ext_params + 810u * 4u);
    e12 = { b31, b40, b40, b40 };
    StwoCairoQm31 e23 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e22, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 811u * 4u);
    e22 = stwo_qm31_sub(e12, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 812u * 4u);
    e12 = { b32, b40, b40, b40 };
    e1 = stwo_qm31_mul(e23, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 813u * 4u);
    e23 = stwo_qm31_add(e12, e1);
    e12 = stwo_load_qm31(arena, args->ext_params + 814u * 4u);
    e1 = { b33, b40, b40, b40 };
    StwoCairoQm31 e24 = stwo_qm31_mul(e12, e1);
    e1 = stwo_qm31_add(e23, e24);
    e24 = stwo_load_qm31(arena, args->ext_params + 815u * 4u);
    e23 = stwo_qm31_sub(e1, e24);
    e24 = stwo_load_qm31(arena, args->ext_params + 816u * 4u);
    e1 = { b34, b40, b40, b40 };
    e12 = stwo_qm31_mul(e24, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 817u * 4u);
    e24 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(arena, args->ext_params + 818u * 4u);
    e12 = { b35, b40, b40, b40 };
    StwoCairoQm31 e25 = stwo_qm31_mul(e1, e12);
    e12 = stwo_qm31_add(e24, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 819u * 4u);
    e24 = stwo_qm31_sub(e12, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 820u * 4u);
    e12 = { b36, b40, b40, b40 };
    e1 = stwo_qm31_mul(e25, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 821u * 4u);
    e25 = stwo_qm31_add(e12, e1);
    e12 = stwo_load_qm31(arena, args->ext_params + 822u * 4u);
    e1 = { b37, b40, b40, b40 };
    StwoCairoQm31 e26 = stwo_qm31_mul(e12, e1);
    e1 = stwo_qm31_add(e25, e26);
    e26 = stwo_load_qm31(arena, args->ext_params + 823u * 4u);
    e25 = stwo_qm31_sub(e1, e26);
    e26 = stwo_load_qm31(arena, args->ext_params + 824u * 4u);
    e1 = { b9, b40, b40, b40 };
    e12 = stwo_qm31_mul(e26, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 825u * 4u);
    e26 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(arena, args->ext_params + 826u * 4u);
    e12 = stwo_qm31_sub(e26, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 827u * 4u);
    e26 = { b38, b40, b40, b40 };
    StwoCairoQm31 e27 = stwo_qm31_mul(e1, e26);
    e26 = stwo_load_qm31(arena, args->ext_params + 828u * 4u);
    e1 = stwo_qm31_add(e26, e27);
    e26 = stwo_load_qm31(arena, args->ext_params + 829u * 4u);
    e27 = stwo_qm31_sub(e1, e26);
    e26 = stwo_load_qm31(arena, args->ext_params + 1520u * 4u);
    e1 = stwo_qm31_mul(e3, e26);
    e26 = stwo_load_qm31(arena, args->ext_params + 1521u * 4u);
    StwoCairoQm31 e28 = stwo_qm31_mul(e2, e26);
    e26 = stwo_qm31_add(e1, e28);
    e28 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 1522u * 4u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 1523u * 4u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 1524u * 4u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 1525u * 4u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 1526u * 4u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 1527u * 4u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 1528u * 4u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 1529u * 4u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 1530u * 4u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 1531u * 4u);
    e8 = stwo_qm31_mul(e0, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e0, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 1532u * 4u);
    e0 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 1533u * 4u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e0, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 1534u * 4u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 1535u * 4u);
    e0 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e0);
    e0 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 1536u * 4u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 1537u * 4u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 1538u * 4u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 1539u * 4u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e20, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 1540u * 4u);
    e20 = stwo_qm31_mul(e23, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 1541u * 4u);
    e18 = stwo_qm31_mul(e22, e21);
    e21 = stwo_qm31_add(e20, e18);
    e18 = stwo_qm31_mul(e22, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 1542u * 4u);
    e22 = stwo_qm31_mul(e25, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 1543u * 4u);
    e20 = stwo_qm31_mul(e24, e23);
    e23 = stwo_qm31_add(e22, e20);
    e20 = stwo_qm31_mul(e24, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 1544u * 4u);
    e24 = stwo_qm31_mul(e27, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 1545u * 4u);
    e22 = stwo_qm31_mul(e12, e25);
    e25 = stwo_qm31_add(e24, e22);
    e22 = stwo_qm31_mul(e12, e27);
    e27 = { b41, b39, b43, b44 };
    e12 = { b45, b46, b47, b48 };
    e24 = stwo_qm31_sub(e12, e27);
    e27 = stwo_qm31_mul(e24, e28);
    e24 = stwo_qm31_sub(e27, e26);
    e27 = { b49, b50, b51, b52 };
    e26 = stwo_qm31_sub(e27, e12);
    e12 = stwo_qm31_mul(e26, e1);
    e26 = stwo_qm31_sub(e12, e3);
    e12 = { b53, b54, b55, b56 };
    e3 = stwo_qm31_sub(e12, e27);
    e27 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e27, e5);
    e27 = { b57, b58, b59, b60 };
    e5 = stwo_qm31_sub(e27, e12);
    e12 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e12, e7);
    e12 = { b61, b62, b63, b64 };
    e7 = stwo_qm31_sub(e12, e27);
    e27 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e27, e9);
    e27 = { b65, b66, b67, b68 };
    e9 = stwo_qm31_sub(e27, e12);
    e12 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e12, e11);
    e12 = { b69, b70, b71, b72 };
    e11 = stwo_qm31_sub(e12, e27);
    e27 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e27, e13);
    e27 = { b73, b74, b75, b76 };
    e13 = stwo_qm31_sub(e27, e12);
    e12 = stwo_qm31_mul(e13, e0);
    e13 = stwo_qm31_sub(e12, e15);
    e12 = { b77, b78, b79, b80 };
    e15 = stwo_qm31_sub(e12, e27);
    e27 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e27, e17);
    e27 = { b81, b82, b83, b84 };
    e17 = stwo_qm31_sub(e27, e12);
    e12 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e12, e19);
    e12 = { b85, b86, b87, b88 };
    e19 = stwo_qm31_sub(e12, e27);
    e27 = stwo_qm31_mul(e19, e18);
    e19 = stwo_qm31_sub(e27, e21);
    e27 = { b89, b90, b91, b92 };
    e21 = stwo_qm31_sub(e27, e12);
    e12 = stwo_qm31_mul(e21, e20);
    e21 = stwo_qm31_sub(e12, e23);
    e12 = { b93, b94, b95, b96 };
    e23 = stwo_qm31_sub(e12, e27);
    e12 = stwo_qm31_mul(e23, e22);
    e23 = stwo_qm31_sub(e12, e25);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e24, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e26, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
