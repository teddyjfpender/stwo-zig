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
stwo_cairo_cuda_eval_v1_5b50c4d4530b76d2(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 25u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 455u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 456u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 457u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 458u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 459u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 460u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 461u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 462u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 463u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 464u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 465u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 466u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 467u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 468u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 469u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 470u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 471u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 472u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 473u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 474u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 475u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 476u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 477u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 478u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 479u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 480u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 481u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 482u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 522u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 523u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 524u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 528u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 529u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 530u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 531u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 557u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 558u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 559u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 560u, row, 0);
    unsigned b46 = 0u;
    unsigned b47 = stwo_m31_add(b0, b0);
    b0 = stwo_m31_add(b47, b35);
    b47 = stwo_m31_add(b1, b1);
    b1 = stwo_m31_add(b47, b36);
    b47 = stwo_m31_add(b2, b2);
    b2 = stwo_m31_add(b47, b37);
    b47 = stwo_m31_add(b3, b3);
    b3 = stwo_m31_add(b47, b38);
    b47 = stwo_m31_add(b4, b4);
    b4 = stwo_m31_add(b47, b39);
    b47 = stwo_m31_add(b5, b5);
    b5 = stwo_m31_add(b47, b40);
    b47 = stwo_m31_add(b6, b6);
    b6 = stwo_m31_add(b47, b41);
    b47 = stwo_m31_mul(b7, b10);
    b41 = stwo_m31_mul(b8, b9);
    b40 = stwo_m31_add(b47, b41);
    b41 = stwo_m31_mul(b9, b8);
    b47 = stwo_m31_add(b40, b41);
    b41 = stwo_m31_mul(b10, b7);
    b40 = stwo_m31_add(b47, b41);
    b41 = stwo_m31_mul(b7, b11);
    b47 = stwo_m31_mul(b8, b10);
    b39 = stwo_m31_add(b41, b47);
    b47 = stwo_m31_mul(b9, b9);
    b41 = stwo_m31_add(b39, b47);
    b47 = stwo_m31_mul(b10, b8);
    b39 = stwo_m31_add(b41, b47);
    b47 = stwo_m31_mul(b11, b7);
    b41 = stwo_m31_add(b39, b47);
    b47 = stwo_m31_mul(b7, b12);
    b39 = stwo_m31_mul(b8, b11);
    b38 = stwo_m31_add(b47, b39);
    b39 = stwo_m31_mul(b9, b10);
    b47 = stwo_m31_add(b38, b39);
    b39 = stwo_m31_mul(b10, b9);
    b38 = stwo_m31_add(b47, b39);
    b39 = stwo_m31_mul(b11, b8);
    b47 = stwo_m31_add(b38, b39);
    b39 = stwo_m31_mul(b12, b7);
    b38 = stwo_m31_add(b47, b39);
    b39 = stwo_m31_mul(b7, b13);
    b47 = stwo_m31_mul(b8, b12);
    b37 = stwo_m31_add(b39, b47);
    b47 = stwo_m31_mul(b9, b11);
    b39 = stwo_m31_add(b37, b47);
    b47 = stwo_m31_mul(b10, b10);
    b37 = stwo_m31_add(b39, b47);
    b47 = stwo_m31_mul(b11, b9);
    b39 = stwo_m31_add(b37, b47);
    b47 = stwo_m31_mul(b12, b8);
    b37 = stwo_m31_add(b39, b47);
    b47 = stwo_m31_mul(b13, b7);
    b39 = stwo_m31_add(b37, b47);
    b47 = stwo_m31_mul(b11, b13);
    b37 = stwo_m31_mul(b12, b12);
    b36 = stwo_m31_add(b47, b37);
    b37 = stwo_m31_mul(b13, b11);
    b47 = stwo_m31_add(b36, b37);
    b37 = stwo_m31_mul(b12, b13);
    b36 = stwo_m31_mul(b13, b12);
    b35 = stwo_m31_add(b37, b36);
    b36 = stwo_m31_mul(b13, b13);
    b37 = stwo_m31_mul(b14, b17);
    unsigned b48 = stwo_m31_mul(b15, b16);
    unsigned b49 = stwo_m31_add(b37, b48);
    b48 = stwo_m31_mul(b16, b15);
    b37 = stwo_m31_add(b49, b48);
    b48 = stwo_m31_mul(b17, b14);
    b49 = stwo_m31_add(b37, b48);
    b48 = stwo_m31_mul(b14, b18);
    b37 = stwo_m31_mul(b15, b17);
    unsigned b50 = stwo_m31_add(b48, b37);
    b37 = stwo_m31_mul(b16, b16);
    b48 = stwo_m31_add(b50, b37);
    b37 = stwo_m31_mul(b17, b15);
    b50 = stwo_m31_add(b48, b37);
    b37 = stwo_m31_mul(b18, b14);
    b48 = stwo_m31_add(b50, b37);
    b37 = stwo_m31_mul(b14, b19);
    b50 = stwo_m31_mul(b15, b18);
    unsigned b51 = stwo_m31_add(b37, b50);
    b50 = stwo_m31_mul(b16, b17);
    b37 = stwo_m31_add(b51, b50);
    b50 = stwo_m31_mul(b17, b16);
    b51 = stwo_m31_add(b37, b50);
    b50 = stwo_m31_mul(b18, b15);
    b37 = stwo_m31_add(b51, b50);
    b50 = stwo_m31_mul(b19, b14);
    b51 = stwo_m31_add(b37, b50);
    b50 = stwo_m31_mul(b14, b20);
    b37 = stwo_m31_mul(b15, b19);
    unsigned b52 = stwo_m31_add(b50, b37);
    b37 = stwo_m31_mul(b16, b18);
    b50 = stwo_m31_add(b52, b37);
    b37 = stwo_m31_mul(b17, b17);
    b52 = stwo_m31_add(b50, b37);
    b37 = stwo_m31_mul(b18, b16);
    b50 = stwo_m31_add(b52, b37);
    b37 = stwo_m31_mul(b19, b15);
    b52 = stwo_m31_add(b50, b37);
    b37 = stwo_m31_mul(b20, b14);
    b50 = stwo_m31_add(b52, b37);
    b37 = stwo_m31_mul(b18, b20);
    b52 = stwo_m31_mul(b19, b19);
    unsigned b53 = stwo_m31_add(b37, b52);
    b52 = stwo_m31_mul(b20, b18);
    b37 = stwo_m31_add(b53, b52);
    b52 = stwo_m31_mul(b19, b20);
    b53 = stwo_m31_mul(b20, b19);
    unsigned b54 = stwo_m31_add(b52, b53);
    b53 = stwo_m31_mul(b20, b20);
    b52 = stwo_m31_add(b7, b14);
    unsigned b55 = stwo_m31_add(b8, b15);
    unsigned b56 = stwo_m31_add(b9, b16);
    unsigned b57 = stwo_m31_add(b10, b17);
    unsigned b58 = stwo_m31_add(b11, b18);
    unsigned b59 = stwo_m31_add(b12, b19);
    unsigned b60 = stwo_m31_add(b13, b20);
    unsigned b61 = stwo_m31_add(b7, b14);
    b14 = stwo_m31_add(b8, b15);
    b15 = stwo_m31_add(b9, b16);
    b16 = stwo_m31_add(b10, b17);
    b17 = stwo_m31_add(b11, b18);
    b18 = stwo_m31_add(b12, b19);
    unsigned b62 = stwo_m31_add(b13, b20);
    unsigned b63 = stwo_m31_mul(b52, b17);
    unsigned b64 = stwo_m31_mul(b55, b16);
    unsigned b65 = stwo_m31_add(b63, b64);
    b64 = stwo_m31_mul(b56, b15);
    b63 = stwo_m31_add(b65, b64);
    b64 = stwo_m31_mul(b57, b14);
    b65 = stwo_m31_add(b63, b64);
    b64 = stwo_m31_mul(b58, b61);
    b63 = stwo_m31_add(b65, b64);
    b64 = stwo_m31_sub(b63, b41);
    b63 = stwo_m31_sub(b64, b48);
    b64 = stwo_m31_add(b35, b63);
    b63 = stwo_m31_mul(b52, b18);
    b65 = stwo_m31_mul(b55, b17);
    unsigned b66 = stwo_m31_add(b63, b65);
    b65 = stwo_m31_mul(b56, b16);
    b63 = stwo_m31_add(b66, b65);
    b65 = stwo_m31_mul(b57, b15);
    b66 = stwo_m31_add(b63, b65);
    b65 = stwo_m31_mul(b58, b14);
    b63 = stwo_m31_add(b66, b65);
    b65 = stwo_m31_mul(b59, b61);
    b66 = stwo_m31_add(b63, b65);
    b65 = stwo_m31_sub(b66, b38);
    b66 = stwo_m31_sub(b65, b51);
    b65 = stwo_m31_add(b36, b66);
    b66 = stwo_m31_mul(b52, b62);
    b52 = stwo_m31_mul(b55, b18);
    b55 = stwo_m31_add(b66, b52);
    b52 = stwo_m31_mul(b56, b17);
    b56 = stwo_m31_add(b55, b52);
    b52 = stwo_m31_mul(b57, b16);
    b16 = stwo_m31_add(b56, b52);
    b52 = stwo_m31_mul(b58, b15);
    b15 = stwo_m31_add(b16, b52);
    b52 = stwo_m31_mul(b59, b14);
    b14 = stwo_m31_add(b15, b52);
    b52 = stwo_m31_mul(b60, b61);
    b61 = stwo_m31_add(b14, b52);
    b52 = stwo_m31_sub(b61, b39);
    b61 = stwo_m31_sub(b52, b50);
    b52 = stwo_m31_mul(b58, b62);
    b58 = stwo_m31_mul(b59, b18);
    b14 = stwo_m31_add(b52, b58);
    b58 = stwo_m31_mul(b60, b17);
    b17 = stwo_m31_add(b14, b58);
    b58 = stwo_m31_sub(b17, b47);
    b17 = stwo_m31_sub(b58, b37);
    b58 = stwo_m31_add(b49, b17);
    b17 = stwo_m31_mul(b59, b62);
    b59 = stwo_m31_mul(b60, b18);
    b18 = stwo_m31_add(b17, b59);
    b59 = stwo_m31_sub(b18, b35);
    b18 = stwo_m31_sub(b59, b54);
    b59 = stwo_m31_add(b48, b18);
    b18 = stwo_m31_mul(b60, b62);
    b62 = stwo_m31_sub(b18, b36);
    b18 = stwo_m31_sub(b62, b53);
    b62 = stwo_m31_add(b51, b18);
    b18 = stwo_m31_mul(b21, b24);
    b51 = stwo_m31_mul(b22, b23);
    b36 = stwo_m31_add(b18, b51);
    b51 = stwo_m31_mul(b23, b22);
    b18 = stwo_m31_add(b36, b51);
    b51 = stwo_m31_mul(b24, b21);
    b36 = stwo_m31_add(b18, b51);
    b51 = stwo_m31_mul(b21, b25);
    b18 = stwo_m31_mul(b22, b24);
    b60 = stwo_m31_add(b51, b18);
    b18 = stwo_m31_mul(b23, b23);
    b51 = stwo_m31_add(b60, b18);
    b18 = stwo_m31_mul(b24, b22);
    b60 = stwo_m31_add(b51, b18);
    b18 = stwo_m31_mul(b25, b21);
    b51 = stwo_m31_add(b60, b18);
    b18 = stwo_m31_mul(b21, b26);
    b60 = stwo_m31_mul(b22, b25);
    b48 = stwo_m31_add(b18, b60);
    b60 = stwo_m31_mul(b23, b24);
    b18 = stwo_m31_add(b48, b60);
    b60 = stwo_m31_mul(b24, b23);
    b48 = stwo_m31_add(b18, b60);
    b60 = stwo_m31_mul(b25, b22);
    b18 = stwo_m31_add(b48, b60);
    b60 = stwo_m31_mul(b26, b21);
    b48 = stwo_m31_add(b18, b60);
    b60 = stwo_m31_mul(b21, b27);
    b18 = stwo_m31_mul(b22, b26);
    b35 = stwo_m31_add(b60, b18);
    b18 = stwo_m31_mul(b23, b25);
    b60 = stwo_m31_add(b35, b18);
    b18 = stwo_m31_mul(b24, b24);
    b35 = stwo_m31_add(b60, b18);
    b18 = stwo_m31_mul(b25, b23);
    b60 = stwo_m31_add(b35, b18);
    b18 = stwo_m31_mul(b26, b22);
    b35 = stwo_m31_add(b60, b18);
    b18 = stwo_m31_mul(b27, b21);
    b60 = stwo_m31_add(b35, b18);
    b18 = stwo_m31_mul(b26, b27);
    b35 = stwo_m31_mul(b27, b26);
    b17 = stwo_m31_add(b18, b35);
    b35 = stwo_m31_mul(b27, b27);
    b18 = stwo_m31_mul(b28, b32);
    b49 = stwo_m31_mul(b29, b31);
    b37 = stwo_m31_add(b18, b49);
    b49 = stwo_m31_mul(b30, b30);
    b18 = stwo_m31_add(b37, b49);
    b49 = stwo_m31_mul(b31, b29);
    b37 = stwo_m31_add(b18, b49);
    b49 = stwo_m31_mul(b32, b28);
    b18 = stwo_m31_add(b37, b49);
    b49 = stwo_m31_mul(b28, b33);
    b37 = stwo_m31_mul(b29, b32);
    b47 = stwo_m31_add(b49, b37);
    b37 = stwo_m31_mul(b30, b31);
    b49 = stwo_m31_add(b47, b37);
    b37 = stwo_m31_mul(b31, b30);
    b47 = stwo_m31_add(b49, b37);
    b37 = stwo_m31_mul(b32, b29);
    b49 = stwo_m31_add(b47, b37);
    b37 = stwo_m31_mul(b33, b28);
    b47 = stwo_m31_add(b49, b37);
    b37 = stwo_m31_mul(b28, b34);
    b49 = stwo_m31_mul(b29, b33);
    b14 = stwo_m31_add(b37, b49);
    b49 = stwo_m31_mul(b30, b32);
    b37 = stwo_m31_add(b14, b49);
    b49 = stwo_m31_mul(b31, b31);
    b14 = stwo_m31_add(b37, b49);
    b49 = stwo_m31_mul(b32, b30);
    b37 = stwo_m31_add(b14, b49);
    b49 = stwo_m31_mul(b33, b29);
    b14 = stwo_m31_add(b37, b49);
    b49 = stwo_m31_mul(b34, b28);
    b37 = stwo_m31_add(b14, b49);
    b49 = stwo_m31_mul(b33, b34);
    b14 = stwo_m31_mul(b34, b33);
    b52 = stwo_m31_add(b49, b14);
    b14 = stwo_m31_mul(b34, b34);
    b49 = stwo_m31_add(b21, b28);
    b15 = stwo_m31_add(b22, b29);
    b16 = stwo_m31_add(b23, b30);
    b56 = stwo_m31_add(b24, b31);
    b57 = stwo_m31_add(b25, b32);
    b55 = stwo_m31_add(b26, b33);
    b66 = stwo_m31_add(b27, b34);
    b63 = stwo_m31_add(b21, b28);
    b28 = stwo_m31_add(b22, b29);
    b29 = stwo_m31_add(b23, b30);
    b30 = stwo_m31_add(b24, b31);
    b31 = stwo_m31_add(b25, b32);
    b32 = stwo_m31_add(b26, b33);
    unsigned b67 = stwo_m31_add(b27, b34);
    unsigned b68 = stwo_m31_mul(b49, b31);
    unsigned b69 = stwo_m31_mul(b15, b30);
    unsigned b70 = stwo_m31_add(b68, b69);
    b69 = stwo_m31_mul(b16, b29);
    b68 = stwo_m31_add(b70, b69);
    b69 = stwo_m31_mul(b56, b28);
    b70 = stwo_m31_add(b68, b69);
    b69 = stwo_m31_mul(b57, b63);
    b68 = stwo_m31_add(b70, b69);
    b69 = stwo_m31_sub(b68, b51);
    b68 = stwo_m31_sub(b69, b18);
    b69 = stwo_m31_add(b17, b68);
    b68 = stwo_m31_mul(b49, b32);
    b17 = stwo_m31_mul(b15, b31);
    b18 = stwo_m31_add(b68, b17);
    b17 = stwo_m31_mul(b16, b30);
    b68 = stwo_m31_add(b18, b17);
    b17 = stwo_m31_mul(b56, b29);
    b18 = stwo_m31_add(b68, b17);
    b17 = stwo_m31_mul(b57, b28);
    b68 = stwo_m31_add(b18, b17);
    b17 = stwo_m31_mul(b55, b63);
    b18 = stwo_m31_add(b68, b17);
    b17 = stwo_m31_sub(b18, b48);
    b18 = stwo_m31_sub(b17, b47);
    b17 = stwo_m31_add(b35, b18);
    b18 = stwo_m31_mul(b49, b67);
    b67 = stwo_m31_mul(b15, b32);
    b32 = stwo_m31_add(b18, b67);
    b67 = stwo_m31_mul(b16, b31);
    b31 = stwo_m31_add(b32, b67);
    b67 = stwo_m31_mul(b56, b30);
    b30 = stwo_m31_add(b31, b67);
    b67 = stwo_m31_mul(b57, b29);
    b29 = stwo_m31_add(b30, b67);
    b67 = stwo_m31_mul(b55, b28);
    b28 = stwo_m31_add(b29, b67);
    b67 = stwo_m31_mul(b66, b63);
    b63 = stwo_m31_add(b28, b67);
    b67 = stwo_m31_sub(b63, b60);
    b63 = stwo_m31_sub(b67, b37);
    b67 = stwo_m31_add(b7, b21);
    b37 = stwo_m31_add(b8, b22);
    b28 = stwo_m31_add(b9, b23);
    b66 = stwo_m31_add(b10, b24);
    b29 = stwo_m31_add(b11, b25);
    b55 = stwo_m31_add(b12, b26);
    b30 = stwo_m31_add(b13, b27);
    b57 = stwo_m31_add(b19, b33);
    b31 = stwo_m31_add(b20, b34);
    b56 = stwo_m31_add(b7, b21);
    b21 = stwo_m31_add(b8, b22);
    b22 = stwo_m31_add(b9, b23);
    b23 = stwo_m31_add(b10, b24);
    b24 = stwo_m31_add(b11, b25);
    b25 = stwo_m31_add(b12, b26);
    b26 = stwo_m31_add(b13, b27);
    b27 = stwo_m31_add(b19, b33);
    b33 = stwo_m31_add(b20, b34);
    b34 = stwo_m31_mul(b67, b23);
    b20 = stwo_m31_mul(b37, b22);
    b19 = stwo_m31_add(b34, b20);
    b20 = stwo_m31_mul(b28, b21);
    b34 = stwo_m31_add(b19, b20);
    b20 = stwo_m31_mul(b66, b56);
    b19 = stwo_m31_add(b34, b20);
    b20 = stwo_m31_mul(b67, b24);
    b34 = stwo_m31_mul(b37, b23);
    b13 = stwo_m31_add(b20, b34);
    b34 = stwo_m31_mul(b28, b22);
    b20 = stwo_m31_add(b13, b34);
    b34 = stwo_m31_mul(b66, b21);
    b13 = stwo_m31_add(b20, b34);
    b34 = stwo_m31_mul(b29, b56);
    b20 = stwo_m31_add(b13, b34);
    b34 = stwo_m31_mul(b67, b25);
    b13 = stwo_m31_mul(b37, b24);
    b12 = stwo_m31_add(b34, b13);
    b13 = stwo_m31_mul(b28, b23);
    b34 = stwo_m31_add(b12, b13);
    b13 = stwo_m31_mul(b66, b22);
    b12 = stwo_m31_add(b34, b13);
    b13 = stwo_m31_mul(b29, b21);
    b34 = stwo_m31_add(b12, b13);
    b13 = stwo_m31_mul(b55, b56);
    b12 = stwo_m31_add(b34, b13);
    b13 = stwo_m31_mul(b67, b26);
    b26 = stwo_m31_mul(b37, b25);
    b25 = stwo_m31_add(b13, b26);
    b26 = stwo_m31_mul(b28, b24);
    b24 = stwo_m31_add(b25, b26);
    b26 = stwo_m31_mul(b66, b23);
    b23 = stwo_m31_add(b24, b26);
    b26 = stwo_m31_mul(b29, b22);
    b22 = stwo_m31_add(b23, b26);
    b26 = stwo_m31_mul(b55, b21);
    b21 = stwo_m31_add(b22, b26);
    b26 = stwo_m31_mul(b30, b56);
    b56 = stwo_m31_add(b21, b26);
    b26 = stwo_m31_mul(b57, b33);
    b57 = stwo_m31_mul(b31, b27);
    b27 = stwo_m31_add(b26, b57);
    b57 = stwo_m31_mul(b31, b33);
    b33 = stwo_m31_sub(b19, b40);
    b19 = stwo_m31_sub(b33, b36);
    b33 = stwo_m31_add(b58, b19);
    b19 = stwo_m31_sub(b20, b41);
    b20 = stwo_m31_sub(b19, b51);
    b19 = stwo_m31_add(b59, b20);
    b20 = stwo_m31_sub(b12, b38);
    b12 = stwo_m31_sub(b20, b48);
    b20 = stwo_m31_add(b62, b12);
    b12 = stwo_m31_sub(b56, b39);
    b56 = stwo_m31_sub(b12, b60);
    b12 = stwo_m31_add(b50, b56);
    b56 = stwo_m31_sub(b27, b54);
    b27 = stwo_m31_sub(b56, b52);
    b56 = stwo_m31_add(b69, b27);
    b27 = stwo_m31_sub(b57, b53);
    b57 = stwo_m31_sub(b27, b14);
    b27 = stwo_m31_add(b17, b57);
    b57 = stwo_m31_sub(b64, b0);
    b64 = stwo_m31_sub(b65, b1);
    b65 = stwo_m31_sub(b61, b2);
    b61 = stwo_m31_sub(b33, b3);
    b33 = stwo_m31_sub(b19, b4);
    b19 = stwo_m31_sub(b20, b5);
    b20 = stwo_m31_sub(b12, b6);
    b12 = 2u;
    b6 = stwo_m31_mul(b12, b57);
    b12 = stwo_m31_add(b6, b61);
    b6 = 32u;
    b61 = stwo_m31_mul(b6, b33);
    b6 = stwo_m31_add(b12, b61);
    b61 = 4u;
    b12 = stwo_m31_mul(b61, b56);
    b61 = stwo_m31_sub(b6, b12);
    b12 = 2u;
    b6 = stwo_m31_mul(b12, b64);
    b12 = stwo_m31_add(b6, b33);
    b6 = 32u;
    b33 = stwo_m31_mul(b6, b19);
    b6 = stwo_m31_add(b12, b33);
    b33 = 4u;
    b12 = stwo_m31_mul(b33, b27);
    b33 = stwo_m31_sub(b6, b12);
    b12 = 2u;
    b6 = stwo_m31_mul(b12, b65);
    b12 = stwo_m31_add(b6, b19);
    b6 = 32u;
    b19 = stwo_m31_mul(b6, b20);
    b6 = stwo_m31_add(b12, b19);
    b19 = 4u;
    b12 = stwo_m31_mul(b19, b63);
    b19 = stwo_m31_sub(b6, b12);
    b12 = 512u;
    b6 = stwo_m31_mul(b43, b12);
    b12 = stwo_m31_add(b61, b42);
    b61 = stwo_m31_sub(b6, b12);
    b12 = 512u;
    b6 = stwo_m31_mul(b44, b12);
    b12 = stwo_m31_add(b33, b43);
    b33 = stwo_m31_sub(b6, b12);
    b12 = 512u;
    b6 = stwo_m31_mul(b45, b12);
    b12 = stwo_m31_add(b19, b44);
    b19 = stwo_m31_sub(b6, b12);
    StwoCairoQm31 e0 = { b61, b46, b46, b46 };
    StwoCairoQm31 e1 = { b33, b46, b46, b46 };
    StwoCairoQm31 e2 = { b19, b46, b46, b46 };
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
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
