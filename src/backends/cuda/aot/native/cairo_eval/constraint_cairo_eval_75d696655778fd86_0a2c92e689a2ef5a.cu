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
stwo_cairo_cuda_eval_v1_e7b891cbf5890df6(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
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
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 513u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 514u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 515u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 519u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 520u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 521u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 522u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 548u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 549u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 550u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 551u, row, 0);
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
    b47 = stwo_m31_mul(b7, b8);
    b41 = stwo_m31_mul(b8, b7);
    b40 = stwo_m31_add(b47, b41);
    b41 = stwo_m31_mul(b7, b9);
    b47 = stwo_m31_mul(b8, b8);
    b39 = stwo_m31_add(b41, b47);
    b47 = stwo_m31_mul(b9, b7);
    b41 = stwo_m31_add(b39, b47);
    b47 = stwo_m31_mul(b7, b10);
    b39 = stwo_m31_mul(b8, b9);
    b38 = stwo_m31_add(b47, b39);
    b39 = stwo_m31_mul(b9, b8);
    b47 = stwo_m31_add(b38, b39);
    b39 = stwo_m31_mul(b10, b7);
    b38 = stwo_m31_add(b47, b39);
    b39 = stwo_m31_mul(b7, b11);
    b47 = stwo_m31_mul(b8, b10);
    b37 = stwo_m31_add(b39, b47);
    b47 = stwo_m31_mul(b9, b9);
    b39 = stwo_m31_add(b37, b47);
    b47 = stwo_m31_mul(b10, b8);
    b37 = stwo_m31_add(b39, b47);
    b47 = stwo_m31_mul(b11, b7);
    b39 = stwo_m31_add(b37, b47);
    b47 = stwo_m31_mul(b9, b13);
    b37 = stwo_m31_mul(b10, b12);
    b36 = stwo_m31_add(b47, b37);
    b37 = stwo_m31_mul(b11, b11);
    b47 = stwo_m31_add(b36, b37);
    b37 = stwo_m31_mul(b12, b10);
    b36 = stwo_m31_add(b47, b37);
    b37 = stwo_m31_mul(b13, b9);
    b47 = stwo_m31_add(b36, b37);
    b37 = stwo_m31_mul(b10, b13);
    b36 = stwo_m31_mul(b11, b12);
    b35 = stwo_m31_add(b37, b36);
    b36 = stwo_m31_mul(b12, b11);
    b37 = stwo_m31_add(b35, b36);
    b36 = stwo_m31_mul(b13, b10);
    b35 = stwo_m31_add(b37, b36);
    b36 = stwo_m31_mul(b11, b13);
    b37 = stwo_m31_mul(b12, b12);
    unsigned b48 = stwo_m31_add(b36, b37);
    b37 = stwo_m31_mul(b13, b11);
    b36 = stwo_m31_add(b48, b37);
    b37 = stwo_m31_mul(b12, b13);
    b48 = stwo_m31_mul(b13, b12);
    unsigned b49 = stwo_m31_add(b37, b48);
    b48 = stwo_m31_mul(b14, b15);
    b37 = stwo_m31_mul(b15, b14);
    unsigned b50 = stwo_m31_add(b48, b37);
    b37 = stwo_m31_mul(b14, b16);
    b48 = stwo_m31_mul(b15, b15);
    unsigned b51 = stwo_m31_add(b37, b48);
    b48 = stwo_m31_mul(b16, b14);
    b37 = stwo_m31_add(b51, b48);
    b48 = stwo_m31_mul(b14, b17);
    b51 = stwo_m31_mul(b15, b16);
    unsigned b52 = stwo_m31_add(b48, b51);
    b51 = stwo_m31_mul(b16, b15);
    b48 = stwo_m31_add(b52, b51);
    b51 = stwo_m31_mul(b17, b14);
    b52 = stwo_m31_add(b48, b51);
    b51 = stwo_m31_mul(b14, b18);
    b48 = stwo_m31_mul(b15, b17);
    unsigned b53 = stwo_m31_add(b51, b48);
    b48 = stwo_m31_mul(b16, b16);
    b51 = stwo_m31_add(b53, b48);
    b48 = stwo_m31_mul(b17, b15);
    b53 = stwo_m31_add(b51, b48);
    b48 = stwo_m31_mul(b18, b14);
    b51 = stwo_m31_add(b53, b48);
    b48 = stwo_m31_mul(b17, b20);
    b53 = stwo_m31_mul(b18, b19);
    unsigned b54 = stwo_m31_add(b48, b53);
    b53 = stwo_m31_mul(b19, b18);
    b48 = stwo_m31_add(b54, b53);
    b53 = stwo_m31_mul(b20, b17);
    b54 = stwo_m31_add(b48, b53);
    b53 = stwo_m31_mul(b18, b20);
    b48 = stwo_m31_mul(b19, b19);
    unsigned b55 = stwo_m31_add(b53, b48);
    b48 = stwo_m31_mul(b20, b18);
    b53 = stwo_m31_add(b55, b48);
    b48 = stwo_m31_mul(b19, b20);
    b55 = stwo_m31_mul(b20, b19);
    unsigned b56 = stwo_m31_add(b48, b55);
    b55 = stwo_m31_add(b7, b14);
    b48 = stwo_m31_add(b8, b15);
    unsigned b57 = stwo_m31_add(b9, b16);
    unsigned b58 = stwo_m31_add(b10, b17);
    unsigned b59 = stwo_m31_add(b11, b18);
    unsigned b60 = stwo_m31_add(b12, b19);
    unsigned b61 = stwo_m31_add(b13, b20);
    unsigned b62 = stwo_m31_add(b7, b14);
    b7 = stwo_m31_add(b8, b15);
    b8 = stwo_m31_add(b9, b16);
    b9 = stwo_m31_add(b10, b17);
    unsigned b63 = stwo_m31_add(b11, b18);
    unsigned b64 = stwo_m31_add(b12, b19);
    unsigned b65 = stwo_m31_add(b13, b20);
    unsigned b66 = stwo_m31_mul(b55, b7);
    unsigned b67 = stwo_m31_mul(b48, b62);
    unsigned b68 = stwo_m31_add(b66, b67);
    b67 = stwo_m31_sub(b68, b40);
    b68 = stwo_m31_sub(b67, b50);
    b67 = stwo_m31_add(b47, b68);
    b68 = stwo_m31_mul(b55, b8);
    b47 = stwo_m31_mul(b48, b7);
    b50 = stwo_m31_add(b68, b47);
    b47 = stwo_m31_mul(b57, b62);
    b68 = stwo_m31_add(b50, b47);
    b47 = stwo_m31_sub(b68, b41);
    b68 = stwo_m31_sub(b47, b37);
    b47 = stwo_m31_add(b35, b68);
    b68 = stwo_m31_mul(b55, b9);
    b50 = stwo_m31_mul(b48, b8);
    b40 = stwo_m31_add(b68, b50);
    b50 = stwo_m31_mul(b57, b7);
    b68 = stwo_m31_add(b40, b50);
    b50 = stwo_m31_mul(b58, b62);
    b40 = stwo_m31_add(b68, b50);
    b50 = stwo_m31_sub(b40, b38);
    b40 = stwo_m31_sub(b50, b52);
    b50 = stwo_m31_add(b36, b40);
    b40 = stwo_m31_mul(b55, b63);
    b55 = stwo_m31_mul(b48, b9);
    b48 = stwo_m31_add(b40, b55);
    b55 = stwo_m31_mul(b57, b8);
    b8 = stwo_m31_add(b48, b55);
    b55 = stwo_m31_mul(b58, b7);
    b7 = stwo_m31_add(b8, b55);
    b55 = stwo_m31_mul(b59, b62);
    b62 = stwo_m31_add(b7, b55);
    b55 = stwo_m31_sub(b62, b39);
    b62 = stwo_m31_sub(b55, b51);
    b55 = stwo_m31_add(b49, b62);
    b62 = stwo_m31_mul(b58, b65);
    b58 = stwo_m31_mul(b59, b64);
    b7 = stwo_m31_add(b62, b58);
    b58 = stwo_m31_mul(b60, b63);
    b62 = stwo_m31_add(b7, b58);
    b58 = stwo_m31_mul(b61, b9);
    b9 = stwo_m31_add(b62, b58);
    b58 = stwo_m31_sub(b9, b35);
    b9 = stwo_m31_sub(b58, b54);
    b58 = stwo_m31_add(b37, b9);
    b9 = stwo_m31_mul(b59, b65);
    b59 = stwo_m31_mul(b60, b64);
    b37 = stwo_m31_add(b9, b59);
    b59 = stwo_m31_mul(b61, b63);
    b63 = stwo_m31_add(b37, b59);
    b59 = stwo_m31_sub(b63, b36);
    b63 = stwo_m31_sub(b59, b53);
    b59 = stwo_m31_add(b52, b63);
    b63 = stwo_m31_mul(b60, b65);
    b65 = stwo_m31_mul(b61, b64);
    b64 = stwo_m31_add(b63, b65);
    b65 = stwo_m31_sub(b64, b49);
    b64 = stwo_m31_sub(b65, b56);
    b65 = stwo_m31_add(b51, b64);
    b64 = stwo_m31_mul(b21, b23);
    b51 = stwo_m31_mul(b22, b22);
    b56 = stwo_m31_add(b64, b51);
    b51 = stwo_m31_mul(b23, b21);
    b64 = stwo_m31_add(b56, b51);
    b51 = stwo_m31_mul(b21, b24);
    b56 = stwo_m31_mul(b22, b23);
    b49 = stwo_m31_add(b51, b56);
    b56 = stwo_m31_mul(b23, b22);
    b51 = stwo_m31_add(b49, b56);
    b56 = stwo_m31_mul(b24, b21);
    b49 = stwo_m31_add(b51, b56);
    b56 = stwo_m31_mul(b21, b25);
    b51 = stwo_m31_mul(b22, b24);
    b63 = stwo_m31_add(b56, b51);
    b51 = stwo_m31_mul(b23, b23);
    b23 = stwo_m31_add(b63, b51);
    b51 = stwo_m31_mul(b24, b22);
    b22 = stwo_m31_add(b23, b51);
    b51 = stwo_m31_mul(b25, b21);
    b21 = stwo_m31_add(b22, b51);
    b51 = stwo_m31_mul(b24, b27);
    b22 = stwo_m31_mul(b25, b26);
    b23 = stwo_m31_add(b51, b22);
    b22 = stwo_m31_mul(b26, b25);
    b51 = stwo_m31_add(b23, b22);
    b22 = stwo_m31_mul(b27, b24);
    b23 = stwo_m31_add(b51, b22);
    b22 = stwo_m31_mul(b25, b27);
    b51 = stwo_m31_mul(b26, b26);
    b63 = stwo_m31_add(b22, b51);
    b51 = stwo_m31_mul(b27, b25);
    b22 = stwo_m31_add(b63, b51);
    b51 = stwo_m31_mul(b26, b27);
    b63 = stwo_m31_mul(b27, b26);
    b56 = stwo_m31_add(b51, b63);
    b63 = stwo_m31_mul(b28, b30);
    b51 = stwo_m31_mul(b29, b29);
    b61 = stwo_m31_add(b63, b51);
    b51 = stwo_m31_mul(b30, b28);
    b63 = stwo_m31_add(b61, b51);
    b51 = stwo_m31_mul(b28, b31);
    b61 = stwo_m31_mul(b29, b30);
    b60 = stwo_m31_add(b51, b61);
    b61 = stwo_m31_mul(b30, b29);
    b51 = stwo_m31_add(b60, b61);
    b61 = stwo_m31_mul(b31, b28);
    b60 = stwo_m31_add(b51, b61);
    b61 = stwo_m31_mul(b28, b32);
    b51 = stwo_m31_mul(b29, b31);
    b52 = stwo_m31_add(b61, b51);
    b51 = stwo_m31_mul(b30, b30);
    b61 = stwo_m31_add(b52, b51);
    b51 = stwo_m31_mul(b31, b29);
    b52 = stwo_m31_add(b61, b51);
    b51 = stwo_m31_mul(b32, b28);
    b61 = stwo_m31_add(b52, b51);
    b51 = stwo_m31_mul(b31, b34);
    b52 = stwo_m31_mul(b32, b33);
    b53 = stwo_m31_add(b51, b52);
    b52 = stwo_m31_mul(b33, b32);
    b51 = stwo_m31_add(b53, b52);
    b52 = stwo_m31_mul(b34, b31);
    b53 = stwo_m31_add(b51, b52);
    b52 = stwo_m31_mul(b32, b34);
    b51 = stwo_m31_mul(b33, b33);
    b36 = stwo_m31_add(b52, b51);
    b51 = stwo_m31_mul(b34, b32);
    b52 = stwo_m31_add(b36, b51);
    b51 = stwo_m31_mul(b33, b34);
    b36 = stwo_m31_mul(b34, b33);
    b37 = stwo_m31_add(b51, b36);
    b36 = stwo_m31_add(b24, b31);
    b51 = stwo_m31_add(b25, b32);
    b9 = stwo_m31_add(b26, b33);
    b54 = stwo_m31_add(b27, b34);
    b35 = stwo_m31_add(b24, b31);
    b62 = stwo_m31_add(b25, b32);
    b7 = stwo_m31_add(b26, b33);
    b8 = stwo_m31_add(b27, b34);
    b48 = stwo_m31_mul(b36, b8);
    b36 = stwo_m31_mul(b51, b7);
    b57 = stwo_m31_add(b48, b36);
    b36 = stwo_m31_mul(b9, b62);
    b48 = stwo_m31_add(b57, b36);
    b36 = stwo_m31_mul(b54, b35);
    b35 = stwo_m31_add(b48, b36);
    b36 = stwo_m31_sub(b35, b23);
    b35 = stwo_m31_sub(b36, b53);
    b36 = stwo_m31_add(b63, b35);
    b35 = stwo_m31_mul(b51, b8);
    b51 = stwo_m31_mul(b9, b7);
    b63 = stwo_m31_add(b35, b51);
    b51 = stwo_m31_mul(b54, b62);
    b62 = stwo_m31_add(b63, b51);
    b51 = stwo_m31_sub(b62, b22);
    b62 = stwo_m31_sub(b51, b52);
    b51 = stwo_m31_add(b60, b62);
    b62 = stwo_m31_mul(b9, b8);
    b8 = stwo_m31_mul(b54, b7);
    b7 = stwo_m31_add(b62, b8);
    b8 = stwo_m31_sub(b7, b56);
    b7 = stwo_m31_sub(b8, b37);
    b8 = stwo_m31_add(b61, b7);
    b7 = stwo_m31_add(b10, b24);
    b61 = stwo_m31_add(b11, b25);
    b37 = stwo_m31_add(b12, b26);
    b56 = stwo_m31_add(b13, b27);
    b62 = stwo_m31_add(b14, b28);
    b54 = stwo_m31_add(b15, b29);
    b9 = stwo_m31_add(b16, b30);
    b60 = stwo_m31_add(b17, b31);
    b52 = stwo_m31_add(b18, b32);
    b22 = stwo_m31_add(b19, b33);
    b63 = stwo_m31_add(b20, b34);
    b35 = stwo_m31_add(b10, b24);
    b24 = stwo_m31_add(b11, b25);
    b25 = stwo_m31_add(b12, b26);
    b26 = stwo_m31_add(b13, b27);
    b27 = stwo_m31_add(b14, b28);
    b28 = stwo_m31_add(b15, b29);
    b29 = stwo_m31_add(b16, b30);
    b30 = stwo_m31_add(b17, b31);
    b31 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_add(b19, b33);
    b33 = stwo_m31_add(b20, b34);
    b34 = stwo_m31_mul(b7, b26);
    b20 = stwo_m31_mul(b61, b25);
    b19 = stwo_m31_add(b34, b20);
    b20 = stwo_m31_mul(b37, b24);
    b34 = stwo_m31_add(b19, b20);
    b20 = stwo_m31_mul(b56, b35);
    b19 = stwo_m31_add(b34, b20);
    b20 = stwo_m31_mul(b61, b26);
    b34 = stwo_m31_mul(b37, b25);
    b18 = stwo_m31_add(b20, b34);
    b34 = stwo_m31_mul(b56, b24);
    b20 = stwo_m31_add(b18, b34);
    b34 = stwo_m31_mul(b37, b26);
    b18 = stwo_m31_mul(b56, b25);
    b17 = stwo_m31_add(b34, b18);
    b18 = stwo_m31_mul(b62, b29);
    b34 = stwo_m31_mul(b54, b28);
    b16 = stwo_m31_add(b18, b34);
    b34 = stwo_m31_mul(b9, b27);
    b18 = stwo_m31_add(b16, b34);
    b34 = stwo_m31_mul(b62, b30);
    b16 = stwo_m31_mul(b54, b29);
    b15 = stwo_m31_add(b34, b16);
    b16 = stwo_m31_mul(b9, b28);
    b34 = stwo_m31_add(b15, b16);
    b16 = stwo_m31_mul(b60, b27);
    b15 = stwo_m31_add(b34, b16);
    b16 = stwo_m31_mul(b62, b31);
    b62 = stwo_m31_mul(b54, b30);
    b54 = stwo_m31_add(b16, b62);
    b62 = stwo_m31_mul(b9, b29);
    b29 = stwo_m31_add(b54, b62);
    b62 = stwo_m31_mul(b60, b28);
    b28 = stwo_m31_add(b29, b62);
    b62 = stwo_m31_mul(b52, b27);
    b27 = stwo_m31_add(b28, b62);
    b62 = stwo_m31_mul(b60, b33);
    b28 = stwo_m31_mul(b52, b32);
    b29 = stwo_m31_add(b62, b28);
    b28 = stwo_m31_mul(b22, b31);
    b62 = stwo_m31_add(b29, b28);
    b28 = stwo_m31_mul(b63, b30);
    b29 = stwo_m31_add(b62, b28);
    b28 = stwo_m31_mul(b52, b33);
    b62 = stwo_m31_mul(b22, b32);
    b54 = stwo_m31_add(b28, b62);
    b62 = stwo_m31_mul(b63, b31);
    b28 = stwo_m31_add(b54, b62);
    b62 = stwo_m31_mul(b22, b33);
    b54 = stwo_m31_mul(b63, b32);
    b9 = stwo_m31_add(b62, b54);
    b54 = stwo_m31_add(b7, b60);
    b60 = stwo_m31_add(b61, b52);
    b52 = stwo_m31_add(b37, b22);
    b22 = stwo_m31_add(b56, b63);
    b63 = stwo_m31_add(b35, b30);
    b30 = stwo_m31_add(b24, b31);
    b31 = stwo_m31_add(b25, b32);
    b32 = stwo_m31_add(b26, b33);
    b33 = stwo_m31_mul(b54, b32);
    b54 = stwo_m31_mul(b60, b31);
    b26 = stwo_m31_add(b33, b54);
    b54 = stwo_m31_mul(b52, b30);
    b33 = stwo_m31_add(b26, b54);
    b54 = stwo_m31_mul(b22, b63);
    b63 = stwo_m31_add(b33, b54);
    b54 = stwo_m31_sub(b63, b19);
    b63 = stwo_m31_sub(b54, b29);
    b54 = stwo_m31_add(b18, b63);
    b63 = stwo_m31_mul(b60, b32);
    b60 = stwo_m31_mul(b52, b31);
    b18 = stwo_m31_add(b63, b60);
    b60 = stwo_m31_mul(b22, b30);
    b30 = stwo_m31_add(b18, b60);
    b60 = stwo_m31_sub(b30, b20);
    b30 = stwo_m31_sub(b60, b28);
    b60 = stwo_m31_add(b15, b30);
    b30 = stwo_m31_mul(b52, b32);
    b32 = stwo_m31_mul(b22, b31);
    b31 = stwo_m31_add(b30, b32);
    b32 = stwo_m31_sub(b31, b17);
    b31 = stwo_m31_sub(b32, b9);
    b32 = stwo_m31_add(b27, b31);
    b31 = stwo_m31_sub(b54, b58);
    b54 = stwo_m31_sub(b31, b36);
    b31 = stwo_m31_add(b64, b54);
    b54 = stwo_m31_sub(b60, b59);
    b60 = stwo_m31_sub(b54, b51);
    b54 = stwo_m31_add(b49, b60);
    b60 = stwo_m31_sub(b32, b65);
    b32 = stwo_m31_sub(b60, b8);
    b60 = stwo_m31_add(b21, b32);
    b32 = stwo_m31_sub(b41, b0);
    b41 = stwo_m31_sub(b38, b1);
    b38 = stwo_m31_sub(b39, b2);
    b39 = stwo_m31_sub(b67, b3);
    b67 = stwo_m31_sub(b47, b4);
    b47 = stwo_m31_sub(b50, b5);
    b50 = stwo_m31_sub(b55, b6);
    b55 = 2u;
    b6 = stwo_m31_mul(b55, b32);
    b55 = stwo_m31_add(b6, b39);
    b6 = 32u;
    b39 = stwo_m31_mul(b6, b67);
    b6 = stwo_m31_add(b55, b39);
    b39 = 4u;
    b55 = stwo_m31_mul(b39, b31);
    b39 = stwo_m31_sub(b6, b55);
    b55 = 2u;
    b6 = stwo_m31_mul(b55, b41);
    b55 = stwo_m31_add(b6, b67);
    b6 = 32u;
    b67 = stwo_m31_mul(b6, b47);
    b6 = stwo_m31_add(b55, b67);
    b67 = 4u;
    b55 = stwo_m31_mul(b67, b54);
    b67 = stwo_m31_sub(b6, b55);
    b55 = 2u;
    b6 = stwo_m31_mul(b55, b38);
    b55 = stwo_m31_add(b6, b47);
    b6 = 32u;
    b47 = stwo_m31_mul(b6, b50);
    b6 = stwo_m31_add(b55, b47);
    b47 = 4u;
    b55 = stwo_m31_mul(b47, b60);
    b47 = stwo_m31_sub(b6, b55);
    b55 = 512u;
    b6 = stwo_m31_mul(b43, b55);
    b55 = stwo_m31_add(b39, b42);
    b39 = stwo_m31_sub(b6, b55);
    b55 = 512u;
    b6 = stwo_m31_mul(b44, b55);
    b55 = stwo_m31_add(b67, b43);
    b67 = stwo_m31_sub(b6, b55);
    b55 = 512u;
    b6 = stwo_m31_mul(b45, b55);
    b55 = stwo_m31_add(b47, b44);
    b47 = stwo_m31_sub(b6, b55);
    StwoCairoQm31 e0 = { b39, b46, b46, b46 };
    StwoCairoQm31 e1 = { b67, b46, b46, b46 };
    StwoCairoQm31 e2 = { b47, b46, b46, b46 };
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
