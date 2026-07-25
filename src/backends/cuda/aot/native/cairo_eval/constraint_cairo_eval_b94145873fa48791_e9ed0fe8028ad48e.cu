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
stwo_cairo_cuda_eval_v1_e86d177ae98f917f(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
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
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 512u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 513u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 514u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 515u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 534u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 535u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 536u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 541u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 542u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 543u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 544u, row, 0);
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
    b47 = stwo_m31_mul(b10, b13);
    b37 = stwo_m31_mul(b11, b12);
    b36 = stwo_m31_add(b47, b37);
    b37 = stwo_m31_mul(b12, b11);
    b47 = stwo_m31_add(b36, b37);
    b37 = stwo_m31_mul(b13, b10);
    b36 = stwo_m31_add(b47, b37);
    b37 = stwo_m31_mul(b11, b13);
    b47 = stwo_m31_mul(b12, b12);
    b35 = stwo_m31_add(b37, b47);
    b47 = stwo_m31_mul(b13, b11);
    b37 = stwo_m31_add(b35, b47);
    b47 = stwo_m31_mul(b12, b13);
    b35 = stwo_m31_mul(b13, b12);
    unsigned b48 = stwo_m31_add(b47, b35);
    b35 = stwo_m31_mul(b14, b16);
    b47 = stwo_m31_mul(b15, b15);
    unsigned b49 = stwo_m31_add(b35, b47);
    b47 = stwo_m31_mul(b16, b14);
    b35 = stwo_m31_add(b49, b47);
    b47 = stwo_m31_mul(b14, b17);
    b49 = stwo_m31_mul(b15, b16);
    unsigned b50 = stwo_m31_add(b47, b49);
    b49 = stwo_m31_mul(b16, b15);
    b47 = stwo_m31_add(b50, b49);
    b49 = stwo_m31_mul(b17, b14);
    b50 = stwo_m31_add(b47, b49);
    b49 = stwo_m31_mul(b14, b18);
    b47 = stwo_m31_mul(b15, b17);
    unsigned b51 = stwo_m31_add(b49, b47);
    b47 = stwo_m31_mul(b16, b16);
    b49 = stwo_m31_add(b51, b47);
    b47 = stwo_m31_mul(b17, b15);
    b51 = stwo_m31_add(b49, b47);
    b47 = stwo_m31_mul(b18, b14);
    b49 = stwo_m31_add(b51, b47);
    b47 = stwo_m31_mul(b17, b20);
    b51 = stwo_m31_mul(b18, b19);
    unsigned b52 = stwo_m31_add(b47, b51);
    b51 = stwo_m31_mul(b19, b18);
    b47 = stwo_m31_add(b52, b51);
    b51 = stwo_m31_mul(b20, b17);
    b52 = stwo_m31_add(b47, b51);
    b51 = stwo_m31_mul(b18, b20);
    b47 = stwo_m31_mul(b19, b19);
    unsigned b53 = stwo_m31_add(b51, b47);
    b47 = stwo_m31_mul(b20, b18);
    b51 = stwo_m31_add(b53, b47);
    b47 = stwo_m31_mul(b19, b20);
    b53 = stwo_m31_mul(b20, b19);
    b20 = stwo_m31_add(b47, b53);
    b53 = stwo_m31_add(b7, b14);
    b47 = stwo_m31_add(b8, b15);
    b19 = stwo_m31_add(b9, b16);
    unsigned b54 = stwo_m31_add(b10, b17);
    unsigned b55 = stwo_m31_add(b11, b18);
    unsigned b56 = stwo_m31_add(b7, b14);
    unsigned b57 = stwo_m31_add(b8, b15);
    unsigned b58 = stwo_m31_add(b9, b16);
    unsigned b59 = stwo_m31_add(b10, b17);
    unsigned b60 = stwo_m31_add(b11, b18);
    unsigned b61 = stwo_m31_mul(b53, b58);
    unsigned b62 = stwo_m31_mul(b47, b57);
    unsigned b63 = stwo_m31_add(b61, b62);
    b62 = stwo_m31_mul(b19, b56);
    b61 = stwo_m31_add(b63, b62);
    b62 = stwo_m31_sub(b61, b41);
    b61 = stwo_m31_sub(b62, b35);
    b62 = stwo_m31_add(b36, b61);
    b61 = stwo_m31_mul(b53, b59);
    b36 = stwo_m31_mul(b47, b58);
    b35 = stwo_m31_add(b61, b36);
    b36 = stwo_m31_mul(b19, b57);
    b61 = stwo_m31_add(b35, b36);
    b36 = stwo_m31_mul(b54, b56);
    b35 = stwo_m31_add(b61, b36);
    b36 = stwo_m31_sub(b35, b38);
    b35 = stwo_m31_sub(b36, b50);
    b36 = stwo_m31_add(b37, b35);
    b35 = stwo_m31_mul(b53, b60);
    b60 = stwo_m31_mul(b47, b59);
    b59 = stwo_m31_add(b35, b60);
    b60 = stwo_m31_mul(b19, b58);
    b58 = stwo_m31_add(b59, b60);
    b60 = stwo_m31_mul(b54, b57);
    b57 = stwo_m31_add(b58, b60);
    b60 = stwo_m31_mul(b55, b56);
    b56 = stwo_m31_add(b57, b60);
    b60 = stwo_m31_sub(b56, b39);
    b56 = stwo_m31_sub(b60, b49);
    b60 = stwo_m31_add(b48, b56);
    b56 = stwo_m31_mul(b21, b23);
    b48 = stwo_m31_mul(b22, b22);
    b49 = stwo_m31_add(b56, b48);
    b48 = stwo_m31_mul(b23, b21);
    b56 = stwo_m31_add(b49, b48);
    b48 = stwo_m31_mul(b21, b24);
    b49 = stwo_m31_mul(b22, b23);
    b57 = stwo_m31_add(b48, b49);
    b49 = stwo_m31_mul(b23, b22);
    b48 = stwo_m31_add(b57, b49);
    b49 = stwo_m31_mul(b24, b21);
    b57 = stwo_m31_add(b48, b49);
    b49 = stwo_m31_mul(b21, b25);
    b48 = stwo_m31_mul(b22, b24);
    b55 = stwo_m31_add(b49, b48);
    b48 = stwo_m31_mul(b23, b23);
    b49 = stwo_m31_add(b55, b48);
    b48 = stwo_m31_mul(b24, b22);
    b55 = stwo_m31_add(b49, b48);
    b48 = stwo_m31_mul(b25, b21);
    b49 = stwo_m31_add(b55, b48);
    b48 = stwo_m31_mul(b24, b27);
    b55 = stwo_m31_mul(b25, b26);
    b58 = stwo_m31_add(b48, b55);
    b55 = stwo_m31_mul(b26, b25);
    b48 = stwo_m31_add(b58, b55);
    b55 = stwo_m31_mul(b27, b24);
    b58 = stwo_m31_add(b48, b55);
    b55 = stwo_m31_mul(b25, b27);
    b48 = stwo_m31_mul(b26, b26);
    b54 = stwo_m31_add(b55, b48);
    b48 = stwo_m31_mul(b27, b25);
    b55 = stwo_m31_add(b54, b48);
    b48 = stwo_m31_mul(b26, b27);
    b54 = stwo_m31_mul(b27, b26);
    b59 = stwo_m31_add(b48, b54);
    b54 = stwo_m31_mul(b28, b30);
    b48 = stwo_m31_mul(b29, b29);
    b19 = stwo_m31_add(b54, b48);
    b48 = stwo_m31_mul(b30, b28);
    b54 = stwo_m31_add(b19, b48);
    b48 = stwo_m31_mul(b28, b31);
    b19 = stwo_m31_mul(b29, b30);
    b35 = stwo_m31_add(b48, b19);
    b19 = stwo_m31_mul(b30, b29);
    b48 = stwo_m31_add(b35, b19);
    b19 = stwo_m31_mul(b31, b28);
    b35 = stwo_m31_add(b48, b19);
    b19 = stwo_m31_mul(b28, b32);
    b48 = stwo_m31_mul(b29, b31);
    b47 = stwo_m31_add(b19, b48);
    b48 = stwo_m31_mul(b30, b30);
    b19 = stwo_m31_add(b47, b48);
    b48 = stwo_m31_mul(b31, b29);
    b47 = stwo_m31_add(b19, b48);
    b48 = stwo_m31_mul(b32, b28);
    b19 = stwo_m31_add(b47, b48);
    b48 = stwo_m31_mul(b31, b34);
    b47 = stwo_m31_mul(b32, b33);
    b53 = stwo_m31_add(b48, b47);
    b47 = stwo_m31_mul(b33, b32);
    b48 = stwo_m31_add(b53, b47);
    b47 = stwo_m31_mul(b34, b31);
    b53 = stwo_m31_add(b48, b47);
    b47 = stwo_m31_mul(b32, b34);
    b48 = stwo_m31_mul(b33, b33);
    b37 = stwo_m31_add(b47, b48);
    b48 = stwo_m31_mul(b34, b32);
    b47 = stwo_m31_add(b37, b48);
    b48 = stwo_m31_mul(b33, b34);
    b37 = stwo_m31_mul(b34, b33);
    b34 = stwo_m31_add(b48, b37);
    b37 = stwo_m31_add(b21, b28);
    b48 = stwo_m31_add(b22, b29);
    b33 = stwo_m31_add(b23, b30);
    b50 = stwo_m31_add(b24, b31);
    b61 = stwo_m31_add(b25, b32);
    b63 = stwo_m31_add(b21, b28);
    unsigned b64 = stwo_m31_add(b22, b29);
    unsigned b65 = stwo_m31_add(b23, b30);
    unsigned b66 = stwo_m31_add(b24, b31);
    unsigned b67 = stwo_m31_add(b25, b32);
    unsigned b68 = stwo_m31_mul(b37, b65);
    unsigned b69 = stwo_m31_mul(b48, b64);
    unsigned b70 = stwo_m31_add(b68, b69);
    b69 = stwo_m31_mul(b33, b63);
    b68 = stwo_m31_add(b70, b69);
    b69 = stwo_m31_sub(b68, b56);
    b68 = stwo_m31_sub(b69, b54);
    b69 = stwo_m31_add(b58, b68);
    b68 = stwo_m31_mul(b37, b66);
    b58 = stwo_m31_mul(b48, b65);
    b54 = stwo_m31_add(b68, b58);
    b58 = stwo_m31_mul(b33, b64);
    b68 = stwo_m31_add(b54, b58);
    b58 = stwo_m31_mul(b50, b63);
    b54 = stwo_m31_add(b68, b58);
    b58 = stwo_m31_sub(b54, b57);
    b54 = stwo_m31_sub(b58, b35);
    b58 = stwo_m31_add(b55, b54);
    b54 = stwo_m31_mul(b37, b67);
    b67 = stwo_m31_mul(b48, b66);
    b66 = stwo_m31_add(b54, b67);
    b67 = stwo_m31_mul(b33, b65);
    b65 = stwo_m31_add(b66, b67);
    b67 = stwo_m31_mul(b50, b64);
    b64 = stwo_m31_add(b65, b67);
    b67 = stwo_m31_mul(b61, b63);
    b63 = stwo_m31_add(b64, b67);
    b67 = stwo_m31_sub(b63, b49);
    b63 = stwo_m31_sub(b67, b19);
    b67 = stwo_m31_add(b59, b63);
    b63 = stwo_m31_add(b7, b21);
    b59 = stwo_m31_add(b8, b22);
    b19 = stwo_m31_add(b9, b23);
    b49 = stwo_m31_add(b10, b24);
    b64 = stwo_m31_add(b11, b25);
    b61 = stwo_m31_add(b12, b26);
    b65 = stwo_m31_add(b13, b27);
    b50 = stwo_m31_add(b14, b28);
    b66 = stwo_m31_add(b15, b29);
    b33 = stwo_m31_add(b16, b30);
    b54 = stwo_m31_add(b17, b31);
    b48 = stwo_m31_add(b18, b32);
    b37 = stwo_m31_add(b7, b21);
    b21 = stwo_m31_add(b8, b22);
    b22 = stwo_m31_add(b9, b23);
    b23 = stwo_m31_add(b10, b24);
    b24 = stwo_m31_add(b11, b25);
    b25 = stwo_m31_add(b12, b26);
    b26 = stwo_m31_add(b13, b27);
    b27 = stwo_m31_add(b14, b28);
    b28 = stwo_m31_add(b15, b29);
    b29 = stwo_m31_add(b16, b30);
    b30 = stwo_m31_add(b17, b31);
    b31 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_mul(b63, b22);
    b18 = stwo_m31_mul(b59, b21);
    b17 = stwo_m31_add(b32, b18);
    b18 = stwo_m31_mul(b19, b37);
    b32 = stwo_m31_add(b17, b18);
    b18 = stwo_m31_mul(b63, b23);
    b17 = stwo_m31_mul(b59, b22);
    b16 = stwo_m31_add(b18, b17);
    b17 = stwo_m31_mul(b19, b21);
    b18 = stwo_m31_add(b16, b17);
    b17 = stwo_m31_mul(b49, b37);
    b16 = stwo_m31_add(b18, b17);
    b17 = stwo_m31_mul(b63, b24);
    b18 = stwo_m31_mul(b59, b23);
    b15 = stwo_m31_add(b17, b18);
    b18 = stwo_m31_mul(b19, b22);
    b17 = stwo_m31_add(b15, b18);
    b18 = stwo_m31_mul(b49, b21);
    b15 = stwo_m31_add(b17, b18);
    b18 = stwo_m31_mul(b64, b37);
    b17 = stwo_m31_add(b15, b18);
    b18 = stwo_m31_mul(b49, b26);
    b15 = stwo_m31_mul(b64, b25);
    b14 = stwo_m31_add(b18, b15);
    b15 = stwo_m31_mul(b61, b24);
    b18 = stwo_m31_add(b14, b15);
    b15 = stwo_m31_mul(b65, b23);
    b14 = stwo_m31_add(b18, b15);
    b15 = stwo_m31_mul(b64, b26);
    b18 = stwo_m31_mul(b61, b25);
    b13 = stwo_m31_add(b15, b18);
    b18 = stwo_m31_mul(b65, b24);
    b15 = stwo_m31_add(b13, b18);
    b18 = stwo_m31_mul(b61, b26);
    b26 = stwo_m31_mul(b65, b25);
    b25 = stwo_m31_add(b18, b26);
    b26 = stwo_m31_mul(b50, b29);
    b18 = stwo_m31_mul(b66, b28);
    b65 = stwo_m31_add(b26, b18);
    b18 = stwo_m31_mul(b33, b27);
    b26 = stwo_m31_add(b65, b18);
    b18 = stwo_m31_mul(b50, b30);
    b65 = stwo_m31_mul(b66, b29);
    b61 = stwo_m31_add(b18, b65);
    b65 = stwo_m31_mul(b33, b28);
    b18 = stwo_m31_add(b61, b65);
    b65 = stwo_m31_mul(b54, b27);
    b61 = stwo_m31_add(b18, b65);
    b65 = stwo_m31_mul(b50, b31);
    b18 = stwo_m31_mul(b66, b30);
    b13 = stwo_m31_add(b65, b18);
    b18 = stwo_m31_mul(b33, b29);
    b65 = stwo_m31_add(b13, b18);
    b18 = stwo_m31_mul(b54, b28);
    b13 = stwo_m31_add(b65, b18);
    b18 = stwo_m31_mul(b48, b27);
    b65 = stwo_m31_add(b13, b18);
    b18 = stwo_m31_add(b63, b50);
    b50 = stwo_m31_add(b59, b66);
    b66 = stwo_m31_add(b19, b33);
    b33 = stwo_m31_add(b49, b54);
    b54 = stwo_m31_add(b64, b48);
    b48 = stwo_m31_add(b37, b27);
    b27 = stwo_m31_add(b21, b28);
    b28 = stwo_m31_add(b22, b29);
    b29 = stwo_m31_add(b23, b30);
    b30 = stwo_m31_add(b24, b31);
    b31 = stwo_m31_mul(b18, b28);
    b24 = stwo_m31_mul(b50, b27);
    b23 = stwo_m31_add(b31, b24);
    b24 = stwo_m31_mul(b66, b48);
    b31 = stwo_m31_add(b23, b24);
    b24 = stwo_m31_sub(b31, b32);
    b31 = stwo_m31_sub(b24, b26);
    b24 = stwo_m31_add(b14, b31);
    b31 = stwo_m31_mul(b18, b29);
    b14 = stwo_m31_mul(b50, b28);
    b26 = stwo_m31_add(b31, b14);
    b14 = stwo_m31_mul(b66, b27);
    b31 = stwo_m31_add(b26, b14);
    b14 = stwo_m31_mul(b33, b48);
    b26 = stwo_m31_add(b31, b14);
    b14 = stwo_m31_sub(b26, b16);
    b26 = stwo_m31_sub(b14, b61);
    b14 = stwo_m31_add(b15, b26);
    b26 = stwo_m31_mul(b18, b30);
    b30 = stwo_m31_mul(b50, b29);
    b29 = stwo_m31_add(b26, b30);
    b30 = stwo_m31_mul(b66, b28);
    b28 = stwo_m31_add(b29, b30);
    b30 = stwo_m31_mul(b33, b27);
    b27 = stwo_m31_add(b28, b30);
    b30 = stwo_m31_mul(b54, b48);
    b48 = stwo_m31_add(b27, b30);
    b30 = stwo_m31_sub(b48, b17);
    b48 = stwo_m31_sub(b30, b65);
    b30 = stwo_m31_add(b25, b48);
    b48 = stwo_m31_sub(b24, b62);
    b24 = stwo_m31_sub(b48, b69);
    b48 = stwo_m31_add(b52, b24);
    b24 = stwo_m31_sub(b14, b36);
    b14 = stwo_m31_sub(b24, b58);
    b24 = stwo_m31_add(b51, b14);
    b14 = stwo_m31_sub(b30, b60);
    b30 = stwo_m31_sub(b14, b67);
    b14 = stwo_m31_add(b20, b30);
    b30 = stwo_m31_sub(b40, b0);
    b40 = stwo_m31_sub(b41, b1);
    b41 = stwo_m31_sub(b38, b2);
    b38 = stwo_m31_sub(b39, b3);
    b39 = stwo_m31_sub(b48, b4);
    b48 = stwo_m31_sub(b24, b5);
    b24 = stwo_m31_sub(b14, b6);
    b14 = 32u;
    b6 = stwo_m31_mul(b14, b40);
    b14 = stwo_m31_add(b30, b6);
    b6 = 4u;
    b30 = stwo_m31_mul(b6, b39);
    b6 = stwo_m31_sub(b14, b30);
    b30 = 8u;
    b14 = stwo_m31_mul(b30, b53);
    b30 = stwo_m31_add(b6, b14);
    b14 = 32u;
    b6 = stwo_m31_mul(b14, b41);
    b14 = stwo_m31_add(b40, b6);
    b6 = 4u;
    b40 = stwo_m31_mul(b6, b48);
    b6 = stwo_m31_sub(b14, b40);
    b40 = 8u;
    b14 = stwo_m31_mul(b40, b47);
    b40 = stwo_m31_add(b6, b14);
    b14 = 32u;
    b6 = stwo_m31_mul(b14, b38);
    b14 = stwo_m31_add(b41, b6);
    b6 = 4u;
    b41 = stwo_m31_mul(b6, b24);
    b6 = stwo_m31_sub(b14, b41);
    b41 = 8u;
    b14 = stwo_m31_mul(b41, b34);
    b41 = stwo_m31_add(b6, b14);
    b14 = 512u;
    b6 = stwo_m31_mul(b43, b14);
    b14 = stwo_m31_add(b30, b42);
    b30 = stwo_m31_sub(b6, b14);
    b14 = 512u;
    b6 = stwo_m31_mul(b44, b14);
    b14 = stwo_m31_add(b40, b43);
    b40 = stwo_m31_sub(b6, b14);
    b14 = 512u;
    b6 = stwo_m31_mul(b45, b14);
    b14 = stwo_m31_add(b41, b44);
    b41 = stwo_m31_sub(b6, b14);
    StwoCairoQm31 e0 = { b30, b46, b46, b46 };
    StwoCairoQm31 e1 = { b40, b46, b46, b46 };
    StwoCairoQm31 e2 = { b41, b46, b46, b46 };
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
