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
stwo_cairo_cuda_eval_v1_091cacc282314dc6(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 455u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 456u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 457u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 458u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 459u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 460u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 461u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 462u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 463u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 464u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 465u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 466u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 467u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 468u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 469u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 470u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 471u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 472u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 473u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 474u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 475u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 476u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 477u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 478u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 479u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 480u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 481u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 482u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 515u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 516u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 517u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 537u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 538u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 544u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 545u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 546u, row, 0);
    unsigned b41 = 0u;
    unsigned b42 = stwo_m31_add(b0, b0);
    b0 = stwo_m31_add(b42, b33);
    b42 = stwo_m31_add(b1, b1);
    b1 = stwo_m31_add(b42, b34);
    b42 = stwo_m31_add(b2, b2);
    b2 = stwo_m31_add(b42, b35);
    b42 = stwo_m31_add(b3, b3);
    b3 = stwo_m31_add(b42, b36);
    b42 = stwo_m31_add(b4, b4);
    b4 = stwo_m31_add(b42, b37);
    b42 = stwo_m31_mul(b5, b9);
    b37 = stwo_m31_mul(b6, b8);
    b36 = stwo_m31_add(b42, b37);
    b37 = stwo_m31_mul(b7, b7);
    b42 = stwo_m31_add(b36, b37);
    b37 = stwo_m31_mul(b8, b6);
    b36 = stwo_m31_add(b42, b37);
    b37 = stwo_m31_mul(b9, b5);
    b42 = stwo_m31_add(b36, b37);
    b37 = stwo_m31_mul(b5, b10);
    b36 = stwo_m31_mul(b6, b9);
    b35 = stwo_m31_add(b37, b36);
    b36 = stwo_m31_mul(b7, b8);
    b37 = stwo_m31_add(b35, b36);
    b36 = stwo_m31_mul(b8, b7);
    b35 = stwo_m31_add(b37, b36);
    b36 = stwo_m31_mul(b9, b6);
    b37 = stwo_m31_add(b35, b36);
    b36 = stwo_m31_mul(b10, b5);
    b35 = stwo_m31_add(b37, b36);
    b36 = stwo_m31_mul(b5, b11);
    b37 = stwo_m31_mul(b6, b10);
    b34 = stwo_m31_add(b36, b37);
    b37 = stwo_m31_mul(b7, b9);
    b36 = stwo_m31_add(b34, b37);
    b37 = stwo_m31_mul(b8, b8);
    b34 = stwo_m31_add(b36, b37);
    b37 = stwo_m31_mul(b9, b7);
    b36 = stwo_m31_add(b34, b37);
    b37 = stwo_m31_mul(b10, b6);
    b34 = stwo_m31_add(b36, b37);
    b37 = stwo_m31_mul(b11, b5);
    b36 = stwo_m31_add(b34, b37);
    b37 = stwo_m31_mul(b11, b11);
    b34 = stwo_m31_mul(b12, b17);
    b33 = stwo_m31_mul(b13, b16);
    unsigned b43 = stwo_m31_add(b34, b33);
    b33 = stwo_m31_mul(b14, b15);
    b34 = stwo_m31_add(b43, b33);
    b33 = stwo_m31_mul(b15, b14);
    b43 = stwo_m31_add(b34, b33);
    b33 = stwo_m31_mul(b16, b13);
    b34 = stwo_m31_add(b43, b33);
    b33 = stwo_m31_mul(b17, b12);
    b43 = stwo_m31_add(b34, b33);
    b33 = stwo_m31_mul(b12, b18);
    b34 = stwo_m31_mul(b13, b17);
    unsigned b44 = stwo_m31_add(b33, b34);
    b34 = stwo_m31_mul(b14, b16);
    b33 = stwo_m31_add(b44, b34);
    b34 = stwo_m31_mul(b15, b15);
    b44 = stwo_m31_add(b33, b34);
    b34 = stwo_m31_mul(b16, b14);
    b33 = stwo_m31_add(b44, b34);
    b34 = stwo_m31_mul(b17, b13);
    b44 = stwo_m31_add(b33, b34);
    b34 = stwo_m31_mul(b18, b12);
    b33 = stwo_m31_add(b44, b34);
    b34 = stwo_m31_mul(b18, b18);
    b44 = stwo_m31_add(b5, b12);
    unsigned b45 = stwo_m31_add(b6, b13);
    unsigned b46 = stwo_m31_add(b7, b14);
    unsigned b47 = stwo_m31_add(b8, b15);
    unsigned b48 = stwo_m31_add(b9, b16);
    unsigned b49 = stwo_m31_add(b10, b17);
    unsigned b50 = stwo_m31_add(b11, b18);
    unsigned b51 = stwo_m31_add(b5, b12);
    unsigned b52 = stwo_m31_add(b6, b13);
    unsigned b53 = stwo_m31_add(b7, b14);
    unsigned b54 = stwo_m31_add(b8, b15);
    unsigned b55 = stwo_m31_add(b9, b16);
    unsigned b56 = stwo_m31_add(b10, b17);
    unsigned b57 = stwo_m31_add(b11, b18);
    unsigned b58 = stwo_m31_mul(b44, b56);
    unsigned b59 = stwo_m31_mul(b45, b55);
    unsigned b60 = stwo_m31_add(b58, b59);
    b59 = stwo_m31_mul(b46, b54);
    b58 = stwo_m31_add(b60, b59);
    b59 = stwo_m31_mul(b47, b53);
    b60 = stwo_m31_add(b58, b59);
    b59 = stwo_m31_mul(b48, b52);
    b58 = stwo_m31_add(b60, b59);
    b59 = stwo_m31_mul(b49, b51);
    b60 = stwo_m31_add(b58, b59);
    b59 = stwo_m31_sub(b60, b35);
    b60 = stwo_m31_sub(b59, b43);
    b59 = stwo_m31_add(b37, b60);
    b60 = stwo_m31_mul(b44, b57);
    b57 = stwo_m31_mul(b45, b56);
    b56 = stwo_m31_add(b60, b57);
    b57 = stwo_m31_mul(b46, b55);
    b55 = stwo_m31_add(b56, b57);
    b57 = stwo_m31_mul(b47, b54);
    b54 = stwo_m31_add(b55, b57);
    b57 = stwo_m31_mul(b48, b53);
    b53 = stwo_m31_add(b54, b57);
    b57 = stwo_m31_mul(b49, b52);
    b52 = stwo_m31_add(b53, b57);
    b57 = stwo_m31_mul(b50, b51);
    b51 = stwo_m31_add(b52, b57);
    b57 = stwo_m31_sub(b51, b36);
    b51 = stwo_m31_sub(b57, b33);
    b57 = stwo_m31_mul(b19, b24);
    b33 = stwo_m31_mul(b20, b23);
    b52 = stwo_m31_add(b57, b33);
    b33 = stwo_m31_mul(b21, b22);
    b57 = stwo_m31_add(b52, b33);
    b33 = stwo_m31_mul(b22, b21);
    b52 = stwo_m31_add(b57, b33);
    b33 = stwo_m31_mul(b23, b20);
    b57 = stwo_m31_add(b52, b33);
    b33 = stwo_m31_mul(b24, b19);
    b52 = stwo_m31_add(b57, b33);
    b33 = stwo_m31_mul(b19, b25);
    b57 = stwo_m31_mul(b20, b24);
    b50 = stwo_m31_add(b33, b57);
    b57 = stwo_m31_mul(b21, b23);
    b33 = stwo_m31_add(b50, b57);
    b57 = stwo_m31_mul(b22, b22);
    b50 = stwo_m31_add(b33, b57);
    b57 = stwo_m31_mul(b23, b21);
    b33 = stwo_m31_add(b50, b57);
    b57 = stwo_m31_mul(b24, b20);
    b50 = stwo_m31_add(b33, b57);
    b57 = stwo_m31_mul(b25, b19);
    b33 = stwo_m31_add(b50, b57);
    b57 = stwo_m31_mul(b25, b25);
    b50 = stwo_m31_mul(b26, b31);
    b53 = stwo_m31_mul(b27, b30);
    b49 = stwo_m31_add(b50, b53);
    b53 = stwo_m31_mul(b28, b29);
    b50 = stwo_m31_add(b49, b53);
    b53 = stwo_m31_mul(b29, b28);
    b49 = stwo_m31_add(b50, b53);
    b53 = stwo_m31_mul(b30, b27);
    b50 = stwo_m31_add(b49, b53);
    b53 = stwo_m31_mul(b31, b26);
    b49 = stwo_m31_add(b50, b53);
    b53 = stwo_m31_mul(b26, b32);
    b50 = stwo_m31_mul(b27, b31);
    b54 = stwo_m31_add(b53, b50);
    b50 = stwo_m31_mul(b28, b30);
    b53 = stwo_m31_add(b54, b50);
    b50 = stwo_m31_mul(b29, b29);
    b54 = stwo_m31_add(b53, b50);
    b50 = stwo_m31_mul(b30, b28);
    b53 = stwo_m31_add(b54, b50);
    b50 = stwo_m31_mul(b31, b27);
    b54 = stwo_m31_add(b53, b50);
    b50 = stwo_m31_mul(b32, b26);
    b53 = stwo_m31_add(b54, b50);
    b50 = stwo_m31_mul(b32, b32);
    b54 = stwo_m31_add(b19, b26);
    b48 = stwo_m31_add(b20, b27);
    b55 = stwo_m31_add(b21, b28);
    b47 = stwo_m31_add(b22, b29);
    b56 = stwo_m31_add(b23, b30);
    b46 = stwo_m31_add(b24, b31);
    b60 = stwo_m31_add(b25, b32);
    b45 = stwo_m31_add(b19, b26);
    b44 = stwo_m31_add(b20, b27);
    b37 = stwo_m31_add(b21, b28);
    b43 = stwo_m31_add(b22, b29);
    b58 = stwo_m31_add(b23, b30);
    unsigned b61 = stwo_m31_add(b24, b31);
    unsigned b62 = stwo_m31_add(b25, b32);
    unsigned b63 = stwo_m31_mul(b54, b61);
    unsigned b64 = stwo_m31_mul(b48, b58);
    unsigned b65 = stwo_m31_add(b63, b64);
    b64 = stwo_m31_mul(b55, b43);
    b63 = stwo_m31_add(b65, b64);
    b64 = stwo_m31_mul(b47, b37);
    b65 = stwo_m31_add(b63, b64);
    b64 = stwo_m31_mul(b56, b44);
    b63 = stwo_m31_add(b65, b64);
    b64 = stwo_m31_mul(b46, b45);
    b65 = stwo_m31_add(b63, b64);
    b64 = stwo_m31_sub(b65, b52);
    b65 = stwo_m31_sub(b64, b49);
    b64 = stwo_m31_add(b57, b65);
    b65 = stwo_m31_mul(b54, b62);
    b62 = stwo_m31_mul(b48, b61);
    b61 = stwo_m31_add(b65, b62);
    b62 = stwo_m31_mul(b55, b58);
    b58 = stwo_m31_add(b61, b62);
    b62 = stwo_m31_mul(b47, b43);
    b43 = stwo_m31_add(b58, b62);
    b62 = stwo_m31_mul(b56, b37);
    b37 = stwo_m31_add(b43, b62);
    b62 = stwo_m31_mul(b46, b44);
    b44 = stwo_m31_add(b37, b62);
    b62 = stwo_m31_mul(b60, b45);
    b45 = stwo_m31_add(b44, b62);
    b62 = stwo_m31_sub(b45, b33);
    b45 = stwo_m31_sub(b62, b53);
    b62 = stwo_m31_add(b5, b19);
    b53 = stwo_m31_add(b6, b20);
    b33 = stwo_m31_add(b7, b21);
    b44 = stwo_m31_add(b8, b22);
    b60 = stwo_m31_add(b9, b23);
    b37 = stwo_m31_add(b10, b24);
    b46 = stwo_m31_add(b11, b25);
    b43 = stwo_m31_add(b12, b26);
    b56 = stwo_m31_add(b13, b27);
    b58 = stwo_m31_add(b14, b28);
    b47 = stwo_m31_add(b15, b29);
    b61 = stwo_m31_add(b16, b30);
    b55 = stwo_m31_add(b17, b31);
    b65 = stwo_m31_add(b18, b32);
    b48 = stwo_m31_add(b5, b19);
    b19 = stwo_m31_add(b6, b20);
    b20 = stwo_m31_add(b7, b21);
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
    b32 = stwo_m31_mul(b62, b23);
    b18 = stwo_m31_mul(b53, b22);
    b17 = stwo_m31_add(b32, b18);
    b18 = stwo_m31_mul(b33, b21);
    b32 = stwo_m31_add(b17, b18);
    b18 = stwo_m31_mul(b44, b20);
    b17 = stwo_m31_add(b32, b18);
    b18 = stwo_m31_mul(b60, b19);
    b32 = stwo_m31_add(b17, b18);
    b18 = stwo_m31_mul(b37, b48);
    b17 = stwo_m31_add(b32, b18);
    b18 = stwo_m31_mul(b62, b24);
    b32 = stwo_m31_mul(b53, b23);
    b16 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_mul(b33, b22);
    b18 = stwo_m31_add(b16, b32);
    b32 = stwo_m31_mul(b44, b21);
    b16 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_mul(b60, b20);
    b18 = stwo_m31_add(b16, b32);
    b32 = stwo_m31_mul(b37, b19);
    b16 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_mul(b46, b48);
    b18 = stwo_m31_add(b16, b32);
    b32 = stwo_m31_mul(b46, b24);
    b16 = stwo_m31_mul(b43, b30);
    b15 = stwo_m31_mul(b56, b29);
    b14 = stwo_m31_add(b16, b15);
    b15 = stwo_m31_mul(b58, b28);
    b16 = stwo_m31_add(b14, b15);
    b15 = stwo_m31_mul(b47, b27);
    b14 = stwo_m31_add(b16, b15);
    b15 = stwo_m31_mul(b61, b26);
    b16 = stwo_m31_add(b14, b15);
    b15 = stwo_m31_mul(b55, b25);
    b14 = stwo_m31_add(b16, b15);
    b15 = stwo_m31_mul(b43, b31);
    b16 = stwo_m31_mul(b56, b30);
    b13 = stwo_m31_add(b15, b16);
    b16 = stwo_m31_mul(b58, b29);
    b15 = stwo_m31_add(b13, b16);
    b16 = stwo_m31_mul(b47, b28);
    b13 = stwo_m31_add(b15, b16);
    b16 = stwo_m31_mul(b61, b27);
    b15 = stwo_m31_add(b13, b16);
    b16 = stwo_m31_mul(b55, b26);
    b13 = stwo_m31_add(b15, b16);
    b16 = stwo_m31_mul(b65, b25);
    b15 = stwo_m31_add(b13, b16);
    b16 = stwo_m31_add(b62, b43);
    b43 = stwo_m31_add(b53, b56);
    b56 = stwo_m31_add(b33, b58);
    b58 = stwo_m31_add(b44, b47);
    b47 = stwo_m31_add(b60, b61);
    b61 = stwo_m31_add(b37, b55);
    b55 = stwo_m31_add(b46, b65);
    b65 = stwo_m31_add(b48, b25);
    b25 = stwo_m31_add(b19, b26);
    b26 = stwo_m31_add(b20, b27);
    b27 = stwo_m31_add(b21, b28);
    b28 = stwo_m31_add(b22, b29);
    b29 = stwo_m31_add(b23, b30);
    b30 = stwo_m31_add(b24, b31);
    b31 = stwo_m31_mul(b16, b29);
    b24 = stwo_m31_mul(b43, b28);
    b23 = stwo_m31_add(b31, b24);
    b24 = stwo_m31_mul(b56, b27);
    b31 = stwo_m31_add(b23, b24);
    b24 = stwo_m31_mul(b58, b26);
    b23 = stwo_m31_add(b31, b24);
    b24 = stwo_m31_mul(b47, b25);
    b31 = stwo_m31_add(b23, b24);
    b24 = stwo_m31_mul(b61, b65);
    b23 = stwo_m31_add(b31, b24);
    b24 = stwo_m31_sub(b23, b17);
    b23 = stwo_m31_sub(b24, b14);
    b24 = stwo_m31_add(b32, b23);
    b23 = stwo_m31_mul(b16, b30);
    b30 = stwo_m31_mul(b43, b29);
    b29 = stwo_m31_add(b23, b30);
    b30 = stwo_m31_mul(b56, b28);
    b28 = stwo_m31_add(b29, b30);
    b30 = stwo_m31_mul(b58, b27);
    b27 = stwo_m31_add(b28, b30);
    b30 = stwo_m31_mul(b47, b26);
    b26 = stwo_m31_add(b27, b30);
    b30 = stwo_m31_mul(b61, b25);
    b25 = stwo_m31_add(b26, b30);
    b30 = stwo_m31_mul(b55, b65);
    b65 = stwo_m31_add(b25, b30);
    b30 = stwo_m31_sub(b65, b18);
    b65 = stwo_m31_sub(b30, b15);
    b30 = stwo_m31_sub(b24, b59);
    b24 = stwo_m31_sub(b30, b64);
    b30 = stwo_m31_add(b34, b24);
    b24 = stwo_m31_sub(b65, b51);
    b65 = stwo_m31_sub(b24, b45);
    b24 = stwo_m31_sub(b42, b0);
    b42 = stwo_m31_sub(b35, b1);
    b35 = stwo_m31_sub(b36, b2);
    b36 = stwo_m31_sub(b30, b3);
    b30 = stwo_m31_sub(b65, b4);
    b65 = 32u;
    b4 = stwo_m31_mul(b65, b42);
    b65 = stwo_m31_add(b24, b4);
    b4 = 4u;
    b24 = stwo_m31_mul(b4, b36);
    b4 = stwo_m31_sub(b65, b24);
    b24 = 8u;
    b65 = stwo_m31_mul(b24, b50);
    b24 = stwo_m31_add(b4, b65);
    b65 = 32u;
    b4 = stwo_m31_mul(b65, b35);
    b65 = stwo_m31_add(b42, b4);
    b4 = 4u;
    b42 = stwo_m31_mul(b4, b30);
    b4 = stwo_m31_sub(b65, b42);
    b42 = 512u;
    b65 = stwo_m31_mul(b39, b42);
    b42 = stwo_m31_add(b24, b38);
    b24 = stwo_m31_sub(b65, b42);
    b42 = 512u;
    b65 = stwo_m31_mul(b40, b42);
    b42 = stwo_m31_add(b4, b39);
    b4 = stwo_m31_sub(b65, b42);
    StwoCairoQm31 e0 = { b24, b41, b41, b41 };
    StwoCairoQm31 e1 = { b4, b41, b41, b41 };
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
