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
stwo_cairo_cuda_eval_v1_96376ce3b7db1d62(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 19u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
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
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 511u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 512u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 517u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 518u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 519u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 546u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 547u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 548u, row, 0);
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
    b42 = stwo_m31_mul(b5, b5);
    b37 = stwo_m31_mul(b5, b6);
    b36 = stwo_m31_mul(b6, b5);
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
    b37 = stwo_m31_mul(b6, b11);
    b34 = stwo_m31_mul(b7, b10);
    b33 = stwo_m31_add(b37, b34);
    b34 = stwo_m31_mul(b8, b9);
    b37 = stwo_m31_add(b33, b34);
    b34 = stwo_m31_mul(b9, b8);
    b33 = stwo_m31_add(b37, b34);
    b34 = stwo_m31_mul(b10, b7);
    b37 = stwo_m31_add(b33, b34);
    b34 = stwo_m31_mul(b11, b6);
    b33 = stwo_m31_add(b37, b34);
    b34 = stwo_m31_mul(b7, b11);
    b37 = stwo_m31_mul(b8, b10);
    unsigned b43 = stwo_m31_add(b34, b37);
    b37 = stwo_m31_mul(b9, b9);
    b34 = stwo_m31_add(b43, b37);
    b37 = stwo_m31_mul(b10, b8);
    b43 = stwo_m31_add(b34, b37);
    b37 = stwo_m31_mul(b11, b7);
    b34 = stwo_m31_add(b43, b37);
    b37 = stwo_m31_mul(b12, b12);
    b43 = stwo_m31_mul(b12, b13);
    unsigned b44 = stwo_m31_mul(b13, b12);
    unsigned b45 = stwo_m31_add(b43, b44);
    b44 = stwo_m31_mul(b13, b18);
    b43 = stwo_m31_mul(b14, b17);
    unsigned b46 = stwo_m31_add(b44, b43);
    b43 = stwo_m31_mul(b15, b16);
    b44 = stwo_m31_add(b46, b43);
    b43 = stwo_m31_mul(b16, b15);
    b46 = stwo_m31_add(b44, b43);
    b43 = stwo_m31_mul(b17, b14);
    b44 = stwo_m31_add(b46, b43);
    b43 = stwo_m31_mul(b18, b13);
    b46 = stwo_m31_add(b44, b43);
    b43 = stwo_m31_mul(b14, b18);
    b44 = stwo_m31_mul(b15, b17);
    unsigned b47 = stwo_m31_add(b43, b44);
    b44 = stwo_m31_mul(b16, b16);
    b43 = stwo_m31_add(b47, b44);
    b44 = stwo_m31_mul(b17, b15);
    b47 = stwo_m31_add(b43, b44);
    b44 = stwo_m31_mul(b18, b14);
    b43 = stwo_m31_add(b47, b44);
    b44 = stwo_m31_add(b5, b12);
    b47 = stwo_m31_add(b6, b13);
    unsigned b48 = stwo_m31_add(b7, b14);
    unsigned b49 = stwo_m31_add(b8, b15);
    unsigned b50 = stwo_m31_add(b9, b16);
    unsigned b51 = stwo_m31_add(b10, b17);
    unsigned b52 = stwo_m31_add(b11, b18);
    unsigned b53 = stwo_m31_add(b5, b12);
    b5 = stwo_m31_add(b6, b13);
    unsigned b54 = stwo_m31_add(b7, b14);
    unsigned b55 = stwo_m31_add(b8, b15);
    unsigned b56 = stwo_m31_add(b9, b16);
    unsigned b57 = stwo_m31_add(b10, b17);
    unsigned b58 = stwo_m31_add(b11, b18);
    unsigned b59 = stwo_m31_mul(b44, b53);
    unsigned b60 = stwo_m31_sub(b59, b42);
    b59 = stwo_m31_sub(b60, b37);
    b60 = stwo_m31_add(b33, b59);
    b59 = stwo_m31_mul(b44, b5);
    b44 = stwo_m31_mul(b47, b53);
    b53 = stwo_m31_add(b59, b44);
    b44 = stwo_m31_sub(b53, b35);
    b53 = stwo_m31_sub(b44, b45);
    b44 = stwo_m31_add(b34, b53);
    b53 = stwo_m31_mul(b47, b58);
    b47 = stwo_m31_mul(b48, b57);
    b59 = stwo_m31_add(b53, b47);
    b47 = stwo_m31_mul(b49, b56);
    b53 = stwo_m31_add(b59, b47);
    b47 = stwo_m31_mul(b50, b55);
    b59 = stwo_m31_add(b53, b47);
    b47 = stwo_m31_mul(b51, b54);
    b53 = stwo_m31_add(b59, b47);
    b47 = stwo_m31_mul(b52, b5);
    b5 = stwo_m31_add(b53, b47);
    b47 = stwo_m31_sub(b5, b33);
    b5 = stwo_m31_sub(b47, b46);
    b47 = stwo_m31_add(b37, b5);
    b5 = stwo_m31_mul(b48, b58);
    b58 = stwo_m31_mul(b49, b57);
    b57 = stwo_m31_add(b5, b58);
    b58 = stwo_m31_mul(b50, b56);
    b56 = stwo_m31_add(b57, b58);
    b58 = stwo_m31_mul(b51, b55);
    b55 = stwo_m31_add(b56, b58);
    b58 = stwo_m31_mul(b52, b54);
    b54 = stwo_m31_add(b55, b58);
    b58 = stwo_m31_sub(b54, b34);
    b54 = stwo_m31_sub(b58, b43);
    b58 = stwo_m31_add(b45, b54);
    b54 = stwo_m31_mul(b19, b19);
    b45 = stwo_m31_mul(b19, b20);
    b43 = stwo_m31_mul(b20, b19);
    b19 = stwo_m31_add(b45, b43);
    b43 = stwo_m31_mul(b20, b25);
    b45 = stwo_m31_mul(b21, b24);
    b34 = stwo_m31_add(b43, b45);
    b45 = stwo_m31_mul(b22, b23);
    b43 = stwo_m31_add(b34, b45);
    b45 = stwo_m31_mul(b23, b22);
    b34 = stwo_m31_add(b43, b45);
    b45 = stwo_m31_mul(b24, b21);
    b43 = stwo_m31_add(b34, b45);
    b45 = stwo_m31_mul(b25, b20);
    b34 = stwo_m31_add(b43, b45);
    b45 = stwo_m31_mul(b21, b25);
    b43 = stwo_m31_mul(b22, b24);
    b55 = stwo_m31_add(b45, b43);
    b43 = stwo_m31_mul(b23, b23);
    b45 = stwo_m31_add(b55, b43);
    b43 = stwo_m31_mul(b24, b22);
    b55 = stwo_m31_add(b45, b43);
    b43 = stwo_m31_mul(b25, b21);
    b45 = stwo_m31_add(b55, b43);
    b43 = stwo_m31_mul(b26, b26);
    b55 = stwo_m31_mul(b26, b27);
    b52 = stwo_m31_mul(b27, b26);
    b56 = stwo_m31_add(b55, b52);
    b52 = stwo_m31_mul(b27, b32);
    b55 = stwo_m31_mul(b28, b31);
    b51 = stwo_m31_add(b52, b55);
    b55 = stwo_m31_mul(b29, b30);
    b52 = stwo_m31_add(b51, b55);
    b55 = stwo_m31_mul(b30, b29);
    b51 = stwo_m31_add(b52, b55);
    b55 = stwo_m31_mul(b31, b28);
    b52 = stwo_m31_add(b51, b55);
    b55 = stwo_m31_mul(b32, b27);
    b51 = stwo_m31_add(b52, b55);
    b55 = stwo_m31_mul(b28, b32);
    b52 = stwo_m31_mul(b29, b31);
    b57 = stwo_m31_add(b55, b52);
    b52 = stwo_m31_mul(b30, b30);
    b55 = stwo_m31_add(b57, b52);
    b52 = stwo_m31_mul(b31, b29);
    b57 = stwo_m31_add(b55, b52);
    b52 = stwo_m31_mul(b32, b28);
    b55 = stwo_m31_add(b57, b52);
    b52 = stwo_m31_add(b20, b27);
    b57 = stwo_m31_add(b21, b28);
    b50 = stwo_m31_add(b22, b29);
    b5 = stwo_m31_add(b23, b30);
    b49 = stwo_m31_add(b24, b31);
    b48 = stwo_m31_add(b25, b32);
    b37 = stwo_m31_add(b20, b27);
    b46 = stwo_m31_add(b21, b28);
    b33 = stwo_m31_add(b22, b29);
    b53 = stwo_m31_add(b23, b30);
    b59 = stwo_m31_add(b24, b31);
    unsigned b61 = stwo_m31_add(b25, b32);
    unsigned b62 = stwo_m31_mul(b52, b61);
    b52 = stwo_m31_mul(b57, b59);
    unsigned b63 = stwo_m31_add(b62, b52);
    b52 = stwo_m31_mul(b50, b53);
    b62 = stwo_m31_add(b63, b52);
    b52 = stwo_m31_mul(b5, b33);
    b63 = stwo_m31_add(b62, b52);
    b52 = stwo_m31_mul(b49, b46);
    b62 = stwo_m31_add(b63, b52);
    b52 = stwo_m31_mul(b48, b37);
    b37 = stwo_m31_add(b62, b52);
    b52 = stwo_m31_sub(b37, b34);
    b37 = stwo_m31_sub(b52, b51);
    b52 = stwo_m31_add(b43, b37);
    b37 = stwo_m31_mul(b57, b61);
    b61 = stwo_m31_mul(b50, b59);
    b59 = stwo_m31_add(b37, b61);
    b61 = stwo_m31_mul(b5, b53);
    b53 = stwo_m31_add(b59, b61);
    b61 = stwo_m31_mul(b49, b33);
    b33 = stwo_m31_add(b53, b61);
    b61 = stwo_m31_mul(b48, b46);
    b46 = stwo_m31_add(b33, b61);
    b61 = stwo_m31_sub(b46, b45);
    b46 = stwo_m31_sub(b61, b55);
    b61 = stwo_m31_add(b56, b46);
    b46 = stwo_m31_add(b6, b20);
    b56 = stwo_m31_add(b7, b21);
    b55 = stwo_m31_add(b8, b22);
    b45 = stwo_m31_add(b9, b23);
    b33 = stwo_m31_add(b10, b24);
    b48 = stwo_m31_add(b11, b25);
    b53 = stwo_m31_add(b12, b26);
    b49 = stwo_m31_add(b13, b27);
    b59 = stwo_m31_add(b14, b28);
    b5 = stwo_m31_add(b15, b29);
    b37 = stwo_m31_add(b16, b30);
    b50 = stwo_m31_add(b17, b31);
    b57 = stwo_m31_add(b18, b32);
    b43 = stwo_m31_add(b6, b20);
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
    b32 = stwo_m31_mul(b46, b24);
    b18 = stwo_m31_mul(b56, b23);
    b17 = stwo_m31_add(b32, b18);
    b18 = stwo_m31_mul(b55, b22);
    b32 = stwo_m31_add(b17, b18);
    b18 = stwo_m31_mul(b45, b21);
    b17 = stwo_m31_add(b32, b18);
    b18 = stwo_m31_mul(b33, b20);
    b32 = stwo_m31_add(b17, b18);
    b18 = stwo_m31_mul(b48, b43);
    b17 = stwo_m31_add(b32, b18);
    b18 = stwo_m31_mul(b56, b24);
    b32 = stwo_m31_mul(b55, b23);
    b16 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_mul(b45, b22);
    b18 = stwo_m31_add(b16, b32);
    b32 = stwo_m31_mul(b33, b21);
    b16 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_mul(b48, b20);
    b18 = stwo_m31_add(b16, b32);
    b32 = stwo_m31_mul(b53, b25);
    b16 = stwo_m31_mul(b53, b26);
    b53 = stwo_m31_mul(b49, b25);
    b25 = stwo_m31_add(b16, b53);
    b53 = stwo_m31_mul(b49, b31);
    b16 = stwo_m31_mul(b59, b30);
    b15 = stwo_m31_add(b53, b16);
    b16 = stwo_m31_mul(b5, b29);
    b53 = stwo_m31_add(b15, b16);
    b16 = stwo_m31_mul(b37, b28);
    b15 = stwo_m31_add(b53, b16);
    b16 = stwo_m31_mul(b50, b27);
    b53 = stwo_m31_add(b15, b16);
    b16 = stwo_m31_mul(b57, b26);
    b15 = stwo_m31_add(b53, b16);
    b16 = stwo_m31_mul(b59, b31);
    b53 = stwo_m31_mul(b5, b30);
    b14 = stwo_m31_add(b16, b53);
    b53 = stwo_m31_mul(b37, b29);
    b16 = stwo_m31_add(b14, b53);
    b53 = stwo_m31_mul(b50, b28);
    b14 = stwo_m31_add(b16, b53);
    b53 = stwo_m31_mul(b57, b27);
    b16 = stwo_m31_add(b14, b53);
    b53 = stwo_m31_add(b46, b49);
    b49 = stwo_m31_add(b56, b59);
    b59 = stwo_m31_add(b55, b5);
    b5 = stwo_m31_add(b45, b37);
    b37 = stwo_m31_add(b33, b50);
    b50 = stwo_m31_add(b48, b57);
    b57 = stwo_m31_add(b43, b26);
    b26 = stwo_m31_add(b20, b27);
    b27 = stwo_m31_add(b21, b28);
    b28 = stwo_m31_add(b22, b29);
    b29 = stwo_m31_add(b23, b30);
    b30 = stwo_m31_add(b24, b31);
    b31 = stwo_m31_mul(b53, b30);
    b53 = stwo_m31_mul(b49, b29);
    b24 = stwo_m31_add(b31, b53);
    b53 = stwo_m31_mul(b59, b28);
    b31 = stwo_m31_add(b24, b53);
    b53 = stwo_m31_mul(b5, b27);
    b24 = stwo_m31_add(b31, b53);
    b53 = stwo_m31_mul(b37, b26);
    b31 = stwo_m31_add(b24, b53);
    b53 = stwo_m31_mul(b50, b57);
    b57 = stwo_m31_add(b31, b53);
    b53 = stwo_m31_sub(b57, b17);
    b57 = stwo_m31_sub(b53, b15);
    b53 = stwo_m31_add(b32, b57);
    b57 = stwo_m31_mul(b49, b30);
    b30 = stwo_m31_mul(b59, b29);
    b29 = stwo_m31_add(b57, b30);
    b30 = stwo_m31_mul(b5, b28);
    b28 = stwo_m31_add(b29, b30);
    b30 = stwo_m31_mul(b37, b27);
    b27 = stwo_m31_add(b28, b30);
    b30 = stwo_m31_mul(b50, b26);
    b26 = stwo_m31_add(b27, b30);
    b30 = stwo_m31_sub(b26, b18);
    b26 = stwo_m31_sub(b30, b16);
    b30 = stwo_m31_add(b25, b26);
    b26 = stwo_m31_sub(b53, b47);
    b53 = stwo_m31_sub(b26, b52);
    b26 = stwo_m31_add(b54, b53);
    b53 = stwo_m31_sub(b30, b58);
    b30 = stwo_m31_sub(b53, b61);
    b53 = stwo_m31_add(b19, b30);
    b30 = stwo_m31_sub(b42, b0);
    b42 = stwo_m31_sub(b35, b1);
    b35 = stwo_m31_sub(b36, b2);
    b36 = stwo_m31_sub(b60, b3);
    b60 = stwo_m31_sub(b44, b4);
    b44 = 2u;
    b4 = stwo_m31_mul(b44, b30);
    b44 = stwo_m31_add(b4, b35);
    b4 = 32u;
    b35 = stwo_m31_mul(b4, b36);
    b4 = stwo_m31_add(b44, b35);
    b35 = 4u;
    b44 = stwo_m31_mul(b35, b26);
    b35 = stwo_m31_sub(b4, b44);
    b44 = 2u;
    b4 = stwo_m31_mul(b44, b42);
    b44 = stwo_m31_add(b4, b36);
    b4 = 32u;
    b36 = stwo_m31_mul(b4, b60);
    b4 = stwo_m31_add(b44, b36);
    b36 = 4u;
    b44 = stwo_m31_mul(b36, b53);
    b36 = stwo_m31_sub(b4, b44);
    b44 = 512u;
    b4 = stwo_m31_mul(b39, b44);
    b44 = stwo_m31_add(b35, b38);
    b35 = stwo_m31_sub(b4, b44);
    b44 = 512u;
    b4 = stwo_m31_mul(b40, b44);
    b44 = stwo_m31_add(b36, b39);
    b36 = stwo_m31_sub(b4, b44);
    StwoCairoQm31 e0 = { b35, b41, b41, b41 };
    StwoCairoQm31 e1 = { b36, b41, b41, b41 };
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
