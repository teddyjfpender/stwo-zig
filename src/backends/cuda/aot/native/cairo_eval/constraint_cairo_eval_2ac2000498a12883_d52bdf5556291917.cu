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
stwo_cairo_cuda_eval_v1_874b800f11ada02a(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 455u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 456u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 457u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 458u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 459u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 460u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 461u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 462u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 463u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 464u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 465u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 466u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 467u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 468u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 469u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 470u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 471u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 472u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 473u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 474u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 475u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 476u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 477u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 478u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 479u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 480u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 481u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 482u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 525u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 526u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 527u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 531u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 539u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 560u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 561u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 562u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 563u, row, 0);
    unsigned b41 = 0u;
    unsigned b42 = stwo_m31_add(b0, b0);
    b0 = stwo_m31_add(b42, b32);
    b42 = stwo_m31_add(b1, b1);
    b1 = stwo_m31_add(b42, b33);
    b42 = stwo_m31_add(b2, b2);
    b2 = stwo_m31_add(b42, b34);
    b42 = stwo_m31_add(b3, b3);
    b3 = stwo_m31_add(b42, b35);
    b42 = stwo_m31_mul(b4, b4);
    b35 = stwo_m31_mul(b4, b5);
    b34 = stwo_m31_mul(b5, b4);
    b33 = stwo_m31_add(b35, b34);
    b34 = stwo_m31_mul(b4, b6);
    b35 = stwo_m31_mul(b5, b5);
    b32 = stwo_m31_add(b34, b35);
    b35 = stwo_m31_mul(b6, b4);
    b34 = stwo_m31_add(b32, b35);
    b35 = stwo_m31_mul(b4, b10);
    b32 = stwo_m31_mul(b5, b9);
    unsigned b43 = stwo_m31_add(b35, b32);
    b32 = stwo_m31_mul(b6, b8);
    b35 = stwo_m31_add(b43, b32);
    b32 = stwo_m31_mul(b7, b7);
    b43 = stwo_m31_add(b35, b32);
    b32 = stwo_m31_mul(b8, b6);
    b35 = stwo_m31_add(b43, b32);
    b32 = stwo_m31_mul(b9, b5);
    b43 = stwo_m31_add(b35, b32);
    b32 = stwo_m31_mul(b10, b4);
    b35 = stwo_m31_add(b43, b32);
    b32 = stwo_m31_mul(b5, b10);
    b43 = stwo_m31_mul(b6, b9);
    unsigned b44 = stwo_m31_add(b32, b43);
    b43 = stwo_m31_mul(b7, b8);
    b32 = stwo_m31_add(b44, b43);
    b43 = stwo_m31_mul(b8, b7);
    b44 = stwo_m31_add(b32, b43);
    b43 = stwo_m31_mul(b9, b6);
    b32 = stwo_m31_add(b44, b43);
    b43 = stwo_m31_mul(b10, b5);
    b44 = stwo_m31_add(b32, b43);
    b43 = stwo_m31_mul(b6, b10);
    b32 = stwo_m31_mul(b7, b9);
    unsigned b45 = stwo_m31_add(b43, b32);
    b32 = stwo_m31_mul(b8, b8);
    b43 = stwo_m31_add(b45, b32);
    b32 = stwo_m31_mul(b9, b7);
    b45 = stwo_m31_add(b43, b32);
    b32 = stwo_m31_mul(b10, b6);
    b43 = stwo_m31_add(b45, b32);
    b32 = stwo_m31_mul(b7, b10);
    b45 = stwo_m31_mul(b8, b9);
    unsigned b46 = stwo_m31_add(b32, b45);
    b45 = stwo_m31_mul(b9, b8);
    b32 = stwo_m31_add(b46, b45);
    b45 = stwo_m31_mul(b10, b7);
    b46 = stwo_m31_add(b32, b45);
    b45 = stwo_m31_mul(b11, b11);
    b32 = stwo_m31_mul(b11, b12);
    unsigned b47 = stwo_m31_mul(b12, b11);
    unsigned b48 = stwo_m31_add(b32, b47);
    b47 = stwo_m31_mul(b11, b13);
    b32 = stwo_m31_mul(b12, b12);
    unsigned b49 = stwo_m31_add(b47, b32);
    b32 = stwo_m31_mul(b13, b11);
    b47 = stwo_m31_add(b49, b32);
    b32 = stwo_m31_mul(b11, b17);
    b49 = stwo_m31_mul(b12, b16);
    unsigned b50 = stwo_m31_add(b32, b49);
    b49 = stwo_m31_mul(b13, b15);
    b32 = stwo_m31_add(b50, b49);
    b49 = stwo_m31_mul(b14, b14);
    b50 = stwo_m31_add(b32, b49);
    b49 = stwo_m31_mul(b15, b13);
    b32 = stwo_m31_add(b50, b49);
    b49 = stwo_m31_mul(b16, b12);
    b50 = stwo_m31_add(b32, b49);
    b49 = stwo_m31_mul(b17, b11);
    b11 = stwo_m31_add(b50, b49);
    b49 = stwo_m31_mul(b12, b17);
    b50 = stwo_m31_mul(b13, b16);
    b32 = stwo_m31_add(b49, b50);
    b50 = stwo_m31_mul(b14, b15);
    b49 = stwo_m31_add(b32, b50);
    b50 = stwo_m31_mul(b15, b14);
    b32 = stwo_m31_add(b49, b50);
    b50 = stwo_m31_mul(b16, b13);
    b49 = stwo_m31_add(b32, b50);
    b50 = stwo_m31_mul(b17, b12);
    b32 = stwo_m31_add(b49, b50);
    b50 = stwo_m31_mul(b13, b17);
    b49 = stwo_m31_mul(b14, b16);
    unsigned b51 = stwo_m31_add(b50, b49);
    b49 = stwo_m31_mul(b15, b15);
    b50 = stwo_m31_add(b51, b49);
    b49 = stwo_m31_mul(b16, b14);
    b51 = stwo_m31_add(b50, b49);
    b49 = stwo_m31_mul(b17, b13);
    b50 = stwo_m31_add(b51, b49);
    b49 = stwo_m31_mul(b14, b17);
    b51 = stwo_m31_mul(b15, b16);
    unsigned b52 = stwo_m31_add(b49, b51);
    b51 = stwo_m31_mul(b16, b15);
    b49 = stwo_m31_add(b52, b51);
    b51 = stwo_m31_mul(b17, b14);
    b52 = stwo_m31_add(b49, b51);
    b51 = stwo_m31_add(b5, b12);
    b49 = stwo_m31_add(b6, b13);
    unsigned b53 = stwo_m31_add(b7, b14);
    unsigned b54 = stwo_m31_add(b8, b15);
    unsigned b55 = stwo_m31_add(b9, b16);
    unsigned b56 = stwo_m31_add(b10, b17);
    unsigned b57 = stwo_m31_add(b5, b12);
    b12 = stwo_m31_add(b6, b13);
    b13 = stwo_m31_add(b7, b14);
    b14 = stwo_m31_add(b8, b15);
    b15 = stwo_m31_add(b9, b16);
    b16 = stwo_m31_add(b10, b17);
    b17 = stwo_m31_mul(b51, b16);
    b51 = stwo_m31_mul(b49, b15);
    unsigned b58 = stwo_m31_add(b17, b51);
    b51 = stwo_m31_mul(b53, b14);
    b17 = stwo_m31_add(b58, b51);
    b51 = stwo_m31_mul(b54, b13);
    b58 = stwo_m31_add(b17, b51);
    b51 = stwo_m31_mul(b55, b12);
    b17 = stwo_m31_add(b58, b51);
    b51 = stwo_m31_mul(b56, b57);
    b57 = stwo_m31_add(b17, b51);
    b51 = stwo_m31_sub(b57, b44);
    b57 = stwo_m31_sub(b51, b32);
    b51 = stwo_m31_add(b45, b57);
    b57 = stwo_m31_mul(b49, b16);
    b49 = stwo_m31_mul(b53, b15);
    b45 = stwo_m31_add(b57, b49);
    b49 = stwo_m31_mul(b54, b14);
    b57 = stwo_m31_add(b45, b49);
    b49 = stwo_m31_mul(b55, b13);
    b45 = stwo_m31_add(b57, b49);
    b49 = stwo_m31_mul(b56, b12);
    b12 = stwo_m31_add(b45, b49);
    b49 = stwo_m31_sub(b12, b43);
    b12 = stwo_m31_sub(b49, b50);
    b49 = stwo_m31_add(b48, b12);
    b12 = stwo_m31_mul(b53, b16);
    b16 = stwo_m31_mul(b54, b15);
    b15 = stwo_m31_add(b12, b16);
    b16 = stwo_m31_mul(b55, b14);
    b14 = stwo_m31_add(b15, b16);
    b16 = stwo_m31_mul(b56, b13);
    b13 = stwo_m31_add(b14, b16);
    b16 = stwo_m31_sub(b13, b46);
    b13 = stwo_m31_sub(b16, b52);
    b16 = stwo_m31_add(b47, b13);
    b13 = stwo_m31_mul(b18, b18);
    b47 = stwo_m31_mul(b18, b19);
    b52 = stwo_m31_mul(b19, b18);
    b46 = stwo_m31_add(b47, b52);
    b52 = stwo_m31_mul(b18, b20);
    b47 = stwo_m31_mul(b19, b19);
    b14 = stwo_m31_add(b52, b47);
    b47 = stwo_m31_mul(b20, b18);
    b52 = stwo_m31_add(b14, b47);
    b47 = stwo_m31_mul(b18, b24);
    b14 = stwo_m31_mul(b19, b23);
    b56 = stwo_m31_add(b47, b14);
    b14 = stwo_m31_mul(b20, b22);
    b47 = stwo_m31_add(b56, b14);
    b14 = stwo_m31_mul(b21, b21);
    b56 = stwo_m31_add(b47, b14);
    b14 = stwo_m31_mul(b22, b20);
    b47 = stwo_m31_add(b56, b14);
    b14 = stwo_m31_mul(b23, b19);
    b56 = stwo_m31_add(b47, b14);
    b14 = stwo_m31_mul(b24, b18);
    b47 = stwo_m31_add(b56, b14);
    b14 = stwo_m31_mul(b19, b24);
    b56 = stwo_m31_mul(b20, b23);
    b15 = stwo_m31_add(b14, b56);
    b56 = stwo_m31_mul(b21, b22);
    b14 = stwo_m31_add(b15, b56);
    b56 = stwo_m31_mul(b22, b21);
    b15 = stwo_m31_add(b14, b56);
    b56 = stwo_m31_mul(b23, b20);
    b14 = stwo_m31_add(b15, b56);
    b56 = stwo_m31_mul(b24, b19);
    b15 = stwo_m31_add(b14, b56);
    b56 = stwo_m31_mul(b20, b24);
    b14 = stwo_m31_mul(b21, b23);
    b55 = stwo_m31_add(b56, b14);
    b14 = stwo_m31_mul(b22, b22);
    b56 = stwo_m31_add(b55, b14);
    b14 = stwo_m31_mul(b23, b21);
    b55 = stwo_m31_add(b56, b14);
    b14 = stwo_m31_mul(b24, b20);
    b56 = stwo_m31_add(b55, b14);
    b14 = stwo_m31_mul(b21, b24);
    b55 = stwo_m31_mul(b22, b23);
    b12 = stwo_m31_add(b14, b55);
    b55 = stwo_m31_mul(b23, b22);
    b14 = stwo_m31_add(b12, b55);
    b55 = stwo_m31_mul(b24, b21);
    b12 = stwo_m31_add(b14, b55);
    b55 = stwo_m31_mul(b25, b25);
    b14 = stwo_m31_mul(b25, b26);
    b54 = stwo_m31_mul(b26, b25);
    b53 = stwo_m31_add(b14, b54);
    b54 = stwo_m31_mul(b25, b27);
    b14 = stwo_m31_mul(b26, b26);
    b48 = stwo_m31_add(b54, b14);
    b14 = stwo_m31_mul(b27, b25);
    b25 = stwo_m31_add(b48, b14);
    b14 = stwo_m31_mul(b26, b31);
    b48 = stwo_m31_mul(b27, b30);
    b54 = stwo_m31_add(b14, b48);
    b48 = stwo_m31_mul(b28, b29);
    b14 = stwo_m31_add(b54, b48);
    b48 = stwo_m31_mul(b29, b28);
    b54 = stwo_m31_add(b14, b48);
    b48 = stwo_m31_mul(b30, b27);
    b14 = stwo_m31_add(b54, b48);
    b48 = stwo_m31_mul(b31, b26);
    b54 = stwo_m31_add(b14, b48);
    b48 = stwo_m31_mul(b27, b31);
    b14 = stwo_m31_mul(b28, b30);
    b50 = stwo_m31_add(b48, b14);
    b14 = stwo_m31_mul(b29, b29);
    b48 = stwo_m31_add(b50, b14);
    b14 = stwo_m31_mul(b30, b28);
    b50 = stwo_m31_add(b48, b14);
    b14 = stwo_m31_mul(b31, b27);
    b48 = stwo_m31_add(b50, b14);
    b14 = stwo_m31_mul(b28, b31);
    b50 = stwo_m31_mul(b29, b30);
    b43 = stwo_m31_add(b14, b50);
    b50 = stwo_m31_mul(b30, b29);
    b14 = stwo_m31_add(b43, b50);
    b50 = stwo_m31_mul(b31, b28);
    b43 = stwo_m31_add(b14, b50);
    b50 = stwo_m31_add(b19, b26);
    b14 = stwo_m31_add(b20, b27);
    b45 = stwo_m31_add(b21, b28);
    b57 = stwo_m31_add(b22, b29);
    b32 = stwo_m31_add(b23, b30);
    b44 = stwo_m31_add(b24, b31);
    b17 = stwo_m31_add(b19, b26);
    b26 = stwo_m31_add(b20, b27);
    b27 = stwo_m31_add(b21, b28);
    b28 = stwo_m31_add(b22, b29);
    b29 = stwo_m31_add(b23, b30);
    b30 = stwo_m31_add(b24, b31);
    b31 = stwo_m31_mul(b50, b30);
    b50 = stwo_m31_mul(b14, b29);
    b58 = stwo_m31_add(b31, b50);
    b50 = stwo_m31_mul(b45, b28);
    b31 = stwo_m31_add(b58, b50);
    b50 = stwo_m31_mul(b57, b27);
    b58 = stwo_m31_add(b31, b50);
    b50 = stwo_m31_mul(b32, b26);
    b31 = stwo_m31_add(b58, b50);
    b50 = stwo_m31_mul(b44, b17);
    b17 = stwo_m31_add(b31, b50);
    b50 = stwo_m31_sub(b17, b15);
    b17 = stwo_m31_sub(b50, b54);
    b50 = stwo_m31_add(b55, b17);
    b17 = stwo_m31_mul(b14, b30);
    b14 = stwo_m31_mul(b45, b29);
    b55 = stwo_m31_add(b17, b14);
    b14 = stwo_m31_mul(b57, b28);
    b17 = stwo_m31_add(b55, b14);
    b14 = stwo_m31_mul(b32, b27);
    b55 = stwo_m31_add(b17, b14);
    b14 = stwo_m31_mul(b44, b26);
    b26 = stwo_m31_add(b55, b14);
    b14 = stwo_m31_sub(b26, b56);
    b26 = stwo_m31_sub(b14, b48);
    b14 = stwo_m31_add(b53, b26);
    b26 = stwo_m31_mul(b45, b30);
    b30 = stwo_m31_mul(b57, b29);
    b29 = stwo_m31_add(b26, b30);
    b30 = stwo_m31_mul(b32, b28);
    b28 = stwo_m31_add(b29, b30);
    b30 = stwo_m31_mul(b44, b27);
    b27 = stwo_m31_add(b28, b30);
    b30 = stwo_m31_sub(b27, b12);
    b27 = stwo_m31_sub(b30, b43);
    b30 = stwo_m31_add(b25, b27);
    b27 = stwo_m31_add(b4, b18);
    b25 = stwo_m31_add(b5, b19);
    b12 = stwo_m31_add(b6, b20);
    b28 = stwo_m31_add(b7, b21);
    b44 = stwo_m31_add(b8, b22);
    b29 = stwo_m31_add(b9, b23);
    b32 = stwo_m31_add(b10, b24);
    b26 = stwo_m31_add(b4, b18);
    b18 = stwo_m31_add(b5, b19);
    b19 = stwo_m31_add(b6, b20);
    b20 = stwo_m31_add(b7, b21);
    b21 = stwo_m31_add(b8, b22);
    b22 = stwo_m31_add(b9, b23);
    b23 = stwo_m31_add(b10, b24);
    b24 = stwo_m31_mul(b27, b26);
    b10 = stwo_m31_mul(b27, b18);
    b9 = stwo_m31_mul(b25, b26);
    b8 = stwo_m31_add(b10, b9);
    b9 = stwo_m31_mul(b27, b19);
    b10 = stwo_m31_mul(b25, b18);
    b7 = stwo_m31_add(b9, b10);
    b10 = stwo_m31_mul(b12, b26);
    b9 = stwo_m31_add(b7, b10);
    b10 = stwo_m31_mul(b27, b23);
    b23 = stwo_m31_mul(b25, b22);
    b22 = stwo_m31_add(b10, b23);
    b23 = stwo_m31_mul(b12, b21);
    b21 = stwo_m31_add(b22, b23);
    b23 = stwo_m31_mul(b28, b20);
    b20 = stwo_m31_add(b21, b23);
    b23 = stwo_m31_mul(b44, b19);
    b19 = stwo_m31_add(b20, b23);
    b23 = stwo_m31_mul(b29, b18);
    b18 = stwo_m31_add(b19, b23);
    b23 = stwo_m31_mul(b32, b26);
    b26 = stwo_m31_add(b18, b23);
    b23 = stwo_m31_sub(b24, b42);
    b24 = stwo_m31_sub(b23, b13);
    b23 = stwo_m31_add(b51, b24);
    b24 = stwo_m31_sub(b8, b33);
    b8 = stwo_m31_sub(b24, b46);
    b24 = stwo_m31_add(b49, b8);
    b8 = stwo_m31_sub(b9, b34);
    b9 = stwo_m31_sub(b8, b52);
    b8 = stwo_m31_add(b16, b9);
    b9 = stwo_m31_sub(b26, b35);
    b26 = stwo_m31_sub(b9, b47);
    b9 = stwo_m31_add(b11, b26);
    b26 = stwo_m31_sub(b23, b0);
    b23 = stwo_m31_sub(b24, b1);
    b24 = stwo_m31_sub(b8, b2);
    b8 = stwo_m31_sub(b9, b3);
    b9 = 2u;
    b3 = stwo_m31_mul(b9, b26);
    b9 = stwo_m31_add(b3, b8);
    b3 = 4u;
    b8 = stwo_m31_mul(b3, b50);
    b3 = stwo_m31_sub(b9, b8);
    b8 = 64u;
    b9 = stwo_m31_mul(b8, b54);
    b8 = stwo_m31_add(b3, b9);
    b9 = 2u;
    b3 = stwo_m31_mul(b9, b23);
    b9 = 4u;
    b23 = stwo_m31_mul(b9, b14);
    b9 = stwo_m31_sub(b3, b23);
    b23 = 2u;
    b3 = stwo_m31_mul(b23, b54);
    b23 = stwo_m31_add(b9, b3);
    b3 = 64u;
    b9 = stwo_m31_mul(b3, b48);
    b3 = stwo_m31_add(b23, b9);
    b9 = 2u;
    b23 = stwo_m31_mul(b9, b24);
    b9 = 4u;
    b24 = stwo_m31_mul(b9, b30);
    b9 = stwo_m31_sub(b23, b24);
    b24 = 2u;
    b23 = stwo_m31_mul(b24, b48);
    b24 = stwo_m31_add(b9, b23);
    b23 = 64u;
    b9 = stwo_m31_mul(b23, b43);
    b23 = stwo_m31_add(b24, b9);
    b9 = 512u;
    b24 = stwo_m31_mul(b38, b9);
    b9 = 136u;
    b43 = stwo_m31_mul(b9, b36);
    b9 = stwo_m31_sub(b8, b43);
    b43 = stwo_m31_add(b9, b37);
    b9 = stwo_m31_sub(b24, b43);
    b43 = 512u;
    b24 = stwo_m31_mul(b39, b43);
    b43 = stwo_m31_add(b3, b38);
    b3 = stwo_m31_sub(b24, b43);
    b43 = 512u;
    b24 = stwo_m31_mul(b40, b43);
    b43 = stwo_m31_add(b23, b39);
    b23 = stwo_m31_sub(b24, b43);
    StwoCairoQm31 e0 = { b9, b41, b41, b41 };
    StwoCairoQm31 e1 = { b3, b41, b41, b41 };
    StwoCairoQm31 e2 = { b23, b41, b41, b41 };
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
