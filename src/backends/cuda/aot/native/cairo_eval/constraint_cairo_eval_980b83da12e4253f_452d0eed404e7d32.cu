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
stwo_cairo_cuda_eval_v1_8d12d7d910dfb9c6(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
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
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 519u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 520u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 521u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 525u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 526u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 527u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 528u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 554u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 555u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 556u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 557u, row, 0);
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
    b47 = stwo_m31_mul(b7, b7);
    b41 = stwo_m31_mul(b7, b8);
    b40 = stwo_m31_mul(b8, b7);
    b39 = stwo_m31_add(b41, b40);
    b40 = stwo_m31_mul(b7, b9);
    b41 = stwo_m31_mul(b8, b8);
    b38 = stwo_m31_add(b40, b41);
    b41 = stwo_m31_mul(b9, b7);
    b40 = stwo_m31_add(b38, b41);
    b41 = stwo_m31_mul(b7, b10);
    b38 = stwo_m31_mul(b8, b9);
    b37 = stwo_m31_add(b41, b38);
    b38 = stwo_m31_mul(b9, b8);
    b41 = stwo_m31_add(b37, b38);
    b38 = stwo_m31_mul(b10, b7);
    b37 = stwo_m31_add(b41, b38);
    b38 = stwo_m31_mul(b8, b13);
    b41 = stwo_m31_mul(b9, b12);
    b36 = stwo_m31_add(b38, b41);
    b41 = stwo_m31_mul(b10, b11);
    b38 = stwo_m31_add(b36, b41);
    b41 = stwo_m31_mul(b11, b10);
    b36 = stwo_m31_add(b38, b41);
    b41 = stwo_m31_mul(b12, b9);
    b38 = stwo_m31_add(b36, b41);
    b41 = stwo_m31_mul(b13, b8);
    b36 = stwo_m31_add(b38, b41);
    b41 = stwo_m31_mul(b9, b13);
    b38 = stwo_m31_mul(b10, b12);
    b35 = stwo_m31_add(b41, b38);
    b38 = stwo_m31_mul(b11, b11);
    b41 = stwo_m31_add(b35, b38);
    b38 = stwo_m31_mul(b12, b10);
    b35 = stwo_m31_add(b41, b38);
    b38 = stwo_m31_mul(b13, b9);
    b41 = stwo_m31_add(b35, b38);
    b38 = stwo_m31_mul(b10, b13);
    b35 = stwo_m31_mul(b11, b12);
    unsigned b48 = stwo_m31_add(b38, b35);
    b35 = stwo_m31_mul(b12, b11);
    b38 = stwo_m31_add(b48, b35);
    b35 = stwo_m31_mul(b13, b10);
    b48 = stwo_m31_add(b38, b35);
    b35 = stwo_m31_mul(b11, b13);
    b38 = stwo_m31_mul(b12, b12);
    unsigned b49 = stwo_m31_add(b35, b38);
    b38 = stwo_m31_mul(b13, b11);
    b35 = stwo_m31_add(b49, b38);
    b38 = stwo_m31_mul(b14, b14);
    b49 = stwo_m31_mul(b14, b15);
    unsigned b50 = stwo_m31_mul(b15, b14);
    unsigned b51 = stwo_m31_add(b49, b50);
    b50 = stwo_m31_mul(b14, b16);
    b49 = stwo_m31_mul(b15, b15);
    unsigned b52 = stwo_m31_add(b50, b49);
    b49 = stwo_m31_mul(b16, b14);
    b50 = stwo_m31_add(b52, b49);
    b49 = stwo_m31_mul(b14, b17);
    b52 = stwo_m31_mul(b15, b16);
    unsigned b53 = stwo_m31_add(b49, b52);
    b52 = stwo_m31_mul(b16, b15);
    b49 = stwo_m31_add(b53, b52);
    b52 = stwo_m31_mul(b17, b14);
    b53 = stwo_m31_add(b49, b52);
    b52 = stwo_m31_mul(b15, b20);
    b49 = stwo_m31_mul(b16, b19);
    unsigned b54 = stwo_m31_add(b52, b49);
    b49 = stwo_m31_mul(b17, b18);
    b52 = stwo_m31_add(b54, b49);
    b49 = stwo_m31_mul(b18, b17);
    b54 = stwo_m31_add(b52, b49);
    b49 = stwo_m31_mul(b19, b16);
    b52 = stwo_m31_add(b54, b49);
    b49 = stwo_m31_mul(b20, b15);
    b54 = stwo_m31_add(b52, b49);
    b49 = stwo_m31_mul(b16, b20);
    b52 = stwo_m31_mul(b17, b19);
    unsigned b55 = stwo_m31_add(b49, b52);
    b52 = stwo_m31_mul(b18, b18);
    b49 = stwo_m31_add(b55, b52);
    b52 = stwo_m31_mul(b19, b17);
    b55 = stwo_m31_add(b49, b52);
    b52 = stwo_m31_mul(b20, b16);
    b49 = stwo_m31_add(b55, b52);
    b52 = stwo_m31_mul(b17, b20);
    b55 = stwo_m31_mul(b18, b19);
    unsigned b56 = stwo_m31_add(b52, b55);
    b55 = stwo_m31_mul(b19, b18);
    b52 = stwo_m31_add(b56, b55);
    b55 = stwo_m31_mul(b20, b17);
    b56 = stwo_m31_add(b52, b55);
    b55 = stwo_m31_mul(b18, b20);
    b52 = stwo_m31_mul(b19, b19);
    unsigned b57 = stwo_m31_add(b55, b52);
    b52 = stwo_m31_mul(b20, b18);
    b55 = stwo_m31_add(b57, b52);
    b52 = stwo_m31_add(b7, b14);
    b57 = stwo_m31_add(b8, b15);
    unsigned b58 = stwo_m31_add(b9, b16);
    unsigned b59 = stwo_m31_add(b10, b17);
    unsigned b60 = stwo_m31_add(b11, b18);
    unsigned b61 = stwo_m31_add(b12, b19);
    unsigned b62 = stwo_m31_add(b13, b20);
    unsigned b63 = stwo_m31_add(b7, b14);
    b14 = stwo_m31_add(b8, b15);
    b15 = stwo_m31_add(b9, b16);
    unsigned b64 = stwo_m31_add(b10, b17);
    unsigned b65 = stwo_m31_add(b11, b18);
    b11 = stwo_m31_add(b12, b19);
    b12 = stwo_m31_add(b13, b20);
    b13 = stwo_m31_mul(b52, b14);
    unsigned b66 = stwo_m31_mul(b57, b63);
    unsigned b67 = stwo_m31_add(b13, b66);
    b66 = stwo_m31_sub(b67, b39);
    b67 = stwo_m31_sub(b66, b51);
    b66 = stwo_m31_add(b41, b67);
    b67 = stwo_m31_mul(b52, b15);
    b13 = stwo_m31_mul(b57, b14);
    unsigned b68 = stwo_m31_add(b67, b13);
    b13 = stwo_m31_mul(b58, b63);
    b67 = stwo_m31_add(b68, b13);
    b13 = stwo_m31_sub(b67, b40);
    b67 = stwo_m31_sub(b13, b50);
    b13 = stwo_m31_add(b48, b67);
    b67 = stwo_m31_mul(b52, b64);
    b52 = stwo_m31_mul(b57, b15);
    b68 = stwo_m31_add(b67, b52);
    b52 = stwo_m31_mul(b58, b14);
    b67 = stwo_m31_add(b68, b52);
    b52 = stwo_m31_mul(b59, b63);
    b63 = stwo_m31_add(b67, b52);
    b52 = stwo_m31_sub(b63, b37);
    b63 = stwo_m31_sub(b52, b53);
    b52 = stwo_m31_add(b35, b63);
    b63 = stwo_m31_mul(b57, b12);
    b57 = stwo_m31_mul(b58, b11);
    b67 = stwo_m31_add(b63, b57);
    b57 = stwo_m31_mul(b59, b65);
    b63 = stwo_m31_add(b67, b57);
    b57 = stwo_m31_mul(b60, b64);
    b67 = stwo_m31_add(b63, b57);
    b57 = stwo_m31_mul(b61, b15);
    b63 = stwo_m31_add(b67, b57);
    b57 = stwo_m31_mul(b62, b14);
    b14 = stwo_m31_add(b63, b57);
    b57 = stwo_m31_sub(b14, b36);
    b14 = stwo_m31_sub(b57, b54);
    b57 = stwo_m31_add(b38, b14);
    b14 = stwo_m31_mul(b58, b12);
    b58 = stwo_m31_mul(b59, b11);
    b38 = stwo_m31_add(b14, b58);
    b58 = stwo_m31_mul(b60, b65);
    b14 = stwo_m31_add(b38, b58);
    b58 = stwo_m31_mul(b61, b64);
    b38 = stwo_m31_add(b14, b58);
    b58 = stwo_m31_mul(b62, b15);
    b15 = stwo_m31_add(b38, b58);
    b58 = stwo_m31_sub(b15, b41);
    b15 = stwo_m31_sub(b58, b49);
    b58 = stwo_m31_add(b51, b15);
    b15 = stwo_m31_mul(b59, b12);
    b59 = stwo_m31_mul(b60, b11);
    b51 = stwo_m31_add(b15, b59);
    b59 = stwo_m31_mul(b61, b65);
    b15 = stwo_m31_add(b51, b59);
    b59 = stwo_m31_mul(b62, b64);
    b64 = stwo_m31_add(b15, b59);
    b59 = stwo_m31_sub(b64, b48);
    b64 = stwo_m31_sub(b59, b56);
    b59 = stwo_m31_add(b50, b64);
    b64 = stwo_m31_mul(b60, b12);
    b12 = stwo_m31_mul(b61, b11);
    b11 = stwo_m31_add(b64, b12);
    b12 = stwo_m31_mul(b62, b65);
    b65 = stwo_m31_add(b11, b12);
    b12 = stwo_m31_sub(b65, b35);
    b65 = stwo_m31_sub(b12, b55);
    b12 = stwo_m31_add(b53, b65);
    b65 = stwo_m31_mul(b21, b21);
    b53 = stwo_m31_mul(b21, b22);
    b35 = stwo_m31_mul(b22, b21);
    b11 = stwo_m31_add(b53, b35);
    b35 = stwo_m31_mul(b21, b23);
    b53 = stwo_m31_mul(b22, b22);
    b62 = stwo_m31_add(b35, b53);
    b53 = stwo_m31_mul(b23, b21);
    b35 = stwo_m31_add(b62, b53);
    b53 = stwo_m31_mul(b21, b24);
    b62 = stwo_m31_mul(b22, b23);
    b64 = stwo_m31_add(b53, b62);
    b62 = stwo_m31_mul(b23, b22);
    b53 = stwo_m31_add(b64, b62);
    b62 = stwo_m31_mul(b24, b21);
    b64 = stwo_m31_add(b53, b62);
    b62 = stwo_m31_mul(b23, b27);
    b53 = stwo_m31_mul(b24, b26);
    b61 = stwo_m31_add(b62, b53);
    b53 = stwo_m31_mul(b25, b25);
    b62 = stwo_m31_add(b61, b53);
    b53 = stwo_m31_mul(b26, b24);
    b61 = stwo_m31_add(b62, b53);
    b53 = stwo_m31_mul(b27, b23);
    b62 = stwo_m31_add(b61, b53);
    b53 = stwo_m31_mul(b24, b27);
    b61 = stwo_m31_mul(b25, b26);
    b60 = stwo_m31_add(b53, b61);
    b61 = stwo_m31_mul(b26, b25);
    b53 = stwo_m31_add(b60, b61);
    b61 = stwo_m31_mul(b27, b24);
    b60 = stwo_m31_add(b53, b61);
    b61 = stwo_m31_mul(b25, b27);
    b53 = stwo_m31_mul(b26, b26);
    b26 = stwo_m31_add(b61, b53);
    b53 = stwo_m31_mul(b27, b25);
    b27 = stwo_m31_add(b26, b53);
    b53 = stwo_m31_mul(b28, b29);
    b26 = stwo_m31_mul(b29, b28);
    b25 = stwo_m31_add(b53, b26);
    b26 = stwo_m31_mul(b28, b30);
    b53 = stwo_m31_mul(b29, b29);
    b61 = stwo_m31_add(b26, b53);
    b53 = stwo_m31_mul(b30, b28);
    b26 = stwo_m31_add(b61, b53);
    b53 = stwo_m31_mul(b28, b31);
    b61 = stwo_m31_mul(b29, b30);
    b50 = stwo_m31_add(b53, b61);
    b61 = stwo_m31_mul(b30, b29);
    b53 = stwo_m31_add(b50, b61);
    b61 = stwo_m31_mul(b31, b28);
    b50 = stwo_m31_add(b53, b61);
    b61 = stwo_m31_mul(b30, b34);
    b53 = stwo_m31_mul(b31, b33);
    b48 = stwo_m31_add(b61, b53);
    b53 = stwo_m31_mul(b32, b32);
    b61 = stwo_m31_add(b48, b53);
    b53 = stwo_m31_mul(b33, b31);
    b48 = stwo_m31_add(b61, b53);
    b53 = stwo_m31_mul(b34, b30);
    b61 = stwo_m31_add(b48, b53);
    b53 = stwo_m31_mul(b31, b34);
    b48 = stwo_m31_mul(b32, b33);
    b15 = stwo_m31_add(b53, b48);
    b48 = stwo_m31_mul(b33, b32);
    b53 = stwo_m31_add(b15, b48);
    b48 = stwo_m31_mul(b34, b31);
    b15 = stwo_m31_add(b53, b48);
    b48 = stwo_m31_mul(b32, b34);
    b53 = stwo_m31_mul(b33, b33);
    b51 = stwo_m31_add(b48, b53);
    b53 = stwo_m31_mul(b34, b32);
    b48 = stwo_m31_add(b51, b53);
    b53 = stwo_m31_add(b21, b28);
    b51 = stwo_m31_add(b22, b29);
    b41 = stwo_m31_add(b23, b30);
    b38 = stwo_m31_add(b24, b31);
    b14 = stwo_m31_add(b21, b28);
    b28 = stwo_m31_add(b22, b29);
    b29 = stwo_m31_add(b23, b30);
    b54 = stwo_m31_add(b24, b31);
    b36 = stwo_m31_mul(b53, b28);
    b63 = stwo_m31_mul(b51, b14);
    b67 = stwo_m31_add(b36, b63);
    b63 = stwo_m31_sub(b67, b11);
    b67 = stwo_m31_sub(b63, b25);
    b63 = stwo_m31_add(b62, b67);
    b67 = stwo_m31_mul(b53, b29);
    b62 = stwo_m31_mul(b51, b28);
    b25 = stwo_m31_add(b67, b62);
    b62 = stwo_m31_mul(b41, b14);
    b67 = stwo_m31_add(b25, b62);
    b62 = stwo_m31_sub(b67, b35);
    b67 = stwo_m31_sub(b62, b26);
    b62 = stwo_m31_add(b60, b67);
    b67 = stwo_m31_mul(b53, b54);
    b54 = stwo_m31_mul(b51, b29);
    b29 = stwo_m31_add(b67, b54);
    b54 = stwo_m31_mul(b41, b28);
    b28 = stwo_m31_add(b29, b54);
    b54 = stwo_m31_mul(b38, b14);
    b14 = stwo_m31_add(b28, b54);
    b54 = stwo_m31_sub(b14, b64);
    b14 = stwo_m31_sub(b54, b50);
    b54 = stwo_m31_add(b27, b14);
    b14 = stwo_m31_add(b7, b21);
    b27 = stwo_m31_add(b8, b22);
    b50 = stwo_m31_add(b9, b23);
    b28 = stwo_m31_add(b10, b24);
    b38 = stwo_m31_add(b16, b30);
    b29 = stwo_m31_add(b17, b31);
    b41 = stwo_m31_add(b18, b32);
    b67 = stwo_m31_add(b19, b33);
    b51 = stwo_m31_add(b20, b34);
    b53 = stwo_m31_add(b7, b21);
    b21 = stwo_m31_add(b8, b22);
    b22 = stwo_m31_add(b9, b23);
    b23 = stwo_m31_add(b10, b24);
    b24 = stwo_m31_add(b16, b30);
    b30 = stwo_m31_add(b17, b31);
    b31 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_add(b19, b33);
    b33 = stwo_m31_add(b20, b34);
    b34 = stwo_m31_mul(b14, b53);
    b20 = stwo_m31_mul(b14, b21);
    b19 = stwo_m31_mul(b27, b53);
    b18 = stwo_m31_add(b20, b19);
    b19 = stwo_m31_mul(b14, b22);
    b20 = stwo_m31_mul(b27, b21);
    b17 = stwo_m31_add(b19, b20);
    b20 = stwo_m31_mul(b50, b53);
    b19 = stwo_m31_add(b17, b20);
    b20 = stwo_m31_mul(b14, b23);
    b23 = stwo_m31_mul(b27, b22);
    b22 = stwo_m31_add(b20, b23);
    b23 = stwo_m31_mul(b50, b21);
    b21 = stwo_m31_add(b22, b23);
    b23 = stwo_m31_mul(b28, b53);
    b53 = stwo_m31_add(b21, b23);
    b23 = stwo_m31_mul(b38, b33);
    b38 = stwo_m31_mul(b29, b32);
    b21 = stwo_m31_add(b23, b38);
    b38 = stwo_m31_mul(b41, b31);
    b23 = stwo_m31_add(b21, b38);
    b38 = stwo_m31_mul(b67, b30);
    b21 = stwo_m31_add(b23, b38);
    b38 = stwo_m31_mul(b51, b24);
    b24 = stwo_m31_add(b21, b38);
    b38 = stwo_m31_mul(b29, b33);
    b29 = stwo_m31_mul(b41, b32);
    b21 = stwo_m31_add(b38, b29);
    b29 = stwo_m31_mul(b67, b31);
    b38 = stwo_m31_add(b21, b29);
    b29 = stwo_m31_mul(b51, b30);
    b30 = stwo_m31_add(b38, b29);
    b29 = stwo_m31_mul(b41, b33);
    b33 = stwo_m31_mul(b67, b32);
    b32 = stwo_m31_add(b29, b33);
    b33 = stwo_m31_mul(b51, b31);
    b31 = stwo_m31_add(b32, b33);
    b33 = stwo_m31_sub(b34, b47);
    b34 = stwo_m31_sub(b33, b65);
    b33 = stwo_m31_add(b57, b34);
    b34 = stwo_m31_sub(b18, b39);
    b18 = stwo_m31_sub(b34, b11);
    b34 = stwo_m31_add(b58, b18);
    b18 = stwo_m31_sub(b19, b40);
    b19 = stwo_m31_sub(b18, b35);
    b18 = stwo_m31_add(b59, b19);
    b19 = stwo_m31_sub(b53, b37);
    b53 = stwo_m31_sub(b19, b64);
    b19 = stwo_m31_add(b12, b53);
    b53 = stwo_m31_sub(b24, b49);
    b24 = stwo_m31_sub(b53, b61);
    b53 = stwo_m31_add(b63, b24);
    b24 = stwo_m31_sub(b30, b56);
    b30 = stwo_m31_sub(b24, b15);
    b24 = stwo_m31_add(b62, b30);
    b30 = stwo_m31_sub(b31, b55);
    b31 = stwo_m31_sub(b30, b48);
    b30 = stwo_m31_add(b54, b31);
    b31 = stwo_m31_sub(b66, b0);
    b66 = stwo_m31_sub(b13, b1);
    b13 = stwo_m31_sub(b52, b2);
    b52 = stwo_m31_sub(b33, b3);
    b33 = stwo_m31_sub(b34, b4);
    b34 = stwo_m31_sub(b18, b5);
    b18 = stwo_m31_sub(b19, b6);
    b19 = 2u;
    b6 = stwo_m31_mul(b19, b31);
    b19 = stwo_m31_add(b6, b52);
    b6 = 32u;
    b52 = stwo_m31_mul(b6, b33);
    b6 = stwo_m31_add(b19, b52);
    b52 = 4u;
    b19 = stwo_m31_mul(b52, b53);
    b52 = stwo_m31_sub(b6, b19);
    b19 = 2u;
    b6 = stwo_m31_mul(b19, b66);
    b19 = stwo_m31_add(b6, b33);
    b6 = 32u;
    b33 = stwo_m31_mul(b6, b34);
    b6 = stwo_m31_add(b19, b33);
    b33 = 4u;
    b19 = stwo_m31_mul(b33, b24);
    b33 = stwo_m31_sub(b6, b19);
    b19 = 2u;
    b6 = stwo_m31_mul(b19, b13);
    b19 = stwo_m31_add(b6, b34);
    b6 = 32u;
    b34 = stwo_m31_mul(b6, b18);
    b6 = stwo_m31_add(b19, b34);
    b34 = 4u;
    b19 = stwo_m31_mul(b34, b30);
    b34 = stwo_m31_sub(b6, b19);
    b19 = 512u;
    b6 = stwo_m31_mul(b43, b19);
    b19 = stwo_m31_add(b52, b42);
    b52 = stwo_m31_sub(b6, b19);
    b19 = 512u;
    b6 = stwo_m31_mul(b44, b19);
    b19 = stwo_m31_add(b33, b43);
    b33 = stwo_m31_sub(b6, b19);
    b19 = 512u;
    b6 = stwo_m31_mul(b45, b19);
    b19 = stwo_m31_add(b34, b44);
    b34 = stwo_m31_sub(b6, b19);
    StwoCairoQm31 e0 = { b52, b46, b46, b46 };
    StwoCairoQm31 e1 = { b33, b46, b46, b46 };
    StwoCairoQm31 e2 = { b34, b46, b46, b46 };
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
