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
stwo_cairo_cuda_eval_v1_fb18b61fe0223d8c(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 370u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 371u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 372u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 391u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 392u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 393u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 426u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 427u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 428u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 429u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 430u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 431u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 432u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 433u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 434u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 435u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 436u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 437u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 438u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 439u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 440u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 441u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 442u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 443u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 444u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 445u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 446u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 447u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 448u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 449u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 450u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 451u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 452u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 453u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 455u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 456u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 457u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 458u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 459u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 460u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 461u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 462u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 463u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 464u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 465u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 466u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 467u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 468u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 469u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 470u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 471u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 472u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 473u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 474u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 475u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 476u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 477u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 478u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 479u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 480u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 481u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 482u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 483u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 484u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 485u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 486u, row, 0);
    unsigned b66 = 0u;
    unsigned b67 = 3u;
    unsigned b68 = stwo_m31_mul(b67, b0);
    b67 = 1u;
    b0 = stwo_m31_add(b68, b67);
    b67 = 3u;
    b68 = stwo_m31_mul(b67, b1);
    b67 = 3u;
    b1 = stwo_m31_mul(b67, b2);
    b67 = 3u;
    b2 = stwo_m31_mul(b67, b3);
    b67 = 3u;
    b3 = stwo_m31_mul(b67, b4);
    b67 = 3u;
    b4 = stwo_m31_mul(b67, b5);
    b67 = stwo_m31_mul(b34, b6);
    b5 = stwo_m31_mul(b34, b7);
    unsigned b69 = stwo_m31_mul(b35, b6);
    unsigned b70 = stwo_m31_add(b5, b69);
    b69 = stwo_m31_mul(b34, b8);
    b5 = stwo_m31_mul(b35, b7);
    unsigned b71 = stwo_m31_add(b69, b5);
    b5 = stwo_m31_mul(b36, b6);
    b69 = stwo_m31_add(b71, b5);
    b5 = stwo_m31_mul(b35, b12);
    b71 = stwo_m31_mul(b36, b11);
    unsigned b72 = stwo_m31_add(b5, b71);
    b71 = stwo_m31_mul(b37, b10);
    b5 = stwo_m31_add(b72, b71);
    b71 = stwo_m31_mul(b38, b9);
    b72 = stwo_m31_add(b5, b71);
    b71 = stwo_m31_mul(b39, b8);
    b5 = stwo_m31_add(b72, b71);
    b71 = stwo_m31_mul(b40, b7);
    b72 = stwo_m31_add(b5, b71);
    b71 = stwo_m31_mul(b36, b12);
    b5 = stwo_m31_mul(b37, b11);
    unsigned b73 = stwo_m31_add(b71, b5);
    b5 = stwo_m31_mul(b38, b10);
    b71 = stwo_m31_add(b73, b5);
    b5 = stwo_m31_mul(b39, b9);
    b73 = stwo_m31_add(b71, b5);
    b5 = stwo_m31_mul(b40, b8);
    b71 = stwo_m31_add(b73, b5);
    b5 = stwo_m31_mul(b37, b12);
    b73 = stwo_m31_mul(b38, b11);
    unsigned b74 = stwo_m31_add(b5, b73);
    b73 = stwo_m31_mul(b39, b10);
    b5 = stwo_m31_add(b74, b73);
    b73 = stwo_m31_mul(b40, b9);
    b74 = stwo_m31_add(b5, b73);
    b73 = stwo_m31_mul(b41, b13);
    b5 = stwo_m31_mul(b41, b14);
    unsigned b75 = stwo_m31_mul(b42, b13);
    unsigned b76 = stwo_m31_add(b5, b75);
    b75 = stwo_m31_mul(b41, b15);
    b5 = stwo_m31_mul(b42, b14);
    unsigned b77 = stwo_m31_add(b75, b5);
    b5 = stwo_m31_mul(b43, b13);
    b75 = stwo_m31_add(b77, b5);
    b5 = stwo_m31_mul(b42, b19);
    b77 = stwo_m31_mul(b43, b18);
    unsigned b78 = stwo_m31_add(b5, b77);
    b77 = stwo_m31_mul(b44, b17);
    b5 = stwo_m31_add(b78, b77);
    b77 = stwo_m31_mul(b45, b16);
    b78 = stwo_m31_add(b5, b77);
    b77 = stwo_m31_mul(b46, b15);
    b5 = stwo_m31_add(b78, b77);
    b77 = stwo_m31_mul(b47, b14);
    b78 = stwo_m31_add(b5, b77);
    b77 = stwo_m31_mul(b43, b19);
    b5 = stwo_m31_mul(b44, b18);
    unsigned b79 = stwo_m31_add(b77, b5);
    b5 = stwo_m31_mul(b45, b17);
    b77 = stwo_m31_add(b79, b5);
    b5 = stwo_m31_mul(b46, b16);
    b79 = stwo_m31_add(b77, b5);
    b5 = stwo_m31_mul(b47, b15);
    b77 = stwo_m31_add(b79, b5);
    b5 = stwo_m31_mul(b44, b19);
    b44 = stwo_m31_mul(b45, b18);
    b45 = stwo_m31_add(b5, b44);
    b44 = stwo_m31_mul(b46, b17);
    b46 = stwo_m31_add(b45, b44);
    b44 = stwo_m31_mul(b47, b16);
    b47 = stwo_m31_add(b46, b44);
    b44 = stwo_m31_add(b34, b41);
    b46 = stwo_m31_add(b35, b42);
    b16 = stwo_m31_add(b36, b43);
    b45 = stwo_m31_add(b6, b13);
    b17 = stwo_m31_add(b7, b14);
    b5 = stwo_m31_add(b8, b15);
    b18 = stwo_m31_mul(b44, b45);
    b19 = stwo_m31_sub(b18, b67);
    b18 = stwo_m31_sub(b19, b73);
    b19 = stwo_m31_add(b72, b18);
    b18 = stwo_m31_mul(b44, b17);
    b72 = stwo_m31_mul(b46, b45);
    b73 = stwo_m31_add(b18, b72);
    b72 = stwo_m31_sub(b73, b70);
    b73 = stwo_m31_sub(b72, b76);
    b72 = stwo_m31_add(b71, b73);
    b73 = stwo_m31_mul(b44, b5);
    b5 = stwo_m31_mul(b46, b17);
    b17 = stwo_m31_add(b73, b5);
    b5 = stwo_m31_mul(b16, b45);
    b45 = stwo_m31_add(b17, b5);
    b5 = stwo_m31_sub(b45, b69);
    b45 = stwo_m31_sub(b5, b75);
    b5 = stwo_m31_add(b74, b45);
    b45 = stwo_m31_mul(b48, b20);
    b74 = stwo_m31_mul(b48, b21);
    b75 = stwo_m31_mul(b49, b20);
    b17 = stwo_m31_add(b74, b75);
    b75 = stwo_m31_mul(b48, b22);
    b74 = stwo_m31_mul(b49, b21);
    b16 = stwo_m31_add(b75, b74);
    b74 = stwo_m31_mul(b50, b20);
    b75 = stwo_m31_add(b16, b74);
    b74 = stwo_m31_mul(b49, b26);
    b16 = stwo_m31_mul(b50, b25);
    b73 = stwo_m31_add(b74, b16);
    b16 = stwo_m31_mul(b51, b24);
    b74 = stwo_m31_add(b73, b16);
    b16 = stwo_m31_mul(b52, b23);
    b73 = stwo_m31_add(b74, b16);
    b16 = stwo_m31_mul(b53, b22);
    b74 = stwo_m31_add(b73, b16);
    b16 = stwo_m31_mul(b54, b21);
    b73 = stwo_m31_add(b74, b16);
    b16 = stwo_m31_mul(b50, b26);
    b74 = stwo_m31_mul(b51, b25);
    b46 = stwo_m31_add(b16, b74);
    b74 = stwo_m31_mul(b52, b24);
    b16 = stwo_m31_add(b46, b74);
    b74 = stwo_m31_mul(b53, b23);
    b46 = stwo_m31_add(b16, b74);
    b74 = stwo_m31_mul(b54, b22);
    b16 = stwo_m31_add(b46, b74);
    b74 = stwo_m31_mul(b51, b26);
    b46 = stwo_m31_mul(b52, b25);
    b44 = stwo_m31_add(b74, b46);
    b46 = stwo_m31_mul(b53, b24);
    b74 = stwo_m31_add(b44, b46);
    b46 = stwo_m31_mul(b54, b23);
    b44 = stwo_m31_add(b74, b46);
    b46 = stwo_m31_mul(b55, b27);
    b74 = stwo_m31_mul(b55, b28);
    b71 = stwo_m31_mul(b56, b27);
    b76 = stwo_m31_add(b74, b71);
    b71 = stwo_m31_mul(b55, b29);
    b74 = stwo_m31_mul(b56, b28);
    b18 = stwo_m31_add(b71, b74);
    b74 = stwo_m31_mul(b57, b27);
    b71 = stwo_m31_add(b18, b74);
    b74 = stwo_m31_mul(b56, b33);
    b18 = stwo_m31_mul(b57, b32);
    b79 = stwo_m31_add(b74, b18);
    b18 = stwo_m31_mul(b58, b31);
    b74 = stwo_m31_add(b79, b18);
    b18 = stwo_m31_mul(b59, b30);
    b79 = stwo_m31_add(b74, b18);
    b18 = stwo_m31_mul(b60, b29);
    b74 = stwo_m31_add(b79, b18);
    b18 = stwo_m31_mul(b61, b28);
    b79 = stwo_m31_add(b74, b18);
    b18 = stwo_m31_mul(b57, b33);
    b74 = stwo_m31_mul(b58, b32);
    unsigned b80 = stwo_m31_add(b18, b74);
    b74 = stwo_m31_mul(b59, b31);
    b18 = stwo_m31_add(b80, b74);
    b74 = stwo_m31_mul(b60, b30);
    b80 = stwo_m31_add(b18, b74);
    b74 = stwo_m31_mul(b61, b29);
    b18 = stwo_m31_add(b80, b74);
    b74 = stwo_m31_mul(b58, b33);
    b58 = stwo_m31_mul(b59, b32);
    b59 = stwo_m31_add(b74, b58);
    b58 = stwo_m31_mul(b60, b31);
    b60 = stwo_m31_add(b59, b58);
    b58 = stwo_m31_mul(b61, b30);
    b61 = stwo_m31_add(b60, b58);
    b58 = stwo_m31_add(b48, b55);
    b60 = stwo_m31_add(b49, b56);
    b30 = stwo_m31_add(b50, b57);
    b59 = stwo_m31_add(b20, b27);
    b31 = stwo_m31_add(b21, b28);
    b74 = stwo_m31_add(b22, b29);
    b32 = stwo_m31_mul(b58, b59);
    b33 = stwo_m31_sub(b32, b45);
    b32 = stwo_m31_sub(b33, b46);
    b33 = stwo_m31_add(b73, b32);
    b32 = stwo_m31_mul(b58, b31);
    b73 = stwo_m31_mul(b60, b59);
    b46 = stwo_m31_add(b32, b73);
    b73 = stwo_m31_sub(b46, b17);
    b46 = stwo_m31_sub(b73, b76);
    b73 = stwo_m31_add(b16, b46);
    b46 = stwo_m31_mul(b58, b74);
    b74 = stwo_m31_mul(b60, b31);
    b31 = stwo_m31_add(b46, b74);
    b74 = stwo_m31_mul(b30, b59);
    b59 = stwo_m31_add(b31, b74);
    b74 = stwo_m31_sub(b59, b75);
    b59 = stwo_m31_sub(b74, b71);
    b74 = stwo_m31_add(b44, b59);
    b59 = stwo_m31_add(b34, b48);
    b48 = stwo_m31_add(b35, b49);
    b49 = stwo_m31_add(b36, b50);
    b50 = stwo_m31_add(b37, b51);
    b51 = stwo_m31_add(b38, b52);
    b52 = stwo_m31_add(b39, b53);
    b53 = stwo_m31_add(b40, b54);
    b54 = stwo_m31_add(b41, b55);
    b55 = stwo_m31_add(b42, b56);
    b56 = stwo_m31_add(b43, b57);
    b57 = stwo_m31_add(b6, b20);
    b20 = stwo_m31_add(b7, b21);
    b21 = stwo_m31_add(b8, b22);
    b22 = stwo_m31_add(b9, b23);
    b23 = stwo_m31_add(b10, b24);
    b24 = stwo_m31_add(b11, b25);
    b25 = stwo_m31_add(b12, b26);
    b26 = stwo_m31_add(b13, b27);
    b27 = stwo_m31_add(b14, b28);
    b28 = stwo_m31_add(b15, b29);
    b29 = stwo_m31_mul(b59, b57);
    b15 = stwo_m31_mul(b59, b20);
    b14 = stwo_m31_mul(b48, b57);
    b13 = stwo_m31_add(b15, b14);
    b14 = stwo_m31_mul(b59, b21);
    b15 = stwo_m31_mul(b48, b20);
    b12 = stwo_m31_add(b14, b15);
    b15 = stwo_m31_mul(b49, b57);
    b14 = stwo_m31_add(b12, b15);
    b15 = stwo_m31_mul(b48, b25);
    b12 = stwo_m31_mul(b49, b24);
    b11 = stwo_m31_add(b15, b12);
    b12 = stwo_m31_mul(b50, b23);
    b15 = stwo_m31_add(b11, b12);
    b12 = stwo_m31_mul(b51, b22);
    b11 = stwo_m31_add(b15, b12);
    b12 = stwo_m31_mul(b52, b21);
    b15 = stwo_m31_add(b11, b12);
    b12 = stwo_m31_mul(b53, b20);
    b11 = stwo_m31_add(b15, b12);
    b12 = stwo_m31_mul(b49, b25);
    b15 = stwo_m31_mul(b50, b24);
    b10 = stwo_m31_add(b12, b15);
    b15 = stwo_m31_mul(b51, b23);
    b12 = stwo_m31_add(b10, b15);
    b15 = stwo_m31_mul(b52, b22);
    b10 = stwo_m31_add(b12, b15);
    b15 = stwo_m31_mul(b53, b21);
    b12 = stwo_m31_add(b10, b15);
    b15 = stwo_m31_mul(b50, b25);
    b25 = stwo_m31_mul(b51, b24);
    b24 = stwo_m31_add(b15, b25);
    b25 = stwo_m31_mul(b52, b23);
    b23 = stwo_m31_add(b24, b25);
    b25 = stwo_m31_mul(b53, b22);
    b22 = stwo_m31_add(b23, b25);
    b25 = stwo_m31_mul(b54, b26);
    b23 = stwo_m31_mul(b54, b27);
    b53 = stwo_m31_mul(b55, b26);
    b24 = stwo_m31_add(b23, b53);
    b53 = stwo_m31_mul(b54, b28);
    b23 = stwo_m31_mul(b55, b27);
    b52 = stwo_m31_add(b53, b23);
    b23 = stwo_m31_mul(b56, b26);
    b53 = stwo_m31_add(b52, b23);
    b23 = stwo_m31_add(b59, b54);
    b54 = stwo_m31_add(b48, b55);
    b55 = stwo_m31_add(b49, b56);
    b56 = stwo_m31_add(b57, b26);
    b26 = stwo_m31_add(b20, b27);
    b27 = stwo_m31_add(b21, b28);
    b28 = stwo_m31_mul(b23, b56);
    b21 = stwo_m31_sub(b28, b29);
    b28 = stwo_m31_sub(b21, b25);
    b21 = stwo_m31_add(b11, b28);
    b28 = stwo_m31_mul(b23, b26);
    b11 = stwo_m31_mul(b54, b56);
    b25 = stwo_m31_add(b28, b11);
    b11 = stwo_m31_sub(b25, b13);
    b25 = stwo_m31_sub(b11, b24);
    b11 = stwo_m31_add(b12, b25);
    b25 = stwo_m31_mul(b23, b27);
    b27 = stwo_m31_mul(b54, b26);
    b26 = stwo_m31_add(b25, b27);
    b27 = stwo_m31_mul(b55, b56);
    b56 = stwo_m31_add(b26, b27);
    b27 = stwo_m31_sub(b56, b14);
    b56 = stwo_m31_sub(b27, b53);
    b27 = stwo_m31_add(b22, b56);
    b56 = stwo_m31_sub(b21, b19);
    b21 = stwo_m31_sub(b56, b33);
    b56 = stwo_m31_add(b78, b21);
    b21 = stwo_m31_sub(b11, b72);
    b11 = stwo_m31_sub(b21, b73);
    b21 = stwo_m31_add(b77, b11);
    b11 = stwo_m31_sub(b27, b5);
    b27 = stwo_m31_sub(b11, b74);
    b11 = stwo_m31_add(b47, b27);
    b27 = stwo_m31_sub(b67, b0);
    b67 = stwo_m31_sub(b70, b68);
    b70 = stwo_m31_sub(b69, b1);
    b69 = stwo_m31_sub(b56, b2);
    b56 = stwo_m31_sub(b21, b3);
    b21 = stwo_m31_sub(b11, b4);
    b11 = 32u;
    b4 = stwo_m31_mul(b11, b27);
    b11 = 4u;
    b3 = stwo_m31_mul(b11, b69);
    b11 = stwo_m31_sub(b4, b3);
    b3 = 8u;
    b4 = stwo_m31_mul(b3, b79);
    b3 = stwo_m31_add(b11, b4);
    b4 = 32u;
    b11 = stwo_m31_mul(b4, b67);
    b4 = stwo_m31_add(b27, b11);
    b11 = 4u;
    b27 = stwo_m31_mul(b11, b56);
    b11 = stwo_m31_sub(b4, b27);
    b27 = 8u;
    b4 = stwo_m31_mul(b27, b18);
    b27 = stwo_m31_add(b11, b4);
    b4 = 32u;
    b11 = stwo_m31_mul(b4, b70);
    b4 = stwo_m31_add(b67, b11);
    b11 = 4u;
    b67 = stwo_m31_mul(b11, b21);
    b11 = stwo_m31_sub(b4, b67);
    b67 = 8u;
    b4 = stwo_m31_mul(b67, b61);
    b67 = stwo_m31_add(b11, b4);
    b4 = 512u;
    b11 = stwo_m31_mul(b63, b4);
    b4 = stwo_m31_sub(b3, b62);
    b3 = stwo_m31_sub(b11, b4);
    b4 = 512u;
    b11 = stwo_m31_mul(b64, b4);
    b4 = stwo_m31_add(b27, b63);
    b27 = stwo_m31_sub(b11, b4);
    b4 = 512u;
    b11 = stwo_m31_mul(b65, b4);
    b4 = stwo_m31_add(b67, b64);
    b67 = stwo_m31_sub(b11, b4);
    StwoCairoQm31 e0 = { b3, b66, b66, b66 };
    StwoCairoQm31 e1 = { b27, b66, b66, b66 };
    StwoCairoQm31 e2 = { b67, b66, b66, b66 };
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
