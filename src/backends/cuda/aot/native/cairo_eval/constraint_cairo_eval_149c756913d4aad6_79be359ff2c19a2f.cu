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
stwo_cairo_cuda_eval_v1_7d62e7b60f681d57(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 375u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 376u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 377u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 381u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 382u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 383u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 384u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 426u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 427u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 428u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 429u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 430u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 431u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 432u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 433u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 434u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 435u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 436u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 437u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 438u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 439u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 440u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 441u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 442u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 443u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 444u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 445u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 446u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 447u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 448u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 449u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 450u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 451u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 452u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 453u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 455u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 456u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 457u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 458u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 459u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 460u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 461u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 462u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 463u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 464u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 465u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 466u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 467u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 468u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 469u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 470u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 471u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 472u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 473u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 474u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 475u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 476u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 477u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 478u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 479u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 480u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 481u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 482u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 495u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 496u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 497u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 498u, row, 0);
    unsigned b67 = 0u;
    unsigned b68 = 3u;
    unsigned b69 = stwo_m31_mul(b68, b0);
    b68 = 3u;
    b0 = stwo_m31_mul(b68, b1);
    b68 = 3u;
    b1 = stwo_m31_mul(b68, b2);
    b68 = 3u;
    b2 = stwo_m31_mul(b68, b3);
    b68 = 3u;
    b3 = stwo_m31_mul(b68, b4);
    b68 = 3u;
    b4 = stwo_m31_mul(b68, b5);
    b68 = 3u;
    b5 = stwo_m31_mul(b68, b6);
    b68 = stwo_m31_mul(b35, b7);
    b6 = stwo_m31_mul(b35, b11);
    unsigned b70 = stwo_m31_mul(b36, b10);
    unsigned b71 = stwo_m31_add(b6, b70);
    b70 = stwo_m31_mul(b37, b9);
    b6 = stwo_m31_add(b71, b70);
    b70 = stwo_m31_mul(b38, b8);
    b71 = stwo_m31_add(b6, b70);
    b70 = stwo_m31_mul(b39, b7);
    b6 = stwo_m31_add(b71, b70);
    b70 = stwo_m31_mul(b35, b12);
    b71 = stwo_m31_mul(b36, b11);
    unsigned b72 = stwo_m31_add(b70, b71);
    b71 = stwo_m31_mul(b37, b10);
    b70 = stwo_m31_add(b72, b71);
    b71 = stwo_m31_mul(b38, b9);
    b72 = stwo_m31_add(b70, b71);
    b71 = stwo_m31_mul(b39, b8);
    b70 = stwo_m31_add(b72, b71);
    b71 = stwo_m31_mul(b40, b7);
    b72 = stwo_m31_add(b70, b71);
    b71 = stwo_m31_mul(b35, b13);
    b70 = stwo_m31_mul(b36, b12);
    unsigned b73 = stwo_m31_add(b71, b70);
    b70 = stwo_m31_mul(b37, b11);
    b71 = stwo_m31_add(b73, b70);
    b70 = stwo_m31_mul(b38, b10);
    b73 = stwo_m31_add(b71, b70);
    b70 = stwo_m31_mul(b39, b9);
    b71 = stwo_m31_add(b73, b70);
    b70 = stwo_m31_mul(b40, b8);
    b73 = stwo_m31_add(b71, b70);
    b70 = stwo_m31_mul(b41, b7);
    b71 = stwo_m31_add(b73, b70);
    b70 = stwo_m31_mul(b36, b13);
    b73 = stwo_m31_mul(b37, b12);
    unsigned b74 = stwo_m31_add(b70, b73);
    b73 = stwo_m31_mul(b38, b11);
    b70 = stwo_m31_add(b74, b73);
    b73 = stwo_m31_mul(b39, b10);
    b74 = stwo_m31_add(b70, b73);
    b73 = stwo_m31_mul(b40, b9);
    b70 = stwo_m31_add(b74, b73);
    b73 = stwo_m31_mul(b41, b8);
    b74 = stwo_m31_add(b70, b73);
    b73 = stwo_m31_mul(b40, b13);
    b70 = stwo_m31_mul(b41, b12);
    unsigned b75 = stwo_m31_add(b73, b70);
    b70 = stwo_m31_mul(b41, b13);
    b73 = stwo_m31_mul(b42, b14);
    unsigned b76 = stwo_m31_mul(b42, b18);
    unsigned b77 = stwo_m31_mul(b43, b17);
    unsigned b78 = stwo_m31_add(b76, b77);
    b77 = stwo_m31_mul(b44, b16);
    b76 = stwo_m31_add(b78, b77);
    b77 = stwo_m31_mul(b45, b15);
    b78 = stwo_m31_add(b76, b77);
    b77 = stwo_m31_mul(b46, b14);
    b76 = stwo_m31_add(b78, b77);
    b77 = stwo_m31_mul(b42, b19);
    b78 = stwo_m31_mul(b43, b18);
    unsigned b79 = stwo_m31_add(b77, b78);
    b78 = stwo_m31_mul(b44, b17);
    b77 = stwo_m31_add(b79, b78);
    b78 = stwo_m31_mul(b45, b16);
    b79 = stwo_m31_add(b77, b78);
    b78 = stwo_m31_mul(b46, b15);
    b77 = stwo_m31_add(b79, b78);
    b78 = stwo_m31_mul(b47, b14);
    b79 = stwo_m31_add(b77, b78);
    b78 = stwo_m31_mul(b42, b20);
    b77 = stwo_m31_mul(b43, b19);
    unsigned b80 = stwo_m31_add(b78, b77);
    b77 = stwo_m31_mul(b44, b18);
    b78 = stwo_m31_add(b80, b77);
    b77 = stwo_m31_mul(b45, b17);
    b80 = stwo_m31_add(b78, b77);
    b77 = stwo_m31_mul(b46, b16);
    b78 = stwo_m31_add(b80, b77);
    b77 = stwo_m31_mul(b47, b15);
    b80 = stwo_m31_add(b78, b77);
    b77 = stwo_m31_mul(b48, b14);
    b78 = stwo_m31_add(b80, b77);
    b77 = stwo_m31_mul(b43, b20);
    b80 = stwo_m31_mul(b44, b19);
    unsigned b81 = stwo_m31_add(b77, b80);
    b80 = stwo_m31_mul(b45, b18);
    b77 = stwo_m31_add(b81, b80);
    b80 = stwo_m31_mul(b46, b17);
    b81 = stwo_m31_add(b77, b80);
    b80 = stwo_m31_mul(b47, b16);
    b77 = stwo_m31_add(b81, b80);
    b80 = stwo_m31_mul(b48, b15);
    b81 = stwo_m31_add(b77, b80);
    b80 = stwo_m31_mul(b48, b20);
    b77 = stwo_m31_add(b35, b42);
    unsigned b82 = stwo_m31_add(b36, b43);
    b36 = stwo_m31_add(b37, b44);
    b37 = stwo_m31_add(b38, b45);
    b38 = stwo_m31_add(b39, b46);
    b39 = stwo_m31_add(b40, b47);
    b40 = stwo_m31_add(b41, b48);
    unsigned b83 = stwo_m31_add(b7, b14);
    unsigned b84 = stwo_m31_add(b8, b15);
    b8 = stwo_m31_add(b9, b16);
    b9 = stwo_m31_add(b10, b17);
    b10 = stwo_m31_add(b11, b18);
    b11 = stwo_m31_add(b12, b19);
    b12 = stwo_m31_add(b13, b20);
    unsigned b85 = stwo_m31_mul(b77, b83);
    unsigned b86 = stwo_m31_sub(b85, b68);
    b85 = stwo_m31_sub(b86, b73);
    b86 = stwo_m31_add(b74, b85);
    b85 = stwo_m31_mul(b77, b10);
    unsigned b87 = stwo_m31_mul(b82, b9);
    unsigned b88 = stwo_m31_add(b85, b87);
    b87 = stwo_m31_mul(b36, b8);
    b85 = stwo_m31_add(b88, b87);
    b87 = stwo_m31_mul(b37, b84);
    b88 = stwo_m31_add(b85, b87);
    b87 = stwo_m31_mul(b38, b83);
    b85 = stwo_m31_add(b88, b87);
    b87 = stwo_m31_sub(b85, b6);
    b85 = stwo_m31_sub(b87, b76);
    b87 = stwo_m31_add(b75, b85);
    b85 = stwo_m31_mul(b77, b11);
    b75 = stwo_m31_mul(b82, b10);
    b76 = stwo_m31_add(b85, b75);
    b75 = stwo_m31_mul(b36, b9);
    b85 = stwo_m31_add(b76, b75);
    b75 = stwo_m31_mul(b37, b8);
    b76 = stwo_m31_add(b85, b75);
    b75 = stwo_m31_mul(b38, b84);
    b85 = stwo_m31_add(b76, b75);
    b75 = stwo_m31_mul(b39, b83);
    b76 = stwo_m31_add(b85, b75);
    b75 = stwo_m31_sub(b76, b72);
    b76 = stwo_m31_sub(b75, b79);
    b75 = stwo_m31_add(b70, b76);
    b76 = stwo_m31_mul(b77, b12);
    b77 = stwo_m31_mul(b82, b11);
    b85 = stwo_m31_add(b76, b77);
    b77 = stwo_m31_mul(b36, b10);
    b76 = stwo_m31_add(b85, b77);
    b77 = stwo_m31_mul(b37, b9);
    b85 = stwo_m31_add(b76, b77);
    b77 = stwo_m31_mul(b38, b8);
    b76 = stwo_m31_add(b85, b77);
    b77 = stwo_m31_mul(b39, b84);
    b85 = stwo_m31_add(b76, b77);
    b77 = stwo_m31_mul(b40, b83);
    b83 = stwo_m31_add(b85, b77);
    b77 = stwo_m31_sub(b83, b71);
    b83 = stwo_m31_sub(b77, b78);
    b77 = stwo_m31_mul(b82, b12);
    b82 = stwo_m31_mul(b36, b11);
    b11 = stwo_m31_add(b77, b82);
    b82 = stwo_m31_mul(b37, b10);
    b10 = stwo_m31_add(b11, b82);
    b82 = stwo_m31_mul(b38, b9);
    b9 = stwo_m31_add(b10, b82);
    b82 = stwo_m31_mul(b39, b8);
    b8 = stwo_m31_add(b9, b82);
    b82 = stwo_m31_mul(b40, b84);
    b84 = stwo_m31_add(b8, b82);
    b82 = stwo_m31_sub(b84, b74);
    b84 = stwo_m31_sub(b82, b81);
    b82 = stwo_m31_add(b73, b84);
    b84 = stwo_m31_mul(b40, b12);
    b12 = stwo_m31_sub(b84, b70);
    b84 = stwo_m31_sub(b12, b80);
    b12 = stwo_m31_add(b79, b84);
    b84 = stwo_m31_mul(b49, b21);
    b79 = stwo_m31_mul(b49, b26);
    b80 = stwo_m31_mul(b50, b25);
    b70 = stwo_m31_add(b79, b80);
    b80 = stwo_m31_mul(b51, b24);
    b79 = stwo_m31_add(b70, b80);
    b80 = stwo_m31_mul(b52, b23);
    b70 = stwo_m31_add(b79, b80);
    b80 = stwo_m31_mul(b53, b22);
    b79 = stwo_m31_add(b70, b80);
    b80 = stwo_m31_mul(b54, b21);
    b70 = stwo_m31_add(b79, b80);
    b80 = stwo_m31_mul(b49, b27);
    b79 = stwo_m31_mul(b50, b26);
    b40 = stwo_m31_add(b80, b79);
    b79 = stwo_m31_mul(b51, b25);
    b80 = stwo_m31_add(b40, b79);
    b79 = stwo_m31_mul(b52, b24);
    b40 = stwo_m31_add(b80, b79);
    b79 = stwo_m31_mul(b53, b23);
    b80 = stwo_m31_add(b40, b79);
    b79 = stwo_m31_mul(b54, b22);
    b40 = stwo_m31_add(b80, b79);
    b79 = stwo_m31_mul(b55, b21);
    b80 = stwo_m31_add(b40, b79);
    b79 = stwo_m31_mul(b50, b27);
    b50 = stwo_m31_mul(b51, b26);
    b51 = stwo_m31_add(b79, b50);
    b50 = stwo_m31_mul(b52, b25);
    b52 = stwo_m31_add(b51, b50);
    b50 = stwo_m31_mul(b53, b24);
    b53 = stwo_m31_add(b52, b50);
    b50 = stwo_m31_mul(b54, b23);
    b54 = stwo_m31_add(b53, b50);
    b50 = stwo_m31_mul(b55, b22);
    b22 = stwo_m31_add(b54, b50);
    b50 = stwo_m31_mul(b55, b27);
    b54 = stwo_m31_mul(b56, b28);
    b53 = stwo_m31_mul(b56, b33);
    b23 = stwo_m31_mul(b57, b32);
    b52 = stwo_m31_add(b53, b23);
    b23 = stwo_m31_mul(b58, b31);
    b53 = stwo_m31_add(b52, b23);
    b23 = stwo_m31_mul(b59, b30);
    b52 = stwo_m31_add(b53, b23);
    b23 = stwo_m31_mul(b60, b29);
    b53 = stwo_m31_add(b52, b23);
    b23 = stwo_m31_mul(b61, b28);
    b52 = stwo_m31_add(b53, b23);
    b23 = stwo_m31_mul(b56, b34);
    b53 = stwo_m31_mul(b57, b33);
    b24 = stwo_m31_add(b23, b53);
    b53 = stwo_m31_mul(b58, b32);
    b23 = stwo_m31_add(b24, b53);
    b53 = stwo_m31_mul(b59, b31);
    b24 = stwo_m31_add(b23, b53);
    b53 = stwo_m31_mul(b60, b30);
    b23 = stwo_m31_add(b24, b53);
    b53 = stwo_m31_mul(b61, b29);
    b24 = stwo_m31_add(b23, b53);
    b53 = stwo_m31_mul(b62, b28);
    b23 = stwo_m31_add(b24, b53);
    b53 = stwo_m31_mul(b57, b34);
    b24 = stwo_m31_mul(b58, b33);
    b51 = stwo_m31_add(b53, b24);
    b24 = stwo_m31_mul(b59, b32);
    b53 = stwo_m31_add(b51, b24);
    b24 = stwo_m31_mul(b60, b31);
    b51 = stwo_m31_add(b53, b24);
    b24 = stwo_m31_mul(b61, b30);
    b53 = stwo_m31_add(b51, b24);
    b24 = stwo_m31_mul(b62, b29);
    b51 = stwo_m31_add(b53, b24);
    b24 = stwo_m31_mul(b62, b34);
    b53 = stwo_m31_add(b49, b56);
    b25 = stwo_m31_add(b55, b62);
    b79 = stwo_m31_add(b21, b28);
    b26 = stwo_m31_add(b27, b34);
    b40 = stwo_m31_mul(b53, b79);
    b79 = stwo_m31_sub(b40, b84);
    b40 = stwo_m31_sub(b79, b54);
    b79 = stwo_m31_add(b22, b40);
    b40 = stwo_m31_mul(b25, b26);
    b26 = stwo_m31_sub(b40, b50);
    b40 = stwo_m31_sub(b26, b24);
    b26 = stwo_m31_add(b52, b40);
    b40 = stwo_m31_add(b35, b49);
    b49 = stwo_m31_add(b41, b55);
    b55 = stwo_m31_add(b42, b56);
    b56 = stwo_m31_add(b43, b57);
    b57 = stwo_m31_add(b44, b58);
    b58 = stwo_m31_add(b45, b59);
    b59 = stwo_m31_add(b46, b60);
    b60 = stwo_m31_add(b47, b61);
    b61 = stwo_m31_add(b48, b62);
    b62 = stwo_m31_add(b7, b21);
    b21 = stwo_m31_add(b13, b27);
    b27 = stwo_m31_add(b14, b28);
    b28 = stwo_m31_add(b15, b29);
    b29 = stwo_m31_add(b16, b30);
    b30 = stwo_m31_add(b17, b31);
    b31 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_add(b19, b33);
    b33 = stwo_m31_add(b20, b34);
    b34 = stwo_m31_mul(b40, b62);
    b62 = stwo_m31_mul(b49, b21);
    b40 = stwo_m31_mul(b55, b32);
    b20 = stwo_m31_mul(b56, b31);
    b19 = stwo_m31_add(b40, b20);
    b20 = stwo_m31_mul(b57, b30);
    b40 = stwo_m31_add(b19, b20);
    b20 = stwo_m31_mul(b58, b29);
    b19 = stwo_m31_add(b40, b20);
    b20 = stwo_m31_mul(b59, b28);
    b40 = stwo_m31_add(b19, b20);
    b20 = stwo_m31_mul(b60, b27);
    b19 = stwo_m31_add(b40, b20);
    b20 = stwo_m31_mul(b55, b33);
    b55 = stwo_m31_mul(b56, b32);
    b40 = stwo_m31_add(b20, b55);
    b55 = stwo_m31_mul(b57, b31);
    b20 = stwo_m31_add(b40, b55);
    b55 = stwo_m31_mul(b58, b30);
    b40 = stwo_m31_add(b20, b55);
    b55 = stwo_m31_mul(b59, b29);
    b20 = stwo_m31_add(b40, b55);
    b55 = stwo_m31_mul(b60, b28);
    b40 = stwo_m31_add(b20, b55);
    b55 = stwo_m31_mul(b61, b27);
    b27 = stwo_m31_add(b40, b55);
    b55 = stwo_m31_mul(b56, b33);
    b56 = stwo_m31_mul(b57, b32);
    b32 = stwo_m31_add(b55, b56);
    b56 = stwo_m31_mul(b58, b31);
    b31 = stwo_m31_add(b32, b56);
    b56 = stwo_m31_mul(b59, b30);
    b30 = stwo_m31_add(b31, b56);
    b56 = stwo_m31_mul(b60, b29);
    b29 = stwo_m31_add(b30, b56);
    b56 = stwo_m31_mul(b61, b28);
    b28 = stwo_m31_add(b29, b56);
    b56 = stwo_m31_mul(b61, b33);
    b29 = stwo_m31_add(b49, b61);
    b61 = stwo_m31_add(b21, b33);
    b33 = stwo_m31_mul(b29, b61);
    b61 = stwo_m31_sub(b33, b62);
    b33 = stwo_m31_sub(b61, b56);
    b61 = stwo_m31_add(b19, b33);
    b33 = stwo_m31_sub(b34, b68);
    b34 = stwo_m31_sub(b33, b84);
    b33 = stwo_m31_add(b82, b34);
    b34 = stwo_m31_sub(b61, b12);
    b61 = stwo_m31_sub(b34, b26);
    b34 = stwo_m31_add(b70, b61);
    b61 = stwo_m31_sub(b27, b78);
    b27 = stwo_m31_sub(b61, b23);
    b61 = stwo_m31_add(b80, b27);
    b27 = stwo_m31_sub(b28, b81);
    b28 = stwo_m31_sub(b27, b51);
    b27 = stwo_m31_add(b79, b28);
    b28 = stwo_m31_sub(b72, b69);
    b72 = stwo_m31_sub(b71, b0);
    b71 = stwo_m31_sub(b86, b1);
    b86 = stwo_m31_sub(b87, b2);
    b87 = stwo_m31_sub(b75, b3);
    b75 = stwo_m31_sub(b83, b4);
    b83 = stwo_m31_sub(b33, b5);
    b33 = 2u;
    b5 = stwo_m31_mul(b33, b28);
    b33 = stwo_m31_add(b5, b86);
    b5 = 32u;
    b86 = stwo_m31_mul(b5, b87);
    b5 = stwo_m31_add(b33, b86);
    b86 = 4u;
    b33 = stwo_m31_mul(b86, b34);
    b86 = stwo_m31_sub(b5, b33);
    b33 = 2u;
    b5 = stwo_m31_mul(b33, b72);
    b33 = stwo_m31_add(b5, b87);
    b5 = 32u;
    b87 = stwo_m31_mul(b5, b75);
    b5 = stwo_m31_add(b33, b87);
    b87 = 4u;
    b33 = stwo_m31_mul(b87, b61);
    b87 = stwo_m31_sub(b5, b33);
    b33 = 2u;
    b5 = stwo_m31_mul(b33, b71);
    b33 = stwo_m31_add(b5, b75);
    b5 = 32u;
    b75 = stwo_m31_mul(b5, b83);
    b5 = stwo_m31_add(b33, b75);
    b75 = 4u;
    b33 = stwo_m31_mul(b75, b27);
    b75 = stwo_m31_sub(b5, b33);
    b33 = 512u;
    b5 = stwo_m31_mul(b64, b33);
    b33 = stwo_m31_add(b86, b63);
    b86 = stwo_m31_sub(b5, b33);
    b33 = 512u;
    b5 = stwo_m31_mul(b65, b33);
    b33 = stwo_m31_add(b87, b64);
    b87 = stwo_m31_sub(b5, b33);
    b33 = 512u;
    b5 = stwo_m31_mul(b66, b33);
    b33 = stwo_m31_add(b75, b65);
    b75 = stwo_m31_sub(b5, b33);
    StwoCairoQm31 e0 = { b86, b67, b67, b67 };
    StwoCairoQm31 e1 = { b87, b67, b67, b67 };
    StwoCairoQm31 e2 = { b75, b67, b67, b67 };
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
