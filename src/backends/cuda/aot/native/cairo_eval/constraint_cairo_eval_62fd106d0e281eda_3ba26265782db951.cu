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
stwo_cairo_cuda_eval_v1_2696b8e1a2674154(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 378u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 379u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 380u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 384u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 385u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 386u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 387u, row, 0);
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
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 498u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 499u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 500u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 501u, row, 0);
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
    b6 = stwo_m31_mul(b35, b8);
    unsigned b70 = stwo_m31_mul(b36, b7);
    unsigned b71 = stwo_m31_add(b6, b70);
    b70 = stwo_m31_mul(b35, b9);
    b6 = stwo_m31_mul(b36, b8);
    unsigned b72 = stwo_m31_add(b70, b6);
    b6 = stwo_m31_mul(b37, b7);
    b70 = stwo_m31_add(b72, b6);
    b6 = stwo_m31_mul(b35, b10);
    b72 = stwo_m31_mul(b36, b9);
    unsigned b73 = stwo_m31_add(b6, b72);
    b72 = stwo_m31_mul(b37, b8);
    b6 = stwo_m31_add(b73, b72);
    b72 = stwo_m31_mul(b38, b7);
    b73 = stwo_m31_add(b6, b72);
    b72 = stwo_m31_mul(b36, b13);
    b6 = stwo_m31_mul(b37, b12);
    unsigned b74 = stwo_m31_add(b72, b6);
    b6 = stwo_m31_mul(b38, b11);
    b72 = stwo_m31_add(b74, b6);
    b6 = stwo_m31_mul(b39, b10);
    b74 = stwo_m31_add(b72, b6);
    b6 = stwo_m31_mul(b40, b9);
    b72 = stwo_m31_add(b74, b6);
    b6 = stwo_m31_mul(b41, b8);
    b74 = stwo_m31_add(b72, b6);
    b6 = stwo_m31_mul(b37, b13);
    b72 = stwo_m31_mul(b38, b12);
    unsigned b75 = stwo_m31_add(b6, b72);
    b72 = stwo_m31_mul(b39, b11);
    b6 = stwo_m31_add(b75, b72);
    b72 = stwo_m31_mul(b40, b10);
    b75 = stwo_m31_add(b6, b72);
    b72 = stwo_m31_mul(b41, b9);
    b6 = stwo_m31_add(b75, b72);
    b72 = stwo_m31_mul(b38, b13);
    b75 = stwo_m31_mul(b39, b12);
    unsigned b76 = stwo_m31_add(b72, b75);
    b75 = stwo_m31_mul(b40, b11);
    b72 = stwo_m31_add(b76, b75);
    b75 = stwo_m31_mul(b41, b10);
    b76 = stwo_m31_add(b72, b75);
    b75 = stwo_m31_mul(b39, b13);
    b72 = stwo_m31_mul(b40, b12);
    unsigned b77 = stwo_m31_add(b75, b72);
    b72 = stwo_m31_mul(b41, b11);
    b75 = stwo_m31_add(b77, b72);
    b72 = stwo_m31_mul(b42, b14);
    b77 = stwo_m31_mul(b42, b15);
    unsigned b78 = stwo_m31_mul(b43, b14);
    unsigned b79 = stwo_m31_add(b77, b78);
    b78 = stwo_m31_mul(b42, b16);
    b77 = stwo_m31_mul(b43, b15);
    unsigned b80 = stwo_m31_add(b78, b77);
    b77 = stwo_m31_mul(b44, b14);
    b78 = stwo_m31_add(b80, b77);
    b77 = stwo_m31_mul(b42, b17);
    b80 = stwo_m31_mul(b43, b16);
    unsigned b81 = stwo_m31_add(b77, b80);
    b80 = stwo_m31_mul(b44, b15);
    b77 = stwo_m31_add(b81, b80);
    b80 = stwo_m31_mul(b45, b14);
    b81 = stwo_m31_add(b77, b80);
    b80 = stwo_m31_mul(b43, b20);
    b77 = stwo_m31_mul(b44, b19);
    unsigned b82 = stwo_m31_add(b80, b77);
    b77 = stwo_m31_mul(b45, b18);
    b80 = stwo_m31_add(b82, b77);
    b77 = stwo_m31_mul(b46, b17);
    b82 = stwo_m31_add(b80, b77);
    b77 = stwo_m31_mul(b47, b16);
    b80 = stwo_m31_add(b82, b77);
    b77 = stwo_m31_mul(b48, b15);
    b82 = stwo_m31_add(b80, b77);
    b77 = stwo_m31_mul(b44, b20);
    b80 = stwo_m31_mul(b45, b19);
    unsigned b83 = stwo_m31_add(b77, b80);
    b80 = stwo_m31_mul(b46, b18);
    b77 = stwo_m31_add(b83, b80);
    b80 = stwo_m31_mul(b47, b17);
    b83 = stwo_m31_add(b77, b80);
    b80 = stwo_m31_mul(b48, b16);
    b77 = stwo_m31_add(b83, b80);
    b80 = stwo_m31_mul(b45, b20);
    b83 = stwo_m31_mul(b46, b19);
    unsigned b84 = stwo_m31_add(b80, b83);
    b83 = stwo_m31_mul(b47, b18);
    b80 = stwo_m31_add(b84, b83);
    b83 = stwo_m31_mul(b48, b17);
    b84 = stwo_m31_add(b80, b83);
    b83 = stwo_m31_mul(b46, b20);
    b80 = stwo_m31_mul(b47, b19);
    unsigned b85 = stwo_m31_add(b83, b80);
    b80 = stwo_m31_mul(b48, b18);
    b83 = stwo_m31_add(b85, b80);
    b80 = stwo_m31_add(b35, b42);
    b42 = stwo_m31_add(b36, b43);
    b43 = stwo_m31_add(b37, b44);
    b85 = stwo_m31_add(b38, b45);
    unsigned b86 = stwo_m31_add(b39, b46);
    b39 = stwo_m31_add(b40, b47);
    b40 = stwo_m31_add(b41, b48);
    b41 = stwo_m31_add(b7, b14);
    b14 = stwo_m31_add(b8, b15);
    b15 = stwo_m31_add(b9, b16);
    unsigned b87 = stwo_m31_add(b10, b17);
    unsigned b88 = stwo_m31_add(b11, b18);
    b11 = stwo_m31_add(b12, b19);
    b12 = stwo_m31_add(b13, b20);
    b13 = stwo_m31_mul(b80, b14);
    unsigned b89 = stwo_m31_mul(b42, b41);
    unsigned b90 = stwo_m31_add(b13, b89);
    b89 = stwo_m31_sub(b90, b71);
    b90 = stwo_m31_sub(b89, b79);
    b89 = stwo_m31_add(b6, b90);
    b90 = stwo_m31_mul(b80, b15);
    b13 = stwo_m31_mul(b42, b14);
    unsigned b91 = stwo_m31_add(b90, b13);
    b13 = stwo_m31_mul(b43, b41);
    b90 = stwo_m31_add(b91, b13);
    b13 = stwo_m31_sub(b90, b70);
    b90 = stwo_m31_sub(b13, b78);
    b13 = stwo_m31_add(b76, b90);
    b90 = stwo_m31_mul(b80, b87);
    b80 = stwo_m31_mul(b42, b15);
    b91 = stwo_m31_add(b90, b80);
    b80 = stwo_m31_mul(b43, b14);
    b90 = stwo_m31_add(b91, b80);
    b80 = stwo_m31_mul(b85, b41);
    b41 = stwo_m31_add(b90, b80);
    b80 = stwo_m31_sub(b41, b73);
    b41 = stwo_m31_sub(b80, b81);
    b80 = stwo_m31_add(b75, b41);
    b41 = stwo_m31_mul(b42, b12);
    b42 = stwo_m31_mul(b43, b11);
    b90 = stwo_m31_add(b41, b42);
    b42 = stwo_m31_mul(b85, b88);
    b41 = stwo_m31_add(b90, b42);
    b42 = stwo_m31_mul(b86, b87);
    b90 = stwo_m31_add(b41, b42);
    b42 = stwo_m31_mul(b39, b15);
    b41 = stwo_m31_add(b90, b42);
    b42 = stwo_m31_mul(b40, b14);
    b14 = stwo_m31_add(b41, b42);
    b42 = stwo_m31_sub(b14, b74);
    b14 = stwo_m31_sub(b42, b82);
    b42 = stwo_m31_add(b72, b14);
    b14 = stwo_m31_mul(b43, b12);
    b43 = stwo_m31_mul(b85, b11);
    b72 = stwo_m31_add(b14, b43);
    b43 = stwo_m31_mul(b86, b88);
    b14 = stwo_m31_add(b72, b43);
    b43 = stwo_m31_mul(b39, b87);
    b72 = stwo_m31_add(b14, b43);
    b43 = stwo_m31_mul(b40, b15);
    b15 = stwo_m31_add(b72, b43);
    b43 = stwo_m31_sub(b15, b6);
    b15 = stwo_m31_sub(b43, b77);
    b43 = stwo_m31_add(b79, b15);
    b15 = stwo_m31_mul(b85, b12);
    b85 = stwo_m31_mul(b86, b11);
    b79 = stwo_m31_add(b15, b85);
    b85 = stwo_m31_mul(b39, b88);
    b15 = stwo_m31_add(b79, b85);
    b85 = stwo_m31_mul(b40, b87);
    b87 = stwo_m31_add(b15, b85);
    b85 = stwo_m31_sub(b87, b76);
    b87 = stwo_m31_sub(b85, b84);
    b85 = stwo_m31_add(b78, b87);
    b87 = stwo_m31_mul(b86, b12);
    b12 = stwo_m31_mul(b39, b11);
    b11 = stwo_m31_add(b87, b12);
    b12 = stwo_m31_mul(b40, b88);
    b88 = stwo_m31_add(b11, b12);
    b12 = stwo_m31_sub(b88, b75);
    b88 = stwo_m31_sub(b12, b83);
    b12 = stwo_m31_add(b81, b88);
    b88 = stwo_m31_mul(b49, b21);
    b81 = stwo_m31_mul(b49, b22);
    b75 = stwo_m31_mul(b50, b21);
    b11 = stwo_m31_add(b81, b75);
    b75 = stwo_m31_mul(b49, b23);
    b81 = stwo_m31_mul(b50, b22);
    b40 = stwo_m31_add(b75, b81);
    b81 = stwo_m31_mul(b51, b21);
    b75 = stwo_m31_add(b40, b81);
    b81 = stwo_m31_mul(b49, b24);
    b40 = stwo_m31_mul(b50, b23);
    b87 = stwo_m31_add(b81, b40);
    b40 = stwo_m31_mul(b51, b22);
    b81 = stwo_m31_add(b87, b40);
    b40 = stwo_m31_mul(b52, b21);
    b87 = stwo_m31_add(b81, b40);
    b40 = stwo_m31_mul(b51, b27);
    b81 = stwo_m31_mul(b52, b26);
    b39 = stwo_m31_add(b40, b81);
    b81 = stwo_m31_mul(b53, b25);
    b40 = stwo_m31_add(b39, b81);
    b81 = stwo_m31_mul(b54, b24);
    b39 = stwo_m31_add(b40, b81);
    b81 = stwo_m31_mul(b55, b23);
    b40 = stwo_m31_add(b39, b81);
    b81 = stwo_m31_mul(b52, b27);
    b39 = stwo_m31_mul(b53, b26);
    b86 = stwo_m31_add(b81, b39);
    b39 = stwo_m31_mul(b54, b25);
    b81 = stwo_m31_add(b86, b39);
    b39 = stwo_m31_mul(b55, b24);
    b86 = stwo_m31_add(b81, b39);
    b39 = stwo_m31_mul(b53, b27);
    b53 = stwo_m31_mul(b54, b26);
    b54 = stwo_m31_add(b39, b53);
    b53 = stwo_m31_mul(b55, b25);
    b55 = stwo_m31_add(b54, b53);
    b53 = stwo_m31_mul(b56, b29);
    b54 = stwo_m31_mul(b57, b28);
    b25 = stwo_m31_add(b53, b54);
    b54 = stwo_m31_mul(b56, b30);
    b53 = stwo_m31_mul(b57, b29);
    b39 = stwo_m31_add(b54, b53);
    b53 = stwo_m31_mul(b58, b28);
    b54 = stwo_m31_add(b39, b53);
    b53 = stwo_m31_mul(b56, b31);
    b39 = stwo_m31_mul(b57, b30);
    b26 = stwo_m31_add(b53, b39);
    b39 = stwo_m31_mul(b58, b29);
    b53 = stwo_m31_add(b26, b39);
    b39 = stwo_m31_mul(b59, b28);
    b26 = stwo_m31_add(b53, b39);
    b39 = stwo_m31_mul(b58, b34);
    b53 = stwo_m31_mul(b59, b33);
    b27 = stwo_m31_add(b39, b53);
    b53 = stwo_m31_mul(b60, b32);
    b39 = stwo_m31_add(b27, b53);
    b53 = stwo_m31_mul(b61, b31);
    b27 = stwo_m31_add(b39, b53);
    b53 = stwo_m31_mul(b62, b30);
    b39 = stwo_m31_add(b27, b53);
    b53 = stwo_m31_mul(b59, b34);
    b27 = stwo_m31_mul(b60, b33);
    b81 = stwo_m31_add(b53, b27);
    b27 = stwo_m31_mul(b61, b32);
    b53 = stwo_m31_add(b81, b27);
    b27 = stwo_m31_mul(b62, b31);
    b81 = stwo_m31_add(b53, b27);
    b27 = stwo_m31_mul(b60, b34);
    b53 = stwo_m31_mul(b61, b33);
    b78 = stwo_m31_add(b27, b53);
    b53 = stwo_m31_mul(b62, b32);
    b27 = stwo_m31_add(b78, b53);
    b53 = stwo_m31_add(b49, b56);
    b56 = stwo_m31_add(b50, b57);
    b57 = stwo_m31_add(b51, b58);
    b78 = stwo_m31_add(b52, b59);
    b76 = stwo_m31_add(b21, b28);
    b28 = stwo_m31_add(b22, b29);
    b29 = stwo_m31_add(b23, b30);
    b15 = stwo_m31_add(b24, b31);
    b79 = stwo_m31_mul(b53, b28);
    b6 = stwo_m31_mul(b56, b76);
    b72 = stwo_m31_add(b79, b6);
    b6 = stwo_m31_sub(b72, b11);
    b72 = stwo_m31_sub(b6, b25);
    b6 = stwo_m31_add(b40, b72);
    b72 = stwo_m31_mul(b53, b29);
    b40 = stwo_m31_mul(b56, b28);
    b25 = stwo_m31_add(b72, b40);
    b40 = stwo_m31_mul(b57, b76);
    b72 = stwo_m31_add(b25, b40);
    b40 = stwo_m31_sub(b72, b75);
    b72 = stwo_m31_sub(b40, b54);
    b40 = stwo_m31_add(b86, b72);
    b72 = stwo_m31_mul(b53, b15);
    b15 = stwo_m31_mul(b56, b29);
    b29 = stwo_m31_add(b72, b15);
    b15 = stwo_m31_mul(b57, b28);
    b28 = stwo_m31_add(b29, b15);
    b15 = stwo_m31_mul(b78, b76);
    b76 = stwo_m31_add(b28, b15);
    b15 = stwo_m31_sub(b76, b87);
    b76 = stwo_m31_sub(b15, b26);
    b15 = stwo_m31_add(b55, b76);
    b76 = stwo_m31_add(b35, b49);
    b49 = stwo_m31_add(b36, b50);
    b50 = stwo_m31_add(b37, b51);
    b51 = stwo_m31_add(b38, b52);
    b52 = stwo_m31_add(b44, b58);
    b58 = stwo_m31_add(b45, b59);
    b59 = stwo_m31_add(b46, b60);
    b60 = stwo_m31_add(b47, b61);
    b61 = stwo_m31_add(b48, b62);
    b62 = stwo_m31_add(b7, b21);
    b21 = stwo_m31_add(b8, b22);
    b22 = stwo_m31_add(b9, b23);
    b23 = stwo_m31_add(b10, b24);
    b24 = stwo_m31_add(b16, b30);
    b30 = stwo_m31_add(b17, b31);
    b31 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_add(b19, b33);
    b33 = stwo_m31_add(b20, b34);
    b34 = stwo_m31_mul(b76, b62);
    b20 = stwo_m31_mul(b76, b21);
    b19 = stwo_m31_mul(b49, b62);
    b18 = stwo_m31_add(b20, b19);
    b19 = stwo_m31_mul(b76, b22);
    b20 = stwo_m31_mul(b49, b21);
    b17 = stwo_m31_add(b19, b20);
    b20 = stwo_m31_mul(b50, b62);
    b19 = stwo_m31_add(b17, b20);
    b20 = stwo_m31_mul(b76, b23);
    b23 = stwo_m31_mul(b49, b22);
    b22 = stwo_m31_add(b20, b23);
    b23 = stwo_m31_mul(b50, b21);
    b21 = stwo_m31_add(b22, b23);
    b23 = stwo_m31_mul(b51, b62);
    b62 = stwo_m31_add(b21, b23);
    b23 = stwo_m31_mul(b52, b33);
    b52 = stwo_m31_mul(b58, b32);
    b21 = stwo_m31_add(b23, b52);
    b52 = stwo_m31_mul(b59, b31);
    b23 = stwo_m31_add(b21, b52);
    b52 = stwo_m31_mul(b60, b30);
    b21 = stwo_m31_add(b23, b52);
    b52 = stwo_m31_mul(b61, b24);
    b24 = stwo_m31_add(b21, b52);
    b52 = stwo_m31_mul(b58, b33);
    b58 = stwo_m31_mul(b59, b32);
    b21 = stwo_m31_add(b52, b58);
    b58 = stwo_m31_mul(b60, b31);
    b52 = stwo_m31_add(b21, b58);
    b58 = stwo_m31_mul(b61, b30);
    b30 = stwo_m31_add(b52, b58);
    b58 = stwo_m31_mul(b59, b33);
    b33 = stwo_m31_mul(b60, b32);
    b32 = stwo_m31_add(b58, b33);
    b33 = stwo_m31_mul(b61, b31);
    b31 = stwo_m31_add(b32, b33);
    b33 = stwo_m31_sub(b34, b68);
    b34 = stwo_m31_sub(b33, b88);
    b33 = stwo_m31_add(b42, b34);
    b34 = stwo_m31_sub(b18, b71);
    b18 = stwo_m31_sub(b34, b11);
    b34 = stwo_m31_add(b43, b18);
    b18 = stwo_m31_sub(b19, b70);
    b19 = stwo_m31_sub(b18, b75);
    b18 = stwo_m31_add(b85, b19);
    b19 = stwo_m31_sub(b62, b73);
    b62 = stwo_m31_sub(b19, b87);
    b19 = stwo_m31_add(b12, b62);
    b62 = stwo_m31_sub(b24, b77);
    b24 = stwo_m31_sub(b62, b39);
    b62 = stwo_m31_add(b6, b24);
    b24 = stwo_m31_sub(b30, b84);
    b30 = stwo_m31_sub(b24, b81);
    b24 = stwo_m31_add(b40, b30);
    b30 = stwo_m31_sub(b31, b83);
    b31 = stwo_m31_sub(b30, b27);
    b30 = stwo_m31_add(b15, b31);
    b31 = stwo_m31_sub(b89, b69);
    b89 = stwo_m31_sub(b13, b0);
    b13 = stwo_m31_sub(b80, b1);
    b80 = stwo_m31_sub(b33, b2);
    b33 = stwo_m31_sub(b34, b3);
    b34 = stwo_m31_sub(b18, b4);
    b18 = stwo_m31_sub(b19, b5);
    b19 = 2u;
    b5 = stwo_m31_mul(b19, b31);
    b19 = stwo_m31_add(b5, b80);
    b5 = 32u;
    b80 = stwo_m31_mul(b5, b33);
    b5 = stwo_m31_add(b19, b80);
    b80 = 4u;
    b19 = stwo_m31_mul(b80, b62);
    b80 = stwo_m31_sub(b5, b19);
    b19 = 2u;
    b5 = stwo_m31_mul(b19, b89);
    b19 = stwo_m31_add(b5, b33);
    b5 = 32u;
    b33 = stwo_m31_mul(b5, b34);
    b5 = stwo_m31_add(b19, b33);
    b33 = 4u;
    b19 = stwo_m31_mul(b33, b24);
    b33 = stwo_m31_sub(b5, b19);
    b19 = 2u;
    b5 = stwo_m31_mul(b19, b13);
    b19 = stwo_m31_add(b5, b34);
    b5 = 32u;
    b34 = stwo_m31_mul(b5, b18);
    b5 = stwo_m31_add(b19, b34);
    b34 = 4u;
    b19 = stwo_m31_mul(b34, b30);
    b34 = stwo_m31_sub(b5, b19);
    b19 = 512u;
    b5 = stwo_m31_mul(b64, b19);
    b19 = stwo_m31_add(b80, b63);
    b80 = stwo_m31_sub(b5, b19);
    b19 = 512u;
    b5 = stwo_m31_mul(b65, b19);
    b19 = stwo_m31_add(b33, b64);
    b33 = stwo_m31_sub(b5, b19);
    b19 = 512u;
    b5 = stwo_m31_mul(b66, b19);
    b19 = stwo_m31_add(b34, b65);
    b34 = stwo_m31_sub(b5, b19);
    StwoCairoQm31 e0 = { b80, b67, b67, b67 };
    StwoCairoQm31 e1 = { b33, b67, b67, b67 };
    StwoCairoQm31 e2 = { b34, b67, b67, b67 };
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
