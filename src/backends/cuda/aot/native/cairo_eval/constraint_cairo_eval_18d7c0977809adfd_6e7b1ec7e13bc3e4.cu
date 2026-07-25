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
stwo_cairo_cuda_eval_v1_842ee1ad34fe008f(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 374u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 375u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 376u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 396u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 397u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 426u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 427u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 428u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 429u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 430u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 431u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 432u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 433u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 434u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 435u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 436u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 437u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 438u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 439u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 440u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 441u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 442u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 443u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 444u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 445u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 446u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 447u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 448u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 449u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 450u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 451u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 452u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 453u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 455u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 456u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 457u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 458u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 459u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 460u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 461u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 462u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 463u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 464u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 465u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 466u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 467u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 468u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 469u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 470u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 471u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 472u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 473u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 474u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 475u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 476u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 477u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 478u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 479u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 480u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 481u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 482u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 488u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 489u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 490u, row, 0);
    unsigned b64 = 0u;
    unsigned b65 = 3u;
    unsigned b66 = stwo_m31_mul(b65, b0);
    b65 = 3u;
    b0 = stwo_m31_mul(b65, b1);
    b65 = 3u;
    b1 = stwo_m31_mul(b65, b2);
    b65 = 3u;
    b2 = stwo_m31_mul(b65, b3);
    b65 = 3u;
    b3 = stwo_m31_mul(b65, b4);
    b65 = stwo_m31_mul(b33, b9);
    b4 = stwo_m31_mul(b34, b8);
    unsigned b67 = stwo_m31_add(b65, b4);
    b4 = stwo_m31_mul(b35, b7);
    b65 = stwo_m31_add(b67, b4);
    b4 = stwo_m31_mul(b36, b6);
    b67 = stwo_m31_add(b65, b4);
    b4 = stwo_m31_mul(b37, b5);
    b65 = stwo_m31_add(b67, b4);
    b4 = stwo_m31_mul(b33, b10);
    b67 = stwo_m31_mul(b34, b9);
    unsigned b68 = stwo_m31_add(b4, b67);
    b67 = stwo_m31_mul(b35, b8);
    b4 = stwo_m31_add(b68, b67);
    b67 = stwo_m31_mul(b36, b7);
    b68 = stwo_m31_add(b4, b67);
    b67 = stwo_m31_mul(b37, b6);
    b4 = stwo_m31_add(b68, b67);
    b67 = stwo_m31_mul(b38, b5);
    b68 = stwo_m31_add(b4, b67);
    b67 = stwo_m31_mul(b33, b11);
    b4 = stwo_m31_mul(b34, b10);
    unsigned b69 = stwo_m31_add(b67, b4);
    b4 = stwo_m31_mul(b35, b9);
    b67 = stwo_m31_add(b69, b4);
    b4 = stwo_m31_mul(b36, b8);
    b69 = stwo_m31_add(b67, b4);
    b4 = stwo_m31_mul(b37, b7);
    b67 = stwo_m31_add(b69, b4);
    b4 = stwo_m31_mul(b38, b6);
    b69 = stwo_m31_add(b67, b4);
    b4 = stwo_m31_mul(b39, b5);
    b67 = stwo_m31_add(b69, b4);
    b4 = stwo_m31_mul(b39, b11);
    b69 = stwo_m31_mul(b40, b17);
    unsigned b70 = stwo_m31_mul(b41, b16);
    unsigned b71 = stwo_m31_add(b69, b70);
    b70 = stwo_m31_mul(b42, b15);
    b69 = stwo_m31_add(b71, b70);
    b70 = stwo_m31_mul(b43, b14);
    b71 = stwo_m31_add(b69, b70);
    b70 = stwo_m31_mul(b44, b13);
    b69 = stwo_m31_add(b71, b70);
    b70 = stwo_m31_mul(b45, b12);
    b71 = stwo_m31_add(b69, b70);
    b70 = stwo_m31_mul(b40, b18);
    b69 = stwo_m31_mul(b41, b17);
    unsigned b72 = stwo_m31_add(b70, b69);
    b69 = stwo_m31_mul(b42, b16);
    b70 = stwo_m31_add(b72, b69);
    b69 = stwo_m31_mul(b43, b15);
    b72 = stwo_m31_add(b70, b69);
    b69 = stwo_m31_mul(b44, b14);
    b70 = stwo_m31_add(b72, b69);
    b69 = stwo_m31_mul(b45, b13);
    b72 = stwo_m31_add(b70, b69);
    b69 = stwo_m31_mul(b46, b12);
    b70 = stwo_m31_add(b72, b69);
    b69 = stwo_m31_mul(b46, b18);
    b72 = stwo_m31_add(b33, b40);
    unsigned b73 = stwo_m31_add(b34, b41);
    unsigned b74 = stwo_m31_add(b35, b42);
    unsigned b75 = stwo_m31_add(b36, b43);
    unsigned b76 = stwo_m31_add(b37, b44);
    unsigned b77 = stwo_m31_add(b38, b45);
    unsigned b78 = stwo_m31_add(b39, b46);
    unsigned b79 = stwo_m31_add(b5, b12);
    unsigned b80 = stwo_m31_add(b6, b13);
    unsigned b81 = stwo_m31_add(b7, b14);
    unsigned b82 = stwo_m31_add(b8, b15);
    unsigned b83 = stwo_m31_add(b9, b16);
    unsigned b84 = stwo_m31_add(b10, b17);
    unsigned b85 = stwo_m31_add(b11, b18);
    unsigned b86 = stwo_m31_mul(b72, b84);
    unsigned b87 = stwo_m31_mul(b73, b83);
    unsigned b88 = stwo_m31_add(b86, b87);
    b87 = stwo_m31_mul(b74, b82);
    b86 = stwo_m31_add(b88, b87);
    b87 = stwo_m31_mul(b75, b81);
    b88 = stwo_m31_add(b86, b87);
    b87 = stwo_m31_mul(b76, b80);
    b86 = stwo_m31_add(b88, b87);
    b87 = stwo_m31_mul(b77, b79);
    b88 = stwo_m31_add(b86, b87);
    b87 = stwo_m31_sub(b88, b68);
    b88 = stwo_m31_sub(b87, b71);
    b87 = stwo_m31_add(b4, b88);
    b88 = stwo_m31_mul(b72, b85);
    b85 = stwo_m31_mul(b73, b84);
    b84 = stwo_m31_add(b88, b85);
    b85 = stwo_m31_mul(b74, b83);
    b83 = stwo_m31_add(b84, b85);
    b85 = stwo_m31_mul(b75, b82);
    b82 = stwo_m31_add(b83, b85);
    b85 = stwo_m31_mul(b76, b81);
    b81 = stwo_m31_add(b82, b85);
    b85 = stwo_m31_mul(b77, b80);
    b80 = stwo_m31_add(b81, b85);
    b85 = stwo_m31_mul(b78, b79);
    b79 = stwo_m31_add(b80, b85);
    b85 = stwo_m31_sub(b79, b67);
    b79 = stwo_m31_sub(b85, b70);
    b85 = stwo_m31_mul(b47, b24);
    b70 = stwo_m31_mul(b48, b23);
    b80 = stwo_m31_add(b85, b70);
    b70 = stwo_m31_mul(b49, b22);
    b85 = stwo_m31_add(b80, b70);
    b70 = stwo_m31_mul(b50, b21);
    b80 = stwo_m31_add(b85, b70);
    b70 = stwo_m31_mul(b51, b20);
    b85 = stwo_m31_add(b80, b70);
    b70 = stwo_m31_mul(b52, b19);
    b80 = stwo_m31_add(b85, b70);
    b70 = stwo_m31_mul(b47, b25);
    b85 = stwo_m31_mul(b48, b24);
    b78 = stwo_m31_add(b70, b85);
    b85 = stwo_m31_mul(b49, b23);
    b70 = stwo_m31_add(b78, b85);
    b85 = stwo_m31_mul(b50, b22);
    b78 = stwo_m31_add(b70, b85);
    b85 = stwo_m31_mul(b51, b21);
    b70 = stwo_m31_add(b78, b85);
    b85 = stwo_m31_mul(b52, b20);
    b78 = stwo_m31_add(b70, b85);
    b85 = stwo_m31_mul(b53, b19);
    b70 = stwo_m31_add(b78, b85);
    b85 = stwo_m31_mul(b53, b25);
    b78 = stwo_m31_mul(b54, b31);
    b81 = stwo_m31_mul(b55, b30);
    b77 = stwo_m31_add(b78, b81);
    b81 = stwo_m31_mul(b56, b29);
    b78 = stwo_m31_add(b77, b81);
    b81 = stwo_m31_mul(b57, b28);
    b77 = stwo_m31_add(b78, b81);
    b81 = stwo_m31_mul(b58, b27);
    b78 = stwo_m31_add(b77, b81);
    b81 = stwo_m31_mul(b59, b26);
    b77 = stwo_m31_add(b78, b81);
    b81 = stwo_m31_mul(b54, b32);
    b78 = stwo_m31_mul(b55, b31);
    b82 = stwo_m31_add(b81, b78);
    b78 = stwo_m31_mul(b56, b30);
    b81 = stwo_m31_add(b82, b78);
    b78 = stwo_m31_mul(b57, b29);
    b82 = stwo_m31_add(b81, b78);
    b78 = stwo_m31_mul(b58, b28);
    b81 = stwo_m31_add(b82, b78);
    b78 = stwo_m31_mul(b59, b27);
    b82 = stwo_m31_add(b81, b78);
    b78 = stwo_m31_mul(b60, b26);
    b81 = stwo_m31_add(b82, b78);
    b78 = stwo_m31_mul(b60, b32);
    b82 = stwo_m31_add(b47, b54);
    b76 = stwo_m31_add(b48, b55);
    b83 = stwo_m31_add(b49, b56);
    b75 = stwo_m31_add(b50, b57);
    b84 = stwo_m31_add(b51, b58);
    b74 = stwo_m31_add(b52, b59);
    b88 = stwo_m31_add(b53, b60);
    b73 = stwo_m31_add(b19, b26);
    b72 = stwo_m31_add(b20, b27);
    b4 = stwo_m31_add(b21, b28);
    b71 = stwo_m31_add(b22, b29);
    b86 = stwo_m31_add(b23, b30);
    unsigned b89 = stwo_m31_add(b24, b31);
    unsigned b90 = stwo_m31_add(b25, b32);
    unsigned b91 = stwo_m31_mul(b82, b89);
    unsigned b92 = stwo_m31_mul(b76, b86);
    unsigned b93 = stwo_m31_add(b91, b92);
    b92 = stwo_m31_mul(b83, b71);
    b91 = stwo_m31_add(b93, b92);
    b92 = stwo_m31_mul(b75, b4);
    b93 = stwo_m31_add(b91, b92);
    b92 = stwo_m31_mul(b84, b72);
    b91 = stwo_m31_add(b93, b92);
    b92 = stwo_m31_mul(b74, b73);
    b93 = stwo_m31_add(b91, b92);
    b92 = stwo_m31_sub(b93, b80);
    b93 = stwo_m31_sub(b92, b77);
    b92 = stwo_m31_add(b85, b93);
    b93 = stwo_m31_mul(b82, b90);
    b90 = stwo_m31_mul(b76, b89);
    b89 = stwo_m31_add(b93, b90);
    b90 = stwo_m31_mul(b83, b86);
    b86 = stwo_m31_add(b89, b90);
    b90 = stwo_m31_mul(b75, b71);
    b71 = stwo_m31_add(b86, b90);
    b90 = stwo_m31_mul(b84, b4);
    b4 = stwo_m31_add(b71, b90);
    b90 = stwo_m31_mul(b74, b72);
    b72 = stwo_m31_add(b4, b90);
    b90 = stwo_m31_mul(b88, b73);
    b73 = stwo_m31_add(b72, b90);
    b90 = stwo_m31_sub(b73, b70);
    b73 = stwo_m31_sub(b90, b81);
    b90 = stwo_m31_add(b33, b47);
    b47 = stwo_m31_add(b34, b48);
    b48 = stwo_m31_add(b35, b49);
    b49 = stwo_m31_add(b36, b50);
    b50 = stwo_m31_add(b37, b51);
    b51 = stwo_m31_add(b38, b52);
    b52 = stwo_m31_add(b39, b53);
    b53 = stwo_m31_add(b40, b54);
    b54 = stwo_m31_add(b41, b55);
    b55 = stwo_m31_add(b42, b56);
    b56 = stwo_m31_add(b43, b57);
    b57 = stwo_m31_add(b44, b58);
    b58 = stwo_m31_add(b45, b59);
    b59 = stwo_m31_add(b46, b60);
    b60 = stwo_m31_add(b5, b19);
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
    b32 = stwo_m31_mul(b90, b23);
    b18 = stwo_m31_mul(b47, b22);
    b17 = stwo_m31_add(b32, b18);
    b18 = stwo_m31_mul(b48, b21);
    b32 = stwo_m31_add(b17, b18);
    b18 = stwo_m31_mul(b49, b20);
    b17 = stwo_m31_add(b32, b18);
    b18 = stwo_m31_mul(b50, b19);
    b32 = stwo_m31_add(b17, b18);
    b18 = stwo_m31_mul(b51, b60);
    b17 = stwo_m31_add(b32, b18);
    b18 = stwo_m31_mul(b90, b24);
    b32 = stwo_m31_mul(b47, b23);
    b16 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_mul(b48, b22);
    b18 = stwo_m31_add(b16, b32);
    b32 = stwo_m31_mul(b49, b21);
    b16 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_mul(b50, b20);
    b18 = stwo_m31_add(b16, b32);
    b32 = stwo_m31_mul(b51, b19);
    b16 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_mul(b52, b60);
    b18 = stwo_m31_add(b16, b32);
    b32 = stwo_m31_mul(b52, b24);
    b16 = stwo_m31_mul(b53, b30);
    b15 = stwo_m31_mul(b54, b29);
    b14 = stwo_m31_add(b16, b15);
    b15 = stwo_m31_mul(b55, b28);
    b16 = stwo_m31_add(b14, b15);
    b15 = stwo_m31_mul(b56, b27);
    b14 = stwo_m31_add(b16, b15);
    b15 = stwo_m31_mul(b57, b26);
    b16 = stwo_m31_add(b14, b15);
    b15 = stwo_m31_mul(b58, b25);
    b14 = stwo_m31_add(b16, b15);
    b15 = stwo_m31_mul(b53, b31);
    b16 = stwo_m31_mul(b54, b30);
    b13 = stwo_m31_add(b15, b16);
    b16 = stwo_m31_mul(b55, b29);
    b15 = stwo_m31_add(b13, b16);
    b16 = stwo_m31_mul(b56, b28);
    b13 = stwo_m31_add(b15, b16);
    b16 = stwo_m31_mul(b57, b27);
    b15 = stwo_m31_add(b13, b16);
    b16 = stwo_m31_mul(b58, b26);
    b13 = stwo_m31_add(b15, b16);
    b16 = stwo_m31_mul(b59, b25);
    b15 = stwo_m31_add(b13, b16);
    b16 = stwo_m31_add(b90, b53);
    b53 = stwo_m31_add(b47, b54);
    b54 = stwo_m31_add(b48, b55);
    b55 = stwo_m31_add(b49, b56);
    b56 = stwo_m31_add(b50, b57);
    b57 = stwo_m31_add(b51, b58);
    b58 = stwo_m31_add(b52, b59);
    b59 = stwo_m31_add(b60, b25);
    b25 = stwo_m31_add(b19, b26);
    b26 = stwo_m31_add(b20, b27);
    b27 = stwo_m31_add(b21, b28);
    b28 = stwo_m31_add(b22, b29);
    b29 = stwo_m31_add(b23, b30);
    b30 = stwo_m31_add(b24, b31);
    b31 = stwo_m31_mul(b16, b29);
    b24 = stwo_m31_mul(b53, b28);
    b23 = stwo_m31_add(b31, b24);
    b24 = stwo_m31_mul(b54, b27);
    b31 = stwo_m31_add(b23, b24);
    b24 = stwo_m31_mul(b55, b26);
    b23 = stwo_m31_add(b31, b24);
    b24 = stwo_m31_mul(b56, b25);
    b31 = stwo_m31_add(b23, b24);
    b24 = stwo_m31_mul(b57, b59);
    b23 = stwo_m31_add(b31, b24);
    b24 = stwo_m31_sub(b23, b17);
    b23 = stwo_m31_sub(b24, b14);
    b24 = stwo_m31_add(b32, b23);
    b23 = stwo_m31_mul(b16, b30);
    b30 = stwo_m31_mul(b53, b29);
    b29 = stwo_m31_add(b23, b30);
    b30 = stwo_m31_mul(b54, b28);
    b28 = stwo_m31_add(b29, b30);
    b30 = stwo_m31_mul(b55, b27);
    b27 = stwo_m31_add(b28, b30);
    b30 = stwo_m31_mul(b56, b26);
    b26 = stwo_m31_add(b27, b30);
    b30 = stwo_m31_mul(b57, b25);
    b25 = stwo_m31_add(b26, b30);
    b30 = stwo_m31_mul(b58, b59);
    b59 = stwo_m31_add(b25, b30);
    b30 = stwo_m31_sub(b59, b18);
    b59 = stwo_m31_sub(b30, b15);
    b30 = stwo_m31_sub(b24, b87);
    b24 = stwo_m31_sub(b30, b92);
    b30 = stwo_m31_add(b69, b24);
    b24 = stwo_m31_sub(b59, b79);
    b59 = stwo_m31_sub(b24, b73);
    b24 = stwo_m31_sub(b65, b66);
    b65 = stwo_m31_sub(b68, b0);
    b68 = stwo_m31_sub(b67, b1);
    b67 = stwo_m31_sub(b30, b2);
    b30 = stwo_m31_sub(b59, b3);
    b59 = 32u;
    b3 = stwo_m31_mul(b59, b65);
    b59 = stwo_m31_add(b24, b3);
    b3 = 4u;
    b24 = stwo_m31_mul(b3, b67);
    b3 = stwo_m31_sub(b59, b24);
    b24 = 8u;
    b59 = stwo_m31_mul(b24, b78);
    b24 = stwo_m31_add(b3, b59);
    b59 = 32u;
    b3 = stwo_m31_mul(b59, b68);
    b59 = stwo_m31_add(b65, b3);
    b3 = 4u;
    b65 = stwo_m31_mul(b3, b30);
    b3 = stwo_m31_sub(b59, b65);
    b65 = 512u;
    b59 = stwo_m31_mul(b62, b65);
    b65 = stwo_m31_add(b24, b61);
    b24 = stwo_m31_sub(b59, b65);
    b65 = 512u;
    b59 = stwo_m31_mul(b63, b65);
    b65 = stwo_m31_add(b3, b62);
    b3 = stwo_m31_sub(b59, b65);
    StwoCairoQm31 e0 = { b24, b64, b64, b64 };
    StwoCairoQm31 e1 = { b3, b64, b64, b64 };
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
