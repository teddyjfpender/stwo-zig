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
stwo_cairo_cuda_eval_v1_cf2257f6104b47f4(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 390u, row, 0);
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
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 483u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 510u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 511u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 512u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 532u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 533u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 539u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 540u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 541u, row, 0);
    unsigned b70 = 0u;
    unsigned b71 = 3u;
    unsigned b72 = stwo_m31_mul(b71, b4);
    b71 = stwo_m31_mul(b33, b11);
    b4 = stwo_m31_mul(b34, b10);
    unsigned b73 = stwo_m31_add(b71, b4);
    b4 = stwo_m31_mul(b35, b9);
    b71 = stwo_m31_add(b73, b4);
    b4 = stwo_m31_mul(b36, b8);
    b73 = stwo_m31_add(b71, b4);
    b4 = stwo_m31_mul(b37, b7);
    b71 = stwo_m31_add(b73, b4);
    b4 = stwo_m31_mul(b38, b6);
    b73 = stwo_m31_add(b71, b4);
    b4 = stwo_m31_mul(b39, b5);
    b71 = stwo_m31_add(b73, b4);
    b4 = stwo_m31_mul(b40, b18);
    b18 = stwo_m31_mul(b41, b17);
    b17 = stwo_m31_add(b4, b18);
    b18 = stwo_m31_mul(b42, b16);
    b16 = stwo_m31_add(b17, b18);
    b18 = stwo_m31_mul(b43, b15);
    b15 = stwo_m31_add(b16, b18);
    b18 = stwo_m31_mul(b44, b14);
    b14 = stwo_m31_add(b15, b18);
    b18 = stwo_m31_mul(b45, b13);
    b13 = stwo_m31_add(b14, b18);
    b18 = stwo_m31_mul(b46, b12);
    b12 = stwo_m31_add(b13, b18);
    b18 = stwo_m31_mul(b47, b25);
    b13 = stwo_m31_mul(b48, b24);
    b14 = stwo_m31_add(b18, b13);
    b13 = stwo_m31_mul(b49, b23);
    b18 = stwo_m31_add(b14, b13);
    b13 = stwo_m31_mul(b50, b22);
    b14 = stwo_m31_add(b18, b13);
    b13 = stwo_m31_mul(b51, b21);
    b18 = stwo_m31_add(b14, b13);
    b13 = stwo_m31_mul(b52, b20);
    b14 = stwo_m31_add(b18, b13);
    b13 = stwo_m31_mul(b53, b19);
    b18 = stwo_m31_add(b14, b13);
    b13 = stwo_m31_mul(b54, b32);
    b14 = stwo_m31_mul(b55, b31);
    b31 = stwo_m31_add(b13, b14);
    b14 = stwo_m31_mul(b56, b30);
    b30 = stwo_m31_add(b31, b14);
    b14 = stwo_m31_mul(b57, b29);
    b29 = stwo_m31_add(b30, b14);
    b14 = stwo_m31_mul(b58, b28);
    b28 = stwo_m31_add(b29, b14);
    b14 = stwo_m31_mul(b59, b27);
    b27 = stwo_m31_add(b28, b14);
    b14 = stwo_m31_mul(b60, b26);
    b26 = stwo_m31_add(b27, b14);
    b14 = stwo_m31_mul(b60, b32);
    b32 = stwo_m31_add(b33, b47);
    b27 = stwo_m31_add(b34, b48);
    b28 = stwo_m31_add(b35, b49);
    b29 = stwo_m31_add(b36, b50);
    b30 = stwo_m31_add(b37, b51);
    b31 = stwo_m31_add(b38, b52);
    b13 = stwo_m31_add(b39, b53);
    b15 = stwo_m31_add(b5, b19);
    b19 = stwo_m31_add(b6, b20);
    b20 = stwo_m31_add(b7, b21);
    b21 = stwo_m31_add(b8, b22);
    b22 = stwo_m31_add(b9, b23);
    b23 = stwo_m31_add(b10, b24);
    b24 = stwo_m31_add(b11, b25);
    b25 = stwo_m31_mul(b32, b24);
    b24 = stwo_m31_mul(b27, b23);
    b23 = stwo_m31_add(b25, b24);
    b24 = stwo_m31_mul(b28, b22);
    b22 = stwo_m31_add(b23, b24);
    b24 = stwo_m31_mul(b29, b21);
    b21 = stwo_m31_add(b22, b24);
    b24 = stwo_m31_mul(b30, b20);
    b20 = stwo_m31_add(b21, b24);
    b24 = stwo_m31_mul(b31, b19);
    b19 = stwo_m31_add(b20, b24);
    b24 = stwo_m31_mul(b13, b15);
    b15 = stwo_m31_add(b19, b24);
    b24 = stwo_m31_sub(b15, b71);
    b15 = stwo_m31_sub(b24, b18);
    b24 = stwo_m31_add(b12, b15);
    b15 = stwo_m31_sub(b24, b72);
    b24 = 2u;
    b72 = stwo_m31_mul(b24, b15);
    b24 = 4u;
    b15 = stwo_m31_mul(b24, b26);
    b24 = stwo_m31_sub(b72, b15);
    b15 = 2u;
    b72 = stwo_m31_mul(b15, b14);
    b15 = stwo_m31_add(b24, b72);
    b72 = 256u;
    b24 = stwo_m31_mul(b72, b61);
    b72 = stwo_m31_sub(b15, b24);
    b24 = stwo_m31_add(b72, b62);
    b72 = stwo_m31_add(b0, b0);
    b0 = stwo_m31_add(b72, b63);
    b72 = stwo_m31_add(b1, b1);
    b1 = stwo_m31_add(b72, b64);
    b72 = stwo_m31_add(b2, b2);
    b2 = stwo_m31_add(b72, b65);
    b72 = stwo_m31_add(b3, b3);
    b3 = stwo_m31_add(b72, b66);
    b72 = stwo_m31_mul(b33, b33);
    b66 = stwo_m31_mul(b33, b34);
    b65 = stwo_m31_mul(b34, b33);
    b64 = stwo_m31_add(b66, b65);
    b65 = stwo_m31_mul(b34, b39);
    b66 = stwo_m31_mul(b35, b38);
    b63 = stwo_m31_add(b65, b66);
    b66 = stwo_m31_mul(b36, b37);
    b65 = stwo_m31_add(b63, b66);
    b66 = stwo_m31_mul(b37, b36);
    b63 = stwo_m31_add(b65, b66);
    b66 = stwo_m31_mul(b38, b35);
    b65 = stwo_m31_add(b63, b66);
    b66 = stwo_m31_mul(b39, b34);
    b63 = stwo_m31_add(b65, b66);
    b66 = stwo_m31_mul(b35, b39);
    b65 = stwo_m31_mul(b36, b38);
    b62 = stwo_m31_add(b66, b65);
    b65 = stwo_m31_mul(b37, b37);
    b66 = stwo_m31_add(b62, b65);
    b65 = stwo_m31_mul(b38, b36);
    b62 = stwo_m31_add(b66, b65);
    b65 = stwo_m31_mul(b39, b35);
    b66 = stwo_m31_add(b62, b65);
    b65 = stwo_m31_mul(b40, b40);
    b62 = stwo_m31_mul(b40, b41);
    b15 = stwo_m31_mul(b41, b40);
    b61 = stwo_m31_add(b62, b15);
    b15 = stwo_m31_mul(b41, b46);
    b62 = stwo_m31_mul(b42, b45);
    b14 = stwo_m31_add(b15, b62);
    b62 = stwo_m31_mul(b43, b44);
    b15 = stwo_m31_add(b14, b62);
    b62 = stwo_m31_mul(b44, b43);
    b14 = stwo_m31_add(b15, b62);
    b62 = stwo_m31_mul(b45, b42);
    b15 = stwo_m31_add(b14, b62);
    b62 = stwo_m31_mul(b46, b41);
    b14 = stwo_m31_add(b15, b62);
    b62 = stwo_m31_mul(b42, b46);
    b15 = stwo_m31_mul(b43, b45);
    b26 = stwo_m31_add(b62, b15);
    b15 = stwo_m31_mul(b44, b44);
    b44 = stwo_m31_add(b26, b15);
    b15 = stwo_m31_mul(b45, b43);
    b45 = stwo_m31_add(b44, b15);
    b15 = stwo_m31_mul(b46, b42);
    b46 = stwo_m31_add(b45, b15);
    b15 = stwo_m31_add(b33, b40);
    b45 = stwo_m31_add(b34, b41);
    b42 = stwo_m31_add(b33, b40);
    b44 = stwo_m31_add(b34, b41);
    b43 = stwo_m31_mul(b15, b42);
    b26 = stwo_m31_sub(b43, b72);
    b43 = stwo_m31_sub(b26, b65);
    b26 = stwo_m31_add(b63, b43);
    b43 = stwo_m31_mul(b15, b44);
    b44 = stwo_m31_mul(b45, b42);
    b42 = stwo_m31_add(b43, b44);
    b44 = stwo_m31_sub(b42, b64);
    b42 = stwo_m31_sub(b44, b61);
    b44 = stwo_m31_add(b66, b42);
    b42 = stwo_m31_mul(b47, b47);
    b66 = stwo_m31_mul(b47, b48);
    b61 = stwo_m31_mul(b48, b47);
    b43 = stwo_m31_add(b66, b61);
    b61 = stwo_m31_mul(b48, b53);
    b66 = stwo_m31_mul(b49, b52);
    b45 = stwo_m31_add(b61, b66);
    b66 = stwo_m31_mul(b50, b51);
    b61 = stwo_m31_add(b45, b66);
    b66 = stwo_m31_mul(b51, b50);
    b45 = stwo_m31_add(b61, b66);
    b66 = stwo_m31_mul(b52, b49);
    b61 = stwo_m31_add(b45, b66);
    b66 = stwo_m31_mul(b53, b48);
    b45 = stwo_m31_add(b61, b66);
    b66 = stwo_m31_mul(b49, b53);
    b61 = stwo_m31_mul(b50, b52);
    b15 = stwo_m31_add(b66, b61);
    b61 = stwo_m31_mul(b51, b51);
    b66 = stwo_m31_add(b15, b61);
    b61 = stwo_m31_mul(b52, b50);
    b15 = stwo_m31_add(b66, b61);
    b61 = stwo_m31_mul(b53, b49);
    b66 = stwo_m31_add(b15, b61);
    b61 = stwo_m31_mul(b54, b54);
    b15 = stwo_m31_mul(b54, b55);
    b63 = stwo_m31_mul(b55, b54);
    b65 = stwo_m31_add(b15, b63);
    b63 = stwo_m31_mul(b55, b60);
    b15 = stwo_m31_mul(b56, b59);
    b62 = stwo_m31_add(b63, b15);
    b15 = stwo_m31_mul(b57, b58);
    b63 = stwo_m31_add(b62, b15);
    b15 = stwo_m31_mul(b58, b57);
    b62 = stwo_m31_add(b63, b15);
    b15 = stwo_m31_mul(b59, b56);
    b63 = stwo_m31_add(b62, b15);
    b15 = stwo_m31_mul(b60, b55);
    b62 = stwo_m31_add(b63, b15);
    b15 = stwo_m31_mul(b56, b60);
    b63 = stwo_m31_mul(b57, b59);
    b12 = stwo_m31_add(b15, b63);
    b63 = stwo_m31_mul(b58, b58);
    b58 = stwo_m31_add(b12, b63);
    b63 = stwo_m31_mul(b59, b57);
    b59 = stwo_m31_add(b58, b63);
    b63 = stwo_m31_mul(b60, b56);
    b60 = stwo_m31_add(b59, b63);
    b63 = stwo_m31_add(b47, b54);
    b59 = stwo_m31_add(b48, b55);
    b56 = stwo_m31_add(b47, b54);
    b58 = stwo_m31_add(b48, b55);
    b57 = stwo_m31_mul(b63, b56);
    b12 = stwo_m31_sub(b57, b42);
    b57 = stwo_m31_sub(b12, b61);
    b12 = stwo_m31_add(b45, b57);
    b57 = stwo_m31_mul(b63, b58);
    b58 = stwo_m31_mul(b59, b56);
    b56 = stwo_m31_add(b57, b58);
    b58 = stwo_m31_sub(b56, b43);
    b56 = stwo_m31_sub(b58, b65);
    b58 = stwo_m31_add(b66, b56);
    b56 = stwo_m31_add(b33, b47);
    b66 = stwo_m31_add(b34, b48);
    b65 = stwo_m31_add(b35, b49);
    b43 = stwo_m31_add(b36, b50);
    b57 = stwo_m31_add(b37, b51);
    b59 = stwo_m31_add(b38, b52);
    b63 = stwo_m31_add(b39, b53);
    b45 = stwo_m31_add(b40, b54);
    b61 = stwo_m31_add(b41, b55);
    b42 = stwo_m31_add(b33, b47);
    b47 = stwo_m31_add(b34, b48);
    b48 = stwo_m31_add(b35, b49);
    b49 = stwo_m31_add(b36, b50);
    b50 = stwo_m31_add(b37, b51);
    b51 = stwo_m31_add(b38, b52);
    b52 = stwo_m31_add(b39, b53);
    b53 = stwo_m31_add(b40, b54);
    b54 = stwo_m31_add(b41, b55);
    b55 = stwo_m31_mul(b56, b42);
    b41 = stwo_m31_mul(b56, b47);
    b40 = stwo_m31_mul(b66, b42);
    b39 = stwo_m31_add(b41, b40);
    b40 = stwo_m31_mul(b66, b52);
    b41 = stwo_m31_mul(b65, b51);
    b38 = stwo_m31_add(b40, b41);
    b41 = stwo_m31_mul(b43, b50);
    b40 = stwo_m31_add(b38, b41);
    b41 = stwo_m31_mul(b57, b49);
    b38 = stwo_m31_add(b40, b41);
    b41 = stwo_m31_mul(b59, b48);
    b40 = stwo_m31_add(b38, b41);
    b41 = stwo_m31_mul(b63, b47);
    b38 = stwo_m31_add(b40, b41);
    b41 = stwo_m31_mul(b65, b52);
    b52 = stwo_m31_mul(b43, b51);
    b51 = stwo_m31_add(b41, b52);
    b52 = stwo_m31_mul(b57, b50);
    b50 = stwo_m31_add(b51, b52);
    b52 = stwo_m31_mul(b59, b49);
    b49 = stwo_m31_add(b50, b52);
    b52 = stwo_m31_mul(b63, b48);
    b48 = stwo_m31_add(b49, b52);
    b52 = stwo_m31_mul(b45, b53);
    b49 = stwo_m31_mul(b45, b54);
    b63 = stwo_m31_mul(b61, b53);
    b50 = stwo_m31_add(b49, b63);
    b63 = stwo_m31_add(b56, b45);
    b45 = stwo_m31_add(b66, b61);
    b61 = stwo_m31_add(b42, b53);
    b53 = stwo_m31_add(b47, b54);
    b54 = stwo_m31_mul(b63, b61);
    b47 = stwo_m31_sub(b54, b55);
    b54 = stwo_m31_sub(b47, b52);
    b47 = stwo_m31_add(b38, b54);
    b54 = stwo_m31_mul(b63, b53);
    b53 = stwo_m31_mul(b45, b61);
    b61 = stwo_m31_add(b54, b53);
    b53 = stwo_m31_sub(b61, b39);
    b61 = stwo_m31_sub(b53, b50);
    b53 = stwo_m31_add(b48, b61);
    b61 = stwo_m31_sub(b47, b26);
    b47 = stwo_m31_sub(b61, b12);
    b61 = stwo_m31_add(b14, b47);
    b47 = stwo_m31_sub(b53, b44);
    b53 = stwo_m31_sub(b47, b58);
    b47 = stwo_m31_add(b46, b53);
    b53 = stwo_m31_sub(b72, b0);
    b72 = stwo_m31_sub(b64, b1);
    b64 = stwo_m31_sub(b61, b2);
    b61 = stwo_m31_sub(b47, b3);
    b47 = 32u;
    b3 = stwo_m31_mul(b47, b53);
    b47 = 4u;
    b2 = stwo_m31_mul(b47, b64);
    b47 = stwo_m31_sub(b3, b2);
    b2 = 8u;
    b3 = stwo_m31_mul(b2, b62);
    b2 = stwo_m31_add(b47, b3);
    b3 = 32u;
    b47 = stwo_m31_mul(b3, b72);
    b3 = stwo_m31_add(b53, b47);
    b47 = 4u;
    b53 = stwo_m31_mul(b47, b61);
    b47 = stwo_m31_sub(b3, b53);
    b53 = 8u;
    b3 = stwo_m31_mul(b53, b60);
    b53 = stwo_m31_add(b47, b3);
    b3 = 512u;
    b47 = stwo_m31_mul(b68, b3);
    b3 = stwo_m31_sub(b2, b67);
    b2 = stwo_m31_sub(b47, b3);
    b3 = 512u;
    b47 = stwo_m31_mul(b69, b3);
    b3 = stwo_m31_add(b53, b68);
    b53 = stwo_m31_sub(b47, b3);
    StwoCairoQm31 e0 = { b24, b70, b70, b70 };
    StwoCairoQm31 e1 = { b2, b70, b70, b70 };
    StwoCairoQm31 e2 = { b53, b70, b70, b70 };
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
