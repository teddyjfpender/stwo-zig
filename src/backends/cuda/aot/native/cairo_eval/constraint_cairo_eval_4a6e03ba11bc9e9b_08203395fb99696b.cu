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
stwo_cairo_cuda_eval_v1_3333954a87dfbeb9(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 19u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 25u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 54u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 55u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 60u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 455u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 456u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 457u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 458u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 459u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 460u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 461u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 462u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 463u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 464u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 465u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 466u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 467u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 468u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 469u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 470u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 471u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 472u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 473u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 474u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 475u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 476u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 477u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 478u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 479u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 480u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 481u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 482u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 511u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 512u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 513u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 514u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 515u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 516u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 517u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 518u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 519u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 520u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 521u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 522u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 523u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 524u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 525u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 526u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 527u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 528u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 529u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 530u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 531u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 532u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 533u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 534u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 535u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 1u, 536u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 1u, 537u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 1u, 538u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 1u, 581u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 1u, 582u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 1u, 583u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 1u, 587u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 1u, 595u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 1u, 616u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 1u, 617u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 1u, 618u, row, 0);
    unsigned b96 = stwo_trace_value(arena, *args, 1u, 619u, row, 0);
    unsigned b97 = 0u;
    unsigned b98 = stwo_m31_sub(b0, b60);
    b60 = stwo_m31_sub(b1, b61);
    b61 = stwo_m31_sub(b2, b62);
    b62 = stwo_m31_sub(b3, b63);
    b63 = stwo_m31_sub(b4, b64);
    b64 = stwo_m31_sub(b5, b65);
    b65 = stwo_m31_sub(b6, b66);
    b66 = stwo_m31_sub(b7, b67);
    b67 = stwo_m31_sub(b8, b68);
    b68 = stwo_m31_sub(b9, b69);
    b69 = stwo_m31_sub(b10, b70);
    b70 = stwo_m31_sub(b11, b71);
    b71 = stwo_m31_sub(b12, b72);
    b72 = stwo_m31_sub(b13, b73);
    b73 = stwo_m31_sub(b14, b74);
    b74 = stwo_m31_sub(b15, b75);
    b75 = stwo_m31_sub(b16, b76);
    b76 = stwo_m31_sub(b17, b77);
    b77 = stwo_m31_sub(b18, b78);
    b78 = stwo_m31_sub(b19, b79);
    b79 = stwo_m31_sub(b20, b80);
    b80 = stwo_m31_sub(b21, b81);
    b81 = stwo_m31_sub(b22, b82);
    b82 = stwo_m31_sub(b23, b83);
    b83 = stwo_m31_sub(b24, b84);
    b84 = stwo_m31_sub(b25, b85);
    b85 = stwo_m31_sub(b26, b86);
    b86 = stwo_m31_sub(b27, b87);
    b87 = stwo_m31_add(b28, b88);
    b88 = stwo_m31_add(b29, b89);
    b89 = stwo_m31_add(b30, b90);
    b90 = stwo_m31_add(b31, b91);
    b91 = stwo_m31_mul(b32, b98);
    b31 = stwo_m31_mul(b32, b60);
    b30 = stwo_m31_mul(b33, b98);
    b29 = stwo_m31_add(b31, b30);
    b30 = stwo_m31_mul(b32, b61);
    b31 = stwo_m31_mul(b33, b60);
    b28 = stwo_m31_add(b30, b31);
    b31 = stwo_m31_mul(b34, b98);
    b30 = stwo_m31_add(b28, b31);
    b31 = stwo_m31_mul(b32, b65);
    b28 = stwo_m31_mul(b33, b64);
    b27 = stwo_m31_add(b31, b28);
    b28 = stwo_m31_mul(b34, b63);
    b31 = stwo_m31_add(b27, b28);
    b28 = stwo_m31_mul(b35, b62);
    b27 = stwo_m31_add(b31, b28);
    b28 = stwo_m31_mul(b36, b61);
    b31 = stwo_m31_add(b27, b28);
    b28 = stwo_m31_mul(b37, b60);
    b27 = stwo_m31_add(b31, b28);
    b28 = stwo_m31_mul(b38, b98);
    b31 = stwo_m31_add(b27, b28);
    b28 = stwo_m31_mul(b33, b65);
    b27 = stwo_m31_mul(b34, b64);
    b26 = stwo_m31_add(b28, b27);
    b27 = stwo_m31_mul(b35, b63);
    b28 = stwo_m31_add(b26, b27);
    b27 = stwo_m31_mul(b36, b62);
    b26 = stwo_m31_add(b28, b27);
    b27 = stwo_m31_mul(b37, b61);
    b28 = stwo_m31_add(b26, b27);
    b27 = stwo_m31_mul(b38, b60);
    b26 = stwo_m31_add(b28, b27);
    b27 = stwo_m31_mul(b34, b65);
    b28 = stwo_m31_mul(b35, b64);
    b25 = stwo_m31_add(b27, b28);
    b28 = stwo_m31_mul(b36, b63);
    b27 = stwo_m31_add(b25, b28);
    b28 = stwo_m31_mul(b37, b62);
    b25 = stwo_m31_add(b27, b28);
    b28 = stwo_m31_mul(b38, b61);
    b27 = stwo_m31_add(b25, b28);
    b28 = stwo_m31_mul(b35, b65);
    b25 = stwo_m31_mul(b36, b64);
    b24 = stwo_m31_add(b28, b25);
    b25 = stwo_m31_mul(b37, b63);
    b28 = stwo_m31_add(b24, b25);
    b25 = stwo_m31_mul(b38, b62);
    b24 = stwo_m31_add(b28, b25);
    b25 = stwo_m31_mul(b39, b66);
    b28 = stwo_m31_mul(b39, b67);
    b23 = stwo_m31_mul(b40, b66);
    b22 = stwo_m31_add(b28, b23);
    b23 = stwo_m31_mul(b39, b68);
    b28 = stwo_m31_mul(b40, b67);
    b21 = stwo_m31_add(b23, b28);
    b28 = stwo_m31_mul(b41, b66);
    b23 = stwo_m31_add(b21, b28);
    b28 = stwo_m31_mul(b39, b72);
    b39 = stwo_m31_mul(b40, b71);
    b21 = stwo_m31_add(b28, b39);
    b39 = stwo_m31_mul(b41, b70);
    b28 = stwo_m31_add(b21, b39);
    b39 = stwo_m31_mul(b42, b69);
    b21 = stwo_m31_add(b28, b39);
    b39 = stwo_m31_mul(b43, b68);
    b28 = stwo_m31_add(b21, b39);
    b39 = stwo_m31_mul(b44, b67);
    b21 = stwo_m31_add(b28, b39);
    b39 = stwo_m31_mul(b45, b66);
    b66 = stwo_m31_add(b21, b39);
    b39 = stwo_m31_mul(b40, b72);
    b21 = stwo_m31_mul(b41, b71);
    b28 = stwo_m31_add(b39, b21);
    b21 = stwo_m31_mul(b42, b70);
    b39 = stwo_m31_add(b28, b21);
    b21 = stwo_m31_mul(b43, b69);
    b28 = stwo_m31_add(b39, b21);
    b21 = stwo_m31_mul(b44, b68);
    b39 = stwo_m31_add(b28, b21);
    b21 = stwo_m31_mul(b45, b67);
    b28 = stwo_m31_add(b39, b21);
    b21 = stwo_m31_mul(b41, b72);
    b39 = stwo_m31_mul(b42, b71);
    b20 = stwo_m31_add(b21, b39);
    b39 = stwo_m31_mul(b43, b70);
    b21 = stwo_m31_add(b20, b39);
    b39 = stwo_m31_mul(b44, b69);
    b20 = stwo_m31_add(b21, b39);
    b39 = stwo_m31_mul(b45, b68);
    b21 = stwo_m31_add(b20, b39);
    b39 = stwo_m31_mul(b42, b72);
    b20 = stwo_m31_mul(b43, b71);
    b19 = stwo_m31_add(b39, b20);
    b20 = stwo_m31_mul(b44, b70);
    b39 = stwo_m31_add(b19, b20);
    b20 = stwo_m31_mul(b45, b69);
    b19 = stwo_m31_add(b39, b20);
    b20 = stwo_m31_add(b33, b40);
    b40 = stwo_m31_add(b34, b41);
    b41 = stwo_m31_add(b35, b42);
    b42 = stwo_m31_add(b36, b43);
    b43 = stwo_m31_add(b37, b44);
    b44 = stwo_m31_add(b38, b45);
    b45 = stwo_m31_add(b60, b67);
    b67 = stwo_m31_add(b61, b68);
    b68 = stwo_m31_add(b62, b69);
    b69 = stwo_m31_add(b63, b70);
    b70 = stwo_m31_add(b64, b71);
    b71 = stwo_m31_add(b65, b72);
    b72 = stwo_m31_mul(b20, b71);
    b20 = stwo_m31_mul(b40, b70);
    b39 = stwo_m31_add(b72, b20);
    b20 = stwo_m31_mul(b41, b69);
    b72 = stwo_m31_add(b39, b20);
    b20 = stwo_m31_mul(b42, b68);
    b39 = stwo_m31_add(b72, b20);
    b20 = stwo_m31_mul(b43, b67);
    b72 = stwo_m31_add(b39, b20);
    b20 = stwo_m31_mul(b44, b45);
    b45 = stwo_m31_add(b72, b20);
    b20 = stwo_m31_sub(b45, b26);
    b45 = stwo_m31_sub(b20, b28);
    b20 = stwo_m31_add(b25, b45);
    b45 = stwo_m31_mul(b40, b71);
    b40 = stwo_m31_mul(b41, b70);
    b25 = stwo_m31_add(b45, b40);
    b40 = stwo_m31_mul(b42, b69);
    b45 = stwo_m31_add(b25, b40);
    b40 = stwo_m31_mul(b43, b68);
    b25 = stwo_m31_add(b45, b40);
    b40 = stwo_m31_mul(b44, b67);
    b67 = stwo_m31_add(b25, b40);
    b40 = stwo_m31_sub(b67, b27);
    b67 = stwo_m31_sub(b40, b21);
    b40 = stwo_m31_add(b22, b67);
    b67 = stwo_m31_mul(b41, b71);
    b71 = stwo_m31_mul(b42, b70);
    b70 = stwo_m31_add(b67, b71);
    b71 = stwo_m31_mul(b43, b69);
    b69 = stwo_m31_add(b70, b71);
    b71 = stwo_m31_mul(b44, b68);
    b68 = stwo_m31_add(b69, b71);
    b71 = stwo_m31_sub(b68, b24);
    b68 = stwo_m31_sub(b71, b19);
    b71 = stwo_m31_add(b23, b68);
    b68 = stwo_m31_mul(b46, b73);
    b23 = stwo_m31_mul(b46, b74);
    b19 = stwo_m31_mul(b47, b73);
    b24 = stwo_m31_add(b23, b19);
    b19 = stwo_m31_mul(b46, b75);
    b23 = stwo_m31_mul(b47, b74);
    b69 = stwo_m31_add(b19, b23);
    b23 = stwo_m31_mul(b48, b73);
    b19 = stwo_m31_add(b69, b23);
    b23 = stwo_m31_mul(b46, b79);
    b69 = stwo_m31_mul(b47, b78);
    b44 = stwo_m31_add(b23, b69);
    b69 = stwo_m31_mul(b48, b77);
    b23 = stwo_m31_add(b44, b69);
    b69 = stwo_m31_mul(b49, b76);
    b44 = stwo_m31_add(b23, b69);
    b69 = stwo_m31_mul(b50, b75);
    b23 = stwo_m31_add(b44, b69);
    b69 = stwo_m31_mul(b51, b74);
    b44 = stwo_m31_add(b23, b69);
    b69 = stwo_m31_mul(b52, b73);
    b23 = stwo_m31_add(b44, b69);
    b69 = stwo_m31_mul(b47, b79);
    b44 = stwo_m31_mul(b48, b78);
    b70 = stwo_m31_add(b69, b44);
    b44 = stwo_m31_mul(b49, b77);
    b69 = stwo_m31_add(b70, b44);
    b44 = stwo_m31_mul(b50, b76);
    b70 = stwo_m31_add(b69, b44);
    b44 = stwo_m31_mul(b51, b75);
    b69 = stwo_m31_add(b70, b44);
    b44 = stwo_m31_mul(b52, b74);
    b70 = stwo_m31_add(b69, b44);
    b44 = stwo_m31_mul(b48, b79);
    b69 = stwo_m31_mul(b49, b78);
    b43 = stwo_m31_add(b44, b69);
    b69 = stwo_m31_mul(b50, b77);
    b44 = stwo_m31_add(b43, b69);
    b69 = stwo_m31_mul(b51, b76);
    b43 = stwo_m31_add(b44, b69);
    b69 = stwo_m31_mul(b52, b75);
    b44 = stwo_m31_add(b43, b69);
    b69 = stwo_m31_mul(b49, b79);
    b43 = stwo_m31_mul(b50, b78);
    b67 = stwo_m31_add(b69, b43);
    b43 = stwo_m31_mul(b51, b77);
    b69 = stwo_m31_add(b67, b43);
    b43 = stwo_m31_mul(b52, b76);
    b67 = stwo_m31_add(b69, b43);
    b43 = stwo_m31_mul(b53, b80);
    b69 = stwo_m31_mul(b53, b81);
    b42 = stwo_m31_mul(b54, b80);
    b41 = stwo_m31_add(b69, b42);
    b42 = stwo_m31_mul(b53, b82);
    b53 = stwo_m31_mul(b54, b81);
    b69 = stwo_m31_add(b42, b53);
    b53 = stwo_m31_mul(b55, b80);
    b80 = stwo_m31_add(b69, b53);
    b53 = stwo_m31_mul(b54, b86);
    b69 = stwo_m31_mul(b55, b85);
    b42 = stwo_m31_add(b53, b69);
    b69 = stwo_m31_mul(b56, b84);
    b53 = stwo_m31_add(b42, b69);
    b69 = stwo_m31_mul(b57, b83);
    b42 = stwo_m31_add(b53, b69);
    b69 = stwo_m31_mul(b58, b82);
    b53 = stwo_m31_add(b42, b69);
    b69 = stwo_m31_mul(b59, b81);
    b42 = stwo_m31_add(b53, b69);
    b69 = stwo_m31_mul(b55, b86);
    b53 = stwo_m31_mul(b56, b85);
    b22 = stwo_m31_add(b69, b53);
    b53 = stwo_m31_mul(b57, b84);
    b69 = stwo_m31_add(b22, b53);
    b53 = stwo_m31_mul(b58, b83);
    b22 = stwo_m31_add(b69, b53);
    b53 = stwo_m31_mul(b59, b82);
    b69 = stwo_m31_add(b22, b53);
    b53 = stwo_m31_mul(b56, b86);
    b22 = stwo_m31_mul(b57, b85);
    b21 = stwo_m31_add(b53, b22);
    b22 = stwo_m31_mul(b58, b84);
    b53 = stwo_m31_add(b21, b22);
    b22 = stwo_m31_mul(b59, b83);
    b21 = stwo_m31_add(b53, b22);
    b22 = stwo_m31_add(b47, b54);
    b54 = stwo_m31_add(b48, b55);
    b55 = stwo_m31_add(b49, b56);
    b56 = stwo_m31_add(b50, b57);
    b57 = stwo_m31_add(b51, b58);
    b58 = stwo_m31_add(b52, b59);
    b59 = stwo_m31_add(b74, b81);
    b81 = stwo_m31_add(b75, b82);
    b82 = stwo_m31_add(b76, b83);
    b83 = stwo_m31_add(b77, b84);
    b84 = stwo_m31_add(b78, b85);
    b85 = stwo_m31_add(b79, b86);
    b86 = stwo_m31_mul(b22, b85);
    b22 = stwo_m31_mul(b54, b84);
    b53 = stwo_m31_add(b86, b22);
    b22 = stwo_m31_mul(b55, b83);
    b86 = stwo_m31_add(b53, b22);
    b22 = stwo_m31_mul(b56, b82);
    b53 = stwo_m31_add(b86, b22);
    b22 = stwo_m31_mul(b57, b81);
    b86 = stwo_m31_add(b53, b22);
    b22 = stwo_m31_mul(b58, b59);
    b59 = stwo_m31_add(b86, b22);
    b22 = stwo_m31_sub(b59, b70);
    b59 = stwo_m31_sub(b22, b42);
    b22 = stwo_m31_add(b43, b59);
    b59 = stwo_m31_mul(b54, b85);
    b54 = stwo_m31_mul(b55, b84);
    b43 = stwo_m31_add(b59, b54);
    b54 = stwo_m31_mul(b56, b83);
    b59 = stwo_m31_add(b43, b54);
    b54 = stwo_m31_mul(b57, b82);
    b43 = stwo_m31_add(b59, b54);
    b54 = stwo_m31_mul(b58, b81);
    b81 = stwo_m31_add(b43, b54);
    b54 = stwo_m31_sub(b81, b44);
    b81 = stwo_m31_sub(b54, b69);
    b54 = stwo_m31_add(b41, b81);
    b81 = stwo_m31_mul(b55, b85);
    b85 = stwo_m31_mul(b56, b84);
    b84 = stwo_m31_add(b81, b85);
    b85 = stwo_m31_mul(b57, b83);
    b83 = stwo_m31_add(b84, b85);
    b85 = stwo_m31_mul(b58, b82);
    b82 = stwo_m31_add(b83, b85);
    b85 = stwo_m31_sub(b82, b67);
    b82 = stwo_m31_sub(b85, b21);
    b85 = stwo_m31_add(b80, b82);
    b82 = stwo_m31_add(b32, b46);
    b46 = stwo_m31_add(b33, b47);
    b47 = stwo_m31_add(b34, b48);
    b48 = stwo_m31_add(b35, b49);
    b49 = stwo_m31_add(b36, b50);
    b50 = stwo_m31_add(b37, b51);
    b51 = stwo_m31_add(b38, b52);
    b52 = stwo_m31_add(b98, b73);
    b73 = stwo_m31_add(b60, b74);
    b74 = stwo_m31_add(b61, b75);
    b75 = stwo_m31_add(b62, b76);
    b76 = stwo_m31_add(b63, b77);
    b77 = stwo_m31_add(b64, b78);
    b78 = stwo_m31_add(b65, b79);
    b79 = stwo_m31_mul(b82, b52);
    b65 = stwo_m31_mul(b82, b73);
    b64 = stwo_m31_mul(b46, b52);
    b63 = stwo_m31_add(b65, b64);
    b64 = stwo_m31_mul(b82, b74);
    b65 = stwo_m31_mul(b46, b73);
    b62 = stwo_m31_add(b64, b65);
    b65 = stwo_m31_mul(b47, b52);
    b64 = stwo_m31_add(b62, b65);
    b65 = stwo_m31_mul(b82, b78);
    b78 = stwo_m31_mul(b46, b77);
    b77 = stwo_m31_add(b65, b78);
    b78 = stwo_m31_mul(b47, b76);
    b76 = stwo_m31_add(b77, b78);
    b78 = stwo_m31_mul(b48, b75);
    b75 = stwo_m31_add(b76, b78);
    b78 = stwo_m31_mul(b49, b74);
    b74 = stwo_m31_add(b75, b78);
    b78 = stwo_m31_mul(b50, b73);
    b73 = stwo_m31_add(b74, b78);
    b78 = stwo_m31_mul(b51, b52);
    b52 = stwo_m31_add(b73, b78);
    b78 = stwo_m31_sub(b79, b91);
    b79 = stwo_m31_sub(b78, b68);
    b78 = stwo_m31_add(b20, b79);
    b79 = stwo_m31_sub(b63, b29);
    b63 = stwo_m31_sub(b79, b24);
    b79 = stwo_m31_add(b40, b63);
    b63 = stwo_m31_sub(b64, b30);
    b64 = stwo_m31_sub(b63, b19);
    b63 = stwo_m31_add(b71, b64);
    b64 = stwo_m31_sub(b52, b31);
    b52 = stwo_m31_sub(b64, b23);
    b64 = stwo_m31_add(b66, b52);
    b52 = stwo_m31_sub(b78, b87);
    b78 = stwo_m31_sub(b79, b88);
    b79 = stwo_m31_sub(b63, b89);
    b63 = stwo_m31_sub(b64, b90);
    b64 = 2u;
    b90 = stwo_m31_mul(b64, b52);
    b64 = stwo_m31_add(b90, b63);
    b90 = 4u;
    b63 = stwo_m31_mul(b90, b22);
    b90 = stwo_m31_sub(b64, b63);
    b63 = 64u;
    b64 = stwo_m31_mul(b63, b42);
    b63 = stwo_m31_add(b90, b64);
    b64 = 2u;
    b90 = stwo_m31_mul(b64, b78);
    b64 = 4u;
    b78 = stwo_m31_mul(b64, b54);
    b64 = stwo_m31_sub(b90, b78);
    b78 = 2u;
    b90 = stwo_m31_mul(b78, b42);
    b78 = stwo_m31_add(b64, b90);
    b90 = 64u;
    b64 = stwo_m31_mul(b90, b69);
    b90 = stwo_m31_add(b78, b64);
    b64 = 2u;
    b78 = stwo_m31_mul(b64, b79);
    b64 = 4u;
    b79 = stwo_m31_mul(b64, b85);
    b64 = stwo_m31_sub(b78, b79);
    b79 = 2u;
    b78 = stwo_m31_mul(b79, b69);
    b79 = stwo_m31_add(b64, b78);
    b78 = 64u;
    b64 = stwo_m31_mul(b78, b21);
    b78 = stwo_m31_add(b79, b64);
    b64 = 512u;
    b79 = stwo_m31_mul(b94, b64);
    b64 = 136u;
    b21 = stwo_m31_mul(b64, b92);
    b64 = stwo_m31_sub(b63, b21);
    b21 = stwo_m31_add(b64, b93);
    b64 = stwo_m31_sub(b79, b21);
    b21 = 512u;
    b79 = stwo_m31_mul(b95, b21);
    b21 = stwo_m31_add(b90, b94);
    b90 = stwo_m31_sub(b79, b21);
    b21 = 512u;
    b79 = stwo_m31_mul(b96, b21);
    b21 = stwo_m31_add(b78, b95);
    b78 = stwo_m31_sub(b79, b21);
    StwoCairoQm31 e0 = { b64, b97, b97, b97 };
    StwoCairoQm31 e1 = { b90, b97, b97, b97 };
    StwoCairoQm31 e2 = { b78, b97, b97, b97 };
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
