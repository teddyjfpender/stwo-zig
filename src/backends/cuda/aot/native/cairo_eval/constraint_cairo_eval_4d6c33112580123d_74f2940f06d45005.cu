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
stwo_cairo_cuda_eval_v1_6ccad7a56132d863(
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
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 41u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 42u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 61u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 62u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 63u, row, 0);
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
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 511u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 512u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 513u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 514u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 515u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 516u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 517u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 518u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 519u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 520u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 521u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 522u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 523u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 524u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 525u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 526u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 527u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 528u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 529u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 530u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 531u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 532u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 533u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 1u, 534u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 1u, 535u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 1u, 536u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 1u, 537u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 1u, 538u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 1u, 567u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 1u, 568u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 1u, 569u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 1u, 588u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 1u, 589u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 1u, 590u, row, 0);
    unsigned b96 = stwo_trace_value(arena, *args, 1u, 595u, row, 0);
    unsigned b97 = stwo_trace_value(arena, *args, 1u, 596u, row, 0);
    unsigned b98 = stwo_trace_value(arena, *args, 1u, 597u, row, 0);
    unsigned b99 = stwo_trace_value(arena, *args, 1u, 598u, row, 0);
    unsigned b100 = 0u;
    unsigned b101 = stwo_m31_sub(b0, b62);
    b62 = stwo_m31_sub(b1, b63);
    b63 = stwo_m31_sub(b2, b64);
    b64 = stwo_m31_sub(b3, b65);
    b65 = stwo_m31_sub(b4, b66);
    b66 = stwo_m31_sub(b5, b67);
    b67 = stwo_m31_sub(b6, b68);
    b68 = stwo_m31_sub(b7, b69);
    b69 = stwo_m31_sub(b8, b70);
    b70 = stwo_m31_sub(b9, b71);
    b71 = stwo_m31_sub(b10, b72);
    b72 = stwo_m31_sub(b11, b73);
    b73 = stwo_m31_sub(b12, b74);
    b74 = stwo_m31_sub(b13, b75);
    b75 = stwo_m31_sub(b14, b76);
    b76 = stwo_m31_sub(b15, b77);
    b77 = stwo_m31_sub(b16, b78);
    b78 = stwo_m31_sub(b17, b79);
    b79 = stwo_m31_sub(b18, b80);
    b80 = stwo_m31_sub(b19, b81);
    b81 = stwo_m31_sub(b20, b82);
    b82 = stwo_m31_sub(b21, b83);
    b83 = stwo_m31_sub(b22, b84);
    b84 = stwo_m31_sub(b23, b85);
    b85 = stwo_m31_sub(b24, b86);
    b86 = stwo_m31_sub(b25, b87);
    b87 = stwo_m31_sub(b26, b88);
    b88 = stwo_m31_sub(b27, b89);
    b89 = stwo_m31_add(b28, b90);
    b90 = stwo_m31_add(b29, b91);
    b91 = stwo_m31_add(b30, b92);
    b92 = stwo_m31_add(b31, b93);
    b93 = stwo_m31_add(b32, b94);
    b94 = stwo_m31_add(b33, b95);
    b95 = stwo_m31_mul(b34, b101);
    b33 = stwo_m31_mul(b34, b62);
    b32 = stwo_m31_mul(b35, b101);
    b31 = stwo_m31_add(b33, b32);
    b32 = stwo_m31_mul(b34, b63);
    b33 = stwo_m31_mul(b35, b62);
    b30 = stwo_m31_add(b32, b33);
    b33 = stwo_m31_mul(b36, b101);
    b32 = stwo_m31_add(b30, b33);
    b33 = stwo_m31_mul(b35, b67);
    b30 = stwo_m31_mul(b36, b66);
    b29 = stwo_m31_add(b33, b30);
    b30 = stwo_m31_mul(b37, b65);
    b33 = stwo_m31_add(b29, b30);
    b30 = stwo_m31_mul(b38, b64);
    b29 = stwo_m31_add(b33, b30);
    b30 = stwo_m31_mul(b39, b63);
    b33 = stwo_m31_add(b29, b30);
    b30 = stwo_m31_mul(b40, b62);
    b29 = stwo_m31_add(b33, b30);
    b30 = stwo_m31_mul(b36, b67);
    b33 = stwo_m31_mul(b37, b66);
    b28 = stwo_m31_add(b30, b33);
    b33 = stwo_m31_mul(b38, b65);
    b30 = stwo_m31_add(b28, b33);
    b33 = stwo_m31_mul(b39, b64);
    b28 = stwo_m31_add(b30, b33);
    b33 = stwo_m31_mul(b40, b63);
    b30 = stwo_m31_add(b28, b33);
    b33 = stwo_m31_mul(b37, b67);
    b28 = stwo_m31_mul(b38, b66);
    b27 = stwo_m31_add(b33, b28);
    b28 = stwo_m31_mul(b39, b65);
    b33 = stwo_m31_add(b27, b28);
    b28 = stwo_m31_mul(b40, b64);
    b27 = stwo_m31_add(b33, b28);
    b28 = stwo_m31_mul(b41, b68);
    b33 = stwo_m31_mul(b41, b69);
    b26 = stwo_m31_mul(b42, b68);
    b25 = stwo_m31_add(b33, b26);
    b26 = stwo_m31_mul(b41, b70);
    b33 = stwo_m31_mul(b42, b69);
    b24 = stwo_m31_add(b26, b33);
    b33 = stwo_m31_mul(b43, b68);
    b26 = stwo_m31_add(b24, b33);
    b33 = stwo_m31_mul(b42, b74);
    b24 = stwo_m31_mul(b43, b73);
    b23 = stwo_m31_add(b33, b24);
    b24 = stwo_m31_mul(b44, b72);
    b33 = stwo_m31_add(b23, b24);
    b24 = stwo_m31_mul(b45, b71);
    b23 = stwo_m31_add(b33, b24);
    b24 = stwo_m31_mul(b46, b70);
    b33 = stwo_m31_add(b23, b24);
    b24 = stwo_m31_mul(b47, b69);
    b23 = stwo_m31_add(b33, b24);
    b24 = stwo_m31_mul(b43, b74);
    b33 = stwo_m31_mul(b44, b73);
    b22 = stwo_m31_add(b24, b33);
    b33 = stwo_m31_mul(b45, b72);
    b24 = stwo_m31_add(b22, b33);
    b33 = stwo_m31_mul(b46, b71);
    b22 = stwo_m31_add(b24, b33);
    b33 = stwo_m31_mul(b47, b70);
    b24 = stwo_m31_add(b22, b33);
    b33 = stwo_m31_mul(b44, b74);
    b74 = stwo_m31_mul(b45, b73);
    b73 = stwo_m31_add(b33, b74);
    b74 = stwo_m31_mul(b46, b72);
    b72 = stwo_m31_add(b73, b74);
    b74 = stwo_m31_mul(b47, b71);
    b71 = stwo_m31_add(b72, b74);
    b74 = stwo_m31_add(b34, b41);
    b72 = stwo_m31_add(b35, b42);
    b47 = stwo_m31_add(b36, b43);
    b73 = stwo_m31_add(b101, b68);
    b46 = stwo_m31_add(b62, b69);
    b33 = stwo_m31_add(b63, b70);
    b45 = stwo_m31_mul(b74, b73);
    b44 = stwo_m31_sub(b45, b95);
    b45 = stwo_m31_sub(b44, b28);
    b44 = stwo_m31_add(b29, b45);
    b45 = stwo_m31_mul(b74, b46);
    b29 = stwo_m31_mul(b72, b73);
    b28 = stwo_m31_add(b45, b29);
    b29 = stwo_m31_sub(b28, b31);
    b28 = stwo_m31_sub(b29, b25);
    b29 = stwo_m31_add(b30, b28);
    b28 = stwo_m31_mul(b74, b33);
    b33 = stwo_m31_mul(b72, b46);
    b46 = stwo_m31_add(b28, b33);
    b33 = stwo_m31_mul(b47, b73);
    b73 = stwo_m31_add(b46, b33);
    b33 = stwo_m31_sub(b73, b32);
    b73 = stwo_m31_sub(b33, b26);
    b33 = stwo_m31_add(b27, b73);
    b73 = stwo_m31_mul(b48, b75);
    b27 = stwo_m31_mul(b48, b76);
    b26 = stwo_m31_mul(b49, b75);
    b46 = stwo_m31_add(b27, b26);
    b26 = stwo_m31_mul(b48, b77);
    b27 = stwo_m31_mul(b49, b76);
    b47 = stwo_m31_add(b26, b27);
    b27 = stwo_m31_mul(b50, b75);
    b26 = stwo_m31_add(b47, b27);
    b27 = stwo_m31_mul(b49, b81);
    b47 = stwo_m31_mul(b50, b80);
    b28 = stwo_m31_add(b27, b47);
    b47 = stwo_m31_mul(b51, b79);
    b27 = stwo_m31_add(b28, b47);
    b47 = stwo_m31_mul(b52, b78);
    b28 = stwo_m31_add(b27, b47);
    b47 = stwo_m31_mul(b53, b77);
    b27 = stwo_m31_add(b28, b47);
    b47 = stwo_m31_mul(b54, b76);
    b28 = stwo_m31_add(b27, b47);
    b47 = stwo_m31_mul(b50, b81);
    b27 = stwo_m31_mul(b51, b80);
    b72 = stwo_m31_add(b47, b27);
    b27 = stwo_m31_mul(b52, b79);
    b47 = stwo_m31_add(b72, b27);
    b27 = stwo_m31_mul(b53, b78);
    b72 = stwo_m31_add(b47, b27);
    b27 = stwo_m31_mul(b54, b77);
    b47 = stwo_m31_add(b72, b27);
    b27 = stwo_m31_mul(b51, b81);
    b72 = stwo_m31_mul(b52, b80);
    b74 = stwo_m31_add(b27, b72);
    b72 = stwo_m31_mul(b53, b79);
    b27 = stwo_m31_add(b74, b72);
    b72 = stwo_m31_mul(b54, b78);
    b74 = stwo_m31_add(b27, b72);
    b72 = stwo_m31_mul(b55, b82);
    b27 = stwo_m31_mul(b55, b83);
    b30 = stwo_m31_mul(b56, b82);
    b25 = stwo_m31_add(b27, b30);
    b30 = stwo_m31_mul(b55, b84);
    b27 = stwo_m31_mul(b56, b83);
    b45 = stwo_m31_add(b30, b27);
    b27 = stwo_m31_mul(b57, b82);
    b30 = stwo_m31_add(b45, b27);
    b27 = stwo_m31_mul(b56, b88);
    b45 = stwo_m31_mul(b57, b87);
    b22 = stwo_m31_add(b27, b45);
    b45 = stwo_m31_mul(b58, b86);
    b27 = stwo_m31_add(b22, b45);
    b45 = stwo_m31_mul(b59, b85);
    b22 = stwo_m31_add(b27, b45);
    b45 = stwo_m31_mul(b60, b84);
    b27 = stwo_m31_add(b22, b45);
    b45 = stwo_m31_mul(b61, b83);
    b22 = stwo_m31_add(b27, b45);
    b45 = stwo_m31_mul(b57, b88);
    b27 = stwo_m31_mul(b58, b87);
    b21 = stwo_m31_add(b45, b27);
    b27 = stwo_m31_mul(b59, b86);
    b45 = stwo_m31_add(b21, b27);
    b27 = stwo_m31_mul(b60, b85);
    b21 = stwo_m31_add(b45, b27);
    b27 = stwo_m31_mul(b61, b84);
    b45 = stwo_m31_add(b21, b27);
    b27 = stwo_m31_mul(b58, b88);
    b88 = stwo_m31_mul(b59, b87);
    b87 = stwo_m31_add(b27, b88);
    b88 = stwo_m31_mul(b60, b86);
    b86 = stwo_m31_add(b87, b88);
    b88 = stwo_m31_mul(b61, b85);
    b85 = stwo_m31_add(b86, b88);
    b88 = stwo_m31_add(b48, b55);
    b86 = stwo_m31_add(b49, b56);
    b61 = stwo_m31_add(b50, b57);
    b87 = stwo_m31_add(b75, b82);
    b60 = stwo_m31_add(b76, b83);
    b27 = stwo_m31_add(b77, b84);
    b59 = stwo_m31_mul(b88, b87);
    b58 = stwo_m31_sub(b59, b73);
    b59 = stwo_m31_sub(b58, b72);
    b58 = stwo_m31_add(b28, b59);
    b59 = stwo_m31_mul(b88, b60);
    b28 = stwo_m31_mul(b86, b87);
    b72 = stwo_m31_add(b59, b28);
    b28 = stwo_m31_sub(b72, b46);
    b72 = stwo_m31_sub(b28, b25);
    b28 = stwo_m31_add(b47, b72);
    b72 = stwo_m31_mul(b88, b27);
    b27 = stwo_m31_mul(b86, b60);
    b60 = stwo_m31_add(b72, b27);
    b27 = stwo_m31_mul(b61, b87);
    b87 = stwo_m31_add(b60, b27);
    b27 = stwo_m31_sub(b87, b26);
    b87 = stwo_m31_sub(b27, b30);
    b27 = stwo_m31_add(b74, b87);
    b87 = stwo_m31_add(b34, b48);
    b48 = stwo_m31_add(b35, b49);
    b49 = stwo_m31_add(b36, b50);
    b50 = stwo_m31_add(b37, b51);
    b51 = stwo_m31_add(b38, b52);
    b52 = stwo_m31_add(b39, b53);
    b53 = stwo_m31_add(b40, b54);
    b54 = stwo_m31_add(b41, b55);
    b55 = stwo_m31_add(b42, b56);
    b56 = stwo_m31_add(b43, b57);
    b57 = stwo_m31_add(b101, b75);
    b75 = stwo_m31_add(b62, b76);
    b76 = stwo_m31_add(b63, b77);
    b77 = stwo_m31_add(b64, b78);
    b78 = stwo_m31_add(b65, b79);
    b79 = stwo_m31_add(b66, b80);
    b80 = stwo_m31_add(b67, b81);
    b81 = stwo_m31_add(b68, b82);
    b82 = stwo_m31_add(b69, b83);
    b83 = stwo_m31_add(b70, b84);
    b84 = stwo_m31_mul(b87, b57);
    b70 = stwo_m31_mul(b87, b75);
    b69 = stwo_m31_mul(b48, b57);
    b68 = stwo_m31_add(b70, b69);
    b69 = stwo_m31_mul(b87, b76);
    b70 = stwo_m31_mul(b48, b75);
    b67 = stwo_m31_add(b69, b70);
    b70 = stwo_m31_mul(b49, b57);
    b69 = stwo_m31_add(b67, b70);
    b70 = stwo_m31_mul(b48, b80);
    b67 = stwo_m31_mul(b49, b79);
    b66 = stwo_m31_add(b70, b67);
    b67 = stwo_m31_mul(b50, b78);
    b70 = stwo_m31_add(b66, b67);
    b67 = stwo_m31_mul(b51, b77);
    b66 = stwo_m31_add(b70, b67);
    b67 = stwo_m31_mul(b52, b76);
    b70 = stwo_m31_add(b66, b67);
    b67 = stwo_m31_mul(b53, b75);
    b66 = stwo_m31_add(b70, b67);
    b67 = stwo_m31_mul(b49, b80);
    b70 = stwo_m31_mul(b50, b79);
    b65 = stwo_m31_add(b67, b70);
    b70 = stwo_m31_mul(b51, b78);
    b67 = stwo_m31_add(b65, b70);
    b70 = stwo_m31_mul(b52, b77);
    b65 = stwo_m31_add(b67, b70);
    b70 = stwo_m31_mul(b53, b76);
    b67 = stwo_m31_add(b65, b70);
    b70 = stwo_m31_mul(b50, b80);
    b80 = stwo_m31_mul(b51, b79);
    b79 = stwo_m31_add(b70, b80);
    b80 = stwo_m31_mul(b52, b78);
    b78 = stwo_m31_add(b79, b80);
    b80 = stwo_m31_mul(b53, b77);
    b77 = stwo_m31_add(b78, b80);
    b80 = stwo_m31_mul(b54, b81);
    b78 = stwo_m31_mul(b54, b82);
    b53 = stwo_m31_mul(b55, b81);
    b79 = stwo_m31_add(b78, b53);
    b53 = stwo_m31_mul(b54, b83);
    b78 = stwo_m31_mul(b55, b82);
    b52 = stwo_m31_add(b53, b78);
    b78 = stwo_m31_mul(b56, b81);
    b53 = stwo_m31_add(b52, b78);
    b78 = stwo_m31_add(b87, b54);
    b54 = stwo_m31_add(b48, b55);
    b55 = stwo_m31_add(b49, b56);
    b56 = stwo_m31_add(b57, b81);
    b81 = stwo_m31_add(b75, b82);
    b82 = stwo_m31_add(b76, b83);
    b83 = stwo_m31_mul(b78, b56);
    b76 = stwo_m31_sub(b83, b84);
    b83 = stwo_m31_sub(b76, b80);
    b76 = stwo_m31_add(b66, b83);
    b83 = stwo_m31_mul(b78, b81);
    b66 = stwo_m31_mul(b54, b56);
    b80 = stwo_m31_add(b83, b66);
    b66 = stwo_m31_sub(b80, b68);
    b80 = stwo_m31_sub(b66, b79);
    b66 = stwo_m31_add(b67, b80);
    b80 = stwo_m31_mul(b78, b82);
    b82 = stwo_m31_mul(b54, b81);
    b81 = stwo_m31_add(b80, b82);
    b82 = stwo_m31_mul(b55, b56);
    b56 = stwo_m31_add(b81, b82);
    b82 = stwo_m31_sub(b56, b69);
    b56 = stwo_m31_sub(b82, b53);
    b82 = stwo_m31_add(b77, b56);
    b56 = stwo_m31_sub(b76, b44);
    b76 = stwo_m31_sub(b56, b58);
    b56 = stwo_m31_add(b23, b76);
    b76 = stwo_m31_sub(b66, b29);
    b66 = stwo_m31_sub(b76, b28);
    b76 = stwo_m31_add(b24, b66);
    b66 = stwo_m31_sub(b82, b33);
    b82 = stwo_m31_sub(b66, b27);
    b66 = stwo_m31_add(b71, b82);
    b82 = stwo_m31_sub(b95, b89);
    b95 = stwo_m31_sub(b31, b90);
    b31 = stwo_m31_sub(b32, b91);
    b32 = stwo_m31_sub(b56, b92);
    b56 = stwo_m31_sub(b76, b93);
    b76 = stwo_m31_sub(b66, b94);
    b66 = 32u;
    b94 = stwo_m31_mul(b66, b82);
    b66 = 4u;
    b93 = stwo_m31_mul(b66, b32);
    b66 = stwo_m31_sub(b94, b93);
    b93 = 8u;
    b94 = stwo_m31_mul(b93, b22);
    b93 = stwo_m31_add(b66, b94);
    b94 = 32u;
    b66 = stwo_m31_mul(b94, b95);
    b94 = stwo_m31_add(b82, b66);
    b66 = 4u;
    b82 = stwo_m31_mul(b66, b56);
    b66 = stwo_m31_sub(b94, b82);
    b82 = 8u;
    b94 = stwo_m31_mul(b82, b45);
    b82 = stwo_m31_add(b66, b94);
    b94 = 32u;
    b66 = stwo_m31_mul(b94, b31);
    b94 = stwo_m31_add(b95, b66);
    b66 = 4u;
    b95 = stwo_m31_mul(b66, b76);
    b66 = stwo_m31_sub(b94, b95);
    b95 = 8u;
    b94 = stwo_m31_mul(b95, b85);
    b95 = stwo_m31_add(b66, b94);
    b94 = 512u;
    b66 = stwo_m31_mul(b97, b94);
    b94 = stwo_m31_sub(b93, b96);
    b93 = stwo_m31_sub(b66, b94);
    b94 = 512u;
    b66 = stwo_m31_mul(b98, b94);
    b94 = stwo_m31_add(b82, b97);
    b82 = stwo_m31_sub(b66, b94);
    b94 = 512u;
    b66 = stwo_m31_mul(b99, b94);
    b94 = stwo_m31_add(b95, b98);
    b95 = stwo_m31_sub(b66, b94);
    StwoCairoQm31 e0 = { b93, b100, b100, b100 };
    StwoCairoQm31 e1 = { b82, b100, b100, b100 };
    StwoCairoQm31 e2 = { b95, b100, b100, b100 };
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
