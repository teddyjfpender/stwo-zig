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
stwo_cairo_cuda_eval_v1_e3508d38a9e099f4(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 2u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 3u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 4u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 5u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 6u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 7u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 8u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 9u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 10u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 11u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 19u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 25u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 71u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 124u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 126u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 127u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 1u, 143u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 1u, 144u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 1u, 145u, row, 0);
    unsigned b88 = 1u;
    unsigned b89 = stwo_m31_sub(b88, b67);
    b88 = stwo_m31_mul(b67, b89);
    b89 = 0u;
    unsigned b90 = 1u;
    unsigned b91 = stwo_m31_sub(b90, b68);
    b90 = stwo_m31_add(b66, b68);
    unsigned b92 = stwo_m31_mul(b68, b91);
    unsigned b93 = stwo_m31_mul(b66, b69);
    unsigned b94 = stwo_m31_sub(b93, b91);
    b93 = stwo_m31_mul(b69, b90);
    b90 = 1u;
    b69 = stwo_m31_sub(b93, b90);
    b90 = stwo_m31_sub(b0, b67);
    b67 = stwo_m31_mul(b90, b68);
    b68 = 1073741824u;
    b0 = stwo_m31_mul(b90, b68);
    b68 = stwo_m31_sub(b0, b1);
    b0 = stwo_m31_mul(b68, b91);
    b68 = stwo_m31_add(b0, b1);
    b0 = stwo_m31_sub(b70, b68);
    b68 = stwo_m31_sub(b1, b2);
    b1 = stwo_m31_mul(b68, b91);
    b68 = stwo_m31_add(b1, b2);
    b1 = stwo_m31_sub(b71, b68);
    b68 = stwo_m31_sub(b2, b3);
    b2 = stwo_m31_mul(b68, b91);
    b68 = stwo_m31_add(b2, b3);
    b2 = stwo_m31_sub(b72, b68);
    b68 = stwo_m31_sub(b3, b4);
    b3 = stwo_m31_mul(b68, b91);
    b68 = stwo_m31_add(b3, b4);
    b3 = stwo_m31_sub(b73, b68);
    b68 = stwo_m31_sub(b4, b5);
    b4 = stwo_m31_mul(b68, b91);
    b68 = stwo_m31_add(b4, b5);
    b4 = stwo_m31_sub(b74, b68);
    b68 = stwo_m31_sub(b5, b6);
    b5 = stwo_m31_mul(b68, b91);
    b68 = stwo_m31_add(b5, b6);
    b5 = stwo_m31_sub(b75, b68);
    b68 = stwo_m31_sub(b6, b7);
    b6 = stwo_m31_mul(b68, b91);
    b68 = stwo_m31_add(b6, b7);
    b6 = stwo_m31_sub(b76, b68);
    b68 = stwo_m31_sub(b7, b8);
    b7 = stwo_m31_mul(b68, b91);
    b68 = stwo_m31_add(b7, b8);
    b7 = stwo_m31_sub(b77, b68);
    b68 = stwo_m31_sub(b8, b9);
    b8 = stwo_m31_mul(b68, b91);
    b68 = stwo_m31_add(b8, b9);
    b8 = stwo_m31_sub(b78, b68);
    b68 = stwo_m31_mul(b9, b91);
    b9 = stwo_m31_sub(b79, b68);
    b68 = 1u;
    b79 = stwo_m31_sub(b66, b68);
    b68 = 26u;
    b66 = stwo_m31_sub(b79, b68);
    b68 = stwo_m31_mul(b66, b91);
    b66 = 26u;
    b91 = stwo_m31_add(b68, b66);
    b66 = stwo_m31_sub(b80, b91);
    b91 = 1u;
    b80 = stwo_m31_sub(b91, b81);
    b91 = stwo_m31_mul(b81, b80);
    b80 = 1u;
    b68 = stwo_m31_sub(b80, b82);
    b80 = stwo_m31_mul(b82, b68);
    b68 = stwo_m31_add(b60, b61);
    b79 = stwo_m31_add(b68, b62);
    b68 = stwo_m31_add(b79, b63);
    b79 = stwo_m31_add(b68, b64);
    b68 = stwo_m31_mul(b81, b79);
    b79 = 120u;
    b78 = stwo_m31_add(b79, b59);
    b79 = stwo_m31_sub(b78, b82);
    b78 = stwo_m31_mul(b81, b79);
    b79 = stwo_m31_sub(b83, b78);
    b78 = stwo_m31_add(b38, b39);
    b83 = stwo_m31_add(b78, b40);
    b78 = stwo_m31_add(b83, b41);
    b83 = stwo_m31_add(b78, b42);
    b78 = stwo_m31_add(b83, b43);
    b83 = stwo_m31_add(b78, b44);
    b78 = stwo_m31_add(b83, b45);
    b83 = stwo_m31_add(b78, b46);
    b78 = stwo_m31_add(b83, b47);
    b83 = stwo_m31_add(b78, b48);
    b78 = stwo_m31_add(b83, b49);
    b83 = stwo_m31_add(b78, b50);
    b78 = stwo_m31_add(b83, b51);
    b83 = stwo_m31_add(b78, b52);
    b78 = stwo_m31_add(b83, b53);
    b83 = stwo_m31_add(b78, b54);
    b78 = stwo_m31_add(b83, b55);
    b83 = stwo_m31_add(b78, b56);
    b78 = stwo_m31_add(b83, b57);
    b83 = stwo_m31_add(b78, b58);
    b78 = stwo_m31_mul(b82, b83);
    b83 = 1u;
    b82 = stwo_m31_sub(b83, b84);
    b83 = stwo_m31_mul(b84, b82);
    b82 = 1u;
    b81 = stwo_m31_sub(b82, b85);
    b82 = stwo_m31_mul(b85, b81);
    b81 = stwo_m31_add(b32, b33);
    b77 = stwo_m31_add(b81, b34);
    b81 = stwo_m31_add(b77, b35);
    b77 = stwo_m31_add(b81, b36);
    b81 = stwo_m31_mul(b84, b77);
    b77 = 120u;
    b76 = stwo_m31_add(b77, b31);
    b77 = stwo_m31_sub(b76, b85);
    b76 = stwo_m31_mul(b84, b77);
    b77 = stwo_m31_sub(b86, b76);
    b76 = stwo_m31_add(b10, b11);
    b86 = stwo_m31_add(b76, b12);
    b76 = stwo_m31_add(b86, b13);
    b86 = stwo_m31_add(b76, b14);
    b76 = stwo_m31_add(b86, b15);
    b86 = stwo_m31_add(b76, b16);
    b76 = stwo_m31_add(b86, b17);
    b86 = stwo_m31_add(b76, b18);
    b76 = stwo_m31_add(b86, b19);
    b86 = stwo_m31_add(b76, b20);
    b76 = stwo_m31_add(b86, b21);
    b86 = stwo_m31_add(b76, b22);
    b76 = stwo_m31_add(b86, b23);
    b86 = stwo_m31_add(b76, b24);
    b76 = stwo_m31_add(b86, b25);
    b86 = stwo_m31_add(b76, b26);
    b76 = stwo_m31_add(b86, b27);
    b86 = stwo_m31_add(b76, b28);
    b76 = stwo_m31_add(b86, b29);
    b86 = stwo_m31_add(b76, b30);
    b76 = stwo_m31_mul(b85, b86);
    b86 = stwo_m31_sub(b10, b38);
    b38 = stwo_m31_sub(b11, b39);
    b39 = stwo_m31_sub(b12, b40);
    b40 = stwo_m31_sub(b13, b41);
    b41 = stwo_m31_sub(b14, b42);
    b42 = stwo_m31_sub(b15, b43);
    b43 = stwo_m31_sub(b16, b44);
    b44 = stwo_m31_sub(b17, b45);
    b45 = stwo_m31_sub(b18, b46);
    b46 = stwo_m31_sub(b19, b47);
    b47 = stwo_m31_sub(b20, b48);
    b48 = stwo_m31_sub(b21, b49);
    b49 = stwo_m31_sub(b22, b50);
    b50 = stwo_m31_sub(b23, b51);
    b51 = stwo_m31_sub(b24, b52);
    b52 = stwo_m31_sub(b25, b53);
    b53 = stwo_m31_sub(b26, b54);
    b54 = stwo_m31_sub(b27, b55);
    b55 = stwo_m31_sub(b28, b56);
    b56 = stwo_m31_sub(b29, b57);
    b57 = stwo_m31_sub(b30, b58);
    b58 = stwo_m31_sub(b31, b59);
    b59 = stwo_m31_sub(b32, b60);
    b60 = stwo_m31_sub(b33, b61);
    b61 = stwo_m31_sub(b34, b62);
    b62 = stwo_m31_sub(b35, b63);
    b63 = stwo_m31_sub(b36, b64);
    b64 = stwo_m31_sub(b37, b65);
    b65 = stwo_m31_mul(b86, b86);
    b86 = stwo_m31_mul(b38, b38);
    b38 = stwo_m31_add(b65, b86);
    b86 = stwo_m31_mul(b39, b39);
    b39 = stwo_m31_add(b38, b86);
    b86 = stwo_m31_mul(b40, b40);
    b40 = stwo_m31_add(b39, b86);
    b86 = stwo_m31_mul(b41, b41);
    b41 = stwo_m31_add(b40, b86);
    b86 = stwo_m31_mul(b42, b42);
    b42 = stwo_m31_add(b41, b86);
    b86 = stwo_m31_mul(b43, b43);
    b43 = stwo_m31_add(b42, b86);
    b86 = stwo_m31_mul(b44, b44);
    b44 = stwo_m31_add(b43, b86);
    b86 = stwo_m31_mul(b45, b45);
    b45 = stwo_m31_add(b44, b86);
    b86 = stwo_m31_mul(b46, b46);
    b46 = stwo_m31_add(b45, b86);
    b86 = stwo_m31_mul(b47, b47);
    b47 = stwo_m31_add(b46, b86);
    b86 = stwo_m31_mul(b48, b48);
    b48 = stwo_m31_add(b47, b86);
    b86 = stwo_m31_mul(b49, b49);
    b49 = stwo_m31_add(b48, b86);
    b86 = stwo_m31_mul(b50, b50);
    b50 = stwo_m31_add(b49, b86);
    b86 = stwo_m31_mul(b51, b51);
    b51 = stwo_m31_add(b50, b86);
    b86 = stwo_m31_mul(b52, b52);
    b52 = stwo_m31_add(b51, b86);
    b86 = stwo_m31_mul(b53, b53);
    b53 = stwo_m31_add(b52, b86);
    b86 = stwo_m31_mul(b54, b54);
    b54 = stwo_m31_add(b53, b86);
    b86 = stwo_m31_mul(b55, b55);
    b55 = stwo_m31_add(b54, b86);
    b86 = stwo_m31_mul(b56, b56);
    b56 = stwo_m31_add(b55, b86);
    b86 = stwo_m31_mul(b57, b57);
    b57 = stwo_m31_add(b56, b86);
    b86 = stwo_m31_mul(b58, b58);
    b58 = stwo_m31_add(b57, b86);
    b86 = stwo_m31_mul(b59, b59);
    b59 = stwo_m31_add(b58, b86);
    b86 = stwo_m31_mul(b60, b60);
    b60 = stwo_m31_add(b59, b86);
    b86 = stwo_m31_mul(b61, b61);
    b61 = stwo_m31_add(b60, b86);
    b86 = stwo_m31_mul(b62, b62);
    b62 = stwo_m31_add(b61, b86);
    b86 = stwo_m31_mul(b63, b63);
    b63 = stwo_m31_add(b62, b86);
    b86 = stwo_m31_mul(b64, b64);
    b64 = stwo_m31_add(b63, b86);
    b86 = stwo_m31_mul(b64, b87);
    b64 = 1u;
    b87 = stwo_m31_sub(b86, b64);
    StwoCairoQm31 e0 = { b88, b89, b89, b89 };
    StwoCairoQm31 e1 = { b92, b89, b89, b89 };
    StwoCairoQm31 e2 = { b94, b89, b89, b89 };
    StwoCairoQm31 e3 = { b69, b89, b89, b89 };
    StwoCairoQm31 e4 = { b67, b89, b89, b89 };
    StwoCairoQm31 e5 = { b0, b89, b89, b89 };
    StwoCairoQm31 e6 = { b1, b89, b89, b89 };
    StwoCairoQm31 e7 = { b2, b89, b89, b89 };
    StwoCairoQm31 e8 = { b3, b89, b89, b89 };
    StwoCairoQm31 e9 = { b4, b89, b89, b89 };
    StwoCairoQm31 e10 = { b5, b89, b89, b89 };
    StwoCairoQm31 e11 = { b6, b89, b89, b89 };
    StwoCairoQm31 e12 = { b7, b89, b89, b89 };
    StwoCairoQm31 e13 = { b8, b89, b89, b89 };
    StwoCairoQm31 e14 = { b9, b89, b89, b89 };
    StwoCairoQm31 e15 = { b66, b89, b89, b89 };
    StwoCairoQm31 e16 = { b91, b89, b89, b89 };
    StwoCairoQm31 e17 = { b80, b89, b89, b89 };
    StwoCairoQm31 e18 = { b68, b89, b89, b89 };
    StwoCairoQm31 e19 = { b79, b89, b89, b89 };
    StwoCairoQm31 e20 = { b78, b89, b89, b89 };
    StwoCairoQm31 e21 = { b83, b89, b89, b89 };
    StwoCairoQm31 e22 = { b82, b89, b89, b89 };
    StwoCairoQm31 e23 = { b81, b89, b89, b89 };
    StwoCairoQm31 e24 = { b77, b89, b89, b89 };
    StwoCairoQm31 e25 = { b76, b89, b89, b89 };
    StwoCairoQm31 e26 = { b87, b89, b89, b89 };
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e4, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e6, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e8, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 8u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e9, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 9u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e10, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 10u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e11, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 11u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e12, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 12u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e13, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 13u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e14, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 14u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e15, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 15u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e16, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 16u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e17, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 17u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e18, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 18u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e19, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 19u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e20, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 20u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e21, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 21u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e22, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 22u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e23, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 23u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e24, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 24u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e25, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 25u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e26, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 26u) * 4u)));
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
