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
stwo_cairo_cuda_eval_v1_cdcc0086172858c1(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 19u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 25u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 41u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 42u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 43u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 47u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 52u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 53u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 54u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 103u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 108u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 109u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 110u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 143u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 144u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 145u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 1u, 165u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 1u, 166u, row, 0);
    unsigned b96 = stwo_trace_value(arena, *args, 1u, 167u, row, 0);
    unsigned b97 = 0u;
    unsigned b98 = stwo_m31_sub(b33, b0);
    b33 = stwo_m31_sub(b34, b1);
    b34 = stwo_m31_sub(b35, b2);
    b35 = stwo_m31_sub(b36, b3);
    b36 = stwo_m31_sub(b37, b4);
    b37 = stwo_m31_sub(b38, b5);
    b38 = stwo_m31_sub(b39, b6);
    b39 = stwo_m31_sub(b40, b7);
    b40 = stwo_m31_sub(b41, b8);
    b41 = stwo_m31_sub(b42, b9);
    b42 = stwo_m31_sub(b43, b10);
    b43 = stwo_m31_sub(b44, b11);
    b44 = stwo_m31_sub(b45, b12);
    b45 = stwo_m31_sub(b46, b13);
    b46 = stwo_m31_sub(b47, b14);
    b47 = stwo_m31_sub(b48, b15);
    b48 = stwo_m31_sub(b49, b16);
    b49 = stwo_m31_sub(b50, b17);
    b50 = stwo_m31_sub(b51, b18);
    b51 = stwo_m31_sub(b52, b19);
    b52 = stwo_m31_sub(b53, b20);
    b53 = stwo_m31_sub(b54, b21);
    b54 = stwo_m31_sub(b55, b22);
    b55 = stwo_m31_sub(b56, b23);
    b56 = stwo_m31_sub(b57, b24);
    b57 = stwo_m31_sub(b58, b25);
    b58 = stwo_m31_sub(b59, b26);
    b59 = stwo_m31_sub(b60, b27);
    b60 = stwo_m31_sub(b61, b28);
    b61 = stwo_m31_sub(b62, b29);
    b62 = stwo_m31_sub(b63, b30);
    b63 = stwo_m31_sub(b64, b31);
    b64 = stwo_m31_sub(b65, b32);
    b65 = stwo_m31_mul(b66, b33);
    b32 = stwo_m31_mul(b67, b98);
    b31 = stwo_m31_add(b65, b32);
    b32 = stwo_m31_mul(b66, b34);
    b65 = stwo_m31_mul(b67, b33);
    b30 = stwo_m31_add(b32, b65);
    b65 = stwo_m31_mul(b68, b98);
    b32 = stwo_m31_add(b30, b65);
    b65 = stwo_m31_mul(b66, b35);
    b30 = stwo_m31_mul(b67, b34);
    b29 = stwo_m31_add(b65, b30);
    b30 = stwo_m31_mul(b68, b33);
    b65 = stwo_m31_add(b29, b30);
    b30 = stwo_m31_mul(b69, b98);
    b29 = stwo_m31_add(b65, b30);
    b30 = stwo_m31_mul(b68, b38);
    b65 = stwo_m31_mul(b69, b37);
    b28 = stwo_m31_add(b30, b65);
    b65 = stwo_m31_mul(b70, b36);
    b30 = stwo_m31_add(b28, b65);
    b65 = stwo_m31_mul(b71, b35);
    b28 = stwo_m31_add(b30, b65);
    b65 = stwo_m31_mul(b72, b34);
    b30 = stwo_m31_add(b28, b65);
    b65 = stwo_m31_mul(b69, b38);
    b28 = stwo_m31_mul(b70, b37);
    b27 = stwo_m31_add(b65, b28);
    b28 = stwo_m31_mul(b71, b36);
    b65 = stwo_m31_add(b27, b28);
    b28 = stwo_m31_mul(b72, b35);
    b27 = stwo_m31_add(b65, b28);
    b28 = stwo_m31_mul(b70, b38);
    b65 = stwo_m31_mul(b71, b37);
    b26 = stwo_m31_add(b28, b65);
    b65 = stwo_m31_mul(b72, b36);
    b28 = stwo_m31_add(b26, b65);
    b65 = stwo_m31_mul(b73, b40);
    b26 = stwo_m31_mul(b74, b39);
    b25 = stwo_m31_add(b65, b26);
    b26 = stwo_m31_mul(b73, b41);
    b65 = stwo_m31_mul(b74, b40);
    b24 = stwo_m31_add(b26, b65);
    b65 = stwo_m31_mul(b75, b39);
    b26 = stwo_m31_add(b24, b65);
    b65 = stwo_m31_mul(b73, b42);
    b24 = stwo_m31_mul(b74, b41);
    b23 = stwo_m31_add(b65, b24);
    b24 = stwo_m31_mul(b75, b40);
    b65 = stwo_m31_add(b23, b24);
    b24 = stwo_m31_mul(b76, b39);
    b23 = stwo_m31_add(b65, b24);
    b24 = stwo_m31_mul(b76, b45);
    b65 = stwo_m31_mul(b77, b44);
    b22 = stwo_m31_add(b24, b65);
    b65 = stwo_m31_mul(b78, b43);
    b24 = stwo_m31_add(b22, b65);
    b65 = stwo_m31_mul(b79, b42);
    b22 = stwo_m31_add(b24, b65);
    b65 = stwo_m31_mul(b77, b45);
    b24 = stwo_m31_mul(b78, b44);
    b21 = stwo_m31_add(b65, b24);
    b24 = stwo_m31_mul(b79, b43);
    b65 = stwo_m31_add(b21, b24);
    b24 = stwo_m31_add(b66, b73);
    b66 = stwo_m31_add(b67, b74);
    b67 = stwo_m31_add(b68, b75);
    b68 = stwo_m31_add(b69, b76);
    b21 = stwo_m31_add(b70, b77);
    b20 = stwo_m31_add(b71, b78);
    b19 = stwo_m31_add(b72, b79);
    b18 = stwo_m31_add(b98, b39);
    b98 = stwo_m31_add(b33, b40);
    b33 = stwo_m31_add(b34, b41);
    b34 = stwo_m31_add(b35, b42);
    b17 = stwo_m31_add(b36, b43);
    b16 = stwo_m31_add(b37, b44);
    b15 = stwo_m31_add(b38, b45);
    b14 = stwo_m31_mul(b24, b98);
    b13 = stwo_m31_mul(b66, b18);
    b12 = stwo_m31_add(b14, b13);
    b13 = stwo_m31_sub(b12, b31);
    b12 = stwo_m31_sub(b13, b25);
    b13 = stwo_m31_add(b30, b12);
    b12 = stwo_m31_mul(b24, b33);
    b30 = stwo_m31_mul(b66, b98);
    b25 = stwo_m31_add(b12, b30);
    b30 = stwo_m31_mul(b67, b18);
    b12 = stwo_m31_add(b25, b30);
    b30 = stwo_m31_sub(b12, b32);
    b12 = stwo_m31_sub(b30, b26);
    b30 = stwo_m31_add(b27, b12);
    b12 = stwo_m31_mul(b24, b34);
    b24 = stwo_m31_mul(b66, b33);
    b33 = stwo_m31_add(b12, b24);
    b24 = stwo_m31_mul(b67, b98);
    b98 = stwo_m31_add(b33, b24);
    b24 = stwo_m31_mul(b68, b18);
    b18 = stwo_m31_add(b98, b24);
    b24 = stwo_m31_sub(b18, b29);
    b18 = stwo_m31_sub(b24, b23);
    b24 = stwo_m31_add(b28, b18);
    b18 = stwo_m31_mul(b68, b15);
    b68 = stwo_m31_mul(b21, b16);
    b98 = stwo_m31_add(b18, b68);
    b68 = stwo_m31_mul(b20, b17);
    b18 = stwo_m31_add(b98, b68);
    b68 = stwo_m31_mul(b19, b34);
    b34 = stwo_m31_add(b18, b68);
    b68 = stwo_m31_sub(b34, b27);
    b34 = stwo_m31_sub(b68, b22);
    b68 = stwo_m31_add(b26, b34);
    b34 = stwo_m31_mul(b21, b15);
    b15 = stwo_m31_mul(b20, b16);
    b16 = stwo_m31_add(b34, b15);
    b15 = stwo_m31_mul(b19, b17);
    b17 = stwo_m31_add(b16, b15);
    b15 = stwo_m31_sub(b17, b28);
    b17 = stwo_m31_sub(b15, b65);
    b15 = stwo_m31_add(b23, b17);
    b17 = stwo_m31_mul(b80, b48);
    b23 = stwo_m31_mul(b81, b47);
    b65 = stwo_m31_add(b17, b23);
    b23 = stwo_m31_mul(b82, b46);
    b17 = stwo_m31_add(b65, b23);
    b23 = stwo_m31_mul(b80, b49);
    b80 = stwo_m31_mul(b81, b48);
    b48 = stwo_m31_add(b23, b80);
    b80 = stwo_m31_mul(b82, b47);
    b47 = stwo_m31_add(b48, b80);
    b80 = stwo_m31_mul(b83, b46);
    b46 = stwo_m31_add(b47, b80);
    b80 = stwo_m31_mul(b83, b52);
    b47 = stwo_m31_mul(b84, b51);
    b48 = stwo_m31_add(b80, b47);
    b47 = stwo_m31_mul(b85, b50);
    b80 = stwo_m31_add(b48, b47);
    b47 = stwo_m31_mul(b86, b49);
    b48 = stwo_m31_add(b80, b47);
    b47 = stwo_m31_mul(b84, b52);
    b80 = stwo_m31_mul(b85, b51);
    b82 = stwo_m31_add(b47, b80);
    b80 = stwo_m31_mul(b86, b50);
    b47 = stwo_m31_add(b82, b80);
    b80 = stwo_m31_mul(b87, b55);
    b82 = stwo_m31_mul(b88, b54);
    b23 = stwo_m31_add(b80, b82);
    b82 = stwo_m31_mul(b89, b53);
    b80 = stwo_m31_add(b23, b82);
    b82 = stwo_m31_mul(b87, b56);
    b23 = stwo_m31_mul(b88, b55);
    b81 = stwo_m31_add(b82, b23);
    b23 = stwo_m31_mul(b89, b54);
    b82 = stwo_m31_add(b81, b23);
    b23 = stwo_m31_mul(b90, b53);
    b81 = stwo_m31_add(b82, b23);
    b23 = stwo_m31_mul(b90, b59);
    b82 = stwo_m31_mul(b91, b58);
    b65 = stwo_m31_add(b23, b82);
    b82 = stwo_m31_mul(b92, b57);
    b23 = stwo_m31_add(b65, b82);
    b82 = stwo_m31_mul(b93, b56);
    b65 = stwo_m31_add(b23, b82);
    b82 = stwo_m31_mul(b91, b59);
    b23 = stwo_m31_mul(b92, b58);
    b28 = stwo_m31_add(b82, b23);
    b23 = stwo_m31_mul(b93, b57);
    b82 = stwo_m31_add(b28, b23);
    b23 = stwo_m31_add(b83, b90);
    b28 = stwo_m31_add(b84, b91);
    b16 = stwo_m31_add(b85, b92);
    b19 = stwo_m31_add(b86, b93);
    b34 = stwo_m31_add(b49, b56);
    b20 = stwo_m31_add(b50, b57);
    b21 = stwo_m31_add(b51, b58);
    b26 = stwo_m31_add(b52, b59);
    b22 = stwo_m31_mul(b23, b26);
    b23 = stwo_m31_mul(b28, b21);
    b27 = stwo_m31_add(b22, b23);
    b23 = stwo_m31_mul(b16, b20);
    b22 = stwo_m31_add(b27, b23);
    b23 = stwo_m31_mul(b19, b34);
    b34 = stwo_m31_add(b22, b23);
    b23 = stwo_m31_sub(b34, b48);
    b34 = stwo_m31_sub(b23, b65);
    b23 = stwo_m31_add(b80, b34);
    b34 = stwo_m31_mul(b28, b26);
    b26 = stwo_m31_mul(b16, b21);
    b21 = stwo_m31_add(b34, b26);
    b26 = stwo_m31_mul(b19, b20);
    b20 = stwo_m31_add(b21, b26);
    b26 = stwo_m31_sub(b20, b47);
    b20 = stwo_m31_sub(b26, b82);
    b26 = stwo_m31_add(b81, b20);
    b20 = stwo_m31_add(b69, b83);
    b83 = stwo_m31_add(b70, b84);
    b84 = stwo_m31_add(b71, b85);
    b85 = stwo_m31_add(b72, b86);
    b86 = stwo_m31_add(b73, b87);
    b87 = stwo_m31_add(b74, b88);
    b88 = stwo_m31_add(b75, b89);
    b89 = stwo_m31_add(b76, b90);
    b90 = stwo_m31_add(b77, b91);
    b91 = stwo_m31_add(b78, b92);
    b92 = stwo_m31_add(b79, b93);
    b93 = stwo_m31_add(b35, b49);
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
    b59 = stwo_m31_mul(b20, b51);
    b45 = stwo_m31_mul(b83, b50);
    b44 = stwo_m31_add(b59, b45);
    b45 = stwo_m31_mul(b84, b49);
    b59 = stwo_m31_add(b44, b45);
    b45 = stwo_m31_mul(b85, b93);
    b44 = stwo_m31_add(b59, b45);
    b45 = stwo_m31_mul(b83, b51);
    b59 = stwo_m31_mul(b84, b50);
    b43 = stwo_m31_add(b45, b59);
    b59 = stwo_m31_mul(b85, b49);
    b45 = stwo_m31_add(b43, b59);
    b59 = stwo_m31_mul(b86, b54);
    b43 = stwo_m31_mul(b87, b53);
    b42 = stwo_m31_add(b59, b43);
    b43 = stwo_m31_mul(b88, b52);
    b59 = stwo_m31_add(b42, b43);
    b43 = stwo_m31_mul(b86, b55);
    b86 = stwo_m31_mul(b87, b54);
    b54 = stwo_m31_add(b43, b86);
    b86 = stwo_m31_mul(b88, b53);
    b53 = stwo_m31_add(b54, b86);
    b86 = stwo_m31_mul(b89, b52);
    b52 = stwo_m31_add(b53, b86);
    b86 = stwo_m31_mul(b89, b58);
    b53 = stwo_m31_mul(b90, b57);
    b54 = stwo_m31_add(b86, b53);
    b53 = stwo_m31_mul(b91, b56);
    b86 = stwo_m31_add(b54, b53);
    b53 = stwo_m31_mul(b92, b55);
    b54 = stwo_m31_add(b86, b53);
    b53 = stwo_m31_mul(b90, b58);
    b86 = stwo_m31_mul(b91, b57);
    b88 = stwo_m31_add(b53, b86);
    b86 = stwo_m31_mul(b92, b56);
    b53 = stwo_m31_add(b88, b86);
    b86 = stwo_m31_add(b20, b89);
    b89 = stwo_m31_add(b83, b90);
    b90 = stwo_m31_add(b84, b91);
    b91 = stwo_m31_add(b85, b92);
    b92 = stwo_m31_add(b93, b55);
    b55 = stwo_m31_add(b49, b56);
    b56 = stwo_m31_add(b50, b57);
    b57 = stwo_m31_add(b51, b58);
    b58 = stwo_m31_mul(b86, b57);
    b86 = stwo_m31_mul(b89, b56);
    b51 = stwo_m31_add(b58, b86);
    b86 = stwo_m31_mul(b90, b55);
    b58 = stwo_m31_add(b51, b86);
    b86 = stwo_m31_mul(b91, b92);
    b92 = stwo_m31_add(b58, b86);
    b86 = stwo_m31_sub(b92, b44);
    b92 = stwo_m31_sub(b86, b54);
    b86 = stwo_m31_add(b59, b92);
    b92 = stwo_m31_mul(b89, b57);
    b57 = stwo_m31_mul(b90, b56);
    b56 = stwo_m31_add(b92, b57);
    b57 = stwo_m31_mul(b91, b55);
    b55 = stwo_m31_add(b56, b57);
    b57 = stwo_m31_sub(b55, b45);
    b55 = stwo_m31_sub(b57, b53);
    b57 = stwo_m31_add(b52, b55);
    b55 = stwo_m31_sub(b86, b68);
    b86 = stwo_m31_sub(b55, b23);
    b55 = stwo_m31_add(b17, b86);
    b86 = stwo_m31_sub(b57, b15);
    b57 = stwo_m31_sub(b86, b26);
    b86 = stwo_m31_add(b46, b57);
    b57 = stwo_m31_sub(b32, b60);
    b32 = stwo_m31_sub(b29, b61);
    b29 = stwo_m31_sub(b13, b62);
    b13 = stwo_m31_sub(b30, b63);
    b30 = stwo_m31_sub(b24, b64);
    b24 = 2u;
    b64 = stwo_m31_mul(b24, b57);
    b24 = stwo_m31_add(b64, b29);
    b64 = 32u;
    b29 = stwo_m31_mul(b64, b13);
    b64 = stwo_m31_add(b24, b29);
    b29 = 4u;
    b24 = stwo_m31_mul(b29, b55);
    b29 = stwo_m31_sub(b64, b24);
    b24 = 2u;
    b64 = stwo_m31_mul(b24, b32);
    b24 = stwo_m31_add(b64, b13);
    b64 = 32u;
    b13 = stwo_m31_mul(b64, b30);
    b64 = stwo_m31_add(b24, b13);
    b13 = 4u;
    b24 = stwo_m31_mul(b13, b86);
    b13 = stwo_m31_sub(b64, b24);
    b24 = 512u;
    b64 = stwo_m31_mul(b95, b24);
    b24 = stwo_m31_add(b29, b94);
    b29 = stwo_m31_sub(b64, b24);
    b24 = 512u;
    b64 = stwo_m31_mul(b96, b24);
    b24 = stwo_m31_add(b13, b95);
    b13 = stwo_m31_sub(b64, b24);
    StwoCairoQm31 e0 = { b29, b97, b97, b97 };
    StwoCairoQm31 e1 = { b13, b97, b97, b97 };
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
