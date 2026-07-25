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
stwo_cairo_cuda_eval_v1_a06121ecbd9661d6(
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
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 65u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 66u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 67u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 101u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 121u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 122u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 123u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 143u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 144u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 1u, 145u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b96 = stwo_trace_value(arena, *args, 1u, 156u, row, 0);
    unsigned b97 = stwo_trace_value(arena, *args, 1u, 157u, row, 0);
    unsigned b98 = stwo_trace_value(arena, *args, 1u, 158u, row, 0);
    unsigned b99 = stwo_trace_value(arena, *args, 1u, 159u, row, 0);
    unsigned b100 = 0u;
    unsigned b101 = stwo_m31_sub(b34, b0);
    b34 = stwo_m31_sub(b35, b1);
    b35 = stwo_m31_sub(b36, b2);
    b36 = stwo_m31_sub(b37, b3);
    b37 = stwo_m31_sub(b38, b4);
    b38 = stwo_m31_sub(b39, b5);
    b39 = stwo_m31_sub(b40, b6);
    b40 = stwo_m31_sub(b41, b7);
    b41 = stwo_m31_sub(b42, b8);
    b42 = stwo_m31_sub(b43, b9);
    b43 = stwo_m31_sub(b44, b10);
    b44 = stwo_m31_sub(b45, b11);
    b45 = stwo_m31_sub(b46, b12);
    b46 = stwo_m31_sub(b47, b13);
    b47 = stwo_m31_sub(b48, b14);
    b48 = stwo_m31_sub(b49, b15);
    b49 = stwo_m31_sub(b50, b16);
    b50 = stwo_m31_sub(b51, b17);
    b51 = stwo_m31_sub(b52, b18);
    b52 = stwo_m31_sub(b53, b19);
    b53 = stwo_m31_sub(b54, b20);
    b54 = stwo_m31_sub(b55, b21);
    b55 = stwo_m31_sub(b56, b22);
    b56 = stwo_m31_sub(b57, b23);
    b57 = stwo_m31_sub(b58, b24);
    b58 = stwo_m31_sub(b59, b25);
    b59 = stwo_m31_sub(b60, b26);
    b60 = stwo_m31_sub(b61, b27);
    b61 = stwo_m31_sub(b62, b28);
    b62 = stwo_m31_sub(b63, b29);
    b63 = stwo_m31_sub(b64, b30);
    b64 = stwo_m31_sub(b65, b31);
    b65 = stwo_m31_sub(b66, b32);
    b66 = stwo_m31_sub(b67, b33);
    b67 = stwo_m31_mul(b68, b101);
    b33 = stwo_m31_mul(b68, b34);
    b32 = stwo_m31_mul(b69, b101);
    b31 = stwo_m31_add(b33, b32);
    b32 = stwo_m31_mul(b68, b35);
    b33 = stwo_m31_mul(b69, b34);
    b30 = stwo_m31_add(b32, b33);
    b33 = stwo_m31_mul(b70, b101);
    b32 = stwo_m31_add(b30, b33);
    b33 = stwo_m31_mul(b69, b39);
    b30 = stwo_m31_mul(b70, b38);
    b29 = stwo_m31_add(b33, b30);
    b30 = stwo_m31_mul(b71, b37);
    b33 = stwo_m31_add(b29, b30);
    b30 = stwo_m31_mul(b72, b36);
    b29 = stwo_m31_add(b33, b30);
    b30 = stwo_m31_mul(b73, b35);
    b33 = stwo_m31_add(b29, b30);
    b30 = stwo_m31_mul(b74, b34);
    b29 = stwo_m31_add(b33, b30);
    b30 = stwo_m31_mul(b70, b39);
    b33 = stwo_m31_mul(b71, b38);
    b28 = stwo_m31_add(b30, b33);
    b33 = stwo_m31_mul(b72, b37);
    b30 = stwo_m31_add(b28, b33);
    b33 = stwo_m31_mul(b73, b36);
    b28 = stwo_m31_add(b30, b33);
    b33 = stwo_m31_mul(b74, b35);
    b30 = stwo_m31_add(b28, b33);
    b33 = stwo_m31_mul(b71, b39);
    b28 = stwo_m31_mul(b72, b38);
    b27 = stwo_m31_add(b33, b28);
    b28 = stwo_m31_mul(b73, b37);
    b33 = stwo_m31_add(b27, b28);
    b28 = stwo_m31_mul(b74, b36);
    b27 = stwo_m31_add(b33, b28);
    b28 = stwo_m31_mul(b75, b40);
    b33 = stwo_m31_mul(b75, b41);
    b26 = stwo_m31_mul(b76, b40);
    b25 = stwo_m31_add(b33, b26);
    b26 = stwo_m31_mul(b75, b42);
    b33 = stwo_m31_mul(b76, b41);
    b24 = stwo_m31_add(b26, b33);
    b33 = stwo_m31_mul(b77, b40);
    b26 = stwo_m31_add(b24, b33);
    b33 = stwo_m31_mul(b76, b46);
    b24 = stwo_m31_mul(b77, b45);
    b23 = stwo_m31_add(b33, b24);
    b24 = stwo_m31_mul(b78, b44);
    b33 = stwo_m31_add(b23, b24);
    b24 = stwo_m31_mul(b79, b43);
    b23 = stwo_m31_add(b33, b24);
    b24 = stwo_m31_mul(b80, b42);
    b33 = stwo_m31_add(b23, b24);
    b24 = stwo_m31_mul(b81, b41);
    b23 = stwo_m31_add(b33, b24);
    b24 = stwo_m31_mul(b77, b46);
    b33 = stwo_m31_mul(b78, b45);
    b22 = stwo_m31_add(b24, b33);
    b33 = stwo_m31_mul(b79, b44);
    b24 = stwo_m31_add(b22, b33);
    b33 = stwo_m31_mul(b80, b43);
    b22 = stwo_m31_add(b24, b33);
    b33 = stwo_m31_mul(b81, b42);
    b24 = stwo_m31_add(b22, b33);
    b33 = stwo_m31_mul(b78, b46);
    b46 = stwo_m31_mul(b79, b45);
    b45 = stwo_m31_add(b33, b46);
    b46 = stwo_m31_mul(b80, b44);
    b44 = stwo_m31_add(b45, b46);
    b46 = stwo_m31_mul(b81, b43);
    b43 = stwo_m31_add(b44, b46);
    b46 = stwo_m31_add(b68, b75);
    b44 = stwo_m31_add(b69, b76);
    b81 = stwo_m31_add(b70, b77);
    b45 = stwo_m31_add(b101, b40);
    b80 = stwo_m31_add(b34, b41);
    b33 = stwo_m31_add(b35, b42);
    b79 = stwo_m31_mul(b46, b45);
    b78 = stwo_m31_sub(b79, b67);
    b79 = stwo_m31_sub(b78, b28);
    b78 = stwo_m31_add(b29, b79);
    b79 = stwo_m31_mul(b46, b80);
    b29 = stwo_m31_mul(b44, b45);
    b28 = stwo_m31_add(b79, b29);
    b29 = stwo_m31_sub(b28, b31);
    b28 = stwo_m31_sub(b29, b25);
    b29 = stwo_m31_add(b30, b28);
    b28 = stwo_m31_mul(b46, b33);
    b33 = stwo_m31_mul(b44, b80);
    b80 = stwo_m31_add(b28, b33);
    b33 = stwo_m31_mul(b81, b45);
    b45 = stwo_m31_add(b80, b33);
    b33 = stwo_m31_sub(b45, b32);
    b45 = stwo_m31_sub(b33, b26);
    b33 = stwo_m31_add(b27, b45);
    b45 = stwo_m31_mul(b82, b47);
    b27 = stwo_m31_mul(b82, b48);
    b26 = stwo_m31_mul(b83, b47);
    b80 = stwo_m31_add(b27, b26);
    b26 = stwo_m31_mul(b82, b49);
    b27 = stwo_m31_mul(b83, b48);
    b81 = stwo_m31_add(b26, b27);
    b27 = stwo_m31_mul(b84, b47);
    b26 = stwo_m31_add(b81, b27);
    b27 = stwo_m31_mul(b83, b53);
    b81 = stwo_m31_mul(b84, b52);
    b28 = stwo_m31_add(b27, b81);
    b81 = stwo_m31_mul(b85, b51);
    b27 = stwo_m31_add(b28, b81);
    b81 = stwo_m31_mul(b86, b50);
    b28 = stwo_m31_add(b27, b81);
    b81 = stwo_m31_mul(b87, b49);
    b27 = stwo_m31_add(b28, b81);
    b81 = stwo_m31_mul(b88, b48);
    b28 = stwo_m31_add(b27, b81);
    b81 = stwo_m31_mul(b84, b53);
    b27 = stwo_m31_mul(b85, b52);
    b44 = stwo_m31_add(b81, b27);
    b27 = stwo_m31_mul(b86, b51);
    b81 = stwo_m31_add(b44, b27);
    b27 = stwo_m31_mul(b87, b50);
    b44 = stwo_m31_add(b81, b27);
    b27 = stwo_m31_mul(b88, b49);
    b81 = stwo_m31_add(b44, b27);
    b27 = stwo_m31_mul(b85, b53);
    b44 = stwo_m31_mul(b86, b52);
    b46 = stwo_m31_add(b27, b44);
    b44 = stwo_m31_mul(b87, b51);
    b27 = stwo_m31_add(b46, b44);
    b44 = stwo_m31_mul(b88, b50);
    b46 = stwo_m31_add(b27, b44);
    b44 = stwo_m31_mul(b89, b54);
    b27 = stwo_m31_mul(b89, b55);
    b30 = stwo_m31_mul(b90, b54);
    b25 = stwo_m31_add(b27, b30);
    b30 = stwo_m31_mul(b89, b56);
    b27 = stwo_m31_mul(b90, b55);
    b79 = stwo_m31_add(b30, b27);
    b27 = stwo_m31_mul(b91, b54);
    b30 = stwo_m31_add(b79, b27);
    b27 = stwo_m31_mul(b90, b60);
    b79 = stwo_m31_mul(b91, b59);
    b22 = stwo_m31_add(b27, b79);
    b79 = stwo_m31_mul(b92, b58);
    b27 = stwo_m31_add(b22, b79);
    b79 = stwo_m31_mul(b93, b57);
    b22 = stwo_m31_add(b27, b79);
    b79 = stwo_m31_mul(b94, b56);
    b27 = stwo_m31_add(b22, b79);
    b79 = stwo_m31_mul(b95, b55);
    b22 = stwo_m31_add(b27, b79);
    b79 = stwo_m31_mul(b91, b60);
    b27 = stwo_m31_mul(b92, b59);
    b21 = stwo_m31_add(b79, b27);
    b27 = stwo_m31_mul(b93, b58);
    b79 = stwo_m31_add(b21, b27);
    b27 = stwo_m31_mul(b94, b57);
    b21 = stwo_m31_add(b79, b27);
    b27 = stwo_m31_mul(b95, b56);
    b79 = stwo_m31_add(b21, b27);
    b27 = stwo_m31_mul(b92, b60);
    b60 = stwo_m31_mul(b93, b59);
    b59 = stwo_m31_add(b27, b60);
    b60 = stwo_m31_mul(b94, b58);
    b58 = stwo_m31_add(b59, b60);
    b60 = stwo_m31_mul(b95, b57);
    b57 = stwo_m31_add(b58, b60);
    b60 = stwo_m31_add(b82, b89);
    b58 = stwo_m31_add(b83, b90);
    b95 = stwo_m31_add(b84, b91);
    b59 = stwo_m31_add(b47, b54);
    b94 = stwo_m31_add(b48, b55);
    b27 = stwo_m31_add(b49, b56);
    b93 = stwo_m31_mul(b60, b59);
    b92 = stwo_m31_sub(b93, b45);
    b93 = stwo_m31_sub(b92, b44);
    b92 = stwo_m31_add(b28, b93);
    b93 = stwo_m31_mul(b60, b94);
    b28 = stwo_m31_mul(b58, b59);
    b44 = stwo_m31_add(b93, b28);
    b28 = stwo_m31_sub(b44, b80);
    b44 = stwo_m31_sub(b28, b25);
    b28 = stwo_m31_add(b81, b44);
    b44 = stwo_m31_mul(b60, b27);
    b27 = stwo_m31_mul(b58, b94);
    b94 = stwo_m31_add(b44, b27);
    b27 = stwo_m31_mul(b95, b59);
    b59 = stwo_m31_add(b94, b27);
    b27 = stwo_m31_sub(b59, b26);
    b59 = stwo_m31_sub(b27, b30);
    b27 = stwo_m31_add(b46, b59);
    b59 = stwo_m31_add(b68, b82);
    b82 = stwo_m31_add(b69, b83);
    b83 = stwo_m31_add(b70, b84);
    b84 = stwo_m31_add(b71, b85);
    b85 = stwo_m31_add(b72, b86);
    b86 = stwo_m31_add(b73, b87);
    b87 = stwo_m31_add(b74, b88);
    b88 = stwo_m31_add(b75, b89);
    b89 = stwo_m31_add(b76, b90);
    b90 = stwo_m31_add(b77, b91);
    b91 = stwo_m31_add(b101, b47);
    b47 = stwo_m31_add(b34, b48);
    b48 = stwo_m31_add(b35, b49);
    b49 = stwo_m31_add(b36, b50);
    b50 = stwo_m31_add(b37, b51);
    b51 = stwo_m31_add(b38, b52);
    b52 = stwo_m31_add(b39, b53);
    b53 = stwo_m31_add(b40, b54);
    b54 = stwo_m31_add(b41, b55);
    b55 = stwo_m31_add(b42, b56);
    b56 = stwo_m31_mul(b59, b91);
    b42 = stwo_m31_mul(b59, b47);
    b41 = stwo_m31_mul(b82, b91);
    b40 = stwo_m31_add(b42, b41);
    b41 = stwo_m31_mul(b59, b48);
    b42 = stwo_m31_mul(b82, b47);
    b39 = stwo_m31_add(b41, b42);
    b42 = stwo_m31_mul(b83, b91);
    b41 = stwo_m31_add(b39, b42);
    b42 = stwo_m31_mul(b82, b52);
    b39 = stwo_m31_mul(b83, b51);
    b38 = stwo_m31_add(b42, b39);
    b39 = stwo_m31_mul(b84, b50);
    b42 = stwo_m31_add(b38, b39);
    b39 = stwo_m31_mul(b85, b49);
    b38 = stwo_m31_add(b42, b39);
    b39 = stwo_m31_mul(b86, b48);
    b42 = stwo_m31_add(b38, b39);
    b39 = stwo_m31_mul(b87, b47);
    b38 = stwo_m31_add(b42, b39);
    b39 = stwo_m31_mul(b83, b52);
    b42 = stwo_m31_mul(b84, b51);
    b37 = stwo_m31_add(b39, b42);
    b42 = stwo_m31_mul(b85, b50);
    b39 = stwo_m31_add(b37, b42);
    b42 = stwo_m31_mul(b86, b49);
    b37 = stwo_m31_add(b39, b42);
    b42 = stwo_m31_mul(b87, b48);
    b39 = stwo_m31_add(b37, b42);
    b42 = stwo_m31_mul(b84, b52);
    b52 = stwo_m31_mul(b85, b51);
    b51 = stwo_m31_add(b42, b52);
    b52 = stwo_m31_mul(b86, b50);
    b50 = stwo_m31_add(b51, b52);
    b52 = stwo_m31_mul(b87, b49);
    b49 = stwo_m31_add(b50, b52);
    b52 = stwo_m31_mul(b88, b53);
    b50 = stwo_m31_mul(b88, b54);
    b87 = stwo_m31_mul(b89, b53);
    b51 = stwo_m31_add(b50, b87);
    b87 = stwo_m31_mul(b88, b55);
    b50 = stwo_m31_mul(b89, b54);
    b86 = stwo_m31_add(b87, b50);
    b50 = stwo_m31_mul(b90, b53);
    b87 = stwo_m31_add(b86, b50);
    b50 = stwo_m31_add(b59, b88);
    b88 = stwo_m31_add(b82, b89);
    b89 = stwo_m31_add(b83, b90);
    b90 = stwo_m31_add(b91, b53);
    b53 = stwo_m31_add(b47, b54);
    b54 = stwo_m31_add(b48, b55);
    b55 = stwo_m31_mul(b50, b90);
    b48 = stwo_m31_sub(b55, b56);
    b55 = stwo_m31_sub(b48, b52);
    b48 = stwo_m31_add(b38, b55);
    b55 = stwo_m31_mul(b50, b53);
    b38 = stwo_m31_mul(b88, b90);
    b52 = stwo_m31_add(b55, b38);
    b38 = stwo_m31_sub(b52, b40);
    b52 = stwo_m31_sub(b38, b51);
    b38 = stwo_m31_add(b39, b52);
    b52 = stwo_m31_mul(b50, b54);
    b54 = stwo_m31_mul(b88, b53);
    b53 = stwo_m31_add(b52, b54);
    b54 = stwo_m31_mul(b89, b90);
    b90 = stwo_m31_add(b53, b54);
    b54 = stwo_m31_sub(b90, b41);
    b90 = stwo_m31_sub(b54, b87);
    b54 = stwo_m31_add(b49, b90);
    b90 = stwo_m31_sub(b48, b78);
    b48 = stwo_m31_sub(b90, b92);
    b90 = stwo_m31_add(b23, b48);
    b48 = stwo_m31_sub(b38, b29);
    b38 = stwo_m31_sub(b48, b28);
    b48 = stwo_m31_add(b24, b38);
    b38 = stwo_m31_sub(b54, b33);
    b54 = stwo_m31_sub(b38, b27);
    b38 = stwo_m31_add(b43, b54);
    b54 = stwo_m31_sub(b67, b61);
    b67 = stwo_m31_sub(b31, b62);
    b31 = stwo_m31_sub(b32, b63);
    b32 = stwo_m31_sub(b90, b64);
    b90 = stwo_m31_sub(b48, b65);
    b48 = stwo_m31_sub(b38, b66);
    b38 = 32u;
    b66 = stwo_m31_mul(b38, b54);
    b38 = 4u;
    b65 = stwo_m31_mul(b38, b32);
    b38 = stwo_m31_sub(b66, b65);
    b65 = 8u;
    b66 = stwo_m31_mul(b65, b22);
    b65 = stwo_m31_add(b38, b66);
    b66 = 32u;
    b38 = stwo_m31_mul(b66, b67);
    b66 = stwo_m31_add(b54, b38);
    b38 = 4u;
    b54 = stwo_m31_mul(b38, b90);
    b38 = stwo_m31_sub(b66, b54);
    b54 = 8u;
    b66 = stwo_m31_mul(b54, b79);
    b54 = stwo_m31_add(b38, b66);
    b66 = 32u;
    b38 = stwo_m31_mul(b66, b31);
    b66 = stwo_m31_add(b67, b38);
    b38 = 4u;
    b67 = stwo_m31_mul(b38, b48);
    b38 = stwo_m31_sub(b66, b67);
    b67 = 8u;
    b66 = stwo_m31_mul(b67, b57);
    b67 = stwo_m31_add(b38, b66);
    b66 = 512u;
    b38 = stwo_m31_mul(b97, b66);
    b66 = stwo_m31_sub(b65, b96);
    b65 = stwo_m31_sub(b38, b66);
    b66 = 512u;
    b38 = stwo_m31_mul(b98, b66);
    b66 = stwo_m31_add(b54, b97);
    b54 = stwo_m31_sub(b38, b66);
    b66 = 512u;
    b38 = stwo_m31_mul(b99, b66);
    b66 = stwo_m31_add(b67, b98);
    b67 = stwo_m31_sub(b38, b66);
    StwoCairoQm31 e0 = { b65, b100, b100, b100 };
    StwoCairoQm31 e1 = { b54, b100, b100, b100 };
    StwoCairoQm31 e2 = { b67, b100, b100, b100 };
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
