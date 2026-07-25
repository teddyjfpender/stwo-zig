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
stwo_cairo_cuda_eval_v1_37962937ab6c0831(
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
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 51u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 58u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 71u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 107u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 112u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 113u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 114u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 156u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 157u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 158u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 159u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 160u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 161u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 162u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 163u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 164u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 1u, 165u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 1u, 166u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 1u, 167u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 1u, 168u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 1u, 169u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 1u, 170u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 1u, 171u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 1u, 172u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 1u, 173u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 1u, 191u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 1u, 192u, row, 0);
    unsigned b96 = stwo_trace_value(arena, *args, 1u, 193u, row, 0);
    unsigned b97 = 0u;
    unsigned b98 = stwo_m31_sub(b0, b33);
    b33 = stwo_m31_sub(b1, b34);
    b34 = stwo_m31_sub(b2, b35);
    b35 = stwo_m31_sub(b3, b36);
    b36 = stwo_m31_sub(b4, b37);
    b37 = stwo_m31_sub(b5, b38);
    b38 = stwo_m31_sub(b6, b39);
    b39 = stwo_m31_sub(b7, b40);
    b40 = stwo_m31_sub(b8, b41);
    b41 = stwo_m31_sub(b9, b42);
    b42 = stwo_m31_sub(b10, b43);
    b43 = stwo_m31_sub(b11, b44);
    b44 = stwo_m31_sub(b12, b45);
    b45 = stwo_m31_sub(b13, b46);
    b46 = stwo_m31_sub(b14, b47);
    b47 = stwo_m31_sub(b15, b48);
    b48 = stwo_m31_sub(b16, b49);
    b49 = stwo_m31_sub(b17, b50);
    b50 = stwo_m31_sub(b18, b51);
    b51 = stwo_m31_sub(b19, b52);
    b52 = stwo_m31_sub(b20, b53);
    b53 = stwo_m31_sub(b21, b54);
    b54 = stwo_m31_sub(b22, b55);
    b55 = stwo_m31_sub(b23, b56);
    b56 = stwo_m31_sub(b24, b57);
    b57 = stwo_m31_sub(b25, b58);
    b58 = stwo_m31_sub(b26, b59);
    b59 = stwo_m31_sub(b27, b60);
    b60 = stwo_m31_sub(b28, b61);
    b61 = stwo_m31_sub(b29, b62);
    b62 = stwo_m31_sub(b30, b63);
    b63 = stwo_m31_sub(b31, b64);
    b64 = stwo_m31_sub(b32, b65);
    b65 = stwo_m31_mul(b66, b34);
    b32 = stwo_m31_mul(b67, b33);
    b31 = stwo_m31_add(b65, b32);
    b32 = stwo_m31_mul(b68, b98);
    b65 = stwo_m31_add(b31, b32);
    b32 = stwo_m31_mul(b66, b35);
    b31 = stwo_m31_mul(b67, b34);
    b30 = stwo_m31_add(b32, b31);
    b31 = stwo_m31_mul(b68, b33);
    b32 = stwo_m31_add(b30, b31);
    b31 = stwo_m31_mul(b69, b98);
    b30 = stwo_m31_add(b32, b31);
    b31 = stwo_m31_mul(b66, b36);
    b32 = stwo_m31_mul(b67, b35);
    b29 = stwo_m31_add(b31, b32);
    b32 = stwo_m31_mul(b68, b34);
    b31 = stwo_m31_add(b29, b32);
    b32 = stwo_m31_mul(b69, b33);
    b29 = stwo_m31_add(b31, b32);
    b32 = stwo_m31_mul(b70, b98);
    b31 = stwo_m31_add(b29, b32);
    b32 = stwo_m31_mul(b69, b38);
    b29 = stwo_m31_mul(b70, b37);
    b28 = stwo_m31_add(b32, b29);
    b29 = stwo_m31_mul(b71, b36);
    b32 = stwo_m31_add(b28, b29);
    b29 = stwo_m31_mul(b72, b35);
    b28 = stwo_m31_add(b32, b29);
    b29 = stwo_m31_mul(b70, b38);
    b32 = stwo_m31_mul(b71, b37);
    b27 = stwo_m31_add(b29, b32);
    b32 = stwo_m31_mul(b72, b36);
    b29 = stwo_m31_add(b27, b32);
    b32 = stwo_m31_mul(b71, b38);
    b27 = stwo_m31_mul(b72, b37);
    b26 = stwo_m31_add(b32, b27);
    b27 = stwo_m31_mul(b73, b41);
    b32 = stwo_m31_mul(b74, b40);
    b25 = stwo_m31_add(b27, b32);
    b32 = stwo_m31_mul(b75, b39);
    b27 = stwo_m31_add(b25, b32);
    b32 = stwo_m31_mul(b73, b42);
    b25 = stwo_m31_mul(b74, b41);
    b24 = stwo_m31_add(b32, b25);
    b25 = stwo_m31_mul(b75, b40);
    b32 = stwo_m31_add(b24, b25);
    b25 = stwo_m31_mul(b76, b39);
    b24 = stwo_m31_add(b32, b25);
    b25 = stwo_m31_mul(b73, b43);
    b32 = stwo_m31_mul(b74, b42);
    b23 = stwo_m31_add(b25, b32);
    b32 = stwo_m31_mul(b75, b41);
    b25 = stwo_m31_add(b23, b32);
    b32 = stwo_m31_mul(b76, b40);
    b23 = stwo_m31_add(b25, b32);
    b32 = stwo_m31_mul(b77, b39);
    b25 = stwo_m31_add(b23, b32);
    b32 = stwo_m31_mul(b76, b45);
    b23 = stwo_m31_mul(b77, b44);
    b22 = stwo_m31_add(b32, b23);
    b23 = stwo_m31_mul(b78, b43);
    b32 = stwo_m31_add(b22, b23);
    b23 = stwo_m31_mul(b79, b42);
    b22 = stwo_m31_add(b32, b23);
    b23 = stwo_m31_mul(b77, b45);
    b32 = stwo_m31_mul(b78, b44);
    b21 = stwo_m31_add(b23, b32);
    b32 = stwo_m31_mul(b79, b43);
    b23 = stwo_m31_add(b21, b32);
    b32 = stwo_m31_mul(b78, b45);
    b21 = stwo_m31_mul(b79, b44);
    b20 = stwo_m31_add(b32, b21);
    b21 = stwo_m31_add(b66, b73);
    b73 = stwo_m31_add(b67, b74);
    b74 = stwo_m31_add(b68, b75);
    b75 = stwo_m31_add(b69, b76);
    b76 = stwo_m31_add(b70, b77);
    b32 = stwo_m31_add(b71, b78);
    b71 = stwo_m31_add(b72, b79);
    b72 = stwo_m31_add(b98, b39);
    b39 = stwo_m31_add(b33, b40);
    b40 = stwo_m31_add(b34, b41);
    b41 = stwo_m31_add(b35, b42);
    b42 = stwo_m31_add(b36, b43);
    b19 = stwo_m31_add(b37, b44);
    b37 = stwo_m31_add(b38, b45);
    b38 = stwo_m31_mul(b21, b41);
    b18 = stwo_m31_mul(b73, b40);
    b17 = stwo_m31_add(b38, b18);
    b18 = stwo_m31_mul(b74, b39);
    b38 = stwo_m31_add(b17, b18);
    b18 = stwo_m31_mul(b75, b72);
    b17 = stwo_m31_add(b38, b18);
    b18 = stwo_m31_sub(b17, b30);
    b17 = stwo_m31_sub(b18, b24);
    b18 = stwo_m31_add(b29, b17);
    b17 = stwo_m31_mul(b21, b42);
    b21 = stwo_m31_mul(b73, b41);
    b73 = stwo_m31_add(b17, b21);
    b21 = stwo_m31_mul(b74, b40);
    b40 = stwo_m31_add(b73, b21);
    b21 = stwo_m31_mul(b75, b39);
    b39 = stwo_m31_add(b40, b21);
    b21 = stwo_m31_mul(b76, b72);
    b72 = stwo_m31_add(b39, b21);
    b21 = stwo_m31_sub(b72, b31);
    b72 = stwo_m31_sub(b21, b25);
    b21 = stwo_m31_add(b26, b72);
    b72 = stwo_m31_mul(b75, b37);
    b75 = stwo_m31_mul(b76, b19);
    b39 = stwo_m31_add(b72, b75);
    b75 = stwo_m31_mul(b32, b42);
    b72 = stwo_m31_add(b39, b75);
    b75 = stwo_m31_mul(b71, b41);
    b41 = stwo_m31_add(b72, b75);
    b75 = stwo_m31_sub(b41, b28);
    b41 = stwo_m31_sub(b75, b22);
    b75 = stwo_m31_add(b27, b41);
    b41 = stwo_m31_mul(b76, b37);
    b76 = stwo_m31_mul(b32, b19);
    b27 = stwo_m31_add(b41, b76);
    b76 = stwo_m31_mul(b71, b42);
    b42 = stwo_m31_add(b27, b76);
    b76 = stwo_m31_sub(b42, b29);
    b42 = stwo_m31_sub(b76, b23);
    b76 = stwo_m31_add(b24, b42);
    b42 = stwo_m31_mul(b32, b37);
    b37 = stwo_m31_mul(b71, b19);
    b19 = stwo_m31_add(b42, b37);
    b37 = stwo_m31_sub(b19, b26);
    b19 = stwo_m31_sub(b37, b20);
    b37 = stwo_m31_add(b25, b19);
    b19 = stwo_m31_mul(b80, b48);
    b25 = stwo_m31_mul(b81, b47);
    b26 = stwo_m31_add(b19, b25);
    b25 = stwo_m31_mul(b82, b46);
    b19 = stwo_m31_add(b26, b25);
    b25 = stwo_m31_mul(b80, b49);
    b26 = stwo_m31_mul(b81, b48);
    b42 = stwo_m31_add(b25, b26);
    b26 = stwo_m31_mul(b82, b47);
    b25 = stwo_m31_add(b42, b26);
    b26 = stwo_m31_mul(b83, b46);
    b42 = stwo_m31_add(b25, b26);
    b26 = stwo_m31_mul(b80, b50);
    b25 = stwo_m31_mul(b81, b49);
    b71 = stwo_m31_add(b26, b25);
    b25 = stwo_m31_mul(b82, b48);
    b26 = stwo_m31_add(b71, b25);
    b25 = stwo_m31_mul(b83, b47);
    b71 = stwo_m31_add(b26, b25);
    b25 = stwo_m31_mul(b84, b46);
    b26 = stwo_m31_add(b71, b25);
    b25 = stwo_m31_mul(b84, b52);
    b71 = stwo_m31_mul(b85, b51);
    b32 = stwo_m31_add(b25, b71);
    b71 = stwo_m31_mul(b86, b50);
    b25 = stwo_m31_add(b32, b71);
    b71 = stwo_m31_mul(b85, b52);
    b52 = stwo_m31_mul(b86, b51);
    b51 = stwo_m31_add(b71, b52);
    b52 = stwo_m31_mul(b87, b56);
    b71 = stwo_m31_mul(b88, b55);
    b86 = stwo_m31_add(b52, b71);
    b71 = stwo_m31_mul(b89, b54);
    b52 = stwo_m31_add(b86, b71);
    b71 = stwo_m31_mul(b90, b53);
    b86 = stwo_m31_add(b52, b71);
    b71 = stwo_m31_mul(b87, b57);
    b52 = stwo_m31_mul(b88, b56);
    b85 = stwo_m31_add(b71, b52);
    b52 = stwo_m31_mul(b89, b55);
    b71 = stwo_m31_add(b85, b52);
    b52 = stwo_m31_mul(b90, b54);
    b85 = stwo_m31_add(b71, b52);
    b52 = stwo_m31_mul(b91, b53);
    b71 = stwo_m31_add(b85, b52);
    b52 = stwo_m31_mul(b91, b59);
    b85 = stwo_m31_mul(b92, b58);
    b32 = stwo_m31_add(b52, b85);
    b85 = stwo_m31_mul(b93, b57);
    b52 = stwo_m31_add(b32, b85);
    b85 = stwo_m31_mul(b92, b59);
    b32 = stwo_m31_mul(b93, b58);
    b24 = stwo_m31_add(b85, b32);
    b32 = stwo_m31_add(b80, b87);
    b87 = stwo_m31_add(b81, b88);
    b88 = stwo_m31_add(b82, b89);
    b89 = stwo_m31_add(b83, b90);
    b90 = stwo_m31_add(b84, b91);
    b85 = stwo_m31_add(b46, b53);
    b53 = stwo_m31_add(b47, b54);
    b54 = stwo_m31_add(b48, b55);
    b55 = stwo_m31_add(b49, b56);
    b56 = stwo_m31_add(b50, b57);
    b29 = stwo_m31_mul(b32, b55);
    b27 = stwo_m31_mul(b87, b54);
    b41 = stwo_m31_add(b29, b27);
    b27 = stwo_m31_mul(b88, b53);
    b29 = stwo_m31_add(b41, b27);
    b27 = stwo_m31_mul(b89, b85);
    b41 = stwo_m31_add(b29, b27);
    b27 = stwo_m31_sub(b41, b42);
    b41 = stwo_m31_sub(b27, b86);
    b27 = stwo_m31_add(b25, b41);
    b41 = stwo_m31_mul(b32, b56);
    b56 = stwo_m31_mul(b87, b55);
    b55 = stwo_m31_add(b41, b56);
    b56 = stwo_m31_mul(b88, b54);
    b54 = stwo_m31_add(b55, b56);
    b56 = stwo_m31_mul(b89, b53);
    b53 = stwo_m31_add(b54, b56);
    b56 = stwo_m31_mul(b90, b85);
    b85 = stwo_m31_add(b53, b56);
    b56 = stwo_m31_sub(b85, b26);
    b85 = stwo_m31_sub(b56, b71);
    b56 = stwo_m31_add(b51, b85);
    b85 = stwo_m31_add(b66, b80);
    b80 = stwo_m31_add(b67, b81);
    b81 = stwo_m31_add(b68, b82);
    b82 = stwo_m31_add(b69, b83);
    b83 = stwo_m31_add(b70, b84);
    b84 = stwo_m31_add(b77, b91);
    b91 = stwo_m31_add(b78, b92);
    b92 = stwo_m31_add(b79, b93);
    b93 = stwo_m31_add(b98, b46);
    b46 = stwo_m31_add(b33, b47);
    b47 = stwo_m31_add(b34, b48);
    b48 = stwo_m31_add(b35, b49);
    b49 = stwo_m31_add(b36, b50);
    b50 = stwo_m31_add(b43, b57);
    b57 = stwo_m31_add(b44, b58);
    b58 = stwo_m31_add(b45, b59);
    b59 = stwo_m31_mul(b85, b47);
    b45 = stwo_m31_mul(b80, b46);
    b44 = stwo_m31_add(b59, b45);
    b45 = stwo_m31_mul(b81, b93);
    b59 = stwo_m31_add(b44, b45);
    b45 = stwo_m31_mul(b85, b48);
    b44 = stwo_m31_mul(b80, b47);
    b43 = stwo_m31_add(b45, b44);
    b44 = stwo_m31_mul(b81, b46);
    b45 = stwo_m31_add(b43, b44);
    b44 = stwo_m31_mul(b82, b93);
    b43 = stwo_m31_add(b45, b44);
    b44 = stwo_m31_mul(b85, b49);
    b49 = stwo_m31_mul(b80, b48);
    b48 = stwo_m31_add(b44, b49);
    b49 = stwo_m31_mul(b81, b47);
    b47 = stwo_m31_add(b48, b49);
    b49 = stwo_m31_mul(b82, b46);
    b46 = stwo_m31_add(b47, b49);
    b49 = stwo_m31_mul(b83, b93);
    b93 = stwo_m31_add(b46, b49);
    b49 = stwo_m31_mul(b84, b58);
    b84 = stwo_m31_mul(b91, b57);
    b46 = stwo_m31_add(b49, b84);
    b84 = stwo_m31_mul(b92, b50);
    b50 = stwo_m31_add(b46, b84);
    b84 = stwo_m31_mul(b91, b58);
    b58 = stwo_m31_mul(b92, b57);
    b57 = stwo_m31_add(b84, b58);
    b58 = stwo_m31_sub(b59, b65);
    b59 = stwo_m31_sub(b58, b19);
    b58 = stwo_m31_add(b75, b59);
    b59 = stwo_m31_sub(b43, b30);
    b43 = stwo_m31_sub(b59, b42);
    b59 = stwo_m31_add(b76, b43);
    b43 = stwo_m31_sub(b93, b31);
    b93 = stwo_m31_sub(b43, b26);
    b43 = stwo_m31_add(b37, b93);
    b93 = stwo_m31_sub(b50, b23);
    b50 = stwo_m31_sub(b93, b52);
    b93 = stwo_m31_add(b27, b50);
    b50 = stwo_m31_sub(b57, b20);
    b57 = stwo_m31_sub(b50, b24);
    b50 = stwo_m31_add(b56, b57);
    b57 = stwo_m31_sub(b18, b60);
    b18 = stwo_m31_sub(b21, b61);
    b21 = stwo_m31_sub(b58, b62);
    b58 = stwo_m31_sub(b59, b63);
    b59 = stwo_m31_sub(b43, b64);
    b43 = 2u;
    b64 = stwo_m31_mul(b43, b57);
    b43 = stwo_m31_add(b64, b21);
    b64 = 32u;
    b21 = stwo_m31_mul(b64, b58);
    b64 = stwo_m31_add(b43, b21);
    b21 = 4u;
    b43 = stwo_m31_mul(b21, b93);
    b21 = stwo_m31_sub(b64, b43);
    b43 = 2u;
    b64 = stwo_m31_mul(b43, b18);
    b43 = stwo_m31_add(b64, b58);
    b64 = 32u;
    b58 = stwo_m31_mul(b64, b59);
    b64 = stwo_m31_add(b43, b58);
    b58 = 4u;
    b43 = stwo_m31_mul(b58, b50);
    b58 = stwo_m31_sub(b64, b43);
    b43 = 512u;
    b64 = stwo_m31_mul(b95, b43);
    b43 = stwo_m31_add(b21, b94);
    b21 = stwo_m31_sub(b64, b43);
    b43 = 512u;
    b64 = stwo_m31_mul(b96, b43);
    b43 = stwo_m31_add(b58, b95);
    b58 = stwo_m31_sub(b64, b43);
    StwoCairoQm31 e0 = { b21, b97, b97, b97 };
    StwoCairoQm31 e1 = { b58, b97, b97, b97 };
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
