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
stwo_cairo_cuda_eval_v1_33deaf5a42eac567(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 6u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 7u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 8u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 9u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 10u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 11u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 19u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 25u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 41u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 42u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 43u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 47u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 48u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 49u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 51u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 52u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 53u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 54u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 55u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 58u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 59u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 60u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 61u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 101u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 103u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 104u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 105u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 107u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 108u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 109u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 110u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 111u, row, 0);
    unsigned b78 = 0u;
    unsigned b79 = 512u;
    unsigned b80 = stwo_m31_mul(b1, b79);
    b79 = stwo_m31_add(b0, b80);
    b80 = 262144u;
    b0 = stwo_m31_mul(b2, b80);
    b80 = stwo_m31_add(b79, b0);
    b0 = 512u;
    b79 = stwo_m31_mul(b4, b0);
    b0 = stwo_m31_add(b3, b79);
    b79 = 262144u;
    b3 = stwo_m31_mul(b5, b79);
    b79 = stwo_m31_add(b0, b3);
    b3 = 512u;
    b0 = stwo_m31_mul(b7, b3);
    b3 = stwo_m31_add(b6, b0);
    b0 = 262144u;
    b6 = stwo_m31_mul(b8, b0);
    b0 = stwo_m31_add(b3, b6);
    b6 = 512u;
    b3 = stwo_m31_mul(b10, b6);
    b6 = stwo_m31_add(b9, b3);
    b3 = 262144u;
    b9 = stwo_m31_mul(b11, b3);
    b3 = stwo_m31_add(b6, b9);
    b9 = 512u;
    b6 = stwo_m31_mul(b13, b9);
    b9 = stwo_m31_add(b12, b6);
    b6 = 262144u;
    b12 = stwo_m31_mul(b14, b6);
    b6 = stwo_m31_add(b9, b12);
    b12 = 512u;
    b9 = stwo_m31_mul(b16, b12);
    b12 = stwo_m31_add(b15, b9);
    b9 = 262144u;
    b15 = stwo_m31_mul(b17, b9);
    b9 = stwo_m31_add(b12, b15);
    b15 = 512u;
    b12 = stwo_m31_mul(b19, b15);
    b15 = stwo_m31_add(b18, b12);
    b12 = 262144u;
    b18 = stwo_m31_mul(b20, b12);
    b12 = stwo_m31_add(b15, b18);
    b18 = 512u;
    b15 = stwo_m31_mul(b22, b18);
    b18 = stwo_m31_add(b21, b15);
    b15 = 262144u;
    b21 = stwo_m31_mul(b23, b15);
    b15 = stwo_m31_add(b18, b21);
    b21 = 512u;
    b18 = stwo_m31_mul(b25, b21);
    b21 = stwo_m31_add(b24, b18);
    b18 = 262144u;
    b24 = stwo_m31_mul(b26, b18);
    b18 = stwo_m31_add(b21, b24);
    b24 = 512u;
    b21 = stwo_m31_mul(b29, b24);
    b24 = stwo_m31_add(b28, b21);
    b21 = 262144u;
    b28 = stwo_m31_mul(b30, b21);
    b21 = stwo_m31_add(b24, b28);
    b28 = 512u;
    b24 = stwo_m31_mul(b32, b28);
    b28 = stwo_m31_add(b31, b24);
    b24 = 262144u;
    b31 = stwo_m31_mul(b33, b24);
    b24 = stwo_m31_add(b28, b31);
    b31 = 512u;
    b28 = stwo_m31_mul(b35, b31);
    b31 = stwo_m31_add(b34, b28);
    b28 = 262144u;
    b34 = stwo_m31_mul(b36, b28);
    b28 = stwo_m31_add(b31, b34);
    b34 = 512u;
    b31 = stwo_m31_mul(b38, b34);
    b34 = stwo_m31_add(b37, b31);
    b31 = 262144u;
    b37 = stwo_m31_mul(b39, b31);
    b31 = stwo_m31_add(b34, b37);
    b37 = 512u;
    b34 = stwo_m31_mul(b41, b37);
    b37 = stwo_m31_add(b40, b34);
    b34 = 262144u;
    b40 = stwo_m31_mul(b42, b34);
    b34 = stwo_m31_add(b37, b40);
    b40 = 512u;
    b37 = stwo_m31_mul(b44, b40);
    b40 = stwo_m31_add(b43, b37);
    b37 = 262144u;
    b43 = stwo_m31_mul(b45, b37);
    b37 = stwo_m31_add(b40, b43);
    b43 = 512u;
    b40 = stwo_m31_mul(b47, b43);
    b43 = stwo_m31_add(b46, b40);
    b40 = 262144u;
    b46 = stwo_m31_mul(b48, b40);
    b40 = stwo_m31_add(b43, b46);
    b46 = 512u;
    b43 = stwo_m31_mul(b50, b46);
    b46 = stwo_m31_add(b49, b43);
    b43 = 262144u;
    b49 = stwo_m31_mul(b51, b43);
    b43 = stwo_m31_add(b46, b49);
    b49 = 512u;
    b46 = stwo_m31_mul(b53, b49);
    b49 = stwo_m31_add(b52, b46);
    b46 = 262144u;
    b52 = stwo_m31_mul(b54, b46);
    b46 = stwo_m31_add(b49, b52);
    b52 = 74972783u;
    b49 = stwo_m31_add(b80, b52);
    b52 = stwo_m31_sub(b49, b56);
    b49 = stwo_m31_sub(b52, b66);
    b52 = 16u;
    b56 = stwo_m31_mul(b49, b52);
    b52 = stwo_m31_add(b56, b79);
    b79 = 117420501u;
    b49 = stwo_m31_add(b52, b79);
    b79 = stwo_m31_sub(b49, b57);
    b49 = 16u;
    b57 = stwo_m31_mul(b79, b49);
    b49 = stwo_m31_add(b57, b0);
    b0 = 112795138u;
    b79 = stwo_m31_add(b49, b0);
    b0 = stwo_m31_sub(b79, b58);
    b79 = 16u;
    b58 = stwo_m31_mul(b0, b79);
    b79 = stwo_m31_add(b58, b3);
    b3 = 91013252u;
    b0 = stwo_m31_add(b79, b3);
    b3 = stwo_m31_sub(b0, b59);
    b0 = 16u;
    b59 = stwo_m31_mul(b3, b0);
    b0 = stwo_m31_add(b59, b6);
    b6 = 60709090u;
    b3 = stwo_m31_add(b0, b6);
    b6 = stwo_m31_sub(b3, b60);
    b3 = 16u;
    b60 = stwo_m31_mul(b6, b3);
    b3 = stwo_m31_add(b60, b9);
    b9 = 44848225u;
    b6 = stwo_m31_add(b3, b9);
    b9 = stwo_m31_sub(b6, b61);
    b6 = 16u;
    b61 = stwo_m31_mul(b9, b6);
    b6 = stwo_m31_add(b61, b12);
    b12 = 108487870u;
    b9 = stwo_m31_add(b6, b12);
    b12 = stwo_m31_sub(b9, b62);
    b9 = 16u;
    b62 = stwo_m31_mul(b12, b9);
    b9 = stwo_m31_add(b62, b15);
    b15 = 44781849u;
    b12 = stwo_m31_add(b9, b15);
    b15 = stwo_m31_sub(b12, b63);
    b12 = 136u;
    b63 = stwo_m31_mul(b66, b12);
    b12 = stwo_m31_sub(b15, b63);
    b63 = 16u;
    b15 = stwo_m31_mul(b12, b63);
    b63 = stwo_m31_add(b15, b18);
    b18 = 102193642u;
    b12 = stwo_m31_add(b63, b18);
    b18 = stwo_m31_sub(b12, b64);
    b12 = 16u;
    b64 = stwo_m31_mul(b18, b12);
    b12 = stwo_m31_add(b64, b27);
    b27 = 208u;
    b18 = stwo_m31_add(b12, b27);
    b27 = stwo_m31_sub(b18, b65);
    b18 = 256u;
    b65 = stwo_m31_mul(b66, b18);
    b18 = stwo_m31_sub(b27, b65);
    b65 = stwo_m31_mul(b66, b66);
    b27 = stwo_m31_mul(b65, b66);
    b65 = stwo_m31_sub(b27, b66);
    b27 = stwo_m31_mul(b56, b56);
    b66 = stwo_m31_mul(b27, b56);
    b27 = stwo_m31_sub(b66, b56);
    b66 = stwo_m31_mul(b57, b57);
    b56 = stwo_m31_mul(b66, b57);
    b66 = stwo_m31_sub(b56, b57);
    b56 = stwo_m31_mul(b58, b58);
    b57 = stwo_m31_mul(b56, b58);
    b56 = stwo_m31_sub(b57, b58);
    b57 = stwo_m31_mul(b59, b59);
    b58 = stwo_m31_mul(b57, b59);
    b57 = stwo_m31_sub(b58, b59);
    b58 = stwo_m31_mul(b60, b60);
    b59 = stwo_m31_mul(b58, b60);
    b58 = stwo_m31_sub(b59, b60);
    b59 = stwo_m31_mul(b61, b61);
    b60 = stwo_m31_mul(b59, b61);
    b59 = stwo_m31_sub(b60, b61);
    b60 = stwo_m31_mul(b62, b62);
    b61 = stwo_m31_mul(b60, b62);
    b60 = stwo_m31_sub(b61, b62);
    b61 = stwo_m31_mul(b15, b15);
    b62 = stwo_m31_mul(b61, b15);
    b61 = stwo_m31_sub(b62, b15);
    b62 = stwo_m31_mul(b64, b64);
    b15 = stwo_m31_mul(b62, b64);
    b62 = stwo_m31_sub(b15, b64);
    b15 = 41224388u;
    b64 = stwo_m31_add(b21, b15);
    b15 = stwo_m31_sub(b64, b67);
    b64 = stwo_m31_sub(b15, b77);
    b15 = 16u;
    b67 = stwo_m31_mul(b64, b15);
    b15 = stwo_m31_add(b67, b24);
    b24 = 90391646u;
    b64 = stwo_m31_add(b15, b24);
    b24 = stwo_m31_sub(b64, b68);
    b64 = 16u;
    b68 = stwo_m31_mul(b24, b64);
    b64 = stwo_m31_add(b68, b28);
    b28 = 36279186u;
    b24 = stwo_m31_add(b64, b28);
    b28 = stwo_m31_sub(b24, b69);
    b24 = 16u;
    b69 = stwo_m31_mul(b28, b24);
    b24 = stwo_m31_add(b69, b31);
    b31 = 129717753u;
    b28 = stwo_m31_add(b24, b31);
    b31 = stwo_m31_sub(b28, b70);
    b28 = 16u;
    b70 = stwo_m31_mul(b31, b28);
    b28 = stwo_m31_add(b70, b34);
    b34 = 94624323u;
    b31 = stwo_m31_add(b28, b34);
    b34 = stwo_m31_sub(b31, b71);
    b31 = 16u;
    b71 = stwo_m31_mul(b34, b31);
    b31 = stwo_m31_add(b71, b37);
    b37 = 75104388u;
    b34 = stwo_m31_add(b31, b37);
    b37 = stwo_m31_sub(b34, b72);
    b34 = 16u;
    b72 = stwo_m31_mul(b37, b34);
    b34 = stwo_m31_add(b72, b40);
    b40 = 133303902u;
    b37 = stwo_m31_add(b34, b40);
    b40 = stwo_m31_sub(b37, b73);
    b37 = 16u;
    b73 = stwo_m31_mul(b40, b37);
    b37 = stwo_m31_add(b73, b43);
    b43 = 48945103u;
    b40 = stwo_m31_add(b37, b43);
    b43 = stwo_m31_sub(b40, b74);
    b40 = 136u;
    b74 = stwo_m31_mul(b77, b40);
    b40 = stwo_m31_sub(b43, b74);
    b74 = 16u;
    b43 = stwo_m31_mul(b40, b74);
    b74 = stwo_m31_add(b43, b46);
    b46 = 41320857u;
    b40 = stwo_m31_add(b74, b46);
    b46 = stwo_m31_sub(b40, b75);
    b40 = 16u;
    b75 = stwo_m31_mul(b46, b40);
    b40 = stwo_m31_add(b75, b55);
    b55 = 112u;
    b46 = stwo_m31_add(b40, b55);
    b55 = stwo_m31_sub(b46, b76);
    b46 = 256u;
    b76 = stwo_m31_mul(b77, b46);
    b46 = stwo_m31_sub(b55, b76);
    b76 = stwo_m31_mul(b77, b77);
    b55 = stwo_m31_mul(b76, b77);
    b76 = stwo_m31_sub(b55, b77);
    b55 = stwo_m31_mul(b67, b67);
    b77 = stwo_m31_mul(b55, b67);
    b55 = stwo_m31_sub(b77, b67);
    b77 = stwo_m31_mul(b68, b68);
    b67 = stwo_m31_mul(b77, b68);
    b77 = stwo_m31_sub(b67, b68);
    b67 = stwo_m31_mul(b69, b69);
    b68 = stwo_m31_mul(b67, b69);
    b67 = stwo_m31_sub(b68, b69);
    b68 = stwo_m31_mul(b70, b70);
    b69 = stwo_m31_mul(b68, b70);
    b68 = stwo_m31_sub(b69, b70);
    b69 = stwo_m31_mul(b71, b71);
    b70 = stwo_m31_mul(b69, b71);
    b69 = stwo_m31_sub(b70, b71);
    b70 = stwo_m31_mul(b72, b72);
    b71 = stwo_m31_mul(b70, b72);
    b70 = stwo_m31_sub(b71, b72);
    b71 = stwo_m31_mul(b73, b73);
    b72 = stwo_m31_mul(b71, b73);
    b71 = stwo_m31_sub(b72, b73);
    b72 = stwo_m31_mul(b43, b43);
    b73 = stwo_m31_mul(b72, b43);
    b72 = stwo_m31_sub(b73, b43);
    b73 = stwo_m31_mul(b75, b75);
    b43 = stwo_m31_mul(b73, b75);
    b73 = stwo_m31_sub(b43, b75);
    StwoCairoQm31 e0 = { b18, b78, b78, b78 };
    StwoCairoQm31 e1 = { b65, b78, b78, b78 };
    StwoCairoQm31 e2 = { b27, b78, b78, b78 };
    StwoCairoQm31 e3 = { b66, b78, b78, b78 };
    StwoCairoQm31 e4 = { b56, b78, b78, b78 };
    StwoCairoQm31 e5 = { b57, b78, b78, b78 };
    StwoCairoQm31 e6 = { b58, b78, b78, b78 };
    StwoCairoQm31 e7 = { b59, b78, b78, b78 };
    StwoCairoQm31 e8 = { b60, b78, b78, b78 };
    StwoCairoQm31 e9 = { b61, b78, b78, b78 };
    StwoCairoQm31 e10 = { b62, b78, b78, b78 };
    StwoCairoQm31 e11 = { b46, b78, b78, b78 };
    StwoCairoQm31 e12 = { b76, b78, b78, b78 };
    StwoCairoQm31 e13 = { b55, b78, b78, b78 };
    StwoCairoQm31 e14 = { b77, b78, b78, b78 };
    StwoCairoQm31 e15 = { b67, b78, b78, b78 };
    StwoCairoQm31 e16 = { b68, b78, b78, b78 };
    StwoCairoQm31 e17 = { b69, b78, b78, b78 };
    StwoCairoQm31 e18 = { b70, b78, b78, b78 };
    StwoCairoQm31 e19 = { b71, b78, b78, b78 };
    StwoCairoQm31 e20 = { b72, b78, b78, b78 };
    StwoCairoQm31 e21 = { b73, b78, b78, b78 };
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
