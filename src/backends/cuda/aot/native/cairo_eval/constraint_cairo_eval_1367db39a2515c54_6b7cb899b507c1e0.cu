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
stwo_cairo_cuda_eval_v1_ec8c56e1b3fcdb89(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 0u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 1u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 2u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 3u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 4u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 5u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 6u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 7u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 8u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 9u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 101u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 103u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 104u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 105u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 107u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 108u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 109u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 110u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 111u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 122u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 123u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 124u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 126u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 127u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b57 = 0u;
    unsigned b58 = 524288u;
    unsigned b59 = stwo_m31_add(b38, b58);
    b58 = 524288u;
    b38 = stwo_m31_add(b39, b58);
    b58 = 524288u;
    b39 = stwo_m31_add(b40, b58);
    b58 = 524288u;
    b40 = stwo_m31_add(b41, b58);
    b58 = 524288u;
    b41 = stwo_m31_add(b42, b58);
    b58 = 524288u;
    b42 = stwo_m31_add(b43, b58);
    b58 = 524288u;
    b43 = stwo_m31_add(b44, b58);
    b58 = 524288u;
    b44 = stwo_m31_add(b45, b58);
    b58 = 524288u;
    b45 = stwo_m31_add(b46, b58);
    b58 = 524288u;
    b46 = stwo_m31_add(b47, b58);
    b58 = 524288u;
    b47 = stwo_m31_add(b48, b58);
    b58 = 524288u;
    b48 = stwo_m31_add(b49, b58);
    b58 = 524288u;
    b49 = stwo_m31_add(b50, b58);
    b58 = 524288u;
    b50 = stwo_m31_add(b51, b58);
    b58 = 524288u;
    b51 = stwo_m31_add(b52, b58);
    b58 = 524288u;
    b52 = stwo_m31_add(b53, b58);
    b58 = 524288u;
    b53 = stwo_m31_add(b54, b58);
    b58 = 524288u;
    b54 = stwo_m31_add(b55, b58);
    b58 = 512u;
    b55 = stwo_m31_mul(b11, b58);
    b58 = stwo_m31_add(b10, b55);
    b55 = 262144u;
    b10 = stwo_m31_mul(b12, b55);
    b55 = stwo_m31_add(b58, b10);
    b10 = 512u;
    b58 = stwo_m31_mul(b14, b10);
    b10 = stwo_m31_add(b13, b58);
    b58 = 262144u;
    b13 = stwo_m31_mul(b15, b58);
    b58 = stwo_m31_add(b10, b13);
    b13 = 512u;
    b10 = stwo_m31_mul(b17, b13);
    b13 = stwo_m31_add(b16, b10);
    b10 = 262144u;
    b16 = stwo_m31_mul(b18, b10);
    b10 = stwo_m31_add(b13, b16);
    b16 = 512u;
    b13 = stwo_m31_mul(b20, b16);
    b16 = stwo_m31_add(b19, b13);
    b13 = 262144u;
    b19 = stwo_m31_mul(b21, b13);
    b13 = stwo_m31_add(b16, b19);
    b19 = 512u;
    b16 = stwo_m31_mul(b23, b19);
    b19 = stwo_m31_add(b22, b16);
    b16 = 262144u;
    b22 = stwo_m31_mul(b24, b16);
    b16 = stwo_m31_add(b19, b22);
    b22 = 512u;
    b19 = stwo_m31_mul(b26, b22);
    b22 = stwo_m31_add(b25, b19);
    b19 = 262144u;
    b25 = stwo_m31_mul(b27, b19);
    b19 = stwo_m31_add(b22, b25);
    b25 = 512u;
    b22 = stwo_m31_mul(b29, b25);
    b25 = stwo_m31_add(b28, b22);
    b22 = 262144u;
    b28 = stwo_m31_mul(b30, b22);
    b22 = stwo_m31_add(b25, b28);
    b28 = 512u;
    b25 = stwo_m31_mul(b32, b28);
    b28 = stwo_m31_add(b31, b25);
    b25 = 262144u;
    b31 = stwo_m31_mul(b33, b25);
    b25 = stwo_m31_add(b28, b31);
    b31 = 512u;
    b28 = stwo_m31_mul(b35, b31);
    b31 = stwo_m31_add(b34, b28);
    b28 = 262144u;
    b34 = stwo_m31_mul(b36, b28);
    b28 = stwo_m31_add(b31, b34);
    b34 = stwo_trace_value(arena, *args, 2u, 156u, row, 0);
    b31 = stwo_trace_value(arena, *args, 2u, 157u, row, 0);
    b36 = stwo_trace_value(arena, *args, 2u, 158u, row, 0);
    b35 = stwo_trace_value(arena, *args, 2u, 159u, row, 0);
    b33 = stwo_trace_value(arena, *args, 2u, 160u, row, 0);
    b32 = stwo_trace_value(arena, *args, 2u, 161u, row, 0);
    b30 = stwo_trace_value(arena, *args, 2u, 162u, row, 0);
    b29 = stwo_trace_value(arena, *args, 2u, 163u, row, 0);
    b27 = stwo_trace_value(arena, *args, 2u, 164u, row, 0);
    b26 = stwo_trace_value(arena, *args, 2u, 165u, row, 0);
    b24 = stwo_trace_value(arena, *args, 2u, 166u, row, 0);
    b23 = stwo_trace_value(arena, *args, 2u, 167u, row, 0);
    b21 = stwo_trace_value(arena, *args, 2u, 168u, row, 0);
    b20 = stwo_trace_value(arena, *args, 2u, 169u, row, 0);
    b18 = stwo_trace_value(arena, *args, 2u, 170u, row, 0);
    b17 = stwo_trace_value(arena, *args, 2u, 171u, row, 0);
    b15 = stwo_trace_value(arena, *args, 2u, 172u, row, 0);
    b14 = stwo_trace_value(arena, *args, 2u, 173u, row, 0);
    b12 = stwo_trace_value(arena, *args, 2u, 174u, row, 0);
    b11 = stwo_trace_value(arena, *args, 2u, 175u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 2u, 176u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 2u, 177u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 2u, 178u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 2u, 179u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 2u, 180u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 181u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 182u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 183u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 184u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 185u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 2u, 186u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 2u, 187u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 2u, 188u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 2u, 189u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 2u, 190u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 191u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 192u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 193u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 2u, 194u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 2u, 195u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 2u, 196u, row, -1);
    unsigned b81 = stwo_trace_value(arena, *args, 2u, 196u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 2u, 197u, row, -1);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 197u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 198u, row, -1);
    unsigned b85 = stwo_trace_value(arena, *args, 2u, 198u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 199u, row, -1);
    unsigned b87 = stwo_trace_value(arena, *args, 2u, 199u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 282u * 4u);
    StwoCairoQm31 e1 = { b59, b57, b57, b57 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 283u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 284u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 285u * 4u);
    e0 = { b38, b57, b57, b57 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 286u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 287u * 4u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 288u * 4u);
    e1 = { b39, b57, b57, b57 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 289u * 4u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(arena, args->ext_params + 290u * 4u);
    e4 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 291u * 4u);
    e0 = { b40, b57, b57, b57 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 292u * 4u);
    e1 = stwo_qm31_add(e0, e5);
    e0 = stwo_load_qm31(arena, args->ext_params + 293u * 4u);
    e5 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 294u * 4u);
    e1 = { b41, b57, b57, b57 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 295u * 4u);
    e0 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(arena, args->ext_params + 296u * 4u);
    e6 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 297u * 4u);
    e0 = { b42, b57, b57, b57 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 298u * 4u);
    e1 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(arena, args->ext_params + 299u * 4u);
    e7 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 300u * 4u);
    e1 = { b43, b57, b57, b57 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 301u * 4u);
    e0 = stwo_qm31_add(e1, e8);
    e1 = stwo_load_qm31(arena, args->ext_params + 302u * 4u);
    e8 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 303u * 4u);
    e0 = { b44, b57, b57, b57 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 304u * 4u);
    e1 = stwo_qm31_add(e0, e9);
    e0 = stwo_load_qm31(arena, args->ext_params + 305u * 4u);
    e9 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 306u * 4u);
    e1 = { b45, b57, b57, b57 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 307u * 4u);
    e0 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(arena, args->ext_params + 308u * 4u);
    e10 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 309u * 4u);
    e0 = { b46, b57, b57, b57 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 310u * 4u);
    e1 = stwo_qm31_add(e0, e11);
    e0 = stwo_load_qm31(arena, args->ext_params + 311u * 4u);
    e11 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 312u * 4u);
    e1 = { b47, b57, b57, b57 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 313u * 4u);
    e0 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(arena, args->ext_params + 314u * 4u);
    e12 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 315u * 4u);
    e0 = { b48, b57, b57, b57 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 316u * 4u);
    e1 = stwo_qm31_add(e0, e13);
    e0 = stwo_load_qm31(arena, args->ext_params + 317u * 4u);
    e13 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 318u * 4u);
    e1 = { b49, b57, b57, b57 };
    StwoCairoQm31 e14 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 319u * 4u);
    e0 = stwo_qm31_add(e1, e14);
    e1 = stwo_load_qm31(arena, args->ext_params + 320u * 4u);
    e14 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 321u * 4u);
    e0 = { b50, b57, b57, b57 };
    StwoCairoQm31 e15 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 322u * 4u);
    e1 = stwo_qm31_add(e0, e15);
    e0 = stwo_load_qm31(arena, args->ext_params + 323u * 4u);
    e15 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 324u * 4u);
    e1 = { b51, b57, b57, b57 };
    StwoCairoQm31 e16 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 325u * 4u);
    e0 = stwo_qm31_add(e1, e16);
    e1 = stwo_load_qm31(arena, args->ext_params + 326u * 4u);
    e16 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 327u * 4u);
    e0 = { b52, b57, b57, b57 };
    StwoCairoQm31 e17 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 328u * 4u);
    e1 = stwo_qm31_add(e0, e17);
    e0 = stwo_load_qm31(arena, args->ext_params + 329u * 4u);
    e17 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 330u * 4u);
    e1 = { b53, b57, b57, b57 };
    StwoCairoQm31 e18 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 331u * 4u);
    e0 = stwo_qm31_add(e1, e18);
    e1 = stwo_load_qm31(arena, args->ext_params + 332u * 4u);
    e18 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 333u * 4u);
    e0 = { b54, b57, b57, b57 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 334u * 4u);
    e1 = stwo_qm31_add(e0, e19);
    e0 = stwo_load_qm31(arena, args->ext_params + 335u * 4u);
    e19 = stwo_qm31_sub(e1, e0);
    e0 = { b56, b57, b57, b57 };
    e1 = stwo_qm31_neg(e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 336u * 4u);
    StwoCairoQm31 e20 = { b0, b57, b57, b57 };
    StwoCairoQm31 e21 = stwo_qm31_mul(e0, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 337u * 4u);
    e0 = stwo_qm31_add(e20, e21);
    e20 = stwo_load_qm31(arena, args->ext_params + 338u * 4u);
    e21 = { b1, b57, b57, b57 };
    StwoCairoQm31 e22 = stwo_qm31_mul(e20, e21);
    e21 = stwo_qm31_add(e0, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 339u * 4u);
    e0 = { b2, b57, b57, b57 };
    e20 = stwo_qm31_mul(e22, e0);
    e0 = stwo_qm31_add(e21, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 340u * 4u);
    e21 = { b3, b57, b57, b57 };
    e22 = stwo_qm31_mul(e20, e21);
    e21 = stwo_qm31_add(e0, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 341u * 4u);
    e0 = { b4, b57, b57, b57 };
    e20 = stwo_qm31_mul(e22, e0);
    e0 = stwo_qm31_add(e21, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 342u * 4u);
    e21 = { b5, b57, b57, b57 };
    e22 = stwo_qm31_mul(e20, e21);
    e21 = stwo_qm31_add(e0, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 343u * 4u);
    e0 = { b6, b57, b57, b57 };
    e20 = stwo_qm31_mul(e22, e0);
    e0 = stwo_qm31_add(e21, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 344u * 4u);
    e21 = { b7, b57, b57, b57 };
    e22 = stwo_qm31_mul(e20, e21);
    e21 = stwo_qm31_add(e0, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 345u * 4u);
    e0 = { b8, b57, b57, b57 };
    e20 = stwo_qm31_mul(e22, e0);
    e0 = stwo_qm31_add(e21, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 346u * 4u);
    e21 = { b9, b57, b57, b57 };
    e22 = stwo_qm31_mul(e20, e21);
    e21 = stwo_qm31_add(e0, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 347u * 4u);
    e0 = { b55, b57, b57, b57 };
    e20 = stwo_qm31_mul(e22, e0);
    e0 = stwo_qm31_add(e21, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 348u * 4u);
    e21 = { b58, b57, b57, b57 };
    e22 = stwo_qm31_mul(e20, e21);
    e21 = stwo_qm31_add(e0, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 349u * 4u);
    e0 = { b10, b57, b57, b57 };
    e20 = stwo_qm31_mul(e22, e0);
    e0 = stwo_qm31_add(e21, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 350u * 4u);
    e21 = { b13, b57, b57, b57 };
    e22 = stwo_qm31_mul(e20, e21);
    e21 = stwo_qm31_add(e0, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 351u * 4u);
    e0 = { b16, b57, b57, b57 };
    e20 = stwo_qm31_mul(e22, e0);
    e0 = stwo_qm31_add(e21, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 352u * 4u);
    e21 = { b19, b57, b57, b57 };
    e22 = stwo_qm31_mul(e20, e21);
    e21 = stwo_qm31_add(e0, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 353u * 4u);
    e0 = { b22, b57, b57, b57 };
    e20 = stwo_qm31_mul(e22, e0);
    e0 = stwo_qm31_add(e21, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 354u * 4u);
    e21 = { b25, b57, b57, b57 };
    e22 = stwo_qm31_mul(e20, e21);
    e21 = stwo_qm31_add(e0, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 355u * 4u);
    e0 = { b28, b57, b57, b57 };
    e20 = stwo_qm31_mul(e22, e0);
    e0 = stwo_qm31_add(e21, e20);
    e20 = stwo_load_qm31(arena, args->ext_params + 356u * 4u);
    e21 = { b37, b57, b57, b57 };
    e22 = stwo_qm31_mul(e20, e21);
    e21 = stwo_qm31_add(e0, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 357u * 4u);
    e0 = stwo_qm31_sub(e21, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 438u * 4u);
    e21 = stwo_qm31_mul(e3, e22);
    e22 = stwo_load_qm31(arena, args->ext_params + 439u * 4u);
    e20 = stwo_qm31_mul(e2, e22);
    e22 = stwo_qm31_add(e21, e20);
    e20 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 440u * 4u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 441u * 4u);
    e21 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e21);
    e21 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 442u * 4u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 443u * 4u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 444u * 4u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 445u * 4u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 446u * 4u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 447u * 4u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 448u * 4u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 449u * 4u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 450u * 4u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 451u * 4u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 452u * 4u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 453u * 4u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 454u * 4u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 455u * 4u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = { b34, b31, b36, b35 };
    e18 = { b33, b32, b30, b29 };
    e16 = stwo_qm31_sub(e18, e19);
    e19 = stwo_qm31_mul(e16, e20);
    e16 = stwo_qm31_sub(e19, e22);
    e19 = { b27, b26, b24, b23 };
    e22 = stwo_qm31_sub(e19, e18);
    e18 = stwo_qm31_mul(e22, e21);
    e22 = stwo_qm31_sub(e18, e3);
    e18 = { b21, b20, b18, b17 };
    e3 = stwo_qm31_sub(e18, e19);
    e19 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e19, e5);
    e19 = { b15, b14, b12, b11 };
    e5 = stwo_qm31_sub(e19, e18);
    e18 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e18, e7);
    e18 = { b60, b61, b62, b63 };
    e7 = stwo_qm31_sub(e18, e19);
    e19 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e19, e9);
    e19 = { b64, b65, b66, b67 };
    e9 = stwo_qm31_sub(e19, e18);
    e18 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e18, e11);
    e18 = { b68, b69, b70, b71 };
    e11 = stwo_qm31_sub(e18, e19);
    e19 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e19, e13);
    e19 = { b72, b73, b74, b75 };
    e13 = stwo_qm31_sub(e19, e18);
    e18 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e18, e15);
    e18 = { b76, b77, b78, b79 };
    e15 = stwo_qm31_sub(e18, e19);
    e19 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e19, e17);
    e19 = { b80, b82, b84, b86 };
    e17 = { b81, b83, b85, b87 };
    e14 = stwo_qm31_sub(e17, e19);
    e17 = stwo_qm31_sub(e14, e18);
    e14 = stwo_load_qm31(arena, args->ext_params + 456u * 4u);
    e18 = stwo_qm31_add(e17, e14);
    e14 = stwo_qm31_mul(e18, e0);
    e18 = stwo_qm31_sub(e14, e1);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e16, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e22, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e9, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e11, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e13, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e15, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 8u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e18, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 9u) * 4u)));
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
