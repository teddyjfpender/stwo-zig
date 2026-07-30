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
stwo_cairo_cuda_eval_v1_8f64b096ebc06002(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 1u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 2u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 101u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 103u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 104u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 105u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 107u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 108u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 109u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 110u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 111u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 112u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 113u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 114u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 115u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 116u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 117u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 118u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 119u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 120u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 121u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 122u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 123u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 124u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 126u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 127u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 143u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 144u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 145u, row, 0);
    unsigned b76 = 262144u;
    unsigned b77 = stwo_m31_mul(b76, b0);
    b76 = stwo_m31_add(b77, b1);
    b77 = 0u;
    b1 = stwo_trace_value(arena, *args, 2u, 0u, row, 0);
    b0 = stwo_trace_value(arena, *args, 2u, 1u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 2u, 2u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 2u, 3u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 2u, 4u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 2u, 5u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 2u, 6u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 7u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 8u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 2u, 9u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 10u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 2u, 11u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e1 = { b76, b77, b77, b77 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    e2 = { b2, b77, b77, b77 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    e0 = { b3, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    e2 = { b4, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 5u * 4u);
    e0 = { b5, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 6u * 4u);
    e2 = { b6, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 7u * 4u);
    e0 = { b7, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 8u * 4u);
    e2 = { b8, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 9u * 4u);
    e0 = { b9, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 10u * 4u);
    e2 = { b10, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 11u * 4u);
    e0 = { b11, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 12u * 4u);
    e2 = { b12, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 13u * 4u);
    e0 = { b13, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 14u * 4u);
    e2 = { b14, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 15u * 4u);
    e0 = { b15, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 16u * 4u);
    e2 = { b16, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 17u * 4u);
    e0 = { b17, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 18u * 4u);
    e2 = { b18, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 19u * 4u);
    e0 = { b19, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 20u * 4u);
    e2 = { b20, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 21u * 4u);
    e0 = { b21, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 22u * 4u);
    e2 = { b22, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 23u * 4u);
    e0 = { b23, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 24u * 4u);
    e2 = { b24, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 25u * 4u);
    e0 = { b25, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 26u * 4u);
    e2 = { b26, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 27u * 4u);
    e0 = { b27, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 28u * 4u);
    e2 = { b28, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 29u * 4u);
    e0 = { b29, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 30u * 4u);
    e2 = { b30, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 31u * 4u);
    e0 = { b31, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 32u * 4u);
    e2 = { b32, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 33u * 4u);
    e0 = { b33, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 34u * 4u);
    e2 = { b34, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 35u * 4u);
    e0 = { b35, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 36u * 4u);
    e2 = { b36, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 37u * 4u);
    e0 = { b37, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 38u * 4u);
    e2 = { b38, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 39u * 4u);
    e0 = { b39, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 40u * 4u);
    e2 = { b40, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 41u * 4u);
    e0 = { b41, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 42u * 4u);
    e2 = { b42, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 43u * 4u);
    e0 = { b43, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 44u * 4u);
    e2 = { b44, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 45u * 4u);
    e0 = { b45, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 46u * 4u);
    e2 = { b46, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 47u * 4u);
    e0 = { b47, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 48u * 4u);
    e2 = { b48, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 49u * 4u);
    e0 = { b49, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 50u * 4u);
    e2 = { b50, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 51u * 4u);
    e0 = { b51, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 52u * 4u);
    e2 = { b52, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 53u * 4u);
    e0 = { b53, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 54u * 4u);
    e2 = { b54, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 55u * 4u);
    e0 = { b55, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 56u * 4u);
    e2 = { b56, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 57u * 4u);
    e0 = { b57, b77, b77, b77 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 58u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 59u * 4u);
    e0 = { b58, b77, b77, b77 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 60u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 61u * 4u);
    e3 = { b59, b77, b77, b77 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 62u * 4u);
    e1 = stwo_qm31_sub(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 63u * 4u);
    e3 = { b60, b77, b77, b77 };
    e0 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 64u * 4u);
    e4 = stwo_qm31_add(e3, e0);
    e3 = stwo_load_qm31(arena, args->ext_params + 65u * 4u);
    e0 = { b61, b77, b77, b77 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 66u * 4u);
    e4 = stwo_qm31_sub(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 67u * 4u);
    e0 = { b62, b77, b77, b77 };
    e3 = stwo_qm31_mul(e5, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 68u * 4u);
    e5 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 69u * 4u);
    e3 = { b63, b77, b77, b77 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 70u * 4u);
    e5 = stwo_qm31_sub(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 71u * 4u);
    e3 = { b64, b77, b77, b77 };
    e0 = stwo_qm31_mul(e6, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 72u * 4u);
    e6 = stwo_qm31_add(e3, e0);
    e3 = stwo_load_qm31(arena, args->ext_params + 73u * 4u);
    e0 = { b65, b77, b77, b77 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 74u * 4u);
    e6 = stwo_qm31_sub(e0, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 75u * 4u);
    e0 = { b66, b77, b77, b77 };
    e3 = stwo_qm31_mul(e7, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 76u * 4u);
    e7 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 77u * 4u);
    e3 = { b67, b77, b77, b77 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 78u * 4u);
    e7 = stwo_qm31_sub(e3, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 79u * 4u);
    e3 = { b68, b77, b77, b77 };
    e0 = stwo_qm31_mul(e8, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 80u * 4u);
    e8 = stwo_qm31_add(e3, e0);
    e3 = stwo_load_qm31(arena, args->ext_params + 81u * 4u);
    e0 = { b69, b77, b77, b77 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 82u * 4u);
    e8 = stwo_qm31_sub(e0, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 83u * 4u);
    e0 = { b70, b77, b77, b77 };
    e3 = stwo_qm31_mul(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 84u * 4u);
    e9 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 85u * 4u);
    e3 = { b71, b77, b77, b77 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 86u * 4u);
    e9 = stwo_qm31_sub(e3, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 87u * 4u);
    e3 = { b72, b77, b77, b77 };
    e0 = stwo_qm31_mul(e10, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 88u * 4u);
    e10 = stwo_qm31_add(e3, e0);
    e3 = stwo_load_qm31(arena, args->ext_params + 89u * 4u);
    e0 = { b73, b77, b77, b77 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 90u * 4u);
    e10 = stwo_qm31_sub(e0, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 91u * 4u);
    e0 = { b74, b77, b77, b77 };
    e3 = stwo_qm31_mul(e11, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 92u * 4u);
    e11 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 93u * 4u);
    e3 = { b75, b77, b77, b77 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e11, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 94u * 4u);
    e11 = stwo_qm31_sub(e3, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 627u * 4u);
    e3 = stwo_qm31_mul(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 628u * 4u);
    e0 = stwo_qm31_mul(e2, e12);
    e12 = stwo_qm31_add(e3, e0);
    e0 = stwo_qm31_mul(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 629u * 4u);
    e2 = stwo_qm31_mul(e5, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 630u * 4u);
    e3 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e2, e3);
    e3 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 631u * 4u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 632u * 4u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 633u * 4u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 634u * 4u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 635u * 4u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 636u * 4u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = { b1, b0, b78, b79 };
    e10 = stwo_qm31_mul(e11, e0);
    e0 = stwo_qm31_sub(e10, e12);
    e10 = { b80, b81, b82, b83 };
    e12 = stwo_qm31_sub(e10, e11);
    e11 = stwo_qm31_mul(e12, e3);
    e12 = stwo_qm31_sub(e11, e1);
    e11 = { b84, b85, b86, b87 };
    e1 = stwo_qm31_sub(e11, e10);
    e10 = stwo_qm31_mul(e1, e2);
    e1 = stwo_qm31_sub(e10, e5);
    e10 = { b88, b89, b90, b91 };
    e5 = stwo_qm31_sub(e10, e11);
    e11 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e11, e7);
    e11 = { b92, b93, b94, b95 };
    e7 = stwo_qm31_sub(e11, e10);
    e11 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e11, e9);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e12, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
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
