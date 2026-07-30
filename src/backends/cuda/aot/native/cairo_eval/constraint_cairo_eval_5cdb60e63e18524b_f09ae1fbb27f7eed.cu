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
stwo_cairo_cuda_eval_v1_4dee333ccda82e8a(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 0u, 0u, row, 0);
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
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 65u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 66u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 67u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 71u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 101u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 103u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 104u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 105u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 107u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 108u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 109u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 110u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 111u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 112u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 113u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 114u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 115u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 116u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 117u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 118u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 119u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 120u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 1u, 121u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 1u, 122u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 1u, 123u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 1u, 124u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 1u, 126u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 1u, 127u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b96 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b97 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b98 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b99 = 0u;
    unsigned b100 = 2u;
    unsigned b101 = stwo_m31_mul(b0, b100);
    b100 = 512u;
    b0 = stwo_m31_mul(b2, b100);
    b100 = stwo_m31_add(b1, b0);
    b0 = 512u;
    b1 = stwo_m31_mul(b4, b0);
    b0 = stwo_m31_add(b3, b1);
    b1 = 512u;
    b3 = stwo_m31_mul(b6, b1);
    b1 = stwo_m31_add(b5, b3);
    b3 = 512u;
    b5 = stwo_m31_mul(b8, b3);
    b3 = stwo_m31_add(b7, b5);
    b5 = 512u;
    b7 = stwo_m31_mul(b10, b5);
    b5 = stwo_m31_add(b9, b7);
    b7 = 512u;
    b9 = stwo_m31_mul(b12, b7);
    b7 = stwo_m31_add(b11, b9);
    b9 = 512u;
    b11 = stwo_m31_mul(b14, b9);
    b9 = stwo_m31_add(b13, b11);
    b11 = 512u;
    b13 = stwo_m31_mul(b16, b11);
    b11 = stwo_m31_add(b15, b13);
    b13 = 512u;
    b15 = stwo_m31_mul(b18, b13);
    b13 = stwo_m31_add(b17, b15);
    b15 = 512u;
    b17 = stwo_m31_mul(b20, b15);
    b15 = stwo_m31_add(b19, b17);
    b17 = 512u;
    b19 = stwo_m31_mul(b22, b17);
    b17 = stwo_m31_add(b21, b19);
    b19 = 512u;
    b21 = stwo_m31_mul(b24, b19);
    b19 = stwo_m31_add(b23, b21);
    b21 = 512u;
    b23 = stwo_m31_mul(b26, b21);
    b21 = stwo_m31_add(b25, b23);
    b23 = 512u;
    b25 = stwo_m31_mul(b28, b23);
    b23 = stwo_m31_add(b27, b25);
    b25 = stwo_trace_value(arena, *args, 2u, 8u, row, 0);
    b27 = stwo_trace_value(arena, *args, 2u, 9u, row, 0);
    b28 = stwo_trace_value(arena, *args, 2u, 10u, row, 0);
    b26 = stwo_trace_value(arena, *args, 2u, 11u, row, 0);
    b24 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    b22 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    b20 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    b18 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 74u * 4u);
    StwoCairoQm31 e1 = { b101, b99, b99, b99 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 75u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 76u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 77u * 4u);
    e0 = { b100, b99, b99, b99 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 78u * 4u);
    e2 = { b0, b99, b99, b99 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 79u * 4u);
    e0 = { b1, b99, b99, b99 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 80u * 4u);
    e2 = { b3, b99, b99, b99 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 81u * 4u);
    e0 = { b5, b99, b99, b99 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 82u * 4u);
    e2 = { b7, b99, b99, b99 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 83u * 4u);
    e0 = { b9, b99, b99, b99 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 84u * 4u);
    e2 = { b11, b99, b99, b99 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 85u * 4u);
    e0 = { b13, b99, b99, b99 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 86u * 4u);
    e2 = { b15, b99, b99, b99 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 87u * 4u);
    e0 = { b17, b99, b99, b99 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 88u * 4u);
    e2 = { b19, b99, b99, b99 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 89u * 4u);
    e0 = { b21, b99, b99, b99 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 90u * 4u);
    e2 = { b23, b99, b99, b99 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 91u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 92u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 93u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 94u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 95u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 96u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 97u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 98u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 99u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 100u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 101u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 102u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 103u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 104u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 105u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 106u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 107u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 108u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 109u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 110u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 111u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 112u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 113u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 114u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 115u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 116u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 117u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 118u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 119u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 120u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 121u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 122u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 123u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 124u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 125u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 126u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 127u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 128u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 129u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 130u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 131u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 132u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 133u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 134u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 135u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 136u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 137u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 138u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 139u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 140u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 141u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 142u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 143u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 144u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 145u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 146u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 147u * 4u);
    e0 = stwo_qm31_sub(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 148u * 4u);
    e2 = { b101, b99, b99, b99 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 149u * 4u);
    e1 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(arena, args->ext_params + 150u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 151u * 4u);
    e1 = { b29, b99, b99, b99 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 152u * 4u);
    e3 = { b30, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 153u * 4u);
    e1 = { b31, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 154u * 4u);
    e3 = { b32, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 155u * 4u);
    e1 = { b33, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 156u * 4u);
    e3 = { b34, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 157u * 4u);
    e1 = { b35, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 158u * 4u);
    e3 = { b36, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 159u * 4u);
    e1 = { b37, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 160u * 4u);
    e3 = { b38, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 161u * 4u);
    e1 = { b39, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 162u * 4u);
    e3 = { b40, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 163u * 4u);
    e1 = { b41, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 164u * 4u);
    e3 = { b42, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 165u * 4u);
    e1 = { b43, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 166u * 4u);
    e3 = { b44, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 167u * 4u);
    e1 = { b45, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 168u * 4u);
    e3 = { b46, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 169u * 4u);
    e1 = { b47, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 170u * 4u);
    e3 = { b48, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 171u * 4u);
    e1 = { b49, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 172u * 4u);
    e3 = { b50, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 173u * 4u);
    e1 = { b51, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 174u * 4u);
    e3 = { b52, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 175u * 4u);
    e1 = { b53, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 176u * 4u);
    e3 = { b54, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 177u * 4u);
    e1 = { b55, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 178u * 4u);
    e3 = { b56, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 179u * 4u);
    e1 = { b57, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 180u * 4u);
    e3 = { b58, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 181u * 4u);
    e1 = { b59, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 182u * 4u);
    e3 = { b60, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 183u * 4u);
    e1 = { b61, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 184u * 4u);
    e3 = { b62, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 185u * 4u);
    e1 = { b63, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 186u * 4u);
    e3 = { b64, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 187u * 4u);
    e1 = { b65, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 188u * 4u);
    e3 = { b66, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 189u * 4u);
    e1 = { b67, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 190u * 4u);
    e3 = { b68, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 191u * 4u);
    e1 = { b69, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 192u * 4u);
    e3 = { b70, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 193u * 4u);
    e1 = { b71, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 194u * 4u);
    e3 = { b72, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 195u * 4u);
    e1 = { b73, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 196u * 4u);
    e3 = { b74, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 197u * 4u);
    e1 = { b75, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 198u * 4u);
    e3 = { b76, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 199u * 4u);
    e1 = { b77, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 200u * 4u);
    e3 = { b78, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 201u * 4u);
    e1 = { b79, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 202u * 4u);
    e3 = { b80, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 203u * 4u);
    e1 = { b81, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 204u * 4u);
    e3 = { b82, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 205u * 4u);
    e1 = { b83, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 206u * 4u);
    e3 = { b84, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 207u * 4u);
    e1 = { b85, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 208u * 4u);
    e3 = { b86, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 209u * 4u);
    e1 = { b87, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 210u * 4u);
    e3 = { b88, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 211u * 4u);
    e1 = { b89, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 212u * 4u);
    e3 = { b90, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 213u * 4u);
    e1 = { b91, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 214u * 4u);
    e3 = { b92, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 215u * 4u);
    e1 = { b93, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 216u * 4u);
    e3 = { b94, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 217u * 4u);
    e1 = { b95, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 218u * 4u);
    e3 = { b96, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 219u * 4u);
    e1 = { b97, b99, b99, b99 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 220u * 4u);
    e3 = { b98, b99, b99, b99 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 221u * 4u);
    e1 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 412u * 4u);
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 413u * 4u);
    e4 = stwo_qm31_mul(e0, e2);
    e2 = stwo_qm31_add(e3, e4);
    e4 = stwo_qm31_mul(e0, e1);
    e1 = { b25, b27, b28, b26 };
    e0 = { b24, b22, b20, b18 };
    e3 = stwo_qm31_sub(e0, e1);
    e0 = stwo_qm31_mul(e3, e4);
    e3 = stwo_qm31_sub(e0, e2);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
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
