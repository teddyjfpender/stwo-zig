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
stwo_cairo_cuda_eval_v1_ba8710d9778672ac(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 101u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 103u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 104u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 105u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 107u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 108u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 109u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 110u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 111u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 112u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 113u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 114u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 115u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 116u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 117u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 118u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 119u, row, 0);
    unsigned b48 = 0u;
    unsigned b49 = 524288u;
    unsigned b50 = stwo_m31_add(b29, b49);
    b49 = 524288u;
    b29 = stwo_m31_add(b30, b49);
    b49 = 524288u;
    b30 = stwo_m31_add(b31, b49);
    b49 = 524288u;
    b31 = stwo_m31_add(b32, b49);
    b49 = 524288u;
    b32 = stwo_m31_add(b33, b49);
    b49 = 524288u;
    b33 = stwo_m31_add(b34, b49);
    b49 = 524288u;
    b34 = stwo_m31_add(b35, b49);
    b49 = 524288u;
    b35 = stwo_m31_add(b36, b49);
    b49 = 524288u;
    b36 = stwo_m31_add(b37, b49);
    b49 = 524288u;
    b37 = stwo_m31_add(b38, b49);
    b49 = 524288u;
    b38 = stwo_m31_add(b39, b49);
    b49 = 524288u;
    b39 = stwo_m31_add(b40, b49);
    b49 = 524288u;
    b40 = stwo_m31_add(b41, b49);
    b49 = 524288u;
    b41 = stwo_m31_add(b42, b49);
    b49 = 524288u;
    b42 = stwo_m31_add(b43, b49);
    b49 = 524288u;
    b43 = stwo_m31_add(b44, b49);
    b49 = 524288u;
    b44 = stwo_m31_add(b45, b49);
    b49 = 524288u;
    b45 = stwo_m31_add(b46, b49);
    b49 = 524288u;
    b46 = stwo_m31_add(b47, b49);
    b49 = stwo_trace_value(arena, *args, 2u, 8u, row, 0);
    b47 = stwo_trace_value(arena, *args, 2u, 9u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 2u, 10u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 2u, 11u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 2u, 20u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 2u, 21u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 2u, 22u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 2u, 23u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 24u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 25u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 26u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 27u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 28u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 2u, 29u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 2u, 30u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 2u, 31u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 2u, 32u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 2u, 33u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 34u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 35u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 36u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 2u, 37u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 2u, 38u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 2u, 39u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 2u, 40u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 2u, 41u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 42u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 43u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 2u, 44u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 45u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 2u, 46u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 2u, 47u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 2u, 48u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 2u, 49u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 2u, 50u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 2u, 51u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 82u * 4u);
    StwoCairoQm31 e1 = { b0, b48, b48, b48 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 83u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 84u * 4u);
    e2 = { b1, b48, b48, b48 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 85u * 4u);
    e0 = { b2, b48, b48, b48 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 86u * 4u);
    e2 = { b3, b48, b48, b48 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 87u * 4u);
    e0 = { b4, b48, b48, b48 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 88u * 4u);
    e2 = { b5, b48, b48, b48 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 89u * 4u);
    e0 = { b6, b48, b48, b48 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 90u * 4u);
    e2 = { b7, b48, b48, b48 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 91u * 4u);
    e0 = { b8, b48, b48, b48 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 92u * 4u);
    e2 = { b9, b48, b48, b48 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 93u * 4u);
    e0 = { b10, b48, b48, b48 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 94u * 4u);
    e2 = { b11, b48, b48, b48 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 95u * 4u);
    e0 = { b12, b48, b48, b48 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 96u * 4u);
    e2 = { b13, b48, b48, b48 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 97u * 4u);
    e0 = { b14, b48, b48, b48 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 98u * 4u);
    e2 = { b15, b48, b48, b48 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 99u * 4u);
    e0 = { b16, b48, b48, b48 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 100u * 4u);
    e2 = { b17, b48, b48, b48 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 101u * 4u);
    e0 = { b18, b48, b48, b48 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 102u * 4u);
    e2 = { b19, b48, b48, b48 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 103u * 4u);
    e0 = { b20, b48, b48, b48 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 104u * 4u);
    e2 = { b21, b48, b48, b48 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 105u * 4u);
    e0 = { b22, b48, b48, b48 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 106u * 4u);
    e2 = { b23, b48, b48, b48 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 107u * 4u);
    e0 = { b24, b48, b48, b48 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 108u * 4u);
    e2 = { b25, b48, b48, b48 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 109u * 4u);
    e0 = { b26, b48, b48, b48 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 110u * 4u);
    e2 = { b27, b48, b48, b48 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 111u * 4u);
    e0 = { b28, b48, b48, b48 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 112u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 113u * 4u);
    e0 = { b50, b48, b48, b48 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 114u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 115u * 4u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 116u * 4u);
    e1 = { b29, b48, b48, b48 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 117u * 4u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(arena, args->ext_params + 118u * 4u);
    e4 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 119u * 4u);
    e0 = { b30, b48, b48, b48 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 120u * 4u);
    e1 = stwo_qm31_add(e0, e5);
    e0 = stwo_load_qm31(arena, args->ext_params + 121u * 4u);
    e5 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 122u * 4u);
    e1 = { b31, b48, b48, b48 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 123u * 4u);
    e0 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(arena, args->ext_params + 124u * 4u);
    e6 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 125u * 4u);
    e0 = { b32, b48, b48, b48 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 126u * 4u);
    e1 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(arena, args->ext_params + 127u * 4u);
    e7 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 128u * 4u);
    e1 = { b33, b48, b48, b48 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 129u * 4u);
    e0 = stwo_qm31_add(e1, e8);
    e1 = stwo_load_qm31(arena, args->ext_params + 130u * 4u);
    e8 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 131u * 4u);
    e0 = { b34, b48, b48, b48 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 132u * 4u);
    e1 = stwo_qm31_add(e0, e9);
    e0 = stwo_load_qm31(arena, args->ext_params + 133u * 4u);
    e9 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 134u * 4u);
    e1 = { b35, b48, b48, b48 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 135u * 4u);
    e0 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(arena, args->ext_params + 136u * 4u);
    e10 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 137u * 4u);
    e0 = { b36, b48, b48, b48 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 138u * 4u);
    e1 = stwo_qm31_add(e0, e11);
    e0 = stwo_load_qm31(arena, args->ext_params + 139u * 4u);
    e11 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 140u * 4u);
    e1 = { b37, b48, b48, b48 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 141u * 4u);
    e0 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(arena, args->ext_params + 142u * 4u);
    e12 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 143u * 4u);
    e0 = { b38, b48, b48, b48 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 144u * 4u);
    e1 = stwo_qm31_add(e0, e13);
    e0 = stwo_load_qm31(arena, args->ext_params + 145u * 4u);
    e13 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 146u * 4u);
    e1 = { b39, b48, b48, b48 };
    StwoCairoQm31 e14 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 147u * 4u);
    e0 = stwo_qm31_add(e1, e14);
    e1 = stwo_load_qm31(arena, args->ext_params + 148u * 4u);
    e14 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 149u * 4u);
    e0 = { b40, b48, b48, b48 };
    StwoCairoQm31 e15 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 150u * 4u);
    e1 = stwo_qm31_add(e0, e15);
    e0 = stwo_load_qm31(arena, args->ext_params + 151u * 4u);
    e15 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 152u * 4u);
    e1 = { b41, b48, b48, b48 };
    StwoCairoQm31 e16 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 153u * 4u);
    e0 = stwo_qm31_add(e1, e16);
    e1 = stwo_load_qm31(arena, args->ext_params + 154u * 4u);
    e16 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 155u * 4u);
    e0 = { b42, b48, b48, b48 };
    StwoCairoQm31 e17 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 156u * 4u);
    e1 = stwo_qm31_add(e0, e17);
    e0 = stwo_load_qm31(arena, args->ext_params + 157u * 4u);
    e17 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 158u * 4u);
    e1 = { b43, b48, b48, b48 };
    StwoCairoQm31 e18 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 159u * 4u);
    e0 = stwo_qm31_add(e1, e18);
    e1 = stwo_load_qm31(arena, args->ext_params + 160u * 4u);
    e18 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 161u * 4u);
    e0 = { b44, b48, b48, b48 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 162u * 4u);
    e1 = stwo_qm31_add(e0, e19);
    e0 = stwo_load_qm31(arena, args->ext_params + 163u * 4u);
    e19 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 164u * 4u);
    e1 = { b45, b48, b48, b48 };
    StwoCairoQm31 e20 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 165u * 4u);
    e0 = stwo_qm31_add(e1, e20);
    e1 = stwo_load_qm31(arena, args->ext_params + 166u * 4u);
    e20 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 167u * 4u);
    e0 = { b46, b48, b48, b48 };
    StwoCairoQm31 e21 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 168u * 4u);
    e1 = stwo_qm31_add(e0, e21);
    e0 = stwo_load_qm31(arena, args->ext_params + 169u * 4u);
    e21 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 213u * 4u);
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 214u * 4u);
    StwoCairoQm31 e22 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e1, e22);
    e22 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 215u * 4u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 216u * 4u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 217u * 4u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 218u * 4u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 219u * 4u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 220u * 4u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 221u * 4u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 222u * 4u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 223u * 4u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 224u * 4u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 225u * 4u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 226u * 4u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 227u * 4u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 228u * 4u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 229u * 4u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 230u * 4u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 231u * 4u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 232u * 4u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e20, e21);
    e21 = { b49, b47, b51, b52 };
    e20 = { b53, b54, b55, b56 };
    e18 = stwo_qm31_sub(e20, e21);
    e21 = stwo_qm31_mul(e18, e22);
    e18 = stwo_qm31_sub(e21, e0);
    e21 = { b57, b58, b59, b60 };
    e0 = stwo_qm31_sub(e21, e20);
    e20 = stwo_qm31_mul(e0, e1);
    e0 = stwo_qm31_sub(e20, e3);
    e20 = { b61, b62, b63, b64 };
    e3 = stwo_qm31_sub(e20, e21);
    e21 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e21, e5);
    e21 = { b65, b66, b67, b68 };
    e5 = stwo_qm31_sub(e21, e20);
    e20 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e20, e7);
    e20 = { b69, b70, b71, b72 };
    e7 = stwo_qm31_sub(e20, e21);
    e21 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e21, e9);
    e21 = { b73, b74, b75, b76 };
    e9 = stwo_qm31_sub(e21, e20);
    e20 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e20, e11);
    e20 = { b77, b78, b79, b80 };
    e11 = stwo_qm31_sub(e20, e21);
    e21 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e21, e13);
    e21 = { b81, b82, b83, b84 };
    e13 = stwo_qm31_sub(e21, e20);
    e20 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e20, e15);
    e20 = { b85, b86, b87, b88 };
    e15 = stwo_qm31_sub(e20, e21);
    e21 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e21, e17);
    e21 = { b89, b90, b91, b92 };
    e17 = stwo_qm31_sub(e21, e20);
    e21 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e21, e19);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e18, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e9, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e11, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e13, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e15, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 8u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e17, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 9u) * 4u)));
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
