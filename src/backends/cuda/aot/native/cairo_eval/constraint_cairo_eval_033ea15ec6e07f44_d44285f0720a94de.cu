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
stwo_cairo_cuda_eval_v1_b3c599a886f3f67d(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 156u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 157u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 158u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 159u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 160u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 161u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 162u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 163u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 164u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 165u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 166u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 167u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 168u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 169u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 170u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 171u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 172u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 173u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 174u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 175u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 176u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 177u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 178u, row, 0);
    unsigned b33 = 0u;
    unsigned b34 = 524288u;
    unsigned b35 = stwo_m31_add(b10, b34);
    b34 = 524288u;
    b10 = stwo_m31_add(b11, b34);
    b34 = 524288u;
    b11 = stwo_m31_add(b12, b34);
    b34 = 524288u;
    b12 = stwo_m31_add(b13, b34);
    b34 = 524288u;
    b13 = stwo_m31_add(b14, b34);
    b34 = 524288u;
    b14 = stwo_m31_add(b15, b34);
    b34 = 524288u;
    b15 = stwo_m31_add(b16, b34);
    b34 = 524288u;
    b16 = stwo_m31_add(b17, b34);
    b34 = 524288u;
    b17 = stwo_m31_add(b18, b34);
    b34 = 524288u;
    b18 = stwo_m31_add(b19, b34);
    b34 = 524288u;
    b19 = stwo_m31_add(b20, b34);
    b34 = 524288u;
    b20 = stwo_m31_add(b21, b34);
    b34 = 524288u;
    b21 = stwo_m31_add(b22, b34);
    b34 = 524288u;
    b22 = stwo_m31_add(b23, b34);
    b34 = 524288u;
    b23 = stwo_m31_add(b24, b34);
    b34 = 524288u;
    b24 = stwo_m31_add(b25, b34);
    b34 = 524288u;
    b25 = stwo_m31_add(b26, b34);
    b34 = 524288u;
    b26 = stwo_m31_add(b27, b34);
    b34 = 524288u;
    b27 = stwo_m31_add(b28, b34);
    b34 = 524288u;
    b28 = stwo_m31_add(b29, b34);
    b34 = 524288u;
    b29 = stwo_m31_add(b30, b34);
    b34 = 524288u;
    b30 = stwo_m31_add(b31, b34);
    b34 = 524288u;
    b31 = stwo_m31_add(b32, b34);
    b34 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    b32 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 2u, 20u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 21u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 22u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 23u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 24u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 25u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 26u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 2u, 27u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 2u, 28u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 2u, 29u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 2u, 30u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 2u, 31u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 2u, 32u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 2u, 33u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 2u, 34u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 2u, 35u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 2u, 36u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 2u, 37u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 2u, 38u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 2u, 39u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 2u, 40u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 2u, 41u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 2u, 42u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 2u, 43u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 2u, 44u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 2u, 45u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 2u, 46u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 47u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 48u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 49u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 50u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 51u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 2u, 52u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 2u, 53u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 2u, 54u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 2u, 55u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 2u, 56u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 57u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 58u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 59u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 2u, 60u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 2u, 61u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 2u, 62u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 2u, 63u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 2u, 64u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 65u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 66u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 2u, 67u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 68u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 2u, 69u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 2u, 70u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 2u, 71u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 2u, 72u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 2u, 73u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 2u, 74u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 2u, 75u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 95u * 4u);
    StwoCairoQm31 e1 = { b0, b33, b33, b33 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 96u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 97u * 4u);
    e2 = { b1, b33, b33, b33 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 98u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 99u * 4u);
    e2 = { b2, b33, b33, b33 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 100u * 4u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 101u * 4u);
    e1 = { b3, b33, b33, b33 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 102u * 4u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 103u * 4u);
    e1 = { b4, b33, b33, b33 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 104u * 4u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 105u * 4u);
    e2 = { b5, b33, b33, b33 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 106u * 4u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 107u * 4u);
    e2 = { b6, b33, b33, b33 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 108u * 4u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 109u * 4u);
    e1 = { b7, b33, b33, b33 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 110u * 4u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 111u * 4u);
    e1 = { b8, b33, b33, b33 };
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 112u * 4u);
    e6 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 113u * 4u);
    e2 = { b9, b33, b33, b33 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 114u * 4u);
    e6 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 115u * 4u);
    e2 = { b35, b33, b33, b33 };
    e1 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 116u * 4u);
    e7 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 117u * 4u);
    e1 = stwo_qm31_sub(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 118u * 4u);
    e7 = { b10, b33, b33, b33 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 119u * 4u);
    e2 = stwo_qm31_add(e7, e8);
    e7 = stwo_load_qm31(arena, args->ext_params + 120u * 4u);
    e8 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 121u * 4u);
    e2 = { b11, b33, b33, b33 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 122u * 4u);
    e7 = stwo_qm31_add(e2, e9);
    e2 = stwo_load_qm31(arena, args->ext_params + 123u * 4u);
    e9 = stwo_qm31_sub(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 124u * 4u);
    e7 = { b12, b33, b33, b33 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 125u * 4u);
    e2 = stwo_qm31_add(e7, e10);
    e7 = stwo_load_qm31(arena, args->ext_params + 126u * 4u);
    e10 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 127u * 4u);
    e2 = { b13, b33, b33, b33 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 128u * 4u);
    e7 = stwo_qm31_add(e2, e11);
    e2 = stwo_load_qm31(arena, args->ext_params + 129u * 4u);
    e11 = stwo_qm31_sub(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 130u * 4u);
    e7 = { b14, b33, b33, b33 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 131u * 4u);
    e2 = stwo_qm31_add(e7, e12);
    e7 = stwo_load_qm31(arena, args->ext_params + 132u * 4u);
    e12 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 133u * 4u);
    e2 = { b15, b33, b33, b33 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 134u * 4u);
    e7 = stwo_qm31_add(e2, e13);
    e2 = stwo_load_qm31(arena, args->ext_params + 135u * 4u);
    e13 = stwo_qm31_sub(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 136u * 4u);
    e7 = { b16, b33, b33, b33 };
    StwoCairoQm31 e14 = stwo_qm31_mul(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 137u * 4u);
    e2 = stwo_qm31_add(e7, e14);
    e7 = stwo_load_qm31(arena, args->ext_params + 138u * 4u);
    e14 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 139u * 4u);
    e2 = { b17, b33, b33, b33 };
    StwoCairoQm31 e15 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 140u * 4u);
    e7 = stwo_qm31_add(e2, e15);
    e2 = stwo_load_qm31(arena, args->ext_params + 141u * 4u);
    e15 = stwo_qm31_sub(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 142u * 4u);
    e7 = { b18, b33, b33, b33 };
    StwoCairoQm31 e16 = stwo_qm31_mul(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 143u * 4u);
    e2 = stwo_qm31_add(e7, e16);
    e7 = stwo_load_qm31(arena, args->ext_params + 144u * 4u);
    e16 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 145u * 4u);
    e2 = { b19, b33, b33, b33 };
    StwoCairoQm31 e17 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 146u * 4u);
    e7 = stwo_qm31_add(e2, e17);
    e2 = stwo_load_qm31(arena, args->ext_params + 147u * 4u);
    e17 = stwo_qm31_sub(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 148u * 4u);
    e7 = { b20, b33, b33, b33 };
    StwoCairoQm31 e18 = stwo_qm31_mul(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 149u * 4u);
    e2 = stwo_qm31_add(e7, e18);
    e7 = stwo_load_qm31(arena, args->ext_params + 150u * 4u);
    e18 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 151u * 4u);
    e2 = { b21, b33, b33, b33 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 152u * 4u);
    e7 = stwo_qm31_add(e2, e19);
    e2 = stwo_load_qm31(arena, args->ext_params + 153u * 4u);
    e19 = stwo_qm31_sub(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 154u * 4u);
    e7 = { b22, b33, b33, b33 };
    StwoCairoQm31 e20 = stwo_qm31_mul(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 155u * 4u);
    e2 = stwo_qm31_add(e7, e20);
    e7 = stwo_load_qm31(arena, args->ext_params + 156u * 4u);
    e20 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 157u * 4u);
    e2 = { b23, b33, b33, b33 };
    StwoCairoQm31 e21 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 158u * 4u);
    e7 = stwo_qm31_add(e2, e21);
    e2 = stwo_load_qm31(arena, args->ext_params + 159u * 4u);
    e21 = stwo_qm31_sub(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 160u * 4u);
    e7 = { b24, b33, b33, b33 };
    StwoCairoQm31 e22 = stwo_qm31_mul(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 161u * 4u);
    e2 = stwo_qm31_add(e7, e22);
    e7 = stwo_load_qm31(arena, args->ext_params + 162u * 4u);
    e22 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 163u * 4u);
    e2 = { b25, b33, b33, b33 };
    StwoCairoQm31 e23 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 164u * 4u);
    e7 = stwo_qm31_add(e2, e23);
    e2 = stwo_load_qm31(arena, args->ext_params + 165u * 4u);
    e23 = stwo_qm31_sub(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 166u * 4u);
    e7 = { b26, b33, b33, b33 };
    StwoCairoQm31 e24 = stwo_qm31_mul(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 167u * 4u);
    e2 = stwo_qm31_add(e7, e24);
    e7 = stwo_load_qm31(arena, args->ext_params + 168u * 4u);
    e24 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 169u * 4u);
    e2 = { b27, b33, b33, b33 };
    StwoCairoQm31 e25 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 170u * 4u);
    e7 = stwo_qm31_add(e2, e25);
    e2 = stwo_load_qm31(arena, args->ext_params + 171u * 4u);
    e25 = stwo_qm31_sub(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 172u * 4u);
    e7 = { b28, b33, b33, b33 };
    StwoCairoQm31 e26 = stwo_qm31_mul(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 173u * 4u);
    e2 = stwo_qm31_add(e7, e26);
    e7 = stwo_load_qm31(arena, args->ext_params + 174u * 4u);
    e26 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 175u * 4u);
    e2 = { b29, b33, b33, b33 };
    StwoCairoQm31 e27 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 176u * 4u);
    e7 = stwo_qm31_add(e2, e27);
    e2 = stwo_load_qm31(arena, args->ext_params + 177u * 4u);
    e27 = stwo_qm31_sub(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 178u * 4u);
    e7 = { b30, b33, b33, b33 };
    StwoCairoQm31 e28 = stwo_qm31_mul(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 179u * 4u);
    e2 = stwo_qm31_add(e7, e28);
    e7 = stwo_load_qm31(arena, args->ext_params + 180u * 4u);
    e28 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 181u * 4u);
    e2 = { b31, b33, b33, b33 };
    StwoCairoQm31 e29 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 182u * 4u);
    e7 = stwo_qm31_add(e2, e29);
    e2 = stwo_load_qm31(arena, args->ext_params + 183u * 4u);
    e29 = stwo_qm31_sub(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 637u * 4u);
    e7 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 638u * 4u);
    StwoCairoQm31 e30 = stwo_qm31_mul(e0, e2);
    e2 = stwo_qm31_add(e7, e30);
    e30 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 639u * 4u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 640u * 4u);
    e7 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e7);
    e7 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 641u * 4u);
    e4 = stwo_qm31_mul(e1, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 642u * 4u);
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 643u * 4u);
    e6 = stwo_qm31_mul(e9, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 644u * 4u);
    e4 = stwo_qm31_mul(e8, e1);
    e1 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 645u * 4u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 646u * 4u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 647u * 4u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 648u * 4u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 649u * 4u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 650u * 4u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 651u * 4u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 652u * 4u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 653u * 4u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 654u * 4u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 655u * 4u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 656u * 4u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e20, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 657u * 4u);
    e20 = stwo_qm31_mul(e23, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 658u * 4u);
    e18 = stwo_qm31_mul(e22, e21);
    e21 = stwo_qm31_add(e20, e18);
    e18 = stwo_qm31_mul(e22, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 659u * 4u);
    e22 = stwo_qm31_mul(e25, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 660u * 4u);
    e20 = stwo_qm31_mul(e24, e23);
    e23 = stwo_qm31_add(e22, e20);
    e20 = stwo_qm31_mul(e24, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 661u * 4u);
    e24 = stwo_qm31_mul(e27, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 662u * 4u);
    e22 = stwo_qm31_mul(e26, e25);
    e25 = stwo_qm31_add(e24, e22);
    e22 = stwo_qm31_mul(e26, e27);
    e27 = stwo_load_qm31(arena, args->ext_params + 663u * 4u);
    e26 = stwo_qm31_mul(e29, e27);
    e27 = stwo_load_qm31(arena, args->ext_params + 664u * 4u);
    e24 = stwo_qm31_mul(e28, e27);
    e27 = stwo_qm31_add(e26, e24);
    e24 = stwo_qm31_mul(e28, e29);
    e29 = { b34, b32, b36, b37 };
    e28 = { b38, b39, b40, b41 };
    e26 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e26, e30);
    e26 = stwo_qm31_sub(e29, e2);
    e29 = { b42, b43, b44, b45 };
    e2 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e2, e7);
    e2 = stwo_qm31_sub(e28, e3);
    e28 = { b46, b47, b48, b49 };
    e3 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e29, e5);
    e29 = { b50, b51, b52, b53 };
    e5 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e28, e1);
    e28 = { b54, b55, b56, b57 };
    e1 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e1, e6);
    e1 = stwo_qm31_sub(e29, e9);
    e29 = { b58, b59, b60, b61 };
    e9 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e28, e11);
    e28 = { b62, b63, b64, b65 };
    e11 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e29, e13);
    e29 = { b66, b67, b68, b69 };
    e13 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e28, e15);
    e28 = { b70, b71, b72, b73 };
    e15 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e29, e17);
    e29 = { b74, b75, b76, b77 };
    e17 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e28, e19);
    e28 = { b78, b79, b80, b81 };
    e19 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e19, e18);
    e19 = stwo_qm31_sub(e29, e21);
    e29 = { b82, b83, b84, b85 };
    e21 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e21, e20);
    e21 = stwo_qm31_sub(e28, e23);
    e28 = { b86, b87, b88, b89 };
    e23 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e23, e22);
    e23 = stwo_qm31_sub(e29, e25);
    e29 = { b90, b91, b92, b93 };
    e25 = stwo_qm31_sub(e29, e28);
    e29 = stwo_qm31_mul(e25, e24);
    e25 = stwo_qm31_sub(e29, e27);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e26, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e9, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e11, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e13, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e15, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 8u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e17, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 9u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e19, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 10u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e21, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 11u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e23, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 12u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e25, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 13u) * 4u)));
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
