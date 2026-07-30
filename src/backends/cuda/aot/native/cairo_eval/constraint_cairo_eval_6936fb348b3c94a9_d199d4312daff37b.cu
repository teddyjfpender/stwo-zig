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
stwo_cairo_cuda_eval_v1_d85e8dd5532d08c0(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 0u, 0u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 10u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 51u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 62u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 63u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 101u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 103u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 104u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 105u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 107u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 108u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 109u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 110u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 111u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 112u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 113u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 114u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 115u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 116u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 117u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 118u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 119u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 120u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 121u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 122u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 123u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 124u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 126u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 127u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b63 = 0u;
    unsigned b64 = 512u;
    unsigned b65 = stwo_m31_mul(b3, b64);
    b64 = stwo_m31_add(b2, b65);
    b65 = 262144u;
    b2 = stwo_m31_mul(b4, b65);
    b65 = stwo_m31_add(b64, b2);
    b2 = 134217728u;
    b64 = stwo_m31_mul(b5, b2);
    b2 = stwo_m31_add(b65, b64);
    b64 = 1u;
    b65 = stwo_m31_sub(b1, b64);
    b64 = 256u;
    b1 = stwo_m31_mul(b23, b64);
    b64 = stwo_m31_add(b22, b1);
    b1 = 256u;
    b22 = stwo_m31_mul(b25, b1);
    b1 = stwo_m31_add(b24, b22);
    b22 = 9812u;
    b24 = stwo_m31_mul(b65, b22);
    b22 = 1u;
    b25 = stwo_m31_sub(b22, b65);
    b22 = 55723u;
    b23 = stwo_m31_mul(b25, b22);
    b22 = stwo_m31_add(b24, b23);
    b23 = 57468u;
    b24 = stwo_m31_mul(b65, b23);
    b23 = 1u;
    b25 = stwo_m31_sub(b23, b65);
    b23 = 8067u;
    b65 = stwo_m31_mul(b25, b23);
    b23 = stwo_m31_add(b24, b65);
    b65 = stwo_trace_value(arena, *args, 2u, 72u, row, 0);
    b24 = stwo_trace_value(arena, *args, 2u, 73u, row, 0);
    b25 = stwo_trace_value(arena, *args, 2u, 74u, row, 0);
    b5 = stwo_trace_value(arena, *args, 2u, 75u, row, 0);
    b4 = stwo_trace_value(arena, *args, 2u, 76u, row, 0);
    b3 = stwo_trace_value(arena, *args, 2u, 77u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 78u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 79u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 80u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 81u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 2u, 82u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 2u, 83u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 422u * 4u);
    StwoCairoQm31 e1 = { b0, b63, b63, b63 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 423u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 424u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 425u * 4u);
    e0 = { b6, b63, b63, b63 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 426u * 4u);
    e2 = { b7, b63, b63, b63 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 427u * 4u);
    e0 = { b8, b63, b63, b63 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 428u * 4u);
    e2 = { b9, b63, b63, b63 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 429u * 4u);
    e0 = { b10, b63, b63, b63 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 430u * 4u);
    e2 = { b11, b63, b63, b63 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 431u * 4u);
    e0 = { b12, b63, b63, b63 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 432u * 4u);
    e2 = { b13, b63, b63, b63 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 433u * 4u);
    e0 = { b14, b63, b63, b63 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 434u * 4u);
    e2 = { b15, b63, b63, b63 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 435u * 4u);
    e0 = { b16, b63, b63, b63 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 436u * 4u);
    e2 = { b17, b63, b63, b63 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 437u * 4u);
    e0 = { b18, b63, b63, b63 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 438u * 4u);
    e2 = { b19, b63, b63, b63 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 439u * 4u);
    e0 = { b20, b63, b63, b63 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 440u * 4u);
    e2 = { b21, b63, b63, b63 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 441u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 442u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 443u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 444u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 445u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 446u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 447u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 448u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 449u * 4u);
    e0 = { b64, b63, b63, b63 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 450u * 4u);
    e2 = { b1, b63, b63, b63 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 451u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 452u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 453u * 4u);
    e0 = { b22, b63, b63, b63 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 454u * 4u);
    e2 = { b23, b63, b63, b63 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 455u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 456u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 457u * 4u);
    e0 = { b2, b63, b63, b63 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 458u * 4u);
    e2 = stwo_qm31_sub(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 459u * 4u);
    e0 = { b0, b63, b63, b63 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 460u * 4u);
    e3 = stwo_qm31_add(e0, e1);
    e0 = stwo_load_qm31(arena, args->ext_params + 461u * 4u);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 462u * 4u);
    e3 = { b26, b63, b63, b63 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 463u * 4u);
    e1 = { b27, b63, b63, b63 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 464u * 4u);
    e3 = { b28, b63, b63, b63 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 465u * 4u);
    e1 = { b29, b63, b63, b63 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 466u * 4u);
    e3 = { b30, b63, b63, b63 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 467u * 4u);
    e1 = { b31, b63, b63, b63 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 468u * 4u);
    e3 = { b32, b63, b63, b63 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 469u * 4u);
    e1 = { b33, b63, b63, b63 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 470u * 4u);
    e3 = { b34, b63, b63, b63 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 471u * 4u);
    e1 = { b35, b63, b63, b63 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 472u * 4u);
    e3 = { b36, b63, b63, b63 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 473u * 4u);
    e1 = { b37, b63, b63, b63 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 474u * 4u);
    e3 = { b38, b63, b63, b63 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 475u * 4u);
    e1 = { b39, b63, b63, b63 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 476u * 4u);
    e3 = { b40, b63, b63, b63 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 477u * 4u);
    e1 = { b41, b63, b63, b63 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 478u * 4u);
    e3 = { b42, b63, b63, b63 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 479u * 4u);
    e1 = { b43, b63, b63, b63 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 480u * 4u);
    e3 = { b44, b63, b63, b63 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 481u * 4u);
    e1 = { b45, b63, b63, b63 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 482u * 4u);
    e3 = { b46, b63, b63, b63 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 483u * 4u);
    e1 = { b47, b63, b63, b63 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 484u * 4u);
    e3 = { b48, b63, b63, b63 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 485u * 4u);
    e1 = { b49, b63, b63, b63 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 486u * 4u);
    e3 = { b50, b63, b63, b63 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 487u * 4u);
    e1 = { b51, b63, b63, b63 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 488u * 4u);
    e3 = { b52, b63, b63, b63 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 489u * 4u);
    e1 = { b53, b63, b63, b63 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 490u * 4u);
    e3 = { b54, b63, b63, b63 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 491u * 4u);
    e1 = { b55, b63, b63, b63 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 492u * 4u);
    e3 = { b56, b63, b63, b63 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 493u * 4u);
    e1 = { b57, b63, b63, b63 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 494u * 4u);
    e3 = { b58, b63, b63, b63 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 495u * 4u);
    e1 = stwo_qm31_sub(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 496u * 4u);
    e3 = { b26, b63, b63, b63 };
    e0 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 497u * 4u);
    e4 = stwo_qm31_add(e3, e0);
    e3 = stwo_load_qm31(arena, args->ext_params + 498u * 4u);
    e0 = { b27, b63, b63, b63 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 499u * 4u);
    e4 = { b42, b63, b63, b63 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 500u * 4u);
    e0 = { b43, b63, b63, b63 };
    e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 501u * 4u);
    e4 = { b6, b63, b63, b63 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 502u * 4u);
    e0 = { b7, b63, b63, b63 };
    e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 503u * 4u);
    e4 = { b59, b63, b63, b63 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 504u * 4u);
    e0 = { b60, b63, b63, b63 };
    e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 505u * 4u);
    e4 = stwo_qm31_sub(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 506u * 4u);
    e0 = { b28, b63, b63, b63 };
    e3 = stwo_qm31_mul(e5, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 507u * 4u);
    e5 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 508u * 4u);
    e3 = { b29, b63, b63, b63 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 509u * 4u);
    e5 = { b44, b63, b63, b63 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 510u * 4u);
    e3 = { b45, b63, b63, b63 };
    e6 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 511u * 4u);
    e5 = { b8, b63, b63, b63 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 512u * 4u);
    e3 = { b9, b63, b63, b63 };
    e6 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 513u * 4u);
    e5 = { b61, b63, b63, b63 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 514u * 4u);
    e3 = { b62, b63, b63, b63 };
    e6 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 515u * 4u);
    e5 = stwo_qm31_sub(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 944u * 4u);
    e3 = stwo_qm31_mul(e1, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 945u * 4u);
    e0 = stwo_qm31_mul(e2, e6);
    e6 = stwo_qm31_add(e3, e0);
    e0 = stwo_qm31_mul(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 946u * 4u);
    e2 = stwo_qm31_mul(e5, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 947u * 4u);
    e3 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e2, e3);
    e3 = stwo_qm31_mul(e4, e5);
    e5 = { b65, b24, b25, b5 };
    e4 = { b4, b3, b66, b67 };
    e2 = stwo_qm31_sub(e4, e5);
    e5 = stwo_qm31_mul(e2, e0);
    e2 = stwo_qm31_sub(e5, e6);
    e5 = { b68, b69, b70, b71 };
    e6 = stwo_qm31_sub(e5, e4);
    e5 = stwo_qm31_mul(e6, e3);
    e6 = stwo_qm31_sub(e5, e1);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e6, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
