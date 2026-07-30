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
stwo_cairo_cuda_eval_v1_c68706440509088f(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 51u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 62u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 63u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 101u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 103u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 104u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 105u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 107u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 112u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 113u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 114u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 115u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 116u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 117u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 118u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 119u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 120u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 121u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 122u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 123u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 126u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 143u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 144u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 145u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b62 = 0u;
    unsigned b63 = 512u;
    unsigned b64 = stwo_m31_mul(b1, b63);
    b63 = stwo_m31_add(b0, b64);
    b64 = 262144u;
    b0 = stwo_m31_mul(b2, b64);
    b64 = stwo_m31_add(b63, b0);
    b0 = 134217728u;
    b63 = stwo_m31_mul(b3, b0);
    b0 = stwo_m31_add(b64, b63);
    b63 = 4u;
    b64 = stwo_m31_mul(b56, b63);
    b63 = stwo_m31_sub(b41, b64);
    b64 = 512u;
    b41 = stwo_m31_mul(b55, b64);
    b64 = stwo_m31_sub(b40, b41);
    b41 = 128u;
    b40 = stwo_m31_mul(b63, b41);
    b41 = stwo_m31_add(b55, b40);
    b40 = 512u;
    b3 = stwo_m31_mul(b57, b40);
    b40 = stwo_m31_sub(b56, b3);
    b3 = 4u;
    b56 = stwo_m31_mul(b60, b3);
    b3 = stwo_m31_sub(b42, b56);
    b56 = stwo_trace_value(arena, *args, 2u, 80u, row, 0);
    b42 = stwo_trace_value(arena, *args, 2u, 81u, row, 0);
    b60 = stwo_trace_value(arena, *args, 2u, 82u, row, 0);
    b2 = stwo_trace_value(arena, *args, 2u, 83u, row, 0);
    b1 = stwo_trace_value(arena, *args, 2u, 84u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 85u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 86u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 87u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 88u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 89u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 2u, 90u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 2u, 91u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 2u, 92u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 2u, 93u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 2u, 94u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 95u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 96u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 97u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 2u, 98u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 2u, 99u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 2u, 100u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 2u, 101u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 2u, 102u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 103u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 516u * 4u);
    StwoCairoQm31 e1 = { b16, b62, b62, b62 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 517u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 518u * 4u);
    e2 = { b17, b62, b62, b62 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 519u * 4u);
    e0 = { b28, b62, b62, b62 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 520u * 4u);
    e2 = { b29, b62, b62, b62 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 521u * 4u);
    e0 = { b4, b62, b62, b62 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 522u * 4u);
    e2 = { b5, b62, b62, b62 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 523u * 4u);
    e0 = { b43, b62, b62, b62 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 524u * 4u);
    e2 = { b44, b62, b62, b62 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 525u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 526u * 4u);
    e2 = { b18, b62, b62, b62 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 527u * 4u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 528u * 4u);
    e1 = { b19, b62, b62, b62 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 529u * 4u);
    e3 = { b30, b62, b62, b62 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 530u * 4u);
    e1 = { b31, b62, b62, b62 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 531u * 4u);
    e3 = { b6, b62, b62, b62 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 532u * 4u);
    e1 = { b7, b62, b62, b62 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 533u * 4u);
    e3 = { b45, b62, b62, b62 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 534u * 4u);
    e1 = { b46, b62, b62, b62 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 535u * 4u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 536u * 4u);
    e1 = { b20, b62, b62, b62 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 537u * 4u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 538u * 4u);
    e2 = { b21, b62, b62, b62 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 539u * 4u);
    e4 = { b32, b62, b62, b62 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 540u * 4u);
    e2 = { b33, b62, b62, b62 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 541u * 4u);
    e4 = { b8, b62, b62, b62 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 542u * 4u);
    e2 = { b9, b62, b62, b62 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 543u * 4u);
    e4 = { b47, b62, b62, b62 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 544u * 4u);
    e2 = { b48, b62, b62, b62 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 545u * 4u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 546u * 4u);
    e2 = { b22, b62, b62, b62 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 547u * 4u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 548u * 4u);
    e1 = { b23, b62, b62, b62 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 549u * 4u);
    e5 = { b34, b62, b62, b62 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 550u * 4u);
    e1 = { b35, b62, b62, b62 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 551u * 4u);
    e5 = { b10, b62, b62, b62 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 552u * 4u);
    e1 = { b11, b62, b62, b62 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 553u * 4u);
    e5 = { b49, b62, b62, b62 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 554u * 4u);
    e1 = { b50, b62, b62, b62 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 555u * 4u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 556u * 4u);
    e1 = { b24, b62, b62, b62 };
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 557u * 4u);
    e6 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 558u * 4u);
    e2 = { b25, b62, b62, b62 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 559u * 4u);
    e6 = { b36, b62, b62, b62 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 560u * 4u);
    e2 = { b37, b62, b62, b62 };
    e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 561u * 4u);
    e6 = { b12, b62, b62, b62 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 562u * 4u);
    e2 = { b13, b62, b62, b62 };
    e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 563u * 4u);
    e6 = { b51, b62, b62, b62 };
    e1 = stwo_qm31_mul(e7, e6);
    e6 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 564u * 4u);
    e2 = { b52, b62, b62, b62 };
    e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 565u * 4u);
    e6 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 566u * 4u);
    e2 = { b26, b62, b62, b62 };
    e1 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 567u * 4u);
    e7 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 568u * 4u);
    e1 = { b27, b62, b62, b62 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 569u * 4u);
    e7 = { b38, b62, b62, b62 };
    e2 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 570u * 4u);
    e1 = { b39, b62, b62, b62 };
    e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 571u * 4u);
    e7 = { b14, b62, b62, b62 };
    e2 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 572u * 4u);
    e1 = { b15, b62, b62, b62 };
    e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 573u * 4u);
    e7 = { b53, b62, b62, b62 };
    e2 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 574u * 4u);
    e1 = { b54, b62, b62, b62 };
    e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 575u * 4u);
    e7 = stwo_qm31_sub(e1, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 576u * 4u);
    e1 = { b55, b62, b62, b62 };
    e2 = stwo_qm31_mul(e8, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 577u * 4u);
    e8 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 578u * 4u);
    e2 = { b63, b62, b62, b62 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 579u * 4u);
    e8 = { b57, b62, b62, b62 };
    e1 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 580u * 4u);
    e2 = stwo_qm31_sub(e8, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 581u * 4u);
    e8 = { b0, b62, b62, b62 };
    e9 = stwo_qm31_mul(e1, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 582u * 4u);
    e1 = stwo_qm31_add(e8, e9);
    e8 = stwo_load_qm31(arena, args->ext_params + 583u * 4u);
    e9 = { b58, b62, b62, b62 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 584u * 4u);
    e1 = stwo_qm31_sub(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 585u * 4u);
    e9 = { b58, b62, b62, b62 };
    e8 = stwo_qm31_mul(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 586u * 4u);
    e10 = stwo_qm31_add(e9, e8);
    e9 = stwo_load_qm31(arena, args->ext_params + 587u * 4u);
    e8 = { b64, b62, b62, b62 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 588u * 4u);
    e10 = { b41, b62, b62, b62 };
    e9 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 589u * 4u);
    e8 = { b40, b62, b62, b62 };
    e11 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 590u * 4u);
    e10 = { b57, b62, b62, b62 };
    e9 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 591u * 4u);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 592u * 4u);
    e10 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 593u * 4u);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 594u * 4u);
    e10 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 595u * 4u);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 596u * 4u);
    e10 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 597u * 4u);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 598u * 4u);
    e10 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 599u * 4u);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 600u * 4u);
    e10 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 601u * 4u);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 602u * 4u);
    e10 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 603u * 4u);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 604u * 4u);
    e10 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 605u * 4u);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 606u * 4u);
    e10 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 607u * 4u);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 608u * 4u);
    e10 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 609u * 4u);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 610u * 4u);
    e10 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 611u * 4u);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 612u * 4u);
    e10 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 613u * 4u);
    e8 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 614u * 4u);
    e10 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 615u * 4u);
    e8 = stwo_qm31_sub(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 616u * 4u);
    e10 = { b59, b62, b62, b62 };
    e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 617u * 4u);
    e9 = stwo_qm31_add(e10, e11);
    e10 = stwo_load_qm31(arena, args->ext_params + 618u * 4u);
    e11 = { b3, b62, b62, b62 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e10, e11);
    e11 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 619u * 4u);
    e9 = { b61, b62, b62, b62 };
    e10 = stwo_qm31_mul(e12, e9);
    e9 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 620u * 4u);
    e11 = stwo_qm31_sub(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 948u * 4u);
    e9 = stwo_qm31_mul(e3, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 949u * 4u);
    e12 = stwo_qm31_mul(e0, e10);
    e10 = stwo_qm31_add(e9, e12);
    e12 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 950u * 4u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 951u * 4u);
    e9 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e9);
    e9 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 952u * 4u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 953u * 4u);
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 954u * 4u);
    e6 = stwo_qm31_mul(e1, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 955u * 4u);
    e4 = stwo_qm31_mul(e2, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 956u * 4u);
    e2 = stwo_qm31_mul(e11, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 957u * 4u);
    e6 = stwo_qm31_mul(e8, e1);
    e1 = stwo_qm31_add(e2, e6);
    e6 = stwo_qm31_mul(e8, e11);
    e11 = { b56, b42, b60, b2 };
    e8 = { b1, b65, b66, b67 };
    e2 = stwo_qm31_sub(e8, e11);
    e11 = stwo_qm31_mul(e2, e12);
    e2 = stwo_qm31_sub(e11, e10);
    e11 = { b68, b69, b70, b71 };
    e10 = stwo_qm31_sub(e11, e8);
    e8 = stwo_qm31_mul(e10, e9);
    e10 = stwo_qm31_sub(e8, e3);
    e8 = { b72, b73, b74, b75 };
    e3 = stwo_qm31_sub(e8, e11);
    e11 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e11, e5);
    e11 = { b76, b77, b78, b79 };
    e5 = stwo_qm31_sub(e11, e8);
    e8 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e8, e7);
    e8 = { b80, b81, b82, b83 };
    e7 = stwo_qm31_sub(e8, e11);
    e8 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e8, e1);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e10, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
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
