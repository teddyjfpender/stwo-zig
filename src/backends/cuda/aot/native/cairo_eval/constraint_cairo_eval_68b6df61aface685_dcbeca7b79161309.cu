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
stwo_cairo_cuda_eval_v1_ef9b97dec27c4ac8(
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
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 10u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 11u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 19u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 25u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 41u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 42u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 43u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 47u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 48u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 49u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 51u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 52u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 53u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 54u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 55u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 58u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 59u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 60u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 61u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 62u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 63u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 64u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 65u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 66u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 67u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 71u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 289u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 290u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 291u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 292u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 293u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 294u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 295u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 296u, row, 0);
    unsigned b80 = 0u;
    unsigned b81 = 524288u;
    unsigned b82 = stwo_m31_add(b72, b81);
    b81 = 524288u;
    b72 = stwo_m31_add(b73, b81);
    b81 = 524288u;
    b73 = stwo_m31_add(b74, b81);
    b81 = 524288u;
    b74 = stwo_m31_add(b75, b81);
    b81 = 524288u;
    b75 = stwo_m31_add(b76, b81);
    b81 = 524288u;
    b76 = stwo_m31_add(b77, b81);
    b81 = 524288u;
    b77 = stwo_m31_add(b78, b81);
    b81 = stwo_trace_value(arena, *args, 2u, 236u, row, 0);
    b78 = stwo_trace_value(arena, *args, 2u, 237u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 238u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 239u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 2u, 240u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 241u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 2u, 242u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 2u, 243u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 2u, 244u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 2u, 245u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 2u, 246u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 2u, 247u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 2u, 248u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 2u, 249u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 2u, 250u, row, 0);
    unsigned b96 = stwo_trace_value(arena, *args, 2u, 251u, row, 0);
    unsigned b97 = stwo_trace_value(arena, *args, 2u, 252u, row, 0);
    unsigned b98 = stwo_trace_value(arena, *args, 2u, 253u, row, 0);
    unsigned b99 = stwo_trace_value(arena, *args, 2u, 254u, row, 0);
    unsigned b100 = stwo_trace_value(arena, *args, 2u, 255u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 458u * 4u);
    StwoCairoQm31 e1 = { b82, b80, b80, b80 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 459u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 460u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 461u * 4u);
    e0 = { b72, b80, b80, b80 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 462u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 463u * 4u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 464u * 4u);
    e1 = { b73, b80, b80, b80 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 465u * 4u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(arena, args->ext_params + 466u * 4u);
    e4 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 467u * 4u);
    e0 = { b74, b80, b80, b80 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 468u * 4u);
    e1 = stwo_qm31_add(e0, e5);
    e0 = stwo_load_qm31(arena, args->ext_params + 469u * 4u);
    e5 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 470u * 4u);
    e1 = { b75, b80, b80, b80 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 471u * 4u);
    e0 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(arena, args->ext_params + 472u * 4u);
    e6 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 473u * 4u);
    e0 = { b76, b80, b80, b80 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 474u * 4u);
    e1 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(arena, args->ext_params + 475u * 4u);
    e7 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 476u * 4u);
    e1 = { b77, b80, b80, b80 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 477u * 4u);
    e0 = stwo_qm31_add(e1, e8);
    e1 = stwo_load_qm31(arena, args->ext_params + 478u * 4u);
    e8 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 479u * 4u);
    e0 = { b0, b80, b80, b80 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 480u * 4u);
    e1 = stwo_qm31_add(e0, e9);
    e0 = stwo_load_qm31(arena, args->ext_params + 481u * 4u);
    e9 = { b1, b80, b80, b80 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 482u * 4u);
    e1 = { b2, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 483u * 4u);
    e9 = { b3, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 484u * 4u);
    e1 = { b4, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 485u * 4u);
    e9 = { b5, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 486u * 4u);
    e1 = { b6, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 487u * 4u);
    e9 = { b7, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 488u * 4u);
    e1 = { b8, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 489u * 4u);
    e9 = { b9, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 490u * 4u);
    e1 = { b10, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 491u * 4u);
    e9 = { b11, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 492u * 4u);
    e1 = { b12, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 493u * 4u);
    e9 = { b13, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 494u * 4u);
    e1 = { b14, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 495u * 4u);
    e9 = { b15, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 496u * 4u);
    e1 = { b16, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 497u * 4u);
    e9 = { b17, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 498u * 4u);
    e1 = { b18, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 499u * 4u);
    e9 = { b19, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 500u * 4u);
    e1 = { b20, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 501u * 4u);
    e9 = { b21, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 502u * 4u);
    e1 = { b22, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 503u * 4u);
    e9 = { b23, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 504u * 4u);
    e1 = { b24, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 505u * 4u);
    e9 = { b25, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 506u * 4u);
    e1 = { b26, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 507u * 4u);
    e9 = { b27, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 508u * 4u);
    e1 = { b28, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 509u * 4u);
    e9 = { b29, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 510u * 4u);
    e1 = { b30, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 511u * 4u);
    e9 = { b31, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 512u * 4u);
    e1 = { b32, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 513u * 4u);
    e9 = { b33, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 514u * 4u);
    e1 = { b34, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 515u * 4u);
    e9 = { b35, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 516u * 4u);
    e1 = { b36, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 517u * 4u);
    e9 = { b37, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 518u * 4u);
    e1 = { b38, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 519u * 4u);
    e9 = { b39, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 520u * 4u);
    e1 = { b40, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 521u * 4u);
    e9 = { b41, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 522u * 4u);
    e1 = { b42, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 523u * 4u);
    e9 = { b43, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 524u * 4u);
    e1 = { b44, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 525u * 4u);
    e9 = { b45, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 526u * 4u);
    e1 = { b46, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 527u * 4u);
    e9 = { b47, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 528u * 4u);
    e1 = { b48, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 529u * 4u);
    e9 = { b49, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 530u * 4u);
    e1 = { b50, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 531u * 4u);
    e9 = { b51, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 532u * 4u);
    e1 = { b52, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 533u * 4u);
    e9 = { b53, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 534u * 4u);
    e1 = { b54, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 535u * 4u);
    e9 = { b55, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 536u * 4u);
    e1 = { b56, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 537u * 4u);
    e9 = { b57, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 538u * 4u);
    e1 = { b58, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 539u * 4u);
    e9 = { b59, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 540u * 4u);
    e1 = { b60, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 541u * 4u);
    e9 = { b61, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 542u * 4u);
    e1 = { b62, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 543u * 4u);
    e9 = { b63, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 544u * 4u);
    e1 = { b64, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 545u * 4u);
    e9 = { b65, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 546u * 4u);
    e1 = { b66, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 547u * 4u);
    e9 = { b67, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 548u * 4u);
    e1 = { b68, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 549u * 4u);
    e9 = { b69, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 550u * 4u);
    e1 = { b70, b80, b80, b80 };
    e0 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e9, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 551u * 4u);
    e9 = { b71, b80, b80, b80 };
    e10 = stwo_qm31_mul(e0, e9);
    e9 = stwo_qm31_add(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 552u * 4u);
    e1 = stwo_qm31_sub(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 747u * 4u);
    e9 = stwo_qm31_mul(e3, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 748u * 4u);
    e0 = stwo_qm31_mul(e2, e10);
    e10 = stwo_qm31_add(e9, e0);
    e0 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 749u * 4u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 750u * 4u);
    e9 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e9);
    e9 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 751u * 4u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 752u * 4u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 753u * 4u);
    e6 = stwo_qm31_mul(e1, e7);
    e7 = { b79, b80, b80, b80 };
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e1);
    e1 = { b81, b78, b83, b84 };
    e8 = { b85, b86, b87, b88 };
    e6 = stwo_qm31_sub(e8, e1);
    e1 = stwo_qm31_mul(e6, e0);
    e6 = stwo_qm31_sub(e1, e10);
    e1 = { b89, b90, b91, b92 };
    e10 = stwo_qm31_sub(e1, e8);
    e8 = stwo_qm31_mul(e10, e9);
    e10 = stwo_qm31_sub(e8, e3);
    e8 = { b93, b94, b95, b96 };
    e3 = stwo_qm31_sub(e8, e1);
    e1 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e1, e5);
    e1 = { b97, b98, b99, b100 };
    e5 = stwo_qm31_sub(e1, e8);
    e1 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e1, e7);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e6, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e10, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
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
