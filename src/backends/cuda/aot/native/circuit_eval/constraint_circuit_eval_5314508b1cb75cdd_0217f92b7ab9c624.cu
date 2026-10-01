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
__device__ __forceinline__ unsigned stwo_m31_add(
    unsigned lhs, unsigned rhs) {
    const unsigned sum = lhs + rhs;
    return sum < STWO_M31_P ? sum : sum - STWO_M31_P;
}
__device__ __forceinline__ unsigned stwo_m31_sub(
    unsigned lhs, unsigned rhs) {
    return lhs >= rhs ? lhs - rhs : lhs + STWO_M31_P - rhs;
}
__device__ __forceinline__ unsigned stwo_m31_mul(
    unsigned lhs, unsigned rhs) {
    const u64 product = (u64)lhs * rhs;
    const unsigned folded = (unsigned)(product & STWO_M31_P) +
        (unsigned)(product >> 31u);
    return folded < STWO_M31_P ? folded : folded - STWO_M31_P;
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
    #if defined(STWO_CUMETAL)
    value = ((value >> 1u) & 0x55555555u) | ((value & 0x55555555u) << 1u);
    value = ((value >> 2u) & 0x33333333u) | ((value & 0x33333333u) << 2u);
    value = ((value >> 4u) & 0x0f0f0f0fu) | ((value & 0x0f0f0f0fu) << 4u);
    value = ((value >> 8u) & 0x00ff00ffu) | ((value & 0x00ff00ffu) << 8u);
    value = (value >> 16u) | (value << 16u);
    return bits == 0u ? 0u : value >> (32u - bits);
#else
    return bits == 0u ? 0u : __brev(value) >> (32u - bits);
#endif
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
    const u64 address = (u64)arena[args.trace_offsets + 2u * global] | ((u64)arena[args.trace_offsets + 2u * global + 1u] << 32u); return arena[address + target];
}
extern "C" __global__ void __launch_bounds__(256)
stwo_cairo_cuda_eval_v6_5314508b1cb75cdd(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    unsigned b0 = stwo_trace_value(arena, *args, 0u, 0u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 0u, 1u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 0u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 1u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 2u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 3u, row, 0);
    unsigned b6 = arena[args->base_params + 0u];
    unsigned b7 = stwo_trace_value(arena, *args, 2u, 0u, row, -1);
    unsigned b8 = stwo_trace_value(arena, *args, 2u, 0u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 2u, 1u, row, -1);
    unsigned b10 = stwo_trace_value(arena, *args, 2u, 1u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 2u, 2u, row, -1);
    unsigned b12 = stwo_trace_value(arena, *args, 2u, 2u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 2u, 3u, row, -1);
    unsigned b14 = stwo_trace_value(arena, *args, 2u, 3u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e1 = { b0, b6, b6, b6 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    StwoCairoQm31 e3 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e4 = stwo_qm31_add(e3, e2);
    StwoCairoQm31 e5 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e6 = { b2, b6, b6, b6 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e5, e6);
    StwoCairoQm31 e8 = stwo_qm31_add(e4, e7);
    StwoCairoQm31 e9 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e10 = { b3, b6, b6, b6 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e9, e10);
    StwoCairoQm31 e12 = stwo_qm31_add(e8, e11);
    StwoCairoQm31 e13 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e14 = { b4, b6, b6, b6 };
    StwoCairoQm31 e15 = stwo_qm31_mul(e13, e14);
    StwoCairoQm31 e16 = stwo_qm31_add(e12, e15);
    StwoCairoQm31 e17 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    StwoCairoQm31 e18 = { b5, b6, b6, b6 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e17, e18);
    StwoCairoQm31 e20 = stwo_qm31_add(e16, e19);
    StwoCairoQm31 e21 = stwo_load_qm31(arena, args->ext_params + 5u * 4u);
    StwoCairoQm31 e22 = stwo_qm31_sub(e20, e21);
    StwoCairoQm31 e23 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e24 = { b1, b6, b6, b6 };
    StwoCairoQm31 e25 = stwo_qm31_mul(e23, e24);
    StwoCairoQm31 e26 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e27 = stwo_qm31_add(e26, e25);
    StwoCairoQm31 e28 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e29 = { b2, b6, b6, b6 };
    StwoCairoQm31 e30 = stwo_qm31_mul(e28, e29);
    StwoCairoQm31 e31 = stwo_qm31_add(e27, e30);
    StwoCairoQm31 e32 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e33 = { b3, b6, b6, b6 };
    StwoCairoQm31 e34 = stwo_qm31_mul(e32, e33);
    StwoCairoQm31 e35 = stwo_qm31_add(e31, e34);
    StwoCairoQm31 e36 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e37 = { b4, b6, b6, b6 };
    StwoCairoQm31 e38 = stwo_qm31_mul(e36, e37);
    StwoCairoQm31 e39 = stwo_qm31_add(e35, e38);
    StwoCairoQm31 e40 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    StwoCairoQm31 e41 = { b5, b6, b6, b6 };
    StwoCairoQm31 e42 = stwo_qm31_mul(e40, e41);
    StwoCairoQm31 e43 = stwo_qm31_add(e39, e42);
    StwoCairoQm31 e44 = stwo_load_qm31(arena, args->ext_params + 5u * 4u);
    StwoCairoQm31 e45 = stwo_qm31_sub(e43, e44);
    StwoCairoQm31 e46 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e47 = e45;
    StwoCairoQm31 e48 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e49 = e22;
    StwoCairoQm31 e50 = stwo_qm31_add(e47, e49);
    StwoCairoQm31 e51 = stwo_qm31_mul(e22, e45);
    StwoCairoQm31 e52 = { b7, b9, b11, b13 };
    StwoCairoQm31 e53 = { b8, b10, b12, b14 };
    StwoCairoQm31 e54 = stwo_qm31_sub(e53, e52);
    StwoCairoQm31 e55 = stwo_load_qm31(arena, args->ext_params + 6u * 4u);
    StwoCairoQm31 e56 = stwo_qm31_add(e54, e55);
    StwoCairoQm31 e57 = stwo_qm31_mul(e56, e51);
    StwoCairoQm31 e58 = stwo_qm31_sub(e57, e50);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e58, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
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
