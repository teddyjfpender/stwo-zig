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
stwo_cairo_cuda_eval_v1_c4a89340a088f06f(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 71u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b26 = 0u;
    unsigned b27 = stwo_m31_add(b0, b1);
    b1 = 4u;
    unsigned b28 = stwo_m31_mul(b7, b1);
    b1 = stwo_m31_sub(b5, b28);
    b28 = 512u;
    b5 = stwo_m31_mul(b6, b28);
    b28 = stwo_m31_sub(b4, b5);
    b5 = 128u;
    b4 = stwo_m31_mul(b1, b5);
    b5 = stwo_m31_add(b6, b4);
    b4 = 512u;
    unsigned b29 = stwo_m31_mul(b8, b4);
    b4 = stwo_m31_sub(b7, b29);
    b29 = stwo_m31_add(b0, b2);
    b2 = 4u;
    b7 = stwo_m31_mul(b13, b2);
    b2 = stwo_m31_sub(b11, b7);
    b7 = 512u;
    b11 = stwo_m31_mul(b12, b7);
    b7 = stwo_m31_sub(b10, b11);
    b11 = 128u;
    b10 = stwo_m31_mul(b2, b11);
    b11 = stwo_m31_add(b12, b10);
    b10 = 512u;
    unsigned b30 = stwo_m31_mul(b14, b10);
    b10 = stwo_m31_sub(b13, b30);
    b30 = stwo_m31_add(b0, b3);
    b3 = 4u;
    b0 = stwo_m31_mul(b19, b3);
    b3 = stwo_m31_sub(b17, b0);
    b0 = 512u;
    b17 = stwo_m31_mul(b18, b0);
    b0 = stwo_m31_sub(b16, b17);
    b17 = 128u;
    b16 = stwo_m31_mul(b3, b17);
    b17 = stwo_m31_add(b18, b16);
    b16 = 512u;
    b13 = stwo_m31_mul(b20, b16);
    b16 = stwo_m31_sub(b19, b13);
    b13 = 4u;
    b19 = stwo_m31_mul(b24, b13);
    b13 = stwo_m31_sub(b22, b19);
    b19 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    b22 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    b24 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 2u, 20u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 2u, 21u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 2u, 22u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 2u, 23u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 2u, 24u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 2u, 25u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 2u, 26u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 27u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 28u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 29u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 30u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 31u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 32u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 2u, 33u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 2u, 34u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 2u, 35u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 2u, 36u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 2u, 37u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 2u, 38u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 2u, 39u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 139u * 4u);
    StwoCairoQm31 e1 = { b6, b26, b26, b26 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 140u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 141u * 4u);
    e2 = { b1, b26, b26, b26 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 142u * 4u);
    e0 = { b8, b26, b26, b26 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 143u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 144u * 4u);
    e0 = { b27, b26, b26, b26 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 145u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 146u * 4u);
    e3 = { b9, b26, b26, b26 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 147u * 4u);
    e1 = stwo_qm31_sub(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 148u * 4u);
    e3 = { b9, b26, b26, b26 };
    e0 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 149u * 4u);
    e4 = stwo_qm31_add(e3, e0);
    e3 = stwo_load_qm31(arena, args->ext_params + 150u * 4u);
    e0 = { b28, b26, b26, b26 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 151u * 4u);
    e4 = { b5, b26, b26, b26 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 152u * 4u);
    e0 = { b4, b26, b26, b26 };
    e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 153u * 4u);
    e4 = { b8, b26, b26, b26 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 154u * 4u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 155u * 4u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 156u * 4u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 157u * 4u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 158u * 4u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 159u * 4u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 160u * 4u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 161u * 4u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 162u * 4u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 163u * 4u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 164u * 4u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 165u * 4u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 166u * 4u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 167u * 4u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 168u * 4u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 169u * 4u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 170u * 4u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 171u * 4u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 172u * 4u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 173u * 4u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 174u * 4u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 175u * 4u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 176u * 4u);
    e0 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 177u * 4u);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 178u * 4u);
    e0 = stwo_qm31_sub(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 179u * 4u);
    e4 = { b12, b26, b26, b26 };
    e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 180u * 4u);
    e3 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(arena, args->ext_params + 181u * 4u);
    e5 = { b2, b26, b26, b26 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 182u * 4u);
    e3 = { b14, b26, b26, b26 };
    e4 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 183u * 4u);
    e5 = stwo_qm31_sub(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 184u * 4u);
    e3 = { b29, b26, b26, b26 };
    e6 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 185u * 4u);
    e4 = stwo_qm31_add(e3, e6);
    e3 = stwo_load_qm31(arena, args->ext_params + 186u * 4u);
    e6 = { b15, b26, b26, b26 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e3, e6);
    e6 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 187u * 4u);
    e4 = stwo_qm31_sub(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 188u * 4u);
    e6 = { b15, b26, b26, b26 };
    e3 = stwo_qm31_mul(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 189u * 4u);
    e7 = stwo_qm31_add(e6, e3);
    e6 = stwo_load_qm31(arena, args->ext_params + 190u * 4u);
    e3 = { b7, b26, b26, b26 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 191u * 4u);
    e7 = { b11, b26, b26, b26 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 192u * 4u);
    e3 = { b10, b26, b26, b26 };
    e8 = stwo_qm31_mul(e6, e3);
    e3 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 193u * 4u);
    e7 = { b14, b26, b26, b26 };
    e6 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 194u * 4u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 195u * 4u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 196u * 4u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 197u * 4u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 198u * 4u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 199u * 4u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 200u * 4u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 201u * 4u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 202u * 4u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 203u * 4u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 204u * 4u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 205u * 4u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 206u * 4u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 207u * 4u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 208u * 4u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 209u * 4u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 210u * 4u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 211u * 4u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 212u * 4u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 213u * 4u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 214u * 4u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 215u * 4u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 216u * 4u);
    e3 = stwo_qm31_add(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 217u * 4u);
    e7 = stwo_qm31_add(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 218u * 4u);
    e3 = stwo_qm31_sub(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 219u * 4u);
    e7 = { b18, b26, b26, b26 };
    e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 220u * 4u);
    e6 = stwo_qm31_add(e7, e8);
    e7 = stwo_load_qm31(arena, args->ext_params + 221u * 4u);
    e8 = { b3, b26, b26, b26 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 222u * 4u);
    e6 = { b20, b26, b26, b26 };
    e7 = stwo_qm31_mul(e9, e6);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 223u * 4u);
    e8 = stwo_qm31_sub(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 224u * 4u);
    e6 = { b30, b26, b26, b26 };
    e9 = stwo_qm31_mul(e7, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 225u * 4u);
    e7 = stwo_qm31_add(e6, e9);
    e6 = stwo_load_qm31(arena, args->ext_params + 226u * 4u);
    e9 = { b21, b26, b26, b26 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e6, e9);
    e9 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 227u * 4u);
    e7 = stwo_qm31_sub(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 228u * 4u);
    e9 = { b21, b26, b26, b26 };
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 229u * 4u);
    e10 = stwo_qm31_add(e9, e6);
    e9 = stwo_load_qm31(arena, args->ext_params + 230u * 4u);
    e6 = { b0, b26, b26, b26 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e9, e6);
    e6 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 231u * 4u);
    e10 = { b17, b26, b26, b26 };
    e9 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 232u * 4u);
    e6 = { b16, b26, b26, b26 };
    e11 = stwo_qm31_mul(e9, e6);
    e6 = stwo_qm31_add(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 233u * 4u);
    e10 = { b20, b26, b26, b26 };
    e9 = stwo_qm31_mul(e11, e10);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 234u * 4u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 235u * 4u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 236u * 4u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 237u * 4u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 238u * 4u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 239u * 4u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 240u * 4u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 241u * 4u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 242u * 4u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 243u * 4u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 244u * 4u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 245u * 4u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 246u * 4u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 247u * 4u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 248u * 4u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 249u * 4u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 250u * 4u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 251u * 4u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 252u * 4u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 253u * 4u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 254u * 4u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 255u * 4u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 256u * 4u);
    e6 = stwo_qm31_add(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 257u * 4u);
    e10 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 258u * 4u);
    e6 = stwo_qm31_sub(e10, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 259u * 4u);
    e10 = { b23, b26, b26, b26 };
    e11 = stwo_qm31_mul(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 260u * 4u);
    e9 = stwo_qm31_add(e10, e11);
    e10 = stwo_load_qm31(arena, args->ext_params + 261u * 4u);
    e11 = { b13, b26, b26, b26 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e10, e11);
    e11 = stwo_qm31_add(e9, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 262u * 4u);
    e9 = { b25, b26, b26, b26 };
    e10 = stwo_qm31_mul(e12, e9);
    e9 = stwo_qm31_add(e11, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 263u * 4u);
    e11 = stwo_qm31_sub(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 919u * 4u);
    e9 = stwo_qm31_mul(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 920u * 4u);
    e12 = stwo_qm31_mul(e2, e10);
    e10 = stwo_qm31_add(e9, e12);
    e12 = stwo_qm31_mul(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 921u * 4u);
    e2 = stwo_qm31_mul(e5, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 922u * 4u);
    e9 = stwo_qm31_mul(e0, e1);
    e1 = stwo_qm31_add(e2, e9);
    e9 = stwo_qm31_mul(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 923u * 4u);
    e0 = stwo_qm31_mul(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 924u * 4u);
    e2 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e0, e2);
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 925u * 4u);
    e4 = stwo_qm31_mul(e7, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 926u * 4u);
    e0 = stwo_qm31_mul(e8, e3);
    e3 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 927u * 4u);
    e8 = stwo_qm31_mul(e11, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 928u * 4u);
    e4 = stwo_qm31_mul(e6, e7);
    e7 = stwo_qm31_add(e8, e4);
    e4 = stwo_qm31_mul(e6, e11);
    e11 = { b19, b22, b24, b31 };
    e6 = { b32, b33, b34, b35 };
    e8 = stwo_qm31_sub(e6, e11);
    e11 = stwo_qm31_mul(e8, e12);
    e8 = stwo_qm31_sub(e11, e10);
    e11 = { b36, b37, b38, b39 };
    e10 = stwo_qm31_sub(e11, e6);
    e6 = stwo_qm31_mul(e10, e9);
    e10 = stwo_qm31_sub(e6, e1);
    e6 = { b40, b41, b42, b43 };
    e1 = stwo_qm31_sub(e6, e11);
    e11 = stwo_qm31_mul(e1, e2);
    e1 = stwo_qm31_sub(e11, e5);
    e11 = { b44, b45, b46, b47 };
    e5 = stwo_qm31_sub(e11, e6);
    e6 = stwo_qm31_mul(e5, e0);
    e5 = stwo_qm31_sub(e6, e3);
    e6 = { b48, b49, b50, b51 };
    e3 = stwo_qm31_sub(e6, e11);
    e6 = stwo_qm31_mul(e3, e4);
    e3 = stwo_qm31_sub(e6, e7);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e8, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e10, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
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
