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
stwo_cairo_cuda_eval_v1_40ac0e5b25e94f90(
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
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 8u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 10u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 120u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 121u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 122u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 123u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 124u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 126u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 127u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b15 = 0u;
    unsigned b16 = 524288u;
    unsigned b17 = stwo_m31_add(b5, b16);
    b16 = 524288u;
    b5 = stwo_m31_add(b6, b16);
    b16 = 524288u;
    b6 = stwo_m31_add(b7, b16);
    b16 = 524288u;
    b7 = stwo_m31_add(b8, b16);
    b16 = 524288u;
    b8 = stwo_m31_add(b9, b16);
    b16 = 524288u;
    b9 = stwo_m31_add(b10, b16);
    b16 = 524288u;
    b10 = stwo_m31_add(b11, b16);
    b16 = 524288u;
    b11 = stwo_m31_add(b12, b16);
    b16 = 524288u;
    b12 = stwo_m31_add(b13, b16);
    b16 = 1u;
    b13 = stwo_m31_add(b0, b16);
    b16 = stwo_m31_add(b13, b3);
    b13 = stwo_m31_add(b1, b4);
    b4 = stwo_trace_value(arena, *args, 2u, 48u, row, 0);
    b3 = stwo_trace_value(arena, *args, 2u, 49u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 2u, 50u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 2u, 51u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 2u, 52u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 2u, 53u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 2u, 54u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 2u, 55u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 2u, 56u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 2u, 57u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 2u, 58u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 2u, 59u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 2u, 60u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 2u, 61u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 2u, 62u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 2u, 63u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 2u, 64u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 2u, 65u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 2u, 66u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 2u, 67u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 2u, 68u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 2u, 69u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 2u, 70u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 71u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 72u, row, -1);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 72u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 73u, row, -1);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 73u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 74u, row, -1);
    unsigned b45 = stwo_trace_value(arena, *args, 2u, 74u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 2u, 75u, row, -1);
    unsigned b47 = stwo_trace_value(arena, *args, 2u, 75u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 170u * 4u);
    StwoCairoQm31 e1 = { b17, b15, b15, b15 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 171u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 172u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 173u * 4u);
    e0 = { b5, b15, b15, b15 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 174u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 175u * 4u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 176u * 4u);
    e1 = { b6, b15, b15, b15 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 177u * 4u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(arena, args->ext_params + 178u * 4u);
    e4 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 179u * 4u);
    e0 = { b7, b15, b15, b15 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 180u * 4u);
    e1 = stwo_qm31_add(e0, e5);
    e0 = stwo_load_qm31(arena, args->ext_params + 181u * 4u);
    e5 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 182u * 4u);
    e1 = { b8, b15, b15, b15 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 183u * 4u);
    e0 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(arena, args->ext_params + 184u * 4u);
    e6 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 185u * 4u);
    e0 = { b9, b15, b15, b15 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 186u * 4u);
    e1 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(arena, args->ext_params + 187u * 4u);
    e7 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 188u * 4u);
    e1 = { b10, b15, b15, b15 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 189u * 4u);
    e0 = stwo_qm31_add(e1, e8);
    e1 = stwo_load_qm31(arena, args->ext_params + 190u * 4u);
    e8 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 191u * 4u);
    e0 = { b11, b15, b15, b15 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 192u * 4u);
    e1 = stwo_qm31_add(e0, e9);
    e0 = stwo_load_qm31(arena, args->ext_params + 193u * 4u);
    e9 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 194u * 4u);
    e1 = { b12, b15, b15, b15 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 195u * 4u);
    e0 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(arena, args->ext_params + 196u * 4u);
    e10 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 197u * 4u);
    e0 = { b0, b15, b15, b15 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 198u * 4u);
    e1 = stwo_qm31_add(e0, e11);
    e0 = stwo_load_qm31(arena, args->ext_params + 199u * 4u);
    e11 = { b1, b15, b15, b15 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e0, e11);
    e11 = stwo_qm31_add(e1, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 200u * 4u);
    e1 = { b2, b15, b15, b15 };
    e0 = stwo_qm31_mul(e12, e1);
    e1 = stwo_qm31_add(e11, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 201u * 4u);
    e11 = stwo_qm31_sub(e1, e0);
    e0 = { b14, b15, b15, b15 };
    e1 = stwo_qm31_neg(e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 202u * 4u);
    e12 = { b16, b15, b15, b15 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e0, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 203u * 4u);
    e0 = stwo_qm31_add(e12, e13);
    e12 = stwo_load_qm31(arena, args->ext_params + 204u * 4u);
    e13 = { b13, b15, b15, b15 };
    StwoCairoQm31 e14 = stwo_qm31_mul(e12, e13);
    e13 = stwo_qm31_add(e0, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 205u * 4u);
    e0 = { b2, b15, b15, b15 };
    e12 = stwo_qm31_mul(e14, e0);
    e0 = stwo_qm31_add(e13, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 206u * 4u);
    e13 = stwo_qm31_sub(e0, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 233u * 4u);
    e0 = stwo_qm31_mul(e3, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 234u * 4u);
    e14 = stwo_qm31_mul(e2, e12);
    e12 = stwo_qm31_add(e0, e14);
    e14 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 235u * 4u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 236u * 4u);
    e0 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e0);
    e0 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 237u * 4u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 238u * 4u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 239u * 4u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 240u * 4u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 241u * 4u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = { b14, b15, b15, b15 };
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = { b4, b3, b18, b19 };
    e10 = { b20, b21, b22, b23 };
    e8 = stwo_qm31_sub(e10, e11);
    e11 = stwo_qm31_mul(e8, e14);
    e8 = stwo_qm31_sub(e11, e12);
    e11 = { b24, b25, b26, b27 };
    e12 = stwo_qm31_sub(e11, e10);
    e10 = stwo_qm31_mul(e12, e0);
    e12 = stwo_qm31_sub(e10, e3);
    e10 = { b28, b29, b30, b31 };
    e3 = stwo_qm31_sub(e10, e11);
    e11 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e11, e5);
    e11 = { b32, b33, b34, b35 };
    e5 = stwo_qm31_sub(e11, e10);
    e10 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e10, e7);
    e10 = { b36, b37, b38, b39 };
    e7 = stwo_qm31_sub(e10, e11);
    e11 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e11, e9);
    e11 = { b40, b42, b44, b46 };
    e9 = { b41, b43, b45, b47 };
    e6 = stwo_qm31_sub(e9, e11);
    e9 = stwo_qm31_sub(e6, e10);
    e6 = stwo_load_qm31(arena, args->ext_params + 242u * 4u);
    e10 = stwo_qm31_add(e9, e6);
    e6 = stwo_qm31_mul(e10, e13);
    e10 = stwo_qm31_sub(e6, e1);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e8, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e12, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e10, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
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
