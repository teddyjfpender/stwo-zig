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
stwo_cairo_cuda_eval_v1_f680473ae447a672(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 0u, 0u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 116u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 117u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 118u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 119u, row, 0);
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
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 143u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 144u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 145u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b32 = 7u;
    unsigned b33 = stwo_m31_mul(b0, b32);
    b32 = 6955877u;
    b0 = stwo_m31_add(b33, b32);
    b32 = 0u;
    b33 = 4u;
    unsigned b34 = stwo_m31_add(b0, b33);
    b33 = stwo_m31_sub(b29, b30);
    b30 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    b0 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 20u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 21u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 22u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 23u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 140u * 4u);
    StwoCairoQm31 e1 = { b34, b32, b32, b32 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 141u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 142u * 4u);
    e2 = { b1, b32, b32, b32 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 143u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 144u * 4u);
    e2 = { b1, b32, b32, b32 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 145u * 4u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 146u * 4u);
    e1 = { b2, b32, b32, b32 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 147u * 4u);
    e3 = { b3, b32, b32, b32 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 148u * 4u);
    e1 = { b4, b32, b32, b32 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 149u * 4u);
    e3 = { b5, b32, b32, b32 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 150u * 4u);
    e1 = { b6, b32, b32, b32 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 151u * 4u);
    e3 = { b7, b32, b32, b32 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 152u * 4u);
    e1 = { b8, b32, b32, b32 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 153u * 4u);
    e3 = { b9, b32, b32, b32 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 154u * 4u);
    e1 = { b10, b32, b32, b32 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 155u * 4u);
    e3 = { b11, b32, b32, b32 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 156u * 4u);
    e1 = { b12, b32, b32, b32 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 157u * 4u);
    e3 = { b13, b32, b32, b32 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 158u * 4u);
    e1 = { b14, b32, b32, b32 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 159u * 4u);
    e3 = { b15, b32, b32, b32 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 160u * 4u);
    e1 = { b16, b32, b32, b32 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 161u * 4u);
    e3 = { b17, b32, b32, b32 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 162u * 4u);
    e1 = { b18, b32, b32, b32 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 163u * 4u);
    e3 = { b19, b32, b32, b32 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 164u * 4u);
    e1 = { b20, b32, b32, b32 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 165u * 4u);
    e3 = { b21, b32, b32, b32 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 166u * 4u);
    e1 = { b22, b32, b32, b32 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 167u * 4u);
    e3 = { b23, b32, b32, b32 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 168u * 4u);
    e1 = { b24, b32, b32, b32 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 169u * 4u);
    e3 = { b25, b32, b32, b32 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 170u * 4u);
    e1 = { b26, b32, b32, b32 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 171u * 4u);
    e3 = { b27, b32, b32, b32 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 172u * 4u);
    e1 = { b28, b32, b32, b32 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 173u * 4u);
    e3 = { b29, b32, b32, b32 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 174u * 4u);
    e1 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 175u * 4u);
    e3 = { b33, b32, b32, b32 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 176u * 4u);
    e2 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(arena, args->ext_params + 177u * 4u);
    e4 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 178u * 4u);
    e2 = { b31, b32, b32, b32 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 179u * 4u);
    e3 = stwo_qm31_add(e2, e5);
    e2 = stwo_load_qm31(arena, args->ext_params + 180u * 4u);
    e5 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 513u * 4u);
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 514u * 4u);
    StwoCairoQm31 e6 = stwo_qm31_mul(e0, e2);
    e2 = stwo_qm31_add(e3, e6);
    e6 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 515u * 4u);
    e0 = stwo_qm31_mul(e5, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 516u * 4u);
    e3 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e0, e3);
    e3 = stwo_qm31_mul(e4, e5);
    e5 = { b30, b0, b35, b36 };
    e4 = { b37, b38, b39, b40 };
    e0 = stwo_qm31_sub(e4, e5);
    e5 = stwo_qm31_mul(e0, e6);
    e0 = stwo_qm31_sub(e5, e2);
    e5 = { b41, b42, b43, b44 };
    e2 = stwo_qm31_sub(e5, e4);
    e5 = stwo_qm31_mul(e2, e3);
    e2 = stwo_qm31_sub(e5, e1);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
