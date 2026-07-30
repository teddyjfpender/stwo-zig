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
stwo_cairo_cuda_eval_v1_c8cce5ed505dcf5e(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 123u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 124u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 126u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 127u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 156u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 157u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 158u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 159u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 160u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 161u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 174u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 175u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 176u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 177u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 178u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 179u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 180u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 181u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 182u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 184u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 185u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 186u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 187u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 188u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 189u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 190u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 191u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 192u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 194u, row, 0);
    unsigned b37 = 0u;
    unsigned b38 = 4u;
    unsigned b39 = stwo_m31_mul(b38, b0);
    b38 = 2u;
    b0 = stwo_m31_mul(b38, b9);
    b38 = stwo_m31_add(b39, b0);
    b0 = 2u;
    b39 = stwo_m31_mul(b0, b18);
    b0 = stwo_m31_sub(b38, b39);
    b39 = 121657377u;
    b38 = stwo_m31_add(b0, b39);
    b39 = stwo_m31_sub(b38, b27);
    b38 = stwo_m31_sub(b39, b36);
    b39 = 16u;
    b27 = stwo_m31_mul(b38, b39);
    b39 = 4u;
    b38 = stwo_m31_mul(b39, b1);
    b39 = stwo_m31_add(b27, b38);
    b38 = 2u;
    b27 = stwo_m31_mul(b38, b10);
    b38 = stwo_m31_add(b39, b27);
    b27 = 2u;
    b39 = stwo_m31_mul(b27, b19);
    b27 = stwo_m31_sub(b38, b39);
    b39 = 112479959u;
    b38 = stwo_m31_add(b27, b39);
    b39 = stwo_m31_sub(b38, b28);
    b38 = 16u;
    b28 = stwo_m31_mul(b39, b38);
    b38 = 4u;
    b39 = stwo_m31_mul(b38, b2);
    b38 = stwo_m31_add(b28, b39);
    b39 = 2u;
    b28 = stwo_m31_mul(b39, b11);
    b39 = stwo_m31_add(b38, b28);
    b28 = 2u;
    b38 = stwo_m31_mul(b28, b20);
    b28 = stwo_m31_sub(b39, b38);
    b38 = 130418270u;
    b39 = stwo_m31_add(b28, b38);
    b38 = stwo_m31_sub(b39, b29);
    b39 = 16u;
    b29 = stwo_m31_mul(b38, b39);
    b39 = 4u;
    b38 = stwo_m31_mul(b39, b3);
    b39 = stwo_m31_add(b29, b38);
    b38 = 2u;
    b29 = stwo_m31_mul(b38, b12);
    b38 = stwo_m31_add(b39, b29);
    b29 = 2u;
    b39 = stwo_m31_mul(b29, b21);
    b29 = stwo_m31_sub(b38, b39);
    b39 = 4974792u;
    b38 = stwo_m31_add(b29, b39);
    b39 = stwo_m31_sub(b38, b30);
    b38 = 16u;
    b30 = stwo_m31_mul(b39, b38);
    b38 = 4u;
    b39 = stwo_m31_mul(b38, b4);
    b38 = stwo_m31_add(b30, b39);
    b39 = 2u;
    b4 = stwo_m31_mul(b39, b13);
    b39 = stwo_m31_add(b38, b4);
    b4 = 2u;
    b38 = stwo_m31_mul(b4, b22);
    b4 = stwo_m31_sub(b39, b38);
    b38 = 59852719u;
    b39 = stwo_m31_add(b4, b38);
    b38 = stwo_m31_sub(b39, b31);
    b39 = 16u;
    b31 = stwo_m31_mul(b38, b39);
    b39 = 4u;
    b38 = stwo_m31_mul(b39, b5);
    b39 = stwo_m31_add(b31, b38);
    b38 = 2u;
    b5 = stwo_m31_mul(b38, b14);
    b38 = stwo_m31_add(b39, b5);
    b5 = 2u;
    b39 = stwo_m31_mul(b5, b23);
    b5 = stwo_m31_sub(b38, b39);
    b39 = 120369218u;
    b38 = stwo_m31_add(b5, b39);
    b39 = stwo_m31_sub(b38, b32);
    b38 = 16u;
    b32 = stwo_m31_mul(b39, b38);
    b38 = 4u;
    b39 = stwo_m31_mul(b38, b6);
    b38 = stwo_m31_add(b32, b39);
    b39 = 2u;
    b6 = stwo_m31_mul(b39, b15);
    b39 = stwo_m31_add(b38, b6);
    b6 = 2u;
    b38 = stwo_m31_mul(b6, b24);
    b6 = stwo_m31_sub(b39, b38);
    b38 = 62439890u;
    b39 = stwo_m31_add(b6, b38);
    b38 = stwo_m31_sub(b39, b33);
    b39 = 16u;
    b33 = stwo_m31_mul(b38, b39);
    b39 = 4u;
    b38 = stwo_m31_mul(b39, b7);
    b39 = stwo_m31_add(b33, b38);
    b38 = 2u;
    b7 = stwo_m31_mul(b38, b16);
    b38 = stwo_m31_add(b39, b7);
    b7 = 2u;
    b39 = stwo_m31_mul(b7, b25);
    b7 = stwo_m31_sub(b38, b39);
    b39 = 50468641u;
    b38 = stwo_m31_add(b7, b39);
    b39 = stwo_m31_sub(b38, b34);
    b38 = 136u;
    b34 = stwo_m31_mul(b36, b38);
    b38 = stwo_m31_sub(b39, b34);
    b34 = 16u;
    b39 = stwo_m31_mul(b38, b34);
    b34 = 4u;
    b38 = stwo_m31_mul(b34, b8);
    b34 = stwo_m31_add(b39, b38);
    b38 = 2u;
    b8 = stwo_m31_mul(b38, b17);
    b38 = stwo_m31_add(b34, b8);
    b8 = 2u;
    b34 = stwo_m31_mul(b8, b26);
    b8 = stwo_m31_sub(b38, b34);
    b34 = 86573645u;
    b38 = stwo_m31_add(b8, b34);
    b34 = stwo_m31_sub(b38, b35);
    b38 = 16u;
    b35 = stwo_m31_mul(b34, b38);
    b38 = 3u;
    b34 = stwo_m31_add(b30, b38);
    b38 = 3u;
    b30 = stwo_m31_add(b31, b38);
    b38 = 3u;
    b31 = stwo_m31_add(b32, b38);
    b38 = 3u;
    b32 = stwo_m31_add(b33, b38);
    b38 = 3u;
    b33 = stwo_m31_add(b39, b38);
    b38 = 3u;
    b39 = stwo_m31_add(b35, b38);
    b38 = stwo_trace_value(arena, *args, 2u, 20u, row, 0);
    b35 = stwo_trace_value(arena, *args, 2u, 21u, row, 0);
    b8 = stwo_trace_value(arena, *args, 2u, 22u, row, 0);
    b26 = stwo_trace_value(arena, *args, 2u, 23u, row, 0);
    b17 = stwo_trace_value(arena, *args, 2u, 24u, row, 0);
    b36 = stwo_trace_value(arena, *args, 2u, 25u, row, 0);
    b7 = stwo_trace_value(arena, *args, 2u, 26u, row, 0);
    b25 = stwo_trace_value(arena, *args, 2u, 27u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 249u * 4u);
    StwoCairoQm31 e1 = { b34, b37, b37, b37 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 250u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 251u * 4u);
    e2 = { b30, b37, b37, b37 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 252u * 4u);
    e0 = { b31, b37, b37, b37 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 253u * 4u);
    e2 = { b32, b37, b37, b37 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 254u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 255u * 4u);
    e2 = { b33, b37, b37, b37 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 256u * 4u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 257u * 4u);
    e1 = { b39, b37, b37, b37 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 258u * 4u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 560u * 4u);
    e1 = stwo_qm31_mul(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 561u * 4u);
    e2 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e1, e2);
    e2 = stwo_qm31_mul(e0, e3);
    e3 = { b38, b35, b8, b26 };
    e0 = { b17, b36, b7, b25 };
    e1 = stwo_qm31_sub(e0, e3);
    e0 = stwo_qm31_mul(e1, e2);
    e1 = stwo_qm31_sub(e0, e4);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
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
