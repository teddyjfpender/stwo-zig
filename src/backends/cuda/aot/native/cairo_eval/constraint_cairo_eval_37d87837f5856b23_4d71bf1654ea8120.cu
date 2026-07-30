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
stwo_cairo_cuda_eval_v1_fbb5d2d2b701f4ca(
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
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 205u, row, 0);
    unsigned b32 = 0u;
    unsigned b33 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 2u, 20u, row, -1);
    unsigned b38 = stwo_trace_value(arena, *args, 2u, 20u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 21u, row, -1);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 21u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 22u, row, -1);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 22u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 23u, row, -1);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 23u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 370u * 4u);
    StwoCairoQm31 e1 = { b2, b32, b32, b32 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 371u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 372u * 4u);
    e2 = { b3, b32, b32, b32 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 373u * 4u);
    e0 = { b4, b32, b32, b32 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 374u * 4u);
    e2 = { b5, b32, b32, b32 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 375u * 4u);
    e0 = { b6, b32, b32, b32 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 376u * 4u);
    e2 = { b7, b32, b32, b32 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 377u * 4u);
    e0 = { b8, b32, b32, b32 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 378u * 4u);
    e2 = { b9, b32, b32, b32 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 379u * 4u);
    e0 = { b10, b32, b32, b32 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 380u * 4u);
    e2 = { b11, b32, b32, b32 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 381u * 4u);
    e0 = { b12, b32, b32, b32 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 382u * 4u);
    e2 = { b13, b32, b32, b32 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 383u * 4u);
    e0 = { b14, b32, b32, b32 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 384u * 4u);
    e2 = { b15, b32, b32, b32 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 385u * 4u);
    e0 = { b16, b32, b32, b32 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 386u * 4u);
    e2 = { b17, b32, b32, b32 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 387u * 4u);
    e0 = { b18, b32, b32, b32 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 388u * 4u);
    e2 = { b19, b32, b32, b32 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 389u * 4u);
    e0 = { b20, b32, b32, b32 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 390u * 4u);
    e2 = { b21, b32, b32, b32 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 391u * 4u);
    e0 = { b22, b32, b32, b32 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 392u * 4u);
    e2 = { b23, b32, b32, b32 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 393u * 4u);
    e0 = { b24, b32, b32, b32 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 394u * 4u);
    e2 = { b25, b32, b32, b32 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 395u * 4u);
    e0 = { b26, b32, b32, b32 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 396u * 4u);
    e2 = { b27, b32, b32, b32 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 397u * 4u);
    e0 = { b28, b32, b32, b32 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 398u * 4u);
    e2 = { b29, b32, b32, b32 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 399u * 4u);
    e0 = { b30, b32, b32, b32 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 400u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = { b31, b32, b32, b32 };
    e0 = stwo_qm31_neg(e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 401u * 4u);
    e3 = { b0, b32, b32, b32 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e1, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 402u * 4u);
    e1 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(arena, args->ext_params + 403u * 4u);
    e4 = { b1, b32, b32, b32 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e1, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 404u * 4u);
    e1 = { b2, b32, b32, b32 };
    e3 = stwo_qm31_mul(e5, e1);
    e1 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 405u * 4u);
    e4 = stwo_qm31_sub(e1, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 416u * 4u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e1, e3);
    e3 = stwo_qm31_mul(e2, e4);
    e4 = { b33, b34, b35, b36 };
    e2 = { b37, b39, b41, b43 };
    e1 = { b38, b40, b42, b44 };
    e5 = stwo_qm31_sub(e1, e2);
    e1 = stwo_qm31_sub(e5, e4);
    e5 = stwo_load_qm31(arena, args->ext_params + 417u * 4u);
    e4 = stwo_qm31_add(e1, e5);
    e5 = stwo_qm31_mul(e4, e3);
    e4 = stwo_qm31_sub(e5, e0);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e4, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
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
