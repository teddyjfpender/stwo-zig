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
stwo_cairo_cuda_eval_v1_3d71260ad5604bdc(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 42u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 43u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 47u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 48u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 49u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 52u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 53u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 54u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 55u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 58u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 59u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 60u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 114u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 115u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 116u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 117u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 118u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 119u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 120u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 121u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 122u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 124u, row, 0);
    unsigned b46 = 0u;
    unsigned b47 = stwo_m31_add(b0, b9);
    b9 = 2u;
    b0 = stwo_m31_mul(b9, b18);
    b9 = stwo_m31_sub(b47, b0);
    b0 = stwo_m31_add(b9, b27);
    b9 = stwo_m31_sub(b0, b36);
    b0 = stwo_m31_sub(b9, b45);
    b9 = 16u;
    b36 = stwo_m31_mul(b0, b9);
    b9 = stwo_m31_add(b36, b1);
    b1 = stwo_m31_add(b9, b10);
    b9 = 2u;
    b10 = stwo_m31_mul(b9, b19);
    b9 = stwo_m31_sub(b1, b10);
    b10 = stwo_m31_add(b9, b28);
    b9 = stwo_m31_sub(b10, b37);
    b10 = 16u;
    b37 = stwo_m31_mul(b9, b10);
    b10 = stwo_m31_add(b37, b2);
    b2 = stwo_m31_add(b10, b11);
    b10 = 2u;
    b11 = stwo_m31_mul(b10, b20);
    b10 = stwo_m31_sub(b2, b11);
    b11 = stwo_m31_add(b10, b29);
    b10 = stwo_m31_sub(b11, b38);
    b11 = 16u;
    b38 = stwo_m31_mul(b10, b11);
    b11 = stwo_m31_add(b38, b3);
    b3 = stwo_m31_add(b11, b12);
    b11 = 2u;
    b12 = stwo_m31_mul(b11, b21);
    b11 = stwo_m31_sub(b3, b12);
    b12 = stwo_m31_add(b11, b30);
    b11 = stwo_m31_sub(b12, b39);
    b12 = 16u;
    b39 = stwo_m31_mul(b11, b12);
    b12 = stwo_m31_add(b39, b4);
    b4 = stwo_m31_add(b12, b13);
    b12 = 2u;
    b13 = stwo_m31_mul(b12, b22);
    b12 = stwo_m31_sub(b4, b13);
    b13 = stwo_m31_add(b12, b31);
    b12 = stwo_m31_sub(b13, b40);
    b13 = 16u;
    b40 = stwo_m31_mul(b12, b13);
    b13 = stwo_m31_add(b40, b5);
    b5 = stwo_m31_add(b13, b14);
    b13 = 2u;
    b14 = stwo_m31_mul(b13, b23);
    b13 = stwo_m31_sub(b5, b14);
    b14 = stwo_m31_add(b13, b32);
    b13 = stwo_m31_sub(b14, b41);
    b14 = 16u;
    b41 = stwo_m31_mul(b13, b14);
    b14 = stwo_m31_add(b41, b6);
    b6 = stwo_m31_add(b14, b15);
    b14 = 2u;
    b15 = stwo_m31_mul(b14, b24);
    b14 = stwo_m31_sub(b6, b15);
    b15 = stwo_m31_add(b14, b33);
    b14 = stwo_m31_sub(b15, b42);
    b15 = 16u;
    b42 = stwo_m31_mul(b14, b15);
    b15 = stwo_m31_add(b42, b7);
    b7 = stwo_m31_add(b15, b16);
    b15 = 2u;
    b16 = stwo_m31_mul(b15, b25);
    b15 = stwo_m31_sub(b7, b16);
    b16 = stwo_m31_add(b15, b34);
    b15 = stwo_m31_sub(b16, b43);
    b16 = 136u;
    b43 = stwo_m31_mul(b45, b16);
    b16 = stwo_m31_sub(b15, b43);
    b43 = 16u;
    b15 = stwo_m31_mul(b16, b43);
    b43 = stwo_m31_add(b15, b8);
    b8 = stwo_m31_add(b43, b17);
    b43 = 2u;
    b17 = stwo_m31_mul(b43, b26);
    b43 = stwo_m31_sub(b8, b17);
    b17 = stwo_m31_add(b43, b35);
    b43 = stwo_m31_sub(b17, b44);
    b17 = 16u;
    b44 = stwo_m31_mul(b43, b17);
    b17 = 3u;
    b43 = stwo_m31_add(b45, b17);
    b17 = 3u;
    b45 = stwo_m31_add(b36, b17);
    b17 = 3u;
    b36 = stwo_m31_add(b37, b17);
    b17 = 3u;
    b37 = stwo_m31_add(b38, b17);
    b17 = 3u;
    b38 = stwo_m31_add(b39, b17);
    b17 = 3u;
    b39 = stwo_m31_add(b40, b17);
    b17 = 3u;
    b40 = stwo_m31_add(b41, b17);
    b17 = 3u;
    b41 = stwo_m31_add(b42, b17);
    b17 = 3u;
    b42 = stwo_m31_add(b15, b17);
    b17 = 3u;
    b15 = stwo_m31_add(b44, b17);
    b17 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    b44 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    b35 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    b8 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    b26 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    b16 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    b34 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    b7 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 127u * 4u);
    StwoCairoQm31 e1 = { b43, b46, b46, b46 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 128u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 129u * 4u);
    e2 = { b45, b46, b46, b46 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 130u * 4u);
    e0 = { b36, b46, b46, b46 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 131u * 4u);
    e2 = { b37, b46, b46, b46 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 132u * 4u);
    e0 = { b38, b46, b46, b46 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 133u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 134u * 4u);
    e0 = { b39, b46, b46, b46 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 135u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 136u * 4u);
    e3 = { b40, b46, b46, b46 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 137u * 4u);
    e1 = { b41, b46, b46, b46 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 138u * 4u);
    e3 = { b42, b46, b46, b46 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 139u * 4u);
    e1 = { b15, b46, b46, b46 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 140u * 4u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 217u * 4u);
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 218u * 4u);
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e1, e4);
    e4 = stwo_qm31_mul(e2, e3);
    e3 = { b17, b44, b35, b8 };
    e2 = { b26, b16, b34, b7 };
    e1 = stwo_qm31_sub(e2, e3);
    e2 = stwo_qm31_mul(e1, e4);
    e1 = stwo_qm31_sub(e2, e0);
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
