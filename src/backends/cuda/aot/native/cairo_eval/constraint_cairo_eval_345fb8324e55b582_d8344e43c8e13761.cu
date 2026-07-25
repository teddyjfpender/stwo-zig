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
stwo_cairo_cuda_eval_v1_9dc138cb2a8271eb(
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
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 9u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 169u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 170u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 171u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 172u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 173u, row, 0);
    unsigned b15 = 0u;
    unsigned b16 = 512u;
    unsigned b17 = stwo_m31_mul(b5, b16);
    b16 = stwo_m31_add(b4, b17);
    b17 = 262144u;
    b4 = stwo_m31_mul(b6, b17);
    b17 = stwo_m31_add(b16, b4);
    b4 = 134217728u;
    b16 = stwo_m31_mul(b7, b4);
    b4 = stwo_m31_add(b17, b16);
    b16 = 7u;
    b17 = stwo_m31_add(b4, b16);
    b16 = 4u;
    b4 = stwo_m31_mul(b11, b16);
    b16 = stwo_m31_sub(b9, b4);
    b4 = 512u;
    b9 = stwo_m31_mul(b10, b4);
    b4 = stwo_m31_sub(b8, b9);
    b9 = 128u;
    b8 = stwo_m31_mul(b16, b9);
    b9 = stwo_m31_add(b10, b8);
    b8 = 512u;
    b10 = stwo_m31_mul(b12, b8);
    b8 = stwo_m31_sub(b11, b10);
    b10 = 1u;
    b11 = stwo_m31_add(b0, b10);
    b10 = stwo_m31_add(b1, b3);
    b3 = stwo_trace_value(arena, *args, 2u, 136u, row, 0);
    b16 = stwo_trace_value(arena, *args, 2u, 137u, row, 0);
    b7 = stwo_trace_value(arena, *args, 2u, 138u, row, 0);
    b6 = stwo_trace_value(arena, *args, 2u, 139u, row, 0);
    b5 = stwo_trace_value(arena, *args, 2u, 140u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 2u, 141u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 2u, 142u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 2u, 143u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 2u, 144u, row, -1);
    unsigned b22 = stwo_trace_value(arena, *args, 2u, 144u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 2u, 145u, row, -1);
    unsigned b24 = stwo_trace_value(arena, *args, 2u, 145u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 2u, 146u, row, -1);
    unsigned b26 = stwo_trace_value(arena, *args, 2u, 146u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 2u, 147u, row, -1);
    unsigned b28 = stwo_trace_value(arena, *args, 2u, 147u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 861u * 4u);
    StwoCairoQm31 e1 = { b17, b15, b15, b15 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 862u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 863u * 4u);
    e2 = { b13, b15, b15, b15 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 864u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 865u * 4u);
    e2 = { b13, b15, b15, b15 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 866u * 4u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 867u * 4u);
    e1 = { b4, b15, b15, b15 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 868u * 4u);
    e3 = { b9, b15, b15, b15 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 869u * 4u);
    e1 = { b8, b15, b15, b15 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 870u * 4u);
    e3 = { b12, b15, b15, b15 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 871u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 872u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 873u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 874u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 875u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 876u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 877u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 878u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 879u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 880u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 881u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 882u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 883u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 884u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 885u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 886u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 887u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 888u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 889u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 890u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 891u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 892u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 893u * 4u);
    e1 = stwo_qm31_add(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 894u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 895u * 4u);
    e1 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 896u * 4u);
    e3 = { b0, b15, b15, b15 };
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 897u * 4u);
    e2 = stwo_qm31_add(e3, e4);
    e3 = stwo_load_qm31(arena, args->ext_params + 898u * 4u);
    e4 = { b1, b15, b15, b15 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_qm31_add(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 899u * 4u);
    e2 = { b2, b15, b15, b15 };
    e3 = stwo_qm31_mul(e5, e2);
    e2 = stwo_qm31_add(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 900u * 4u);
    e4 = stwo_qm31_sub(e2, e3);
    e3 = { b14, b15, b15, b15 };
    e2 = stwo_qm31_neg(e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 901u * 4u);
    e5 = { b11, b15, b15, b15 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 902u * 4u);
    e3 = stwo_qm31_add(e5, e6);
    e5 = stwo_load_qm31(arena, args->ext_params + 903u * 4u);
    e6 = { b10, b15, b15, b15 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_qm31_add(e3, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 904u * 4u);
    e3 = { b2, b15, b15, b15 };
    e5 = stwo_qm31_mul(e7, e3);
    e3 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 905u * 4u);
    e6 = stwo_qm31_sub(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 976u * 4u);
    e3 = stwo_qm31_mul(e1, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 977u * 4u);
    e7 = stwo_qm31_mul(e0, e5);
    e5 = stwo_qm31_add(e3, e7);
    e7 = stwo_qm31_mul(e0, e1);
    e1 = { b14, b15, b15, b15 };
    e0 = stwo_qm31_mul(e6, e1);
    e1 = stwo_qm31_mul(e4, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_qm31_mul(e4, e6);
    e6 = { b3, b16, b7, b6 };
    e4 = { b5, b18, b19, b20 };
    e0 = stwo_qm31_sub(e4, e6);
    e6 = stwo_qm31_mul(e0, e7);
    e0 = stwo_qm31_sub(e6, e5);
    e6 = { b21, b23, b25, b27 };
    e5 = { b22, b24, b26, b28 };
    e7 = stwo_qm31_sub(e5, e6);
    e5 = stwo_qm31_sub(e7, e4);
    e7 = stwo_load_qm31(arena, args->ext_params + 978u * 4u);
    e4 = stwo_qm31_add(e5, e7);
    e7 = stwo_qm31_mul(e4, e1);
    e4 = stwo_qm31_sub(e7, e2);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e4, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
