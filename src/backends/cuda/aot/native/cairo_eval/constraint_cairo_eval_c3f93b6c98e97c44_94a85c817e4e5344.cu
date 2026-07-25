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
stwo_cairo_cuda_eval_v1_959209439df79130(
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
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
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
    unsigned b26 = 0u;
    unsigned b27 = 512u;
    unsigned b28 = stwo_m31_mul(b1, b27);
    b27 = stwo_m31_add(b0, b28);
    b28 = 262144u;
    b0 = stwo_m31_mul(b2, b28);
    b28 = stwo_m31_add(b27, b0);
    b0 = 134217728u;
    b27 = stwo_m31_mul(b3, b0);
    b0 = stwo_m31_add(b28, b27);
    b27 = 4u;
    b28 = stwo_m31_mul(b12, b27);
    b27 = stwo_m31_sub(b5, b28);
    b28 = 512u;
    b5 = stwo_m31_mul(b11, b28);
    b28 = stwo_m31_sub(b4, b5);
    b5 = 128u;
    b4 = stwo_m31_mul(b27, b5);
    b5 = stwo_m31_add(b11, b4);
    b4 = 512u;
    b11 = stwo_m31_mul(b13, b4);
    b4 = stwo_m31_sub(b12, b11);
    b11 = 5u;
    b12 = stwo_m31_add(b0, b11);
    b11 = 4u;
    b27 = stwo_m31_mul(b16, b11);
    b11 = stwo_m31_sub(b7, b27);
    b27 = 512u;
    b7 = stwo_m31_mul(b15, b27);
    b27 = stwo_m31_sub(b6, b7);
    b7 = 128u;
    b6 = stwo_m31_mul(b11, b7);
    b7 = stwo_m31_add(b15, b6);
    b6 = 512u;
    b3 = stwo_m31_mul(b17, b6);
    b6 = stwo_m31_sub(b16, b3);
    b3 = 6u;
    b16 = stwo_m31_add(b0, b3);
    b3 = 4u;
    b0 = stwo_m31_mul(b20, b3);
    b3 = stwo_m31_sub(b9, b0);
    b0 = 512u;
    b9 = stwo_m31_mul(b19, b0);
    b0 = stwo_m31_sub(b8, b9);
    b9 = 128u;
    b8 = stwo_m31_mul(b3, b9);
    b9 = stwo_m31_add(b19, b8);
    b8 = 512u;
    b2 = stwo_m31_mul(b21, b8);
    b8 = stwo_m31_sub(b20, b2);
    b2 = 4u;
    b20 = stwo_m31_mul(b24, b2);
    b2 = stwo_m31_sub(b10, b20);
    b20 = stwo_trace_value(arena, *args, 2u, 120u, row, 0);
    b10 = stwo_trace_value(arena, *args, 2u, 121u, row, 0);
    b24 = stwo_trace_value(arena, *args, 2u, 122u, row, 0);
    b1 = stwo_trace_value(arena, *args, 2u, 123u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 2u, 124u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 2u, 125u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 2u, 126u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 2u, 127u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 2u, 128u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 2u, 129u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 2u, 130u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 2u, 131u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 2u, 132u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 2u, 133u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 134u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 135u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 136u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 137u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 138u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 139u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 745u * 4u);
    StwoCairoQm31 e1 = { b14, b26, b26, b26 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 746u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 747u * 4u);
    e2 = { b28, b26, b26, b26 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 748u * 4u);
    e0 = { b5, b26, b26, b26 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 749u * 4u);
    e2 = { b4, b26, b26, b26 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 750u * 4u);
    e0 = { b13, b26, b26, b26 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 751u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 752u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 753u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 754u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 755u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 756u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 757u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 758u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 759u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 760u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 761u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 762u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 763u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 764u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 765u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 766u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 767u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 768u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 769u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 770u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 771u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 772u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 773u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 774u * 4u);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 775u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 776u * 4u);
    e0 = { b15, b26, b26, b26 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 777u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 778u * 4u);
    e3 = { b11, b26, b26, b26 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 779u * 4u);
    e1 = { b17, b26, b26, b26 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 780u * 4u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 781u * 4u);
    e1 = { b12, b26, b26, b26 };
    e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 782u * 4u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(arena, args->ext_params + 783u * 4u);
    e4 = { b18, b26, b26, b26 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 784u * 4u);
    e0 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 785u * 4u);
    e4 = { b18, b26, b26, b26 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 786u * 4u);
    e5 = stwo_qm31_add(e4, e1);
    e4 = stwo_load_qm31(arena, args->ext_params + 787u * 4u);
    e1 = { b27, b26, b26, b26 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 788u * 4u);
    e5 = { b7, b26, b26, b26 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 789u * 4u);
    e1 = { b6, b26, b26, b26 };
    e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 790u * 4u);
    e5 = { b17, b26, b26, b26 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 791u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 792u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 793u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 794u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 795u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 796u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 797u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 798u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 799u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 800u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 801u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 802u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 803u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 804u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 805u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 806u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 807u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 808u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 809u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 810u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 811u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 812u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 813u * 4u);
    e1 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 814u * 4u);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 815u * 4u);
    e1 = stwo_qm31_sub(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 816u * 4u);
    e5 = { b19, b26, b26, b26 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 817u * 4u);
    e4 = stwo_qm31_add(e5, e6);
    e5 = stwo_load_qm31(arena, args->ext_params + 818u * 4u);
    e6 = { b3, b26, b26, b26 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e5, e6);
    e6 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 819u * 4u);
    e4 = { b21, b26, b26, b26 };
    e5 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 820u * 4u);
    e6 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 821u * 4u);
    e4 = { b16, b26, b26, b26 };
    e7 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 822u * 4u);
    e5 = stwo_qm31_add(e4, e7);
    e4 = stwo_load_qm31(arena, args->ext_params + 823u * 4u);
    e7 = { b22, b26, b26, b26 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e4, e7);
    e7 = stwo_qm31_add(e5, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 824u * 4u);
    e5 = stwo_qm31_sub(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 825u * 4u);
    e7 = { b22, b26, b26, b26 };
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 826u * 4u);
    e8 = stwo_qm31_add(e7, e4);
    e7 = stwo_load_qm31(arena, args->ext_params + 827u * 4u);
    e4 = { b0, b26, b26, b26 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 828u * 4u);
    e8 = { b9, b26, b26, b26 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 829u * 4u);
    e4 = { b8, b26, b26, b26 };
    e9 = stwo_qm31_mul(e7, e4);
    e4 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 830u * 4u);
    e8 = { b21, b26, b26, b26 };
    e7 = stwo_qm31_mul(e9, e8);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 831u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 832u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 833u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 834u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 835u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 836u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 837u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 838u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 839u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 840u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 841u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 842u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 843u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 844u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 845u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 846u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 847u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 848u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 849u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 850u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 851u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 852u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 853u * 4u);
    e4 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 854u * 4u);
    e8 = stwo_qm31_add(e4, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 855u * 4u);
    e4 = stwo_qm31_sub(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 856u * 4u);
    e8 = { b23, b26, b26, b26 };
    e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 857u * 4u);
    e7 = stwo_qm31_add(e8, e9);
    e8 = stwo_load_qm31(arena, args->ext_params + 858u * 4u);
    e9 = { b2, b26, b26, b26 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e8, e9);
    e9 = stwo_qm31_add(e7, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 859u * 4u);
    e7 = { b25, b26, b26, b26 };
    e8 = stwo_qm31_mul(e10, e7);
    e7 = stwo_qm31_add(e9, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 860u * 4u);
    e9 = stwo_qm31_sub(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 968u * 4u);
    e7 = stwo_qm31_mul(e3, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 969u * 4u);
    e10 = stwo_qm31_mul(e2, e8);
    e8 = stwo_qm31_add(e7, e10);
    e10 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 970u * 4u);
    e2 = stwo_qm31_mul(e1, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 971u * 4u);
    e7 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e2, e7);
    e7 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 972u * 4u);
    e0 = stwo_qm31_mul(e5, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 973u * 4u);
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_qm31_add(e0, e2);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 974u * 4u);
    e6 = stwo_qm31_mul(e9, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 975u * 4u);
    e0 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e6, e0);
    e0 = stwo_qm31_mul(e4, e9);
    e9 = { b20, b10, b24, b1 };
    e4 = { b29, b30, b31, b32 };
    e6 = stwo_qm31_sub(e4, e9);
    e9 = stwo_qm31_mul(e6, e10);
    e6 = stwo_qm31_sub(e9, e8);
    e9 = { b33, b34, b35, b36 };
    e8 = stwo_qm31_sub(e9, e4);
    e4 = stwo_qm31_mul(e8, e7);
    e8 = stwo_qm31_sub(e4, e3);
    e4 = { b37, b38, b39, b40 };
    e3 = stwo_qm31_sub(e4, e9);
    e9 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e9, e1);
    e9 = { b41, b42, b43, b44 };
    e1 = stwo_qm31_sub(e9, e4);
    e9 = stwo_qm31_mul(e1, e0);
    e1 = stwo_qm31_sub(e9, e5);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e6, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e8, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
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
