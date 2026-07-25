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
stwo_cairo_cuda_eval_v1_b0a972d5339ebf10(
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
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 156u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 157u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 158u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 159u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 160u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 161u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 163u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 164u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 165u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 166u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 167u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 168u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 169u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 170u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 171u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 172u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 173u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 174u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 175u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 176u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 177u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 178u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 179u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 180u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 181u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 182u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 183u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 184u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 185u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 186u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 194u, row, 0);
    unsigned b52 = 0u;
    unsigned b53 = stwo_m31_add(b0, b9);
    b9 = 2u;
    unsigned b54 = stwo_m31_mul(b9, b18);
    b9 = stwo_m31_sub(b53, b54);
    b54 = 103094260u;
    b53 = stwo_m31_add(b9, b54);
    b54 = stwo_m31_sub(b53, b27);
    b53 = stwo_m31_sub(b54, b37);
    b54 = 16u;
    b9 = stwo_m31_mul(b53, b54);
    b54 = stwo_m31_add(b9, b1);
    b53 = stwo_m31_add(b54, b10);
    b54 = 2u;
    b10 = stwo_m31_mul(b54, b19);
    b54 = stwo_m31_sub(b53, b10);
    b10 = 121146754u;
    b53 = stwo_m31_add(b54, b10);
    b10 = stwo_m31_sub(b53, b28);
    b53 = 16u;
    b54 = stwo_m31_mul(b10, b53);
    b53 = stwo_m31_add(b54, b2);
    b10 = stwo_m31_add(b53, b11);
    b53 = 2u;
    b11 = stwo_m31_mul(b53, b20);
    b53 = stwo_m31_sub(b10, b11);
    b11 = 95050340u;
    b10 = stwo_m31_add(b53, b11);
    b11 = stwo_m31_sub(b10, b29);
    b10 = 16u;
    b53 = stwo_m31_mul(b11, b10);
    b10 = stwo_m31_add(b53, b3);
    b3 = stwo_m31_add(b10, b12);
    b10 = 2u;
    b12 = stwo_m31_mul(b10, b21);
    b10 = stwo_m31_sub(b3, b12);
    b12 = 16173996u;
    b3 = stwo_m31_add(b10, b12);
    b12 = stwo_m31_sub(b3, b30);
    b3 = 16u;
    b10 = stwo_m31_mul(b12, b3);
    b3 = stwo_m31_add(b10, b4);
    b4 = stwo_m31_add(b3, b13);
    b3 = 2u;
    b13 = stwo_m31_mul(b3, b22);
    b3 = stwo_m31_sub(b4, b13);
    b13 = 50758155u;
    b4 = stwo_m31_add(b3, b13);
    b13 = stwo_m31_sub(b4, b31);
    b4 = 16u;
    b3 = stwo_m31_mul(b13, b4);
    b4 = stwo_m31_add(b3, b5);
    b5 = stwo_m31_add(b4, b14);
    b4 = 2u;
    b14 = stwo_m31_mul(b4, b23);
    b4 = stwo_m31_sub(b5, b14);
    b14 = 54415179u;
    b5 = stwo_m31_add(b4, b14);
    b14 = stwo_m31_sub(b5, b32);
    b5 = 16u;
    b4 = stwo_m31_mul(b14, b5);
    b5 = stwo_m31_add(b4, b6);
    b6 = stwo_m31_add(b5, b15);
    b5 = 2u;
    b15 = stwo_m31_mul(b5, b24);
    b5 = stwo_m31_sub(b6, b15);
    b15 = 19292069u;
    b6 = stwo_m31_add(b5, b15);
    b15 = stwo_m31_sub(b6, b33);
    b6 = 16u;
    b5 = stwo_m31_mul(b15, b6);
    b6 = stwo_m31_add(b5, b7);
    b7 = stwo_m31_add(b6, b16);
    b6 = 2u;
    b16 = stwo_m31_mul(b6, b25);
    b6 = stwo_m31_sub(b7, b16);
    b16 = 45351266u;
    b7 = stwo_m31_add(b6, b16);
    b16 = stwo_m31_sub(b7, b34);
    b7 = 136u;
    b6 = stwo_m31_mul(b37, b7);
    b7 = stwo_m31_sub(b16, b6);
    b6 = 16u;
    b16 = stwo_m31_mul(b7, b6);
    b6 = stwo_m31_add(b16, b8);
    b8 = stwo_m31_add(b6, b17);
    b6 = 2u;
    b17 = stwo_m31_mul(b6, b26);
    b6 = stwo_m31_sub(b8, b17);
    b17 = 122233508u;
    b8 = stwo_m31_add(b6, b17);
    b17 = stwo_m31_sub(b8, b35);
    b8 = 16u;
    b6 = stwo_m31_mul(b17, b8);
    b8 = 3u;
    b17 = stwo_m31_add(b37, b8);
    b8 = 3u;
    b37 = stwo_m31_add(b9, b8);
    b8 = 3u;
    b9 = stwo_m31_add(b54, b8);
    b8 = 3u;
    b54 = stwo_m31_add(b53, b8);
    b8 = 3u;
    b53 = stwo_m31_add(b10, b8);
    b8 = 3u;
    b10 = stwo_m31_add(b3, b8);
    b8 = 3u;
    b3 = stwo_m31_add(b4, b8);
    b8 = 3u;
    b4 = stwo_m31_add(b5, b8);
    b8 = 3u;
    b5 = stwo_m31_add(b16, b8);
    b8 = 3u;
    b16 = stwo_m31_add(b6, b8);
    b8 = 4u;
    b6 = stwo_m31_mul(b8, b0);
    b8 = 2u;
    b0 = stwo_m31_mul(b8, b18);
    b8 = stwo_m31_add(b6, b0);
    b0 = 2u;
    b6 = stwo_m31_mul(b0, b38);
    b0 = stwo_m31_sub(b8, b6);
    b6 = 121657377u;
    b8 = stwo_m31_add(b0, b6);
    b6 = stwo_m31_sub(b8, b48);
    b8 = stwo_m31_sub(b6, b51);
    b6 = 16u;
    b48 = stwo_m31_mul(b8, b6);
    b6 = 4u;
    b8 = stwo_m31_mul(b6, b1);
    b6 = stwo_m31_add(b48, b8);
    b8 = 2u;
    b1 = stwo_m31_mul(b8, b19);
    b8 = stwo_m31_add(b6, b1);
    b1 = 2u;
    b6 = stwo_m31_mul(b1, b39);
    b1 = stwo_m31_sub(b8, b6);
    b6 = 112479959u;
    b8 = stwo_m31_add(b1, b6);
    b6 = stwo_m31_sub(b8, b49);
    b8 = 16u;
    b49 = stwo_m31_mul(b6, b8);
    b8 = 4u;
    b6 = stwo_m31_mul(b8, b2);
    b8 = stwo_m31_add(b49, b6);
    b6 = 2u;
    b2 = stwo_m31_mul(b6, b20);
    b6 = stwo_m31_add(b8, b2);
    b2 = 2u;
    b8 = stwo_m31_mul(b2, b40);
    b2 = stwo_m31_sub(b6, b8);
    b8 = 130418270u;
    b6 = stwo_m31_add(b2, b8);
    b8 = stwo_m31_sub(b6, b50);
    b6 = 16u;
    b50 = stwo_m31_mul(b8, b6);
    b6 = 3u;
    b8 = stwo_m31_add(b51, b6);
    b6 = 3u;
    b51 = stwo_m31_add(b48, b6);
    b6 = 3u;
    b48 = stwo_m31_add(b49, b6);
    b6 = 3u;
    b49 = stwo_m31_add(b50, b6);
    b6 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    b50 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    b2 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    b20 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    b1 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    b19 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    b0 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    b18 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    b26 = stwo_trace_value(arena, *args, 2u, 20u, row, 0);
    b7 = stwo_trace_value(arena, *args, 2u, 21u, row, 0);
    b25 = stwo_trace_value(arena, *args, 2u, 22u, row, 0);
    b15 = stwo_trace_value(arena, *args, 2u, 23u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 207u * 4u);
    StwoCairoQm31 e1 = { b17, b52, b52, b52 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 208u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 209u * 4u);
    e2 = { b37, b52, b52, b52 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 210u * 4u);
    e0 = { b9, b52, b52, b52 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 211u * 4u);
    e2 = { b54, b52, b52, b52 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 212u * 4u);
    e0 = { b53, b52, b52, b52 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 213u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 214u * 4u);
    e0 = { b10, b52, b52, b52 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 215u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 216u * 4u);
    e3 = { b3, b52, b52, b52 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 217u * 4u);
    e1 = { b4, b52, b52, b52 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 218u * 4u);
    e3 = { b5, b52, b52, b52 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 219u * 4u);
    e1 = { b16, b52, b52, b52 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 220u * 4u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 221u * 4u);
    e1 = { b27, b52, b52, b52 };
    e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 222u * 4u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(arena, args->ext_params + 223u * 4u);
    e4 = { b28, b52, b52, b52 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 224u * 4u);
    e0 = { b29, b52, b52, b52 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 225u * 4u);
    e4 = { b30, b52, b52, b52 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 226u * 4u);
    e0 = { b31, b52, b52, b52 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 227u * 4u);
    e4 = { b32, b52, b52, b52 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 228u * 4u);
    e0 = { b33, b52, b52, b52 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 229u * 4u);
    e4 = { b34, b52, b52, b52 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 230u * 4u);
    e0 = { b35, b52, b52, b52 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 231u * 4u);
    e4 = { b36, b52, b52, b52 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 232u * 4u);
    e0 = { b38, b52, b52, b52 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 233u * 4u);
    e4 = { b39, b52, b52, b52 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 234u * 4u);
    e0 = { b40, b52, b52, b52 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 235u * 4u);
    e4 = { b41, b52, b52, b52 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 236u * 4u);
    e0 = { b42, b52, b52, b52 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 237u * 4u);
    e4 = { b43, b52, b52, b52 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 238u * 4u);
    e0 = { b44, b52, b52, b52 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 239u * 4u);
    e4 = { b45, b52, b52, b52 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 240u * 4u);
    e0 = { b46, b52, b52, b52 };
    e1 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 241u * 4u);
    e4 = { b47, b52, b52, b52 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 242u * 4u);
    e0 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 243u * 4u);
    e4 = { b8, b52, b52, b52 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 244u * 4u);
    e5 = stwo_qm31_add(e4, e1);
    e4 = stwo_load_qm31(arena, args->ext_params + 245u * 4u);
    e1 = { b51, b52, b52, b52 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 246u * 4u);
    e5 = { b48, b52, b52, b52 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 247u * 4u);
    e1 = { b49, b52, b52, b52 };
    e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 248u * 4u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 556u * 4u);
    e1 = stwo_qm31_mul(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 557u * 4u);
    e4 = stwo_qm31_mul(e2, e6);
    e6 = stwo_qm31_add(e1, e4);
    e4 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 558u * 4u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 559u * 4u);
    e1 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e2, e1);
    e1 = stwo_qm31_mul(e0, e5);
    e5 = { b6, b50, b2, b20 };
    e0 = { b1, b19, b0, b18 };
    e2 = stwo_qm31_sub(e0, e5);
    e5 = stwo_qm31_mul(e2, e4);
    e2 = stwo_qm31_sub(e5, e6);
    e5 = { b26, b7, b25, b15 };
    e6 = stwo_qm31_sub(e5, e0);
    e5 = stwo_qm31_mul(e6, e1);
    e6 = stwo_qm31_sub(e5, e3);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e6, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
