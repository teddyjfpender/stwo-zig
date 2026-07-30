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
stwo_cairo_cuda_eval_v1_d2d1c259f5f18005(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 25u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 52u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 53u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 54u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 55u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 58u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 59u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 60u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 101u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 104u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 105u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 107u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 108u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 109u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 110u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 111u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 112u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 114u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 115u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 116u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 117u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 118u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 119u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 120u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 121u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 122u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 123u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 124u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 126u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 127u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 143u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 144u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 145u, row, 0);
    unsigned b85 = 0u;
    unsigned b86 = 4u;
    unsigned b87 = stwo_m31_mul(b86, b0);
    b86 = 2u;
    b0 = stwo_m31_mul(b86, b9);
    b86 = stwo_m31_add(b87, b0);
    b0 = 3u;
    b87 = stwo_m31_mul(b0, b27);
    b0 = stwo_m31_add(b86, b87);
    b87 = stwo_m31_add(b0, b36);
    b0 = stwo_m31_sub(b87, b45);
    b87 = stwo_m31_add(b0, b18);
    b0 = stwo_m31_sub(b87, b54);
    b87 = stwo_m31_sub(b0, b64);
    b0 = 16u;
    b18 = stwo_m31_mul(b87, b0);
    b0 = 4u;
    b87 = stwo_m31_mul(b0, b1);
    b0 = stwo_m31_add(b18, b87);
    b87 = 2u;
    b18 = stwo_m31_mul(b87, b10);
    b87 = stwo_m31_add(b0, b18);
    b18 = 3u;
    b0 = stwo_m31_mul(b18, b28);
    b18 = stwo_m31_add(b87, b0);
    b0 = stwo_m31_add(b18, b37);
    b18 = stwo_m31_sub(b0, b46);
    b0 = stwo_m31_add(b18, b19);
    b18 = stwo_m31_sub(b0, b55);
    b0 = 16u;
    b19 = stwo_m31_mul(b18, b0);
    b0 = 4u;
    b18 = stwo_m31_mul(b0, b2);
    b0 = stwo_m31_add(b19, b18);
    b18 = 2u;
    b19 = stwo_m31_mul(b18, b11);
    b18 = stwo_m31_add(b0, b19);
    b19 = 3u;
    b0 = stwo_m31_mul(b19, b29);
    b19 = stwo_m31_add(b18, b0);
    b0 = stwo_m31_add(b19, b38);
    b19 = stwo_m31_sub(b0, b47);
    b0 = stwo_m31_add(b19, b20);
    b19 = stwo_m31_sub(b0, b56);
    b0 = 16u;
    b20 = stwo_m31_mul(b19, b0);
    b0 = 4u;
    b19 = stwo_m31_mul(b0, b3);
    b0 = stwo_m31_add(b20, b19);
    b19 = 2u;
    b20 = stwo_m31_mul(b19, b12);
    b19 = stwo_m31_add(b0, b20);
    b20 = 3u;
    b0 = stwo_m31_mul(b20, b30);
    b20 = stwo_m31_add(b19, b0);
    b0 = stwo_m31_add(b20, b39);
    b20 = stwo_m31_sub(b0, b48);
    b0 = stwo_m31_add(b20, b21);
    b20 = stwo_m31_sub(b0, b57);
    b0 = 16u;
    b21 = stwo_m31_mul(b20, b0);
    b0 = 4u;
    b20 = stwo_m31_mul(b0, b4);
    b0 = stwo_m31_add(b21, b20);
    b20 = 2u;
    b4 = stwo_m31_mul(b20, b13);
    b20 = stwo_m31_add(b0, b4);
    b4 = 3u;
    b0 = stwo_m31_mul(b4, b31);
    b4 = stwo_m31_add(b20, b0);
    b0 = stwo_m31_add(b4, b40);
    b4 = stwo_m31_sub(b0, b49);
    b0 = stwo_m31_add(b4, b22);
    b4 = stwo_m31_sub(b0, b58);
    b0 = 16u;
    b22 = stwo_m31_mul(b4, b0);
    b0 = 4u;
    b4 = stwo_m31_mul(b0, b5);
    b0 = stwo_m31_add(b22, b4);
    b4 = 2u;
    b5 = stwo_m31_mul(b4, b14);
    b4 = stwo_m31_add(b0, b5);
    b5 = 3u;
    b0 = stwo_m31_mul(b5, b32);
    b5 = stwo_m31_add(b4, b0);
    b0 = stwo_m31_add(b5, b41);
    b5 = stwo_m31_sub(b0, b50);
    b0 = stwo_m31_add(b5, b23);
    b5 = stwo_m31_sub(b0, b59);
    b0 = 16u;
    b23 = stwo_m31_mul(b5, b0);
    b0 = 4u;
    b5 = stwo_m31_mul(b0, b6);
    b0 = stwo_m31_add(b23, b5);
    b5 = 2u;
    b6 = stwo_m31_mul(b5, b15);
    b5 = stwo_m31_add(b0, b6);
    b6 = 3u;
    b0 = stwo_m31_mul(b6, b33);
    b6 = stwo_m31_add(b5, b0);
    b0 = stwo_m31_add(b6, b42);
    b6 = stwo_m31_sub(b0, b51);
    b0 = stwo_m31_add(b6, b24);
    b6 = stwo_m31_sub(b0, b60);
    b0 = 16u;
    b24 = stwo_m31_mul(b6, b0);
    b0 = 4u;
    b6 = stwo_m31_mul(b0, b7);
    b0 = stwo_m31_add(b24, b6);
    b6 = 2u;
    b7 = stwo_m31_mul(b6, b16);
    b6 = stwo_m31_add(b0, b7);
    b7 = 3u;
    b0 = stwo_m31_mul(b7, b34);
    b7 = stwo_m31_add(b6, b0);
    b0 = stwo_m31_add(b7, b43);
    b7 = stwo_m31_sub(b0, b52);
    b0 = stwo_m31_add(b7, b25);
    b7 = stwo_m31_sub(b0, b61);
    b0 = 136u;
    b25 = stwo_m31_mul(b64, b0);
    b0 = stwo_m31_sub(b7, b25);
    b25 = 16u;
    b7 = stwo_m31_mul(b0, b25);
    b25 = 4u;
    b0 = stwo_m31_mul(b25, b8);
    b25 = stwo_m31_add(b7, b0);
    b0 = 2u;
    b8 = stwo_m31_mul(b0, b17);
    b0 = stwo_m31_add(b25, b8);
    b8 = 3u;
    b25 = stwo_m31_mul(b8, b35);
    b8 = stwo_m31_add(b0, b25);
    b25 = stwo_m31_add(b8, b44);
    b8 = stwo_m31_sub(b25, b53);
    b25 = stwo_m31_add(b8, b26);
    b8 = stwo_m31_sub(b25, b62);
    b25 = 16u;
    b26 = stwo_m31_mul(b8, b25);
    b25 = 2u;
    b8 = stwo_m31_add(b21, b25);
    b25 = 2u;
    b21 = stwo_m31_add(b22, b25);
    b25 = 2u;
    b22 = stwo_m31_add(b23, b25);
    b25 = 2u;
    b23 = stwo_m31_add(b24, b25);
    b25 = 2u;
    b24 = stwo_m31_add(b7, b25);
    b25 = 2u;
    b7 = stwo_m31_add(b26, b25);
    b25 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    b26 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    b53 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    b44 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    b0 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    b35 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    b17 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    b64 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    b52 = stwo_trace_value(arena, *args, 2u, 20u, row, 0);
    b43 = stwo_trace_value(arena, *args, 2u, 21u, row, 0);
    b6 = stwo_trace_value(arena, *args, 2u, 22u, row, 0);
    b34 = stwo_trace_value(arena, *args, 2u, 23u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 111u * 4u);
    StwoCairoQm31 e1 = { b8, b85, b85, b85 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 112u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 113u * 4u);
    e2 = { b21, b85, b85, b85 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 114u * 4u);
    e0 = { b22, b85, b85, b85 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 115u * 4u);
    e2 = { b23, b85, b85, b85 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 116u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 117u * 4u);
    e2 = { b24, b85, b85, b85 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 118u * 4u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 119u * 4u);
    e1 = { b7, b85, b85, b85 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 120u * 4u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 121u * 4u);
    e1 = { b54, b85, b85, b85 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 122u * 4u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 123u * 4u);
    e2 = { b55, b85, b85, b85 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 124u * 4u);
    e4 = { b56, b85, b85, b85 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 125u * 4u);
    e2 = { b57, b85, b85, b85 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 126u * 4u);
    e4 = { b58, b85, b85, b85 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 127u * 4u);
    e2 = { b59, b85, b85, b85 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 128u * 4u);
    e4 = { b60, b85, b85, b85 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 129u * 4u);
    e2 = { b61, b85, b85, b85 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 130u * 4u);
    e4 = { b62, b85, b85, b85 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 131u * 4u);
    e2 = { b63, b85, b85, b85 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 132u * 4u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 133u * 4u);
    e2 = { b65, b85, b85, b85 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 134u * 4u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 135u * 4u);
    e1 = { b66, b85, b85, b85 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 136u * 4u);
    e5 = { b67, b85, b85, b85 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 137u * 4u);
    e1 = { b68, b85, b85, b85 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 138u * 4u);
    e5 = { b69, b85, b85, b85 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 139u * 4u);
    e1 = { b70, b85, b85, b85 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 140u * 4u);
    e5 = { b71, b85, b85, b85 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 141u * 4u);
    e1 = { b72, b85, b85, b85 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 142u * 4u);
    e5 = { b73, b85, b85, b85 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 143u * 4u);
    e1 = { b74, b85, b85, b85 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 144u * 4u);
    e5 = { b75, b85, b85, b85 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 145u * 4u);
    e1 = { b76, b85, b85, b85 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 146u * 4u);
    e5 = { b77, b85, b85, b85 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 147u * 4u);
    e1 = { b78, b85, b85, b85 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 148u * 4u);
    e5 = { b79, b85, b85, b85 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 149u * 4u);
    e1 = { b80, b85, b85, b85 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 150u * 4u);
    e5 = { b81, b85, b85, b85 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 151u * 4u);
    e1 = { b82, b85, b85, b85 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 152u * 4u);
    e5 = { b83, b85, b85, b85 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 153u * 4u);
    e1 = { b84, b85, b85, b85 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 154u * 4u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 279u * 4u);
    e1 = stwo_qm31_mul(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 280u * 4u);
    e2 = stwo_qm31_mul(e0, e6);
    e6 = stwo_qm31_add(e1, e2);
    e2 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 281u * 4u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 282u * 4u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = { b25, b26, b53, b44 };
    e4 = { b0, b35, b17, b64 };
    e0 = stwo_qm31_sub(e4, e5);
    e5 = stwo_qm31_mul(e0, e2);
    e0 = stwo_qm31_sub(e5, e6);
    e5 = { b52, b43, b6, b34 };
    e6 = stwo_qm31_sub(e5, e4);
    e5 = stwo_qm31_mul(e6, e1);
    e6 = stwo_qm31_sub(e5, e3);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
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
