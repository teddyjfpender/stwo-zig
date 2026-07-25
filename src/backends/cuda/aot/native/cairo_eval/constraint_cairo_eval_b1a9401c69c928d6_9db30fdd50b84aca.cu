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
stwo_cairo_cuda_eval_v1_51811c3ec87c268a(
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
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 41u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 52u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 53u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 54u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 55u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 58u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 59u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 60u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 61u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 101u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 104u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 105u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 107u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 108u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 109u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 110u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 111u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 112u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 113u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 114u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 115u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 116u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 117u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 118u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 119u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 120u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 121u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 122u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 123u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 124u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 126u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 127u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b82 = 0u;
    unsigned b83 = 4u;
    unsigned b84 = stwo_m31_mul(b83, b0);
    b83 = 2u;
    b0 = stwo_m31_mul(b83, b10);
    b83 = stwo_m31_add(b84, b0);
    b0 = 3u;
    b84 = stwo_m31_mul(b0, b30);
    b0 = stwo_m31_add(b83, b84);
    b84 = stwo_m31_add(b0, b40);
    b0 = stwo_m31_sub(b84, b50);
    b84 = stwo_m31_add(b0, b20);
    b0 = stwo_m31_sub(b84, b60);
    b84 = stwo_m31_sub(b0, b70);
    b0 = 16u;
    b20 = stwo_m31_mul(b84, b0);
    b0 = 4u;
    b84 = stwo_m31_mul(b0, b1);
    b0 = stwo_m31_add(b20, b84);
    b84 = 2u;
    b20 = stwo_m31_mul(b84, b11);
    b84 = stwo_m31_add(b0, b20);
    b20 = 3u;
    b0 = stwo_m31_mul(b20, b31);
    b20 = stwo_m31_add(b84, b0);
    b0 = stwo_m31_add(b20, b41);
    b20 = stwo_m31_sub(b0, b51);
    b0 = stwo_m31_add(b20, b21);
    b20 = stwo_m31_sub(b0, b61);
    b0 = 16u;
    b21 = stwo_m31_mul(b20, b0);
    b0 = 4u;
    b20 = stwo_m31_mul(b0, b2);
    b0 = stwo_m31_add(b21, b20);
    b20 = 2u;
    b21 = stwo_m31_mul(b20, b12);
    b20 = stwo_m31_add(b0, b21);
    b21 = 3u;
    b0 = stwo_m31_mul(b21, b32);
    b21 = stwo_m31_add(b20, b0);
    b0 = stwo_m31_add(b21, b42);
    b21 = stwo_m31_sub(b0, b52);
    b0 = stwo_m31_add(b21, b22);
    b21 = stwo_m31_sub(b0, b62);
    b0 = 16u;
    b22 = stwo_m31_mul(b21, b0);
    b0 = 4u;
    b21 = stwo_m31_mul(b0, b3);
    b0 = stwo_m31_add(b22, b21);
    b21 = 2u;
    b22 = stwo_m31_mul(b21, b13);
    b21 = stwo_m31_add(b0, b22);
    b22 = 3u;
    b0 = stwo_m31_mul(b22, b33);
    b22 = stwo_m31_add(b21, b0);
    b0 = stwo_m31_add(b22, b43);
    b22 = stwo_m31_sub(b0, b53);
    b0 = stwo_m31_add(b22, b23);
    b22 = stwo_m31_sub(b0, b63);
    b0 = 16u;
    b23 = stwo_m31_mul(b22, b0);
    b0 = 4u;
    b22 = stwo_m31_mul(b0, b4);
    b0 = stwo_m31_add(b23, b22);
    b22 = 2u;
    b23 = stwo_m31_mul(b22, b14);
    b22 = stwo_m31_add(b0, b23);
    b23 = 3u;
    b0 = stwo_m31_mul(b23, b34);
    b23 = stwo_m31_add(b22, b0);
    b0 = stwo_m31_add(b23, b44);
    b23 = stwo_m31_sub(b0, b54);
    b0 = stwo_m31_add(b23, b24);
    b23 = stwo_m31_sub(b0, b64);
    b0 = 16u;
    b24 = stwo_m31_mul(b23, b0);
    b0 = 4u;
    b23 = stwo_m31_mul(b0, b5);
    b0 = stwo_m31_add(b24, b23);
    b23 = 2u;
    b24 = stwo_m31_mul(b23, b15);
    b23 = stwo_m31_add(b0, b24);
    b24 = 3u;
    b0 = stwo_m31_mul(b24, b35);
    b24 = stwo_m31_add(b23, b0);
    b0 = stwo_m31_add(b24, b45);
    b24 = stwo_m31_sub(b0, b55);
    b0 = stwo_m31_add(b24, b25);
    b24 = stwo_m31_sub(b0, b65);
    b0 = 16u;
    b25 = stwo_m31_mul(b24, b0);
    b0 = 4u;
    b24 = stwo_m31_mul(b0, b6);
    b0 = stwo_m31_add(b25, b24);
    b24 = 2u;
    b25 = stwo_m31_mul(b24, b16);
    b24 = stwo_m31_add(b0, b25);
    b25 = 3u;
    b0 = stwo_m31_mul(b25, b36);
    b25 = stwo_m31_add(b24, b0);
    b0 = stwo_m31_add(b25, b46);
    b25 = stwo_m31_sub(b0, b56);
    b0 = stwo_m31_add(b25, b26);
    b25 = stwo_m31_sub(b0, b66);
    b0 = 16u;
    b26 = stwo_m31_mul(b25, b0);
    b0 = 4u;
    b25 = stwo_m31_mul(b0, b7);
    b0 = stwo_m31_add(b26, b25);
    b25 = 2u;
    b26 = stwo_m31_mul(b25, b17);
    b25 = stwo_m31_add(b0, b26);
    b26 = 3u;
    b0 = stwo_m31_mul(b26, b37);
    b26 = stwo_m31_add(b25, b0);
    b0 = stwo_m31_add(b26, b47);
    b26 = stwo_m31_sub(b0, b57);
    b0 = stwo_m31_add(b26, b27);
    b26 = stwo_m31_sub(b0, b67);
    b0 = 136u;
    b27 = stwo_m31_mul(b70, b0);
    b0 = stwo_m31_sub(b26, b27);
    b27 = 16u;
    b26 = stwo_m31_mul(b0, b27);
    b27 = 4u;
    b0 = stwo_m31_mul(b27, b8);
    b27 = stwo_m31_add(b26, b0);
    b0 = 2u;
    b26 = stwo_m31_mul(b0, b18);
    b0 = stwo_m31_add(b27, b26);
    b26 = 3u;
    b27 = stwo_m31_mul(b26, b38);
    b26 = stwo_m31_add(b0, b27);
    b27 = stwo_m31_add(b26, b48);
    b26 = stwo_m31_sub(b27, b58);
    b27 = stwo_m31_add(b26, b28);
    b26 = stwo_m31_sub(b27, b68);
    b27 = 16u;
    b28 = stwo_m31_mul(b26, b27);
    b27 = 4u;
    b26 = stwo_m31_mul(b27, b9);
    b27 = stwo_m31_add(b28, b26);
    b26 = 2u;
    b28 = stwo_m31_mul(b26, b19);
    b26 = stwo_m31_add(b27, b28);
    b28 = 3u;
    b27 = stwo_m31_mul(b28, b39);
    b28 = stwo_m31_add(b26, b27);
    b27 = stwo_m31_add(b28, b49);
    b28 = stwo_m31_sub(b27, b59);
    b27 = stwo_m31_add(b28, b29);
    b28 = stwo_m31_sub(b27, b69);
    b27 = 256u;
    b29 = stwo_m31_mul(b70, b27);
    b27 = stwo_m31_sub(b28, b29);
    b29 = 2u;
    b28 = stwo_m31_mul(b29, b60);
    b29 = stwo_m31_sub(b28, b71);
    b28 = stwo_m31_sub(b29, b81);
    b29 = 16u;
    b71 = stwo_m31_mul(b28, b29);
    b29 = 2u;
    b28 = stwo_m31_mul(b29, b61);
    b29 = stwo_m31_add(b71, b28);
    b28 = stwo_m31_sub(b29, b72);
    b29 = 16u;
    b72 = stwo_m31_mul(b28, b29);
    b29 = 2u;
    b28 = stwo_m31_mul(b29, b62);
    b29 = stwo_m31_add(b72, b28);
    b28 = stwo_m31_sub(b29, b73);
    b29 = 16u;
    b73 = stwo_m31_mul(b28, b29);
    b29 = 2u;
    b28 = stwo_m31_mul(b29, b63);
    b29 = stwo_m31_add(b73, b28);
    b28 = stwo_m31_sub(b29, b74);
    b29 = 16u;
    b74 = stwo_m31_mul(b28, b29);
    b29 = 2u;
    b28 = stwo_m31_mul(b29, b64);
    b29 = stwo_m31_add(b74, b28);
    b28 = stwo_m31_sub(b29, b75);
    b29 = 16u;
    b75 = stwo_m31_mul(b28, b29);
    b29 = 2u;
    b28 = stwo_m31_mul(b29, b65);
    b29 = stwo_m31_add(b75, b28);
    b28 = stwo_m31_sub(b29, b76);
    b29 = 16u;
    b76 = stwo_m31_mul(b28, b29);
    b29 = 2u;
    b28 = stwo_m31_mul(b29, b66);
    b29 = stwo_m31_add(b76, b28);
    b28 = stwo_m31_sub(b29, b77);
    b29 = 16u;
    b77 = stwo_m31_mul(b28, b29);
    b29 = 2u;
    b28 = stwo_m31_mul(b29, b67);
    b29 = stwo_m31_add(b77, b28);
    b28 = stwo_m31_sub(b29, b78);
    b29 = 136u;
    b78 = stwo_m31_mul(b81, b29);
    b29 = stwo_m31_sub(b28, b78);
    b78 = 16u;
    b28 = stwo_m31_mul(b29, b78);
    b78 = 2u;
    b29 = stwo_m31_mul(b78, b68);
    b78 = stwo_m31_add(b28, b29);
    b29 = stwo_m31_sub(b78, b79);
    b78 = 16u;
    b79 = stwo_m31_mul(b29, b78);
    b78 = 2u;
    b29 = stwo_m31_mul(b78, b69);
    b78 = stwo_m31_add(b79, b29);
    b29 = stwo_m31_sub(b78, b80);
    b78 = 256u;
    b80 = stwo_m31_mul(b81, b78);
    b78 = stwo_m31_sub(b29, b80);
    b80 = stwo_m31_mul(b81, b81);
    b29 = stwo_m31_mul(b80, b81);
    b80 = stwo_m31_sub(b29, b81);
    b29 = stwo_m31_mul(b71, b71);
    b81 = stwo_m31_mul(b29, b71);
    b29 = stwo_m31_sub(b81, b71);
    b81 = stwo_m31_mul(b72, b72);
    b71 = stwo_m31_mul(b81, b72);
    b81 = stwo_m31_sub(b71, b72);
    b71 = stwo_m31_mul(b73, b73);
    b72 = stwo_m31_mul(b71, b73);
    b71 = stwo_m31_sub(b72, b73);
    b72 = stwo_m31_mul(b74, b74);
    b73 = stwo_m31_mul(b72, b74);
    b72 = stwo_m31_sub(b73, b74);
    b73 = stwo_m31_mul(b75, b75);
    b74 = stwo_m31_mul(b73, b75);
    b73 = stwo_m31_sub(b74, b75);
    b74 = stwo_m31_mul(b76, b76);
    b75 = stwo_m31_mul(b74, b76);
    b74 = stwo_m31_sub(b75, b76);
    b75 = stwo_m31_mul(b77, b77);
    b76 = stwo_m31_mul(b75, b77);
    b75 = stwo_m31_sub(b76, b77);
    b76 = stwo_m31_mul(b28, b28);
    b77 = stwo_m31_mul(b76, b28);
    b76 = stwo_m31_sub(b77, b28);
    b77 = stwo_m31_mul(b79, b79);
    b28 = stwo_m31_mul(b77, b79);
    b77 = stwo_m31_sub(b28, b79);
    StwoCairoQm31 e0 = { b27, b82, b82, b82 };
    StwoCairoQm31 e1 = { b78, b82, b82, b82 };
    StwoCairoQm31 e2 = { b80, b82, b82, b82 };
    StwoCairoQm31 e3 = { b29, b82, b82, b82 };
    StwoCairoQm31 e4 = { b81, b82, b82, b82 };
    StwoCairoQm31 e5 = { b71, b82, b82, b82 };
    StwoCairoQm31 e6 = { b72, b82, b82, b82 };
    StwoCairoQm31 e7 = { b73, b82, b82, b82 };
    StwoCairoQm31 e8 = { b74, b82, b82, b82 };
    StwoCairoQm31 e9 = { b75, b82, b82, b82 };
    StwoCairoQm31 e10 = { b76, b82, b82, b82 };
    StwoCairoQm31 e11 = { b77, b82, b82, b82 };
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e4, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e6, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e8, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 8u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e9, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 9u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e10, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 10u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e11, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 11u) * 4u)));
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
