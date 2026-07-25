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
stwo_cairo_cuda_eval_v1_1011e5834c51e708(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 62u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 63u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 64u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 65u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 66u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 67u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 71u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 101u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 104u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 105u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 107u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 108u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 109u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 110u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 111u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 112u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 113u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 126u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 127u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 143u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 144u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 145u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 156u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 157u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 158u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 159u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 160u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 161u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 162u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 163u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 164u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 165u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 166u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 167u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 168u, row, 0);
    unsigned b83 = 0u;
    unsigned b84 = 4u;
    unsigned b85 = stwo_m31_mul(b84, b10);
    b84 = 2u;
    b10 = stwo_m31_mul(b84, b20);
    b84 = stwo_m31_add(b85, b10);
    b10 = 3u;
    b85 = stwo_m31_mul(b10, b30);
    b10 = stwo_m31_add(b84, b85);
    b85 = stwo_m31_add(b10, b40);
    b10 = stwo_m31_sub(b85, b50);
    b85 = stwo_m31_add(b10, b0);
    b10 = stwo_m31_sub(b85, b60);
    b85 = stwo_m31_sub(b10, b70);
    b10 = 16u;
    b0 = stwo_m31_mul(b85, b10);
    b10 = 4u;
    b85 = stwo_m31_mul(b10, b11);
    b10 = stwo_m31_add(b0, b85);
    b85 = 2u;
    b0 = stwo_m31_mul(b85, b21);
    b85 = stwo_m31_add(b10, b0);
    b0 = 3u;
    b10 = stwo_m31_mul(b0, b31);
    b0 = stwo_m31_add(b85, b10);
    b10 = stwo_m31_add(b0, b41);
    b0 = stwo_m31_sub(b10, b51);
    b10 = stwo_m31_add(b0, b1);
    b0 = stwo_m31_sub(b10, b61);
    b10 = 16u;
    b1 = stwo_m31_mul(b0, b10);
    b10 = 4u;
    b0 = stwo_m31_mul(b10, b12);
    b10 = stwo_m31_add(b1, b0);
    b0 = 2u;
    b1 = stwo_m31_mul(b0, b22);
    b0 = stwo_m31_add(b10, b1);
    b1 = 3u;
    b10 = stwo_m31_mul(b1, b32);
    b1 = stwo_m31_add(b0, b10);
    b10 = stwo_m31_add(b1, b42);
    b1 = stwo_m31_sub(b10, b52);
    b10 = stwo_m31_add(b1, b2);
    b1 = stwo_m31_sub(b10, b62);
    b10 = 16u;
    b2 = stwo_m31_mul(b1, b10);
    b10 = 4u;
    b1 = stwo_m31_mul(b10, b13);
    b10 = stwo_m31_add(b2, b1);
    b1 = 2u;
    b2 = stwo_m31_mul(b1, b23);
    b1 = stwo_m31_add(b10, b2);
    b2 = 3u;
    b10 = stwo_m31_mul(b2, b33);
    b2 = stwo_m31_add(b1, b10);
    b10 = stwo_m31_add(b2, b43);
    b2 = stwo_m31_sub(b10, b53);
    b10 = stwo_m31_add(b2, b3);
    b2 = stwo_m31_sub(b10, b63);
    b10 = 16u;
    b3 = stwo_m31_mul(b2, b10);
    b10 = 4u;
    b2 = stwo_m31_mul(b10, b14);
    b10 = stwo_m31_add(b3, b2);
    b2 = 2u;
    b3 = stwo_m31_mul(b2, b24);
    b2 = stwo_m31_add(b10, b3);
    b3 = 3u;
    b10 = stwo_m31_mul(b3, b34);
    b3 = stwo_m31_add(b2, b10);
    b10 = stwo_m31_add(b3, b44);
    b3 = stwo_m31_sub(b10, b54);
    b10 = stwo_m31_add(b3, b4);
    b3 = stwo_m31_sub(b10, b64);
    b10 = 16u;
    b4 = stwo_m31_mul(b3, b10);
    b10 = 4u;
    b3 = stwo_m31_mul(b10, b15);
    b10 = stwo_m31_add(b4, b3);
    b3 = 2u;
    b4 = stwo_m31_mul(b3, b25);
    b3 = stwo_m31_add(b10, b4);
    b4 = 3u;
    b10 = stwo_m31_mul(b4, b35);
    b4 = stwo_m31_add(b3, b10);
    b10 = stwo_m31_add(b4, b45);
    b4 = stwo_m31_sub(b10, b55);
    b10 = stwo_m31_add(b4, b5);
    b4 = stwo_m31_sub(b10, b65);
    b10 = 16u;
    b5 = stwo_m31_mul(b4, b10);
    b10 = 4u;
    b4 = stwo_m31_mul(b10, b16);
    b10 = stwo_m31_add(b5, b4);
    b4 = 2u;
    b5 = stwo_m31_mul(b4, b26);
    b4 = stwo_m31_add(b10, b5);
    b5 = 3u;
    b10 = stwo_m31_mul(b5, b36);
    b5 = stwo_m31_add(b4, b10);
    b10 = stwo_m31_add(b5, b46);
    b5 = stwo_m31_sub(b10, b56);
    b10 = stwo_m31_add(b5, b6);
    b5 = stwo_m31_sub(b10, b66);
    b10 = 16u;
    b6 = stwo_m31_mul(b5, b10);
    b10 = 4u;
    b5 = stwo_m31_mul(b10, b17);
    b10 = stwo_m31_add(b6, b5);
    b5 = 2u;
    b6 = stwo_m31_mul(b5, b27);
    b5 = stwo_m31_add(b10, b6);
    b6 = 3u;
    b10 = stwo_m31_mul(b6, b37);
    b6 = stwo_m31_add(b5, b10);
    b10 = stwo_m31_add(b6, b47);
    b6 = stwo_m31_sub(b10, b57);
    b10 = stwo_m31_add(b6, b7);
    b6 = stwo_m31_sub(b10, b67);
    b10 = 136u;
    b7 = stwo_m31_mul(b70, b10);
    b10 = stwo_m31_sub(b6, b7);
    b7 = 16u;
    b6 = stwo_m31_mul(b10, b7);
    b7 = 4u;
    b10 = stwo_m31_mul(b7, b18);
    b7 = stwo_m31_add(b6, b10);
    b10 = 2u;
    b6 = stwo_m31_mul(b10, b28);
    b10 = stwo_m31_add(b7, b6);
    b6 = 3u;
    b7 = stwo_m31_mul(b6, b38);
    b6 = stwo_m31_add(b10, b7);
    b7 = stwo_m31_add(b6, b48);
    b6 = stwo_m31_sub(b7, b58);
    b7 = stwo_m31_add(b6, b8);
    b6 = stwo_m31_sub(b7, b68);
    b7 = 16u;
    b8 = stwo_m31_mul(b6, b7);
    b7 = 4u;
    b6 = stwo_m31_mul(b7, b19);
    b7 = stwo_m31_add(b8, b6);
    b6 = 2u;
    b8 = stwo_m31_mul(b6, b29);
    b6 = stwo_m31_add(b7, b8);
    b8 = 3u;
    b7 = stwo_m31_mul(b8, b39);
    b8 = stwo_m31_add(b6, b7);
    b7 = stwo_m31_add(b8, b49);
    b8 = stwo_m31_sub(b7, b59);
    b7 = stwo_m31_add(b8, b9);
    b8 = stwo_m31_sub(b7, b69);
    b7 = 256u;
    b9 = stwo_m31_mul(b70, b7);
    b7 = stwo_m31_sub(b8, b9);
    b9 = 2u;
    b8 = stwo_m31_mul(b9, b60);
    b9 = stwo_m31_sub(b8, b71);
    b8 = stwo_m31_sub(b9, b81);
    b9 = 16u;
    b71 = stwo_m31_mul(b8, b9);
    b9 = 2u;
    b8 = stwo_m31_mul(b9, b61);
    b9 = stwo_m31_add(b71, b8);
    b8 = stwo_m31_sub(b9, b72);
    b9 = 16u;
    b72 = stwo_m31_mul(b8, b9);
    b9 = 2u;
    b8 = stwo_m31_mul(b9, b62);
    b9 = stwo_m31_add(b72, b8);
    b8 = stwo_m31_sub(b9, b73);
    b9 = 16u;
    b73 = stwo_m31_mul(b8, b9);
    b9 = 2u;
    b8 = stwo_m31_mul(b9, b63);
    b9 = stwo_m31_add(b73, b8);
    b8 = stwo_m31_sub(b9, b74);
    b9 = 16u;
    b74 = stwo_m31_mul(b8, b9);
    b9 = 2u;
    b8 = stwo_m31_mul(b9, b64);
    b9 = stwo_m31_add(b74, b8);
    b8 = stwo_m31_sub(b9, b75);
    b9 = 16u;
    b75 = stwo_m31_mul(b8, b9);
    b9 = 2u;
    b8 = stwo_m31_mul(b9, b65);
    b9 = stwo_m31_add(b75, b8);
    b8 = stwo_m31_sub(b9, b76);
    b9 = 16u;
    b76 = stwo_m31_mul(b8, b9);
    b9 = 2u;
    b8 = stwo_m31_mul(b9, b66);
    b9 = stwo_m31_add(b76, b8);
    b8 = stwo_m31_sub(b9, b77);
    b9 = 16u;
    b77 = stwo_m31_mul(b8, b9);
    b9 = 2u;
    b8 = stwo_m31_mul(b9, b67);
    b9 = stwo_m31_add(b77, b8);
    b8 = stwo_m31_sub(b9, b78);
    b9 = 136u;
    b78 = stwo_m31_mul(b81, b9);
    b9 = stwo_m31_sub(b8, b78);
    b78 = 16u;
    b8 = stwo_m31_mul(b9, b78);
    b78 = 2u;
    b9 = stwo_m31_mul(b78, b68);
    b78 = stwo_m31_add(b8, b9);
    b9 = stwo_m31_sub(b78, b79);
    b78 = 16u;
    b79 = stwo_m31_mul(b9, b78);
    b78 = 2u;
    b9 = stwo_m31_mul(b78, b69);
    b78 = stwo_m31_add(b79, b9);
    b9 = stwo_m31_sub(b78, b80);
    b78 = 256u;
    b80 = stwo_m31_mul(b81, b78);
    b78 = stwo_m31_sub(b9, b80);
    b80 = stwo_m31_mul(b81, b81);
    b9 = stwo_m31_mul(b80, b81);
    b80 = stwo_m31_sub(b9, b81);
    b9 = stwo_m31_mul(b71, b71);
    b81 = stwo_m31_mul(b9, b71);
    b9 = stwo_m31_sub(b81, b71);
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
    b76 = stwo_m31_mul(b8, b8);
    b77 = stwo_m31_mul(b76, b8);
    b76 = stwo_m31_sub(b77, b8);
    b77 = stwo_m31_mul(b79, b79);
    b8 = stwo_m31_mul(b77, b79);
    b77 = stwo_m31_sub(b8, b79);
    b8 = stwo_m31_mul(b82, b82);
    b79 = stwo_m31_sub(b8, b82);
    StwoCairoQm31 e0 = { b7, b83, b83, b83 };
    StwoCairoQm31 e1 = { b78, b83, b83, b83 };
    StwoCairoQm31 e2 = { b80, b83, b83, b83 };
    StwoCairoQm31 e3 = { b9, b83, b83, b83 };
    StwoCairoQm31 e4 = { b81, b83, b83, b83 };
    StwoCairoQm31 e5 = { b71, b83, b83, b83 };
    StwoCairoQm31 e6 = { b72, b83, b83, b83 };
    StwoCairoQm31 e7 = { b73, b83, b83, b83 };
    StwoCairoQm31 e8 = { b74, b83, b83, b83 };
    StwoCairoQm31 e9 = { b75, b83, b83, b83 };
    StwoCairoQm31 e10 = { b76, b83, b83, b83 };
    StwoCairoQm31 e11 = { b77, b83, b83, b83 };
    StwoCairoQm31 e12 = { b79, b83, b83, b83 };
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
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e12, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 12u) * 4u)));
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
