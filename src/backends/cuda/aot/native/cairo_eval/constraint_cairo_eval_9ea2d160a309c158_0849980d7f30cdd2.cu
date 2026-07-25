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
stwo_cairo_cuda_eval_v1_3b5e0b7150394f0c(
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
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 3u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 4u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 5u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 6u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 7u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 8u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 9u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 10u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 11u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 19u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 25u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 41u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 42u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 43u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 47u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 48u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 49u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 51u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 52u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 53u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 54u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 55u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 103u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 104u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 112u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b64 = stwo_m31_sub(b0, b10);
    b0 = 512u;
    unsigned b65 = stwo_m31_mul(b11, b0);
    b0 = stwo_m31_sub(b64, b65);
    b65 = 8192u;
    b64 = stwo_m31_mul(b0, b65);
    b65 = stwo_m31_sub(b1, b12);
    b1 = 512u;
    b0 = stwo_m31_mul(b13, b1);
    b1 = stwo_m31_sub(b65, b0);
    b0 = 8192u;
    b65 = stwo_m31_mul(b1, b0);
    b0 = stwo_m31_sub(b2, b14);
    b2 = 512u;
    b1 = stwo_m31_mul(b15, b2);
    b2 = stwo_m31_sub(b0, b1);
    b1 = 8192u;
    b0 = stwo_m31_mul(b2, b1);
    b1 = stwo_m31_sub(b3, b16);
    b3 = 512u;
    b2 = stwo_m31_mul(b17, b3);
    b3 = stwo_m31_sub(b1, b2);
    b2 = 8192u;
    b1 = stwo_m31_mul(b3, b2);
    b2 = stwo_m31_sub(b4, b18);
    b4 = 512u;
    b3 = stwo_m31_mul(b19, b4);
    b4 = stwo_m31_sub(b2, b3);
    b3 = 8192u;
    b2 = stwo_m31_mul(b4, b3);
    b3 = stwo_m31_sub(b5, b20);
    b5 = 512u;
    b4 = stwo_m31_mul(b21, b5);
    b5 = stwo_m31_sub(b3, b4);
    b4 = 8192u;
    b3 = stwo_m31_mul(b5, b4);
    b4 = stwo_m31_sub(b6, b22);
    b6 = 512u;
    b5 = stwo_m31_mul(b23, b6);
    b6 = stwo_m31_sub(b4, b5);
    b5 = 8192u;
    b4 = stwo_m31_mul(b6, b5);
    b5 = stwo_m31_sub(b7, b24);
    b7 = 512u;
    b6 = stwo_m31_mul(b25, b7);
    b7 = stwo_m31_sub(b5, b6);
    b6 = 8192u;
    b5 = stwo_m31_mul(b7, b6);
    b6 = stwo_m31_sub(b8, b26);
    b8 = 512u;
    b7 = stwo_m31_mul(b27, b8);
    b8 = stwo_m31_sub(b6, b7);
    b7 = 8192u;
    b6 = stwo_m31_mul(b8, b7);
    b7 = 0u;
    b8 = stwo_m31_mul(b10, b32);
    unsigned b66 = stwo_m31_mul(b11, b31);
    unsigned b67 = stwo_m31_add(b8, b66);
    b66 = stwo_m31_mul(b64, b30);
    b8 = stwo_m31_add(b67, b66);
    b66 = stwo_m31_mul(b12, b29);
    b67 = stwo_m31_add(b8, b66);
    b66 = stwo_m31_mul(b13, b28);
    b8 = stwo_m31_add(b67, b66);
    b66 = stwo_m31_mul(b10, b33);
    b67 = stwo_m31_mul(b11, b32);
    unsigned b68 = stwo_m31_add(b66, b67);
    b67 = stwo_m31_mul(b64, b31);
    b66 = stwo_m31_add(b68, b67);
    b67 = stwo_m31_mul(b12, b30);
    b68 = stwo_m31_add(b66, b67);
    b67 = stwo_m31_mul(b13, b29);
    b66 = stwo_m31_add(b68, b67);
    b67 = stwo_m31_mul(b65, b28);
    b68 = stwo_m31_add(b66, b67);
    b67 = stwo_m31_mul(b10, b34);
    b66 = stwo_m31_mul(b11, b33);
    unsigned b69 = stwo_m31_add(b67, b66);
    b66 = stwo_m31_mul(b64, b32);
    b67 = stwo_m31_add(b69, b66);
    b66 = stwo_m31_mul(b12, b31);
    b69 = stwo_m31_add(b67, b66);
    b66 = stwo_m31_mul(b13, b30);
    b67 = stwo_m31_add(b69, b66);
    b66 = stwo_m31_mul(b65, b29);
    b69 = stwo_m31_add(b67, b66);
    b66 = stwo_m31_mul(b14, b28);
    b67 = stwo_m31_add(b69, b66);
    b66 = stwo_m31_mul(b65, b34);
    b69 = stwo_m31_mul(b14, b33);
    unsigned b70 = stwo_m31_add(b66, b69);
    b69 = stwo_m31_mul(b14, b34);
    b66 = stwo_m31_mul(b15, b39);
    unsigned b71 = stwo_m31_mul(b0, b38);
    unsigned b72 = stwo_m31_add(b66, b71);
    b71 = stwo_m31_mul(b16, b37);
    b66 = stwo_m31_add(b72, b71);
    b71 = stwo_m31_mul(b17, b36);
    b72 = stwo_m31_add(b66, b71);
    b71 = stwo_m31_mul(b1, b35);
    b66 = stwo_m31_add(b72, b71);
    b71 = stwo_m31_mul(b15, b40);
    b72 = stwo_m31_mul(b0, b39);
    unsigned b73 = stwo_m31_add(b71, b72);
    b72 = stwo_m31_mul(b16, b38);
    b71 = stwo_m31_add(b73, b72);
    b72 = stwo_m31_mul(b17, b37);
    b73 = stwo_m31_add(b71, b72);
    b72 = stwo_m31_mul(b1, b36);
    b71 = stwo_m31_add(b73, b72);
    b72 = stwo_m31_mul(b18, b35);
    b73 = stwo_m31_add(b71, b72);
    b72 = stwo_m31_mul(b15, b41);
    b71 = stwo_m31_mul(b0, b40);
    b0 = stwo_m31_add(b72, b71);
    b71 = stwo_m31_mul(b16, b39);
    b39 = stwo_m31_add(b0, b71);
    b71 = stwo_m31_mul(b17, b38);
    b38 = stwo_m31_add(b39, b71);
    b71 = stwo_m31_mul(b1, b37);
    b1 = stwo_m31_add(b38, b71);
    b71 = stwo_m31_mul(b18, b36);
    b36 = stwo_m31_add(b1, b71);
    b71 = stwo_m31_mul(b19, b35);
    b35 = stwo_m31_add(b36, b71);
    b71 = stwo_m31_mul(b18, b41);
    b36 = stwo_m31_mul(b19, b40);
    b1 = stwo_m31_add(b71, b36);
    b36 = stwo_m31_mul(b19, b41);
    b71 = stwo_m31_add(b65, b18);
    b18 = stwo_m31_add(b14, b19);
    b19 = stwo_m31_add(b33, b40);
    b40 = stwo_m31_add(b34, b41);
    b41 = stwo_m31_mul(b71, b40);
    b71 = stwo_m31_mul(b18, b19);
    b19 = stwo_m31_add(b41, b71);
    b71 = stwo_m31_sub(b19, b70);
    b19 = stwo_m31_sub(b71, b1);
    b71 = stwo_m31_add(b66, b19);
    b19 = stwo_m31_mul(b18, b40);
    b40 = stwo_m31_sub(b19, b69);
    b19 = stwo_m31_sub(b40, b36);
    b40 = stwo_m31_add(b73, b19);
    b19 = stwo_m31_mul(b2, b46);
    b73 = stwo_m31_mul(b20, b45);
    b36 = stwo_m31_add(b19, b73);
    b73 = stwo_m31_mul(b21, b44);
    b19 = stwo_m31_add(b36, b73);
    b73 = stwo_m31_mul(b3, b43);
    b36 = stwo_m31_add(b19, b73);
    b73 = stwo_m31_mul(b22, b42);
    b19 = stwo_m31_add(b36, b73);
    b73 = stwo_m31_mul(b2, b47);
    b36 = stwo_m31_mul(b20, b46);
    b69 = stwo_m31_add(b73, b36);
    b36 = stwo_m31_mul(b21, b45);
    b73 = stwo_m31_add(b69, b36);
    b36 = stwo_m31_mul(b3, b44);
    b69 = stwo_m31_add(b73, b36);
    b36 = stwo_m31_mul(b22, b43);
    b73 = stwo_m31_add(b69, b36);
    b36 = stwo_m31_mul(b23, b42);
    b69 = stwo_m31_add(b73, b36);
    b36 = stwo_m31_mul(b2, b48);
    b73 = stwo_m31_mul(b20, b47);
    b18 = stwo_m31_add(b36, b73);
    b73 = stwo_m31_mul(b21, b46);
    b36 = stwo_m31_add(b18, b73);
    b73 = stwo_m31_mul(b3, b45);
    b18 = stwo_m31_add(b36, b73);
    b73 = stwo_m31_mul(b22, b44);
    b36 = stwo_m31_add(b18, b73);
    b73 = stwo_m31_mul(b23, b43);
    b18 = stwo_m31_add(b36, b73);
    b73 = stwo_m31_mul(b4, b42);
    b36 = stwo_m31_add(b18, b73);
    b73 = stwo_m31_mul(b23, b48);
    b18 = stwo_m31_mul(b4, b47);
    b66 = stwo_m31_add(b73, b18);
    b18 = stwo_m31_mul(b4, b48);
    b73 = stwo_m31_mul(b24, b53);
    b1 = stwo_m31_mul(b25, b52);
    b70 = stwo_m31_add(b73, b1);
    b1 = stwo_m31_mul(b5, b51);
    b73 = stwo_m31_add(b70, b1);
    b1 = stwo_m31_mul(b26, b50);
    b70 = stwo_m31_add(b73, b1);
    b1 = stwo_m31_mul(b27, b49);
    b73 = stwo_m31_add(b70, b1);
    b1 = stwo_m31_mul(b24, b54);
    b70 = stwo_m31_mul(b25, b53);
    b41 = stwo_m31_add(b1, b70);
    b70 = stwo_m31_mul(b5, b52);
    b1 = stwo_m31_add(b41, b70);
    b70 = stwo_m31_mul(b26, b51);
    b41 = stwo_m31_add(b1, b70);
    b70 = stwo_m31_mul(b27, b50);
    b1 = stwo_m31_add(b41, b70);
    b70 = stwo_m31_mul(b6, b49);
    b41 = stwo_m31_add(b1, b70);
    b70 = stwo_m31_mul(b24, b55);
    b24 = stwo_m31_mul(b25, b54);
    b25 = stwo_m31_add(b70, b24);
    b24 = stwo_m31_mul(b5, b53);
    b5 = stwo_m31_add(b25, b24);
    b24 = stwo_m31_mul(b26, b52);
    b52 = stwo_m31_add(b5, b24);
    b24 = stwo_m31_mul(b27, b51);
    b51 = stwo_m31_add(b52, b24);
    b24 = stwo_m31_mul(b6, b50);
    b50 = stwo_m31_add(b51, b24);
    b24 = stwo_m31_mul(b9, b49);
    b49 = stwo_m31_add(b50, b24);
    b24 = stwo_m31_mul(b27, b55);
    b27 = stwo_m31_mul(b6, b54);
    b50 = stwo_m31_add(b24, b27);
    b27 = stwo_m31_mul(b9, b53);
    b53 = stwo_m31_add(b50, b27);
    b27 = stwo_m31_mul(b6, b55);
    b50 = stwo_m31_mul(b9, b54);
    b24 = stwo_m31_add(b27, b50);
    b50 = stwo_m31_mul(b9, b55);
    b27 = stwo_m31_add(b23, b6);
    b6 = stwo_m31_add(b4, b9);
    b9 = stwo_m31_add(b47, b54);
    b54 = stwo_m31_add(b48, b55);
    b55 = stwo_m31_mul(b27, b54);
    b27 = stwo_m31_mul(b6, b9);
    b9 = stwo_m31_add(b55, b27);
    b27 = stwo_m31_sub(b9, b66);
    b9 = stwo_m31_sub(b27, b24);
    b27 = stwo_m31_add(b73, b9);
    b9 = stwo_m31_mul(b6, b54);
    b54 = stwo_m31_sub(b9, b18);
    b9 = stwo_m31_sub(b54, b50);
    b54 = stwo_m31_add(b41, b9);
    b9 = stwo_m31_add(b10, b2);
    b2 = stwo_m31_add(b11, b20);
    b20 = stwo_m31_add(b64, b21);
    b21 = stwo_m31_add(b12, b3);
    b3 = stwo_m31_add(b13, b22);
    b22 = stwo_m31_add(b65, b23);
    b23 = stwo_m31_add(b14, b4);
    b4 = stwo_m31_add(b28, b42);
    b42 = stwo_m31_add(b29, b43);
    b43 = stwo_m31_add(b30, b44);
    b44 = stwo_m31_add(b31, b45);
    b45 = stwo_m31_add(b32, b46);
    b46 = stwo_m31_add(b33, b47);
    b47 = stwo_m31_add(b34, b48);
    b48 = stwo_m31_mul(b9, b45);
    b34 = stwo_m31_mul(b2, b44);
    b33 = stwo_m31_add(b48, b34);
    b34 = stwo_m31_mul(b20, b43);
    b48 = stwo_m31_add(b33, b34);
    b34 = stwo_m31_mul(b21, b42);
    b33 = stwo_m31_add(b48, b34);
    b34 = stwo_m31_mul(b3, b4);
    b48 = stwo_m31_add(b33, b34);
    b34 = stwo_m31_mul(b9, b46);
    b33 = stwo_m31_mul(b2, b45);
    b32 = stwo_m31_add(b34, b33);
    b33 = stwo_m31_mul(b20, b44);
    b34 = stwo_m31_add(b32, b33);
    b33 = stwo_m31_mul(b21, b43);
    b32 = stwo_m31_add(b34, b33);
    b33 = stwo_m31_mul(b3, b42);
    b34 = stwo_m31_add(b32, b33);
    b33 = stwo_m31_mul(b22, b4);
    b32 = stwo_m31_add(b34, b33);
    b33 = stwo_m31_mul(b9, b47);
    b47 = stwo_m31_mul(b2, b46);
    b46 = stwo_m31_add(b33, b47);
    b47 = stwo_m31_mul(b20, b45);
    b45 = stwo_m31_add(b46, b47);
    b47 = stwo_m31_mul(b21, b44);
    b44 = stwo_m31_add(b45, b47);
    b47 = stwo_m31_mul(b3, b43);
    b43 = stwo_m31_add(b44, b47);
    b47 = stwo_m31_mul(b22, b42);
    b42 = stwo_m31_add(b43, b47);
    b47 = stwo_m31_mul(b23, b4);
    b4 = stwo_m31_add(b42, b47);
    b47 = stwo_m31_sub(b48, b8);
    b48 = stwo_m31_sub(b47, b19);
    b47 = stwo_m31_add(b71, b48);
    b48 = stwo_m31_sub(b32, b68);
    b32 = stwo_m31_sub(b48, b69);
    b48 = stwo_m31_add(b40, b32);
    b32 = stwo_m31_sub(b4, b67);
    b4 = stwo_m31_sub(b32, b36);
    b32 = stwo_m31_add(b35, b4);
    b4 = stwo_m31_sub(b47, b56);
    b47 = stwo_m31_sub(b48, b57);
    b48 = stwo_m31_sub(b32, b58);
    b32 = 2u;
    b58 = stwo_m31_mul(b32, b4);
    b32 = 4u;
    b4 = stwo_m31_mul(b32, b27);
    b32 = stwo_m31_sub(b58, b4);
    b4 = 2u;
    b58 = stwo_m31_mul(b4, b53);
    b4 = stwo_m31_add(b32, b58);
    b58 = 64u;
    b32 = stwo_m31_mul(b58, b24);
    b58 = stwo_m31_add(b4, b32);
    b32 = 2u;
    b4 = stwo_m31_mul(b32, b47);
    b32 = 4u;
    b47 = stwo_m31_mul(b32, b54);
    b32 = stwo_m31_sub(b4, b47);
    b47 = 2u;
    b4 = stwo_m31_mul(b47, b24);
    b47 = stwo_m31_add(b32, b4);
    b4 = 64u;
    b32 = stwo_m31_mul(b4, b50);
    b4 = stwo_m31_add(b47, b32);
    b32 = 2u;
    b47 = stwo_m31_mul(b32, b48);
    b32 = 4u;
    b48 = stwo_m31_mul(b32, b49);
    b32 = stwo_m31_sub(b47, b48);
    b48 = 2u;
    b47 = stwo_m31_mul(b48, b50);
    b48 = stwo_m31_add(b32, b47);
    b47 = 512u;
    b32 = stwo_m31_mul(b61, b47);
    b47 = stwo_m31_add(b58, b60);
    b58 = stwo_m31_sub(b32, b47);
    b47 = 512u;
    b32 = stwo_m31_mul(b62, b47);
    b47 = stwo_m31_add(b4, b61);
    b4 = stwo_m31_sub(b32, b47);
    b47 = 256u;
    b32 = stwo_m31_mul(b47, b59);
    b47 = stwo_m31_sub(b48, b32);
    b32 = stwo_m31_add(b47, b62);
    b47 = stwo_m31_mul(b63, b63);
    b62 = stwo_m31_sub(b47, b63);
    b47 = stwo_trace_value(arena, *args, 2u, 0u, row, 0);
    b63 = stwo_trace_value(arena, *args, 2u, 1u, row, 0);
    b48 = stwo_trace_value(arena, *args, 2u, 2u, row, 0);
    b59 = stwo_trace_value(arena, *args, 2u, 3u, row, 0);
    b61 = stwo_trace_value(arena, *args, 2u, 4u, row, 0);
    b60 = stwo_trace_value(arena, *args, 2u, 5u, row, 0);
    b50 = stwo_trace_value(arena, *args, 2u, 6u, row, 0);
    b49 = stwo_trace_value(arena, *args, 2u, 7u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e1 = { b10, b7, b7, b7 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    e2 = { b11, b7, b7, b7 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    e2 = { b64, b7, b7, b7 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 5u * 4u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 6u * 4u);
    e1 = { b12, b7, b7, b7 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 7u * 4u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 8u * 4u);
    e1 = { b13, b7, b7, b7 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 9u * 4u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 10u * 4u);
    e2 = { b65, b7, b7, b7 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 11u * 4u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 12u * 4u);
    e2 = { b14, b7, b7, b7 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 13u * 4u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 14u * 4u);
    e1 = { b15, b7, b7, b7 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 15u * 4u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = { b58, b7, b7, b7 };
    e1 = { b4, b7, b7, b7 };
    e2 = { b32, b7, b7, b7 };
    StwoCairoQm31 e7 = { b62, b7, b7, b7 };
    StwoCairoQm31 e8 = stwo_load_qm31(arena, args->ext_params + 358u * 4u);
    StwoCairoQm31 e9 = stwo_qm31_mul(e3, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 359u * 4u);
    StwoCairoQm31 e10 = stwo_qm31_mul(e0, e8);
    e8 = stwo_qm31_add(e9, e10);
    e10 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 360u * 4u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 361u * 4u);
    e9 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e9);
    e9 = stwo_qm31_mul(e4, e5);
    e5 = { b47, b63, b48, b59 };
    e4 = stwo_qm31_mul(e5, e10);
    e10 = stwo_qm31_sub(e4, e8);
    e4 = { b61, b60, b50, b49 };
    e8 = stwo_qm31_sub(e4, e5);
    e4 = stwo_qm31_mul(e8, e9);
    e8 = stwo_qm31_sub(e4, e3);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e6, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e10, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e8, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
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
