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
stwo_cairo_cuda_eval_v1_73209455fd5a5962(
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
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 41u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 67u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b39 = stwo_m31_sub(b0, b10);
    b0 = 512u;
    unsigned b40 = stwo_m31_mul(b11, b0);
    b0 = stwo_m31_sub(b39, b40);
    b40 = 8192u;
    b39 = stwo_m31_mul(b0, b40);
    b40 = stwo_m31_sub(b1, b12);
    b1 = 512u;
    b0 = stwo_m31_mul(b13, b1);
    b1 = stwo_m31_sub(b40, b0);
    b0 = 8192u;
    b40 = stwo_m31_mul(b1, b0);
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
    b8 = stwo_m31_mul(b10, b12);
    unsigned b41 = stwo_m31_mul(b11, b39);
    unsigned b42 = stwo_m31_add(b8, b41);
    b41 = stwo_m31_mul(b39, b11);
    b8 = stwo_m31_add(b42, b41);
    b41 = stwo_m31_mul(b12, b10);
    b42 = stwo_m31_add(b8, b41);
    b41 = stwo_m31_mul(b10, b13);
    b8 = stwo_m31_mul(b11, b12);
    unsigned b43 = stwo_m31_add(b41, b8);
    b8 = stwo_m31_mul(b39, b39);
    b41 = stwo_m31_add(b43, b8);
    b8 = stwo_m31_mul(b12, b11);
    b43 = stwo_m31_add(b41, b8);
    b8 = stwo_m31_mul(b13, b10);
    b41 = stwo_m31_add(b43, b8);
    b8 = stwo_m31_mul(b10, b40);
    b43 = stwo_m31_mul(b11, b13);
    unsigned b44 = stwo_m31_add(b8, b43);
    b43 = stwo_m31_mul(b39, b12);
    b8 = stwo_m31_add(b44, b43);
    b43 = stwo_m31_mul(b12, b39);
    b44 = stwo_m31_add(b8, b43);
    b43 = stwo_m31_mul(b13, b11);
    b8 = stwo_m31_add(b44, b43);
    b43 = stwo_m31_mul(b40, b10);
    b44 = stwo_m31_add(b8, b43);
    b43 = stwo_m31_mul(b10, b14);
    b8 = stwo_m31_mul(b11, b40);
    unsigned b45 = stwo_m31_add(b43, b8);
    b8 = stwo_m31_mul(b39, b13);
    b43 = stwo_m31_add(b45, b8);
    b8 = stwo_m31_mul(b12, b12);
    b45 = stwo_m31_add(b43, b8);
    b8 = stwo_m31_mul(b13, b39);
    b43 = stwo_m31_add(b45, b8);
    b8 = stwo_m31_mul(b40, b11);
    b45 = stwo_m31_add(b43, b8);
    b8 = stwo_m31_mul(b14, b10);
    b43 = stwo_m31_add(b45, b8);
    b8 = stwo_m31_mul(b13, b14);
    b45 = stwo_m31_mul(b40, b40);
    unsigned b46 = stwo_m31_add(b8, b45);
    b45 = stwo_m31_mul(b14, b13);
    b8 = stwo_m31_add(b46, b45);
    b45 = stwo_m31_mul(b40, b14);
    b46 = stwo_m31_mul(b14, b40);
    unsigned b47 = stwo_m31_add(b45, b46);
    b46 = stwo_m31_mul(b14, b14);
    b45 = stwo_m31_mul(b15, b17);
    unsigned b48 = stwo_m31_mul(b0, b16);
    unsigned b49 = stwo_m31_add(b45, b48);
    b48 = stwo_m31_mul(b16, b0);
    b45 = stwo_m31_add(b49, b48);
    b48 = stwo_m31_mul(b17, b15);
    b49 = stwo_m31_add(b45, b48);
    b48 = stwo_m31_mul(b15, b1);
    b45 = stwo_m31_mul(b0, b17);
    unsigned b50 = stwo_m31_add(b48, b45);
    b45 = stwo_m31_mul(b16, b16);
    b48 = stwo_m31_add(b50, b45);
    b45 = stwo_m31_mul(b17, b0);
    b50 = stwo_m31_add(b48, b45);
    b45 = stwo_m31_mul(b1, b15);
    b48 = stwo_m31_add(b50, b45);
    b45 = stwo_m31_mul(b15, b18);
    b50 = stwo_m31_mul(b0, b1);
    unsigned b51 = stwo_m31_add(b45, b50);
    b50 = stwo_m31_mul(b16, b17);
    b45 = stwo_m31_add(b51, b50);
    b50 = stwo_m31_mul(b17, b16);
    b51 = stwo_m31_add(b45, b50);
    b50 = stwo_m31_mul(b1, b0);
    b45 = stwo_m31_add(b51, b50);
    b50 = stwo_m31_mul(b18, b15);
    b51 = stwo_m31_add(b45, b50);
    b50 = stwo_m31_mul(b15, b19);
    b45 = stwo_m31_mul(b0, b18);
    unsigned b52 = stwo_m31_add(b50, b45);
    b45 = stwo_m31_mul(b16, b1);
    b50 = stwo_m31_add(b52, b45);
    b45 = stwo_m31_mul(b17, b17);
    b52 = stwo_m31_add(b50, b45);
    b45 = stwo_m31_mul(b1, b16);
    b50 = stwo_m31_add(b52, b45);
    b45 = stwo_m31_mul(b18, b0);
    b52 = stwo_m31_add(b50, b45);
    b45 = stwo_m31_mul(b19, b15);
    b50 = stwo_m31_add(b52, b45);
    b45 = stwo_m31_mul(b18, b19);
    b52 = stwo_m31_mul(b19, b18);
    unsigned b53 = stwo_m31_add(b45, b52);
    b52 = stwo_m31_mul(b19, b19);
    b45 = stwo_m31_add(b10, b15);
    unsigned b54 = stwo_m31_add(b11, b0);
    unsigned b55 = stwo_m31_add(b39, b16);
    unsigned b56 = stwo_m31_add(b12, b17);
    unsigned b57 = stwo_m31_add(b13, b1);
    unsigned b58 = stwo_m31_add(b40, b18);
    unsigned b59 = stwo_m31_add(b14, b19);
    unsigned b60 = stwo_m31_add(b10, b15);
    b10 = stwo_m31_add(b11, b0);
    b11 = stwo_m31_add(b39, b16);
    b39 = stwo_m31_add(b12, b17);
    b12 = stwo_m31_add(b13, b1);
    b13 = stwo_m31_add(b40, b18);
    unsigned b61 = stwo_m31_add(b14, b19);
    unsigned b62 = stwo_m31_mul(b45, b39);
    unsigned b63 = stwo_m31_mul(b54, b11);
    unsigned b64 = stwo_m31_add(b62, b63);
    b63 = stwo_m31_mul(b55, b10);
    b62 = stwo_m31_add(b64, b63);
    b63 = stwo_m31_mul(b56, b60);
    b64 = stwo_m31_add(b62, b63);
    b63 = stwo_m31_sub(b64, b42);
    b64 = stwo_m31_sub(b63, b49);
    b63 = stwo_m31_add(b8, b64);
    b64 = stwo_m31_mul(b45, b12);
    b8 = stwo_m31_mul(b54, b39);
    b49 = stwo_m31_add(b64, b8);
    b8 = stwo_m31_mul(b55, b11);
    b64 = stwo_m31_add(b49, b8);
    b8 = stwo_m31_mul(b56, b10);
    b49 = stwo_m31_add(b64, b8);
    b8 = stwo_m31_mul(b57, b60);
    b64 = stwo_m31_add(b49, b8);
    b8 = stwo_m31_sub(b64, b41);
    b64 = stwo_m31_sub(b8, b48);
    b8 = stwo_m31_add(b47, b64);
    b64 = stwo_m31_mul(b45, b13);
    b49 = stwo_m31_mul(b54, b12);
    b42 = stwo_m31_add(b64, b49);
    b49 = stwo_m31_mul(b55, b39);
    b64 = stwo_m31_add(b42, b49);
    b49 = stwo_m31_mul(b56, b11);
    b42 = stwo_m31_add(b64, b49);
    b49 = stwo_m31_mul(b57, b10);
    b64 = stwo_m31_add(b42, b49);
    b49 = stwo_m31_mul(b58, b60);
    b42 = stwo_m31_add(b64, b49);
    b49 = stwo_m31_sub(b42, b44);
    b42 = stwo_m31_sub(b49, b51);
    b49 = stwo_m31_add(b46, b42);
    b42 = stwo_m31_mul(b45, b61);
    b45 = stwo_m31_mul(b54, b13);
    b54 = stwo_m31_add(b42, b45);
    b45 = stwo_m31_mul(b55, b12);
    b12 = stwo_m31_add(b54, b45);
    b45 = stwo_m31_mul(b56, b39);
    b39 = stwo_m31_add(b12, b45);
    b45 = stwo_m31_mul(b57, b11);
    b11 = stwo_m31_add(b39, b45);
    b45 = stwo_m31_mul(b58, b10);
    b10 = stwo_m31_add(b11, b45);
    b45 = stwo_m31_mul(b59, b60);
    b60 = stwo_m31_add(b10, b45);
    b45 = stwo_m31_sub(b60, b43);
    b60 = stwo_m31_sub(b45, b50);
    b45 = stwo_m31_mul(b58, b61);
    b58 = stwo_m31_mul(b59, b13);
    b13 = stwo_m31_add(b45, b58);
    b58 = stwo_m31_sub(b13, b47);
    b13 = stwo_m31_sub(b58, b53);
    b58 = stwo_m31_add(b48, b13);
    b13 = stwo_m31_mul(b59, b61);
    b61 = stwo_m31_sub(b13, b46);
    b13 = stwo_m31_sub(b61, b52);
    b61 = stwo_m31_add(b51, b13);
    b13 = stwo_m31_mul(b2, b22);
    b51 = stwo_m31_mul(b20, b3);
    b52 = stwo_m31_add(b13, b51);
    b51 = stwo_m31_mul(b21, b21);
    b13 = stwo_m31_add(b52, b51);
    b51 = stwo_m31_mul(b3, b20);
    b52 = stwo_m31_add(b13, b51);
    b51 = stwo_m31_mul(b22, b2);
    b13 = stwo_m31_add(b52, b51);
    b51 = stwo_m31_mul(b2, b23);
    b52 = stwo_m31_mul(b20, b22);
    b46 = stwo_m31_add(b51, b52);
    b52 = stwo_m31_mul(b21, b3);
    b51 = stwo_m31_add(b46, b52);
    b52 = stwo_m31_mul(b3, b21);
    b46 = stwo_m31_add(b51, b52);
    b52 = stwo_m31_mul(b22, b20);
    b51 = stwo_m31_add(b46, b52);
    b52 = stwo_m31_mul(b23, b2);
    b46 = stwo_m31_add(b51, b52);
    b52 = stwo_m31_mul(b2, b4);
    b51 = stwo_m31_mul(b20, b23);
    b59 = stwo_m31_add(b52, b51);
    b51 = stwo_m31_mul(b21, b22);
    b52 = stwo_m31_add(b59, b51);
    b51 = stwo_m31_mul(b3, b3);
    b3 = stwo_m31_add(b52, b51);
    b51 = stwo_m31_mul(b22, b21);
    b22 = stwo_m31_add(b3, b51);
    b51 = stwo_m31_mul(b23, b20);
    b20 = stwo_m31_add(b22, b51);
    b51 = stwo_m31_mul(b4, b2);
    b2 = stwo_m31_add(b20, b51);
    b51 = stwo_m31_mul(b23, b4);
    b20 = stwo_m31_mul(b4, b23);
    b22 = stwo_m31_add(b51, b20);
    b20 = stwo_m31_mul(b4, b4);
    b51 = stwo_m31_mul(b24, b27);
    b3 = stwo_m31_mul(b25, b26);
    b21 = stwo_m31_add(b51, b3);
    b3 = stwo_m31_mul(b5, b5);
    b51 = stwo_m31_add(b21, b3);
    b3 = stwo_m31_mul(b26, b25);
    b21 = stwo_m31_add(b51, b3);
    b3 = stwo_m31_mul(b27, b24);
    b51 = stwo_m31_add(b21, b3);
    b3 = stwo_m31_mul(b24, b6);
    b21 = stwo_m31_mul(b25, b27);
    b52 = stwo_m31_add(b3, b21);
    b21 = stwo_m31_mul(b5, b26);
    b3 = stwo_m31_add(b52, b21);
    b21 = stwo_m31_mul(b26, b5);
    b52 = stwo_m31_add(b3, b21);
    b21 = stwo_m31_mul(b27, b25);
    b3 = stwo_m31_add(b52, b21);
    b21 = stwo_m31_mul(b6, b24);
    b52 = stwo_m31_add(b3, b21);
    b21 = stwo_m31_mul(b24, b9);
    b3 = stwo_m31_mul(b25, b6);
    b59 = stwo_m31_add(b21, b3);
    b3 = stwo_m31_mul(b5, b27);
    b21 = stwo_m31_add(b59, b3);
    b3 = stwo_m31_mul(b26, b26);
    b59 = stwo_m31_add(b21, b3);
    b3 = stwo_m31_mul(b27, b5);
    b21 = stwo_m31_add(b59, b3);
    b3 = stwo_m31_mul(b6, b25);
    b59 = stwo_m31_add(b21, b3);
    b3 = stwo_m31_mul(b9, b24);
    b21 = stwo_m31_add(b59, b3);
    b3 = stwo_m31_mul(b6, b9);
    b59 = stwo_m31_mul(b9, b6);
    b48 = stwo_m31_add(b3, b59);
    b59 = stwo_m31_mul(b9, b9);
    b3 = stwo_m31_add(b23, b6);
    b53 = stwo_m31_add(b4, b9);
    b47 = stwo_m31_add(b23, b6);
    b45 = stwo_m31_add(b4, b9);
    b10 = stwo_m31_mul(b3, b45);
    b3 = stwo_m31_mul(b53, b47);
    b47 = stwo_m31_add(b10, b3);
    b3 = stwo_m31_sub(b47, b22);
    b47 = stwo_m31_sub(b3, b48);
    b3 = stwo_m31_add(b51, b47);
    b47 = stwo_m31_mul(b53, b45);
    b45 = stwo_m31_sub(b47, b20);
    b47 = stwo_m31_sub(b45, b59);
    b45 = stwo_m31_add(b52, b47);
    b47 = stwo_m31_add(b40, b23);
    b52 = stwo_m31_add(b14, b4);
    b59 = stwo_m31_add(b15, b24);
    b20 = stwo_m31_add(b0, b25);
    b53 = stwo_m31_add(b16, b5);
    b51 = stwo_m31_add(b17, b26);
    b48 = stwo_m31_add(b1, b27);
    b22 = stwo_m31_add(b18, b6);
    b10 = stwo_m31_add(b19, b9);
    b11 = stwo_m31_add(b40, b23);
    b40 = stwo_m31_add(b14, b4);
    b4 = stwo_m31_add(b15, b24);
    b24 = stwo_m31_add(b0, b25);
    b0 = stwo_m31_add(b16, b5);
    b5 = stwo_m31_add(b17, b26);
    b26 = stwo_m31_add(b1, b27);
    b1 = stwo_m31_add(b18, b6);
    b6 = stwo_m31_add(b19, b9);
    b19 = stwo_m31_mul(b47, b40);
    b9 = stwo_m31_mul(b52, b11);
    b18 = stwo_m31_add(b19, b9);
    b9 = stwo_m31_mul(b52, b40);
    b19 = stwo_m31_mul(b59, b26);
    b27 = stwo_m31_mul(b20, b5);
    b17 = stwo_m31_add(b19, b27);
    b27 = stwo_m31_mul(b53, b0);
    b19 = stwo_m31_add(b17, b27);
    b27 = stwo_m31_mul(b51, b24);
    b17 = stwo_m31_add(b19, b27);
    b27 = stwo_m31_mul(b48, b4);
    b19 = stwo_m31_add(b17, b27);
    b27 = stwo_m31_mul(b59, b1);
    b17 = stwo_m31_mul(b20, b26);
    b16 = stwo_m31_add(b27, b17);
    b17 = stwo_m31_mul(b53, b5);
    b27 = stwo_m31_add(b16, b17);
    b17 = stwo_m31_mul(b51, b0);
    b16 = stwo_m31_add(b27, b17);
    b17 = stwo_m31_mul(b48, b24);
    b27 = stwo_m31_add(b16, b17);
    b17 = stwo_m31_mul(b22, b4);
    b16 = stwo_m31_add(b27, b17);
    b17 = stwo_m31_mul(b59, b6);
    b59 = stwo_m31_mul(b20, b1);
    b20 = stwo_m31_add(b17, b59);
    b59 = stwo_m31_mul(b53, b26);
    b26 = stwo_m31_add(b20, b59);
    b59 = stwo_m31_mul(b51, b5);
    b5 = stwo_m31_add(b26, b59);
    b59 = stwo_m31_mul(b48, b0);
    b0 = stwo_m31_add(b5, b59);
    b59 = stwo_m31_mul(b22, b24);
    b24 = stwo_m31_add(b0, b59);
    b59 = stwo_m31_mul(b10, b4);
    b4 = stwo_m31_add(b24, b59);
    b59 = stwo_m31_mul(b22, b6);
    b24 = stwo_m31_mul(b10, b1);
    b0 = stwo_m31_add(b59, b24);
    b24 = stwo_m31_mul(b10, b6);
    b59 = stwo_m31_add(b47, b22);
    b22 = stwo_m31_add(b52, b10);
    b10 = stwo_m31_add(b11, b1);
    b1 = stwo_m31_add(b40, b6);
    b6 = stwo_m31_mul(b59, b1);
    b59 = stwo_m31_mul(b22, b10);
    b10 = stwo_m31_add(b6, b59);
    b59 = stwo_m31_sub(b10, b18);
    b10 = stwo_m31_sub(b59, b0);
    b59 = stwo_m31_add(b19, b10);
    b10 = stwo_m31_mul(b22, b1);
    b1 = stwo_m31_sub(b10, b9);
    b10 = stwo_m31_sub(b1, b24);
    b1 = stwo_m31_add(b16, b10);
    b10 = stwo_m31_sub(b59, b58);
    b59 = stwo_m31_sub(b10, b3);
    b10 = stwo_m31_add(b13, b59);
    b59 = stwo_m31_sub(b1, b61);
    b1 = stwo_m31_sub(b59, b45);
    b59 = stwo_m31_add(b46, b1);
    b1 = stwo_m31_sub(b4, b50);
    b4 = stwo_m31_sub(b1, b21);
    b1 = stwo_m31_add(b2, b4);
    b4 = stwo_m31_sub(b41, b28);
    b41 = stwo_m31_sub(b44, b29);
    b44 = stwo_m31_sub(b43, b30);
    b43 = stwo_m31_sub(b63, b31);
    b63 = stwo_m31_sub(b8, b32);
    b8 = stwo_m31_sub(b49, b33);
    b49 = stwo_m31_sub(b60, b34);
    b60 = 2u;
    b34 = stwo_m31_mul(b60, b4);
    b60 = stwo_m31_add(b34, b43);
    b34 = 32u;
    b43 = stwo_m31_mul(b34, b63);
    b34 = stwo_m31_add(b60, b43);
    b43 = 4u;
    b60 = stwo_m31_mul(b43, b10);
    b43 = stwo_m31_sub(b34, b60);
    b60 = 2u;
    b34 = stwo_m31_mul(b60, b41);
    b60 = stwo_m31_add(b34, b63);
    b34 = 32u;
    b63 = stwo_m31_mul(b34, b8);
    b34 = stwo_m31_add(b60, b63);
    b63 = 4u;
    b60 = stwo_m31_mul(b63, b59);
    b63 = stwo_m31_sub(b34, b60);
    b60 = 2u;
    b34 = stwo_m31_mul(b60, b44);
    b60 = stwo_m31_add(b34, b8);
    b34 = 32u;
    b8 = stwo_m31_mul(b34, b49);
    b34 = stwo_m31_add(b60, b8);
    b8 = 4u;
    b60 = stwo_m31_mul(b8, b1);
    b8 = stwo_m31_sub(b34, b60);
    b60 = 512u;
    b34 = stwo_m31_mul(b36, b60);
    b60 = stwo_m31_add(b43, b35);
    b43 = stwo_m31_sub(b34, b60);
    b60 = 512u;
    b34 = stwo_m31_mul(b37, b60);
    b60 = stwo_m31_add(b63, b36);
    b63 = stwo_m31_sub(b34, b60);
    b60 = 512u;
    b34 = stwo_m31_mul(b38, b60);
    b60 = stwo_m31_add(b8, b37);
    b8 = stwo_m31_sub(b34, b60);
    StwoCairoQm31 e0 = { b43, b7, b7, b7 };
    StwoCairoQm31 e1 = { b63, b7, b7, b7 };
    StwoCairoQm31 e2 = { b8, b7, b7, b7 };
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
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
