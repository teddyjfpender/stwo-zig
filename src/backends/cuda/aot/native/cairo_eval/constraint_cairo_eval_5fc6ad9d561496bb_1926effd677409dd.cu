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
stwo_cairo_cuda_eval_v1_90c09d84311526c6(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 25u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 47u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 48u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 49u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 51u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 52u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 53u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 54u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 55u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 58u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 59u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 60u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 61u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 62u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 63u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 64u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 65u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 66u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 67u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 71u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 117u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 118u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 119u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 120u, row, 0);
    unsigned b67 = 0u;
    unsigned b68 = stwo_m31_mul(b7, b36);
    unsigned b69 = stwo_m31_mul(b8, b35);
    unsigned b70 = stwo_m31_add(b68, b69);
    b69 = stwo_m31_mul(b7, b37);
    b68 = stwo_m31_mul(b8, b36);
    unsigned b71 = stwo_m31_add(b69, b68);
    b68 = stwo_m31_mul(b9, b35);
    b69 = stwo_m31_add(b71, b68);
    b68 = stwo_m31_mul(b7, b38);
    b71 = stwo_m31_mul(b8, b37);
    unsigned b72 = stwo_m31_add(b68, b71);
    b71 = stwo_m31_mul(b9, b36);
    b68 = stwo_m31_add(b72, b71);
    b71 = stwo_m31_mul(b10, b35);
    b72 = stwo_m31_add(b68, b71);
    b71 = stwo_m31_mul(b7, b39);
    b68 = stwo_m31_mul(b8, b38);
    unsigned b73 = stwo_m31_add(b71, b68);
    b68 = stwo_m31_mul(b9, b37);
    b71 = stwo_m31_add(b73, b68);
    b68 = stwo_m31_mul(b10, b36);
    b73 = stwo_m31_add(b71, b68);
    b68 = stwo_m31_mul(b11, b35);
    b71 = stwo_m31_add(b73, b68);
    b68 = stwo_m31_mul(b9, b41);
    b73 = stwo_m31_mul(b10, b40);
    unsigned b74 = stwo_m31_add(b68, b73);
    b73 = stwo_m31_mul(b11, b39);
    b68 = stwo_m31_add(b74, b73);
    b73 = stwo_m31_mul(b12, b38);
    b74 = stwo_m31_add(b68, b73);
    b73 = stwo_m31_mul(b13, b37);
    b68 = stwo_m31_add(b74, b73);
    b73 = stwo_m31_mul(b10, b41);
    b74 = stwo_m31_mul(b11, b40);
    unsigned b75 = stwo_m31_add(b73, b74);
    b74 = stwo_m31_mul(b12, b39);
    b73 = stwo_m31_add(b75, b74);
    b74 = stwo_m31_mul(b13, b38);
    b75 = stwo_m31_add(b73, b74);
    b74 = stwo_m31_mul(b11, b41);
    b73 = stwo_m31_mul(b12, b40);
    unsigned b76 = stwo_m31_add(b74, b73);
    b73 = stwo_m31_mul(b13, b39);
    b74 = stwo_m31_add(b76, b73);
    b73 = stwo_m31_mul(b12, b41);
    b76 = stwo_m31_mul(b13, b40);
    unsigned b77 = stwo_m31_add(b73, b76);
    b76 = stwo_m31_mul(b14, b43);
    b73 = stwo_m31_mul(b15, b42);
    unsigned b78 = stwo_m31_add(b76, b73);
    b73 = stwo_m31_mul(b14, b44);
    b76 = stwo_m31_mul(b15, b43);
    unsigned b79 = stwo_m31_add(b73, b76);
    b76 = stwo_m31_mul(b16, b42);
    b73 = stwo_m31_add(b79, b76);
    b76 = stwo_m31_mul(b14, b45);
    b79 = stwo_m31_mul(b15, b44);
    unsigned b80 = stwo_m31_add(b76, b79);
    b79 = stwo_m31_mul(b16, b43);
    b76 = stwo_m31_add(b80, b79);
    b79 = stwo_m31_mul(b17, b42);
    b80 = stwo_m31_add(b76, b79);
    b79 = stwo_m31_mul(b14, b46);
    b76 = stwo_m31_mul(b15, b45);
    unsigned b81 = stwo_m31_add(b79, b76);
    b76 = stwo_m31_mul(b16, b44);
    b79 = stwo_m31_add(b81, b76);
    b76 = stwo_m31_mul(b17, b43);
    b81 = stwo_m31_add(b79, b76);
    b76 = stwo_m31_mul(b18, b42);
    b79 = stwo_m31_add(b81, b76);
    b76 = stwo_m31_mul(b16, b48);
    b81 = stwo_m31_mul(b17, b47);
    unsigned b82 = stwo_m31_add(b76, b81);
    b81 = stwo_m31_mul(b18, b46);
    b76 = stwo_m31_add(b82, b81);
    b81 = stwo_m31_mul(b19, b45);
    b82 = stwo_m31_add(b76, b81);
    b81 = stwo_m31_mul(b20, b44);
    b76 = stwo_m31_add(b82, b81);
    b81 = stwo_m31_mul(b17, b48);
    b82 = stwo_m31_mul(b18, b47);
    unsigned b83 = stwo_m31_add(b81, b82);
    b82 = stwo_m31_mul(b19, b46);
    b81 = stwo_m31_add(b83, b82);
    b82 = stwo_m31_mul(b20, b45);
    b83 = stwo_m31_add(b81, b82);
    b82 = stwo_m31_mul(b18, b48);
    b81 = stwo_m31_mul(b19, b47);
    unsigned b84 = stwo_m31_add(b82, b81);
    b81 = stwo_m31_mul(b20, b46);
    b82 = stwo_m31_add(b84, b81);
    b81 = stwo_m31_mul(b19, b48);
    b84 = stwo_m31_mul(b20, b47);
    unsigned b85 = stwo_m31_add(b81, b84);
    b84 = stwo_m31_add(b7, b14);
    b14 = stwo_m31_add(b8, b15);
    b15 = stwo_m31_add(b9, b16);
    b16 = stwo_m31_add(b10, b17);
    b81 = stwo_m31_add(b11, b18);
    unsigned b86 = stwo_m31_add(b12, b19);
    b12 = stwo_m31_add(b13, b20);
    b13 = stwo_m31_add(b35, b42);
    b42 = stwo_m31_add(b36, b43);
    b43 = stwo_m31_add(b37, b44);
    b44 = stwo_m31_add(b38, b45);
    unsigned b87 = stwo_m31_add(b39, b46);
    unsigned b88 = stwo_m31_add(b40, b47);
    b40 = stwo_m31_add(b41, b48);
    b41 = stwo_m31_mul(b84, b43);
    unsigned b89 = stwo_m31_mul(b14, b42);
    unsigned b90 = stwo_m31_add(b41, b89);
    b89 = stwo_m31_mul(b15, b13);
    b41 = stwo_m31_add(b90, b89);
    b89 = stwo_m31_sub(b41, b69);
    b41 = stwo_m31_sub(b89, b73);
    b89 = stwo_m31_add(b75, b41);
    b41 = stwo_m31_mul(b84, b44);
    b90 = stwo_m31_mul(b14, b43);
    unsigned b91 = stwo_m31_add(b41, b90);
    b90 = stwo_m31_mul(b15, b42);
    b41 = stwo_m31_add(b91, b90);
    b90 = stwo_m31_mul(b16, b13);
    b91 = stwo_m31_add(b41, b90);
    b90 = stwo_m31_sub(b91, b72);
    b91 = stwo_m31_sub(b90, b80);
    b90 = stwo_m31_add(b74, b91);
    b91 = stwo_m31_mul(b84, b87);
    b84 = stwo_m31_mul(b14, b44);
    b14 = stwo_m31_add(b91, b84);
    b84 = stwo_m31_mul(b15, b43);
    b91 = stwo_m31_add(b14, b84);
    b84 = stwo_m31_mul(b16, b42);
    b42 = stwo_m31_add(b91, b84);
    b84 = stwo_m31_mul(b81, b13);
    b13 = stwo_m31_add(b42, b84);
    b84 = stwo_m31_sub(b13, b71);
    b13 = stwo_m31_sub(b84, b79);
    b84 = stwo_m31_add(b77, b13);
    b13 = stwo_m31_mul(b15, b40);
    b15 = stwo_m31_mul(b16, b88);
    b42 = stwo_m31_add(b13, b15);
    b15 = stwo_m31_mul(b81, b87);
    b13 = stwo_m31_add(b42, b15);
    b15 = stwo_m31_mul(b86, b44);
    b42 = stwo_m31_add(b13, b15);
    b15 = stwo_m31_mul(b12, b43);
    b43 = stwo_m31_add(b42, b15);
    b15 = stwo_m31_sub(b43, b68);
    b43 = stwo_m31_sub(b15, b76);
    b15 = stwo_m31_add(b78, b43);
    b43 = stwo_m31_mul(b16, b40);
    b16 = stwo_m31_mul(b81, b88);
    b78 = stwo_m31_add(b43, b16);
    b16 = stwo_m31_mul(b86, b87);
    b43 = stwo_m31_add(b78, b16);
    b16 = stwo_m31_mul(b12, b44);
    b44 = stwo_m31_add(b43, b16);
    b16 = stwo_m31_sub(b44, b75);
    b44 = stwo_m31_sub(b16, b83);
    b16 = stwo_m31_add(b73, b44);
    b44 = stwo_m31_mul(b81, b40);
    b81 = stwo_m31_mul(b86, b88);
    b73 = stwo_m31_add(b44, b81);
    b81 = stwo_m31_mul(b12, b87);
    b87 = stwo_m31_add(b73, b81);
    b81 = stwo_m31_sub(b87, b74);
    b87 = stwo_m31_sub(b81, b82);
    b81 = stwo_m31_add(b80, b87);
    b87 = stwo_m31_mul(b86, b40);
    b40 = stwo_m31_mul(b12, b88);
    b88 = stwo_m31_add(b87, b40);
    b40 = stwo_m31_sub(b88, b77);
    b88 = stwo_m31_sub(b40, b85);
    b40 = stwo_m31_add(b79, b88);
    b88 = stwo_m31_mul(b21, b50);
    b79 = stwo_m31_mul(b22, b49);
    b77 = stwo_m31_add(b88, b79);
    b79 = stwo_m31_mul(b21, b51);
    b88 = stwo_m31_mul(b22, b50);
    b87 = stwo_m31_add(b79, b88);
    b88 = stwo_m31_mul(b23, b49);
    b79 = stwo_m31_add(b87, b88);
    b88 = stwo_m31_mul(b21, b52);
    b87 = stwo_m31_mul(b22, b51);
    b12 = stwo_m31_add(b88, b87);
    b87 = stwo_m31_mul(b23, b50);
    b88 = stwo_m31_add(b12, b87);
    b87 = stwo_m31_mul(b24, b49);
    b12 = stwo_m31_add(b88, b87);
    b87 = stwo_m31_mul(b21, b53);
    b88 = stwo_m31_mul(b22, b52);
    b86 = stwo_m31_add(b87, b88);
    b88 = stwo_m31_mul(b23, b51);
    b87 = stwo_m31_add(b86, b88);
    b88 = stwo_m31_mul(b24, b50);
    b86 = stwo_m31_add(b87, b88);
    b88 = stwo_m31_mul(b25, b49);
    b87 = stwo_m31_add(b86, b88);
    b88 = stwo_m31_mul(b24, b55);
    b86 = stwo_m31_mul(b25, b54);
    b80 = stwo_m31_add(b88, b86);
    b86 = stwo_m31_mul(b26, b53);
    b88 = stwo_m31_add(b80, b86);
    b86 = stwo_m31_mul(b27, b52);
    b80 = stwo_m31_add(b88, b86);
    b86 = stwo_m31_mul(b25, b55);
    b88 = stwo_m31_mul(b26, b54);
    b74 = stwo_m31_add(b86, b88);
    b88 = stwo_m31_mul(b27, b53);
    b86 = stwo_m31_add(b74, b88);
    b88 = stwo_m31_mul(b26, b55);
    b55 = stwo_m31_mul(b27, b54);
    b54 = stwo_m31_add(b88, b55);
    b55 = stwo_m31_mul(b28, b58);
    b88 = stwo_m31_mul(b29, b57);
    b27 = stwo_m31_add(b55, b88);
    b88 = stwo_m31_mul(b30, b56);
    b55 = stwo_m31_add(b27, b88);
    b88 = stwo_m31_mul(b28, b59);
    b27 = stwo_m31_mul(b29, b58);
    b26 = stwo_m31_add(b88, b27);
    b27 = stwo_m31_mul(b30, b57);
    b88 = stwo_m31_add(b26, b27);
    b27 = stwo_m31_mul(b31, b56);
    b26 = stwo_m31_add(b88, b27);
    b27 = stwo_m31_mul(b28, b60);
    b88 = stwo_m31_mul(b29, b59);
    b74 = stwo_m31_add(b27, b88);
    b88 = stwo_m31_mul(b30, b58);
    b27 = stwo_m31_add(b74, b88);
    b88 = stwo_m31_mul(b31, b57);
    b74 = stwo_m31_add(b27, b88);
    b88 = stwo_m31_mul(b32, b56);
    b27 = stwo_m31_add(b74, b88);
    b88 = stwo_m31_mul(b31, b62);
    b74 = stwo_m31_mul(b32, b61);
    b73 = stwo_m31_add(b88, b74);
    b74 = stwo_m31_mul(b33, b60);
    b88 = stwo_m31_add(b73, b74);
    b74 = stwo_m31_mul(b34, b59);
    b73 = stwo_m31_add(b88, b74);
    b74 = stwo_m31_mul(b32, b62);
    b88 = stwo_m31_mul(b33, b61);
    b44 = stwo_m31_add(b74, b88);
    b88 = stwo_m31_mul(b34, b60);
    b74 = stwo_m31_add(b44, b88);
    b88 = stwo_m31_mul(b33, b62);
    b44 = stwo_m31_mul(b34, b61);
    b75 = stwo_m31_add(b88, b44);
    b44 = stwo_m31_add(b21, b28);
    b28 = stwo_m31_add(b22, b29);
    b29 = stwo_m31_add(b23, b30);
    b30 = stwo_m31_add(b24, b31);
    b88 = stwo_m31_add(b25, b32);
    b43 = stwo_m31_add(b49, b56);
    b56 = stwo_m31_add(b50, b57);
    b57 = stwo_m31_add(b51, b58);
    b58 = stwo_m31_add(b52, b59);
    b78 = stwo_m31_add(b53, b60);
    b76 = stwo_m31_mul(b44, b57);
    b68 = stwo_m31_mul(b28, b56);
    b42 = stwo_m31_add(b76, b68);
    b68 = stwo_m31_mul(b29, b43);
    b76 = stwo_m31_add(b42, b68);
    b68 = stwo_m31_sub(b76, b79);
    b76 = stwo_m31_sub(b68, b55);
    b68 = stwo_m31_add(b80, b76);
    b76 = stwo_m31_mul(b44, b58);
    b80 = stwo_m31_mul(b28, b57);
    b55 = stwo_m31_add(b76, b80);
    b80 = stwo_m31_mul(b29, b56);
    b76 = stwo_m31_add(b55, b80);
    b80 = stwo_m31_mul(b30, b43);
    b55 = stwo_m31_add(b76, b80);
    b80 = stwo_m31_sub(b55, b12);
    b55 = stwo_m31_sub(b80, b26);
    b80 = stwo_m31_add(b86, b55);
    b55 = stwo_m31_mul(b44, b78);
    b78 = stwo_m31_mul(b28, b58);
    b58 = stwo_m31_add(b55, b78);
    b78 = stwo_m31_mul(b29, b57);
    b57 = stwo_m31_add(b58, b78);
    b78 = stwo_m31_mul(b30, b56);
    b56 = stwo_m31_add(b57, b78);
    b78 = stwo_m31_mul(b88, b43);
    b43 = stwo_m31_add(b56, b78);
    b78 = stwo_m31_sub(b43, b87);
    b43 = stwo_m31_sub(b78, b27);
    b78 = stwo_m31_add(b54, b43);
    b43 = stwo_m31_add(b7, b21);
    b21 = stwo_m31_add(b8, b22);
    b22 = stwo_m31_add(b9, b23);
    b23 = stwo_m31_add(b10, b24);
    b24 = stwo_m31_add(b11, b25);
    b25 = stwo_m31_add(b17, b31);
    b31 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_add(b19, b33);
    b33 = stwo_m31_add(b20, b34);
    b34 = stwo_m31_add(b35, b49);
    b49 = stwo_m31_add(b36, b50);
    b50 = stwo_m31_add(b37, b51);
    b51 = stwo_m31_add(b38, b52);
    b52 = stwo_m31_add(b39, b53);
    b53 = stwo_m31_add(b45, b59);
    b59 = stwo_m31_add(b46, b60);
    b60 = stwo_m31_add(b47, b61);
    b61 = stwo_m31_add(b48, b62);
    b62 = stwo_m31_mul(b43, b49);
    b48 = stwo_m31_mul(b21, b34);
    b47 = stwo_m31_add(b62, b48);
    b48 = stwo_m31_mul(b43, b50);
    b62 = stwo_m31_mul(b21, b49);
    b46 = stwo_m31_add(b48, b62);
    b62 = stwo_m31_mul(b22, b34);
    b48 = stwo_m31_add(b46, b62);
    b62 = stwo_m31_mul(b43, b51);
    b46 = stwo_m31_mul(b21, b50);
    b45 = stwo_m31_add(b62, b46);
    b46 = stwo_m31_mul(b22, b49);
    b62 = stwo_m31_add(b45, b46);
    b46 = stwo_m31_mul(b23, b34);
    b45 = stwo_m31_add(b62, b46);
    b46 = stwo_m31_mul(b43, b52);
    b52 = stwo_m31_mul(b21, b51);
    b51 = stwo_m31_add(b46, b52);
    b52 = stwo_m31_mul(b22, b50);
    b50 = stwo_m31_add(b51, b52);
    b52 = stwo_m31_mul(b23, b49);
    b49 = stwo_m31_add(b50, b52);
    b52 = stwo_m31_mul(b24, b34);
    b34 = stwo_m31_add(b49, b52);
    b52 = stwo_m31_mul(b25, b61);
    b25 = stwo_m31_mul(b31, b60);
    b49 = stwo_m31_add(b52, b25);
    b25 = stwo_m31_mul(b32, b59);
    b52 = stwo_m31_add(b49, b25);
    b25 = stwo_m31_mul(b33, b53);
    b53 = stwo_m31_add(b52, b25);
    b25 = stwo_m31_mul(b31, b61);
    b31 = stwo_m31_mul(b32, b60);
    b52 = stwo_m31_add(b25, b31);
    b31 = stwo_m31_mul(b33, b59);
    b59 = stwo_m31_add(b52, b31);
    b31 = stwo_m31_mul(b32, b61);
    b61 = stwo_m31_mul(b33, b60);
    b60 = stwo_m31_add(b31, b61);
    b61 = stwo_m31_sub(b47, b70);
    b47 = stwo_m31_sub(b61, b77);
    b61 = stwo_m31_add(b15, b47);
    b47 = stwo_m31_sub(b48, b69);
    b48 = stwo_m31_sub(b47, b79);
    b47 = stwo_m31_add(b16, b48);
    b48 = stwo_m31_sub(b45, b72);
    b45 = stwo_m31_sub(b48, b12);
    b48 = stwo_m31_add(b81, b45);
    b45 = stwo_m31_sub(b34, b71);
    b34 = stwo_m31_sub(b45, b87);
    b45 = stwo_m31_add(b40, b34);
    b34 = stwo_m31_sub(b53, b83);
    b53 = stwo_m31_sub(b34, b73);
    b34 = stwo_m31_add(b68, b53);
    b53 = stwo_m31_sub(b59, b82);
    b59 = stwo_m31_sub(b53, b74);
    b53 = stwo_m31_add(b80, b59);
    b59 = stwo_m31_sub(b60, b85);
    b60 = stwo_m31_sub(b59, b75);
    b59 = stwo_m31_add(b78, b60);
    b60 = stwo_m31_sub(b89, b0);
    b89 = stwo_m31_sub(b90, b1);
    b90 = stwo_m31_sub(b84, b2);
    b84 = stwo_m31_sub(b61, b3);
    b61 = stwo_m31_sub(b47, b4);
    b47 = stwo_m31_sub(b48, b5);
    b48 = stwo_m31_sub(b45, b6);
    b45 = 2u;
    b6 = stwo_m31_mul(b45, b60);
    b45 = stwo_m31_add(b6, b84);
    b6 = 32u;
    b84 = stwo_m31_mul(b6, b61);
    b6 = stwo_m31_add(b45, b84);
    b84 = 4u;
    b45 = stwo_m31_mul(b84, b34);
    b84 = stwo_m31_sub(b6, b45);
    b45 = 2u;
    b6 = stwo_m31_mul(b45, b89);
    b45 = stwo_m31_add(b6, b61);
    b6 = 32u;
    b61 = stwo_m31_mul(b6, b47);
    b6 = stwo_m31_add(b45, b61);
    b61 = 4u;
    b45 = stwo_m31_mul(b61, b53);
    b61 = stwo_m31_sub(b6, b45);
    b45 = 2u;
    b6 = stwo_m31_mul(b45, b90);
    b45 = stwo_m31_add(b6, b47);
    b6 = 32u;
    b47 = stwo_m31_mul(b6, b48);
    b6 = stwo_m31_add(b45, b47);
    b47 = 4u;
    b45 = stwo_m31_mul(b47, b59);
    b47 = stwo_m31_sub(b6, b45);
    b45 = 512u;
    b6 = stwo_m31_mul(b64, b45);
    b45 = stwo_m31_add(b84, b63);
    b84 = stwo_m31_sub(b6, b45);
    b45 = 512u;
    b6 = stwo_m31_mul(b65, b45);
    b45 = stwo_m31_add(b61, b64);
    b61 = stwo_m31_sub(b6, b45);
    b45 = 512u;
    b6 = stwo_m31_mul(b66, b45);
    b45 = stwo_m31_add(b47, b65);
    b47 = stwo_m31_sub(b6, b45);
    StwoCairoQm31 e0 = { b84, b67, b67, b67 };
    StwoCairoQm31 e1 = { b61, b67, b67, b67 };
    StwoCairoQm31 e2 = { b47, b67, b67, b67 };
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
