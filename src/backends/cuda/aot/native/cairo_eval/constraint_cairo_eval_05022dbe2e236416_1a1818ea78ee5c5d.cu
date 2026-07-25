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
stwo_cairo_cuda_eval_v1_0494595f65917837(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 71u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 114u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 115u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 116u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 156u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 157u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 158u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 159u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 160u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 161u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 162u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 163u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 164u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 165u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 166u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 167u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 168u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 169u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 170u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 171u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 172u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 173u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 202u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 203u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 204u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 205u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 206u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 207u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 208u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 209u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 210u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 211u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 212u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 213u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 214u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 215u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 216u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 217u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 218u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 219u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 220u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 221u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 222u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 223u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 224u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 225u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 226u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 1u, 227u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 1u, 228u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 1u, 229u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 1u, 276u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 1u, 277u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 1u, 278u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 1u, 286u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 1u, 311u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 1u, 312u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 1u, 313u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 1u, 314u, row, 0);
    unsigned b96 = stwo_trace_value(arena, *args, 1u, 315u, row, 0);
    unsigned b97 = stwo_trace_value(arena, *args, 1u, 316u, row, 0);
    unsigned b98 = stwo_trace_value(arena, *args, 1u, 317u, row, 0);
    unsigned b99 = stwo_trace_value(arena, *args, 1u, 318u, row, 0);
    unsigned b100 = stwo_trace_value(arena, *args, 1u, 319u, row, 0);
    unsigned b101 = stwo_trace_value(arena, *args, 1u, 320u, row, 0);
    unsigned b102 = stwo_trace_value(arena, *args, 1u, 321u, row, 0);
    unsigned b103 = stwo_trace_value(arena, *args, 1u, 322u, row, 0);
    unsigned b104 = stwo_trace_value(arena, *args, 1u, 323u, row, 0);
    unsigned b105 = stwo_trace_value(arena, *args, 1u, 324u, row, 0);
    unsigned b106 = stwo_trace_value(arena, *args, 1u, 325u, row, 0);
    unsigned b107 = stwo_trace_value(arena, *args, 1u, 326u, row, 0);
    unsigned b108 = stwo_trace_value(arena, *args, 1u, 327u, row, 0);
    unsigned b109 = stwo_trace_value(arena, *args, 1u, 328u, row, 0);
    unsigned b110 = stwo_trace_value(arena, *args, 1u, 329u, row, 0);
    unsigned b111 = 0u;
    unsigned b112 = stwo_m31_sub(b0, b60);
    unsigned b113 = stwo_m31_sub(b1, b61);
    unsigned b114 = stwo_m31_sub(b2, b62);
    unsigned b115 = stwo_m31_sub(b3, b63);
    unsigned b116 = stwo_m31_sub(b4, b64);
    unsigned b117 = stwo_m31_sub(b5, b65);
    unsigned b118 = stwo_m31_sub(b6, b66);
    unsigned b119 = stwo_m31_sub(b7, b67);
    unsigned b120 = stwo_m31_sub(b8, b68);
    unsigned b121 = stwo_m31_sub(b9, b69);
    unsigned b122 = stwo_m31_sub(b10, b70);
    unsigned b123 = stwo_m31_sub(b11, b71);
    unsigned b124 = stwo_m31_sub(b12, b72);
    unsigned b125 = stwo_m31_sub(b13, b73);
    unsigned b126 = stwo_m31_sub(b14, b74);
    unsigned b127 = stwo_m31_sub(b15, b75);
    unsigned b128 = stwo_m31_sub(b16, b76);
    b76 = stwo_m31_sub(b17, b77);
    b77 = stwo_m31_sub(b18, b78);
    b78 = stwo_m31_sub(b19, b79);
    b79 = stwo_m31_sub(b20, b80);
    b80 = stwo_m31_sub(b21, b81);
    b81 = stwo_m31_sub(b22, b82);
    b82 = stwo_m31_sub(b23, b83);
    b83 = stwo_m31_sub(b24, b84);
    b84 = stwo_m31_sub(b25, b85);
    b85 = stwo_m31_sub(b26, b86);
    b86 = stwo_m31_sub(b27, b87);
    b87 = stwo_m31_add(b28, b88);
    b88 = stwo_m31_add(b29, b89);
    b89 = stwo_m31_add(b30, b90);
    b90 = stwo_m31_mul(b32, b116);
    b30 = stwo_m31_mul(b33, b115);
    b29 = stwo_m31_add(b90, b30);
    b30 = stwo_m31_mul(b34, b114);
    b90 = stwo_m31_add(b29, b30);
    b30 = stwo_m31_mul(b35, b113);
    b29 = stwo_m31_add(b90, b30);
    b30 = stwo_m31_mul(b36, b112);
    b90 = stwo_m31_add(b29, b30);
    b30 = stwo_m31_mul(b32, b117);
    b29 = stwo_m31_mul(b33, b116);
    b28 = stwo_m31_add(b30, b29);
    b29 = stwo_m31_mul(b34, b115);
    b30 = stwo_m31_add(b28, b29);
    b29 = stwo_m31_mul(b35, b114);
    b28 = stwo_m31_add(b30, b29);
    b29 = stwo_m31_mul(b36, b113);
    b30 = stwo_m31_add(b28, b29);
    b29 = stwo_m31_mul(b37, b112);
    b28 = stwo_m31_add(b30, b29);
    b29 = stwo_m31_mul(b32, b118);
    b30 = stwo_m31_mul(b33, b117);
    b27 = stwo_m31_add(b29, b30);
    b30 = stwo_m31_mul(b34, b116);
    b29 = stwo_m31_add(b27, b30);
    b30 = stwo_m31_mul(b35, b115);
    b27 = stwo_m31_add(b29, b30);
    b30 = stwo_m31_mul(b36, b114);
    b29 = stwo_m31_add(b27, b30);
    b30 = stwo_m31_mul(b37, b113);
    b27 = stwo_m31_add(b29, b30);
    b30 = stwo_m31_mul(b38, b112);
    b29 = stwo_m31_add(b27, b30);
    b30 = stwo_m31_mul(b37, b118);
    b27 = stwo_m31_mul(b38, b117);
    b26 = stwo_m31_add(b30, b27);
    b27 = stwo_m31_mul(b38, b118);
    b30 = stwo_m31_mul(b39, b123);
    b25 = stwo_m31_mul(b40, b122);
    b24 = stwo_m31_add(b30, b25);
    b25 = stwo_m31_mul(b41, b121);
    b30 = stwo_m31_add(b24, b25);
    b25 = stwo_m31_mul(b42, b120);
    b24 = stwo_m31_add(b30, b25);
    b25 = stwo_m31_mul(b43, b119);
    b30 = stwo_m31_add(b24, b25);
    b25 = stwo_m31_mul(b39, b124);
    b24 = stwo_m31_mul(b40, b123);
    b23 = stwo_m31_add(b25, b24);
    b24 = stwo_m31_mul(b41, b122);
    b25 = stwo_m31_add(b23, b24);
    b24 = stwo_m31_mul(b42, b121);
    b23 = stwo_m31_add(b25, b24);
    b24 = stwo_m31_mul(b43, b120);
    b25 = stwo_m31_add(b23, b24);
    b24 = stwo_m31_mul(b44, b119);
    b23 = stwo_m31_add(b25, b24);
    b24 = stwo_m31_mul(b39, b125);
    b39 = stwo_m31_mul(b40, b124);
    b40 = stwo_m31_add(b24, b39);
    b39 = stwo_m31_mul(b41, b123);
    b123 = stwo_m31_add(b40, b39);
    b39 = stwo_m31_mul(b42, b122);
    b122 = stwo_m31_add(b123, b39);
    b39 = stwo_m31_mul(b43, b121);
    b121 = stwo_m31_add(b122, b39);
    b39 = stwo_m31_mul(b44, b120);
    b120 = stwo_m31_add(b121, b39);
    b39 = stwo_m31_mul(b45, b119);
    b119 = stwo_m31_add(b120, b39);
    b39 = stwo_m31_mul(b44, b125);
    b120 = stwo_m31_mul(b45, b124);
    b121 = stwo_m31_add(b39, b120);
    b120 = stwo_m31_mul(b45, b125);
    b39 = stwo_m31_add(b37, b44);
    b44 = stwo_m31_add(b38, b45);
    b45 = stwo_m31_add(b117, b124);
    b124 = stwo_m31_add(b118, b125);
    b125 = stwo_m31_mul(b39, b124);
    b39 = stwo_m31_mul(b44, b45);
    b45 = stwo_m31_add(b125, b39);
    b39 = stwo_m31_sub(b45, b26);
    b45 = stwo_m31_sub(b39, b121);
    b39 = stwo_m31_add(b30, b45);
    b45 = stwo_m31_mul(b44, b124);
    b124 = stwo_m31_sub(b45, b27);
    b45 = stwo_m31_sub(b124, b120);
    b124 = stwo_m31_add(b23, b45);
    b45 = stwo_m31_mul(b46, b77);
    b23 = stwo_m31_mul(b47, b76);
    b120 = stwo_m31_add(b45, b23);
    b23 = stwo_m31_mul(b48, b128);
    b45 = stwo_m31_add(b120, b23);
    b23 = stwo_m31_mul(b49, b127);
    b120 = stwo_m31_add(b45, b23);
    b23 = stwo_m31_mul(b50, b126);
    b45 = stwo_m31_add(b120, b23);
    b23 = stwo_m31_mul(b46, b78);
    b120 = stwo_m31_mul(b47, b77);
    b27 = stwo_m31_add(b23, b120);
    b120 = stwo_m31_mul(b48, b76);
    b23 = stwo_m31_add(b27, b120);
    b120 = stwo_m31_mul(b49, b128);
    b27 = stwo_m31_add(b23, b120);
    b120 = stwo_m31_mul(b50, b127);
    b23 = stwo_m31_add(b27, b120);
    b120 = stwo_m31_mul(b51, b126);
    b27 = stwo_m31_add(b23, b120);
    b120 = stwo_m31_mul(b46, b79);
    b23 = stwo_m31_mul(b47, b78);
    b44 = stwo_m31_add(b120, b23);
    b23 = stwo_m31_mul(b48, b77);
    b120 = stwo_m31_add(b44, b23);
    b23 = stwo_m31_mul(b49, b76);
    b44 = stwo_m31_add(b120, b23);
    b23 = stwo_m31_mul(b50, b128);
    b120 = stwo_m31_add(b44, b23);
    b23 = stwo_m31_mul(b51, b127);
    b44 = stwo_m31_add(b120, b23);
    b23 = stwo_m31_mul(b52, b126);
    b120 = stwo_m31_add(b44, b23);
    b23 = stwo_m31_mul(b51, b79);
    b44 = stwo_m31_mul(b52, b78);
    b30 = stwo_m31_add(b23, b44);
    b44 = stwo_m31_mul(b52, b79);
    b23 = stwo_m31_mul(b53, b84);
    b121 = stwo_m31_mul(b54, b83);
    b26 = stwo_m31_add(b23, b121);
    b121 = stwo_m31_mul(b55, b82);
    b23 = stwo_m31_add(b26, b121);
    b121 = stwo_m31_mul(b56, b81);
    b26 = stwo_m31_add(b23, b121);
    b121 = stwo_m31_mul(b57, b80);
    b23 = stwo_m31_add(b26, b121);
    b121 = stwo_m31_mul(b53, b85);
    b26 = stwo_m31_mul(b54, b84);
    b125 = stwo_m31_add(b121, b26);
    b26 = stwo_m31_mul(b55, b83);
    b121 = stwo_m31_add(b125, b26);
    b26 = stwo_m31_mul(b56, b82);
    b125 = stwo_m31_add(b121, b26);
    b26 = stwo_m31_mul(b57, b81);
    b121 = stwo_m31_add(b125, b26);
    b26 = stwo_m31_mul(b58, b80);
    b125 = stwo_m31_add(b121, b26);
    b26 = stwo_m31_mul(b53, b86);
    b53 = stwo_m31_mul(b54, b85);
    b54 = stwo_m31_add(b26, b53);
    b53 = stwo_m31_mul(b55, b84);
    b55 = stwo_m31_add(b54, b53);
    b53 = stwo_m31_mul(b56, b83);
    b83 = stwo_m31_add(b55, b53);
    b53 = stwo_m31_mul(b57, b82);
    b82 = stwo_m31_add(b83, b53);
    b53 = stwo_m31_mul(b58, b81);
    b81 = stwo_m31_add(b82, b53);
    b53 = stwo_m31_mul(b59, b80);
    b80 = stwo_m31_add(b81, b53);
    b53 = stwo_m31_mul(b57, b86);
    b57 = stwo_m31_mul(b58, b85);
    b81 = stwo_m31_add(b53, b57);
    b57 = stwo_m31_mul(b59, b84);
    b84 = stwo_m31_add(b81, b57);
    b57 = stwo_m31_mul(b58, b86);
    b81 = stwo_m31_mul(b59, b85);
    b53 = stwo_m31_add(b57, b81);
    b81 = stwo_m31_mul(b59, b86);
    b57 = stwo_m31_add(b51, b58);
    b58 = stwo_m31_add(b52, b59);
    b59 = stwo_m31_add(b78, b85);
    b85 = stwo_m31_add(b79, b86);
    b86 = stwo_m31_mul(b57, b85);
    b57 = stwo_m31_mul(b58, b59);
    b59 = stwo_m31_add(b86, b57);
    b57 = stwo_m31_sub(b59, b30);
    b59 = stwo_m31_sub(b57, b53);
    b57 = stwo_m31_add(b23, b59);
    b59 = stwo_m31_mul(b58, b85);
    b85 = stwo_m31_sub(b59, b44);
    b59 = stwo_m31_sub(b85, b81);
    b85 = stwo_m31_add(b125, b59);
    b59 = stwo_m31_add(b32, b46);
    b46 = stwo_m31_add(b33, b47);
    b47 = stwo_m31_add(b34, b48);
    b48 = stwo_m31_add(b35, b49);
    b49 = stwo_m31_add(b36, b50);
    b50 = stwo_m31_add(b37, b51);
    b51 = stwo_m31_add(b38, b52);
    b52 = stwo_m31_add(b112, b126);
    b126 = stwo_m31_add(b113, b127);
    b127 = stwo_m31_add(b114, b128);
    b128 = stwo_m31_add(b115, b76);
    b76 = stwo_m31_add(b116, b77);
    b77 = stwo_m31_add(b117, b78);
    b78 = stwo_m31_add(b118, b79);
    b79 = stwo_m31_mul(b59, b76);
    b118 = stwo_m31_mul(b46, b128);
    b117 = stwo_m31_add(b79, b118);
    b118 = stwo_m31_mul(b47, b127);
    b79 = stwo_m31_add(b117, b118);
    b118 = stwo_m31_mul(b48, b126);
    b117 = stwo_m31_add(b79, b118);
    b118 = stwo_m31_mul(b49, b52);
    b79 = stwo_m31_add(b117, b118);
    b118 = stwo_m31_mul(b59, b77);
    b117 = stwo_m31_mul(b46, b76);
    b116 = stwo_m31_add(b118, b117);
    b117 = stwo_m31_mul(b47, b128);
    b118 = stwo_m31_add(b116, b117);
    b117 = stwo_m31_mul(b48, b127);
    b116 = stwo_m31_add(b118, b117);
    b117 = stwo_m31_mul(b49, b126);
    b118 = stwo_m31_add(b116, b117);
    b117 = stwo_m31_mul(b50, b52);
    b116 = stwo_m31_add(b118, b117);
    b117 = stwo_m31_mul(b59, b78);
    b78 = stwo_m31_mul(b46, b77);
    b77 = stwo_m31_add(b117, b78);
    b78 = stwo_m31_mul(b47, b76);
    b76 = stwo_m31_add(b77, b78);
    b78 = stwo_m31_mul(b48, b128);
    b128 = stwo_m31_add(b76, b78);
    b78 = stwo_m31_mul(b49, b127);
    b127 = stwo_m31_add(b128, b78);
    b78 = stwo_m31_mul(b50, b126);
    b126 = stwo_m31_add(b127, b78);
    b78 = stwo_m31_mul(b51, b52);
    b52 = stwo_m31_add(b126, b78);
    b78 = stwo_m31_sub(b79, b90);
    b79 = stwo_m31_sub(b78, b45);
    b78 = stwo_m31_add(b39, b79);
    b79 = stwo_m31_sub(b116, b28);
    b116 = stwo_m31_sub(b79, b27);
    b79 = stwo_m31_add(b124, b116);
    b116 = stwo_m31_sub(b52, b29);
    b52 = stwo_m31_sub(b116, b120);
    b116 = stwo_m31_add(b119, b52);
    b52 = stwo_m31_sub(b78, b87);
    b78 = stwo_m31_sub(b79, b88);
    b79 = stwo_m31_sub(b116, b89);
    b116 = 2u;
    b89 = stwo_m31_mul(b116, b52);
    b116 = 4u;
    b52 = stwo_m31_mul(b116, b57);
    b116 = stwo_m31_sub(b89, b52);
    b52 = 2u;
    b89 = stwo_m31_mul(b52, b84);
    b52 = stwo_m31_add(b116, b89);
    b89 = 64u;
    b116 = stwo_m31_mul(b89, b53);
    b89 = stwo_m31_add(b52, b116);
    b116 = 2u;
    b52 = stwo_m31_mul(b116, b78);
    b116 = 4u;
    b78 = stwo_m31_mul(b116, b85);
    b116 = stwo_m31_sub(b52, b78);
    b78 = 2u;
    b52 = stwo_m31_mul(b78, b53);
    b78 = stwo_m31_add(b116, b52);
    b52 = 64u;
    b116 = stwo_m31_mul(b52, b81);
    b52 = stwo_m31_add(b78, b116);
    b116 = 2u;
    b78 = stwo_m31_mul(b116, b79);
    b116 = 4u;
    b79 = stwo_m31_mul(b116, b80);
    b116 = stwo_m31_sub(b78, b79);
    b79 = 2u;
    b78 = stwo_m31_mul(b79, b81);
    b79 = stwo_m31_add(b116, b78);
    b78 = 512u;
    b116 = stwo_m31_mul(b93, b78);
    b78 = stwo_m31_add(b89, b92);
    b89 = stwo_m31_sub(b116, b78);
    b78 = 512u;
    b116 = stwo_m31_mul(b94, b78);
    b78 = stwo_m31_add(b52, b93);
    b52 = stwo_m31_sub(b116, b78);
    b78 = 256u;
    b116 = stwo_m31_mul(b78, b91);
    b78 = stwo_m31_sub(b79, b116);
    b116 = stwo_m31_add(b78, b94);
    b78 = stwo_m31_sub(b60, b0);
    b60 = stwo_m31_mul(b78, b31);
    b78 = stwo_m31_add(b60, b0);
    b60 = stwo_m31_sub(b95, b78);
    b78 = stwo_m31_sub(b61, b1);
    b61 = stwo_m31_mul(b78, b31);
    b78 = stwo_m31_add(b61, b1);
    b61 = stwo_m31_sub(b96, b78);
    b78 = stwo_m31_sub(b62, b2);
    b62 = stwo_m31_mul(b78, b31);
    b78 = stwo_m31_add(b62, b2);
    b62 = stwo_m31_sub(b97, b78);
    b78 = stwo_m31_sub(b63, b3);
    b63 = stwo_m31_mul(b78, b31);
    b78 = stwo_m31_add(b63, b3);
    b63 = stwo_m31_sub(b98, b78);
    b78 = stwo_m31_sub(b64, b4);
    b64 = stwo_m31_mul(b78, b31);
    b78 = stwo_m31_add(b64, b4);
    b64 = stwo_m31_sub(b99, b78);
    b78 = stwo_m31_sub(b65, b5);
    b65 = stwo_m31_mul(b78, b31);
    b78 = stwo_m31_add(b65, b5);
    b65 = stwo_m31_sub(b100, b78);
    b78 = stwo_m31_sub(b66, b6);
    b66 = stwo_m31_mul(b78, b31);
    b78 = stwo_m31_add(b66, b6);
    b66 = stwo_m31_sub(b101, b78);
    b78 = stwo_m31_sub(b67, b7);
    b67 = stwo_m31_mul(b78, b31);
    b78 = stwo_m31_add(b67, b7);
    b67 = stwo_m31_sub(b102, b78);
    b78 = stwo_m31_sub(b68, b8);
    b68 = stwo_m31_mul(b78, b31);
    b78 = stwo_m31_add(b68, b8);
    b68 = stwo_m31_sub(b103, b78);
    b78 = stwo_m31_sub(b69, b9);
    b69 = stwo_m31_mul(b78, b31);
    b78 = stwo_m31_add(b69, b9);
    b69 = stwo_m31_sub(b104, b78);
    b78 = stwo_m31_sub(b70, b10);
    b70 = stwo_m31_mul(b78, b31);
    b78 = stwo_m31_add(b70, b10);
    b70 = stwo_m31_sub(b105, b78);
    b78 = stwo_m31_sub(b71, b11);
    b71 = stwo_m31_mul(b78, b31);
    b78 = stwo_m31_add(b71, b11);
    b71 = stwo_m31_sub(b106, b78);
    b78 = stwo_m31_sub(b72, b12);
    b72 = stwo_m31_mul(b78, b31);
    b78 = stwo_m31_add(b72, b12);
    b72 = stwo_m31_sub(b107, b78);
    b78 = stwo_m31_sub(b73, b13);
    b73 = stwo_m31_mul(b78, b31);
    b78 = stwo_m31_add(b73, b13);
    b73 = stwo_m31_sub(b108, b78);
    b78 = stwo_m31_sub(b74, b14);
    b74 = stwo_m31_mul(b78, b31);
    b78 = stwo_m31_add(b74, b14);
    b74 = stwo_m31_sub(b109, b78);
    b78 = stwo_m31_sub(b75, b15);
    b75 = stwo_m31_mul(b78, b31);
    b78 = stwo_m31_add(b75, b15);
    b75 = stwo_m31_sub(b110, b78);
    StwoCairoQm31 e0 = { b89, b111, b111, b111 };
    StwoCairoQm31 e1 = { b52, b111, b111, b111 };
    StwoCairoQm31 e2 = { b116, b111, b111, b111 };
    StwoCairoQm31 e3 = { b60, b111, b111, b111 };
    StwoCairoQm31 e4 = { b61, b111, b111, b111 };
    StwoCairoQm31 e5 = { b62, b111, b111, b111 };
    StwoCairoQm31 e6 = { b63, b111, b111, b111 };
    StwoCairoQm31 e7 = { b64, b111, b111, b111 };
    StwoCairoQm31 e8 = { b65, b111, b111, b111 };
    StwoCairoQm31 e9 = { b66, b111, b111, b111 };
    StwoCairoQm31 e10 = { b67, b111, b111, b111 };
    StwoCairoQm31 e11 = { b68, b111, b111, b111 };
    StwoCairoQm31 e12 = { b69, b111, b111, b111 };
    StwoCairoQm31 e13 = { b70, b111, b111, b111 };
    StwoCairoQm31 e14 = { b71, b111, b111, b111 };
    StwoCairoQm31 e15 = { b72, b111, b111, b111 };
    StwoCairoQm31 e16 = { b73, b111, b111, b111 };
    StwoCairoQm31 e17 = { b74, b111, b111, b111 };
    StwoCairoQm31 e18 = { b75, b111, b111, b111 };
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
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e13, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 13u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e14, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 14u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e15, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 15u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e16, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 16u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e17, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 17u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e18, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 18u) * 4u)));
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
