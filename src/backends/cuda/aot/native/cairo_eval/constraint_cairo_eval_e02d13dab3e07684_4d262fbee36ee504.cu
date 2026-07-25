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
stwo_cairo_cuda_eval_v1_445ad1e3095f90c5(
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
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 105u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 107u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 156u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 157u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 158u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 159u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 160u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 161u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 162u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 163u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 164u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 165u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 166u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 167u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 168u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 169u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 170u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 171u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 172u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 173u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 202u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 203u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 204u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 205u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 206u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 207u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 208u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 209u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 210u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 211u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 212u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 213u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 214u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 215u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 216u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 217u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 218u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 219u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 220u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 221u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 222u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 223u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 224u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 225u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 1u, 226u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 1u, 227u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 1u, 228u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 1u, 229u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 1u, 261u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 1u, 262u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 1u, 267u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 1u, 268u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 1u, 269u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 1u, 296u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 1u, 297u, row, 0);
    unsigned b96 = stwo_trace_value(arena, *args, 1u, 298u, row, 0);
    unsigned b97 = 0u;
    unsigned b98 = stwo_m31_sub(b0, b61);
    b61 = stwo_m31_sub(b1, b62);
    b62 = stwo_m31_sub(b2, b63);
    b63 = stwo_m31_sub(b3, b64);
    b64 = stwo_m31_sub(b4, b65);
    b65 = stwo_m31_sub(b5, b66);
    b66 = stwo_m31_sub(b6, b67);
    b67 = stwo_m31_sub(b7, b68);
    b68 = stwo_m31_sub(b8, b69);
    b69 = stwo_m31_sub(b9, b70);
    b70 = stwo_m31_sub(b10, b71);
    b71 = stwo_m31_sub(b11, b72);
    b72 = stwo_m31_sub(b12, b73);
    b73 = stwo_m31_sub(b13, b74);
    b74 = stwo_m31_sub(b14, b75);
    b75 = stwo_m31_sub(b15, b76);
    b76 = stwo_m31_sub(b16, b77);
    b77 = stwo_m31_sub(b17, b78);
    b78 = stwo_m31_sub(b18, b79);
    b79 = stwo_m31_sub(b19, b80);
    b80 = stwo_m31_sub(b20, b81);
    b81 = stwo_m31_sub(b21, b82);
    b82 = stwo_m31_sub(b22, b83);
    b83 = stwo_m31_sub(b23, b84);
    b84 = stwo_m31_sub(b24, b85);
    b85 = stwo_m31_sub(b25, b86);
    b86 = stwo_m31_sub(b26, b87);
    b87 = stwo_m31_sub(b27, b88);
    b88 = stwo_m31_add(b28, b89);
    b89 = stwo_m31_add(b29, b90);
    b90 = stwo_m31_add(b30, b91);
    b91 = stwo_m31_add(b31, b92);
    b92 = stwo_m31_add(b32, b93);
    b93 = stwo_m31_mul(b33, b62);
    b32 = stwo_m31_mul(b34, b61);
    b31 = stwo_m31_add(b93, b32);
    b32 = stwo_m31_mul(b35, b98);
    b93 = stwo_m31_add(b31, b32);
    b32 = stwo_m31_mul(b33, b63);
    b31 = stwo_m31_mul(b34, b62);
    b30 = stwo_m31_add(b32, b31);
    b31 = stwo_m31_mul(b35, b61);
    b32 = stwo_m31_add(b30, b31);
    b31 = stwo_m31_mul(b36, b98);
    b30 = stwo_m31_add(b32, b31);
    b31 = stwo_m31_mul(b33, b64);
    b32 = stwo_m31_mul(b34, b63);
    b29 = stwo_m31_add(b31, b32);
    b32 = stwo_m31_mul(b35, b62);
    b31 = stwo_m31_add(b29, b32);
    b32 = stwo_m31_mul(b36, b61);
    b29 = stwo_m31_add(b31, b32);
    b32 = stwo_m31_mul(b37, b98);
    b31 = stwo_m31_add(b29, b32);
    b32 = stwo_m31_mul(b36, b66);
    b29 = stwo_m31_mul(b37, b65);
    b28 = stwo_m31_add(b32, b29);
    b29 = stwo_m31_mul(b38, b64);
    b32 = stwo_m31_add(b28, b29);
    b29 = stwo_m31_mul(b39, b63);
    b28 = stwo_m31_add(b32, b29);
    b29 = stwo_m31_mul(b37, b66);
    b32 = stwo_m31_mul(b38, b65);
    b27 = stwo_m31_add(b29, b32);
    b32 = stwo_m31_mul(b39, b64);
    b29 = stwo_m31_add(b27, b32);
    b32 = stwo_m31_mul(b38, b66);
    b27 = stwo_m31_mul(b39, b65);
    b26 = stwo_m31_add(b32, b27);
    b27 = stwo_m31_mul(b40, b69);
    b32 = stwo_m31_mul(b41, b68);
    b25 = stwo_m31_add(b27, b32);
    b32 = stwo_m31_mul(b42, b67);
    b27 = stwo_m31_add(b25, b32);
    b32 = stwo_m31_mul(b40, b70);
    b25 = stwo_m31_mul(b41, b69);
    b24 = stwo_m31_add(b32, b25);
    b25 = stwo_m31_mul(b42, b68);
    b32 = stwo_m31_add(b24, b25);
    b25 = stwo_m31_mul(b43, b67);
    b24 = stwo_m31_add(b32, b25);
    b25 = stwo_m31_mul(b40, b71);
    b32 = stwo_m31_mul(b41, b70);
    b23 = stwo_m31_add(b25, b32);
    b32 = stwo_m31_mul(b42, b69);
    b25 = stwo_m31_add(b23, b32);
    b32 = stwo_m31_mul(b43, b68);
    b23 = stwo_m31_add(b25, b32);
    b32 = stwo_m31_mul(b44, b67);
    b25 = stwo_m31_add(b23, b32);
    b32 = stwo_m31_mul(b44, b73);
    b23 = stwo_m31_mul(b45, b72);
    b22 = stwo_m31_add(b32, b23);
    b23 = stwo_m31_mul(b46, b71);
    b32 = stwo_m31_add(b22, b23);
    b23 = stwo_m31_mul(b45, b73);
    b22 = stwo_m31_mul(b46, b72);
    b21 = stwo_m31_add(b23, b22);
    b22 = stwo_m31_add(b33, b40);
    b33 = stwo_m31_add(b34, b41);
    b34 = stwo_m31_add(b35, b42);
    b35 = stwo_m31_add(b36, b43);
    b36 = stwo_m31_add(b37, b44);
    b23 = stwo_m31_add(b38, b45);
    b20 = stwo_m31_add(b39, b46);
    b19 = stwo_m31_add(b98, b67);
    b98 = stwo_m31_add(b61, b68);
    b61 = stwo_m31_add(b62, b69);
    b62 = stwo_m31_add(b63, b70);
    b63 = stwo_m31_add(b64, b71);
    b18 = stwo_m31_add(b65, b72);
    b17 = stwo_m31_add(b66, b73);
    b16 = stwo_m31_mul(b22, b61);
    b15 = stwo_m31_mul(b33, b98);
    b14 = stwo_m31_add(b16, b15);
    b15 = stwo_m31_mul(b34, b19);
    b16 = stwo_m31_add(b14, b15);
    b15 = stwo_m31_sub(b16, b93);
    b16 = stwo_m31_sub(b15, b27);
    b15 = stwo_m31_add(b28, b16);
    b16 = stwo_m31_mul(b22, b62);
    b28 = stwo_m31_mul(b33, b61);
    b27 = stwo_m31_add(b16, b28);
    b28 = stwo_m31_mul(b34, b98);
    b16 = stwo_m31_add(b27, b28);
    b28 = stwo_m31_mul(b35, b19);
    b27 = stwo_m31_add(b16, b28);
    b28 = stwo_m31_sub(b27, b30);
    b27 = stwo_m31_sub(b28, b24);
    b28 = stwo_m31_add(b29, b27);
    b27 = stwo_m31_mul(b22, b63);
    b22 = stwo_m31_mul(b33, b62);
    b62 = stwo_m31_add(b27, b22);
    b22 = stwo_m31_mul(b34, b61);
    b61 = stwo_m31_add(b62, b22);
    b22 = stwo_m31_mul(b35, b98);
    b98 = stwo_m31_add(b61, b22);
    b22 = stwo_m31_mul(b36, b19);
    b19 = stwo_m31_add(b98, b22);
    b22 = stwo_m31_sub(b19, b31);
    b19 = stwo_m31_sub(b22, b25);
    b22 = stwo_m31_add(b26, b19);
    b19 = stwo_m31_mul(b36, b17);
    b36 = stwo_m31_mul(b23, b18);
    b98 = stwo_m31_add(b19, b36);
    b36 = stwo_m31_mul(b20, b63);
    b63 = stwo_m31_add(b98, b36);
    b36 = stwo_m31_sub(b63, b29);
    b63 = stwo_m31_sub(b36, b32);
    b36 = stwo_m31_add(b24, b63);
    b63 = stwo_m31_mul(b23, b17);
    b17 = stwo_m31_mul(b20, b18);
    b18 = stwo_m31_add(b63, b17);
    b17 = stwo_m31_sub(b18, b26);
    b18 = stwo_m31_sub(b17, b21);
    b17 = stwo_m31_add(b25, b18);
    b18 = stwo_m31_mul(b47, b77);
    b25 = stwo_m31_mul(b48, b76);
    b21 = stwo_m31_add(b18, b25);
    b25 = stwo_m31_mul(b49, b75);
    b18 = stwo_m31_add(b21, b25);
    b25 = stwo_m31_mul(b50, b74);
    b21 = stwo_m31_add(b18, b25);
    b25 = stwo_m31_mul(b47, b78);
    b47 = stwo_m31_mul(b48, b77);
    b77 = stwo_m31_add(b25, b47);
    b47 = stwo_m31_mul(b49, b76);
    b76 = stwo_m31_add(b77, b47);
    b47 = stwo_m31_mul(b50, b75);
    b75 = stwo_m31_add(b76, b47);
    b47 = stwo_m31_mul(b51, b74);
    b74 = stwo_m31_add(b75, b47);
    b47 = stwo_m31_mul(b51, b80);
    b75 = stwo_m31_mul(b52, b79);
    b76 = stwo_m31_add(b47, b75);
    b75 = stwo_m31_mul(b53, b78);
    b47 = stwo_m31_add(b76, b75);
    b75 = stwo_m31_mul(b52, b80);
    b76 = stwo_m31_mul(b53, b79);
    b50 = stwo_m31_add(b75, b76);
    b76 = stwo_m31_mul(b54, b84);
    b75 = stwo_m31_mul(b55, b83);
    b77 = stwo_m31_add(b76, b75);
    b75 = stwo_m31_mul(b56, b82);
    b76 = stwo_m31_add(b77, b75);
    b75 = stwo_m31_mul(b57, b81);
    b77 = stwo_m31_add(b76, b75);
    b75 = stwo_m31_mul(b54, b85);
    b76 = stwo_m31_mul(b55, b84);
    b49 = stwo_m31_add(b75, b76);
    b76 = stwo_m31_mul(b56, b83);
    b75 = stwo_m31_add(b49, b76);
    b76 = stwo_m31_mul(b57, b82);
    b49 = stwo_m31_add(b75, b76);
    b76 = stwo_m31_mul(b58, b81);
    b75 = stwo_m31_add(b49, b76);
    b76 = stwo_m31_mul(b58, b87);
    b49 = stwo_m31_mul(b59, b86);
    b25 = stwo_m31_add(b76, b49);
    b49 = stwo_m31_mul(b60, b85);
    b76 = stwo_m31_add(b25, b49);
    b49 = stwo_m31_mul(b59, b87);
    b25 = stwo_m31_mul(b60, b86);
    b48 = stwo_m31_add(b49, b25);
    b25 = stwo_m31_add(b51, b58);
    b49 = stwo_m31_add(b52, b59);
    b18 = stwo_m31_add(b53, b60);
    b26 = stwo_m31_add(b78, b85);
    b63 = stwo_m31_add(b79, b86);
    b20 = stwo_m31_add(b80, b87);
    b23 = stwo_m31_mul(b25, b20);
    b25 = stwo_m31_mul(b49, b63);
    b24 = stwo_m31_add(b23, b25);
    b25 = stwo_m31_mul(b18, b26);
    b26 = stwo_m31_add(b24, b25);
    b25 = stwo_m31_sub(b26, b47);
    b26 = stwo_m31_sub(b25, b76);
    b25 = stwo_m31_add(b77, b26);
    b26 = stwo_m31_mul(b49, b20);
    b20 = stwo_m31_mul(b18, b63);
    b63 = stwo_m31_add(b26, b20);
    b20 = stwo_m31_sub(b63, b50);
    b63 = stwo_m31_sub(b20, b48);
    b20 = stwo_m31_add(b75, b63);
    b63 = stwo_m31_add(b37, b51);
    b51 = stwo_m31_add(b38, b52);
    b52 = stwo_m31_add(b39, b53);
    b53 = stwo_m31_add(b40, b54);
    b54 = stwo_m31_add(b41, b55);
    b55 = stwo_m31_add(b42, b56);
    b56 = stwo_m31_add(b43, b57);
    b57 = stwo_m31_add(b44, b58);
    b58 = stwo_m31_add(b45, b59);
    b59 = stwo_m31_add(b46, b60);
    b60 = stwo_m31_add(b64, b78);
    b78 = stwo_m31_add(b65, b79);
    b79 = stwo_m31_add(b66, b80);
    b80 = stwo_m31_add(b67, b81);
    b81 = stwo_m31_add(b68, b82);
    b82 = stwo_m31_add(b69, b83);
    b83 = stwo_m31_add(b70, b84);
    b84 = stwo_m31_add(b71, b85);
    b85 = stwo_m31_add(b72, b86);
    b86 = stwo_m31_add(b73, b87);
    b87 = stwo_m31_mul(b63, b79);
    b73 = stwo_m31_mul(b51, b78);
    b72 = stwo_m31_add(b87, b73);
    b73 = stwo_m31_mul(b52, b60);
    b87 = stwo_m31_add(b72, b73);
    b73 = stwo_m31_mul(b51, b79);
    b72 = stwo_m31_mul(b52, b78);
    b71 = stwo_m31_add(b73, b72);
    b72 = stwo_m31_mul(b53, b83);
    b73 = stwo_m31_mul(b54, b82);
    b70 = stwo_m31_add(b72, b73);
    b73 = stwo_m31_mul(b55, b81);
    b72 = stwo_m31_add(b70, b73);
    b73 = stwo_m31_mul(b56, b80);
    b70 = stwo_m31_add(b72, b73);
    b73 = stwo_m31_mul(b53, b84);
    b53 = stwo_m31_mul(b54, b83);
    b83 = stwo_m31_add(b73, b53);
    b53 = stwo_m31_mul(b55, b82);
    b82 = stwo_m31_add(b83, b53);
    b53 = stwo_m31_mul(b56, b81);
    b81 = stwo_m31_add(b82, b53);
    b53 = stwo_m31_mul(b57, b80);
    b80 = stwo_m31_add(b81, b53);
    b53 = stwo_m31_mul(b57, b86);
    b81 = stwo_m31_mul(b58, b85);
    b82 = stwo_m31_add(b53, b81);
    b81 = stwo_m31_mul(b59, b84);
    b53 = stwo_m31_add(b82, b81);
    b81 = stwo_m31_mul(b58, b86);
    b82 = stwo_m31_mul(b59, b85);
    b56 = stwo_m31_add(b81, b82);
    b82 = stwo_m31_add(b63, b57);
    b57 = stwo_m31_add(b51, b58);
    b58 = stwo_m31_add(b52, b59);
    b59 = stwo_m31_add(b60, b84);
    b84 = stwo_m31_add(b78, b85);
    b85 = stwo_m31_add(b79, b86);
    b86 = stwo_m31_mul(b82, b85);
    b82 = stwo_m31_mul(b57, b84);
    b79 = stwo_m31_add(b86, b82);
    b82 = stwo_m31_mul(b58, b59);
    b59 = stwo_m31_add(b79, b82);
    b82 = stwo_m31_sub(b59, b87);
    b59 = stwo_m31_sub(b82, b53);
    b82 = stwo_m31_add(b70, b59);
    b59 = stwo_m31_mul(b57, b85);
    b85 = stwo_m31_mul(b58, b84);
    b84 = stwo_m31_add(b59, b85);
    b85 = stwo_m31_sub(b84, b71);
    b84 = stwo_m31_sub(b85, b56);
    b85 = stwo_m31_add(b80, b84);
    b84 = stwo_m31_sub(b82, b36);
    b82 = stwo_m31_sub(b84, b25);
    b84 = stwo_m31_add(b21, b82);
    b82 = stwo_m31_sub(b85, b17);
    b85 = stwo_m31_sub(b82, b20);
    b82 = stwo_m31_add(b74, b85);
    b85 = stwo_m31_sub(b30, b88);
    b30 = stwo_m31_sub(b31, b89);
    b31 = stwo_m31_sub(b15, b90);
    b15 = stwo_m31_sub(b28, b91);
    b28 = stwo_m31_sub(b22, b92);
    b22 = 2u;
    b92 = stwo_m31_mul(b22, b85);
    b22 = stwo_m31_add(b92, b31);
    b92 = 32u;
    b31 = stwo_m31_mul(b92, b15);
    b92 = stwo_m31_add(b22, b31);
    b31 = 4u;
    b22 = stwo_m31_mul(b31, b84);
    b31 = stwo_m31_sub(b92, b22);
    b22 = 2u;
    b92 = stwo_m31_mul(b22, b30);
    b22 = stwo_m31_add(b92, b15);
    b92 = 32u;
    b15 = stwo_m31_mul(b92, b28);
    b92 = stwo_m31_add(b22, b15);
    b15 = 4u;
    b22 = stwo_m31_mul(b15, b82);
    b15 = stwo_m31_sub(b92, b22);
    b22 = 512u;
    b92 = stwo_m31_mul(b95, b22);
    b22 = stwo_m31_add(b31, b94);
    b31 = stwo_m31_sub(b92, b22);
    b22 = 512u;
    b92 = stwo_m31_mul(b96, b22);
    b22 = stwo_m31_add(b15, b95);
    b15 = stwo_m31_sub(b92, b22);
    StwoCairoQm31 e0 = { b31, b97, b97, b97 };
    StwoCairoQm31 e1 = { b15, b97, b97, b97 };
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
