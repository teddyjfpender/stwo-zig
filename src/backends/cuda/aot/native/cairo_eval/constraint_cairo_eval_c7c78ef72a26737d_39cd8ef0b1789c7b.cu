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
stwo_cairo_cuda_eval_v1_65e8b8d8dbd25497(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 19u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 25u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 101u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 103u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 104u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 105u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 107u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 108u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 109u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 110u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 111u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 112u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 113u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 114u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 115u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 116u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 117u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 118u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 119u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 120u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 121u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 122u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 123u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 218u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 219u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 220u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 221u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 222u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 223u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 224u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 225u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 226u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 227u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 228u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 229u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 258u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 259u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 260u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 261u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 1u, 262u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 1u, 263u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 1u, 264u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 1u, 265u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 1u, 266u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 1u, 267u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 1u, 268u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 1u, 269u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 1u, 270u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 1u, 271u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 1u, 272u, row, 0);
    unsigned b96 = stwo_trace_value(arena, *args, 1u, 273u, row, 0);
    unsigned b97 = stwo_trace_value(arena, *args, 1u, 274u, row, 0);
    unsigned b98 = stwo_trace_value(arena, *args, 1u, 275u, row, 0);
    unsigned b99 = stwo_trace_value(arena, *args, 1u, 276u, row, 0);
    unsigned b100 = stwo_trace_value(arena, *args, 1u, 277u, row, 0);
    unsigned b101 = stwo_trace_value(arena, *args, 1u, 278u, row, 0);
    unsigned b102 = stwo_trace_value(arena, *args, 1u, 279u, row, 0);
    unsigned b103 = stwo_trace_value(arena, *args, 1u, 280u, row, 0);
    unsigned b104 = stwo_trace_value(arena, *args, 1u, 281u, row, 0);
    unsigned b105 = stwo_trace_value(arena, *args, 1u, 282u, row, 0);
    unsigned b106 = stwo_trace_value(arena, *args, 1u, 283u, row, 0);
    unsigned b107 = stwo_trace_value(arena, *args, 1u, 284u, row, 0);
    unsigned b108 = stwo_trace_value(arena, *args, 1u, 285u, row, 0);
    unsigned b109 = stwo_trace_value(arena, *args, 1u, 330u, row, 0);
    unsigned b110 = stwo_trace_value(arena, *args, 1u, 331u, row, 0);
    unsigned b111 = stwo_trace_value(arena, *args, 1u, 332u, row, 0);
    unsigned b112 = stwo_trace_value(arena, *args, 1u, 333u, row, 0);
    unsigned b113 = stwo_trace_value(arena, *args, 1u, 334u, row, 0);
    unsigned b114 = stwo_trace_value(arena, *args, 1u, 335u, row, 0);
    unsigned b115 = stwo_trace_value(arena, *args, 1u, 336u, row, 0);
    unsigned b116 = stwo_trace_value(arena, *args, 1u, 337u, row, 0);
    unsigned b117 = stwo_trace_value(arena, *args, 1u, 338u, row, 0);
    unsigned b118 = stwo_trace_value(arena, *args, 1u, 339u, row, 0);
    unsigned b119 = stwo_trace_value(arena, *args, 1u, 340u, row, 0);
    unsigned b120 = stwo_trace_value(arena, *args, 1u, 341u, row, 0);
    unsigned b121 = stwo_trace_value(arena, *args, 1u, 342u, row, 0);
    unsigned b122 = stwo_trace_value(arena, *args, 1u, 343u, row, 0);
    unsigned b123 = stwo_trace_value(arena, *args, 1u, 344u, row, 0);
    unsigned b124 = stwo_trace_value(arena, *args, 1u, 345u, row, 0);
    unsigned b125 = stwo_trace_value(arena, *args, 1u, 346u, row, 0);
    unsigned b126 = stwo_trace_value(arena, *args, 1u, 347u, row, 0);
    unsigned b127 = stwo_trace_value(arena, *args, 1u, 348u, row, 0);
    unsigned b128 = stwo_trace_value(arena, *args, 1u, 349u, row, 0);
    unsigned b129 = stwo_trace_value(arena, *args, 1u, 350u, row, 0);
    unsigned b130 = stwo_trace_value(arena, *args, 1u, 351u, row, 0);
    unsigned b131 = stwo_trace_value(arena, *args, 1u, 352u, row, 0);
    unsigned b132 = stwo_trace_value(arena, *args, 1u, 353u, row, 0);
    unsigned b133 = stwo_trace_value(arena, *args, 1u, 354u, row, 0);
    unsigned b134 = stwo_trace_value(arena, *args, 1u, 355u, row, 0);
    unsigned b135 = stwo_trace_value(arena, *args, 1u, 356u, row, 0);
    unsigned b136 = stwo_trace_value(arena, *args, 1u, 357u, row, 0);
    unsigned b137 = stwo_trace_value(arena, *args, 1u, 358u, row, 0);
    unsigned b138 = stwo_trace_value(arena, *args, 1u, 359u, row, 0);
    unsigned b139 = stwo_trace_value(arena, *args, 1u, 360u, row, 0);
    unsigned b140 = stwo_trace_value(arena, *args, 1u, 361u, row, 0);
    unsigned b141 = stwo_trace_value(arena, *args, 1u, 362u, row, 0);
    unsigned b142 = stwo_trace_value(arena, *args, 1u, 363u, row, 0);
    unsigned b143 = stwo_trace_value(arena, *args, 1u, 364u, row, 0);
    unsigned b144 = stwo_trace_value(arena, *args, 1u, 365u, row, 0);
    unsigned b145 = stwo_trace_value(arena, *args, 1u, 366u, row, 0);
    unsigned b146 = stwo_trace_value(arena, *args, 1u, 367u, row, 0);
    unsigned b147 = stwo_trace_value(arena, *args, 1u, 368u, row, 0);
    unsigned b148 = stwo_trace_value(arena, *args, 1u, 369u, row, 0);
    unsigned b149 = stwo_trace_value(arena, *args, 1u, 370u, row, 0);
    unsigned b150 = stwo_trace_value(arena, *args, 1u, 391u, row, 0);
    unsigned b151 = stwo_trace_value(arena, *args, 1u, 398u, row, 0);
    unsigned b152 = stwo_trace_value(arena, *args, 1u, 399u, row, 0);
    unsigned b153 = 0u;
    unsigned b154 = stwo_m31_sub(b69, b28);
    b69 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b69, b28);
    b69 = stwo_m31_sub(b109, b154);
    b154 = stwo_m31_sub(b70, b29);
    b70 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b70, b29);
    b70 = stwo_m31_sub(b110, b154);
    b154 = stwo_m31_sub(b71, b30);
    b71 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b71, b30);
    b71 = stwo_m31_sub(b111, b154);
    b154 = stwo_m31_sub(b72, b31);
    b72 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b72, b31);
    b72 = stwo_m31_sub(b112, b154);
    b154 = stwo_m31_sub(b73, b32);
    b73 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b73, b32);
    b73 = stwo_m31_sub(b113, b154);
    b154 = stwo_m31_sub(b74, b33);
    b74 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b74, b33);
    b74 = stwo_m31_sub(b114, b154);
    b154 = stwo_m31_sub(b75, b34);
    b75 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b75, b34);
    b75 = stwo_m31_sub(b115, b154);
    b154 = stwo_m31_sub(b76, b35);
    b76 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b76, b35);
    b76 = stwo_m31_sub(b116, b154);
    b154 = stwo_m31_sub(b77, b36);
    b77 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b77, b36);
    b77 = stwo_m31_sub(b117, b154);
    b154 = stwo_m31_sub(b78, b37);
    b78 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b78, b37);
    b78 = stwo_m31_sub(b118, b154);
    b154 = stwo_m31_sub(b79, b38);
    b79 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b79, b38);
    b79 = stwo_m31_sub(b119, b154);
    b154 = stwo_m31_sub(b80, b39);
    b80 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b80, b39);
    b80 = stwo_m31_sub(b120, b154);
    b154 = stwo_m31_sub(b81, b40);
    b81 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b81, b40);
    b81 = stwo_m31_sub(b121, b154);
    b154 = stwo_m31_sub(b82, b41);
    b82 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b82, b41);
    b82 = stwo_m31_sub(b122, b154);
    b154 = stwo_m31_sub(b83, b42);
    b83 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b83, b42);
    b83 = stwo_m31_sub(b123, b154);
    b154 = stwo_m31_sub(b84, b43);
    b84 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b84, b43);
    b84 = stwo_m31_sub(b124, b154);
    b154 = stwo_m31_sub(b85, b44);
    b85 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b85, b44);
    b85 = stwo_m31_sub(b125, b154);
    b154 = stwo_m31_sub(b86, b45);
    b86 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b86, b45);
    b86 = stwo_m31_sub(b126, b154);
    b154 = stwo_m31_sub(b87, b46);
    b87 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b87, b46);
    b87 = stwo_m31_sub(b127, b154);
    b154 = stwo_m31_sub(b88, b47);
    b88 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b88, b47);
    b88 = stwo_m31_sub(b128, b154);
    b154 = stwo_m31_sub(b89, b48);
    b89 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b89, b48);
    b89 = stwo_m31_sub(b129, b154);
    b154 = stwo_m31_sub(b90, b49);
    b90 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b90, b49);
    b90 = stwo_m31_sub(b130, b154);
    b154 = stwo_m31_sub(b91, b50);
    b91 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b91, b50);
    b91 = stwo_m31_sub(b131, b154);
    b154 = stwo_m31_sub(b92, b51);
    b92 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b92, b51);
    b92 = stwo_m31_sub(b132, b154);
    b154 = stwo_m31_sub(b93, b52);
    b93 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b93, b52);
    b93 = stwo_m31_sub(b133, b154);
    b154 = stwo_m31_sub(b94, b53);
    b94 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b94, b53);
    b94 = stwo_m31_sub(b134, b154);
    b154 = stwo_m31_sub(b95, b54);
    b95 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b95, b54);
    b95 = stwo_m31_sub(b135, b154);
    b154 = stwo_m31_sub(b96, b55);
    b96 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b96, b55);
    b96 = stwo_m31_sub(b136, b154);
    b154 = stwo_m31_sub(b97, b56);
    b97 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b97, b56);
    b97 = stwo_m31_sub(b137, b154);
    b154 = stwo_m31_sub(b98, b57);
    b98 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b98, b57);
    b98 = stwo_m31_sub(b138, b154);
    b154 = stwo_m31_sub(b99, b58);
    b99 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b99, b58);
    b99 = stwo_m31_sub(b139, b154);
    b154 = stwo_m31_sub(b100, b59);
    b100 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b100, b59);
    b100 = stwo_m31_sub(b140, b154);
    b154 = stwo_m31_sub(b101, b60);
    b101 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b101, b60);
    b101 = stwo_m31_sub(b141, b154);
    b154 = stwo_m31_sub(b102, b61);
    b102 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b102, b61);
    b102 = stwo_m31_sub(b142, b154);
    b154 = stwo_m31_sub(b103, b62);
    b103 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b103, b62);
    b103 = stwo_m31_sub(b143, b154);
    b154 = stwo_m31_sub(b104, b63);
    b104 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b104, b63);
    b104 = stwo_m31_sub(b144, b154);
    b154 = stwo_m31_sub(b105, b64);
    b105 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b105, b64);
    b105 = stwo_m31_sub(b145, b154);
    b154 = stwo_m31_sub(b106, b65);
    b106 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b106, b65);
    b106 = stwo_m31_sub(b146, b154);
    b154 = stwo_m31_sub(b107, b66);
    b107 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b107, b66);
    b107 = stwo_m31_sub(b147, b154);
    b154 = stwo_m31_sub(b108, b67);
    b108 = stwo_m31_mul(b154, b68);
    b154 = stwo_m31_add(b108, b67);
    b108 = stwo_m31_sub(b148, b154);
    b154 = stwo_m31_mul(b0, b0);
    b148 = stwo_m31_mul(b1, b6);
    b67 = stwo_m31_mul(b2, b5);
    b68 = stwo_m31_add(b148, b67);
    b67 = stwo_m31_mul(b3, b4);
    b148 = stwo_m31_add(b68, b67);
    b67 = stwo_m31_mul(b4, b3);
    b68 = stwo_m31_add(b148, b67);
    b67 = stwo_m31_mul(b5, b2);
    b148 = stwo_m31_add(b68, b67);
    b67 = stwo_m31_mul(b6, b1);
    b68 = stwo_m31_add(b148, b67);
    b67 = stwo_m31_mul(b7, b7);
    b148 = stwo_m31_mul(b8, b13);
    b147 = stwo_m31_mul(b9, b12);
    b66 = stwo_m31_add(b148, b147);
    b147 = stwo_m31_mul(b10, b11);
    b148 = stwo_m31_add(b66, b147);
    b147 = stwo_m31_mul(b11, b10);
    b11 = stwo_m31_add(b148, b147);
    b147 = stwo_m31_mul(b12, b9);
    b12 = stwo_m31_add(b11, b147);
    b147 = stwo_m31_mul(b13, b8);
    b13 = stwo_m31_add(b12, b147);
    b147 = stwo_m31_add(b0, b7);
    b12 = stwo_m31_add(b0, b7);
    b8 = stwo_m31_mul(b147, b12);
    b12 = stwo_m31_sub(b8, b154);
    b8 = stwo_m31_sub(b12, b67);
    b12 = stwo_m31_add(b68, b8);
    b8 = stwo_m31_mul(b14, b14);
    b68 = stwo_m31_mul(b15, b20);
    b67 = stwo_m31_mul(b16, b19);
    b147 = stwo_m31_add(b68, b67);
    b67 = stwo_m31_mul(b17, b18);
    b68 = stwo_m31_add(b147, b67);
    b67 = stwo_m31_mul(b18, b17);
    b147 = stwo_m31_add(b68, b67);
    b67 = stwo_m31_mul(b19, b16);
    b68 = stwo_m31_add(b147, b67);
    b67 = stwo_m31_mul(b20, b15);
    b147 = stwo_m31_add(b68, b67);
    b67 = stwo_m31_mul(b21, b21);
    b68 = stwo_m31_mul(b22, b27);
    b11 = stwo_m31_mul(b23, b26);
    b9 = stwo_m31_add(b68, b11);
    b11 = stwo_m31_mul(b24, b25);
    b68 = stwo_m31_add(b9, b11);
    b11 = stwo_m31_mul(b25, b24);
    b25 = stwo_m31_add(b68, b11);
    b11 = stwo_m31_mul(b26, b23);
    b26 = stwo_m31_add(b25, b11);
    b11 = stwo_m31_mul(b27, b22);
    b27 = stwo_m31_add(b26, b11);
    b11 = stwo_m31_add(b14, b21);
    b26 = stwo_m31_add(b14, b21);
    b22 = stwo_m31_mul(b11, b26);
    b26 = stwo_m31_sub(b22, b8);
    b22 = stwo_m31_sub(b26, b67);
    b26 = stwo_m31_add(b147, b22);
    b22 = stwo_m31_add(b0, b14);
    b147 = stwo_m31_add(b1, b15);
    b67 = stwo_m31_add(b2, b16);
    b8 = stwo_m31_add(b3, b17);
    b11 = stwo_m31_add(b4, b18);
    b25 = stwo_m31_add(b5, b19);
    b23 = stwo_m31_add(b6, b20);
    b68 = stwo_m31_add(b7, b21);
    b24 = stwo_m31_add(b0, b14);
    b14 = stwo_m31_add(b1, b15);
    b15 = stwo_m31_add(b2, b16);
    b16 = stwo_m31_add(b3, b17);
    b17 = stwo_m31_add(b4, b18);
    b18 = stwo_m31_add(b5, b19);
    b19 = stwo_m31_add(b6, b20);
    b20 = stwo_m31_add(b7, b21);
    b21 = stwo_m31_mul(b22, b24);
    b7 = stwo_m31_mul(b147, b19);
    b19 = stwo_m31_mul(b67, b18);
    b18 = stwo_m31_add(b7, b19);
    b19 = stwo_m31_mul(b8, b17);
    b17 = stwo_m31_add(b18, b19);
    b19 = stwo_m31_mul(b11, b16);
    b16 = stwo_m31_add(b17, b19);
    b19 = stwo_m31_mul(b25, b15);
    b15 = stwo_m31_add(b16, b19);
    b19 = stwo_m31_mul(b23, b14);
    b14 = stwo_m31_add(b15, b19);
    b19 = stwo_m31_mul(b68, b20);
    b15 = stwo_m31_add(b22, b68);
    b68 = stwo_m31_add(b24, b20);
    b20 = stwo_m31_mul(b15, b68);
    b68 = stwo_m31_sub(b20, b21);
    b20 = stwo_m31_sub(b68, b19);
    b68 = stwo_m31_add(b14, b20);
    b20 = stwo_m31_sub(b68, b12);
    b68 = stwo_m31_sub(b20, b26);
    b20 = stwo_m31_add(b13, b68);
    b68 = stwo_m31_sub(b154, b149);
    b154 = stwo_m31_sub(b20, b150);
    b20 = 32u;
    b150 = stwo_m31_mul(b20, b68);
    b20 = 4u;
    b68 = stwo_m31_mul(b20, b154);
    b20 = stwo_m31_sub(b150, b68);
    b68 = 8u;
    b150 = stwo_m31_mul(b68, b27);
    b68 = stwo_m31_add(b20, b150);
    b150 = 512u;
    b20 = stwo_m31_mul(b152, b150);
    b150 = stwo_m31_sub(b68, b151);
    b68 = stwo_m31_sub(b20, b150);
    StwoCairoQm31 e0 = { b69, b153, b153, b153 };
    StwoCairoQm31 e1 = { b70, b153, b153, b153 };
    StwoCairoQm31 e2 = { b71, b153, b153, b153 };
    StwoCairoQm31 e3 = { b72, b153, b153, b153 };
    StwoCairoQm31 e4 = { b73, b153, b153, b153 };
    StwoCairoQm31 e5 = { b74, b153, b153, b153 };
    StwoCairoQm31 e6 = { b75, b153, b153, b153 };
    StwoCairoQm31 e7 = { b76, b153, b153, b153 };
    StwoCairoQm31 e8 = { b77, b153, b153, b153 };
    StwoCairoQm31 e9 = { b78, b153, b153, b153 };
    StwoCairoQm31 e10 = { b79, b153, b153, b153 };
    StwoCairoQm31 e11 = { b80, b153, b153, b153 };
    StwoCairoQm31 e12 = { b81, b153, b153, b153 };
    StwoCairoQm31 e13 = { b82, b153, b153, b153 };
    StwoCairoQm31 e14 = { b83, b153, b153, b153 };
    StwoCairoQm31 e15 = { b84, b153, b153, b153 };
    StwoCairoQm31 e16 = { b85, b153, b153, b153 };
    StwoCairoQm31 e17 = { b86, b153, b153, b153 };
    StwoCairoQm31 e18 = { b87, b153, b153, b153 };
    StwoCairoQm31 e19 = { b88, b153, b153, b153 };
    StwoCairoQm31 e20 = { b89, b153, b153, b153 };
    StwoCairoQm31 e21 = { b90, b153, b153, b153 };
    StwoCairoQm31 e22 = { b91, b153, b153, b153 };
    StwoCairoQm31 e23 = { b92, b153, b153, b153 };
    StwoCairoQm31 e24 = { b93, b153, b153, b153 };
    StwoCairoQm31 e25 = { b94, b153, b153, b153 };
    StwoCairoQm31 e26 = { b95, b153, b153, b153 };
    StwoCairoQm31 e27 = { b96, b153, b153, b153 };
    StwoCairoQm31 e28 = { b97, b153, b153, b153 };
    StwoCairoQm31 e29 = { b98, b153, b153, b153 };
    StwoCairoQm31 e30 = { b99, b153, b153, b153 };
    StwoCairoQm31 e31 = { b100, b153, b153, b153 };
    StwoCairoQm31 e32 = { b101, b153, b153, b153 };
    StwoCairoQm31 e33 = { b102, b153, b153, b153 };
    StwoCairoQm31 e34 = { b103, b153, b153, b153 };
    StwoCairoQm31 e35 = { b104, b153, b153, b153 };
    StwoCairoQm31 e36 = { b105, b153, b153, b153 };
    StwoCairoQm31 e37 = { b106, b153, b153, b153 };
    StwoCairoQm31 e38 = { b107, b153, b153, b153 };
    StwoCairoQm31 e39 = { b108, b153, b153, b153 };
    StwoCairoQm31 e40 = { b68, b153, b153, b153 };
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
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e19, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 19u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e20, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 20u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e21, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 21u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e22, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 22u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e23, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 23u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e24, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 24u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e25, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 25u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e26, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 26u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e27, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 27u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e28, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 28u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e29, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 29u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e30, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 30u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e31, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 31u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e32, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 32u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e33, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 33u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e34, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 34u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e35, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 35u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e36, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 36u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e37, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 37u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e38, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 38u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e39, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 39u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e40, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 40u) * 4u)));
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
