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
stwo_cairo_cuda_eval_v1_a6e34f161c4dd3eb(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 19u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 25u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 41u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 42u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 43u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 65u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 143u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 144u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 145u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 184u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 185u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 186u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 187u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 188u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 189u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 190u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 191u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 192u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 193u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 194u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 195u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 196u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 197u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 198u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 199u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 200u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 201u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 202u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 203u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 204u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 205u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 206u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 207u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 208u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 1u, 209u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 1u, 210u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 1u, 211u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 1u, 212u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 1u, 238u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 1u, 239u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 1u, 240u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 1u, 261u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 1u, 268u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 1u, 269u, row, 0);
    unsigned b95 = 0u;
    unsigned b96 = stwo_m31_add(b19, b30);
    b30 = stwo_m31_add(b96, b79);
    b96 = stwo_m31_add(b20, b31);
    b31 = stwo_m31_add(b96, b80);
    b96 = stwo_m31_mul(b32, b37);
    unsigned b97 = stwo_m31_mul(b33, b36);
    unsigned b98 = stwo_m31_add(b96, b97);
    b97 = stwo_m31_mul(b34, b35);
    b96 = stwo_m31_add(b98, b97);
    b97 = stwo_m31_mul(b35, b34);
    b98 = stwo_m31_add(b96, b97);
    b97 = stwo_m31_mul(b36, b33);
    b96 = stwo_m31_add(b98, b97);
    b97 = stwo_m31_mul(b37, b32);
    b98 = stwo_m31_add(b96, b97);
    b97 = stwo_m31_mul(b32, b38);
    b96 = stwo_m31_mul(b33, b37);
    unsigned b99 = stwo_m31_add(b97, b96);
    b96 = stwo_m31_mul(b34, b36);
    b97 = stwo_m31_add(b99, b96);
    b96 = stwo_m31_mul(b35, b35);
    b99 = stwo_m31_add(b97, b96);
    b96 = stwo_m31_mul(b36, b34);
    b97 = stwo_m31_add(b99, b96);
    b96 = stwo_m31_mul(b37, b33);
    b99 = stwo_m31_add(b97, b96);
    b96 = stwo_m31_mul(b38, b32);
    b97 = stwo_m31_add(b99, b96);
    b96 = stwo_m31_mul(b38, b38);
    b99 = stwo_m31_mul(b39, b44);
    unsigned b100 = stwo_m31_mul(b40, b43);
    unsigned b101 = stwo_m31_add(b99, b100);
    b100 = stwo_m31_mul(b41, b42);
    b99 = stwo_m31_add(b101, b100);
    b100 = stwo_m31_mul(b42, b41);
    b101 = stwo_m31_add(b99, b100);
    b100 = stwo_m31_mul(b43, b40);
    b99 = stwo_m31_add(b101, b100);
    b100 = stwo_m31_mul(b44, b39);
    b101 = stwo_m31_add(b99, b100);
    b100 = stwo_m31_mul(b39, b45);
    b99 = stwo_m31_mul(b40, b44);
    unsigned b102 = stwo_m31_add(b100, b99);
    b99 = stwo_m31_mul(b41, b43);
    b100 = stwo_m31_add(b102, b99);
    b99 = stwo_m31_mul(b42, b42);
    b102 = stwo_m31_add(b100, b99);
    b99 = stwo_m31_mul(b43, b41);
    b100 = stwo_m31_add(b102, b99);
    b99 = stwo_m31_mul(b44, b40);
    b102 = stwo_m31_add(b100, b99);
    b99 = stwo_m31_mul(b45, b39);
    b100 = stwo_m31_add(b102, b99);
    b99 = stwo_m31_mul(b45, b45);
    b102 = stwo_m31_add(b38, b45);
    unsigned b103 = stwo_m31_add(b38, b45);
    unsigned b104 = stwo_m31_mul(b102, b103);
    b103 = stwo_m31_sub(b104, b96);
    b104 = stwo_m31_sub(b103, b99);
    b103 = stwo_m31_add(b101, b104);
    b104 = stwo_m31_mul(b46, b51);
    b101 = stwo_m31_mul(b47, b50);
    b99 = stwo_m31_add(b104, b101);
    b101 = stwo_m31_mul(b48, b49);
    b104 = stwo_m31_add(b99, b101);
    b101 = stwo_m31_mul(b49, b48);
    b99 = stwo_m31_add(b104, b101);
    b101 = stwo_m31_mul(b50, b47);
    b104 = stwo_m31_add(b99, b101);
    b101 = stwo_m31_mul(b51, b46);
    b99 = stwo_m31_add(b104, b101);
    b101 = stwo_m31_mul(b46, b52);
    b104 = stwo_m31_mul(b47, b51);
    b96 = stwo_m31_add(b101, b104);
    b104 = stwo_m31_mul(b48, b50);
    b101 = stwo_m31_add(b96, b104);
    b104 = stwo_m31_mul(b49, b49);
    b96 = stwo_m31_add(b101, b104);
    b104 = stwo_m31_mul(b50, b48);
    b101 = stwo_m31_add(b96, b104);
    b104 = stwo_m31_mul(b51, b47);
    b96 = stwo_m31_add(b101, b104);
    b104 = stwo_m31_mul(b52, b46);
    b101 = stwo_m31_add(b96, b104);
    b104 = stwo_m31_mul(b52, b52);
    b96 = stwo_m31_mul(b53, b58);
    b102 = stwo_m31_mul(b54, b57);
    unsigned b105 = stwo_m31_add(b96, b102);
    b102 = stwo_m31_mul(b55, b56);
    b96 = stwo_m31_add(b105, b102);
    b102 = stwo_m31_mul(b56, b55);
    b105 = stwo_m31_add(b96, b102);
    b102 = stwo_m31_mul(b57, b54);
    b96 = stwo_m31_add(b105, b102);
    b102 = stwo_m31_mul(b58, b53);
    b105 = stwo_m31_add(b96, b102);
    b102 = stwo_m31_mul(b53, b59);
    b96 = stwo_m31_mul(b54, b58);
    unsigned b106 = stwo_m31_add(b102, b96);
    b96 = stwo_m31_mul(b55, b57);
    b102 = stwo_m31_add(b106, b96);
    b96 = stwo_m31_mul(b56, b56);
    b106 = stwo_m31_add(b102, b96);
    b96 = stwo_m31_mul(b57, b55);
    b102 = stwo_m31_add(b106, b96);
    b96 = stwo_m31_mul(b58, b54);
    b106 = stwo_m31_add(b102, b96);
    b96 = stwo_m31_mul(b59, b53);
    b102 = stwo_m31_add(b106, b96);
    b96 = stwo_m31_mul(b58, b59);
    b106 = stwo_m31_mul(b59, b58);
    unsigned b107 = stwo_m31_add(b96, b106);
    b106 = stwo_m31_mul(b59, b59);
    b96 = stwo_m31_add(b52, b59);
    unsigned b108 = stwo_m31_add(b52, b59);
    unsigned b109 = stwo_m31_mul(b96, b108);
    b108 = stwo_m31_sub(b109, b104);
    b109 = stwo_m31_sub(b108, b106);
    b108 = stwo_m31_add(b105, b109);
    b109 = stwo_m31_add(b32, b46);
    b105 = stwo_m31_add(b33, b47);
    b104 = stwo_m31_add(b34, b48);
    b96 = stwo_m31_add(b35, b49);
    unsigned b110 = stwo_m31_add(b36, b50);
    unsigned b111 = stwo_m31_add(b37, b51);
    unsigned b112 = stwo_m31_add(b38, b52);
    unsigned b113 = stwo_m31_add(b32, b46);
    unsigned b114 = stwo_m31_add(b33, b47);
    unsigned b115 = stwo_m31_add(b34, b48);
    unsigned b116 = stwo_m31_add(b35, b49);
    unsigned b117 = stwo_m31_add(b36, b50);
    unsigned b118 = stwo_m31_add(b37, b51);
    unsigned b119 = stwo_m31_add(b38, b52);
    unsigned b120 = stwo_m31_mul(b109, b118);
    unsigned b121 = stwo_m31_mul(b105, b117);
    unsigned b122 = stwo_m31_add(b120, b121);
    b121 = stwo_m31_mul(b104, b116);
    b120 = stwo_m31_add(b122, b121);
    b121 = stwo_m31_mul(b96, b115);
    b122 = stwo_m31_add(b120, b121);
    b121 = stwo_m31_mul(b110, b114);
    b120 = stwo_m31_add(b122, b121);
    b121 = stwo_m31_mul(b111, b113);
    b122 = stwo_m31_add(b120, b121);
    b121 = stwo_m31_mul(b109, b119);
    b119 = stwo_m31_mul(b105, b118);
    b118 = stwo_m31_add(b121, b119);
    b119 = stwo_m31_mul(b104, b117);
    b117 = stwo_m31_add(b118, b119);
    b119 = stwo_m31_mul(b96, b116);
    b116 = stwo_m31_add(b117, b119);
    b119 = stwo_m31_mul(b110, b115);
    b115 = stwo_m31_add(b116, b119);
    b119 = stwo_m31_mul(b111, b114);
    b114 = stwo_m31_add(b115, b119);
    b119 = stwo_m31_mul(b112, b113);
    b113 = stwo_m31_add(b114, b119);
    b119 = stwo_m31_sub(b122, b98);
    b122 = stwo_m31_sub(b119, b99);
    b119 = stwo_m31_add(b103, b122);
    b122 = stwo_m31_sub(b113, b97);
    b113 = stwo_m31_sub(b122, b101);
    b122 = stwo_m31_add(b100, b113);
    b113 = stwo_m31_sub(b119, b30);
    b119 = stwo_m31_sub(b122, b31);
    b122 = 2u;
    b31 = stwo_m31_mul(b122, b113);
    b122 = 4u;
    b113 = stwo_m31_mul(b122, b108);
    b122 = stwo_m31_sub(b31, b113);
    b113 = 2u;
    b31 = stwo_m31_mul(b113, b107);
    b113 = stwo_m31_add(b122, b31);
    b31 = 64u;
    b122 = stwo_m31_mul(b31, b106);
    b31 = stwo_m31_add(b113, b122);
    b122 = 2u;
    b113 = stwo_m31_mul(b122, b119);
    b122 = 4u;
    b119 = stwo_m31_mul(b122, b102);
    b122 = stwo_m31_sub(b113, b119);
    b119 = 2u;
    b113 = stwo_m31_mul(b119, b106);
    b119 = stwo_m31_add(b122, b113);
    b113 = 512u;
    b122 = stwo_m31_mul(b90, b113);
    b113 = stwo_m31_add(b31, b89);
    b31 = stwo_m31_sub(b122, b113);
    b113 = 256u;
    b122 = stwo_m31_mul(b113, b88);
    b113 = stwo_m31_sub(b119, b122);
    b122 = stwo_m31_add(b113, b90);
    b113 = stwo_m31_sub(b0, b60);
    b60 = stwo_m31_sub(b1, b61);
    b61 = stwo_m31_sub(b2, b62);
    b62 = stwo_m31_sub(b3, b63);
    b63 = stwo_m31_sub(b4, b64);
    b64 = stwo_m31_sub(b5, b65);
    b65 = stwo_m31_sub(b6, b66);
    b66 = stwo_m31_sub(b7, b67);
    b67 = stwo_m31_sub(b8, b68);
    b68 = stwo_m31_sub(b9, b69);
    b69 = stwo_m31_sub(b10, b70);
    b70 = stwo_m31_sub(b11, b71);
    b71 = stwo_m31_sub(b12, b72);
    b72 = stwo_m31_sub(b13, b73);
    b73 = stwo_m31_sub(b14, b74);
    b74 = stwo_m31_sub(b15, b75);
    b75 = stwo_m31_sub(b16, b76);
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
    b87 = stwo_m31_add(b28, b91);
    b91 = stwo_m31_add(b29, b92);
    b92 = stwo_m31_mul(b32, b113);
    b29 = stwo_m31_mul(b33, b65);
    b28 = stwo_m31_mul(b34, b64);
    b27 = stwo_m31_add(b29, b28);
    b28 = stwo_m31_mul(b35, b63);
    b29 = stwo_m31_add(b27, b28);
    b28 = stwo_m31_mul(b36, b62);
    b27 = stwo_m31_add(b29, b28);
    b28 = stwo_m31_mul(b37, b61);
    b29 = stwo_m31_add(b27, b28);
    b28 = stwo_m31_mul(b38, b60);
    b27 = stwo_m31_add(b29, b28);
    b28 = stwo_m31_mul(b39, b66);
    b29 = stwo_m31_mul(b40, b72);
    b72 = stwo_m31_mul(b41, b71);
    b71 = stwo_m31_add(b29, b72);
    b72 = stwo_m31_mul(b42, b70);
    b70 = stwo_m31_add(b71, b72);
    b72 = stwo_m31_mul(b43, b69);
    b69 = stwo_m31_add(b70, b72);
    b72 = stwo_m31_mul(b44, b68);
    b68 = stwo_m31_add(b69, b72);
    b72 = stwo_m31_mul(b45, b67);
    b67 = stwo_m31_add(b68, b72);
    b72 = stwo_m31_add(b32, b39);
    b68 = stwo_m31_add(b113, b66);
    b45 = stwo_m31_mul(b72, b68);
    b68 = stwo_m31_sub(b45, b92);
    b45 = stwo_m31_sub(b68, b28);
    b68 = stwo_m31_add(b27, b45);
    b45 = stwo_m31_mul(b46, b73);
    b27 = stwo_m31_mul(b47, b79);
    b28 = stwo_m31_mul(b48, b78);
    b72 = stwo_m31_add(b27, b28);
    b28 = stwo_m31_mul(b49, b77);
    b27 = stwo_m31_add(b72, b28);
    b28 = stwo_m31_mul(b50, b76);
    b72 = stwo_m31_add(b27, b28);
    b28 = stwo_m31_mul(b51, b75);
    b27 = stwo_m31_add(b72, b28);
    b28 = stwo_m31_mul(b52, b74);
    b72 = stwo_m31_add(b27, b28);
    b28 = stwo_m31_mul(b53, b80);
    b27 = stwo_m31_mul(b54, b86);
    b86 = stwo_m31_mul(b55, b85);
    b85 = stwo_m31_add(b27, b86);
    b86 = stwo_m31_mul(b56, b84);
    b84 = stwo_m31_add(b85, b86);
    b86 = stwo_m31_mul(b57, b83);
    b83 = stwo_m31_add(b84, b86);
    b86 = stwo_m31_mul(b58, b82);
    b82 = stwo_m31_add(b83, b86);
    b86 = stwo_m31_mul(b59, b81);
    b81 = stwo_m31_add(b82, b86);
    b86 = stwo_m31_add(b46, b53);
    b82 = stwo_m31_add(b73, b80);
    b59 = stwo_m31_mul(b86, b82);
    b82 = stwo_m31_sub(b59, b45);
    b59 = stwo_m31_sub(b82, b28);
    b82 = stwo_m31_add(b72, b59);
    b59 = stwo_m31_add(b32, b46);
    b46 = stwo_m31_add(b33, b47);
    b47 = stwo_m31_add(b34, b48);
    b48 = stwo_m31_add(b35, b49);
    b49 = stwo_m31_add(b36, b50);
    b50 = stwo_m31_add(b37, b51);
    b51 = stwo_m31_add(b38, b52);
    b52 = stwo_m31_add(b39, b53);
    b53 = stwo_m31_add(b113, b73);
    b73 = stwo_m31_add(b60, b74);
    b74 = stwo_m31_add(b61, b75);
    b75 = stwo_m31_add(b62, b76);
    b76 = stwo_m31_add(b63, b77);
    b77 = stwo_m31_add(b64, b78);
    b78 = stwo_m31_add(b65, b79);
    b79 = stwo_m31_add(b66, b80);
    b80 = stwo_m31_mul(b59, b53);
    b66 = stwo_m31_mul(b46, b78);
    b78 = stwo_m31_mul(b47, b77);
    b77 = stwo_m31_add(b66, b78);
    b78 = stwo_m31_mul(b48, b76);
    b76 = stwo_m31_add(b77, b78);
    b78 = stwo_m31_mul(b49, b75);
    b75 = stwo_m31_add(b76, b78);
    b78 = stwo_m31_mul(b50, b74);
    b74 = stwo_m31_add(b75, b78);
    b78 = stwo_m31_mul(b51, b73);
    b73 = stwo_m31_add(b74, b78);
    b78 = stwo_m31_mul(b52, b79);
    b74 = stwo_m31_add(b59, b52);
    b52 = stwo_m31_add(b53, b79);
    b79 = stwo_m31_mul(b74, b52);
    b52 = stwo_m31_sub(b79, b80);
    b79 = stwo_m31_sub(b52, b78);
    b52 = stwo_m31_add(b73, b79);
    b79 = stwo_m31_sub(b52, b68);
    b52 = stwo_m31_sub(b79, b82);
    b79 = stwo_m31_add(b67, b52);
    b52 = stwo_m31_sub(b92, b87);
    b92 = stwo_m31_sub(b79, b91);
    b79 = 32u;
    b91 = stwo_m31_mul(b79, b52);
    b79 = 4u;
    b52 = stwo_m31_mul(b79, b92);
    b79 = stwo_m31_sub(b91, b52);
    b52 = 8u;
    b91 = stwo_m31_mul(b52, b81);
    b52 = stwo_m31_add(b79, b91);
    b91 = 512u;
    b79 = stwo_m31_mul(b94, b91);
    b91 = stwo_m31_sub(b52, b93);
    b52 = stwo_m31_sub(b79, b91);
    StwoCairoQm31 e0 = { b31, b95, b95, b95 };
    StwoCairoQm31 e1 = { b122, b95, b95, b95 };
    StwoCairoQm31 e2 = { b52, b95, b95, b95 };
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
