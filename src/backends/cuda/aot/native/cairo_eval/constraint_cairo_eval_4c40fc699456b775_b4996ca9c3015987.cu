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
stwo_cairo_cuda_eval_v1_1c5e924282b216bf(
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
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 59u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 60u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 61u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 143u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 144u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 145u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 184u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 185u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 186u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 187u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 188u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 189u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 190u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 191u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 192u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 193u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 194u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 195u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 196u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 197u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 198u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 199u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 200u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 201u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 202u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 203u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 204u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 205u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 206u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 207u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 208u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 209u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 1u, 210u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 1u, 211u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 1u, 255u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 1u, 256u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 1u, 257u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 1u, 290u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 1u, 291u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 1u, 292u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 1u, 293u, row, 0);
    unsigned b94 = 0u;
    unsigned b95 = stwo_m31_sub(b0, b59);
    b59 = stwo_m31_sub(b1, b60);
    b60 = stwo_m31_sub(b2, b61);
    b61 = stwo_m31_sub(b3, b62);
    b62 = stwo_m31_sub(b4, b63);
    b63 = stwo_m31_sub(b5, b64);
    b64 = stwo_m31_sub(b6, b65);
    b65 = stwo_m31_sub(b7, b66);
    b66 = stwo_m31_sub(b8, b67);
    b67 = stwo_m31_sub(b9, b68);
    b68 = stwo_m31_sub(b10, b69);
    b69 = stwo_m31_sub(b11, b70);
    b70 = stwo_m31_sub(b12, b71);
    b71 = stwo_m31_sub(b13, b72);
    b72 = stwo_m31_sub(b14, b73);
    b73 = stwo_m31_sub(b15, b74);
    b74 = stwo_m31_sub(b16, b75);
    b75 = stwo_m31_sub(b17, b76);
    b76 = stwo_m31_sub(b18, b77);
    b77 = stwo_m31_sub(b19, b78);
    b78 = stwo_m31_sub(b20, b79);
    b79 = stwo_m31_sub(b21, b80);
    b80 = stwo_m31_sub(b22, b81);
    b81 = stwo_m31_sub(b23, b82);
    b82 = stwo_m31_sub(b24, b83);
    b83 = stwo_m31_sub(b25, b84);
    b84 = stwo_m31_sub(b26, b85);
    b85 = stwo_m31_sub(b27, b86);
    b86 = stwo_m31_add(b28, b87);
    b87 = stwo_m31_add(b29, b88);
    b88 = stwo_m31_add(b30, b89);
    b89 = stwo_m31_mul(b31, b59);
    b30 = stwo_m31_mul(b32, b95);
    b29 = stwo_m31_add(b89, b30);
    b30 = stwo_m31_mul(b31, b60);
    b89 = stwo_m31_mul(b32, b59);
    b28 = stwo_m31_add(b30, b89);
    b89 = stwo_m31_mul(b33, b95);
    b30 = stwo_m31_add(b28, b89);
    b89 = stwo_m31_mul(b31, b61);
    b28 = stwo_m31_mul(b32, b60);
    b27 = stwo_m31_add(b89, b28);
    b28 = stwo_m31_mul(b33, b59);
    b89 = stwo_m31_add(b27, b28);
    b28 = stwo_m31_mul(b34, b95);
    b27 = stwo_m31_add(b89, b28);
    b28 = stwo_m31_mul(b33, b64);
    b89 = stwo_m31_mul(b34, b63);
    b26 = stwo_m31_add(b28, b89);
    b89 = stwo_m31_mul(b35, b62);
    b28 = stwo_m31_add(b26, b89);
    b89 = stwo_m31_mul(b36, b61);
    b26 = stwo_m31_add(b28, b89);
    b89 = stwo_m31_mul(b37, b60);
    b28 = stwo_m31_add(b26, b89);
    b89 = stwo_m31_mul(b34, b64);
    b26 = stwo_m31_mul(b35, b63);
    b25 = stwo_m31_add(b89, b26);
    b26 = stwo_m31_mul(b36, b62);
    b89 = stwo_m31_add(b25, b26);
    b26 = stwo_m31_mul(b37, b61);
    b25 = stwo_m31_add(b89, b26);
    b26 = stwo_m31_mul(b35, b64);
    b89 = stwo_m31_mul(b36, b63);
    b24 = stwo_m31_add(b26, b89);
    b89 = stwo_m31_mul(b37, b62);
    b26 = stwo_m31_add(b24, b89);
    b89 = stwo_m31_mul(b38, b66);
    b24 = stwo_m31_mul(b39, b65);
    b23 = stwo_m31_add(b89, b24);
    b24 = stwo_m31_mul(b38, b67);
    b89 = stwo_m31_mul(b39, b66);
    b22 = stwo_m31_add(b24, b89);
    b89 = stwo_m31_mul(b40, b65);
    b24 = stwo_m31_add(b22, b89);
    b89 = stwo_m31_mul(b38, b68);
    b38 = stwo_m31_mul(b39, b67);
    b39 = stwo_m31_add(b89, b38);
    b38 = stwo_m31_mul(b40, b66);
    b66 = stwo_m31_add(b39, b38);
    b38 = stwo_m31_mul(b41, b65);
    b65 = stwo_m31_add(b66, b38);
    b38 = stwo_m31_mul(b40, b71);
    b66 = stwo_m31_mul(b41, b70);
    b39 = stwo_m31_add(b38, b66);
    b66 = stwo_m31_mul(b42, b69);
    b38 = stwo_m31_add(b39, b66);
    b66 = stwo_m31_mul(b43, b68);
    b39 = stwo_m31_add(b38, b66);
    b66 = stwo_m31_mul(b44, b67);
    b38 = stwo_m31_add(b39, b66);
    b66 = stwo_m31_mul(b41, b71);
    b39 = stwo_m31_mul(b42, b70);
    b89 = stwo_m31_add(b66, b39);
    b39 = stwo_m31_mul(b43, b69);
    b66 = stwo_m31_add(b89, b39);
    b39 = stwo_m31_mul(b44, b68);
    b89 = stwo_m31_add(b66, b39);
    b39 = stwo_m31_mul(b42, b71);
    b66 = stwo_m31_mul(b43, b70);
    b22 = stwo_m31_add(b39, b66);
    b66 = stwo_m31_mul(b44, b69);
    b39 = stwo_m31_add(b22, b66);
    b66 = stwo_m31_add(b33, b40);
    b40 = stwo_m31_add(b34, b41);
    b41 = stwo_m31_add(b35, b42);
    b42 = stwo_m31_add(b36, b43);
    b43 = stwo_m31_add(b37, b44);
    b44 = stwo_m31_add(b60, b67);
    b67 = stwo_m31_add(b61, b68);
    b68 = stwo_m31_add(b62, b69);
    b69 = stwo_m31_add(b63, b70);
    b70 = stwo_m31_add(b64, b71);
    b71 = stwo_m31_mul(b66, b70);
    b66 = stwo_m31_mul(b40, b69);
    b64 = stwo_m31_add(b71, b66);
    b66 = stwo_m31_mul(b41, b68);
    b71 = stwo_m31_add(b64, b66);
    b66 = stwo_m31_mul(b42, b67);
    b64 = stwo_m31_add(b71, b66);
    b66 = stwo_m31_mul(b43, b44);
    b44 = stwo_m31_add(b64, b66);
    b66 = stwo_m31_sub(b44, b28);
    b44 = stwo_m31_sub(b66, b38);
    b66 = stwo_m31_add(b23, b44);
    b44 = stwo_m31_mul(b40, b70);
    b40 = stwo_m31_mul(b41, b69);
    b23 = stwo_m31_add(b44, b40);
    b40 = stwo_m31_mul(b42, b68);
    b44 = stwo_m31_add(b23, b40);
    b40 = stwo_m31_mul(b43, b67);
    b67 = stwo_m31_add(b44, b40);
    b40 = stwo_m31_sub(b67, b25);
    b67 = stwo_m31_sub(b40, b89);
    b40 = stwo_m31_add(b24, b67);
    b67 = stwo_m31_mul(b41, b70);
    b70 = stwo_m31_mul(b42, b69);
    b69 = stwo_m31_add(b67, b70);
    b70 = stwo_m31_mul(b43, b68);
    b68 = stwo_m31_add(b69, b70);
    b70 = stwo_m31_sub(b68, b26);
    b68 = stwo_m31_sub(b70, b39);
    b70 = stwo_m31_add(b65, b68);
    b68 = stwo_m31_mul(b45, b73);
    b65 = stwo_m31_mul(b46, b72);
    b39 = stwo_m31_add(b68, b65);
    b65 = stwo_m31_mul(b45, b74);
    b68 = stwo_m31_mul(b46, b73);
    b26 = stwo_m31_add(b65, b68);
    b68 = stwo_m31_mul(b47, b72);
    b65 = stwo_m31_add(b26, b68);
    b68 = stwo_m31_mul(b45, b75);
    b26 = stwo_m31_mul(b46, b74);
    b69 = stwo_m31_add(b68, b26);
    b26 = stwo_m31_mul(b47, b73);
    b68 = stwo_m31_add(b69, b26);
    b26 = stwo_m31_mul(b48, b72);
    b69 = stwo_m31_add(b68, b26);
    b26 = stwo_m31_mul(b47, b78);
    b68 = stwo_m31_mul(b48, b77);
    b43 = stwo_m31_add(b26, b68);
    b68 = stwo_m31_mul(b49, b76);
    b26 = stwo_m31_add(b43, b68);
    b68 = stwo_m31_mul(b50, b75);
    b43 = stwo_m31_add(b26, b68);
    b68 = stwo_m31_mul(b51, b74);
    b26 = stwo_m31_add(b43, b68);
    b68 = stwo_m31_mul(b48, b78);
    b43 = stwo_m31_mul(b49, b77);
    b67 = stwo_m31_add(b68, b43);
    b43 = stwo_m31_mul(b50, b76);
    b68 = stwo_m31_add(b67, b43);
    b43 = stwo_m31_mul(b51, b75);
    b67 = stwo_m31_add(b68, b43);
    b43 = stwo_m31_mul(b49, b78);
    b68 = stwo_m31_mul(b50, b77);
    b42 = stwo_m31_add(b43, b68);
    b68 = stwo_m31_mul(b51, b76);
    b43 = stwo_m31_add(b42, b68);
    b68 = stwo_m31_mul(b52, b80);
    b42 = stwo_m31_mul(b53, b79);
    b41 = stwo_m31_add(b68, b42);
    b42 = stwo_m31_mul(b52, b81);
    b68 = stwo_m31_mul(b53, b80);
    b24 = stwo_m31_add(b42, b68);
    b68 = stwo_m31_mul(b54, b79);
    b42 = stwo_m31_add(b24, b68);
    b68 = stwo_m31_mul(b52, b82);
    b52 = stwo_m31_mul(b53, b81);
    b24 = stwo_m31_add(b68, b52);
    b52 = stwo_m31_mul(b54, b80);
    b68 = stwo_m31_add(b24, b52);
    b52 = stwo_m31_mul(b55, b79);
    b79 = stwo_m31_add(b68, b52);
    b52 = stwo_m31_mul(b53, b85);
    b53 = stwo_m31_mul(b54, b84);
    b68 = stwo_m31_add(b52, b53);
    b53 = stwo_m31_mul(b55, b83);
    b52 = stwo_m31_add(b68, b53);
    b53 = stwo_m31_mul(b56, b82);
    b68 = stwo_m31_add(b52, b53);
    b53 = stwo_m31_mul(b57, b81);
    b52 = stwo_m31_add(b68, b53);
    b53 = stwo_m31_mul(b58, b80);
    b80 = stwo_m31_add(b52, b53);
    b53 = stwo_m31_mul(b54, b85);
    b52 = stwo_m31_mul(b55, b84);
    b68 = stwo_m31_add(b53, b52);
    b52 = stwo_m31_mul(b56, b83);
    b53 = stwo_m31_add(b68, b52);
    b52 = stwo_m31_mul(b57, b82);
    b68 = stwo_m31_add(b53, b52);
    b52 = stwo_m31_mul(b58, b81);
    b53 = stwo_m31_add(b68, b52);
    b52 = stwo_m31_mul(b55, b85);
    b68 = stwo_m31_mul(b56, b84);
    b24 = stwo_m31_add(b52, b68);
    b68 = stwo_m31_mul(b57, b83);
    b52 = stwo_m31_add(b24, b68);
    b68 = stwo_m31_mul(b58, b82);
    b24 = stwo_m31_add(b52, b68);
    b68 = stwo_m31_mul(b56, b85);
    b52 = stwo_m31_mul(b57, b84);
    b89 = stwo_m31_add(b68, b52);
    b52 = stwo_m31_mul(b58, b83);
    b68 = stwo_m31_add(b89, b52);
    b52 = stwo_m31_add(b47, b54);
    b54 = stwo_m31_add(b48, b55);
    b55 = stwo_m31_add(b49, b56);
    b56 = stwo_m31_add(b50, b57);
    b57 = stwo_m31_add(b51, b58);
    b58 = stwo_m31_add(b74, b81);
    b81 = stwo_m31_add(b75, b82);
    b82 = stwo_m31_add(b76, b83);
    b83 = stwo_m31_add(b77, b84);
    b84 = stwo_m31_add(b78, b85);
    b85 = stwo_m31_mul(b52, b84);
    b52 = stwo_m31_mul(b54, b83);
    b78 = stwo_m31_add(b85, b52);
    b52 = stwo_m31_mul(b55, b82);
    b85 = stwo_m31_add(b78, b52);
    b52 = stwo_m31_mul(b56, b81);
    b78 = stwo_m31_add(b85, b52);
    b52 = stwo_m31_mul(b57, b58);
    b58 = stwo_m31_add(b78, b52);
    b52 = stwo_m31_sub(b58, b26);
    b58 = stwo_m31_sub(b52, b53);
    b52 = stwo_m31_add(b41, b58);
    b58 = stwo_m31_mul(b54, b84);
    b54 = stwo_m31_mul(b55, b83);
    b41 = stwo_m31_add(b58, b54);
    b54 = stwo_m31_mul(b56, b82);
    b58 = stwo_m31_add(b41, b54);
    b54 = stwo_m31_mul(b57, b81);
    b81 = stwo_m31_add(b58, b54);
    b54 = stwo_m31_sub(b81, b67);
    b81 = stwo_m31_sub(b54, b24);
    b54 = stwo_m31_add(b42, b81);
    b81 = stwo_m31_mul(b55, b84);
    b84 = stwo_m31_mul(b56, b83);
    b83 = stwo_m31_add(b81, b84);
    b84 = stwo_m31_mul(b57, b82);
    b82 = stwo_m31_add(b83, b84);
    b84 = stwo_m31_sub(b82, b43);
    b82 = stwo_m31_sub(b84, b68);
    b84 = stwo_m31_add(b79, b82);
    b82 = stwo_m31_add(b31, b45);
    b45 = stwo_m31_add(b32, b46);
    b46 = stwo_m31_add(b33, b47);
    b47 = stwo_m31_add(b34, b48);
    b48 = stwo_m31_add(b95, b72);
    b72 = stwo_m31_add(b59, b73);
    b73 = stwo_m31_add(b60, b74);
    b74 = stwo_m31_add(b61, b75);
    b75 = stwo_m31_mul(b82, b72);
    b61 = stwo_m31_mul(b45, b48);
    b60 = stwo_m31_add(b75, b61);
    b61 = stwo_m31_mul(b82, b73);
    b75 = stwo_m31_mul(b45, b72);
    b59 = stwo_m31_add(b61, b75);
    b75 = stwo_m31_mul(b46, b48);
    b61 = stwo_m31_add(b59, b75);
    b75 = stwo_m31_mul(b82, b74);
    b74 = stwo_m31_mul(b45, b73);
    b73 = stwo_m31_add(b75, b74);
    b74 = stwo_m31_mul(b46, b72);
    b72 = stwo_m31_add(b73, b74);
    b74 = stwo_m31_mul(b47, b48);
    b48 = stwo_m31_add(b72, b74);
    b74 = stwo_m31_sub(b60, b29);
    b60 = stwo_m31_sub(b74, b39);
    b74 = stwo_m31_add(b66, b60);
    b60 = stwo_m31_sub(b61, b30);
    b61 = stwo_m31_sub(b60, b65);
    b60 = stwo_m31_add(b40, b61);
    b61 = stwo_m31_sub(b48, b27);
    b48 = stwo_m31_sub(b61, b69);
    b61 = stwo_m31_add(b70, b48);
    b48 = stwo_m31_sub(b74, b86);
    b74 = stwo_m31_sub(b60, b87);
    b60 = stwo_m31_sub(b61, b88);
    b61 = 2u;
    b88 = stwo_m31_mul(b61, b48);
    b61 = 4u;
    b48 = stwo_m31_mul(b61, b52);
    b61 = stwo_m31_sub(b88, b48);
    b48 = 2u;
    b88 = stwo_m31_mul(b48, b80);
    b48 = stwo_m31_add(b61, b88);
    b88 = 64u;
    b61 = stwo_m31_mul(b88, b53);
    b88 = stwo_m31_add(b48, b61);
    b61 = 2u;
    b48 = stwo_m31_mul(b61, b74);
    b61 = 4u;
    b74 = stwo_m31_mul(b61, b54);
    b61 = stwo_m31_sub(b48, b74);
    b74 = 2u;
    b48 = stwo_m31_mul(b74, b53);
    b74 = stwo_m31_add(b61, b48);
    b48 = 64u;
    b61 = stwo_m31_mul(b48, b24);
    b48 = stwo_m31_add(b74, b61);
    b61 = 2u;
    b74 = stwo_m31_mul(b61, b60);
    b61 = 4u;
    b60 = stwo_m31_mul(b61, b84);
    b61 = stwo_m31_sub(b74, b60);
    b60 = 2u;
    b74 = stwo_m31_mul(b60, b24);
    b60 = stwo_m31_add(b61, b74);
    b74 = 64u;
    b61 = stwo_m31_mul(b74, b68);
    b74 = stwo_m31_add(b60, b61);
    b61 = 512u;
    b60 = stwo_m31_mul(b91, b61);
    b61 = stwo_m31_add(b88, b90);
    b88 = stwo_m31_sub(b60, b61);
    b61 = 512u;
    b60 = stwo_m31_mul(b92, b61);
    b61 = stwo_m31_add(b48, b91);
    b48 = stwo_m31_sub(b60, b61);
    b61 = 512u;
    b60 = stwo_m31_mul(b93, b61);
    b61 = stwo_m31_add(b74, b92);
    b74 = stwo_m31_sub(b60, b61);
    StwoCairoQm31 e0 = { b88, b94, b94, b94 };
    StwoCairoQm31 e1 = { b48, b94, b94, b94 };
    StwoCairoQm31 e2 = { b74, b94, b94, b94 };
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
