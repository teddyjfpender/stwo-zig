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
stwo_cairo_cuda_eval_v1_94c19907d3df381c(
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
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 47u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 48u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 49u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 51u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 52u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 53u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 54u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 55u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 58u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 59u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 60u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 61u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 62u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 63u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 64u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 65u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 66u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 67u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 71u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b96 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b97 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b98 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b99 = stwo_trace_value(arena, *args, 1u, 101u, row, 0);
    unsigned b100 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b101 = 1u;
    unsigned b102 = stwo_m31_sub(b101, b6);
    b101 = stwo_m31_mul(b6, b102);
    b102 = 0u;
    unsigned b103 = 1u;
    unsigned b104 = stwo_m31_sub(b103, b7);
    b103 = stwo_m31_mul(b7, b104);
    b104 = 1u;
    unsigned b105 = stwo_m31_sub(b104, b8);
    b104 = stwo_m31_mul(b8, b105);
    b105 = 1u;
    unsigned b106 = stwo_m31_sub(b105, b9);
    b105 = stwo_m31_mul(b9, b106);
    b106 = 1u;
    unsigned b107 = stwo_m31_sub(b106, b8);
    b106 = stwo_m31_sub(b107, b9);
    b107 = 1u;
    unsigned b108 = stwo_m31_sub(b107, b106);
    b107 = stwo_m31_mul(b106, b108);
    b108 = 1u;
    unsigned b109 = stwo_m31_sub(b108, b10);
    b108 = stwo_m31_mul(b10, b109);
    b109 = 8u;
    unsigned b110 = stwo_m31_mul(b6, b109);
    b109 = 16u;
    unsigned b111 = stwo_m31_mul(b7, b109);
    b109 = stwo_m31_add(b110, b111);
    b111 = 32u;
    b110 = stwo_m31_mul(b8, b111);
    b111 = stwo_m31_add(b109, b110);
    b110 = 64u;
    b109 = stwo_m31_mul(b9, b110);
    b110 = stwo_m31_add(b111, b109);
    b109 = 128u;
    b111 = stwo_m31_mul(b106, b109);
    b109 = stwo_m31_add(b110, b111);
    b111 = 256u;
    b110 = stwo_m31_add(b109, b111);
    b111 = 32u;
    b109 = stwo_m31_mul(b10, b111);
    b111 = 256u;
    b10 = stwo_m31_add(b109, b111);
    b111 = 32768u;
    b109 = stwo_m31_sub(b3, b111);
    b111 = 32768u;
    unsigned b112 = stwo_m31_sub(b5, b111);
    b111 = 1u;
    unsigned b113 = stwo_m31_sub(b111, b112);
    b111 = stwo_m31_mul(b8, b113);
    b113 = stwo_m31_mul(b6, b2);
    b112 = 1u;
    unsigned b114 = stwo_m31_sub(b112, b6);
    b112 = stwo_m31_mul(b114, b1);
    b114 = stwo_m31_add(b113, b112);
    b112 = stwo_m31_sub(b11, b114);
    b114 = stwo_m31_mul(b7, b2);
    b113 = 1u;
    b6 = stwo_m31_sub(b113, b7);
    b113 = stwo_m31_mul(b6, b1);
    b6 = stwo_m31_add(b114, b113);
    b113 = stwo_m31_sub(b12, b6);
    b6 = stwo_m31_mul(b8, b0);
    b8 = stwo_m31_mul(b9, b2);
    b9 = stwo_m31_add(b6, b8);
    b8 = stwo_m31_mul(b106, b1);
    b106 = stwo_m31_add(b9, b8);
    b8 = stwo_m31_sub(b13, b106);
    b106 = stwo_m31_add(b11, b109);
    b109 = 1u;
    b11 = stwo_m31_sub(b99, b109);
    b109 = stwo_m31_mul(b99, b11);
    b11 = stwo_m31_add(b45, b73);
    b73 = stwo_m31_add(b44, b72);
    b72 = stwo_m31_add(b43, b71);
    b71 = stwo_m31_sub(b72, b15);
    b72 = stwo_m31_sub(b71, b99);
    b71 = 4194304u;
    b15 = stwo_m31_mul(b72, b71);
    b71 = stwo_m31_add(b73, b15);
    b15 = stwo_m31_sub(b71, b16);
    b71 = 4194304u;
    b16 = stwo_m31_mul(b15, b71);
    b71 = stwo_m31_add(b11, b16);
    b16 = stwo_m31_sub(b71, b17);
    b71 = 4194304u;
    b17 = stwo_m31_mul(b16, b71);
    b71 = stwo_m31_mul(b17, b17);
    b16 = 1u;
    b11 = stwo_m31_sub(b71, b16);
    b16 = stwo_m31_mul(b17, b11);
    b11 = stwo_m31_add(b48, b76);
    b76 = stwo_m31_add(b47, b75);
    b75 = stwo_m31_add(b46, b74);
    b74 = stwo_m31_add(b75, b17);
    b75 = stwo_m31_sub(b74, b18);
    b74 = 4194304u;
    b18 = stwo_m31_mul(b75, b74);
    b74 = stwo_m31_add(b76, b18);
    b18 = stwo_m31_sub(b74, b19);
    b74 = 4194304u;
    b19 = stwo_m31_mul(b18, b74);
    b74 = stwo_m31_add(b11, b19);
    b19 = stwo_m31_sub(b74, b20);
    b74 = 4194304u;
    b20 = stwo_m31_mul(b19, b74);
    b74 = stwo_m31_mul(b20, b20);
    b19 = 1u;
    b11 = stwo_m31_sub(b74, b19);
    b19 = stwo_m31_mul(b20, b11);
    b11 = stwo_m31_add(b51, b79);
    b79 = stwo_m31_add(b50, b78);
    b78 = stwo_m31_add(b49, b77);
    b77 = stwo_m31_add(b78, b20);
    b78 = stwo_m31_sub(b77, b21);
    b77 = 4194304u;
    b21 = stwo_m31_mul(b78, b77);
    b77 = stwo_m31_add(b79, b21);
    b21 = stwo_m31_sub(b77, b22);
    b77 = 4194304u;
    b22 = stwo_m31_mul(b21, b77);
    b77 = stwo_m31_add(b11, b22);
    b22 = stwo_m31_sub(b77, b23);
    b77 = 4194304u;
    b23 = stwo_m31_mul(b22, b77);
    b77 = stwo_m31_mul(b23, b23);
    b22 = 1u;
    b11 = stwo_m31_sub(b77, b22);
    b22 = stwo_m31_mul(b23, b11);
    b11 = stwo_m31_add(b54, b82);
    b82 = stwo_m31_add(b53, b81);
    b81 = stwo_m31_add(b52, b80);
    b80 = stwo_m31_add(b81, b23);
    b81 = stwo_m31_sub(b80, b24);
    b80 = 4194304u;
    b24 = stwo_m31_mul(b81, b80);
    b80 = stwo_m31_add(b82, b24);
    b24 = stwo_m31_sub(b80, b25);
    b80 = 4194304u;
    b25 = stwo_m31_mul(b24, b80);
    b80 = stwo_m31_add(b11, b25);
    b25 = stwo_m31_sub(b80, b26);
    b80 = 4194304u;
    b26 = stwo_m31_mul(b25, b80);
    b80 = stwo_m31_mul(b26, b26);
    b25 = 1u;
    b11 = stwo_m31_sub(b80, b25);
    b25 = stwo_m31_mul(b26, b11);
    b11 = stwo_m31_add(b57, b85);
    b85 = stwo_m31_add(b56, b84);
    b84 = stwo_m31_add(b55, b83);
    b83 = stwo_m31_add(b84, b26);
    b84 = stwo_m31_sub(b83, b27);
    b83 = 4194304u;
    b27 = stwo_m31_mul(b84, b83);
    b83 = stwo_m31_add(b85, b27);
    b27 = stwo_m31_sub(b83, b28);
    b83 = 4194304u;
    b28 = stwo_m31_mul(b27, b83);
    b83 = stwo_m31_add(b11, b28);
    b28 = stwo_m31_sub(b83, b29);
    b83 = 4194304u;
    b29 = stwo_m31_mul(b28, b83);
    b83 = stwo_m31_mul(b29, b29);
    b28 = 1u;
    b11 = stwo_m31_sub(b83, b28);
    b28 = stwo_m31_mul(b29, b11);
    b11 = stwo_m31_add(b60, b88);
    b88 = stwo_m31_add(b59, b87);
    b87 = stwo_m31_add(b58, b86);
    b86 = stwo_m31_add(b87, b29);
    b87 = stwo_m31_sub(b86, b30);
    b86 = 4194304u;
    b30 = stwo_m31_mul(b87, b86);
    b86 = stwo_m31_add(b88, b30);
    b30 = stwo_m31_sub(b86, b31);
    b86 = 4194304u;
    b31 = stwo_m31_mul(b30, b86);
    b86 = stwo_m31_add(b11, b31);
    b31 = stwo_m31_sub(b86, b32);
    b86 = 4194304u;
    b32 = stwo_m31_mul(b31, b86);
    b86 = stwo_m31_mul(b32, b32);
    b31 = 1u;
    b11 = stwo_m31_sub(b86, b31);
    b31 = stwo_m31_mul(b32, b11);
    b11 = stwo_m31_add(b63, b91);
    b91 = stwo_m31_add(b62, b90);
    b90 = stwo_m31_add(b61, b89);
    b89 = stwo_m31_add(b90, b32);
    b90 = stwo_m31_sub(b89, b33);
    b89 = 4194304u;
    b33 = stwo_m31_mul(b90, b89);
    b89 = stwo_m31_add(b91, b33);
    b33 = stwo_m31_sub(b89, b34);
    b89 = 4194304u;
    b34 = stwo_m31_mul(b33, b89);
    b89 = stwo_m31_add(b11, b34);
    b34 = stwo_m31_sub(b89, b35);
    b89 = 4194304u;
    b35 = stwo_m31_mul(b34, b89);
    b89 = stwo_m31_mul(b35, b35);
    b34 = 1u;
    b11 = stwo_m31_sub(b89, b34);
    b34 = stwo_m31_mul(b35, b11);
    b11 = stwo_m31_add(b66, b94);
    b94 = stwo_m31_add(b65, b93);
    b93 = stwo_m31_add(b64, b92);
    b92 = stwo_m31_add(b93, b35);
    b93 = stwo_m31_sub(b92, b36);
    b92 = 136u;
    b36 = stwo_m31_mul(b92, b99);
    b92 = stwo_m31_sub(b93, b36);
    b36 = 4194304u;
    b93 = stwo_m31_mul(b92, b36);
    b36 = stwo_m31_add(b94, b93);
    b93 = stwo_m31_sub(b36, b37);
    b36 = 4194304u;
    b37 = stwo_m31_mul(b93, b36);
    b36 = stwo_m31_add(b11, b37);
    b37 = stwo_m31_sub(b36, b38);
    b36 = 4194304u;
    b38 = stwo_m31_mul(b37, b36);
    b36 = stwo_m31_mul(b38, b38);
    b37 = 1u;
    b11 = stwo_m31_sub(b36, b37);
    b37 = stwo_m31_mul(b38, b11);
    b11 = stwo_m31_add(b69, b97);
    b97 = stwo_m31_add(b68, b96);
    b96 = stwo_m31_add(b67, b95);
    b95 = stwo_m31_add(b96, b38);
    b96 = stwo_m31_sub(b95, b39);
    b95 = 4194304u;
    b39 = stwo_m31_mul(b96, b95);
    b95 = stwo_m31_add(b97, b39);
    b39 = stwo_m31_sub(b95, b40);
    b95 = 4194304u;
    b40 = stwo_m31_mul(b39, b95);
    b95 = stwo_m31_add(b11, b40);
    b40 = stwo_m31_sub(b95, b41);
    b95 = 4194304u;
    b41 = stwo_m31_mul(b40, b95);
    b95 = stwo_m31_mul(b41, b41);
    b40 = 1u;
    b11 = stwo_m31_sub(b95, b40);
    b40 = stwo_m31_mul(b41, b11);
    b11 = stwo_m31_add(b70, b98);
    b98 = stwo_m31_add(b11, b41);
    b11 = stwo_m31_sub(b98, b42);
    b98 = 256u;
    b42 = stwo_m31_mul(b98, b99);
    b98 = stwo_m31_sub(b11, b42);
    b42 = stwo_m31_mul(b100, b100);
    b11 = stwo_m31_sub(b42, b100);
    b42 = stwo_trace_value(arena, *args, 2u, 0u, row, 0);
    b100 = stwo_trace_value(arena, *args, 2u, 1u, row, 0);
    b99 = stwo_trace_value(arena, *args, 2u, 2u, row, 0);
    b41 = stwo_trace_value(arena, *args, 2u, 3u, row, 0);
    StwoCairoQm31 e0 = { b101, b102, b102, b102 };
    StwoCairoQm31 e1 = { b103, b102, b102, b102 };
    StwoCairoQm31 e2 = { b104, b102, b102, b102 };
    StwoCairoQm31 e3 = { b105, b102, b102, b102 };
    StwoCairoQm31 e4 = { b107, b102, b102, b102 };
    StwoCairoQm31 e5 = { b108, b102, b102, b102 };
    StwoCairoQm31 e6 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e7 = { b0, b102, b102, b102 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    e6 = stwo_qm31_add(e7, e8);
    e7 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    e8 = { b3, b102, b102, b102 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    e6 = { b4, b102, b102, b102 };
    e7 = stwo_qm31_mul(e9, e6);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    e8 = { b5, b102, b102, b102 };
    e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 5u * 4u);
    e6 = { b110, b102, b102, b102 };
    e7 = stwo_qm31_mul(e9, e6);
    e6 = stwo_qm31_add(e8, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 6u * 4u);
    e8 = { b10, b102, b102, b102 };
    e9 = stwo_qm31_mul(e7, e8);
    e8 = stwo_qm31_add(e6, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 7u * 4u);
    e6 = stwo_qm31_sub(e8, e9);
    e9 = { b111, b102, b102, b102 };
    e8 = { b112, b102, b102, b102 };
    e7 = { b113, b102, b102, b102 };
    StwoCairoQm31 e10 = { b8, b102, b102, b102 };
    StwoCairoQm31 e11 = stwo_load_qm31(arena, args->ext_params + 8u * 4u);
    StwoCairoQm31 e12 = { b106, b102, b102, b102 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e11, e12);
    e12 = stwo_load_qm31(arena, args->ext_params + 9u * 4u);
    e11 = stwo_qm31_add(e12, e13);
    e12 = stwo_load_qm31(arena, args->ext_params + 10u * 4u);
    e13 = { b14, b102, b102, b102 };
    StwoCairoQm31 e14 = stwo_qm31_mul(e12, e13);
    e13 = stwo_qm31_add(e11, e14);
    e14 = stwo_load_qm31(arena, args->ext_params + 11u * 4u);
    e11 = stwo_qm31_sub(e13, e14);
    e14 = { b109, b102, b102, b102 };
    e13 = { b16, b102, b102, b102 };
    e12 = { b19, b102, b102, b102 };
    StwoCairoQm31 e15 = { b22, b102, b102, b102 };
    StwoCairoQm31 e16 = { b25, b102, b102, b102 };
    StwoCairoQm31 e17 = { b28, b102, b102, b102 };
    StwoCairoQm31 e18 = { b31, b102, b102, b102 };
    StwoCairoQm31 e19 = { b34, b102, b102, b102 };
    StwoCairoQm31 e20 = { b37, b102, b102, b102 };
    StwoCairoQm31 e21 = { b40, b102, b102, b102 };
    StwoCairoQm31 e22 = { b98, b102, b102, b102 };
    StwoCairoQm31 e23 = { b11, b102, b102, b102 };
    StwoCairoQm31 e24 = stwo_load_qm31(arena, args->ext_params + 123u * 4u);
    StwoCairoQm31 e25 = stwo_qm31_mul(e11, e24);
    e24 = stwo_load_qm31(arena, args->ext_params + 124u * 4u);
    StwoCairoQm31 e26 = stwo_qm31_mul(e6, e24);
    e24 = stwo_qm31_add(e25, e26);
    e26 = stwo_qm31_mul(e6, e11);
    e11 = { b42, b100, b99, b41 };
    e6 = stwo_qm31_mul(e11, e26);
    e11 = stwo_qm31_sub(e6, e24);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e4, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e9, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e8, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 8u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e10, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 9u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e14, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 10u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e13, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 11u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e12, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 12u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e15, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 13u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e16, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 14u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e17, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 15u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e18, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 16u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e19, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 17u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e20, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 18u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e21, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 19u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e22, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 20u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e23, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 21u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e11, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 22u) * 4u)));
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
