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
stwo_cairo_cuda_eval_v1_1a83a8b54ea69f43(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 41u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 42u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 43u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 47u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 48u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 49u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 51u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 52u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 53u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 54u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 55u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 58u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 59u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 60u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 61u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 62u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 63u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 64u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 65u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 66u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 67u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 71u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 101u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 103u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 104u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 105u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 107u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 108u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 109u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 110u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 111u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 112u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 113u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 114u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 115u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 116u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 1u, 117u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 1u, 118u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 1u, 119u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 1u, 120u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 1u, 121u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 1u, 122u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 1u, 123u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 1u, 124u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b94 = 0u;
    unsigned b95 = 3u;
    unsigned b96 = stwo_m31_mul(b95, b0);
    b95 = stwo_m31_add(b96, b10);
    b96 = stwo_m31_add(b95, b20);
    b95 = stwo_m31_add(b96, b30);
    b96 = stwo_m31_sub(b95, b60);
    b95 = stwo_m31_sub(b96, b70);
    b96 = 16u;
    b60 = stwo_m31_mul(b95, b96);
    b96 = 3u;
    b95 = stwo_m31_mul(b96, b1);
    b96 = stwo_m31_add(b60, b95);
    b95 = stwo_m31_add(b96, b11);
    b96 = stwo_m31_add(b95, b21);
    b95 = stwo_m31_add(b96, b31);
    b96 = stwo_m31_sub(b95, b61);
    b95 = 16u;
    b61 = stwo_m31_mul(b96, b95);
    b95 = 3u;
    b96 = stwo_m31_mul(b95, b2);
    b95 = stwo_m31_add(b61, b96);
    b96 = stwo_m31_add(b95, b12);
    b95 = stwo_m31_add(b96, b22);
    b96 = stwo_m31_add(b95, b32);
    b95 = stwo_m31_sub(b96, b62);
    b96 = 16u;
    b62 = stwo_m31_mul(b95, b96);
    b96 = 3u;
    b95 = stwo_m31_mul(b96, b3);
    b96 = stwo_m31_add(b62, b95);
    b95 = stwo_m31_add(b96, b13);
    b96 = stwo_m31_add(b95, b23);
    b95 = stwo_m31_add(b96, b33);
    b96 = stwo_m31_sub(b95, b63);
    b95 = 16u;
    b63 = stwo_m31_mul(b96, b95);
    b95 = 3u;
    b96 = stwo_m31_mul(b95, b4);
    b95 = stwo_m31_add(b63, b96);
    b96 = stwo_m31_add(b95, b14);
    b95 = stwo_m31_add(b96, b24);
    b96 = stwo_m31_add(b95, b34);
    b95 = stwo_m31_sub(b96, b64);
    b96 = 16u;
    b64 = stwo_m31_mul(b95, b96);
    b96 = 3u;
    b95 = stwo_m31_mul(b96, b5);
    b96 = stwo_m31_add(b64, b95);
    b95 = stwo_m31_add(b96, b15);
    b96 = stwo_m31_add(b95, b25);
    b95 = stwo_m31_add(b96, b35);
    b96 = stwo_m31_sub(b95, b65);
    b95 = 16u;
    b65 = stwo_m31_mul(b96, b95);
    b95 = 3u;
    b96 = stwo_m31_mul(b95, b6);
    b95 = stwo_m31_add(b65, b96);
    b96 = stwo_m31_add(b95, b16);
    b95 = stwo_m31_add(b96, b26);
    b96 = stwo_m31_add(b95, b36);
    b95 = stwo_m31_sub(b96, b66);
    b96 = 16u;
    b66 = stwo_m31_mul(b95, b96);
    b96 = 3u;
    b95 = stwo_m31_mul(b96, b7);
    b96 = stwo_m31_add(b66, b95);
    b95 = stwo_m31_add(b96, b17);
    b96 = stwo_m31_add(b95, b27);
    b95 = stwo_m31_add(b96, b37);
    b96 = stwo_m31_sub(b95, b67);
    b95 = 136u;
    b67 = stwo_m31_mul(b70, b95);
    b95 = stwo_m31_sub(b96, b67);
    b67 = 16u;
    b96 = stwo_m31_mul(b95, b67);
    b67 = 3u;
    b95 = stwo_m31_mul(b67, b8);
    b67 = stwo_m31_add(b96, b95);
    b95 = stwo_m31_add(b67, b18);
    b67 = stwo_m31_add(b95, b28);
    b95 = stwo_m31_add(b67, b38);
    b67 = stwo_m31_sub(b95, b68);
    b95 = 16u;
    b68 = stwo_m31_mul(b67, b95);
    b95 = 3u;
    b67 = stwo_m31_mul(b95, b9);
    b95 = stwo_m31_add(b68, b67);
    b67 = stwo_m31_add(b95, b19);
    b95 = stwo_m31_add(b67, b29);
    b67 = stwo_m31_add(b95, b39);
    b95 = stwo_m31_sub(b67, b69);
    b67 = 256u;
    b69 = stwo_m31_mul(b70, b67);
    b67 = stwo_m31_sub(b95, b69);
    b69 = stwo_m31_sub(b0, b10);
    b95 = stwo_m31_add(b69, b20);
    b69 = stwo_m31_add(b95, b40);
    b95 = stwo_m31_sub(b69, b71);
    b69 = stwo_m31_sub(b95, b81);
    b95 = 16u;
    b71 = stwo_m31_mul(b69, b95);
    b95 = stwo_m31_add(b71, b1);
    b71 = stwo_m31_sub(b95, b11);
    b95 = stwo_m31_add(b71, b21);
    b71 = stwo_m31_add(b95, b41);
    b95 = stwo_m31_sub(b71, b72);
    b71 = 16u;
    b72 = stwo_m31_mul(b95, b71);
    b71 = stwo_m31_add(b72, b2);
    b72 = stwo_m31_sub(b71, b12);
    b71 = stwo_m31_add(b72, b22);
    b72 = stwo_m31_add(b71, b42);
    b71 = stwo_m31_sub(b72, b73);
    b72 = 16u;
    b73 = stwo_m31_mul(b71, b72);
    b72 = stwo_m31_add(b73, b3);
    b73 = stwo_m31_sub(b72, b13);
    b72 = stwo_m31_add(b73, b23);
    b73 = stwo_m31_add(b72, b43);
    b72 = stwo_m31_sub(b73, b74);
    b73 = 16u;
    b74 = stwo_m31_mul(b72, b73);
    b73 = stwo_m31_add(b74, b4);
    b74 = stwo_m31_sub(b73, b14);
    b73 = stwo_m31_add(b74, b24);
    b74 = stwo_m31_add(b73, b44);
    b73 = stwo_m31_sub(b74, b75);
    b74 = 16u;
    b75 = stwo_m31_mul(b73, b74);
    b74 = stwo_m31_add(b75, b5);
    b75 = stwo_m31_sub(b74, b15);
    b74 = stwo_m31_add(b75, b25);
    b75 = stwo_m31_add(b74, b45);
    b74 = stwo_m31_sub(b75, b76);
    b75 = 16u;
    b76 = stwo_m31_mul(b74, b75);
    b75 = stwo_m31_add(b76, b6);
    b76 = stwo_m31_sub(b75, b16);
    b75 = stwo_m31_add(b76, b26);
    b76 = stwo_m31_add(b75, b46);
    b75 = stwo_m31_sub(b76, b77);
    b76 = 16u;
    b77 = stwo_m31_mul(b75, b76);
    b76 = stwo_m31_add(b77, b7);
    b77 = stwo_m31_sub(b76, b17);
    b76 = stwo_m31_add(b77, b27);
    b77 = stwo_m31_add(b76, b47);
    b76 = stwo_m31_sub(b77, b78);
    b77 = 136u;
    b78 = stwo_m31_mul(b81, b77);
    b77 = stwo_m31_sub(b76, b78);
    b78 = 16u;
    b76 = stwo_m31_mul(b77, b78);
    b78 = stwo_m31_add(b76, b8);
    b76 = stwo_m31_sub(b78, b18);
    b78 = stwo_m31_add(b76, b28);
    b76 = stwo_m31_add(b78, b48);
    b78 = stwo_m31_sub(b76, b79);
    b76 = 16u;
    b79 = stwo_m31_mul(b78, b76);
    b76 = stwo_m31_add(b79, b9);
    b79 = stwo_m31_sub(b76, b19);
    b76 = stwo_m31_add(b79, b29);
    b79 = stwo_m31_add(b76, b49);
    b76 = stwo_m31_sub(b79, b80);
    b79 = 256u;
    b80 = stwo_m31_mul(b81, b79);
    b79 = stwo_m31_sub(b76, b80);
    b80 = stwo_m31_add(b0, b10);
    b10 = 2u;
    b0 = stwo_m31_mul(b10, b20);
    b10 = stwo_m31_sub(b80, b0);
    b0 = stwo_m31_add(b10, b50);
    b10 = stwo_m31_sub(b0, b82);
    b0 = stwo_m31_sub(b10, b92);
    b10 = 16u;
    b82 = stwo_m31_mul(b0, b10);
    b10 = stwo_m31_add(b82, b1);
    b82 = stwo_m31_add(b10, b11);
    b10 = 2u;
    b11 = stwo_m31_mul(b10, b21);
    b10 = stwo_m31_sub(b82, b11);
    b11 = stwo_m31_add(b10, b51);
    b10 = stwo_m31_sub(b11, b83);
    b11 = 16u;
    b83 = stwo_m31_mul(b10, b11);
    b11 = stwo_m31_add(b83, b2);
    b83 = stwo_m31_add(b11, b12);
    b11 = 2u;
    b12 = stwo_m31_mul(b11, b22);
    b11 = stwo_m31_sub(b83, b12);
    b12 = stwo_m31_add(b11, b52);
    b11 = stwo_m31_sub(b12, b84);
    b12 = 16u;
    b84 = stwo_m31_mul(b11, b12);
    b12 = stwo_m31_add(b84, b3);
    b84 = stwo_m31_add(b12, b13);
    b12 = 2u;
    b13 = stwo_m31_mul(b12, b23);
    b12 = stwo_m31_sub(b84, b13);
    b13 = stwo_m31_add(b12, b53);
    b12 = stwo_m31_sub(b13, b85);
    b13 = 16u;
    b85 = stwo_m31_mul(b12, b13);
    b13 = stwo_m31_add(b85, b4);
    b85 = stwo_m31_add(b13, b14);
    b13 = 2u;
    b14 = stwo_m31_mul(b13, b24);
    b13 = stwo_m31_sub(b85, b14);
    b14 = stwo_m31_add(b13, b54);
    b13 = stwo_m31_sub(b14, b86);
    b14 = 16u;
    b86 = stwo_m31_mul(b13, b14);
    b14 = stwo_m31_add(b86, b5);
    b86 = stwo_m31_add(b14, b15);
    b14 = 2u;
    b15 = stwo_m31_mul(b14, b25);
    b14 = stwo_m31_sub(b86, b15);
    b15 = stwo_m31_add(b14, b55);
    b14 = stwo_m31_sub(b15, b87);
    b15 = 16u;
    b87 = stwo_m31_mul(b14, b15);
    b15 = stwo_m31_add(b87, b6);
    b87 = stwo_m31_add(b15, b16);
    b15 = 2u;
    b16 = stwo_m31_mul(b15, b26);
    b15 = stwo_m31_sub(b87, b16);
    b16 = stwo_m31_add(b15, b56);
    b15 = stwo_m31_sub(b16, b88);
    b16 = 16u;
    b88 = stwo_m31_mul(b15, b16);
    b16 = stwo_m31_add(b88, b7);
    b88 = stwo_m31_add(b16, b17);
    b16 = 2u;
    b17 = stwo_m31_mul(b16, b27);
    b16 = stwo_m31_sub(b88, b17);
    b17 = stwo_m31_add(b16, b57);
    b16 = stwo_m31_sub(b17, b89);
    b17 = 136u;
    b89 = stwo_m31_mul(b92, b17);
    b17 = stwo_m31_sub(b16, b89);
    b89 = 16u;
    b16 = stwo_m31_mul(b17, b89);
    b89 = stwo_m31_add(b16, b8);
    b16 = stwo_m31_add(b89, b18);
    b89 = 2u;
    b18 = stwo_m31_mul(b89, b28);
    b89 = stwo_m31_sub(b16, b18);
    b18 = stwo_m31_add(b89, b58);
    b89 = stwo_m31_sub(b18, b90);
    b18 = 16u;
    b90 = stwo_m31_mul(b89, b18);
    b18 = stwo_m31_add(b90, b9);
    b90 = stwo_m31_add(b18, b19);
    b18 = 2u;
    b19 = stwo_m31_mul(b18, b29);
    b18 = stwo_m31_sub(b90, b19);
    b19 = stwo_m31_add(b18, b59);
    b18 = stwo_m31_sub(b19, b91);
    b19 = 256u;
    b91 = stwo_m31_mul(b92, b19);
    b19 = stwo_m31_sub(b18, b91);
    b91 = stwo_m31_mul(b93, b93);
    b18 = stwo_m31_sub(b91, b93);
    StwoCairoQm31 e0 = { b67, b94, b94, b94 };
    StwoCairoQm31 e1 = { b79, b94, b94, b94 };
    StwoCairoQm31 e2 = { b19, b94, b94, b94 };
    StwoCairoQm31 e3 = { b18, b94, b94, b94 };
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
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
