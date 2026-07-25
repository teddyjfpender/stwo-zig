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
stwo_cairo_cuda_eval_v1_11631bfcb1515c22(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 0u, 0u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 41u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 42u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 43u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 47u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 48u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 49u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 51u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 52u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 53u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 54u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 55u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 58u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 90u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 91u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 95u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 96u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 97u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 98u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 101u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 102u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 103u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 104u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 105u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 107u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 108u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 109u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 110u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 111u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 112u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 113u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 114u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 115u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 116u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 117u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 118u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 119u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 120u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 121u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 122u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 123u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 124u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 126u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 127u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 1u, 143u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 1u, 144u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 1u, 145u, row, 0);
    unsigned b96 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b97 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b98 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b99 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b100 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b101 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b102 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b103 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b104 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b105 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b106 = stwo_trace_value(arena, *args, 1u, 156u, row, 0);
    unsigned b107 = stwo_trace_value(arena, *args, 1u, 157u, row, 0);
    unsigned b108 = stwo_trace_value(arena, *args, 1u, 158u, row, 0);
    unsigned b109 = stwo_trace_value(arena, *args, 1u, 159u, row, 0);
    unsigned b110 = stwo_trace_value(arena, *args, 1u, 160u, row, 0);
    unsigned b111 = stwo_trace_value(arena, *args, 1u, 161u, row, 0);
    unsigned b112 = stwo_trace_value(arena, *args, 1u, 162u, row, 0);
    unsigned b113 = stwo_trace_value(arena, *args, 1u, 163u, row, 0);
    unsigned b114 = stwo_trace_value(arena, *args, 1u, 164u, row, 0);
    unsigned b115 = stwo_trace_value(arena, *args, 1u, 165u, row, 0);
    unsigned b116 = stwo_trace_value(arena, *args, 1u, 166u, row, 0);
    unsigned b117 = stwo_trace_value(arena, *args, 1u, 167u, row, 0);
    unsigned b118 = stwo_trace_value(arena, *args, 1u, 168u, row, 0);
    unsigned b119 = stwo_trace_value(arena, *args, 1u, 169u, row, 0);
    unsigned b120 = stwo_trace_value(arena, *args, 1u, 170u, row, 0);
    unsigned b121 = stwo_trace_value(arena, *args, 1u, 171u, row, 0);
    unsigned b122 = stwo_trace_value(arena, *args, 1u, 172u, row, 0);
    unsigned b123 = stwo_trace_value(arena, *args, 1u, 173u, row, 0);
    unsigned b124 = stwo_trace_value(arena, *args, 1u, 174u, row, 0);
    unsigned b125 = stwo_trace_value(arena, *args, 1u, 175u, row, 0);
    unsigned b126 = stwo_trace_value(arena, *args, 1u, 176u, row, 0);
    unsigned b127 = stwo_trace_value(arena, *args, 1u, 177u, row, 0);
    unsigned b128 = stwo_trace_value(arena, *args, 1u, 178u, row, 0);
    unsigned b129 = stwo_trace_value(arena, *args, 1u, 179u, row, 0);
    unsigned b130 = stwo_trace_value(arena, *args, 1u, 180u, row, 0);
    unsigned b131 = stwo_trace_value(arena, *args, 1u, 181u, row, 0);
    unsigned b132 = stwo_trace_value(arena, *args, 1u, 182u, row, 0);
    unsigned b133 = stwo_trace_value(arena, *args, 1u, 183u, row, 0);
    unsigned b134 = stwo_trace_value(arena, *args, 1u, 184u, row, 0);
    unsigned b135 = stwo_trace_value(arena, *args, 1u, 185u, row, 0);
    unsigned b136 = stwo_trace_value(arena, *args, 1u, 186u, row, 0);
    unsigned b137 = stwo_trace_value(arena, *args, 1u, 187u, row, 0);
    unsigned b138 = stwo_trace_value(arena, *args, 1u, 188u, row, 0);
    unsigned b139 = stwo_trace_value(arena, *args, 1u, 189u, row, 0);
    unsigned b140 = stwo_trace_value(arena, *args, 1u, 190u, row, 0);
    unsigned b141 = stwo_trace_value(arena, *args, 1u, 191u, row, 0);
    unsigned b142 = stwo_trace_value(arena, *args, 1u, 192u, row, 0);
    unsigned b143 = stwo_trace_value(arena, *args, 1u, 193u, row, 0);
    unsigned b144 = stwo_trace_value(arena, *args, 1u, 194u, row, 0);
    unsigned b145 = stwo_trace_value(arena, *args, 1u, 195u, row, 0);
    unsigned b146 = stwo_trace_value(arena, *args, 1u, 196u, row, 0);
    unsigned b147 = stwo_trace_value(arena, *args, 1u, 197u, row, 0);
    unsigned b148 = stwo_trace_value(arena, *args, 1u, 198u, row, 0);
    unsigned b149 = stwo_trace_value(arena, *args, 1u, 199u, row, 0);
    unsigned b150 = stwo_trace_value(arena, *args, 1u, 200u, row, 0);
    unsigned b151 = stwo_trace_value(arena, *args, 1u, 201u, row, 0);
    unsigned b152 = stwo_trace_value(arena, *args, 1u, 202u, row, 0);
    unsigned b153 = stwo_trace_value(arena, *args, 1u, 203u, row, 0);
    unsigned b154 = stwo_trace_value(arena, *args, 1u, 204u, row, 0);
    unsigned b155 = 0u;
    unsigned b156 = 2u;
    unsigned b157 = stwo_m31_mul(b0, b156);
    b156 = 1u;
    b0 = stwo_m31_add(b157, b156);
    b156 = 512u;
    b157 = stwo_m31_mul(b2, b156);
    b156 = stwo_m31_add(b1, b157);
    b157 = 512u;
    b1 = stwo_m31_mul(b4, b157);
    b157 = stwo_m31_add(b3, b1);
    b1 = 512u;
    b3 = stwo_m31_mul(b6, b1);
    b1 = stwo_m31_add(b5, b3);
    b3 = 512u;
    b5 = stwo_m31_mul(b8, b3);
    b3 = stwo_m31_add(b7, b5);
    b5 = 512u;
    b7 = stwo_m31_mul(b10, b5);
    b5 = stwo_m31_add(b9, b7);
    b7 = 512u;
    b9 = stwo_m31_mul(b12, b7);
    b7 = stwo_m31_add(b11, b9);
    b9 = 512u;
    b11 = stwo_m31_mul(b14, b9);
    b9 = stwo_m31_add(b13, b11);
    b11 = 512u;
    b13 = stwo_m31_mul(b16, b11);
    b11 = stwo_m31_add(b15, b13);
    b13 = 512u;
    b15 = stwo_m31_mul(b18, b13);
    b13 = stwo_m31_add(b17, b15);
    b15 = 512u;
    b17 = stwo_m31_mul(b20, b15);
    b15 = stwo_m31_add(b19, b17);
    b17 = 512u;
    b19 = stwo_m31_mul(b22, b17);
    b17 = stwo_m31_add(b21, b19);
    b19 = 512u;
    b21 = stwo_m31_mul(b24, b19);
    b19 = stwo_m31_add(b23, b21);
    b21 = 512u;
    b23 = stwo_m31_mul(b26, b21);
    b21 = stwo_m31_add(b25, b23);
    b23 = 512u;
    b25 = stwo_m31_mul(b28, b23);
    b23 = stwo_m31_add(b27, b25);
    b25 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    b27 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    b28 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    b26 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    b24 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    b22 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    b20 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    b18 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 222u * 4u);
    StwoCairoQm31 e1 = { b0, b155, b155, b155 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 223u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 224u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 225u * 4u);
    e0 = { b156, b155, b155, b155 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 226u * 4u);
    e2 = { b157, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 227u * 4u);
    e0 = { b1, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 228u * 4u);
    e2 = { b3, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 229u * 4u);
    e0 = { b5, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 230u * 4u);
    e2 = { b7, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 231u * 4u);
    e0 = { b9, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 232u * 4u);
    e2 = { b11, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 233u * 4u);
    e0 = { b13, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 234u * 4u);
    e2 = { b15, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 235u * 4u);
    e0 = { b17, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 236u * 4u);
    e2 = { b19, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 237u * 4u);
    e0 = { b21, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 238u * 4u);
    e2 = { b23, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 239u * 4u);
    e0 = { b29, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 240u * 4u);
    e2 = { b30, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 241u * 4u);
    e0 = { b31, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 242u * 4u);
    e2 = { b32, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 243u * 4u);
    e0 = { b33, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 244u * 4u);
    e2 = { b34, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 245u * 4u);
    e0 = { b35, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 246u * 4u);
    e2 = { b36, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 247u * 4u);
    e0 = { b37, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 248u * 4u);
    e2 = { b38, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 249u * 4u);
    e0 = { b39, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 250u * 4u);
    e2 = { b40, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 251u * 4u);
    e0 = { b41, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 252u * 4u);
    e2 = { b42, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 253u * 4u);
    e0 = { b43, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 254u * 4u);
    e2 = { b44, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 255u * 4u);
    e0 = { b45, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 256u * 4u);
    e2 = { b46, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 257u * 4u);
    e0 = { b47, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 258u * 4u);
    e2 = { b48, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 259u * 4u);
    e0 = { b49, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 260u * 4u);
    e2 = { b50, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 261u * 4u);
    e0 = { b51, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 262u * 4u);
    e2 = { b52, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 263u * 4u);
    e0 = { b53, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 264u * 4u);
    e2 = { b54, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 265u * 4u);
    e0 = { b55, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 266u * 4u);
    e2 = { b56, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 267u * 4u);
    e0 = { b57, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 268u * 4u);
    e2 = { b58, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 269u * 4u);
    e0 = { b59, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 270u * 4u);
    e2 = { b60, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 271u * 4u);
    e0 = { b61, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 272u * 4u);
    e2 = { b62, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 273u * 4u);
    e0 = { b63, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 274u * 4u);
    e2 = { b64, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 275u * 4u);
    e0 = { b65, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 276u * 4u);
    e2 = { b66, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 277u * 4u);
    e0 = { b67, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 278u * 4u);
    e2 = { b68, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 279u * 4u);
    e0 = { b69, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 280u * 4u);
    e2 = { b70, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 281u * 4u);
    e0 = { b71, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 282u * 4u);
    e2 = { b72, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 283u * 4u);
    e0 = { b73, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 284u * 4u);
    e2 = { b74, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 285u * 4u);
    e0 = { b75, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 286u * 4u);
    e2 = { b76, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 287u * 4u);
    e0 = { b77, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 288u * 4u);
    e2 = { b78, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 289u * 4u);
    e0 = { b79, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 290u * 4u);
    e2 = { b80, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 291u * 4u);
    e0 = { b81, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 292u * 4u);
    e2 = { b82, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 293u * 4u);
    e0 = { b83, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 294u * 4u);
    e2 = { b84, b155, b155, b155 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 295u * 4u);
    e0 = stwo_qm31_sub(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 296u * 4u);
    e2 = { b0, b155, b155, b155 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 297u * 4u);
    e1 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(arena, args->ext_params + 298u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 299u * 4u);
    e1 = { b85, b155, b155, b155 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 300u * 4u);
    e3 = { b86, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 301u * 4u);
    e1 = { b87, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 302u * 4u);
    e3 = { b88, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 303u * 4u);
    e1 = { b89, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 304u * 4u);
    e3 = { b90, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 305u * 4u);
    e1 = { b91, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 306u * 4u);
    e3 = { b92, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 307u * 4u);
    e1 = { b93, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 308u * 4u);
    e3 = { b94, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 309u * 4u);
    e1 = { b95, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 310u * 4u);
    e3 = { b96, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 311u * 4u);
    e1 = { b97, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 312u * 4u);
    e3 = { b98, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 313u * 4u);
    e1 = { b99, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 314u * 4u);
    e3 = { b100, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 315u * 4u);
    e1 = { b101, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 316u * 4u);
    e3 = { b102, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 317u * 4u);
    e1 = { b103, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 318u * 4u);
    e3 = { b104, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 319u * 4u);
    e1 = { b105, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 320u * 4u);
    e3 = { b106, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 321u * 4u);
    e1 = { b107, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 322u * 4u);
    e3 = { b108, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 323u * 4u);
    e1 = { b109, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 324u * 4u);
    e3 = { b110, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 325u * 4u);
    e1 = { b111, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 326u * 4u);
    e3 = { b112, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 327u * 4u);
    e1 = { b113, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 328u * 4u);
    e3 = { b114, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 329u * 4u);
    e1 = { b115, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 330u * 4u);
    e3 = { b116, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 331u * 4u);
    e1 = { b117, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 332u * 4u);
    e3 = { b118, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 333u * 4u);
    e1 = { b119, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 334u * 4u);
    e3 = { b120, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 335u * 4u);
    e1 = { b121, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 336u * 4u);
    e3 = { b122, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 337u * 4u);
    e1 = { b123, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 338u * 4u);
    e3 = { b124, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 339u * 4u);
    e1 = { b125, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 340u * 4u);
    e3 = { b126, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 341u * 4u);
    e1 = { b127, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 342u * 4u);
    e3 = { b128, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 343u * 4u);
    e1 = { b129, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 344u * 4u);
    e3 = { b130, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 345u * 4u);
    e1 = { b131, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 346u * 4u);
    e3 = { b132, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 347u * 4u);
    e1 = { b133, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 348u * 4u);
    e3 = { b134, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 349u * 4u);
    e1 = { b135, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 350u * 4u);
    e3 = { b136, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 351u * 4u);
    e1 = { b137, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 352u * 4u);
    e3 = { b138, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 353u * 4u);
    e1 = { b139, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 354u * 4u);
    e3 = { b140, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 355u * 4u);
    e1 = { b141, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 356u * 4u);
    e3 = { b142, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 357u * 4u);
    e1 = { b143, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 358u * 4u);
    e3 = { b144, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 359u * 4u);
    e1 = { b145, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 360u * 4u);
    e3 = { b146, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 361u * 4u);
    e1 = { b147, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 362u * 4u);
    e3 = { b148, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 363u * 4u);
    e1 = { b149, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 364u * 4u);
    e3 = { b150, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 365u * 4u);
    e1 = { b151, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 366u * 4u);
    e3 = { b152, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 367u * 4u);
    e1 = { b153, b155, b155, b155 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 368u * 4u);
    e3 = { b154, b155, b155, b155 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 369u * 4u);
    e1 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 414u * 4u);
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 415u * 4u);
    e4 = stwo_qm31_mul(e0, e2);
    e2 = stwo_qm31_add(e3, e4);
    e4 = stwo_qm31_mul(e0, e1);
    e1 = { b25, b27, b28, b26 };
    e0 = { b24, b22, b20, b18 };
    e3 = stwo_qm31_sub(e0, e1);
    e0 = stwo_qm31_mul(e3, e4);
    e3 = stwo_qm31_sub(e0, e2);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
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
