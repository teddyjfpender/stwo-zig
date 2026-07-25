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
stwo_cairo_cuda_eval_v1_1794e831df1cfb33(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 62u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 63u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 64u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 65u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 66u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 67u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 71u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 89u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 112u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 113u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 114u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 115u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 116u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 117u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 118u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 119u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 120u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 121u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 122u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 123u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 124u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 126u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 127u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 156u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 157u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 158u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 159u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 160u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 161u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 162u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 163u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 164u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 165u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 166u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 167u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 168u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 169u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 170u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 171u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 172u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 173u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 174u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 175u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 176u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 177u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 178u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 1u, 179u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 1u, 180u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 1u, 181u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 1u, 182u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 1u, 183u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 1u, 184u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 1u, 185u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 1u, 186u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 1u, 187u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 1u, 188u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 1u, 189u, row, 0);
    unsigned b96 = stwo_trace_value(arena, *args, 1u, 190u, row, 0);
    unsigned b97 = stwo_trace_value(arena, *args, 1u, 191u, row, 0);
    unsigned b98 = stwo_trace_value(arena, *args, 1u, 192u, row, 0);
    unsigned b99 = stwo_trace_value(arena, *args, 1u, 193u, row, 0);
    unsigned b100 = stwo_trace_value(arena, *args, 1u, 194u, row, 0);
    unsigned b101 = 0u;
    unsigned b102 = 512u;
    unsigned b103 = stwo_m31_mul(b1, b102);
    b102 = stwo_m31_add(b0, b103);
    b103 = 262144u;
    b0 = stwo_m31_mul(b2, b103);
    b103 = stwo_m31_add(b102, b0);
    b0 = 512u;
    b102 = stwo_m31_mul(b4, b0);
    b0 = stwo_m31_add(b3, b102);
    b102 = 262144u;
    b3 = stwo_m31_mul(b5, b102);
    b102 = stwo_m31_add(b0, b3);
    b3 = 512u;
    b0 = stwo_m31_mul(b7, b3);
    b3 = stwo_m31_add(b6, b0);
    b0 = 262144u;
    b6 = stwo_m31_mul(b8, b0);
    b0 = stwo_m31_add(b3, b6);
    b6 = 512u;
    b3 = stwo_m31_mul(b10, b6);
    b6 = stwo_m31_add(b9, b3);
    b3 = 262144u;
    b9 = stwo_m31_mul(b11, b3);
    b3 = stwo_m31_add(b6, b9);
    b9 = 512u;
    b6 = stwo_m31_mul(b13, b9);
    b9 = stwo_m31_add(b12, b6);
    b6 = 262144u;
    b12 = stwo_m31_mul(b14, b6);
    b6 = stwo_m31_add(b9, b12);
    b12 = 512u;
    b9 = stwo_m31_mul(b16, b12);
    b12 = stwo_m31_add(b15, b9);
    b9 = 262144u;
    b15 = stwo_m31_mul(b17, b9);
    b9 = stwo_m31_add(b12, b15);
    b15 = 512u;
    b12 = stwo_m31_mul(b19, b15);
    b15 = stwo_m31_add(b18, b12);
    b12 = 262144u;
    b18 = stwo_m31_mul(b20, b12);
    b12 = stwo_m31_add(b15, b18);
    b18 = 512u;
    b15 = stwo_m31_mul(b22, b18);
    b18 = stwo_m31_add(b21, b15);
    b15 = 262144u;
    b21 = stwo_m31_mul(b23, b15);
    b15 = stwo_m31_add(b18, b21);
    b21 = 512u;
    b18 = stwo_m31_mul(b25, b21);
    b21 = stwo_m31_add(b24, b18);
    b18 = 262144u;
    b24 = stwo_m31_mul(b26, b18);
    b18 = stwo_m31_add(b21, b24);
    b24 = 4883209u;
    b21 = stwo_m31_add(b103, b24);
    b24 = stwo_m31_sub(b21, b28);
    b21 = stwo_m31_sub(b24, b38);
    b24 = 16u;
    b28 = stwo_m31_mul(b21, b24);
    b24 = stwo_m31_add(b28, b102);
    b102 = 28820206u;
    b21 = stwo_m31_add(b24, b102);
    b102 = stwo_m31_sub(b21, b29);
    b21 = 16u;
    b29 = stwo_m31_mul(b102, b21);
    b21 = stwo_m31_add(b29, b0);
    b0 = 79012328u;
    b102 = stwo_m31_add(b21, b0);
    b0 = stwo_m31_sub(b102, b30);
    b102 = 16u;
    b30 = stwo_m31_mul(b0, b102);
    b102 = stwo_m31_add(b30, b3);
    b3 = 49157069u;
    b0 = stwo_m31_add(b102, b3);
    b3 = stwo_m31_sub(b0, b31);
    b0 = 16u;
    b31 = stwo_m31_mul(b3, b0);
    b0 = stwo_m31_add(b31, b6);
    b6 = 78826183u;
    b3 = stwo_m31_add(b0, b6);
    b6 = stwo_m31_sub(b3, b32);
    b3 = 16u;
    b32 = stwo_m31_mul(b6, b3);
    b3 = stwo_m31_add(b32, b9);
    b9 = 72285071u;
    b6 = stwo_m31_add(b3, b9);
    b9 = stwo_m31_sub(b6, b33);
    b6 = 16u;
    b33 = stwo_m31_mul(b9, b6);
    b6 = stwo_m31_add(b33, b12);
    b12 = 33413160u;
    b9 = stwo_m31_add(b6, b12);
    b12 = stwo_m31_sub(b9, b34);
    b9 = 16u;
    b34 = stwo_m31_mul(b12, b9);
    b9 = stwo_m31_add(b34, b15);
    b15 = 90842759u;
    b12 = stwo_m31_add(b9, b15);
    b15 = stwo_m31_sub(b12, b35);
    b12 = 136u;
    b35 = stwo_m31_mul(b38, b12);
    b12 = stwo_m31_sub(b15, b35);
    b35 = 16u;
    b15 = stwo_m31_mul(b12, b35);
    b35 = stwo_m31_add(b15, b18);
    b18 = 60124463u;
    b12 = stwo_m31_add(b35, b18);
    b18 = stwo_m31_sub(b12, b36);
    b12 = 16u;
    b36 = stwo_m31_mul(b18, b12);
    b12 = stwo_m31_add(b36, b27);
    b27 = 116u;
    b18 = stwo_m31_add(b12, b27);
    b27 = stwo_m31_sub(b18, b37);
    b18 = 256u;
    b37 = stwo_m31_mul(b38, b18);
    b18 = stwo_m31_sub(b27, b37);
    b37 = stwo_m31_mul(b38, b38);
    b27 = stwo_m31_mul(b37, b38);
    b37 = stwo_m31_sub(b27, b38);
    b27 = stwo_m31_mul(b28, b28);
    b38 = stwo_m31_mul(b27, b28);
    b27 = stwo_m31_sub(b38, b28);
    b38 = stwo_m31_mul(b29, b29);
    b28 = stwo_m31_mul(b38, b29);
    b38 = stwo_m31_sub(b28, b29);
    b28 = stwo_m31_mul(b30, b30);
    b29 = stwo_m31_mul(b28, b30);
    b28 = stwo_m31_sub(b29, b30);
    b29 = stwo_m31_mul(b31, b31);
    b30 = stwo_m31_mul(b29, b31);
    b29 = stwo_m31_sub(b30, b31);
    b30 = stwo_m31_mul(b32, b32);
    b31 = stwo_m31_mul(b30, b32);
    b30 = stwo_m31_sub(b31, b32);
    b31 = stwo_m31_mul(b33, b33);
    b32 = stwo_m31_mul(b31, b33);
    b31 = stwo_m31_sub(b32, b33);
    b32 = stwo_m31_mul(b34, b34);
    b33 = stwo_m31_mul(b32, b34);
    b32 = stwo_m31_sub(b33, b34);
    b33 = stwo_m31_mul(b15, b15);
    b34 = stwo_m31_mul(b33, b15);
    b33 = stwo_m31_sub(b34, b15);
    b34 = stwo_m31_mul(b36, b36);
    b15 = stwo_m31_mul(b34, b36);
    b34 = stwo_m31_sub(b15, b36);
    b15 = stwo_m31_add(b39, b49);
    b49 = 2u;
    b36 = stwo_m31_mul(b49, b59);
    b49 = stwo_m31_sub(b15, b36);
    b36 = 103094260u;
    b15 = stwo_m31_add(b49, b36);
    b36 = stwo_m31_sub(b15, b69);
    b15 = stwo_m31_sub(b36, b79);
    b36 = 16u;
    b69 = stwo_m31_mul(b15, b36);
    b36 = stwo_m31_add(b69, b40);
    b69 = stwo_m31_add(b36, b50);
    b36 = 2u;
    b50 = stwo_m31_mul(b36, b60);
    b36 = stwo_m31_sub(b69, b50);
    b50 = 121146754u;
    b69 = stwo_m31_add(b36, b50);
    b50 = stwo_m31_sub(b69, b70);
    b69 = 16u;
    b70 = stwo_m31_mul(b50, b69);
    b69 = stwo_m31_add(b70, b41);
    b70 = stwo_m31_add(b69, b51);
    b69 = 2u;
    b51 = stwo_m31_mul(b69, b61);
    b69 = stwo_m31_sub(b70, b51);
    b51 = 95050340u;
    b70 = stwo_m31_add(b69, b51);
    b51 = stwo_m31_sub(b70, b71);
    b70 = 16u;
    b71 = stwo_m31_mul(b51, b70);
    b70 = stwo_m31_add(b71, b42);
    b71 = stwo_m31_add(b70, b52);
    b70 = 2u;
    b52 = stwo_m31_mul(b70, b62);
    b70 = stwo_m31_sub(b71, b52);
    b52 = 16173996u;
    b71 = stwo_m31_add(b70, b52);
    b52 = stwo_m31_sub(b71, b72);
    b71 = 16u;
    b72 = stwo_m31_mul(b52, b71);
    b71 = stwo_m31_add(b72, b43);
    b72 = stwo_m31_add(b71, b53);
    b71 = 2u;
    b53 = stwo_m31_mul(b71, b63);
    b71 = stwo_m31_sub(b72, b53);
    b53 = 50758155u;
    b72 = stwo_m31_add(b71, b53);
    b53 = stwo_m31_sub(b72, b73);
    b72 = 16u;
    b73 = stwo_m31_mul(b53, b72);
    b72 = stwo_m31_add(b73, b44);
    b73 = stwo_m31_add(b72, b54);
    b72 = 2u;
    b54 = stwo_m31_mul(b72, b64);
    b72 = stwo_m31_sub(b73, b54);
    b54 = 54415179u;
    b73 = stwo_m31_add(b72, b54);
    b54 = stwo_m31_sub(b73, b74);
    b73 = 16u;
    b74 = stwo_m31_mul(b54, b73);
    b73 = stwo_m31_add(b74, b45);
    b74 = stwo_m31_add(b73, b55);
    b73 = 2u;
    b55 = stwo_m31_mul(b73, b65);
    b73 = stwo_m31_sub(b74, b55);
    b55 = 19292069u;
    b74 = stwo_m31_add(b73, b55);
    b55 = stwo_m31_sub(b74, b75);
    b74 = 16u;
    b75 = stwo_m31_mul(b55, b74);
    b74 = stwo_m31_add(b75, b46);
    b75 = stwo_m31_add(b74, b56);
    b74 = 2u;
    b56 = stwo_m31_mul(b74, b66);
    b74 = stwo_m31_sub(b75, b56);
    b56 = 45351266u;
    b75 = stwo_m31_add(b74, b56);
    b56 = stwo_m31_sub(b75, b76);
    b75 = 136u;
    b76 = stwo_m31_mul(b79, b75);
    b75 = stwo_m31_sub(b56, b76);
    b76 = 16u;
    b56 = stwo_m31_mul(b75, b76);
    b76 = stwo_m31_add(b56, b47);
    b56 = stwo_m31_add(b76, b57);
    b76 = 2u;
    b57 = stwo_m31_mul(b76, b67);
    b76 = stwo_m31_sub(b56, b57);
    b57 = 122233508u;
    b56 = stwo_m31_add(b76, b57);
    b57 = stwo_m31_sub(b56, b77);
    b56 = 16u;
    b77 = stwo_m31_mul(b57, b56);
    b56 = stwo_m31_add(b77, b48);
    b77 = stwo_m31_add(b56, b58);
    b56 = 2u;
    b58 = stwo_m31_mul(b56, b68);
    b56 = stwo_m31_sub(b77, b58);
    b58 = 248u;
    b77 = stwo_m31_add(b56, b58);
    b58 = stwo_m31_sub(b77, b78);
    b77 = 256u;
    b78 = stwo_m31_mul(b79, b77);
    b77 = stwo_m31_sub(b58, b78);
    b78 = 4u;
    b58 = stwo_m31_mul(b78, b39);
    b78 = 2u;
    b39 = stwo_m31_mul(b78, b59);
    b78 = stwo_m31_add(b58, b39);
    b39 = 2u;
    b58 = stwo_m31_mul(b39, b80);
    b39 = stwo_m31_sub(b78, b58);
    b58 = 121657377u;
    b78 = stwo_m31_add(b39, b58);
    b58 = stwo_m31_sub(b78, b90);
    b78 = stwo_m31_sub(b58, b100);
    b58 = 16u;
    b90 = stwo_m31_mul(b78, b58);
    b58 = 4u;
    b78 = stwo_m31_mul(b58, b40);
    b58 = stwo_m31_add(b90, b78);
    b78 = 2u;
    b90 = stwo_m31_mul(b78, b60);
    b78 = stwo_m31_add(b58, b90);
    b90 = 2u;
    b58 = stwo_m31_mul(b90, b81);
    b90 = stwo_m31_sub(b78, b58);
    b58 = 112479959u;
    b78 = stwo_m31_add(b90, b58);
    b58 = stwo_m31_sub(b78, b91);
    b78 = 16u;
    b91 = stwo_m31_mul(b58, b78);
    b78 = 4u;
    b58 = stwo_m31_mul(b78, b41);
    b78 = stwo_m31_add(b91, b58);
    b58 = 2u;
    b91 = stwo_m31_mul(b58, b61);
    b58 = stwo_m31_add(b78, b91);
    b91 = 2u;
    b78 = stwo_m31_mul(b91, b82);
    b91 = stwo_m31_sub(b58, b78);
    b78 = 130418270u;
    b58 = stwo_m31_add(b91, b78);
    b78 = stwo_m31_sub(b58, b92);
    b58 = 16u;
    b92 = stwo_m31_mul(b78, b58);
    b58 = 4u;
    b78 = stwo_m31_mul(b58, b42);
    b58 = stwo_m31_add(b92, b78);
    b78 = 2u;
    b92 = stwo_m31_mul(b78, b62);
    b78 = stwo_m31_add(b58, b92);
    b92 = 2u;
    b58 = stwo_m31_mul(b92, b83);
    b92 = stwo_m31_sub(b78, b58);
    b58 = 4974792u;
    b78 = stwo_m31_add(b92, b58);
    b58 = stwo_m31_sub(b78, b93);
    b78 = 16u;
    b93 = stwo_m31_mul(b58, b78);
    b78 = 4u;
    b58 = stwo_m31_mul(b78, b43);
    b78 = stwo_m31_add(b93, b58);
    b58 = 2u;
    b93 = stwo_m31_mul(b58, b63);
    b58 = stwo_m31_add(b78, b93);
    b93 = 2u;
    b78 = stwo_m31_mul(b93, b84);
    b93 = stwo_m31_sub(b58, b78);
    b78 = 59852719u;
    b58 = stwo_m31_add(b93, b78);
    b78 = stwo_m31_sub(b58, b94);
    b58 = 16u;
    b94 = stwo_m31_mul(b78, b58);
    b58 = 4u;
    b78 = stwo_m31_mul(b58, b44);
    b58 = stwo_m31_add(b94, b78);
    b78 = 2u;
    b94 = stwo_m31_mul(b78, b64);
    b78 = stwo_m31_add(b58, b94);
    b94 = 2u;
    b58 = stwo_m31_mul(b94, b85);
    b94 = stwo_m31_sub(b78, b58);
    b58 = 120369218u;
    b78 = stwo_m31_add(b94, b58);
    b58 = stwo_m31_sub(b78, b95);
    b78 = 16u;
    b95 = stwo_m31_mul(b58, b78);
    b78 = 4u;
    b58 = stwo_m31_mul(b78, b45);
    b78 = stwo_m31_add(b95, b58);
    b58 = 2u;
    b95 = stwo_m31_mul(b58, b65);
    b58 = stwo_m31_add(b78, b95);
    b95 = 2u;
    b78 = stwo_m31_mul(b95, b86);
    b95 = stwo_m31_sub(b58, b78);
    b78 = 62439890u;
    b58 = stwo_m31_add(b95, b78);
    b78 = stwo_m31_sub(b58, b96);
    b58 = 16u;
    b96 = stwo_m31_mul(b78, b58);
    b58 = 4u;
    b78 = stwo_m31_mul(b58, b46);
    b58 = stwo_m31_add(b96, b78);
    b78 = 2u;
    b96 = stwo_m31_mul(b78, b66);
    b78 = stwo_m31_add(b58, b96);
    b96 = 2u;
    b58 = stwo_m31_mul(b96, b87);
    b96 = stwo_m31_sub(b78, b58);
    b58 = 50468641u;
    b78 = stwo_m31_add(b96, b58);
    b58 = stwo_m31_sub(b78, b97);
    b78 = 136u;
    b97 = stwo_m31_mul(b100, b78);
    b78 = stwo_m31_sub(b58, b97);
    b97 = 16u;
    b58 = stwo_m31_mul(b78, b97);
    b97 = 4u;
    b78 = stwo_m31_mul(b97, b47);
    b97 = stwo_m31_add(b58, b78);
    b78 = 2u;
    b58 = stwo_m31_mul(b78, b67);
    b78 = stwo_m31_add(b97, b58);
    b58 = 2u;
    b97 = stwo_m31_mul(b58, b88);
    b58 = stwo_m31_sub(b78, b97);
    b97 = 86573645u;
    b78 = stwo_m31_add(b58, b97);
    b97 = stwo_m31_sub(b78, b98);
    b78 = 16u;
    b98 = stwo_m31_mul(b97, b78);
    b78 = 4u;
    b97 = stwo_m31_mul(b78, b48);
    b78 = stwo_m31_add(b98, b97);
    b97 = 2u;
    b98 = stwo_m31_mul(b97, b68);
    b97 = stwo_m31_add(b78, b98);
    b98 = 2u;
    b78 = stwo_m31_mul(b98, b89);
    b98 = stwo_m31_sub(b97, b78);
    b78 = 154u;
    b97 = stwo_m31_add(b98, b78);
    b78 = stwo_m31_sub(b97, b99);
    b97 = 256u;
    b99 = stwo_m31_mul(b100, b97);
    b97 = stwo_m31_sub(b78, b99);
    StwoCairoQm31 e0 = { b18, b101, b101, b101 };
    StwoCairoQm31 e1 = { b37, b101, b101, b101 };
    StwoCairoQm31 e2 = { b27, b101, b101, b101 };
    StwoCairoQm31 e3 = { b38, b101, b101, b101 };
    StwoCairoQm31 e4 = { b28, b101, b101, b101 };
    StwoCairoQm31 e5 = { b29, b101, b101, b101 };
    StwoCairoQm31 e6 = { b30, b101, b101, b101 };
    StwoCairoQm31 e7 = { b31, b101, b101, b101 };
    StwoCairoQm31 e8 = { b32, b101, b101, b101 };
    StwoCairoQm31 e9 = { b33, b101, b101, b101 };
    StwoCairoQm31 e10 = { b34, b101, b101, b101 };
    StwoCairoQm31 e11 = { b77, b101, b101, b101 };
    StwoCairoQm31 e12 = { b97, b101, b101, b101 };
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
