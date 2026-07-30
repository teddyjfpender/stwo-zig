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
stwo_cairo_cuda_eval_v1_62765d4b6a9e2ef1(
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
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 135u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 159u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 160u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 169u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 170u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 171u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 172u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 179u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 180u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 181u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 182u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 183u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 184u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 185u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 186u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 187u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 188u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 189u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 190u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 191u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 192u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 193u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 194u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 195u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 196u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 197u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 198u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 199u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 200u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 201u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 202u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 203u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 204u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 205u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 206u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 207u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 208u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 209u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 210u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 211u, row, 0);
    unsigned b80 = 0u;
    unsigned b81 = 1u;
    unsigned b82 = stwo_m31_add(b1, b81);
    b81 = stwo_trace_value(arena, *args, 2u, 108u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 109u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 110u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 2u, 111u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 112u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 2u, 113u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 2u, 114u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 2u, 115u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 2u, 116u, row, -1);
    unsigned b91 = stwo_trace_value(arena, *args, 2u, 116u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 2u, 117u, row, -1);
    unsigned b93 = stwo_trace_value(arena, *args, 2u, 117u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 2u, 118u, row, -1);
    unsigned b95 = stwo_trace_value(arena, *args, 2u, 118u, row, 0);
    unsigned b96 = stwo_trace_value(arena, *args, 2u, 119u, row, -1);
    unsigned b97 = stwo_trace_value(arena, *args, 2u, 119u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 813u * 4u);
    StwoCairoQm31 e1 = { b45, b80, b80, b80 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 814u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 815u * 4u);
    e2 = { b46, b80, b80, b80 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 816u * 4u);
    e0 = { b39, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 817u * 4u);
    e2 = { b40, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 818u * 4u);
    e0 = { b41, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 819u * 4u);
    e2 = { b42, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 820u * 4u);
    e0 = { b43, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 821u * 4u);
    e2 = { b44, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 822u * 4u);
    e0 = { b35, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 823u * 4u);
    e2 = { b36, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 824u * 4u);
    e0 = { b37, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 825u * 4u);
    e2 = { b38, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 826u * 4u);
    e0 = { b71, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 827u * 4u);
    e2 = { b72, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 828u * 4u);
    e0 = { b73, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 829u * 4u);
    e2 = { b74, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 830u * 4u);
    e0 = { b75, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 831u * 4u);
    e2 = { b76, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 832u * 4u);
    e0 = { b77, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 833u * 4u);
    e2 = { b78, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 834u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 835u * 4u);
    e2 = { b0, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 836u * 4u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 837u * 4u);
    e1 = { b1, b80, b80, b80 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 838u * 4u);
    e3 = { b2, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 839u * 4u);
    e1 = { b3, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 840u * 4u);
    e3 = { b4, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 841u * 4u);
    e1 = { b5, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 842u * 4u);
    e3 = { b6, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 843u * 4u);
    e1 = { b7, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 844u * 4u);
    e3 = { b8, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 845u * 4u);
    e1 = { b9, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 846u * 4u);
    e3 = { b10, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 847u * 4u);
    e1 = { b11, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 848u * 4u);
    e3 = { b12, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 849u * 4u);
    e1 = { b13, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 850u * 4u);
    e3 = { b14, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 851u * 4u);
    e1 = { b15, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 852u * 4u);
    e3 = { b16, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 853u * 4u);
    e1 = { b17, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 854u * 4u);
    e3 = { b18, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 855u * 4u);
    e1 = { b19, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 856u * 4u);
    e3 = { b20, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 857u * 4u);
    e1 = { b21, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 858u * 4u);
    e3 = { b22, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 859u * 4u);
    e1 = { b23, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 860u * 4u);
    e3 = { b24, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 861u * 4u);
    e1 = { b25, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 862u * 4u);
    e3 = { b26, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 863u * 4u);
    e1 = { b27, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 864u * 4u);
    e3 = { b28, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 865u * 4u);
    e1 = { b29, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 866u * 4u);
    e3 = { b30, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 867u * 4u);
    e1 = { b31, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 868u * 4u);
    e3 = { b32, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 869u * 4u);
    e1 = { b33, b80, b80, b80 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 870u * 4u);
    e3 = { b34, b80, b80, b80 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 871u * 4u);
    e1 = stwo_qm31_sub(e3, e2);
    e2 = { b79, b80, b80, b80 };
    e3 = stwo_qm31_neg(e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 872u * 4u);
    e4 = { b0, b80, b80, b80 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e2, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 873u * 4u);
    e2 = stwo_qm31_add(e4, e5);
    e4 = stwo_load_qm31(arena, args->ext_params + 874u * 4u);
    e5 = { b82, b80, b80, b80 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 875u * 4u);
    e2 = { b47, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 876u * 4u);
    e5 = { b48, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 877u * 4u);
    e2 = { b55, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 878u * 4u);
    e5 = { b56, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 879u * 4u);
    e2 = { b63, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 880u * 4u);
    e5 = { b64, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 881u * 4u);
    e2 = { b71, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 882u * 4u);
    e5 = { b72, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 883u * 4u);
    e2 = { b73, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 884u * 4u);
    e5 = { b74, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 885u * 4u);
    e2 = { b49, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 886u * 4u);
    e5 = { b50, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 887u * 4u);
    e2 = { b57, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 888u * 4u);
    e5 = { b58, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 889u * 4u);
    e2 = { b65, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 890u * 4u);
    e5 = { b66, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 891u * 4u);
    e2 = { b67, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 892u * 4u);
    e5 = { b68, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 893u * 4u);
    e2 = { b75, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 894u * 4u);
    e5 = { b76, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 895u * 4u);
    e2 = { b51, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 896u * 4u);
    e5 = { b52, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 897u * 4u);
    e2 = { b59, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 898u * 4u);
    e5 = { b60, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 899u * 4u);
    e2 = { b61, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 900u * 4u);
    e5 = { b62, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 901u * 4u);
    e2 = { b69, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 902u * 4u);
    e5 = { b70, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 903u * 4u);
    e2 = { b77, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 904u * 4u);
    e5 = { b78, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 905u * 4u);
    e2 = { b53, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 906u * 4u);
    e5 = { b54, b80, b80, b80 };
    e6 = stwo_qm31_mul(e4, e5);
    e5 = stwo_qm31_add(e2, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 907u * 4u);
    e2 = { b34, b80, b80, b80 };
    e4 = stwo_qm31_mul(e6, e2);
    e2 = stwo_qm31_add(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 908u * 4u);
    e5 = stwo_qm31_sub(e2, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 965u * 4u);
    e2 = stwo_qm31_mul(e1, e4);
    e4 = { b79, b80, b80, b80 };
    e6 = stwo_qm31_mul(e0, e4);
    e4 = stwo_qm31_add(e2, e6);
    e6 = stwo_qm31_mul(e0, e1);
    e1 = { b81, b83, b84, b85 };
    e0 = { b86, b87, b88, b89 };
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_qm31_mul(e2, e6);
    e2 = stwo_qm31_sub(e1, e4);
    e1 = { b90, b92, b94, b96 };
    e4 = { b91, b93, b95, b97 };
    e6 = stwo_qm31_sub(e4, e1);
    e4 = stwo_qm31_sub(e6, e0);
    e6 = stwo_load_qm31(arena, args->ext_params + 966u * 4u);
    e0 = stwo_qm31_add(e4, e6);
    e6 = stwo_qm31_mul(e0, e5);
    e0 = stwo_qm31_sub(e6, e3);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
