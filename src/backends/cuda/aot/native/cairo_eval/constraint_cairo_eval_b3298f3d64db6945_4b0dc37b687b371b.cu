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
stwo_cairo_cuda_eval_v1_7bf054256b1dbbbd(
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
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 104u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 105u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 107u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 108u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 109u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 110u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 111u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 112u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 113u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 125u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 126u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 127u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 128u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 131u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 132u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 133u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 134u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 136u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 137u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 138u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 139u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 140u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 141u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 142u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 143u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 144u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 145u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 157u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 158u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 159u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 160u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 161u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 162u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 163u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 164u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 165u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 166u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 168u, row, 0);
    unsigned b83 = 0u;
    unsigned b84 = 1u;
    unsigned b85 = stwo_m31_add(b1, b84);
    b84 = stwo_trace_value(arena, *args, 2u, 28u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 29u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 2u, 30u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 2u, 31u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 2u, 32u, row, -1);
    unsigned b90 = stwo_trace_value(arena, *args, 2u, 32u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 2u, 33u, row, -1);
    unsigned b92 = stwo_trace_value(arena, *args, 2u, 33u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 2u, 34u, row, -1);
    unsigned b94 = stwo_trace_value(arena, *args, 2u, 34u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 2u, 35u, row, -1);
    unsigned b96 = stwo_trace_value(arena, *args, 2u, 35u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 183u * 4u);
    StwoCairoQm31 e1 = { b0, b83, b83, b83 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 184u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 185u * 4u);
    e2 = { b1, b83, b83, b83 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 186u * 4u);
    e0 = { b2, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 187u * 4u);
    e2 = { b3, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 188u * 4u);
    e0 = { b4, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 189u * 4u);
    e2 = { b5, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 190u * 4u);
    e0 = { b6, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 191u * 4u);
    e2 = { b7, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 192u * 4u);
    e0 = { b8, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 193u * 4u);
    e2 = { b9, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 194u * 4u);
    e0 = { b10, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 195u * 4u);
    e2 = { b11, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 196u * 4u);
    e0 = { b12, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 197u * 4u);
    e2 = { b13, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 198u * 4u);
    e0 = { b14, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 199u * 4u);
    e2 = { b15, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 200u * 4u);
    e0 = { b16, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 201u * 4u);
    e2 = { b17, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 202u * 4u);
    e0 = { b18, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 203u * 4u);
    e2 = { b19, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 204u * 4u);
    e0 = { b20, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 205u * 4u);
    e2 = { b21, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 206u * 4u);
    e0 = { b22, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 207u * 4u);
    e2 = { b23, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 208u * 4u);
    e0 = { b24, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 209u * 4u);
    e2 = { b25, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 210u * 4u);
    e0 = { b26, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 211u * 4u);
    e2 = { b27, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 212u * 4u);
    e0 = { b28, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 213u * 4u);
    e2 = { b29, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 214u * 4u);
    e0 = { b30, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 215u * 4u);
    e2 = { b31, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 216u * 4u);
    e0 = { b32, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 217u * 4u);
    e2 = { b33, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 218u * 4u);
    e0 = { b34, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 219u * 4u);
    e2 = { b35, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 220u * 4u);
    e0 = { b36, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 221u * 4u);
    e2 = { b37, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 222u * 4u);
    e0 = { b38, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 223u * 4u);
    e2 = { b39, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 224u * 4u);
    e0 = { b40, b83, b83, b83 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 225u * 4u);
    e2 = { b41, b83, b83, b83 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 226u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = { b82, b83, b83, b83 };
    e2 = stwo_qm31_neg(e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 227u * 4u);
    e1 = { b0, b83, b83, b83 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e3, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 228u * 4u);
    e3 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(arena, args->ext_params + 229u * 4u);
    e4 = { b85, b83, b83, b83 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 230u * 4u);
    e3 = { b42, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 231u * 4u);
    e4 = { b43, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 232u * 4u);
    e3 = { b44, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 233u * 4u);
    e4 = { b45, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 234u * 4u);
    e3 = { b46, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 235u * 4u);
    e4 = { b47, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 236u * 4u);
    e3 = { b48, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 237u * 4u);
    e4 = { b49, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 238u * 4u);
    e3 = { b50, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 239u * 4u);
    e4 = { b51, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 240u * 4u);
    e3 = { b52, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 241u * 4u);
    e4 = { b53, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 242u * 4u);
    e3 = { b54, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 243u * 4u);
    e4 = { b55, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 244u * 4u);
    e3 = { b56, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 245u * 4u);
    e4 = { b57, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 246u * 4u);
    e3 = { b58, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 247u * 4u);
    e4 = { b59, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 248u * 4u);
    e3 = { b60, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 249u * 4u);
    e4 = { b61, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 250u * 4u);
    e3 = { b62, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 251u * 4u);
    e4 = { b63, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 252u * 4u);
    e3 = { b64, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 253u * 4u);
    e4 = { b65, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 254u * 4u);
    e3 = { b66, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 255u * 4u);
    e4 = { b67, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 256u * 4u);
    e3 = { b68, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 257u * 4u);
    e4 = { b69, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 258u * 4u);
    e3 = { b70, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 259u * 4u);
    e4 = { b71, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 260u * 4u);
    e3 = { b72, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 261u * 4u);
    e4 = { b73, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 262u * 4u);
    e3 = { b74, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 263u * 4u);
    e4 = { b75, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 264u * 4u);
    e3 = { b76, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 265u * 4u);
    e4 = { b77, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 266u * 4u);
    e3 = { b78, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 267u * 4u);
    e4 = { b79, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 268u * 4u);
    e3 = { b80, b83, b83, b83 };
    e1 = stwo_qm31_mul(e5, e3);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 269u * 4u);
    e4 = { b81, b83, b83, b83 };
    e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e3, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 270u * 4u);
    e3 = stwo_qm31_sub(e4, e5);
    e5 = { b82, b83, b83, b83 };
    e4 = stwo_qm31_mul(e3, e5);
    e5 = stwo_qm31_mul(e0, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_qm31_mul(e0, e3);
    e3 = { b84, b86, b87, b88 };
    e0 = { b89, b91, b93, b95 };
    e4 = { b90, b92, b94, b96 };
    e1 = stwo_qm31_sub(e4, e0);
    e4 = stwo_qm31_sub(e1, e3);
    e1 = stwo_load_qm31(arena, args->ext_params + 287u * 4u);
    e3 = stwo_qm31_add(e4, e1);
    e1 = stwo_qm31_mul(e3, e5);
    e3 = stwo_qm31_sub(e1, e2);
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
