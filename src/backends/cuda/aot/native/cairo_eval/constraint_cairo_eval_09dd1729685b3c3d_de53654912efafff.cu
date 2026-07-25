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
stwo_cairo_cuda_eval_v1_67b6d3877e21f174(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 0u, 0u, row, 0);
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
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 41u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 42u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 43u, row, 0);
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
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b86 = 0u;
    unsigned b87 = stwo_m31_add(b1, b29);
    b29 = stwo_m31_sub(b87, b57);
    b87 = 1073741824u;
    b57 = stwo_m31_mul(b87, b29);
    b87 = stwo_m31_add(b2, b30);
    b30 = stwo_m31_sub(b87, b58);
    b87 = 1073741824u;
    b58 = stwo_m31_mul(b87, b30);
    b87 = stwo_m31_add(b3, b31);
    b31 = stwo_m31_sub(b87, b59);
    b87 = 1073741824u;
    b59 = stwo_m31_mul(b87, b31);
    b87 = stwo_m31_add(b4, b32);
    b32 = stwo_m31_sub(b87, b60);
    b87 = 1073741824u;
    b60 = stwo_m31_mul(b87, b32);
    b87 = stwo_m31_add(b5, b33);
    b33 = stwo_m31_sub(b87, b61);
    b87 = 1073741824u;
    b61 = stwo_m31_mul(b87, b33);
    b87 = stwo_m31_add(b6, b34);
    b34 = stwo_m31_sub(b87, b62);
    b87 = 1073741824u;
    b62 = stwo_m31_mul(b87, b34);
    b87 = stwo_m31_add(b7, b35);
    b35 = stwo_m31_sub(b87, b63);
    b87 = 1073741824u;
    b63 = stwo_m31_mul(b87, b35);
    b87 = stwo_m31_add(b8, b36);
    b36 = stwo_m31_sub(b87, b64);
    b87 = 1073741824u;
    b64 = stwo_m31_mul(b87, b36);
    b87 = stwo_m31_add(b9, b37);
    b37 = stwo_m31_sub(b87, b65);
    b87 = 1073741824u;
    b65 = stwo_m31_mul(b87, b37);
    b87 = stwo_m31_add(b10, b38);
    b38 = stwo_m31_sub(b87, b66);
    b87 = 1073741824u;
    b66 = stwo_m31_mul(b87, b38);
    b87 = stwo_m31_add(b11, b39);
    b39 = stwo_m31_sub(b87, b67);
    b87 = 1073741824u;
    b67 = stwo_m31_mul(b87, b39);
    b87 = stwo_m31_add(b12, b40);
    b40 = stwo_m31_sub(b87, b68);
    b87 = 1073741824u;
    b68 = stwo_m31_mul(b87, b40);
    b87 = stwo_m31_add(b13, b41);
    b41 = stwo_m31_sub(b87, b69);
    b87 = 1073741824u;
    b69 = stwo_m31_mul(b87, b41);
    b87 = stwo_m31_add(b14, b42);
    b42 = stwo_m31_sub(b87, b70);
    b87 = 1073741824u;
    b70 = stwo_m31_mul(b87, b42);
    b87 = stwo_m31_add(b15, b43);
    b43 = stwo_m31_sub(b87, b71);
    b87 = 1073741824u;
    b71 = stwo_m31_mul(b87, b43);
    b87 = stwo_m31_add(b16, b44);
    b44 = stwo_m31_sub(b87, b72);
    b87 = 1073741824u;
    b72 = stwo_m31_mul(b87, b44);
    b87 = stwo_m31_add(b17, b45);
    b45 = stwo_m31_sub(b87, b73);
    b87 = 1073741824u;
    b73 = stwo_m31_mul(b87, b45);
    b87 = stwo_m31_add(b18, b46);
    b46 = stwo_m31_sub(b87, b74);
    b87 = 1073741824u;
    b74 = stwo_m31_mul(b87, b46);
    b87 = stwo_m31_add(b19, b47);
    b47 = stwo_m31_sub(b87, b75);
    b87 = 1073741824u;
    b75 = stwo_m31_mul(b87, b47);
    b87 = stwo_m31_add(b20, b48);
    b48 = stwo_m31_sub(b87, b76);
    b87 = 1073741824u;
    b76 = stwo_m31_mul(b87, b48);
    b87 = stwo_m31_add(b21, b49);
    b49 = stwo_m31_sub(b87, b77);
    b87 = 1073741824u;
    b77 = stwo_m31_mul(b87, b49);
    b87 = stwo_m31_add(b22, b50);
    b50 = stwo_m31_sub(b87, b78);
    b87 = 1073741824u;
    b78 = stwo_m31_mul(b87, b50);
    b87 = stwo_m31_add(b23, b51);
    b51 = stwo_m31_sub(b87, b79);
    b87 = 1073741824u;
    b79 = stwo_m31_mul(b87, b51);
    b87 = stwo_m31_add(b24, b52);
    b52 = stwo_m31_sub(b87, b80);
    b87 = 1073741824u;
    b80 = stwo_m31_mul(b87, b52);
    b87 = stwo_m31_add(b25, b53);
    b53 = stwo_m31_sub(b87, b81);
    b87 = 1073741824u;
    b81 = stwo_m31_mul(b87, b53);
    b87 = stwo_m31_add(b26, b54);
    b54 = stwo_m31_sub(b87, b82);
    b87 = 1073741824u;
    b82 = stwo_m31_mul(b87, b54);
    b87 = stwo_m31_add(b27, b55);
    b54 = stwo_m31_sub(b87, b83);
    b87 = 1073741824u;
    b26 = stwo_m31_mul(b87, b54);
    b87 = stwo_m31_add(b28, b56);
    b54 = stwo_m31_sub(b87, b84);
    b87 = 1073741824u;
    b53 = stwo_m31_mul(b87, b54);
    b87 = 5u;
    b54 = stwo_m31_mul(b0, b87);
    b87 = 6954597u;
    b0 = stwo_m31_add(b87, b54);
    b87 = 2u;
    b54 = stwo_m31_add(b0, b87);
    b87 = stwo_trace_value(arena, *args, 2u, 56u, row, 0);
    b0 = stwo_trace_value(arena, *args, 2u, 57u, row, 0);
    b25 = stwo_trace_value(arena, *args, 2u, 58u, row, 0);
    b52 = stwo_trace_value(arena, *args, 2u, 59u, row, 0);
    b24 = stwo_trace_value(arena, *args, 2u, 60u, row, 0);
    b51 = stwo_trace_value(arena, *args, 2u, 61u, row, 0);
    b23 = stwo_trace_value(arena, *args, 2u, 62u, row, 0);
    b50 = stwo_trace_value(arena, *args, 2u, 63u, row, 0);
    b22 = stwo_trace_value(arena, *args, 2u, 64u, row, 0);
    b49 = stwo_trace_value(arena, *args, 2u, 65u, row, 0);
    b21 = stwo_trace_value(arena, *args, 2u, 66u, row, 0);
    b48 = stwo_trace_value(arena, *args, 2u, 67u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 200u * 4u);
    StwoCairoQm31 e1 = { b27, b86, b86, b86 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 201u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 202u * 4u);
    e2 = { b55, b86, b86, b86 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 203u * 4u);
    e0 = { b83, b86, b86, b86 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 204u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 205u * 4u);
    e0 = { b28, b86, b86, b86 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 206u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 207u * 4u);
    e3 = { b56, b86, b86, b86 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 208u * 4u);
    e1 = { b84, b86, b86, b86 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 209u * 4u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 210u * 4u);
    e1 = { b54, b86, b86, b86 };
    e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 211u * 4u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(arena, args->ext_params + 212u * 4u);
    e4 = { b85, b86, b86, b86 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e4);
    e4 = stwo_qm31_add(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 213u * 4u);
    e0 = stwo_qm31_sub(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 214u * 4u);
    e4 = { b85, b86, b86, b86 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 215u * 4u);
    e5 = stwo_qm31_add(e4, e1);
    e4 = stwo_load_qm31(arena, args->ext_params + 216u * 4u);
    e1 = { b57, b86, b86, b86 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 217u * 4u);
    e5 = { b58, b86, b86, b86 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 218u * 4u);
    e1 = { b59, b86, b86, b86 };
    e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 219u * 4u);
    e5 = { b60, b86, b86, b86 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 220u * 4u);
    e1 = { b61, b86, b86, b86 };
    e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 221u * 4u);
    e5 = { b62, b86, b86, b86 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 222u * 4u);
    e1 = { b63, b86, b86, b86 };
    e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 223u * 4u);
    e5 = { b64, b86, b86, b86 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 224u * 4u);
    e1 = { b65, b86, b86, b86 };
    e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 225u * 4u);
    e5 = { b66, b86, b86, b86 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 226u * 4u);
    e1 = { b67, b86, b86, b86 };
    e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 227u * 4u);
    e5 = { b68, b86, b86, b86 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 228u * 4u);
    e1 = { b69, b86, b86, b86 };
    e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 229u * 4u);
    e5 = { b70, b86, b86, b86 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 230u * 4u);
    e1 = { b71, b86, b86, b86 };
    e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 231u * 4u);
    e5 = { b72, b86, b86, b86 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 232u * 4u);
    e1 = { b73, b86, b86, b86 };
    e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 233u * 4u);
    e5 = { b74, b86, b86, b86 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 234u * 4u);
    e1 = { b75, b86, b86, b86 };
    e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 235u * 4u);
    e5 = { b76, b86, b86, b86 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 236u * 4u);
    e1 = { b77, b86, b86, b86 };
    e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 237u * 4u);
    e5 = { b78, b86, b86, b86 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 238u * 4u);
    e1 = { b79, b86, b86, b86 };
    e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 239u * 4u);
    e5 = { b80, b86, b86, b86 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 240u * 4u);
    e1 = { b81, b86, b86, b86 };
    e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 241u * 4u);
    e5 = { b82, b86, b86, b86 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 242u * 4u);
    e1 = { b26, b86, b86, b86 };
    e6 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 243u * 4u);
    e5 = { b53, b86, b86, b86 };
    e4 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 244u * 4u);
    e1 = stwo_qm31_sub(e5, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 345u * 4u);
    e5 = stwo_qm31_mul(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 346u * 4u);
    e6 = stwo_qm31_mul(e2, e4);
    e4 = stwo_qm31_add(e5, e6);
    e6 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 347u * 4u);
    e2 = stwo_qm31_mul(e1, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 348u * 4u);
    e5 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e2, e5);
    e5 = stwo_qm31_mul(e0, e1);
    e1 = { b87, b0, b25, b52 };
    e0 = { b24, b51, b23, b50 };
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_qm31_mul(e2, e6);
    e2 = stwo_qm31_sub(e1, e4);
    e1 = { b22, b49, b21, b48 };
    e4 = stwo_qm31_sub(e1, e0);
    e1 = stwo_qm31_mul(e4, e5);
    e4 = stwo_qm31_sub(e1, e3);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e4, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
