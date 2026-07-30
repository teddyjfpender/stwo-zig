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
stwo_cairo_cuda_eval_v1_8299fc039d2fad70(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 1u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 2u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 3u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 4u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 5u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 6u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 7u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 8u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 25u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 41u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 42u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 43u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 47u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 48u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 49u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 51u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 52u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 53u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 54u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 55u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 56u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 57u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 58u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 59u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 60u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 61u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 62u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 63u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 64u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 65u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 66u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 67u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 68u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 69u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 70u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 71u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 74u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 75u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 76u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 81u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 82u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 83u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 84u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 85u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 86u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 92u, row, 0);
    unsigned b80 = 0u;
    unsigned b81 = 4u;
    unsigned b82 = stwo_m31_mul(b81, b1);
    b81 = 2u;
    b1 = stwo_m31_mul(b81, b8);
    b81 = stwo_m31_add(b82, b1);
    b1 = 3u;
    b82 = stwo_m31_mul(b1, b15);
    b1 = stwo_m31_add(b81, b82);
    b82 = stwo_m31_add(b1, b22);
    b1 = stwo_m31_sub(b82, b62);
    b82 = stwo_m31_add(b1, b32);
    b1 = stwo_m31_sub(b82, b72);
    b82 = stwo_m31_sub(b1, b79);
    b1 = 16u;
    b72 = stwo_m31_mul(b82, b1);
    b1 = 4u;
    b82 = stwo_m31_mul(b1, b2);
    b1 = stwo_m31_add(b72, b82);
    b82 = 2u;
    b2 = stwo_m31_mul(b82, b9);
    b82 = stwo_m31_add(b1, b2);
    b2 = 3u;
    b1 = stwo_m31_mul(b2, b16);
    b2 = stwo_m31_add(b82, b1);
    b1 = stwo_m31_add(b2, b23);
    b2 = stwo_m31_sub(b1, b63);
    b1 = stwo_m31_add(b2, b33);
    b2 = stwo_m31_sub(b1, b73);
    b1 = 16u;
    b73 = stwo_m31_mul(b2, b1);
    b1 = 4u;
    b2 = stwo_m31_mul(b1, b3);
    b1 = stwo_m31_add(b73, b2);
    b2 = 2u;
    b3 = stwo_m31_mul(b2, b10);
    b2 = stwo_m31_add(b1, b3);
    b3 = 3u;
    b1 = stwo_m31_mul(b3, b17);
    b3 = stwo_m31_add(b2, b1);
    b1 = stwo_m31_add(b3, b24);
    b3 = stwo_m31_sub(b1, b64);
    b1 = stwo_m31_add(b3, b34);
    b3 = stwo_m31_sub(b1, b74);
    b1 = 16u;
    b74 = stwo_m31_mul(b3, b1);
    b1 = 4u;
    b3 = stwo_m31_mul(b1, b4);
    b1 = stwo_m31_add(b74, b3);
    b3 = 2u;
    b4 = stwo_m31_mul(b3, b11);
    b3 = stwo_m31_add(b1, b4);
    b4 = 3u;
    b1 = stwo_m31_mul(b4, b18);
    b4 = stwo_m31_add(b3, b1);
    b1 = stwo_m31_add(b4, b25);
    b4 = stwo_m31_sub(b1, b65);
    b1 = stwo_m31_add(b4, b35);
    b4 = stwo_m31_sub(b1, b75);
    b1 = 16u;
    b75 = stwo_m31_mul(b4, b1);
    b1 = 4u;
    b4 = stwo_m31_mul(b1, b5);
    b1 = stwo_m31_add(b75, b4);
    b4 = 2u;
    b5 = stwo_m31_mul(b4, b12);
    b4 = stwo_m31_add(b1, b5);
    b5 = 3u;
    b1 = stwo_m31_mul(b5, b19);
    b5 = stwo_m31_add(b4, b1);
    b1 = stwo_m31_add(b5, b26);
    b5 = stwo_m31_sub(b1, b66);
    b1 = stwo_m31_add(b5, b36);
    b5 = stwo_m31_sub(b1, b76);
    b1 = 16u;
    b76 = stwo_m31_mul(b5, b1);
    b1 = 4u;
    b5 = stwo_m31_mul(b1, b6);
    b1 = stwo_m31_add(b76, b5);
    b5 = 2u;
    b6 = stwo_m31_mul(b5, b13);
    b5 = stwo_m31_add(b1, b6);
    b6 = 3u;
    b1 = stwo_m31_mul(b6, b20);
    b6 = stwo_m31_add(b5, b1);
    b1 = stwo_m31_add(b6, b27);
    b6 = stwo_m31_sub(b1, b67);
    b1 = stwo_m31_add(b6, b37);
    b6 = stwo_m31_sub(b1, b77);
    b1 = 16u;
    b77 = stwo_m31_mul(b6, b1);
    b1 = 4u;
    b6 = stwo_m31_mul(b1, b7);
    b1 = stwo_m31_add(b77, b6);
    b6 = 2u;
    b7 = stwo_m31_mul(b6, b14);
    b6 = stwo_m31_add(b1, b7);
    b7 = 3u;
    b1 = stwo_m31_mul(b7, b21);
    b7 = stwo_m31_add(b6, b1);
    b1 = stwo_m31_add(b7, b28);
    b7 = stwo_m31_sub(b1, b68);
    b1 = stwo_m31_add(b7, b38);
    b7 = stwo_m31_sub(b1, b78);
    b1 = 16u;
    b78 = stwo_m31_mul(b7, b1);
    b1 = 2u;
    b7 = stwo_m31_add(b79, b1);
    b1 = 2u;
    b79 = stwo_m31_add(b72, b1);
    b1 = 2u;
    b72 = stwo_m31_add(b73, b1);
    b1 = 2u;
    b73 = stwo_m31_add(b74, b1);
    b1 = 2u;
    b74 = stwo_m31_add(b75, b1);
    b1 = 2u;
    b75 = stwo_m31_add(b76, b1);
    b1 = 2u;
    b76 = stwo_m31_add(b77, b1);
    b1 = 2u;
    b77 = stwo_m31_add(b78, b1);
    b1 = stwo_trace_value(arena, *args, 2u, 0u, row, 0);
    b78 = stwo_trace_value(arena, *args, 2u, 1u, row, 0);
    b6 = stwo_trace_value(arena, *args, 2u, 2u, row, 0);
    b21 = stwo_trace_value(arena, *args, 2u, 3u, row, 0);
    b14 = stwo_trace_value(arena, *args, 2u, 4u, row, 0);
    b5 = stwo_trace_value(arena, *args, 2u, 5u, row, 0);
    b20 = stwo_trace_value(arena, *args, 2u, 6u, row, 0);
    b13 = stwo_trace_value(arena, *args, 2u, 7u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e1 = { b0, b80, b80, b80 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    e2 = { b32, b80, b80, b80 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    e0 = { b33, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    e2 = { b34, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 5u * 4u);
    e0 = { b35, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 6u * 4u);
    e2 = { b36, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 7u * 4u);
    e0 = { b37, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 8u * 4u);
    e2 = { b38, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 9u * 4u);
    e0 = { b39, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 10u * 4u);
    e2 = { b40, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 11u * 4u);
    e0 = { b41, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 12u * 4u);
    e2 = { b42, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 13u * 4u);
    e0 = { b43, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 14u * 4u);
    e2 = { b44, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 15u * 4u);
    e0 = { b45, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 16u * 4u);
    e2 = { b46, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 17u * 4u);
    e0 = { b47, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 18u * 4u);
    e2 = { b48, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 19u * 4u);
    e0 = { b49, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 20u * 4u);
    e2 = { b50, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 21u * 4u);
    e0 = { b51, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 22u * 4u);
    e2 = { b52, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 23u * 4u);
    e0 = { b53, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 24u * 4u);
    e2 = { b54, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 25u * 4u);
    e0 = { b55, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 26u * 4u);
    e2 = { b56, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 27u * 4u);
    e0 = { b57, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 28u * 4u);
    e2 = { b58, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 29u * 4u);
    e0 = { b59, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 30u * 4u);
    e2 = { b60, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 31u * 4u);
    e0 = { b61, b80, b80, b80 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 32u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 33u * 4u);
    e0 = { b22, b80, b80, b80 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 34u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 35u * 4u);
    e3 = { b23, b80, b80, b80 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 36u * 4u);
    e1 = { b24, b80, b80, b80 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 37u * 4u);
    e3 = { b25, b80, b80, b80 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 38u * 4u);
    e1 = { b26, b80, b80, b80 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 39u * 4u);
    e3 = { b27, b80, b80, b80 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 40u * 4u);
    e1 = { b28, b80, b80, b80 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 41u * 4u);
    e3 = { b29, b80, b80, b80 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 42u * 4u);
    e1 = { b30, b80, b80, b80 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 43u * 4u);
    e3 = { b31, b80, b80, b80 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 44u * 4u);
    e1 = { b62, b80, b80, b80 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 45u * 4u);
    e3 = { b63, b80, b80, b80 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 46u * 4u);
    e1 = { b64, b80, b80, b80 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 47u * 4u);
    e3 = { b65, b80, b80, b80 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 48u * 4u);
    e1 = { b66, b80, b80, b80 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 49u * 4u);
    e3 = { b67, b80, b80, b80 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 50u * 4u);
    e1 = { b68, b80, b80, b80 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 51u * 4u);
    e3 = { b69, b80, b80, b80 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 52u * 4u);
    e1 = { b70, b80, b80, b80 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 53u * 4u);
    e3 = { b71, b80, b80, b80 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 54u * 4u);
    e1 = stwo_qm31_sub(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 55u * 4u);
    e3 = { b7, b80, b80, b80 };
    e0 = stwo_qm31_mul(e4, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 56u * 4u);
    e4 = stwo_qm31_add(e3, e0);
    e3 = stwo_load_qm31(arena, args->ext_params + 57u * 4u);
    e0 = { b79, b80, b80, b80 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 58u * 4u);
    e4 = { b72, b80, b80, b80 };
    e3 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 59u * 4u);
    e0 = { b73, b80, b80, b80 };
    e5 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 60u * 4u);
    e4 = stwo_qm31_sub(e0, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 61u * 4u);
    e0 = { b74, b80, b80, b80 };
    e3 = stwo_qm31_mul(e5, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 62u * 4u);
    e5 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 63u * 4u);
    e3 = { b75, b80, b80, b80 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 64u * 4u);
    e5 = { b76, b80, b80, b80 };
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 65u * 4u);
    e3 = { b77, b80, b80, b80 };
    e6 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 66u * 4u);
    e5 = stwo_qm31_sub(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 271u * 4u);
    e3 = stwo_qm31_mul(e1, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 272u * 4u);
    e0 = stwo_qm31_mul(e2, e6);
    e6 = stwo_qm31_add(e3, e0);
    e0 = stwo_qm31_mul(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 273u * 4u);
    e2 = stwo_qm31_mul(e5, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 274u * 4u);
    e3 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e2, e3);
    e3 = stwo_qm31_mul(e4, e5);
    e5 = { b1, b78, b6, b21 };
    e4 = stwo_qm31_mul(e5, e0);
    e0 = stwo_qm31_sub(e4, e6);
    e4 = { b14, b5, b20, b13 };
    e6 = stwo_qm31_sub(e4, e5);
    e4 = stwo_qm31_mul(e6, e3);
    e6 = stwo_qm31_sub(e4, e1);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e6, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
