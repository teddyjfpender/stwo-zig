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
stwo_cairo_cuda_eval_v1_010044ee4f5166a2(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 8u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 9u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 25u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 87u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 88u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 93u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 94u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 99u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 100u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 105u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 106u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 111u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 112u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 117u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 118u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 123u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 124u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 129u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 130u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 156u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 157u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 158u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 161u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 162u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 163u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 164u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 165u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 166u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 167u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 168u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 171u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 172u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 173u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 174u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 175u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 176u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 177u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 178u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 179u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 180u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 181u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 182u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 183u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 184u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 185u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 186u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 187u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 188u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 189u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 190u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 191u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 192u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 193u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 194u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 195u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 196u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 197u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 198u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 199u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 200u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 201u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 202u, row, 0);
    unsigned b74 = 0u;
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 100u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 101u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 102u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 2u, 103u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 2u, 104u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 2u, 105u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 2u, 106u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 2u, 107u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 108u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 109u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 2u, 110u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 111u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 725u * 4u);
    StwoCairoQm31 e1 = { b0, b74, b74, b74 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 726u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 727u * 4u);
    e2 = { b1, b74, b74, b74 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 728u * 4u);
    e0 = { b2, b74, b74, b74 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 729u * 4u);
    e2 = { b3, b74, b74, b74 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 730u * 4u);
    e0 = { b4, b74, b74, b74 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 731u * 4u);
    e2 = { b5, b74, b74, b74 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 732u * 4u);
    e0 = { b6, b74, b74, b74 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 733u * 4u);
    e2 = { b7, b74, b74, b74 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 734u * 4u);
    e0 = { b8, b74, b74, b74 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 735u * 4u);
    e2 = { b9, b74, b74, b74 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 736u * 4u);
    e0 = { b10, b74, b74, b74 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 737u * 4u);
    e2 = { b11, b74, b74, b74 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 738u * 4u);
    e0 = { b42, b74, b74, b74 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 739u * 4u);
    e2 = { b43, b74, b74, b74 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 740u * 4u);
    e0 = { b44, b74, b74, b74 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 741u * 4u);
    e2 = { b45, b74, b74, b74 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 742u * 4u);
    e0 = { b46, b74, b74, b74 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 743u * 4u);
    e2 = { b47, b74, b74, b74 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 744u * 4u);
    e0 = { b48, b74, b74, b74 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 745u * 4u);
    e2 = { b49, b74, b74, b74 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 746u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 747u * 4u);
    e2 = { b24, b74, b74, b74 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 748u * 4u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 749u * 4u);
    e1 = { b25, b74, b74, b74 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 750u * 4u);
    e3 = { b32, b74, b74, b74 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 751u * 4u);
    e1 = { b33, b74, b74, b74 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 752u * 4u);
    e3 = { b40, b74, b74, b74 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 753u * 4u);
    e1 = { b41, b74, b74, b74 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 754u * 4u);
    e3 = { b48, b74, b74, b74 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 755u * 4u);
    e1 = { b49, b74, b74, b74 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 756u * 4u);
    e3 = { b12, b74, b74, b74 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 757u * 4u);
    e1 = { b13, b74, b74, b74 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 758u * 4u);
    e3 = { b14, b74, b74, b74 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 759u * 4u);
    e1 = { b15, b74, b74, b74 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 760u * 4u);
    e3 = { b50, b74, b74, b74 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 761u * 4u);
    e1 = { b51, b74, b74, b74 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 762u * 4u);
    e3 = { b52, b74, b74, b74 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 763u * 4u);
    e1 = { b53, b74, b74, b74 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 764u * 4u);
    e3 = { b54, b74, b74, b74 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 765u * 4u);
    e1 = { b55, b74, b74, b74 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 766u * 4u);
    e3 = { b56, b74, b74, b74 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 767u * 4u);
    e1 = { b57, b74, b74, b74 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 768u * 4u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 769u * 4u);
    e1 = { b30, b74, b74, b74 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 770u * 4u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 771u * 4u);
    e2 = { b31, b74, b74, b74 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 772u * 4u);
    e4 = { b38, b74, b74, b74 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 773u * 4u);
    e2 = { b39, b74, b74, b74 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 774u * 4u);
    e4 = { b46, b74, b74, b74 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 775u * 4u);
    e2 = { b47, b74, b74, b74 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 776u * 4u);
    e4 = { b28, b74, b74, b74 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 777u * 4u);
    e2 = { b29, b74, b74, b74 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 778u * 4u);
    e4 = { b16, b74, b74, b74 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 779u * 4u);
    e2 = { b17, b74, b74, b74 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 780u * 4u);
    e4 = { b18, b74, b74, b74 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 781u * 4u);
    e2 = { b19, b74, b74, b74 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 782u * 4u);
    e4 = { b58, b74, b74, b74 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 783u * 4u);
    e2 = { b59, b74, b74, b74 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 784u * 4u);
    e4 = { b60, b74, b74, b74 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 785u * 4u);
    e2 = { b61, b74, b74, b74 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 786u * 4u);
    e4 = { b62, b74, b74, b74 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 787u * 4u);
    e2 = { b63, b74, b74, b74 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 788u * 4u);
    e4 = { b64, b74, b74, b74 };
    e1 = stwo_qm31_mul(e5, e4);
    e4 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 789u * 4u);
    e2 = { b65, b74, b74, b74 };
    e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 790u * 4u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 791u * 4u);
    e2 = { b36, b74, b74, b74 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 792u * 4u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 793u * 4u);
    e1 = { b37, b74, b74, b74 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 794u * 4u);
    e5 = { b44, b74, b74, b74 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 795u * 4u);
    e1 = { b45, b74, b74, b74 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 796u * 4u);
    e5 = { b26, b74, b74, b74 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 797u * 4u);
    e1 = { b27, b74, b74, b74 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 798u * 4u);
    e5 = { b34, b74, b74, b74 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 799u * 4u);
    e1 = { b35, b74, b74, b74 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 800u * 4u);
    e5 = { b20, b74, b74, b74 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 801u * 4u);
    e1 = { b21, b74, b74, b74 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 802u * 4u);
    e5 = { b22, b74, b74, b74 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 803u * 4u);
    e1 = { b23, b74, b74, b74 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 804u * 4u);
    e5 = { b66, b74, b74, b74 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 805u * 4u);
    e1 = { b67, b74, b74, b74 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 806u * 4u);
    e5 = { b68, b74, b74, b74 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 807u * 4u);
    e1 = { b69, b74, b74, b74 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 808u * 4u);
    e5 = { b70, b74, b74, b74 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 809u * 4u);
    e1 = { b71, b74, b74, b74 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 810u * 4u);
    e5 = { b72, b74, b74, b74 };
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 811u * 4u);
    e1 = { b73, b74, b74, b74 };
    e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 812u * 4u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 961u * 4u);
    e1 = stwo_qm31_mul(e3, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 962u * 4u);
    e2 = stwo_qm31_mul(e0, e6);
    e6 = stwo_qm31_add(e1, e2);
    e2 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 963u * 4u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 964u * 4u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = { b75, b76, b77, b78 };
    e4 = { b79, b80, b81, b82 };
    e0 = stwo_qm31_sub(e4, e5);
    e5 = stwo_qm31_mul(e0, e2);
    e0 = stwo_qm31_sub(e5, e6);
    e5 = { b83, b84, b85, b86 };
    e6 = stwo_qm31_sub(e5, e4);
    e5 = stwo_qm31_mul(e6, e1);
    e6 = stwo_qm31_sub(e5, e3);
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
