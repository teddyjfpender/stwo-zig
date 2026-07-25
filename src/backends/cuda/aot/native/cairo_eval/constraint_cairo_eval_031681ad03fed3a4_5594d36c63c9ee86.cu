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
stwo_cairo_cuda_eval_v1_ad60967c812e59fb(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 0u, 0u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 156u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 157u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 158u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 159u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 160u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 161u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 162u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 163u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 164u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 165u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 166u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 167u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 168u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 169u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 170u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 171u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 172u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 174u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 175u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 176u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 177u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 178u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 179u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 180u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 181u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 182u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 183u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 184u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 185u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 186u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 187u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 188u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 189u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 190u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 191u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 192u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 193u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 195u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 196u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 197u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 198u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 199u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 200u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 201u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 202u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 203u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 204u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 205u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 206u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 207u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 208u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 209u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 210u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 211u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 212u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 213u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 214u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 215u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 216u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 1u, 217u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 1u, 218u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 1u, 219u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 1u, 220u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 1u, 221u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 1u, 222u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 1u, 223u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 1u, 224u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 1u, 225u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 1u, 226u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 1u, 227u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 1u, 228u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 1u, 229u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 1u, 230u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 1u, 231u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 1u, 232u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 1u, 233u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 1u, 234u, row, 0);
    unsigned b81 = 0u;
    unsigned b82 = stwo_trace_value(arena, *args, 2u, 24u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 25u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 26u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 2u, 27u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 28u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 2u, 29u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 2u, 30u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 2u, 31u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 259u * 4u);
    StwoCairoQm31 e1 = { b0, b81, b81, b81 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 260u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 261u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 262u * 4u);
    e0 = { b1, b81, b81, b81 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 263u * 4u);
    e2 = { b2, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 264u * 4u);
    e0 = { b3, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 265u * 4u);
    e2 = { b4, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 266u * 4u);
    e0 = { b5, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 267u * 4u);
    e2 = { b6, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 268u * 4u);
    e0 = { b7, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 269u * 4u);
    e2 = { b8, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 270u * 4u);
    e0 = { b9, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 271u * 4u);
    e2 = { b10, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 272u * 4u);
    e0 = { b11, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 273u * 4u);
    e2 = { b12, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 274u * 4u);
    e0 = { b13, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 275u * 4u);
    e2 = { b14, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 276u * 4u);
    e0 = { b15, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 277u * 4u);
    e2 = { b16, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 278u * 4u);
    e0 = { b17, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 279u * 4u);
    e2 = { b18, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 280u * 4u);
    e0 = { b19, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 281u * 4u);
    e2 = { b20, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 282u * 4u);
    e0 = { b21, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 283u * 4u);
    e2 = { b22, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 284u * 4u);
    e0 = { b23, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 285u * 4u);
    e2 = { b24, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 286u * 4u);
    e0 = { b25, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 287u * 4u);
    e2 = { b26, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 288u * 4u);
    e0 = { b27, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 289u * 4u);
    e2 = { b28, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 290u * 4u);
    e0 = { b29, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 291u * 4u);
    e2 = { b30, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 292u * 4u);
    e0 = { b31, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 293u * 4u);
    e2 = { b32, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 294u * 4u);
    e0 = { b33, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 295u * 4u);
    e2 = { b34, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 296u * 4u);
    e0 = { b35, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 297u * 4u);
    e2 = { b36, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 298u * 4u);
    e0 = { b37, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 299u * 4u);
    e2 = { b38, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 300u * 4u);
    e0 = { b39, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 301u * 4u);
    e2 = { b40, b81, b81, b81 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 302u * 4u);
    e0 = stwo_qm31_sub(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 303u * 4u);
    e2 = { b0, b81, b81, b81 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 304u * 4u);
    e1 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(arena, args->ext_params + 305u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 306u * 4u);
    e1 = { b41, b81, b81, b81 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 307u * 4u);
    e3 = { b42, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 308u * 4u);
    e1 = { b43, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 309u * 4u);
    e3 = { b44, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 310u * 4u);
    e1 = { b45, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 311u * 4u);
    e3 = { b46, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 312u * 4u);
    e1 = { b47, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 313u * 4u);
    e3 = { b48, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 314u * 4u);
    e1 = { b49, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 315u * 4u);
    e3 = { b50, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 316u * 4u);
    e1 = { b51, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 317u * 4u);
    e3 = { b52, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 318u * 4u);
    e1 = { b53, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 319u * 4u);
    e3 = { b54, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 320u * 4u);
    e1 = { b55, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 321u * 4u);
    e3 = { b56, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 322u * 4u);
    e1 = { b57, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 323u * 4u);
    e3 = { b58, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 324u * 4u);
    e1 = { b59, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 325u * 4u);
    e3 = { b60, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 326u * 4u);
    e1 = { b61, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 327u * 4u);
    e3 = { b62, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 328u * 4u);
    e1 = { b63, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 329u * 4u);
    e3 = { b64, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 330u * 4u);
    e1 = { b65, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 331u * 4u);
    e3 = { b66, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 332u * 4u);
    e1 = { b67, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 333u * 4u);
    e3 = { b68, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 334u * 4u);
    e1 = { b69, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 335u * 4u);
    e3 = { b70, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 336u * 4u);
    e1 = { b71, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 337u * 4u);
    e3 = { b72, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 338u * 4u);
    e1 = { b73, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 339u * 4u);
    e3 = { b74, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 340u * 4u);
    e1 = { b75, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 341u * 4u);
    e3 = { b76, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 342u * 4u);
    e1 = { b77, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 343u * 4u);
    e3 = { b78, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 344u * 4u);
    e1 = { b79, b81, b81, b81 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 345u * 4u);
    e3 = { b80, b81, b81, b81 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 346u * 4u);
    e1 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 562u * 4u);
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 563u * 4u);
    e4 = stwo_qm31_mul(e0, e2);
    e2 = stwo_qm31_add(e3, e4);
    e4 = stwo_qm31_mul(e0, e1);
    e1 = { b82, b83, b84, b85 };
    e0 = { b86, b87, b88, b89 };
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
