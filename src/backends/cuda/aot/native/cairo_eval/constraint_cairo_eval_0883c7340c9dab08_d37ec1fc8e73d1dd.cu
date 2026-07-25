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
stwo_cairo_cuda_eval_v1_cbc96d6a5f79c66e(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 254u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 255u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 256u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 257u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 258u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 259u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 260u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 261u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 262u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 263u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 264u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 265u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 266u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 267u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 268u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 269u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 270u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 271u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 272u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 273u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 274u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 275u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 276u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 277u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 278u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 279u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 280u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 281u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 282u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 283u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 284u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 285u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 286u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 287u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 288u, row, 0);
    unsigned b35 = 0u;
    unsigned b36 = 524288u;
    unsigned b37 = stwo_m31_add(b14, b36);
    b36 = 524288u;
    b14 = stwo_m31_add(b15, b36);
    b36 = 524288u;
    b15 = stwo_m31_add(b16, b36);
    b36 = 524288u;
    b16 = stwo_m31_add(b17, b36);
    b36 = 524288u;
    b17 = stwo_m31_add(b18, b36);
    b36 = 524288u;
    b18 = stwo_m31_add(b19, b36);
    b36 = 524288u;
    b19 = stwo_m31_add(b20, b36);
    b36 = 524288u;
    b20 = stwo_m31_add(b21, b36);
    b36 = 524288u;
    b21 = stwo_m31_add(b22, b36);
    b36 = 524288u;
    b22 = stwo_m31_add(b23, b36);
    b36 = 524288u;
    b23 = stwo_m31_add(b24, b36);
    b36 = 524288u;
    b24 = stwo_m31_add(b25, b36);
    b36 = 524288u;
    b25 = stwo_m31_add(b26, b36);
    b36 = 524288u;
    b26 = stwo_m31_add(b27, b36);
    b36 = 524288u;
    b27 = stwo_m31_add(b28, b36);
    b36 = 524288u;
    b28 = stwo_m31_add(b29, b36);
    b36 = 524288u;
    b29 = stwo_m31_add(b30, b36);
    b36 = 524288u;
    b30 = stwo_m31_add(b31, b36);
    b36 = 524288u;
    b31 = stwo_m31_add(b32, b36);
    b36 = 524288u;
    b32 = stwo_m31_add(b33, b36);
    b36 = 524288u;
    b33 = stwo_m31_add(b34, b36);
    b36 = stwo_trace_value(arena, *args, 2u, 180u, row, 0);
    b34 = stwo_trace_value(arena, *args, 2u, 181u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 2u, 182u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 183u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 184u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 185u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 186u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 187u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 188u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 2u, 189u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 2u, 190u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 2u, 191u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 2u, 192u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 2u, 193u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 2u, 194u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 2u, 195u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 2u, 196u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 2u, 197u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 2u, 198u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 2u, 199u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 2u, 200u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 2u, 201u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 2u, 202u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 2u, 203u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 2u, 204u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 2u, 205u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 2u, 206u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 2u, 207u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 2u, 208u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 209u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 210u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 211u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 212u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 213u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 2u, 214u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 2u, 215u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 2u, 216u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 2u, 217u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 2u, 218u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 219u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 220u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 221u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 2u, 222u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 2u, 223u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 2u, 224u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 2u, 225u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 2u, 226u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 227u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 228u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 2u, 229u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 230u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 2u, 231u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 2u, 232u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 2u, 233u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 2u, 234u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 2u, 235u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 2u, 236u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 2u, 237u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 2u, 238u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 2u, 239u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 367u * 4u);
    StwoCairoQm31 e1 = { b0, b35, b35, b35 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 368u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 369u * 4u);
    e2 = { b1, b35, b35, b35 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 370u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 371u * 4u);
    e2 = { b2, b35, b35, b35 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 372u * 4u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 373u * 4u);
    e1 = { b3, b35, b35, b35 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 374u * 4u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 375u * 4u);
    e1 = { b4, b35, b35, b35 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 376u * 4u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 377u * 4u);
    e2 = { b5, b35, b35, b35 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 378u * 4u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 379u * 4u);
    e2 = { b6, b35, b35, b35 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 380u * 4u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 381u * 4u);
    e1 = { b7, b35, b35, b35 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 382u * 4u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 383u * 4u);
    e1 = { b8, b35, b35, b35 };
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 384u * 4u);
    e6 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 385u * 4u);
    e2 = { b9, b35, b35, b35 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 386u * 4u);
    e6 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 387u * 4u);
    e2 = { b10, b35, b35, b35 };
    e1 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 388u * 4u);
    e7 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 389u * 4u);
    e1 = { b11, b35, b35, b35 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 390u * 4u);
    e7 = stwo_qm31_sub(e1, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 391u * 4u);
    e1 = { b12, b35, b35, b35 };
    e2 = stwo_qm31_mul(e8, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 392u * 4u);
    e8 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 393u * 4u);
    e2 = { b13, b35, b35, b35 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 394u * 4u);
    e8 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 395u * 4u);
    e2 = { b37, b35, b35, b35 };
    e1 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 396u * 4u);
    e9 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 397u * 4u);
    e1 = stwo_qm31_sub(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 398u * 4u);
    e9 = { b14, b35, b35, b35 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 399u * 4u);
    e2 = stwo_qm31_add(e9, e10);
    e9 = stwo_load_qm31(arena, args->ext_params + 400u * 4u);
    e10 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 401u * 4u);
    e2 = { b15, b35, b35, b35 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 402u * 4u);
    e9 = stwo_qm31_add(e2, e11);
    e2 = stwo_load_qm31(arena, args->ext_params + 403u * 4u);
    e11 = stwo_qm31_sub(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 404u * 4u);
    e9 = { b16, b35, b35, b35 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 405u * 4u);
    e2 = stwo_qm31_add(e9, e12);
    e9 = stwo_load_qm31(arena, args->ext_params + 406u * 4u);
    e12 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 407u * 4u);
    e2 = { b17, b35, b35, b35 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 408u * 4u);
    e9 = stwo_qm31_add(e2, e13);
    e2 = stwo_load_qm31(arena, args->ext_params + 409u * 4u);
    e13 = stwo_qm31_sub(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 410u * 4u);
    e9 = { b18, b35, b35, b35 };
    StwoCairoQm31 e14 = stwo_qm31_mul(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 411u * 4u);
    e2 = stwo_qm31_add(e9, e14);
    e9 = stwo_load_qm31(arena, args->ext_params + 412u * 4u);
    e14 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 413u * 4u);
    e2 = { b19, b35, b35, b35 };
    StwoCairoQm31 e15 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 414u * 4u);
    e9 = stwo_qm31_add(e2, e15);
    e2 = stwo_load_qm31(arena, args->ext_params + 415u * 4u);
    e15 = stwo_qm31_sub(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 416u * 4u);
    e9 = { b20, b35, b35, b35 };
    StwoCairoQm31 e16 = stwo_qm31_mul(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 417u * 4u);
    e2 = stwo_qm31_add(e9, e16);
    e9 = stwo_load_qm31(arena, args->ext_params + 418u * 4u);
    e16 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 419u * 4u);
    e2 = { b21, b35, b35, b35 };
    StwoCairoQm31 e17 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 420u * 4u);
    e9 = stwo_qm31_add(e2, e17);
    e2 = stwo_load_qm31(arena, args->ext_params + 421u * 4u);
    e17 = stwo_qm31_sub(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 422u * 4u);
    e9 = { b22, b35, b35, b35 };
    StwoCairoQm31 e18 = stwo_qm31_mul(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 423u * 4u);
    e2 = stwo_qm31_add(e9, e18);
    e9 = stwo_load_qm31(arena, args->ext_params + 424u * 4u);
    e18 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 425u * 4u);
    e2 = { b23, b35, b35, b35 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 426u * 4u);
    e9 = stwo_qm31_add(e2, e19);
    e2 = stwo_load_qm31(arena, args->ext_params + 427u * 4u);
    e19 = stwo_qm31_sub(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 428u * 4u);
    e9 = { b24, b35, b35, b35 };
    StwoCairoQm31 e20 = stwo_qm31_mul(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 429u * 4u);
    e2 = stwo_qm31_add(e9, e20);
    e9 = stwo_load_qm31(arena, args->ext_params + 430u * 4u);
    e20 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 431u * 4u);
    e2 = { b25, b35, b35, b35 };
    StwoCairoQm31 e21 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 432u * 4u);
    e9 = stwo_qm31_add(e2, e21);
    e2 = stwo_load_qm31(arena, args->ext_params + 433u * 4u);
    e21 = stwo_qm31_sub(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 434u * 4u);
    e9 = { b26, b35, b35, b35 };
    StwoCairoQm31 e22 = stwo_qm31_mul(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 435u * 4u);
    e2 = stwo_qm31_add(e9, e22);
    e9 = stwo_load_qm31(arena, args->ext_params + 436u * 4u);
    e22 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 437u * 4u);
    e2 = { b27, b35, b35, b35 };
    StwoCairoQm31 e23 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 438u * 4u);
    e9 = stwo_qm31_add(e2, e23);
    e2 = stwo_load_qm31(arena, args->ext_params + 439u * 4u);
    e23 = stwo_qm31_sub(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 440u * 4u);
    e9 = { b28, b35, b35, b35 };
    StwoCairoQm31 e24 = stwo_qm31_mul(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 441u * 4u);
    e2 = stwo_qm31_add(e9, e24);
    e9 = stwo_load_qm31(arena, args->ext_params + 442u * 4u);
    e24 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 443u * 4u);
    e2 = { b29, b35, b35, b35 };
    StwoCairoQm31 e25 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 444u * 4u);
    e9 = stwo_qm31_add(e2, e25);
    e2 = stwo_load_qm31(arena, args->ext_params + 445u * 4u);
    e25 = stwo_qm31_sub(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 446u * 4u);
    e9 = { b30, b35, b35, b35 };
    StwoCairoQm31 e26 = stwo_qm31_mul(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 447u * 4u);
    e2 = stwo_qm31_add(e9, e26);
    e9 = stwo_load_qm31(arena, args->ext_params + 448u * 4u);
    e26 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 449u * 4u);
    e2 = { b31, b35, b35, b35 };
    StwoCairoQm31 e27 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 450u * 4u);
    e9 = stwo_qm31_add(e2, e27);
    e2 = stwo_load_qm31(arena, args->ext_params + 451u * 4u);
    e27 = stwo_qm31_sub(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 452u * 4u);
    e9 = { b32, b35, b35, b35 };
    StwoCairoQm31 e28 = stwo_qm31_mul(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 453u * 4u);
    e2 = stwo_qm31_add(e9, e28);
    e9 = stwo_load_qm31(arena, args->ext_params + 454u * 4u);
    e28 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 455u * 4u);
    e2 = { b33, b35, b35, b35 };
    StwoCairoQm31 e29 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 456u * 4u);
    e9 = stwo_qm31_add(e2, e29);
    e2 = stwo_load_qm31(arena, args->ext_params + 457u * 4u);
    e29 = stwo_qm31_sub(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 719u * 4u);
    e9 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 720u * 4u);
    StwoCairoQm31 e30 = stwo_qm31_mul(e0, e2);
    e2 = stwo_qm31_add(e9, e30);
    e30 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 721u * 4u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 722u * 4u);
    e9 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e9);
    e9 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 723u * 4u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 724u * 4u);
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 725u * 4u);
    e6 = stwo_qm31_mul(e1, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 726u * 4u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 727u * 4u);
    e8 = stwo_qm31_mul(e11, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 728u * 4u);
    e6 = stwo_qm31_mul(e10, e1);
    e1 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 729u * 4u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 730u * 4u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 731u * 4u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 732u * 4u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 733u * 4u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 734u * 4u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 735u * 4u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 736u * 4u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 737u * 4u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 738u * 4u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e20, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 739u * 4u);
    e20 = stwo_qm31_mul(e23, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 740u * 4u);
    e18 = stwo_qm31_mul(e22, e21);
    e21 = stwo_qm31_add(e20, e18);
    e18 = stwo_qm31_mul(e22, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 741u * 4u);
    e22 = stwo_qm31_mul(e25, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 742u * 4u);
    e20 = stwo_qm31_mul(e24, e23);
    e23 = stwo_qm31_add(e22, e20);
    e20 = stwo_qm31_mul(e24, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 743u * 4u);
    e24 = stwo_qm31_mul(e27, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 744u * 4u);
    e22 = stwo_qm31_mul(e26, e25);
    e25 = stwo_qm31_add(e24, e22);
    e22 = stwo_qm31_mul(e26, e27);
    e27 = stwo_load_qm31(arena, args->ext_params + 745u * 4u);
    e26 = stwo_qm31_mul(e29, e27);
    e27 = stwo_load_qm31(arena, args->ext_params + 746u * 4u);
    e24 = stwo_qm31_mul(e28, e27);
    e27 = stwo_qm31_add(e26, e24);
    e24 = stwo_qm31_mul(e28, e29);
    e29 = { b36, b34, b38, b39 };
    e28 = { b40, b41, b42, b43 };
    e26 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e26, e30);
    e26 = stwo_qm31_sub(e29, e2);
    e29 = { b44, b45, b46, b47 };
    e2 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e2, e9);
    e2 = stwo_qm31_sub(e28, e3);
    e28 = { b48, b49, b50, b51 };
    e3 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e29, e5);
    e29 = { b52, b53, b54, b55 };
    e5 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e28, e7);
    e28 = { b56, b57, b58, b59 };
    e7 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e29, e1);
    e29 = { b60, b61, b62, b63 };
    e1 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e1, e8);
    e1 = stwo_qm31_sub(e28, e11);
    e28 = { b64, b65, b66, b67 };
    e11 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e11, e10);
    e11 = stwo_qm31_sub(e29, e13);
    e29 = { b68, b69, b70, b71 };
    e13 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e28, e15);
    e28 = { b72, b73, b74, b75 };
    e15 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e29, e17);
    e29 = { b76, b77, b78, b79 };
    e17 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e28, e19);
    e28 = { b80, b81, b82, b83 };
    e19 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e19, e18);
    e19 = stwo_qm31_sub(e29, e21);
    e29 = { b84, b85, b86, b87 };
    e21 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e21, e20);
    e21 = stwo_qm31_sub(e28, e23);
    e28 = { b88, b89, b90, b91 };
    e23 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e23, e22);
    e23 = stwo_qm31_sub(e29, e25);
    e29 = { b92, b93, b94, b95 };
    e25 = stwo_qm31_sub(e29, e28);
    e29 = stwo_qm31_mul(e25, e24);
    e25 = stwo_qm31_sub(e29, e27);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e26, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e11, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e13, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e15, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 8u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e17, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 9u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e19, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 10u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e21, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 11u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e23, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 12u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e25, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 13u) * 4u)));
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
