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
stwo_cairo_cuda_eval_v1_97b90f5aed01bb1c(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 0u, 0u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 225u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 226u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 227u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 228u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 229u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 230u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 231u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 232u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 233u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 234u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 235u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 236u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 237u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 238u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 239u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 240u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 241u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 242u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 243u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 244u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 246u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 247u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 248u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 249u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 250u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 251u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 252u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 253u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 254u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 255u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 257u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 258u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 259u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 260u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 261u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 262u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 263u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 264u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 265u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 266u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 267u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 268u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 269u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 270u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 271u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 272u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 273u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 274u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 275u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 276u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 277u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 278u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 279u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 280u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 281u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 282u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 283u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 284u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 285u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 286u, row, 0);
    unsigned b61 = 0u;
    unsigned b62 = 2u;
    unsigned b63 = stwo_m31_mul(b0, b62);
    b62 = 1u;
    b0 = stwo_m31_add(b63, b62);
    b62 = stwo_trace_value(arena, *args, 2u, 40u, row, 0);
    b63 = stwo_trace_value(arena, *args, 2u, 41u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 2u, 42u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 43u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 44u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 45u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 46u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 47u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 379u * 4u);
    StwoCairoQm31 e1 = { b0, b61, b61, b61 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 380u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 381u * 4u);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 382u * 4u);
    e0 = { b21, b61, b61, b61 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 383u * 4u);
    e2 = { b22, b61, b61, b61 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 384u * 4u);
    e0 = { b23, b61, b61, b61 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 385u * 4u);
    e2 = { b24, b61, b61, b61 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 386u * 4u);
    e0 = { b25, b61, b61, b61 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 387u * 4u);
    e2 = { b26, b61, b61, b61 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 388u * 4u);
    e0 = { b27, b61, b61, b61 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 389u * 4u);
    e2 = { b28, b61, b61, b61 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 390u * 4u);
    e0 = { b29, b61, b61, b61 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 391u * 4u);
    e2 = { b30, b61, b61, b61 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 392u * 4u);
    e0 = { b11, b61, b61, b61 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 393u * 4u);
    e2 = { b12, b61, b61, b61 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 394u * 4u);
    e0 = { b13, b61, b61, b61 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 395u * 4u);
    e2 = { b14, b61, b61, b61 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 396u * 4u);
    e0 = { b15, b61, b61, b61 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 397u * 4u);
    e2 = { b16, b61, b61, b61 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 398u * 4u);
    e0 = { b17, b61, b61, b61 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 399u * 4u);
    e2 = { b18, b61, b61, b61 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 400u * 4u);
    e0 = { b19, b61, b61, b61 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 401u * 4u);
    e2 = { b20, b61, b61, b61 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 402u * 4u);
    e0 = { b1, b61, b61, b61 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 403u * 4u);
    e2 = { b2, b61, b61, b61 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 404u * 4u);
    e0 = { b3, b61, b61, b61 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 405u * 4u);
    e2 = { b4, b61, b61, b61 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 406u * 4u);
    e0 = { b5, b61, b61, b61 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 407u * 4u);
    e2 = { b6, b61, b61, b61 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 408u * 4u);
    e0 = { b7, b61, b61, b61 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 409u * 4u);
    e2 = { b8, b61, b61, b61 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 410u * 4u);
    e0 = { b9, b61, b61, b61 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_qm31_add(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 411u * 4u);
    e2 = { b10, b61, b61, b61 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_qm31_add(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 412u * 4u);
    e0 = stwo_qm31_sub(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 413u * 4u);
    e2 = { b0, b61, b61, b61 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 414u * 4u);
    e1 = stwo_qm31_add(e2, e3);
    e2 = stwo_load_qm31(arena, args->ext_params + 415u * 4u);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 416u * 4u);
    e1 = { b31, b61, b61, b61 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 417u * 4u);
    e3 = { b32, b61, b61, b61 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 418u * 4u);
    e1 = { b33, b61, b61, b61 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 419u * 4u);
    e3 = { b34, b61, b61, b61 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 420u * 4u);
    e1 = { b35, b61, b61, b61 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 421u * 4u);
    e3 = { b36, b61, b61, b61 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 422u * 4u);
    e1 = { b37, b61, b61, b61 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 423u * 4u);
    e3 = { b38, b61, b61, b61 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 424u * 4u);
    e1 = { b39, b61, b61, b61 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 425u * 4u);
    e3 = { b40, b61, b61, b61 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 426u * 4u);
    e1 = { b41, b61, b61, b61 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 427u * 4u);
    e3 = { b42, b61, b61, b61 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 428u * 4u);
    e1 = { b43, b61, b61, b61 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 429u * 4u);
    e3 = { b44, b61, b61, b61 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 430u * 4u);
    e1 = { b45, b61, b61, b61 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 431u * 4u);
    e3 = { b46, b61, b61, b61 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 432u * 4u);
    e1 = { b47, b61, b61, b61 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 433u * 4u);
    e3 = { b48, b61, b61, b61 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 434u * 4u);
    e1 = { b49, b61, b61, b61 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 435u * 4u);
    e3 = { b50, b61, b61, b61 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 436u * 4u);
    e1 = { b51, b61, b61, b61 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 437u * 4u);
    e3 = { b52, b61, b61, b61 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 438u * 4u);
    e1 = { b53, b61, b61, b61 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 439u * 4u);
    e3 = { b54, b61, b61, b61 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 440u * 4u);
    e1 = { b55, b61, b61, b61 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 441u * 4u);
    e3 = { b56, b61, b61, b61 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 442u * 4u);
    e1 = { b57, b61, b61, b61 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 443u * 4u);
    e3 = { b58, b61, b61, b61 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 444u * 4u);
    e1 = { b59, b61, b61, b61 };
    e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 445u * 4u);
    e3 = { b60, b61, b61, b61 };
    e2 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 446u * 4u);
    e1 = stwo_qm31_sub(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 570u * 4u);
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 571u * 4u);
    e4 = stwo_qm31_mul(e0, e2);
    e2 = stwo_qm31_add(e3, e4);
    e4 = stwo_qm31_mul(e0, e1);
    e1 = { b62, b63, b64, b65 };
    e0 = { b66, b67, b68, b69 };
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
