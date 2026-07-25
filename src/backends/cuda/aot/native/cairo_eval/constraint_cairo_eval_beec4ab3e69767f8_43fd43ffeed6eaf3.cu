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
stwo_cairo_cuda_eval_v1_b71e72d81d31b79b(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 382u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 383u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 384u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 385u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 386u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 387u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 388u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 389u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 390u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 391u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 392u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 393u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 394u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 395u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 396u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 397u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 398u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 399u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 400u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 401u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 402u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 403u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 404u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 405u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 406u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 407u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 408u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 409u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 410u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 411u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 412u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 413u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 414u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 415u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 416u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 417u, row, 0);
    unsigned b36 = 0u;
    unsigned b37 = 524288u;
    unsigned b38 = stwo_m31_add(b16, b37);
    b37 = 524288u;
    b16 = stwo_m31_add(b17, b37);
    b37 = 524288u;
    b17 = stwo_m31_add(b18, b37);
    b37 = 524288u;
    b18 = stwo_m31_add(b19, b37);
    b37 = 524288u;
    b19 = stwo_m31_add(b20, b37);
    b37 = 524288u;
    b20 = stwo_m31_add(b21, b37);
    b37 = 524288u;
    b21 = stwo_m31_add(b22, b37);
    b37 = 524288u;
    b22 = stwo_m31_add(b23, b37);
    b37 = 524288u;
    b23 = stwo_m31_add(b24, b37);
    b37 = 524288u;
    b24 = stwo_m31_add(b25, b37);
    b37 = 524288u;
    b25 = stwo_m31_add(b26, b37);
    b37 = 524288u;
    b26 = stwo_m31_add(b27, b37);
    b37 = 524288u;
    b27 = stwo_m31_add(b28, b37);
    b37 = 524288u;
    b28 = stwo_m31_add(b29, b37);
    b37 = 524288u;
    b29 = stwo_m31_add(b30, b37);
    b37 = 524288u;
    b30 = stwo_m31_add(b31, b37);
    b37 = 524288u;
    b31 = stwo_m31_add(b32, b37);
    b37 = 524288u;
    b32 = stwo_m31_add(b33, b37);
    b37 = 524288u;
    b33 = stwo_m31_add(b34, b37);
    b37 = 524288u;
    b34 = stwo_m31_add(b35, b37);
    b37 = stwo_trace_value(arena, *args, 2u, 268u, row, 0);
    b35 = stwo_trace_value(arena, *args, 2u, 269u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 270u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 271u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 272u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 273u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 274u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 275u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 2u, 276u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 2u, 277u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 2u, 278u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 2u, 279u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 2u, 280u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 2u, 281u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 2u, 282u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 2u, 283u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 2u, 284u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 2u, 285u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 2u, 286u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 2u, 287u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 2u, 288u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 2u, 289u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 2u, 290u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 2u, 291u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 2u, 292u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 2u, 293u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 2u, 294u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 2u, 295u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 296u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 297u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 298u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 299u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 300u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 2u, 301u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 2u, 302u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 2u, 303u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 2u, 304u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 2u, 305u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 306u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 307u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 308u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 2u, 309u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 2u, 310u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 2u, 311u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 2u, 312u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 2u, 313u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 314u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 315u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 2u, 316u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 317u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 2u, 318u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 2u, 319u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 2u, 320u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 2u, 321u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 2u, 322u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 2u, 323u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 2u, 324u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 2u, 325u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 2u, 326u, row, 0);
    unsigned b96 = stwo_trace_value(arena, *args, 2u, 327u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 456u * 4u);
    StwoCairoQm31 e1 = { b0, b36, b36, b36 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 457u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 458u * 4u);
    e2 = { b1, b36, b36, b36 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 459u * 4u);
    e0 = stwo_qm31_sub(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 460u * 4u);
    e2 = { b2, b36, b36, b36 };
    e1 = stwo_qm31_mul(e3, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 461u * 4u);
    e3 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 462u * 4u);
    e1 = { b3, b36, b36, b36 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e3, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 463u * 4u);
    e3 = stwo_qm31_sub(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 464u * 4u);
    e1 = { b4, b36, b36, b36 };
    e2 = stwo_qm31_mul(e4, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 465u * 4u);
    e4 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 466u * 4u);
    e2 = { b5, b36, b36, b36 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 467u * 4u);
    e4 = stwo_qm31_sub(e2, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 468u * 4u);
    e2 = { b6, b36, b36, b36 };
    e1 = stwo_qm31_mul(e5, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 469u * 4u);
    e5 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 470u * 4u);
    e1 = { b7, b36, b36, b36 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e5, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 471u * 4u);
    e5 = stwo_qm31_sub(e1, e6);
    e6 = stwo_load_qm31(arena, args->ext_params + 472u * 4u);
    e1 = { b8, b36, b36, b36 };
    e2 = stwo_qm31_mul(e6, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 473u * 4u);
    e6 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 474u * 4u);
    e2 = { b9, b36, b36, b36 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 475u * 4u);
    e6 = stwo_qm31_sub(e2, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 476u * 4u);
    e2 = { b10, b36, b36, b36 };
    e1 = stwo_qm31_mul(e7, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 477u * 4u);
    e7 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 478u * 4u);
    e1 = { b11, b36, b36, b36 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e7, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 479u * 4u);
    e7 = stwo_qm31_sub(e1, e8);
    e8 = stwo_load_qm31(arena, args->ext_params + 480u * 4u);
    e1 = { b12, b36, b36, b36 };
    e2 = stwo_qm31_mul(e8, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 481u * 4u);
    e8 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 482u * 4u);
    e2 = { b13, b36, b36, b36 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 483u * 4u);
    e8 = stwo_qm31_sub(e2, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 484u * 4u);
    e2 = { b14, b36, b36, b36 };
    e1 = stwo_qm31_mul(e9, e2);
    e2 = stwo_load_qm31(arena, args->ext_params + 485u * 4u);
    e9 = stwo_qm31_add(e2, e1);
    e2 = stwo_load_qm31(arena, args->ext_params + 486u * 4u);
    e1 = { b15, b36, b36, b36 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e2, e1);
    e1 = stwo_qm31_add(e9, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 487u * 4u);
    e9 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 488u * 4u);
    e1 = { b38, b36, b36, b36 };
    e2 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 489u * 4u);
    e10 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 490u * 4u);
    e2 = stwo_qm31_sub(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 491u * 4u);
    e10 = { b16, b36, b36, b36 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 492u * 4u);
    e1 = stwo_qm31_add(e10, e11);
    e10 = stwo_load_qm31(arena, args->ext_params + 493u * 4u);
    e11 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 494u * 4u);
    e1 = { b17, b36, b36, b36 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 495u * 4u);
    e10 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(arena, args->ext_params + 496u * 4u);
    e12 = stwo_qm31_sub(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 497u * 4u);
    e10 = { b18, b36, b36, b36 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 498u * 4u);
    e1 = stwo_qm31_add(e10, e13);
    e10 = stwo_load_qm31(arena, args->ext_params + 499u * 4u);
    e13 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 500u * 4u);
    e1 = { b19, b36, b36, b36 };
    StwoCairoQm31 e14 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 501u * 4u);
    e10 = stwo_qm31_add(e1, e14);
    e1 = stwo_load_qm31(arena, args->ext_params + 502u * 4u);
    e14 = stwo_qm31_sub(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 503u * 4u);
    e10 = { b20, b36, b36, b36 };
    StwoCairoQm31 e15 = stwo_qm31_mul(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 504u * 4u);
    e1 = stwo_qm31_add(e10, e15);
    e10 = stwo_load_qm31(arena, args->ext_params + 505u * 4u);
    e15 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 506u * 4u);
    e1 = { b21, b36, b36, b36 };
    StwoCairoQm31 e16 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 507u * 4u);
    e10 = stwo_qm31_add(e1, e16);
    e1 = stwo_load_qm31(arena, args->ext_params + 508u * 4u);
    e16 = stwo_qm31_sub(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 509u * 4u);
    e10 = { b22, b36, b36, b36 };
    StwoCairoQm31 e17 = stwo_qm31_mul(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 510u * 4u);
    e1 = stwo_qm31_add(e10, e17);
    e10 = stwo_load_qm31(arena, args->ext_params + 511u * 4u);
    e17 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 512u * 4u);
    e1 = { b23, b36, b36, b36 };
    StwoCairoQm31 e18 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 513u * 4u);
    e10 = stwo_qm31_add(e1, e18);
    e1 = stwo_load_qm31(arena, args->ext_params + 514u * 4u);
    e18 = stwo_qm31_sub(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 515u * 4u);
    e10 = { b24, b36, b36, b36 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 516u * 4u);
    e1 = stwo_qm31_add(e10, e19);
    e10 = stwo_load_qm31(arena, args->ext_params + 517u * 4u);
    e19 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 518u * 4u);
    e1 = { b25, b36, b36, b36 };
    StwoCairoQm31 e20 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 519u * 4u);
    e10 = stwo_qm31_add(e1, e20);
    e1 = stwo_load_qm31(arena, args->ext_params + 520u * 4u);
    e20 = stwo_qm31_sub(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 521u * 4u);
    e10 = { b26, b36, b36, b36 };
    StwoCairoQm31 e21 = stwo_qm31_mul(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 522u * 4u);
    e1 = stwo_qm31_add(e10, e21);
    e10 = stwo_load_qm31(arena, args->ext_params + 523u * 4u);
    e21 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 524u * 4u);
    e1 = { b27, b36, b36, b36 };
    StwoCairoQm31 e22 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 525u * 4u);
    e10 = stwo_qm31_add(e1, e22);
    e1 = stwo_load_qm31(arena, args->ext_params + 526u * 4u);
    e22 = stwo_qm31_sub(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 527u * 4u);
    e10 = { b28, b36, b36, b36 };
    StwoCairoQm31 e23 = stwo_qm31_mul(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 528u * 4u);
    e1 = stwo_qm31_add(e10, e23);
    e10 = stwo_load_qm31(arena, args->ext_params + 529u * 4u);
    e23 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 530u * 4u);
    e1 = { b29, b36, b36, b36 };
    StwoCairoQm31 e24 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 531u * 4u);
    e10 = stwo_qm31_add(e1, e24);
    e1 = stwo_load_qm31(arena, args->ext_params + 532u * 4u);
    e24 = stwo_qm31_sub(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 533u * 4u);
    e10 = { b30, b36, b36, b36 };
    StwoCairoQm31 e25 = stwo_qm31_mul(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 534u * 4u);
    e1 = stwo_qm31_add(e10, e25);
    e10 = stwo_load_qm31(arena, args->ext_params + 535u * 4u);
    e25 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 536u * 4u);
    e1 = { b31, b36, b36, b36 };
    StwoCairoQm31 e26 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 537u * 4u);
    e10 = stwo_qm31_add(e1, e26);
    e1 = stwo_load_qm31(arena, args->ext_params + 538u * 4u);
    e26 = stwo_qm31_sub(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 539u * 4u);
    e10 = { b32, b36, b36, b36 };
    StwoCairoQm31 e27 = stwo_qm31_mul(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 540u * 4u);
    e1 = stwo_qm31_add(e10, e27);
    e10 = stwo_load_qm31(arena, args->ext_params + 541u * 4u);
    e27 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 542u * 4u);
    e1 = { b33, b36, b36, b36 };
    StwoCairoQm31 e28 = stwo_qm31_mul(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 543u * 4u);
    e10 = stwo_qm31_add(e1, e28);
    e1 = stwo_load_qm31(arena, args->ext_params + 544u * 4u);
    e28 = stwo_qm31_sub(e10, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 545u * 4u);
    e10 = { b34, b36, b36, b36 };
    StwoCairoQm31 e29 = stwo_qm31_mul(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 546u * 4u);
    e1 = stwo_qm31_add(e10, e29);
    e10 = stwo_load_qm31(arena, args->ext_params + 547u * 4u);
    e29 = stwo_qm31_sub(e1, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 1438u * 4u);
    e1 = stwo_qm31_mul(e3, e10);
    e10 = stwo_load_qm31(arena, args->ext_params + 1439u * 4u);
    StwoCairoQm31 e30 = stwo_qm31_mul(e0, e10);
    e10 = stwo_qm31_add(e1, e30);
    e30 = stwo_qm31_mul(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 1440u * 4u);
    e0 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 1441u * 4u);
    e1 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e0, e1);
    e1 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 1442u * 4u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 1443u * 4u);
    e0 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e0);
    e0 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 1444u * 4u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 1445u * 4u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 1446u * 4u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 1447u * 4u);
    e6 = stwo_qm31_mul(e2, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e2, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 1448u * 4u);
    e2 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 1449u * 4u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e2, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 1450u * 4u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 1451u * 4u);
    e2 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e2);
    e2 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 1452u * 4u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 1453u * 4u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 1454u * 4u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 1455u * 4u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 1456u * 4u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 1457u * 4u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e20, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 1458u * 4u);
    e20 = stwo_qm31_mul(e23, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 1459u * 4u);
    e18 = stwo_qm31_mul(e22, e21);
    e21 = stwo_qm31_add(e20, e18);
    e18 = stwo_qm31_mul(e22, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 1460u * 4u);
    e22 = stwo_qm31_mul(e25, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 1461u * 4u);
    e20 = stwo_qm31_mul(e24, e23);
    e23 = stwo_qm31_add(e22, e20);
    e20 = stwo_qm31_mul(e24, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 1462u * 4u);
    e24 = stwo_qm31_mul(e27, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 1463u * 4u);
    e22 = stwo_qm31_mul(e26, e25);
    e25 = stwo_qm31_add(e24, e22);
    e22 = stwo_qm31_mul(e26, e27);
    e27 = stwo_load_qm31(arena, args->ext_params + 1464u * 4u);
    e26 = stwo_qm31_mul(e29, e27);
    e27 = stwo_load_qm31(arena, args->ext_params + 1465u * 4u);
    e24 = stwo_qm31_mul(e28, e27);
    e27 = stwo_qm31_add(e26, e24);
    e24 = stwo_qm31_mul(e28, e29);
    e29 = { b37, b35, b39, b40 };
    e28 = { b41, b42, b43, b44 };
    e26 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e26, e30);
    e26 = stwo_qm31_sub(e29, e10);
    e29 = { b45, b46, b47, b48 };
    e10 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e10, e1);
    e10 = stwo_qm31_sub(e28, e3);
    e28 = { b49, b50, b51, b52 };
    e3 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e3, e0);
    e3 = stwo_qm31_sub(e29, e5);
    e29 = { b53, b54, b55, b56 };
    e5 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e28, e7);
    e28 = { b57, b58, b59, b60 };
    e7 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e29, e9);
    e29 = { b61, b62, b63, b64 };
    e9 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e28, e11);
    e28 = { b65, b66, b67, b68 };
    e11 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e11, e2);
    e11 = stwo_qm31_sub(e29, e13);
    e29 = { b69, b70, b71, b72 };
    e13 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e13, e12);
    e13 = stwo_qm31_sub(e28, e15);
    e28 = { b73, b74, b75, b76 };
    e15 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e15, e14);
    e15 = stwo_qm31_sub(e29, e17);
    e29 = { b77, b78, b79, b80 };
    e17 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e17, e16);
    e17 = stwo_qm31_sub(e28, e19);
    e28 = { b81, b82, b83, b84 };
    e19 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e19, e18);
    e19 = stwo_qm31_sub(e29, e21);
    e29 = { b85, b86, b87, b88 };
    e21 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e21, e20);
    e21 = stwo_qm31_sub(e28, e23);
    e28 = { b89, b90, b91, b92 };
    e23 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e23, e22);
    e23 = stwo_qm31_sub(e29, e25);
    e29 = { b93, b94, b95, b96 };
    e25 = stwo_qm31_sub(e29, e28);
    e29 = stwo_qm31_mul(e25, e24);
    e25 = stwo_qm31_sub(e29, e27);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e26, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e10, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e3, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e5, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e7, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e9, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
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
