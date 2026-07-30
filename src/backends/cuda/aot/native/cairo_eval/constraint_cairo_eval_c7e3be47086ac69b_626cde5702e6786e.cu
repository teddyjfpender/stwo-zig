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
stwo_cairo_cuda_eval_v1_1bd7118f332442d0(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 3u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 4u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 257u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 258u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 259u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 260u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 261u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 262u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 263u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 264u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 265u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 266u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 267u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 268u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 269u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 270u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 271u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 272u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 273u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 274u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 275u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 276u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 287u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 288u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 289u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 290u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 291u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 292u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 293u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 294u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 295u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 296u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 297u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 298u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 299u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 300u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 301u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 302u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 303u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 304u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 305u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 306u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 307u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 308u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 309u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 310u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 311u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 312u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 313u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 314u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 315u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 316u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 317u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 318u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 319u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 320u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 321u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 322u, row, 0);
    unsigned b58 = 0u;
    unsigned b59 = stwo_m31_sub(b2, b22);
    b2 = 512u;
    unsigned b60 = stwo_m31_mul(b23, b2);
    b2 = stwo_m31_sub(b59, b60);
    b60 = 8192u;
    b59 = stwo_m31_mul(b2, b60);
    b60 = stwo_m31_sub(b3, b24);
    b3 = 512u;
    b2 = stwo_m31_mul(b25, b3);
    b3 = stwo_m31_sub(b60, b2);
    b2 = 8192u;
    b60 = stwo_m31_mul(b3, b2);
    b2 = stwo_m31_sub(b4, b26);
    b4 = 512u;
    b3 = stwo_m31_mul(b27, b4);
    b4 = stwo_m31_sub(b2, b3);
    b3 = 8192u;
    b2 = stwo_m31_mul(b4, b3);
    b3 = stwo_m31_sub(b5, b28);
    b5 = 512u;
    b4 = stwo_m31_mul(b29, b5);
    b5 = stwo_m31_sub(b3, b4);
    b4 = 8192u;
    b3 = stwo_m31_mul(b5, b4);
    b4 = stwo_m31_sub(b6, b30);
    b6 = 512u;
    b5 = stwo_m31_mul(b31, b6);
    b6 = stwo_m31_sub(b4, b5);
    b5 = 8192u;
    b4 = stwo_m31_mul(b6, b5);
    b5 = stwo_m31_sub(b7, b32);
    b7 = 512u;
    b6 = stwo_m31_mul(b33, b7);
    b7 = stwo_m31_sub(b5, b6);
    b6 = 8192u;
    b5 = stwo_m31_mul(b7, b6);
    b6 = stwo_m31_sub(b8, b34);
    b8 = 512u;
    b7 = stwo_m31_mul(b35, b8);
    b8 = stwo_m31_sub(b6, b7);
    b7 = 8192u;
    b6 = stwo_m31_mul(b8, b7);
    b7 = stwo_m31_sub(b9, b36);
    b9 = 512u;
    b8 = stwo_m31_mul(b37, b9);
    b9 = stwo_m31_sub(b7, b8);
    b8 = 8192u;
    b7 = stwo_m31_mul(b9, b8);
    b8 = stwo_m31_sub(b10, b38);
    b10 = 512u;
    b9 = stwo_m31_mul(b39, b10);
    b10 = stwo_m31_sub(b8, b9);
    b9 = 8192u;
    b8 = stwo_m31_mul(b10, b9);
    b9 = stwo_m31_sub(b12, b40);
    b12 = 512u;
    b10 = stwo_m31_mul(b41, b12);
    b12 = stwo_m31_sub(b9, b10);
    b10 = 8192u;
    b9 = stwo_m31_mul(b12, b10);
    b10 = stwo_m31_sub(b13, b42);
    b13 = 512u;
    b12 = stwo_m31_mul(b43, b13);
    b13 = stwo_m31_sub(b10, b12);
    b12 = 8192u;
    b10 = stwo_m31_mul(b13, b12);
    b12 = stwo_m31_sub(b14, b44);
    b14 = 512u;
    b13 = stwo_m31_mul(b45, b14);
    b14 = stwo_m31_sub(b12, b13);
    b13 = 8192u;
    b12 = stwo_m31_mul(b14, b13);
    b13 = stwo_m31_sub(b15, b46);
    b15 = 512u;
    b14 = stwo_m31_mul(b47, b15);
    b15 = stwo_m31_sub(b13, b14);
    b14 = 8192u;
    b13 = stwo_m31_mul(b15, b14);
    b14 = stwo_m31_sub(b16, b48);
    b16 = 512u;
    b15 = stwo_m31_mul(b49, b16);
    b16 = stwo_m31_sub(b14, b15);
    b15 = 8192u;
    b14 = stwo_m31_mul(b16, b15);
    b15 = stwo_m31_sub(b17, b50);
    b17 = 512u;
    b16 = stwo_m31_mul(b51, b17);
    b17 = stwo_m31_sub(b15, b16);
    b16 = 8192u;
    b15 = stwo_m31_mul(b17, b16);
    b16 = stwo_m31_sub(b18, b52);
    b18 = 512u;
    b17 = stwo_m31_mul(b53, b18);
    b18 = stwo_m31_sub(b16, b17);
    b17 = 8192u;
    b16 = stwo_m31_mul(b18, b17);
    b17 = stwo_m31_sub(b19, b54);
    b19 = 512u;
    b18 = stwo_m31_mul(b55, b19);
    b19 = stwo_m31_sub(b17, b18);
    b18 = 8192u;
    b17 = stwo_m31_mul(b19, b18);
    b18 = stwo_m31_sub(b20, b56);
    b20 = 512u;
    b19 = stwo_m31_mul(b57, b20);
    b20 = stwo_m31_sub(b18, b19);
    b19 = 8192u;
    b18 = stwo_m31_mul(b20, b19);
    b19 = stwo_trace_value(arena, *args, 2u, 44u, row, 0);
    b20 = stwo_trace_value(arena, *args, 2u, 45u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 2u, 46u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 2u, 47u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 2u, 48u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 2u, 49u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 50u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 51u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 447u * 4u);
    StwoCairoQm31 e1 = { b0, b58, b58, b58 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 448u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 449u * 4u);
    e2 = { b22, b58, b58, b58 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 450u * 4u);
    e0 = { b23, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 451u * 4u);
    e2 = { b59, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 452u * 4u);
    e0 = { b24, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 453u * 4u);
    e2 = { b25, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 454u * 4u);
    e0 = { b60, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 455u * 4u);
    e2 = { b26, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 456u * 4u);
    e0 = { b27, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 457u * 4u);
    e2 = { b2, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 458u * 4u);
    e0 = { b28, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 459u * 4u);
    e2 = { b29, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 460u * 4u);
    e0 = { b3, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 461u * 4u);
    e2 = { b30, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 462u * 4u);
    e0 = { b31, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 463u * 4u);
    e2 = { b4, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 464u * 4u);
    e0 = { b32, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 465u * 4u);
    e2 = { b33, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 466u * 4u);
    e0 = { b5, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 467u * 4u);
    e2 = { b34, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 468u * 4u);
    e0 = { b35, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 469u * 4u);
    e2 = { b6, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 470u * 4u);
    e0 = { b36, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 471u * 4u);
    e2 = { b37, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 472u * 4u);
    e0 = { b7, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 473u * 4u);
    e2 = { b38, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 474u * 4u);
    e0 = { b39, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 475u * 4u);
    e2 = { b8, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e2);
    e2 = stwo_qm31_add(e0, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 476u * 4u);
    e0 = { b11, b58, b58, b58 };
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_qm31_add(e2, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 477u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 478u * 4u);
    e0 = { b1, b58, b58, b58 };
    e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 479u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 480u * 4u);
    e3 = { b40, b58, b58, b58 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 481u * 4u);
    e1 = { b41, b58, b58, b58 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 482u * 4u);
    e3 = { b9, b58, b58, b58 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 483u * 4u);
    e1 = { b42, b58, b58, b58 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 484u * 4u);
    e3 = { b43, b58, b58, b58 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 485u * 4u);
    e1 = { b10, b58, b58, b58 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 486u * 4u);
    e3 = { b44, b58, b58, b58 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 487u * 4u);
    e1 = { b45, b58, b58, b58 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 488u * 4u);
    e3 = { b12, b58, b58, b58 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 489u * 4u);
    e1 = { b46, b58, b58, b58 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 490u * 4u);
    e3 = { b47, b58, b58, b58 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 491u * 4u);
    e1 = { b13, b58, b58, b58 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 492u * 4u);
    e3 = { b48, b58, b58, b58 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 493u * 4u);
    e1 = { b49, b58, b58, b58 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 494u * 4u);
    e3 = { b14, b58, b58, b58 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 495u * 4u);
    e1 = { b50, b58, b58, b58 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 496u * 4u);
    e3 = { b51, b58, b58, b58 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 497u * 4u);
    e1 = { b15, b58, b58, b58 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 498u * 4u);
    e3 = { b52, b58, b58, b58 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 499u * 4u);
    e1 = { b53, b58, b58, b58 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 500u * 4u);
    e3 = { b16, b58, b58, b58 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 501u * 4u);
    e1 = { b54, b58, b58, b58 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 502u * 4u);
    e3 = { b55, b58, b58, b58 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 503u * 4u);
    e1 = { b17, b58, b58, b58 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 504u * 4u);
    e3 = { b56, b58, b58, b58 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 505u * 4u);
    e1 = { b57, b58, b58, b58 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 506u * 4u);
    e3 = { b18, b58, b58, b58 };
    e4 = stwo_qm31_mul(e0, e3);
    e3 = stwo_qm31_add(e1, e4);
    e4 = stwo_load_qm31(arena, args->ext_params + 507u * 4u);
    e1 = { b21, b58, b58, b58 };
    e0 = stwo_qm31_mul(e4, e1);
    e1 = stwo_qm31_add(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 508u * 4u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 572u * 4u);
    e1 = stwo_qm31_mul(e3, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 573u * 4u);
    e4 = stwo_qm31_mul(e2, e0);
    e0 = stwo_qm31_add(e1, e4);
    e4 = stwo_qm31_mul(e2, e3);
    e3 = { b19, b20, b61, b62 };
    e2 = { b63, b64, b65, b66 };
    e1 = stwo_qm31_sub(e2, e3);
    e2 = stwo_qm31_mul(e1, e4);
    e1 = stwo_qm31_sub(e2, e0);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
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
