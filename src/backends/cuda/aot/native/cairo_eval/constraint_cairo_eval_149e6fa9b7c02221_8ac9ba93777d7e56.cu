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
stwo_cairo_cuda_eval_v1_de1107274aad99c0(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 219u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 220u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 221u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 222u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 223u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 224u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 225u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 226u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 227u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 228u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 229u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 230u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 231u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 232u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 233u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 234u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 235u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 236u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 237u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 238u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 239u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 240u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 241u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 242u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 243u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 244u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 245u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 246u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 247u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 248u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 249u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 250u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 251u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 252u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 253u, row, 0);
    unsigned b35 = 0u;
    unsigned b36 = 524288u;
    unsigned b37 = stwo_m31_add(b0, b36);
    b36 = 524288u;
    b0 = stwo_m31_add(b1, b36);
    b36 = 524288u;
    b1 = stwo_m31_add(b2, b36);
    b36 = 524288u;
    b2 = stwo_m31_add(b3, b36);
    b36 = 524288u;
    b3 = stwo_m31_add(b4, b36);
    b36 = 524288u;
    b4 = stwo_m31_add(b5, b36);
    b36 = 524288u;
    b5 = stwo_m31_add(b6, b36);
    b36 = 524288u;
    b6 = stwo_m31_add(b7, b36);
    b36 = 524288u;
    b7 = stwo_m31_add(b8, b36);
    b36 = 524288u;
    b8 = stwo_m31_add(b9, b36);
    b36 = 524288u;
    b9 = stwo_m31_add(b10, b36);
    b36 = 524288u;
    b10 = stwo_m31_add(b11, b36);
    b36 = 524288u;
    b11 = stwo_m31_add(b12, b36);
    b36 = 524288u;
    b12 = stwo_m31_add(b13, b36);
    b36 = 524288u;
    b13 = stwo_m31_add(b14, b36);
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
    b36 = stwo_trace_value(arena, *args, 2u, 124u, row, 0);
    b20 = stwo_trace_value(arena, *args, 2u, 125u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 2u, 126u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 2u, 127u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 2u, 128u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 2u, 129u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 2u, 130u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 2u, 131u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 2u, 132u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 2u, 133u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 2u, 134u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 2u, 135u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 2u, 136u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 2u, 137u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 2u, 138u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 2u, 139u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 2u, 140u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 2u, 141u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 2u, 142u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 2u, 143u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 2u, 144u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 2u, 145u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 2u, 146u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 2u, 147u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 2u, 148u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 2u, 149u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 2u, 150u, row, 0);
    unsigned b63 = stwo_trace_value(arena, *args, 2u, 151u, row, 0);
    unsigned b64 = stwo_trace_value(arena, *args, 2u, 152u, row, 0);
    unsigned b65 = stwo_trace_value(arena, *args, 2u, 153u, row, 0);
    unsigned b66 = stwo_trace_value(arena, *args, 2u, 154u, row, 0);
    unsigned b67 = stwo_trace_value(arena, *args, 2u, 155u, row, 0);
    unsigned b68 = stwo_trace_value(arena, *args, 2u, 156u, row, 0);
    unsigned b69 = stwo_trace_value(arena, *args, 2u, 157u, row, 0);
    unsigned b70 = stwo_trace_value(arena, *args, 2u, 158u, row, 0);
    unsigned b71 = stwo_trace_value(arena, *args, 2u, 159u, row, 0);
    unsigned b72 = stwo_trace_value(arena, *args, 2u, 160u, row, 0);
    unsigned b73 = stwo_trace_value(arena, *args, 2u, 161u, row, 0);
    unsigned b74 = stwo_trace_value(arena, *args, 2u, 162u, row, 0);
    unsigned b75 = stwo_trace_value(arena, *args, 2u, 163u, row, 0);
    unsigned b76 = stwo_trace_value(arena, *args, 2u, 164u, row, 0);
    unsigned b77 = stwo_trace_value(arena, *args, 2u, 165u, row, 0);
    unsigned b78 = stwo_trace_value(arena, *args, 2u, 166u, row, 0);
    unsigned b79 = stwo_trace_value(arena, *args, 2u, 167u, row, 0);
    unsigned b80 = stwo_trace_value(arena, *args, 2u, 168u, row, 0);
    unsigned b81 = stwo_trace_value(arena, *args, 2u, 169u, row, 0);
    unsigned b82 = stwo_trace_value(arena, *args, 2u, 170u, row, 0);
    unsigned b83 = stwo_trace_value(arena, *args, 2u, 171u, row, 0);
    unsigned b84 = stwo_trace_value(arena, *args, 2u, 172u, row, 0);
    unsigned b85 = stwo_trace_value(arena, *args, 2u, 173u, row, 0);
    unsigned b86 = stwo_trace_value(arena, *args, 2u, 174u, row, 0);
    unsigned b87 = stwo_trace_value(arena, *args, 2u, 175u, row, 0);
    unsigned b88 = stwo_trace_value(arena, *args, 2u, 176u, row, 0);
    unsigned b89 = stwo_trace_value(arena, *args, 2u, 177u, row, 0);
    unsigned b90 = stwo_trace_value(arena, *args, 2u, 178u, row, 0);
    unsigned b91 = stwo_trace_value(arena, *args, 2u, 179u, row, 0);
    unsigned b92 = stwo_trace_value(arena, *args, 2u, 180u, row, 0);
    unsigned b93 = stwo_trace_value(arena, *args, 2u, 181u, row, 0);
    unsigned b94 = stwo_trace_value(arena, *args, 2u, 182u, row, 0);
    unsigned b95 = stwo_trace_value(arena, *args, 2u, 183u, row, 0);
    StwoCairoQm31 e0 = stwo_load_qm31(arena, args->ext_params + 276u * 4u);
    StwoCairoQm31 e1 = { b37, b35, b35, b35 };
    StwoCairoQm31 e2 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 277u * 4u);
    e0 = stwo_qm31_add(e1, e2);
    e1 = stwo_load_qm31(arena, args->ext_params + 278u * 4u);
    e2 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 279u * 4u);
    e0 = { b0, b35, b35, b35 };
    StwoCairoQm31 e3 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 280u * 4u);
    e1 = stwo_qm31_add(e0, e3);
    e0 = stwo_load_qm31(arena, args->ext_params + 281u * 4u);
    e3 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 282u * 4u);
    e1 = { b1, b35, b35, b35 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 283u * 4u);
    e0 = stwo_qm31_add(e1, e4);
    e1 = stwo_load_qm31(arena, args->ext_params + 284u * 4u);
    e4 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 285u * 4u);
    e0 = { b2, b35, b35, b35 };
    StwoCairoQm31 e5 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 286u * 4u);
    e1 = stwo_qm31_add(e0, e5);
    e0 = stwo_load_qm31(arena, args->ext_params + 287u * 4u);
    e5 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 288u * 4u);
    e1 = { b3, b35, b35, b35 };
    StwoCairoQm31 e6 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 289u * 4u);
    e0 = stwo_qm31_add(e1, e6);
    e1 = stwo_load_qm31(arena, args->ext_params + 290u * 4u);
    e6 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 291u * 4u);
    e0 = { b4, b35, b35, b35 };
    StwoCairoQm31 e7 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 292u * 4u);
    e1 = stwo_qm31_add(e0, e7);
    e0 = stwo_load_qm31(arena, args->ext_params + 293u * 4u);
    e7 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 294u * 4u);
    e1 = { b5, b35, b35, b35 };
    StwoCairoQm31 e8 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 295u * 4u);
    e0 = stwo_qm31_add(e1, e8);
    e1 = stwo_load_qm31(arena, args->ext_params + 296u * 4u);
    e8 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 297u * 4u);
    e0 = { b6, b35, b35, b35 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 298u * 4u);
    e1 = stwo_qm31_add(e0, e9);
    e0 = stwo_load_qm31(arena, args->ext_params + 299u * 4u);
    e9 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 300u * 4u);
    e1 = { b7, b35, b35, b35 };
    StwoCairoQm31 e10 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 301u * 4u);
    e0 = stwo_qm31_add(e1, e10);
    e1 = stwo_load_qm31(arena, args->ext_params + 302u * 4u);
    e10 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 303u * 4u);
    e0 = { b8, b35, b35, b35 };
    StwoCairoQm31 e11 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 304u * 4u);
    e1 = stwo_qm31_add(e0, e11);
    e0 = stwo_load_qm31(arena, args->ext_params + 305u * 4u);
    e11 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 306u * 4u);
    e1 = { b9, b35, b35, b35 };
    StwoCairoQm31 e12 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 307u * 4u);
    e0 = stwo_qm31_add(e1, e12);
    e1 = stwo_load_qm31(arena, args->ext_params + 308u * 4u);
    e12 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 309u * 4u);
    e0 = { b10, b35, b35, b35 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 310u * 4u);
    e1 = stwo_qm31_add(e0, e13);
    e0 = stwo_load_qm31(arena, args->ext_params + 311u * 4u);
    e13 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 312u * 4u);
    e1 = { b11, b35, b35, b35 };
    StwoCairoQm31 e14 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 313u * 4u);
    e0 = stwo_qm31_add(e1, e14);
    e1 = stwo_load_qm31(arena, args->ext_params + 314u * 4u);
    e14 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 315u * 4u);
    e0 = { b12, b35, b35, b35 };
    StwoCairoQm31 e15 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 316u * 4u);
    e1 = stwo_qm31_add(e0, e15);
    e0 = stwo_load_qm31(arena, args->ext_params + 317u * 4u);
    e15 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 318u * 4u);
    e1 = { b13, b35, b35, b35 };
    StwoCairoQm31 e16 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 319u * 4u);
    e0 = stwo_qm31_add(e1, e16);
    e1 = stwo_load_qm31(arena, args->ext_params + 320u * 4u);
    e16 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 321u * 4u);
    e0 = { b14, b35, b35, b35 };
    StwoCairoQm31 e17 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 322u * 4u);
    e1 = stwo_qm31_add(e0, e17);
    e0 = stwo_load_qm31(arena, args->ext_params + 323u * 4u);
    e17 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 324u * 4u);
    e1 = { b15, b35, b35, b35 };
    StwoCairoQm31 e18 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 325u * 4u);
    e0 = stwo_qm31_add(e1, e18);
    e1 = stwo_load_qm31(arena, args->ext_params + 326u * 4u);
    e18 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 327u * 4u);
    e0 = { b16, b35, b35, b35 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 328u * 4u);
    e1 = stwo_qm31_add(e0, e19);
    e0 = stwo_load_qm31(arena, args->ext_params + 329u * 4u);
    e19 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 330u * 4u);
    e1 = { b17, b35, b35, b35 };
    StwoCairoQm31 e20 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 331u * 4u);
    e0 = stwo_qm31_add(e1, e20);
    e1 = stwo_load_qm31(arena, args->ext_params + 332u * 4u);
    e20 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 333u * 4u);
    e0 = { b18, b35, b35, b35 };
    StwoCairoQm31 e21 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 334u * 4u);
    e1 = stwo_qm31_add(e0, e21);
    e0 = stwo_load_qm31(arena, args->ext_params + 335u * 4u);
    e21 = stwo_qm31_sub(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 336u * 4u);
    e1 = { b19, b35, b35, b35 };
    StwoCairoQm31 e22 = stwo_qm31_mul(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 337u * 4u);
    e0 = stwo_qm31_add(e1, e22);
    e1 = stwo_load_qm31(arena, args->ext_params + 338u * 4u);
    e22 = stwo_qm31_sub(e0, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 339u * 4u);
    e0 = { b21, b35, b35, b35 };
    StwoCairoQm31 e23 = stwo_qm31_mul(e1, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 340u * 4u);
    e1 = stwo_qm31_add(e0, e23);
    e0 = stwo_load_qm31(arena, args->ext_params + 341u * 4u);
    e23 = { b22, b35, b35, b35 };
    StwoCairoQm31 e24 = stwo_qm31_mul(e0, e23);
    e23 = stwo_qm31_add(e1, e24);
    e24 = stwo_load_qm31(arena, args->ext_params + 342u * 4u);
    e1 = stwo_qm31_sub(e23, e24);
    e24 = stwo_load_qm31(arena, args->ext_params + 343u * 4u);
    e23 = { b23, b35, b35, b35 };
    e0 = stwo_qm31_mul(e24, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 344u * 4u);
    e24 = stwo_qm31_add(e23, e0);
    e23 = stwo_load_qm31(arena, args->ext_params + 345u * 4u);
    e0 = { b24, b35, b35, b35 };
    StwoCairoQm31 e25 = stwo_qm31_mul(e23, e0);
    e0 = stwo_qm31_add(e24, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 346u * 4u);
    e24 = stwo_qm31_sub(e0, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 347u * 4u);
    e0 = { b25, b35, b35, b35 };
    e23 = stwo_qm31_mul(e25, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 348u * 4u);
    e25 = stwo_qm31_add(e0, e23);
    e0 = stwo_load_qm31(arena, args->ext_params + 349u * 4u);
    e23 = { b26, b35, b35, b35 };
    StwoCairoQm31 e26 = stwo_qm31_mul(e0, e23);
    e23 = stwo_qm31_add(e25, e26);
    e26 = stwo_load_qm31(arena, args->ext_params + 350u * 4u);
    e25 = stwo_qm31_sub(e23, e26);
    e26 = stwo_load_qm31(arena, args->ext_params + 351u * 4u);
    e23 = { b27, b35, b35, b35 };
    e0 = stwo_qm31_mul(e26, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 352u * 4u);
    e26 = stwo_qm31_add(e23, e0);
    e23 = stwo_load_qm31(arena, args->ext_params + 353u * 4u);
    e0 = { b28, b35, b35, b35 };
    StwoCairoQm31 e27 = stwo_qm31_mul(e23, e0);
    e0 = stwo_qm31_add(e26, e27);
    e27 = stwo_load_qm31(arena, args->ext_params + 354u * 4u);
    e26 = stwo_qm31_sub(e0, e27);
    e27 = stwo_load_qm31(arena, args->ext_params + 355u * 4u);
    e0 = { b29, b35, b35, b35 };
    e23 = stwo_qm31_mul(e27, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 356u * 4u);
    e27 = stwo_qm31_add(e0, e23);
    e0 = stwo_load_qm31(arena, args->ext_params + 357u * 4u);
    e23 = { b30, b35, b35, b35 };
    StwoCairoQm31 e28 = stwo_qm31_mul(e0, e23);
    e23 = stwo_qm31_add(e27, e28);
    e28 = stwo_load_qm31(arena, args->ext_params + 358u * 4u);
    e27 = stwo_qm31_sub(e23, e28);
    e28 = stwo_load_qm31(arena, args->ext_params + 359u * 4u);
    e23 = { b31, b35, b35, b35 };
    e0 = stwo_qm31_mul(e28, e23);
    e23 = stwo_load_qm31(arena, args->ext_params + 360u * 4u);
    e28 = stwo_qm31_add(e23, e0);
    e23 = stwo_load_qm31(arena, args->ext_params + 361u * 4u);
    e0 = { b32, b35, b35, b35 };
    StwoCairoQm31 e29 = stwo_qm31_mul(e23, e0);
    e0 = stwo_qm31_add(e28, e29);
    e29 = stwo_load_qm31(arena, args->ext_params + 362u * 4u);
    e28 = stwo_qm31_sub(e0, e29);
    e29 = stwo_load_qm31(arena, args->ext_params + 363u * 4u);
    e0 = { b33, b35, b35, b35 };
    e23 = stwo_qm31_mul(e29, e0);
    e0 = stwo_load_qm31(arena, args->ext_params + 364u * 4u);
    e29 = stwo_qm31_add(e0, e23);
    e0 = stwo_load_qm31(arena, args->ext_params + 365u * 4u);
    e23 = { b34, b35, b35, b35 };
    StwoCairoQm31 e30 = stwo_qm31_mul(e0, e23);
    e23 = stwo_qm31_add(e29, e30);
    e30 = stwo_load_qm31(arena, args->ext_params + 366u * 4u);
    e29 = stwo_qm31_sub(e23, e30);
    e30 = stwo_load_qm31(arena, args->ext_params + 691u * 4u);
    e23 = stwo_qm31_mul(e3, e30);
    e30 = stwo_load_qm31(arena, args->ext_params + 692u * 4u);
    e0 = stwo_qm31_mul(e2, e30);
    e30 = stwo_qm31_add(e23, e0);
    e0 = stwo_qm31_mul(e2, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 693u * 4u);
    e2 = stwo_qm31_mul(e5, e3);
    e3 = stwo_load_qm31(arena, args->ext_params + 694u * 4u);
    e23 = stwo_qm31_mul(e4, e3);
    e3 = stwo_qm31_add(e2, e23);
    e23 = stwo_qm31_mul(e4, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 695u * 4u);
    e4 = stwo_qm31_mul(e7, e5);
    e5 = stwo_load_qm31(arena, args->ext_params + 696u * 4u);
    e2 = stwo_qm31_mul(e6, e5);
    e5 = stwo_qm31_add(e4, e2);
    e2 = stwo_qm31_mul(e6, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 697u * 4u);
    e6 = stwo_qm31_mul(e9, e7);
    e7 = stwo_load_qm31(arena, args->ext_params + 698u * 4u);
    e4 = stwo_qm31_mul(e8, e7);
    e7 = stwo_qm31_add(e6, e4);
    e4 = stwo_qm31_mul(e8, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 699u * 4u);
    e8 = stwo_qm31_mul(e11, e9);
    e9 = stwo_load_qm31(arena, args->ext_params + 700u * 4u);
    e6 = stwo_qm31_mul(e10, e9);
    e9 = stwo_qm31_add(e8, e6);
    e6 = stwo_qm31_mul(e10, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 701u * 4u);
    e10 = stwo_qm31_mul(e13, e11);
    e11 = stwo_load_qm31(arena, args->ext_params + 702u * 4u);
    e8 = stwo_qm31_mul(e12, e11);
    e11 = stwo_qm31_add(e10, e8);
    e8 = stwo_qm31_mul(e12, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 703u * 4u);
    e12 = stwo_qm31_mul(e15, e13);
    e13 = stwo_load_qm31(arena, args->ext_params + 704u * 4u);
    e10 = stwo_qm31_mul(e14, e13);
    e13 = stwo_qm31_add(e12, e10);
    e10 = stwo_qm31_mul(e14, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 705u * 4u);
    e14 = stwo_qm31_mul(e17, e15);
    e15 = stwo_load_qm31(arena, args->ext_params + 706u * 4u);
    e12 = stwo_qm31_mul(e16, e15);
    e15 = stwo_qm31_add(e14, e12);
    e12 = stwo_qm31_mul(e16, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 707u * 4u);
    e16 = stwo_qm31_mul(e19, e17);
    e17 = stwo_load_qm31(arena, args->ext_params + 708u * 4u);
    e14 = stwo_qm31_mul(e18, e17);
    e17 = stwo_qm31_add(e16, e14);
    e14 = stwo_qm31_mul(e18, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 709u * 4u);
    e18 = stwo_qm31_mul(e21, e19);
    e19 = stwo_load_qm31(arena, args->ext_params + 710u * 4u);
    e16 = stwo_qm31_mul(e20, e19);
    e19 = stwo_qm31_add(e18, e16);
    e16 = stwo_qm31_mul(e20, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 711u * 4u);
    e20 = stwo_qm31_mul(e1, e21);
    e21 = stwo_load_qm31(arena, args->ext_params + 712u * 4u);
    e18 = stwo_qm31_mul(e22, e21);
    e21 = stwo_qm31_add(e20, e18);
    e18 = stwo_qm31_mul(e22, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 713u * 4u);
    e22 = stwo_qm31_mul(e25, e1);
    e1 = stwo_load_qm31(arena, args->ext_params + 714u * 4u);
    e20 = stwo_qm31_mul(e24, e1);
    e1 = stwo_qm31_add(e22, e20);
    e20 = stwo_qm31_mul(e24, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 715u * 4u);
    e24 = stwo_qm31_mul(e27, e25);
    e25 = stwo_load_qm31(arena, args->ext_params + 716u * 4u);
    e22 = stwo_qm31_mul(e26, e25);
    e25 = stwo_qm31_add(e24, e22);
    e22 = stwo_qm31_mul(e26, e27);
    e27 = stwo_load_qm31(arena, args->ext_params + 717u * 4u);
    e26 = stwo_qm31_mul(e29, e27);
    e27 = stwo_load_qm31(arena, args->ext_params + 718u * 4u);
    e24 = stwo_qm31_mul(e28, e27);
    e27 = stwo_qm31_add(e26, e24);
    e24 = stwo_qm31_mul(e28, e29);
    e29 = { b36, b20, b38, b39 };
    e28 = { b40, b41, b42, b43 };
    e26 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e26, e0);
    e26 = stwo_qm31_sub(e29, e30);
    e29 = { b44, b45, b46, b47 };
    e30 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e30, e23);
    e30 = stwo_qm31_sub(e28, e3);
    e28 = { b48, b49, b50, b51 };
    e3 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e3, e2);
    e3 = stwo_qm31_sub(e29, e5);
    e29 = { b52, b53, b54, b55 };
    e5 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e5, e4);
    e5 = stwo_qm31_sub(e28, e7);
    e28 = { b56, b57, b58, b59 };
    e7 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e7, e6);
    e7 = stwo_qm31_sub(e29, e9);
    e29 = { b60, b61, b62, b63 };
    e9 = stwo_qm31_sub(e29, e28);
    e28 = stwo_qm31_mul(e9, e8);
    e9 = stwo_qm31_sub(e28, e11);
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
    e21 = stwo_qm31_sub(e28, e1);
    e28 = { b88, b89, b90, b91 };
    e1 = stwo_qm31_sub(e28, e29);
    e29 = stwo_qm31_mul(e1, e22);
    e1 = stwo_qm31_sub(e29, e25);
    e29 = { b92, b93, b94, b95 };
    e25 = stwo_qm31_sub(e29, e28);
    e29 = stwo_qm31_mul(e25, e24);
    e25 = stwo_qm31_sub(e29, e27);
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e26, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e30, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
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
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 12u) * 4u)));
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
