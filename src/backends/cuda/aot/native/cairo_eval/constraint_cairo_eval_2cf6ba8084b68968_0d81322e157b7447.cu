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
stwo_cairo_cuda_eval_v1_7887b583ca517b8d(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    unsigned b0 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 1u, 71u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 1u, 72u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 1u, 73u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 1u, 77u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 78u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 79u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 80u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 146u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 147u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 148u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 149u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 150u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 151u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 152u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 153u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 154u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 155u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 156u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 157u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 158u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 159u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 160u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 161u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 162u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 163u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 164u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 165u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 166u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 167u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 168u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 169u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 170u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 171u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 172u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 173u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 205u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 206u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 207u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 211u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 212u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 213u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 214u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 240u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 241u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 242u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 243u, row, 0);
    unsigned b53 = 0u;
    unsigned b54 = stwo_m31_add(b7, b0);
    b7 = stwo_m31_add(b54, b42);
    b54 = stwo_m31_add(b8, b1);
    b8 = stwo_m31_add(b54, b43);
    b54 = stwo_m31_add(b9, b2);
    b9 = stwo_m31_add(b54, b44);
    b54 = stwo_m31_add(b10, b3);
    b10 = stwo_m31_add(b54, b45);
    b54 = stwo_m31_add(b11, b4);
    b11 = stwo_m31_add(b54, b46);
    b54 = stwo_m31_add(b12, b5);
    b12 = stwo_m31_add(b54, b47);
    b54 = stwo_m31_add(b13, b6);
    b13 = stwo_m31_add(b54, b48);
    b54 = stwo_m31_mul(b14, b16);
    b48 = stwo_m31_mul(b15, b15);
    b6 = stwo_m31_add(b54, b48);
    b48 = stwo_m31_mul(b16, b14);
    b54 = stwo_m31_add(b6, b48);
    b48 = stwo_m31_mul(b14, b17);
    b6 = stwo_m31_mul(b15, b16);
    b47 = stwo_m31_add(b48, b6);
    b6 = stwo_m31_mul(b16, b15);
    b48 = stwo_m31_add(b47, b6);
    b6 = stwo_m31_mul(b17, b14);
    b47 = stwo_m31_add(b48, b6);
    b6 = stwo_m31_mul(b14, b18);
    b48 = stwo_m31_mul(b15, b17);
    b5 = stwo_m31_add(b6, b48);
    b48 = stwo_m31_mul(b16, b16);
    b6 = stwo_m31_add(b5, b48);
    b48 = stwo_m31_mul(b17, b15);
    b5 = stwo_m31_add(b6, b48);
    b48 = stwo_m31_mul(b18, b14);
    b6 = stwo_m31_add(b5, b48);
    b48 = stwo_m31_mul(b14, b19);
    b5 = stwo_m31_mul(b15, b18);
    b46 = stwo_m31_add(b48, b5);
    b5 = stwo_m31_mul(b16, b17);
    b48 = stwo_m31_add(b46, b5);
    b5 = stwo_m31_mul(b17, b16);
    b46 = stwo_m31_add(b48, b5);
    b5 = stwo_m31_mul(b18, b15);
    b48 = stwo_m31_add(b46, b5);
    b5 = stwo_m31_mul(b19, b14);
    b46 = stwo_m31_add(b48, b5);
    b5 = stwo_m31_mul(b17, b20);
    b48 = stwo_m31_mul(b18, b19);
    b4 = stwo_m31_add(b5, b48);
    b48 = stwo_m31_mul(b19, b18);
    b5 = stwo_m31_add(b4, b48);
    b48 = stwo_m31_mul(b20, b17);
    b4 = stwo_m31_add(b5, b48);
    b48 = stwo_m31_mul(b18, b20);
    b5 = stwo_m31_mul(b19, b19);
    b45 = stwo_m31_add(b48, b5);
    b5 = stwo_m31_mul(b20, b18);
    b48 = stwo_m31_add(b45, b5);
    b5 = stwo_m31_mul(b19, b20);
    b45 = stwo_m31_mul(b20, b19);
    b3 = stwo_m31_add(b5, b45);
    b45 = stwo_m31_mul(b20, b20);
    b5 = stwo_m31_mul(b21, b23);
    b44 = stwo_m31_mul(b22, b22);
    b2 = stwo_m31_add(b5, b44);
    b44 = stwo_m31_mul(b23, b21);
    b5 = stwo_m31_add(b2, b44);
    b44 = stwo_m31_mul(b21, b24);
    b2 = stwo_m31_mul(b22, b23);
    b43 = stwo_m31_add(b44, b2);
    b2 = stwo_m31_mul(b23, b22);
    b44 = stwo_m31_add(b43, b2);
    b2 = stwo_m31_mul(b24, b21);
    b43 = stwo_m31_add(b44, b2);
    b2 = stwo_m31_mul(b21, b25);
    b44 = stwo_m31_mul(b22, b24);
    b1 = stwo_m31_add(b2, b44);
    b44 = stwo_m31_mul(b23, b23);
    b2 = stwo_m31_add(b1, b44);
    b44 = stwo_m31_mul(b24, b22);
    b1 = stwo_m31_add(b2, b44);
    b44 = stwo_m31_mul(b25, b21);
    b2 = stwo_m31_add(b1, b44);
    b44 = stwo_m31_mul(b21, b26);
    b1 = stwo_m31_mul(b22, b25);
    b42 = stwo_m31_add(b44, b1);
    b1 = stwo_m31_mul(b23, b24);
    b44 = stwo_m31_add(b42, b1);
    b1 = stwo_m31_mul(b24, b23);
    b42 = stwo_m31_add(b44, b1);
    b1 = stwo_m31_mul(b25, b22);
    b44 = stwo_m31_add(b42, b1);
    b1 = stwo_m31_mul(b26, b21);
    b42 = stwo_m31_add(b44, b1);
    b1 = stwo_m31_mul(b25, b27);
    b44 = stwo_m31_mul(b26, b26);
    b0 = stwo_m31_add(b1, b44);
    b44 = stwo_m31_mul(b27, b25);
    b1 = stwo_m31_add(b0, b44);
    b44 = stwo_m31_mul(b26, b27);
    b0 = stwo_m31_mul(b27, b26);
    unsigned b55 = stwo_m31_add(b44, b0);
    b0 = stwo_m31_mul(b27, b27);
    b44 = stwo_m31_add(b14, b21);
    unsigned b56 = stwo_m31_add(b15, b22);
    unsigned b57 = stwo_m31_add(b16, b23);
    unsigned b58 = stwo_m31_add(b17, b24);
    unsigned b59 = stwo_m31_add(b18, b25);
    unsigned b60 = stwo_m31_add(b19, b26);
    unsigned b61 = stwo_m31_add(b20, b27);
    unsigned b62 = stwo_m31_add(b14, b21);
    b14 = stwo_m31_add(b15, b22);
    b15 = stwo_m31_add(b16, b23);
    b16 = stwo_m31_add(b17, b24);
    b17 = stwo_m31_add(b18, b25);
    unsigned b63 = stwo_m31_add(b19, b26);
    unsigned b64 = stwo_m31_add(b20, b27);
    unsigned b65 = stwo_m31_mul(b44, b15);
    unsigned b66 = stwo_m31_mul(b56, b14);
    unsigned b67 = stwo_m31_add(b65, b66);
    b66 = stwo_m31_mul(b57, b62);
    b65 = stwo_m31_add(b67, b66);
    b66 = stwo_m31_sub(b65, b54);
    b65 = stwo_m31_sub(b66, b5);
    b66 = stwo_m31_add(b4, b65);
    b65 = stwo_m31_mul(b44, b16);
    b4 = stwo_m31_mul(b56, b15);
    b5 = stwo_m31_add(b65, b4);
    b4 = stwo_m31_mul(b57, b14);
    b65 = stwo_m31_add(b5, b4);
    b4 = stwo_m31_mul(b58, b62);
    b5 = stwo_m31_add(b65, b4);
    b4 = stwo_m31_sub(b5, b47);
    b5 = stwo_m31_sub(b4, b43);
    b4 = stwo_m31_add(b48, b5);
    b5 = stwo_m31_mul(b44, b17);
    b65 = stwo_m31_mul(b56, b16);
    b54 = stwo_m31_add(b5, b65);
    b65 = stwo_m31_mul(b57, b15);
    b5 = stwo_m31_add(b54, b65);
    b65 = stwo_m31_mul(b58, b14);
    b54 = stwo_m31_add(b5, b65);
    b65 = stwo_m31_mul(b59, b62);
    b5 = stwo_m31_add(b54, b65);
    b65 = stwo_m31_sub(b5, b6);
    b5 = stwo_m31_sub(b65, b2);
    b65 = stwo_m31_add(b3, b5);
    b5 = stwo_m31_mul(b44, b63);
    b44 = stwo_m31_mul(b56, b17);
    b56 = stwo_m31_add(b5, b44);
    b44 = stwo_m31_mul(b57, b16);
    b16 = stwo_m31_add(b56, b44);
    b44 = stwo_m31_mul(b58, b15);
    b15 = stwo_m31_add(b16, b44);
    b44 = stwo_m31_mul(b59, b14);
    b14 = stwo_m31_add(b15, b44);
    b44 = stwo_m31_mul(b60, b62);
    b62 = stwo_m31_add(b14, b44);
    b44 = stwo_m31_sub(b62, b46);
    b62 = stwo_m31_sub(b44, b42);
    b44 = stwo_m31_add(b45, b62);
    b62 = stwo_m31_mul(b59, b64);
    b59 = stwo_m31_mul(b60, b63);
    b14 = stwo_m31_add(b62, b59);
    b59 = stwo_m31_mul(b61, b17);
    b17 = stwo_m31_add(b14, b59);
    b59 = stwo_m31_sub(b17, b48);
    b17 = stwo_m31_sub(b59, b1);
    b59 = stwo_m31_add(b43, b17);
    b17 = stwo_m31_mul(b60, b64);
    b60 = stwo_m31_mul(b61, b63);
    b63 = stwo_m31_add(b17, b60);
    b60 = stwo_m31_sub(b63, b3);
    b63 = stwo_m31_sub(b60, b55);
    b60 = stwo_m31_add(b2, b63);
    b63 = stwo_m31_mul(b61, b64);
    b64 = stwo_m31_sub(b63, b45);
    b63 = stwo_m31_sub(b64, b0);
    b64 = stwo_m31_add(b42, b63);
    b63 = stwo_m31_mul(b28, b31);
    b42 = stwo_m31_mul(b29, b30);
    b0 = stwo_m31_add(b63, b42);
    b42 = stwo_m31_mul(b30, b29);
    b63 = stwo_m31_add(b0, b42);
    b42 = stwo_m31_mul(b31, b28);
    b0 = stwo_m31_add(b63, b42);
    b42 = stwo_m31_mul(b28, b32);
    b63 = stwo_m31_mul(b29, b31);
    b45 = stwo_m31_add(b42, b63);
    b63 = stwo_m31_mul(b30, b30);
    b42 = stwo_m31_add(b45, b63);
    b63 = stwo_m31_mul(b31, b29);
    b45 = stwo_m31_add(b42, b63);
    b63 = stwo_m31_mul(b32, b28);
    b42 = stwo_m31_add(b45, b63);
    b63 = stwo_m31_mul(b28, b33);
    b45 = stwo_m31_mul(b29, b32);
    b61 = stwo_m31_add(b63, b45);
    b45 = stwo_m31_mul(b30, b31);
    b63 = stwo_m31_add(b61, b45);
    b45 = stwo_m31_mul(b31, b30);
    b31 = stwo_m31_add(b63, b45);
    b45 = stwo_m31_mul(b32, b29);
    b29 = stwo_m31_add(b31, b45);
    b45 = stwo_m31_mul(b33, b28);
    b28 = stwo_m31_add(b29, b45);
    b45 = stwo_m31_mul(b32, b34);
    b29 = stwo_m31_mul(b33, b33);
    b31 = stwo_m31_add(b45, b29);
    b29 = stwo_m31_mul(b34, b32);
    b45 = stwo_m31_add(b31, b29);
    b29 = stwo_m31_mul(b33, b34);
    b31 = stwo_m31_mul(b34, b33);
    b63 = stwo_m31_add(b29, b31);
    b31 = stwo_m31_mul(b34, b34);
    b29 = stwo_m31_mul(b35, b38);
    b30 = stwo_m31_mul(b36, b37);
    b61 = stwo_m31_add(b29, b30);
    b30 = stwo_m31_mul(b37, b36);
    b29 = stwo_m31_add(b61, b30);
    b30 = stwo_m31_mul(b38, b35);
    b61 = stwo_m31_add(b29, b30);
    b30 = stwo_m31_mul(b35, b39);
    b29 = stwo_m31_mul(b36, b38);
    b2 = stwo_m31_add(b30, b29);
    b29 = stwo_m31_mul(b37, b37);
    b30 = stwo_m31_add(b2, b29);
    b29 = stwo_m31_mul(b38, b36);
    b2 = stwo_m31_add(b30, b29);
    b29 = stwo_m31_mul(b39, b35);
    b30 = stwo_m31_add(b2, b29);
    b29 = stwo_m31_mul(b35, b40);
    b2 = stwo_m31_mul(b36, b39);
    b55 = stwo_m31_add(b29, b2);
    b2 = stwo_m31_mul(b37, b38);
    b29 = stwo_m31_add(b55, b2);
    b2 = stwo_m31_mul(b38, b37);
    b55 = stwo_m31_add(b29, b2);
    b2 = stwo_m31_mul(b39, b36);
    b29 = stwo_m31_add(b55, b2);
    b2 = stwo_m31_mul(b40, b35);
    b55 = stwo_m31_add(b29, b2);
    b2 = stwo_m31_mul(b39, b41);
    b29 = stwo_m31_mul(b40, b40);
    b3 = stwo_m31_add(b2, b29);
    b29 = stwo_m31_mul(b41, b39);
    b2 = stwo_m31_add(b3, b29);
    b29 = stwo_m31_mul(b40, b41);
    b3 = stwo_m31_mul(b41, b40);
    b17 = stwo_m31_add(b29, b3);
    b3 = stwo_m31_mul(b41, b41);
    b29 = stwo_m31_add(b32, b39);
    b43 = stwo_m31_add(b33, b40);
    b1 = stwo_m31_add(b34, b41);
    b48 = stwo_m31_add(b32, b39);
    b14 = stwo_m31_add(b33, b40);
    b62 = stwo_m31_add(b34, b41);
    b15 = stwo_m31_mul(b29, b62);
    b29 = stwo_m31_mul(b43, b14);
    b16 = stwo_m31_add(b15, b29);
    b29 = stwo_m31_mul(b1, b48);
    b48 = stwo_m31_add(b16, b29);
    b29 = stwo_m31_sub(b48, b45);
    b48 = stwo_m31_sub(b29, b2);
    b29 = stwo_m31_add(b61, b48);
    b48 = stwo_m31_mul(b43, b62);
    b43 = stwo_m31_mul(b1, b14);
    b14 = stwo_m31_add(b48, b43);
    b43 = stwo_m31_sub(b14, b63);
    b14 = stwo_m31_sub(b43, b17);
    b43 = stwo_m31_add(b30, b14);
    b14 = stwo_m31_mul(b1, b62);
    b62 = stwo_m31_sub(b14, b31);
    b14 = stwo_m31_sub(b62, b3);
    b62 = stwo_m31_add(b55, b14);
    b14 = stwo_m31_add(b18, b32);
    b55 = stwo_m31_add(b19, b33);
    b3 = stwo_m31_add(b20, b34);
    b31 = stwo_m31_add(b21, b35);
    b1 = stwo_m31_add(b22, b36);
    b30 = stwo_m31_add(b23, b37);
    b17 = stwo_m31_add(b24, b38);
    b63 = stwo_m31_add(b25, b39);
    b48 = stwo_m31_add(b26, b40);
    b61 = stwo_m31_add(b27, b41);
    b2 = stwo_m31_add(b18, b32);
    b32 = stwo_m31_add(b19, b33);
    b33 = stwo_m31_add(b20, b34);
    b34 = stwo_m31_add(b21, b35);
    b35 = stwo_m31_add(b22, b36);
    b36 = stwo_m31_add(b23, b37);
    b37 = stwo_m31_add(b24, b38);
    b38 = stwo_m31_add(b25, b39);
    b39 = stwo_m31_add(b26, b40);
    b40 = stwo_m31_add(b27, b41);
    b41 = stwo_m31_mul(b14, b33);
    b27 = stwo_m31_mul(b55, b32);
    b26 = stwo_m31_add(b41, b27);
    b27 = stwo_m31_mul(b3, b2);
    b41 = stwo_m31_add(b26, b27);
    b27 = stwo_m31_mul(b55, b33);
    b26 = stwo_m31_mul(b3, b32);
    b25 = stwo_m31_add(b27, b26);
    b26 = stwo_m31_mul(b3, b33);
    b27 = stwo_m31_mul(b31, b37);
    b24 = stwo_m31_mul(b1, b36);
    b23 = stwo_m31_add(b27, b24);
    b24 = stwo_m31_mul(b30, b35);
    b27 = stwo_m31_add(b23, b24);
    b24 = stwo_m31_mul(b17, b34);
    b23 = stwo_m31_add(b27, b24);
    b24 = stwo_m31_mul(b31, b38);
    b27 = stwo_m31_mul(b1, b37);
    b22 = stwo_m31_add(b24, b27);
    b27 = stwo_m31_mul(b30, b36);
    b24 = stwo_m31_add(b22, b27);
    b27 = stwo_m31_mul(b17, b35);
    b22 = stwo_m31_add(b24, b27);
    b27 = stwo_m31_mul(b63, b34);
    b24 = stwo_m31_add(b22, b27);
    b27 = stwo_m31_mul(b31, b39);
    b31 = stwo_m31_mul(b1, b38);
    b1 = stwo_m31_add(b27, b31);
    b31 = stwo_m31_mul(b30, b37);
    b37 = stwo_m31_add(b1, b31);
    b31 = stwo_m31_mul(b17, b36);
    b36 = stwo_m31_add(b37, b31);
    b31 = stwo_m31_mul(b63, b35);
    b35 = stwo_m31_add(b36, b31);
    b31 = stwo_m31_mul(b48, b34);
    b34 = stwo_m31_add(b35, b31);
    b31 = stwo_m31_mul(b63, b40);
    b35 = stwo_m31_mul(b48, b39);
    b36 = stwo_m31_add(b31, b35);
    b35 = stwo_m31_mul(b61, b38);
    b31 = stwo_m31_add(b36, b35);
    b35 = stwo_m31_mul(b48, b40);
    b36 = stwo_m31_mul(b61, b39);
    b37 = stwo_m31_add(b35, b36);
    b36 = stwo_m31_mul(b61, b40);
    b35 = stwo_m31_add(b14, b63);
    b63 = stwo_m31_add(b55, b48);
    b48 = stwo_m31_add(b3, b61);
    b61 = stwo_m31_add(b2, b38);
    b38 = stwo_m31_add(b32, b39);
    b39 = stwo_m31_add(b33, b40);
    b40 = stwo_m31_mul(b35, b39);
    b35 = stwo_m31_mul(b63, b38);
    b33 = stwo_m31_add(b40, b35);
    b35 = stwo_m31_mul(b48, b61);
    b61 = stwo_m31_add(b33, b35);
    b35 = stwo_m31_sub(b61, b41);
    b61 = stwo_m31_sub(b35, b31);
    b35 = stwo_m31_add(b23, b61);
    b61 = stwo_m31_mul(b63, b39);
    b63 = stwo_m31_mul(b48, b38);
    b38 = stwo_m31_add(b61, b63);
    b63 = stwo_m31_sub(b38, b25);
    b38 = stwo_m31_sub(b63, b37);
    b63 = stwo_m31_add(b24, b38);
    b38 = stwo_m31_mul(b48, b39);
    b39 = stwo_m31_sub(b38, b26);
    b38 = stwo_m31_sub(b39, b36);
    b39 = stwo_m31_add(b34, b38);
    b38 = stwo_m31_sub(b35, b59);
    b35 = stwo_m31_sub(b38, b29);
    b38 = stwo_m31_add(b0, b35);
    b35 = stwo_m31_sub(b63, b60);
    b63 = stwo_m31_sub(b35, b43);
    b35 = stwo_m31_add(b42, b63);
    b63 = stwo_m31_sub(b39, b64);
    b39 = stwo_m31_sub(b63, b62);
    b63 = stwo_m31_add(b28, b39);
    b39 = stwo_m31_sub(b47, b7);
    b47 = stwo_m31_sub(b6, b8);
    b6 = stwo_m31_sub(b46, b9);
    b46 = stwo_m31_sub(b66, b10);
    b66 = stwo_m31_sub(b4, b11);
    b4 = stwo_m31_sub(b65, b12);
    b65 = stwo_m31_sub(b44, b13);
    b44 = 2u;
    b13 = stwo_m31_mul(b44, b39);
    b44 = stwo_m31_add(b13, b46);
    b13 = 32u;
    b46 = stwo_m31_mul(b13, b66);
    b13 = stwo_m31_add(b44, b46);
    b46 = 4u;
    b44 = stwo_m31_mul(b46, b38);
    b46 = stwo_m31_sub(b13, b44);
    b44 = 2u;
    b13 = stwo_m31_mul(b44, b47);
    b44 = stwo_m31_add(b13, b66);
    b13 = 32u;
    b66 = stwo_m31_mul(b13, b4);
    b13 = stwo_m31_add(b44, b66);
    b66 = 4u;
    b44 = stwo_m31_mul(b66, b35);
    b66 = stwo_m31_sub(b13, b44);
    b44 = 2u;
    b13 = stwo_m31_mul(b44, b6);
    b44 = stwo_m31_add(b13, b4);
    b13 = 32u;
    b4 = stwo_m31_mul(b13, b65);
    b13 = stwo_m31_add(b44, b4);
    b4 = 4u;
    b44 = stwo_m31_mul(b4, b63);
    b4 = stwo_m31_sub(b13, b44);
    b44 = 512u;
    b13 = stwo_m31_mul(b50, b44);
    b44 = stwo_m31_add(b46, b49);
    b46 = stwo_m31_sub(b13, b44);
    b44 = 512u;
    b13 = stwo_m31_mul(b51, b44);
    b44 = stwo_m31_add(b66, b50);
    b66 = stwo_m31_sub(b13, b44);
    b44 = 512u;
    b13 = stwo_m31_mul(b52, b44);
    b44 = stwo_m31_add(b4, b51);
    b4 = stwo_m31_sub(b13, b44);
    StwoCairoQm31 e0 = { b46, b53, b53, b53 };
    StwoCairoQm31 e1 = { b66, b53, b53, b53 };
    StwoCairoQm31 e2 = { b4, b53, b53, b53 };
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e2, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
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
