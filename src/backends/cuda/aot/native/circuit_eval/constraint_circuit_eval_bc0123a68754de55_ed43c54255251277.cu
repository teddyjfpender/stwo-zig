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
__device__ __forceinline__ unsigned stwo_m31_add(
    unsigned lhs, unsigned rhs) {
    const unsigned sum = lhs + rhs;
    return sum < STWO_M31_P ? sum : sum - STWO_M31_P;
}
__device__ __forceinline__ unsigned stwo_m31_sub(
    unsigned lhs, unsigned rhs) {
    return lhs >= rhs ? lhs - rhs : lhs + STWO_M31_P - rhs;
}
__device__ __forceinline__ unsigned stwo_m31_mul(
    unsigned lhs, unsigned rhs) {
    const u64 product = (u64)lhs * rhs;
    const unsigned folded = (unsigned)(product & STWO_M31_P) +
        (unsigned)(product >> 31u);
    return folded < STWO_M31_P ? folded : folded - STWO_M31_P;
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
    #if defined(STWO_CUMETAL)
    value = ((value >> 1u) & 0x55555555u) | ((value & 0x55555555u) << 1u);
    value = ((value >> 2u) & 0x33333333u) | ((value & 0x33333333u) << 2u);
    value = ((value >> 4u) & 0x0f0f0f0fu) | ((value & 0x0f0f0f0fu) << 4u);
    value = ((value >> 8u) & 0x00ff00ffu) | ((value & 0x00ff00ffu) << 8u);
    value = (value >> 16u) | (value << 16u);
    return bits == 0u ? 0u : value >> (32u - bits);
#else
    return bits == 0u ? 0u : __brev(value) >> (32u - bits);
#endif
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
    const u64 address = (u64)arena[args.trace_offsets + 2u * global] | ((u64)arena[args.trace_offsets + 2u * global + 1u] << 32u); return arena[address + target];
}
extern "C" __global__ void __launch_bounds__(256)
stwo_cairo_cuda_eval_v6_bc0123a68754de55(
    unsigned *arena,
    u64 arena_words,
    const StwoCairoEvalArgs *args) {
    const unsigned row =
        blockIdx.x * blockDim.x + threadIdx.x;
    if (arena == nullptr || args == nullptr ||
        row >= args->row_count) return;
    StwoCairoQm31 part_acc = { 0u, 0u, 0u, 0u };
    unsigned b0 = stwo_trace_value(arena, *args, 0u, 0u, row, 0);
    unsigned b1 = stwo_trace_value(arena, *args, 0u, 1u, row, 0);
    unsigned b2 = stwo_trace_value(arena, *args, 0u, 2u, row, 0);
    unsigned b3 = stwo_trace_value(arena, *args, 0u, 3u, row, 0);
    unsigned b4 = stwo_trace_value(arena, *args, 0u, 4u, row, 0);
    unsigned b5 = stwo_trace_value(arena, *args, 0u, 5u, row, 0);
    unsigned b6 = stwo_trace_value(arena, *args, 0u, 6u, row, 0);
    unsigned b7 = stwo_trace_value(arena, *args, 0u, 7u, row, 0);
    unsigned b8 = stwo_trace_value(arena, *args, 0u, 8u, row, 0);
    unsigned b9 = stwo_trace_value(arena, *args, 0u, 9u, row, 0);
    unsigned b10 = stwo_trace_value(arena, *args, 0u, 10u, row, 0);
    unsigned b11 = stwo_trace_value(arena, *args, 1u, 0u, row, 0);
    unsigned b12 = stwo_trace_value(arena, *args, 1u, 1u, row, 0);
    unsigned b13 = stwo_trace_value(arena, *args, 1u, 2u, row, 0);
    unsigned b14 = stwo_trace_value(arena, *args, 1u, 3u, row, 0);
    unsigned b15 = stwo_trace_value(arena, *args, 1u, 4u, row, 0);
    unsigned b16 = stwo_trace_value(arena, *args, 1u, 5u, row, 0);
    unsigned b17 = stwo_trace_value(arena, *args, 1u, 6u, row, 0);
    unsigned b18 = stwo_trace_value(arena, *args, 1u, 7u, row, 0);
    unsigned b19 = stwo_trace_value(arena, *args, 1u, 8u, row, 0);
    unsigned b20 = stwo_trace_value(arena, *args, 1u, 9u, row, 0);
    unsigned b21 = stwo_trace_value(arena, *args, 1u, 10u, row, 0);
    unsigned b22 = stwo_trace_value(arena, *args, 1u, 11u, row, 0);
    unsigned b23 = stwo_trace_value(arena, *args, 1u, 12u, row, 0);
    unsigned b24 = stwo_trace_value(arena, *args, 1u, 13u, row, 0);
    unsigned b25 = stwo_trace_value(arena, *args, 1u, 14u, row, 0);
    unsigned b26 = stwo_trace_value(arena, *args, 1u, 15u, row, 0);
    unsigned b27 = stwo_trace_value(arena, *args, 1u, 16u, row, 0);
    unsigned b28 = stwo_trace_value(arena, *args, 1u, 17u, row, 0);
    unsigned b29 = stwo_trace_value(arena, *args, 1u, 18u, row, 0);
    unsigned b30 = stwo_trace_value(arena, *args, 1u, 19u, row, 0);
    unsigned b31 = stwo_trace_value(arena, *args, 1u, 20u, row, 0);
    unsigned b32 = stwo_trace_value(arena, *args, 1u, 21u, row, 0);
    unsigned b33 = stwo_trace_value(arena, *args, 1u, 22u, row, 0);
    unsigned b34 = stwo_trace_value(arena, *args, 1u, 23u, row, 0);
    unsigned b35 = stwo_trace_value(arena, *args, 1u, 24u, row, 0);
    unsigned b36 = stwo_trace_value(arena, *args, 1u, 25u, row, 0);
    unsigned b37 = stwo_trace_value(arena, *args, 1u, 26u, row, 0);
    unsigned b38 = stwo_trace_value(arena, *args, 1u, 27u, row, 0);
    unsigned b39 = stwo_trace_value(arena, *args, 1u, 28u, row, 0);
    unsigned b40 = stwo_trace_value(arena, *args, 1u, 29u, row, 0);
    unsigned b41 = stwo_trace_value(arena, *args, 1u, 30u, row, 0);
    unsigned b42 = stwo_trace_value(arena, *args, 1u, 31u, row, 0);
    unsigned b43 = stwo_trace_value(arena, *args, 1u, 32u, row, 0);
    unsigned b44 = stwo_trace_value(arena, *args, 1u, 33u, row, 0);
    unsigned b45 = stwo_trace_value(arena, *args, 1u, 34u, row, 0);
    unsigned b46 = stwo_trace_value(arena, *args, 1u, 35u, row, 0);
    unsigned b47 = stwo_trace_value(arena, *args, 1u, 36u, row, 0);
    unsigned b48 = stwo_trace_value(arena, *args, 1u, 37u, row, 0);
    unsigned b49 = stwo_trace_value(arena, *args, 1u, 38u, row, 0);
    unsigned b50 = stwo_trace_value(arena, *args, 1u, 39u, row, 0);
    unsigned b51 = stwo_trace_value(arena, *args, 1u, 40u, row, 0);
    unsigned b52 = stwo_trace_value(arena, *args, 1u, 41u, row, 0);
    unsigned b53 = stwo_trace_value(arena, *args, 1u, 42u, row, 0);
    unsigned b54 = stwo_trace_value(arena, *args, 1u, 43u, row, 0);
    unsigned b55 = stwo_trace_value(arena, *args, 1u, 44u, row, 0);
    unsigned b56 = stwo_trace_value(arena, *args, 1u, 45u, row, 0);
    unsigned b57 = stwo_trace_value(arena, *args, 1u, 46u, row, 0);
    unsigned b58 = stwo_trace_value(arena, *args, 1u, 47u, row, 0);
    unsigned b59 = stwo_trace_value(arena, *args, 1u, 48u, row, 0);
    unsigned b60 = stwo_trace_value(arena, *args, 1u, 49u, row, 0);
    unsigned b61 = stwo_trace_value(arena, *args, 1u, 50u, row, 0);
    unsigned b62 = stwo_trace_value(arena, *args, 1u, 51u, row, 0);
    unsigned b63 = stwo_m31_add(b11, b13);
    unsigned b64 = stwo_m31_add(b63, b19);
    unsigned b65 = stwo_m31_sub(b64, b31);
    unsigned b66 = arena[args->base_params + 0u];
    unsigned b67 = stwo_m31_mul(b65, b66);
    unsigned b68 = arena[args->base_params + 1u];
    unsigned b69 = stwo_m31_sub(b67, b68);
    unsigned b70 = stwo_m31_mul(b67, b69);
    unsigned b71 = arena[args->base_params + 2u];
    unsigned b72 = stwo_m31_sub(b67, b71);
    unsigned b73 = stwo_m31_mul(b70, b72);
    unsigned b74 = arena[args->base_params + 3u];
    unsigned b75 = stwo_m31_add(b12, b14);
    unsigned b76 = stwo_m31_add(b75, b20);
    unsigned b77 = stwo_m31_add(b76, b67);
    unsigned b78 = stwo_m31_sub(b77, b32);
    unsigned b79 = arena[args->base_params + 4u];
    unsigned b80 = stwo_m31_mul(b78, b79);
    unsigned b81 = arena[args->base_params + 5u];
    unsigned b82 = stwo_m31_sub(b80, b81);
    unsigned b83 = stwo_m31_mul(b80, b82);
    unsigned b84 = arena[args->base_params + 6u];
    unsigned b85 = stwo_m31_sub(b80, b84);
    unsigned b86 = stwo_m31_mul(b83, b85);
    unsigned b87 = arena[args->base_params + 7u];
    unsigned b88 = stwo_m31_mul(b33, b87);
    unsigned b89 = stwo_m31_sub(b31, b88);
    unsigned b90 = arena[args->base_params + 8u];
    unsigned b91 = stwo_m31_mul(b34, b90);
    unsigned b92 = stwo_m31_sub(b32, b91);
    unsigned b93 = arena[args->base_params + 9u];
    unsigned b94 = stwo_m31_mul(b35, b93);
    unsigned b95 = stwo_m31_sub(b17, b94);
    unsigned b96 = arena[args->base_params + 10u];
    unsigned b97 = stwo_m31_mul(b36, b96);
    unsigned b98 = stwo_m31_sub(b18, b97);
    unsigned b99 = arena[args->base_params + 11u];
    unsigned b100 = stwo_m31_mul(b40, b99);
    unsigned b101 = stwo_m31_add(b39, b100);
    unsigned b102 = arena[args->base_params + 12u];
    unsigned b103 = stwo_m31_mul(b38, b102);
    unsigned b104 = stwo_m31_add(b37, b103);
    unsigned b105 = stwo_m31_add(b15, b101);
    unsigned b106 = arena[args->base_params + 13u];
    unsigned b107 = stwo_m31_add(b105, b106);
    unsigned b108 = stwo_m31_sub(b107, b41);
    unsigned b109 = arena[args->base_params + 14u];
    unsigned b110 = stwo_m31_mul(b108, b109);
    unsigned b111 = arena[args->base_params + 15u];
    unsigned b112 = stwo_m31_sub(b110, b111);
    unsigned b113 = stwo_m31_mul(b110, b112);
    unsigned b114 = arena[args->base_params + 16u];
    unsigned b115 = stwo_m31_sub(b110, b114);
    unsigned b116 = stwo_m31_mul(b113, b115);
    unsigned b117 = stwo_m31_add(b16, b104);
    unsigned b118 = arena[args->base_params + 17u];
    unsigned b119 = stwo_m31_add(b117, b118);
    unsigned b120 = stwo_m31_add(b119, b110);
    unsigned b121 = stwo_m31_sub(b120, b42);
    unsigned b122 = arena[args->base_params + 18u];
    unsigned b123 = stwo_m31_mul(b121, b122);
    unsigned b124 = arena[args->base_params + 19u];
    unsigned b125 = stwo_m31_sub(b123, b124);
    unsigned b126 = stwo_m31_mul(b123, b125);
    unsigned b127 = arena[args->base_params + 20u];
    unsigned b128 = stwo_m31_sub(b123, b127);
    unsigned b129 = stwo_m31_mul(b126, b128);
    unsigned b130 = arena[args->base_params + 21u];
    unsigned b131 = stwo_m31_mul(b43, b130);
    unsigned b132 = stwo_m31_sub(b13, b131);
    unsigned b133 = arena[args->base_params + 22u];
    unsigned b134 = stwo_m31_mul(b44, b133);
    unsigned b135 = stwo_m31_sub(b14, b134);
    unsigned b136 = arena[args->base_params + 23u];
    unsigned b137 = stwo_m31_mul(b45, b136);
    unsigned b138 = stwo_m31_sub(b41, b137);
    unsigned b139 = arena[args->base_params + 24u];
    unsigned b140 = stwo_m31_mul(b46, b139);
    unsigned b141 = stwo_m31_sub(b42, b140);
    unsigned b142 = arena[args->base_params + 25u];
    unsigned b143 = stwo_m31_mul(b49, b142);
    unsigned b144 = stwo_m31_add(b48, b143);
    unsigned b145 = arena[args->base_params + 26u];
    unsigned b146 = stwo_m31_mul(b47, b145);
    unsigned b147 = stwo_m31_add(b50, b146);
    unsigned b148 = stwo_m31_add(b31, b144);
    unsigned b149 = stwo_m31_add(b148, b21);
    unsigned b150 = stwo_m31_sub(b149, b23);
    unsigned b151 = arena[args->base_params + 27u];
    unsigned b152 = stwo_m31_mul(b150, b151);
    unsigned b153 = arena[args->base_params + 28u];
    unsigned b154 = stwo_m31_sub(b152, b153);
    unsigned b155 = stwo_m31_mul(b152, b154);
    unsigned b156 = arena[args->base_params + 29u];
    unsigned b157 = stwo_m31_sub(b152, b156);
    unsigned b158 = stwo_m31_mul(b155, b157);
    unsigned b159 = stwo_m31_add(b32, b147);
    unsigned b160 = stwo_m31_add(b159, b22);
    unsigned b161 = stwo_m31_add(b160, b152);
    unsigned b162 = stwo_m31_sub(b161, b24);
    unsigned b163 = arena[args->base_params + 30u];
    unsigned b164 = stwo_m31_mul(b162, b163);
    unsigned b165 = arena[args->base_params + 31u];
    unsigned b166 = stwo_m31_sub(b164, b165);
    unsigned b167 = stwo_m31_mul(b164, b166);
    unsigned b168 = arena[args->base_params + 32u];
    unsigned b169 = stwo_m31_sub(b164, b168);
    unsigned b170 = stwo_m31_mul(b167, b169);
    unsigned b171 = arena[args->base_params + 33u];
    unsigned b172 = stwo_m31_mul(b51, b171);
    unsigned b173 = stwo_m31_sub(b23, b172);
    unsigned b174 = arena[args->base_params + 34u];
    unsigned b175 = stwo_m31_mul(b52, b174);
    unsigned b176 = stwo_m31_sub(b24, b175);
    unsigned b177 = arena[args->base_params + 35u];
    unsigned b178 = stwo_m31_mul(b53, b177);
    unsigned b179 = stwo_m31_sub(b101, b178);
    unsigned b180 = arena[args->base_params + 36u];
    unsigned b181 = stwo_m31_mul(b54, b180);
    unsigned b182 = stwo_m31_sub(b104, b181);
    unsigned b183 = arena[args->base_params + 37u];
    unsigned b184 = stwo_m31_mul(b55, b183);
    unsigned b185 = stwo_m31_sub(b29, b184);
    unsigned b186 = arena[args->base_params + 38u];
    unsigned b187 = stwo_m31_mul(b56, b186);
    unsigned b188 = stwo_m31_sub(b30, b187);
    unsigned b189 = stwo_m31_add(b41, b29);
    unsigned b190 = arena[args->base_params + 39u];
    unsigned b191 = stwo_m31_add(b189, b190);
    unsigned b192 = stwo_m31_sub(b191, b27);
    unsigned b193 = arena[args->base_params + 40u];
    unsigned b194 = stwo_m31_mul(b192, b193);
    unsigned b195 = arena[args->base_params + 41u];
    unsigned b196 = stwo_m31_sub(b194, b195);
    unsigned b197 = stwo_m31_mul(b194, b196);
    unsigned b198 = arena[args->base_params + 42u];
    unsigned b199 = stwo_m31_sub(b194, b198);
    unsigned b200 = stwo_m31_mul(b197, b199);
    unsigned b201 = stwo_m31_add(b42, b30);
    unsigned b202 = arena[args->base_params + 43u];
    unsigned b203 = stwo_m31_add(b201, b202);
    unsigned b204 = stwo_m31_add(b203, b194);
    unsigned b205 = stwo_m31_sub(b204, b28);
    unsigned b206 = arena[args->base_params + 44u];
    unsigned b207 = stwo_m31_mul(b205, b206);
    unsigned b208 = arena[args->base_params + 45u];
    unsigned b209 = stwo_m31_sub(b207, b208);
    unsigned b210 = stwo_m31_mul(b207, b209);
    unsigned b211 = arena[args->base_params + 46u];
    unsigned b212 = stwo_m31_sub(b207, b211);
    unsigned b213 = stwo_m31_mul(b210, b212);
    unsigned b214 = arena[args->base_params + 47u];
    unsigned b215 = stwo_m31_mul(b57, b214);
    unsigned b216 = stwo_m31_sub(b144, b215);
    unsigned b217 = arena[args->base_params + 48u];
    unsigned b218 = stwo_m31_mul(b58, b217);
    unsigned b219 = stwo_m31_sub(b147, b218);
    unsigned b220 = arena[args->base_params + 49u];
    unsigned b221 = stwo_m31_mul(b59, b220);
    unsigned b222 = stwo_m31_sub(b27, b221);
    unsigned b223 = arena[args->base_params + 50u];
    unsigned b224 = stwo_m31_mul(b60, b223);
    unsigned b225 = stwo_m31_sub(b28, b224);
    unsigned b226 = arena[args->base_params + 51u];
    unsigned b227 = stwo_m31_mul(b61, b226);
    unsigned b228 = stwo_m31_sub(b25, b227);
    unsigned b229 = arena[args->base_params + 52u];
    unsigned b230 = stwo_m31_mul(b62, b229);
    unsigned b231 = stwo_m31_sub(b26, b230);
    unsigned b232 = stwo_trace_value(arena, *args, 2u, 0u, row, 0);
    unsigned b233 = stwo_trace_value(arena, *args, 2u, 1u, row, 0);
    unsigned b234 = stwo_trace_value(arena, *args, 2u, 2u, row, 0);
    unsigned b235 = stwo_trace_value(arena, *args, 2u, 3u, row, 0);
    unsigned b236 = stwo_trace_value(arena, *args, 2u, 4u, row, 0);
    unsigned b237 = stwo_trace_value(arena, *args, 2u, 5u, row, 0);
    unsigned b238 = stwo_trace_value(arena, *args, 2u, 6u, row, 0);
    unsigned b239 = stwo_trace_value(arena, *args, 2u, 7u, row, 0);
    unsigned b240 = stwo_trace_value(arena, *args, 2u, 8u, row, 0);
    unsigned b241 = stwo_trace_value(arena, *args, 2u, 9u, row, 0);
    unsigned b242 = stwo_trace_value(arena, *args, 2u, 10u, row, 0);
    unsigned b243 = stwo_trace_value(arena, *args, 2u, 11u, row, 0);
    unsigned b244 = stwo_trace_value(arena, *args, 2u, 12u, row, 0);
    unsigned b245 = stwo_trace_value(arena, *args, 2u, 13u, row, 0);
    unsigned b246 = stwo_trace_value(arena, *args, 2u, 14u, row, 0);
    unsigned b247 = stwo_trace_value(arena, *args, 2u, 15u, row, 0);
    unsigned b248 = stwo_trace_value(arena, *args, 2u, 16u, row, 0);
    unsigned b249 = stwo_trace_value(arena, *args, 2u, 17u, row, 0);
    unsigned b250 = stwo_trace_value(arena, *args, 2u, 18u, row, 0);
    unsigned b251 = stwo_trace_value(arena, *args, 2u, 19u, row, 0);
    unsigned b252 = stwo_trace_value(arena, *args, 2u, 20u, row, 0);
    unsigned b253 = stwo_trace_value(arena, *args, 2u, 21u, row, 0);
    unsigned b254 = stwo_trace_value(arena, *args, 2u, 22u, row, 0);
    unsigned b255 = stwo_trace_value(arena, *args, 2u, 23u, row, 0);
    unsigned b256 = stwo_trace_value(arena, *args, 2u, 24u, row, 0);
    unsigned b257 = stwo_trace_value(arena, *args, 2u, 25u, row, 0);
    unsigned b258 = stwo_trace_value(arena, *args, 2u, 26u, row, 0);
    unsigned b259 = stwo_trace_value(arena, *args, 2u, 27u, row, 0);
    unsigned b260 = stwo_trace_value(arena, *args, 2u, 28u, row, 0);
    unsigned b261 = stwo_trace_value(arena, *args, 2u, 29u, row, 0);
    unsigned b262 = stwo_trace_value(arena, *args, 2u, 30u, row, 0);
    unsigned b263 = stwo_trace_value(arena, *args, 2u, 31u, row, 0);
    unsigned b264 = stwo_trace_value(arena, *args, 2u, 32u, row, 0);
    unsigned b265 = stwo_trace_value(arena, *args, 2u, 33u, row, 0);
    unsigned b266 = stwo_trace_value(arena, *args, 2u, 34u, row, 0);
    unsigned b267 = stwo_trace_value(arena, *args, 2u, 35u, row, 0);
    unsigned b268 = stwo_trace_value(arena, *args, 2u, 36u, row, 0);
    unsigned b269 = stwo_trace_value(arena, *args, 2u, 37u, row, 0);
    unsigned b270 = stwo_trace_value(arena, *args, 2u, 38u, row, 0);
    unsigned b271 = stwo_trace_value(arena, *args, 2u, 39u, row, 0);
    unsigned b272 = stwo_trace_value(arena, *args, 2u, 40u, row, 0);
    unsigned b273 = stwo_trace_value(arena, *args, 2u, 41u, row, 0);
    unsigned b274 = stwo_trace_value(arena, *args, 2u, 42u, row, 0);
    unsigned b275 = stwo_trace_value(arena, *args, 2u, 43u, row, 0);
    unsigned b276 = stwo_trace_value(arena, *args, 2u, 44u, row, 0);
    unsigned b277 = stwo_trace_value(arena, *args, 2u, 45u, row, 0);
    unsigned b278 = stwo_trace_value(arena, *args, 2u, 46u, row, 0);
    unsigned b279 = stwo_trace_value(arena, *args, 2u, 47u, row, 0);
    unsigned b280 = stwo_trace_value(arena, *args, 2u, 48u, row, -1);
    unsigned b281 = stwo_trace_value(arena, *args, 2u, 48u, row, 0);
    unsigned b282 = stwo_trace_value(arena, *args, 2u, 49u, row, -1);
    unsigned b283 = stwo_trace_value(arena, *args, 2u, 49u, row, 0);
    unsigned b284 = stwo_trace_value(arena, *args, 2u, 50u, row, -1);
    unsigned b285 = stwo_trace_value(arena, *args, 2u, 50u, row, 0);
    unsigned b286 = stwo_trace_value(arena, *args, 2u, 51u, row, -1);
    unsigned b287 = stwo_trace_value(arena, *args, 2u, 51u, row, 0);
    StwoCairoQm31 e0 = { b73, b74, b74, b74 };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e0, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 0u) * 4u)));
    StwoCairoQm31 e1 = { b86, b74, b74, b74 };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e1, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 1u) * 4u)));
    StwoCairoQm31 e2 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e3 = { b89, b74, b74, b74 };
    StwoCairoQm31 e4 = stwo_qm31_mul(e2, e3);
    StwoCairoQm31 e5 = { 112558620u, 0u, 0u, 0u };
    StwoCairoQm31 e6 = stwo_qm31_add(e5, e4);
    StwoCairoQm31 e7 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e8 = { b95, b74, b74, b74 };
    StwoCairoQm31 e9 = stwo_qm31_mul(e7, e8);
    StwoCairoQm31 e10 = stwo_qm31_add(e6, e9);
    StwoCairoQm31 e11 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e12 = { b37, b74, b74, b74 };
    StwoCairoQm31 e13 = stwo_qm31_mul(e11, e12);
    StwoCairoQm31 e14 = stwo_qm31_add(e10, e13);
    StwoCairoQm31 e15 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e16 = stwo_qm31_sub(e14, e15);
    StwoCairoQm31 e17 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e18 = { b33, b74, b74, b74 };
    StwoCairoQm31 e19 = stwo_qm31_mul(e17, e18);
    StwoCairoQm31 e20 = { 112558620u, 0u, 0u, 0u };
    StwoCairoQm31 e21 = stwo_qm31_add(e20, e19);
    StwoCairoQm31 e22 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e23 = { b35, b74, b74, b74 };
    StwoCairoQm31 e24 = stwo_qm31_mul(e22, e23);
    StwoCairoQm31 e25 = stwo_qm31_add(e21, e24);
    StwoCairoQm31 e26 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e27 = { b38, b74, b74, b74 };
    StwoCairoQm31 e28 = stwo_qm31_mul(e26, e27);
    StwoCairoQm31 e29 = stwo_qm31_add(e25, e28);
    StwoCairoQm31 e30 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e31 = stwo_qm31_sub(e29, e30);
    StwoCairoQm31 e32 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e33 = { b92, b74, b74, b74 };
    StwoCairoQm31 e34 = stwo_qm31_mul(e32, e33);
    StwoCairoQm31 e35 = { 521092554u, 0u, 0u, 0u };
    StwoCairoQm31 e36 = stwo_qm31_add(e35, e34);
    StwoCairoQm31 e37 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e38 = { b98, b74, b74, b74 };
    StwoCairoQm31 e39 = stwo_qm31_mul(e37, e38);
    StwoCairoQm31 e40 = stwo_qm31_add(e36, e39);
    StwoCairoQm31 e41 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e42 = { b39, b74, b74, b74 };
    StwoCairoQm31 e43 = stwo_qm31_mul(e41, e42);
    StwoCairoQm31 e44 = stwo_qm31_add(e40, e43);
    StwoCairoQm31 e45 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e46 = stwo_qm31_sub(e44, e45);
    StwoCairoQm31 e47 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e48 = { b34, b74, b74, b74 };
    StwoCairoQm31 e49 = stwo_qm31_mul(e47, e48);
    StwoCairoQm31 e50 = { 521092554u, 0u, 0u, 0u };
    StwoCairoQm31 e51 = stwo_qm31_add(e50, e49);
    StwoCairoQm31 e52 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e53 = { b36, b74, b74, b74 };
    StwoCairoQm31 e54 = stwo_qm31_mul(e52, e53);
    StwoCairoQm31 e55 = stwo_qm31_add(e51, e54);
    StwoCairoQm31 e56 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e57 = { b40, b74, b74, b74 };
    StwoCairoQm31 e58 = stwo_qm31_mul(e56, e57);
    StwoCairoQm31 e59 = stwo_qm31_add(e55, e58);
    StwoCairoQm31 e60 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e61 = stwo_qm31_sub(e59, e60);
    StwoCairoQm31 e62 = { b116, b74, b74, b74 };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e62, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 2u) * 4u)));
    StwoCairoQm31 e63 = { b129, b74, b74, b74 };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e63, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 3u) * 4u)));
    StwoCairoQm31 e64 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e65 = { b132, b74, b74, b74 };
    StwoCairoQm31 e66 = stwo_qm31_mul(e64, e65);
    StwoCairoQm31 e67 = { 648362599u, 0u, 0u, 0u };
    StwoCairoQm31 e68 = stwo_qm31_add(e67, e66);
    StwoCairoQm31 e69 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e70 = { b138, b74, b74, b74 };
    StwoCairoQm31 e71 = stwo_qm31_mul(e69, e70);
    StwoCairoQm31 e72 = stwo_qm31_add(e68, e71);
    StwoCairoQm31 e73 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e74 = { b47, b74, b74, b74 };
    StwoCairoQm31 e75 = stwo_qm31_mul(e73, e74);
    StwoCairoQm31 e76 = stwo_qm31_add(e72, e75);
    StwoCairoQm31 e77 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e78 = stwo_qm31_sub(e76, e77);
    StwoCairoQm31 e79 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e80 = { b43, b74, b74, b74 };
    StwoCairoQm31 e81 = stwo_qm31_mul(e79, e80);
    StwoCairoQm31 e82 = { 45448144u, 0u, 0u, 0u };
    StwoCairoQm31 e83 = stwo_qm31_add(e82, e81);
    StwoCairoQm31 e84 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e85 = { b45, b74, b74, b74 };
    StwoCairoQm31 e86 = stwo_qm31_mul(e84, e85);
    StwoCairoQm31 e87 = stwo_qm31_add(e83, e86);
    StwoCairoQm31 e88 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e89 = { b48, b74, b74, b74 };
    StwoCairoQm31 e90 = stwo_qm31_mul(e88, e89);
    StwoCairoQm31 e91 = stwo_qm31_add(e87, e90);
    StwoCairoQm31 e92 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e93 = stwo_qm31_sub(e91, e92);
    StwoCairoQm31 e94 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e95 = { b135, b74, b74, b74 };
    StwoCairoQm31 e96 = stwo_qm31_mul(e94, e95);
    StwoCairoQm31 e97 = { 648362599u, 0u, 0u, 0u };
    StwoCairoQm31 e98 = stwo_qm31_add(e97, e96);
    StwoCairoQm31 e99 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e100 = { b141, b74, b74, b74 };
    StwoCairoQm31 e101 = stwo_qm31_mul(e99, e100);
    StwoCairoQm31 e102 = stwo_qm31_add(e98, e101);
    StwoCairoQm31 e103 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e104 = { b49, b74, b74, b74 };
    StwoCairoQm31 e105 = stwo_qm31_mul(e103, e104);
    StwoCairoQm31 e106 = stwo_qm31_add(e102, e105);
    StwoCairoQm31 e107 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e108 = stwo_qm31_sub(e106, e107);
    StwoCairoQm31 e109 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e110 = { b44, b74, b74, b74 };
    StwoCairoQm31 e111 = stwo_qm31_mul(e109, e110);
    StwoCairoQm31 e112 = { 45448144u, 0u, 0u, 0u };
    StwoCairoQm31 e113 = stwo_qm31_add(e112, e111);
    StwoCairoQm31 e114 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e115 = { b46, b74, b74, b74 };
    StwoCairoQm31 e116 = stwo_qm31_mul(e114, e115);
    StwoCairoQm31 e117 = stwo_qm31_add(e113, e116);
    StwoCairoQm31 e118 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e119 = { b50, b74, b74, b74 };
    StwoCairoQm31 e120 = stwo_qm31_mul(e118, e119);
    StwoCairoQm31 e121 = stwo_qm31_add(e117, e120);
    StwoCairoQm31 e122 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e123 = stwo_qm31_sub(e121, e122);
    StwoCairoQm31 e124 = { b158, b74, b74, b74 };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e124, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 4u) * 4u)));
    StwoCairoQm31 e125 = { b170, b74, b74, b74 };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e125, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 5u) * 4u)));
    StwoCairoQm31 e126 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e127 = { b51, b74, b74, b74 };
    StwoCairoQm31 e128 = stwo_qm31_mul(e126, e127);
    StwoCairoQm31 e129 = { 112558620u, 0u, 0u, 0u };
    StwoCairoQm31 e130 = stwo_qm31_add(e129, e128);
    StwoCairoQm31 e131 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e132 = { b53, b74, b74, b74 };
    StwoCairoQm31 e133 = stwo_qm31_mul(e131, e132);
    StwoCairoQm31 e134 = stwo_qm31_add(e130, e133);
    StwoCairoQm31 e135 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e136 = { b185, b74, b74, b74 };
    StwoCairoQm31 e137 = stwo_qm31_mul(e135, e136);
    StwoCairoQm31 e138 = stwo_qm31_add(e134, e137);
    StwoCairoQm31 e139 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e140 = stwo_qm31_sub(e138, e139);
    StwoCairoQm31 e141 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e142 = { b176, b74, b74, b74 };
    StwoCairoQm31 e143 = stwo_qm31_mul(e141, e142);
    StwoCairoQm31 e144 = { 112558620u, 0u, 0u, 0u };
    StwoCairoQm31 e145 = stwo_qm31_add(e144, e143);
    StwoCairoQm31 e146 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e147 = { b182, b74, b74, b74 };
    StwoCairoQm31 e148 = stwo_qm31_mul(e146, e147);
    StwoCairoQm31 e149 = stwo_qm31_add(e145, e148);
    StwoCairoQm31 e150 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e151 = { b55, b74, b74, b74 };
    StwoCairoQm31 e152 = stwo_qm31_mul(e150, e151);
    StwoCairoQm31 e153 = stwo_qm31_add(e149, e152);
    StwoCairoQm31 e154 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e155 = stwo_qm31_sub(e153, e154);
    StwoCairoQm31 e156 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e157 = { b52, b74, b74, b74 };
    StwoCairoQm31 e158 = stwo_qm31_mul(e156, e157);
    StwoCairoQm31 e159 = { 112558620u, 0u, 0u, 0u };
    StwoCairoQm31 e160 = stwo_qm31_add(e159, e158);
    StwoCairoQm31 e161 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e162 = { b54, b74, b74, b74 };
    StwoCairoQm31 e163 = stwo_qm31_mul(e161, e162);
    StwoCairoQm31 e164 = stwo_qm31_add(e160, e163);
    StwoCairoQm31 e165 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e166 = { b188, b74, b74, b74 };
    StwoCairoQm31 e167 = stwo_qm31_mul(e165, e166);
    StwoCairoQm31 e168 = stwo_qm31_add(e164, e167);
    StwoCairoQm31 e169 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e170 = stwo_qm31_sub(e168, e169);
    StwoCairoQm31 e171 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e172 = { b173, b74, b74, b74 };
    StwoCairoQm31 e173 = stwo_qm31_mul(e171, e172);
    StwoCairoQm31 e174 = { 112558620u, 0u, 0u, 0u };
    StwoCairoQm31 e175 = stwo_qm31_add(e174, e173);
    StwoCairoQm31 e176 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e177 = { b179, b74, b74, b74 };
    StwoCairoQm31 e178 = stwo_qm31_mul(e176, e177);
    StwoCairoQm31 e179 = stwo_qm31_add(e175, e178);
    StwoCairoQm31 e180 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e181 = { b56, b74, b74, b74 };
    StwoCairoQm31 e182 = stwo_qm31_mul(e180, e181);
    StwoCairoQm31 e183 = stwo_qm31_add(e179, e182);
    StwoCairoQm31 e184 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e185 = stwo_qm31_sub(e183, e184);
    StwoCairoQm31 e186 = { b200, b74, b74, b74 };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e186, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 6u) * 4u)));
    StwoCairoQm31 e187 = { b213, b74, b74, b74 };
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e187, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 7u) * 4u)));
    StwoCairoQm31 e188 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e189 = { b57, b74, b74, b74 };
    StwoCairoQm31 e190 = stwo_qm31_mul(e188, e189);
    StwoCairoQm31 e191 = { 95781001u, 0u, 0u, 0u };
    StwoCairoQm31 e192 = stwo_qm31_add(e191, e190);
    StwoCairoQm31 e193 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e194 = { b59, b74, b74, b74 };
    StwoCairoQm31 e195 = stwo_qm31_mul(e193, e194);
    StwoCairoQm31 e196 = stwo_qm31_add(e192, e195);
    StwoCairoQm31 e197 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e198 = { b228, b74, b74, b74 };
    StwoCairoQm31 e199 = stwo_qm31_mul(e197, e198);
    StwoCairoQm31 e200 = stwo_qm31_add(e196, e199);
    StwoCairoQm31 e201 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e202 = stwo_qm31_sub(e200, e201);
    StwoCairoQm31 e203 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e204 = { b219, b74, b74, b74 };
    StwoCairoQm31 e205 = stwo_qm31_mul(e203, e204);
    StwoCairoQm31 e206 = { 62225763u, 0u, 0u, 0u };
    StwoCairoQm31 e207 = stwo_qm31_add(e206, e205);
    StwoCairoQm31 e208 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e209 = { b225, b74, b74, b74 };
    StwoCairoQm31 e210 = stwo_qm31_mul(e208, e209);
    StwoCairoQm31 e211 = stwo_qm31_add(e207, e210);
    StwoCairoQm31 e212 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e213 = { b61, b74, b74, b74 };
    StwoCairoQm31 e214 = stwo_qm31_mul(e212, e213);
    StwoCairoQm31 e215 = stwo_qm31_add(e211, e214);
    StwoCairoQm31 e216 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e217 = stwo_qm31_sub(e215, e216);
    StwoCairoQm31 e218 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e219 = { b58, b74, b74, b74 };
    StwoCairoQm31 e220 = stwo_qm31_mul(e218, e219);
    StwoCairoQm31 e221 = { 95781001u, 0u, 0u, 0u };
    StwoCairoQm31 e222 = stwo_qm31_add(e221, e220);
    StwoCairoQm31 e223 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e224 = { b60, b74, b74, b74 };
    StwoCairoQm31 e225 = stwo_qm31_mul(e223, e224);
    StwoCairoQm31 e226 = stwo_qm31_add(e222, e225);
    StwoCairoQm31 e227 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e228 = { b231, b74, b74, b74 };
    StwoCairoQm31 e229 = stwo_qm31_mul(e227, e228);
    StwoCairoQm31 e230 = stwo_qm31_add(e226, e229);
    StwoCairoQm31 e231 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e232 = stwo_qm31_sub(e230, e231);
    StwoCairoQm31 e233 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e234 = { b216, b74, b74, b74 };
    StwoCairoQm31 e235 = stwo_qm31_mul(e233, e234);
    StwoCairoQm31 e236 = { 62225763u, 0u, 0u, 0u };
    StwoCairoQm31 e237 = stwo_qm31_add(e236, e235);
    StwoCairoQm31 e238 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e239 = { b222, b74, b74, b74 };
    StwoCairoQm31 e240 = stwo_qm31_mul(e238, e239);
    StwoCairoQm31 e241 = stwo_qm31_add(e237, e240);
    StwoCairoQm31 e242 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e243 = { b62, b74, b74, b74 };
    StwoCairoQm31 e244 = stwo_qm31_mul(e242, e243);
    StwoCairoQm31 e245 = stwo_qm31_add(e241, e244);
    StwoCairoQm31 e246 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e247 = stwo_qm31_sub(e245, e246);
    StwoCairoQm31 e248 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e249 = { b0, b74, b74, b74 };
    StwoCairoQm31 e250 = stwo_qm31_mul(e248, e249);
    StwoCairoQm31 e251 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e252 = stwo_qm31_add(e251, e250);
    StwoCairoQm31 e253 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e254 = { b11, b74, b74, b74 };
    StwoCairoQm31 e255 = stwo_qm31_mul(e253, e254);
    StwoCairoQm31 e256 = stwo_qm31_add(e252, e255);
    StwoCairoQm31 e257 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e258 = { b12, b74, b74, b74 };
    StwoCairoQm31 e259 = stwo_qm31_mul(e257, e258);
    StwoCairoQm31 e260 = stwo_qm31_add(e256, e259);
    StwoCairoQm31 e261 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e262 = stwo_qm31_sub(e260, e261);
    StwoCairoQm31 e263 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e264 = { b1, b74, b74, b74 };
    StwoCairoQm31 e265 = stwo_qm31_mul(e263, e264);
    StwoCairoQm31 e266 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e267 = stwo_qm31_add(e266, e265);
    StwoCairoQm31 e268 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e269 = { b13, b74, b74, b74 };
    StwoCairoQm31 e270 = stwo_qm31_mul(e268, e269);
    StwoCairoQm31 e271 = stwo_qm31_add(e267, e270);
    StwoCairoQm31 e272 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e273 = { b14, b74, b74, b74 };
    StwoCairoQm31 e274 = stwo_qm31_mul(e272, e273);
    StwoCairoQm31 e275 = stwo_qm31_add(e271, e274);
    StwoCairoQm31 e276 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e277 = stwo_qm31_sub(e275, e276);
    StwoCairoQm31 e278 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e279 = { b2, b74, b74, b74 };
    StwoCairoQm31 e280 = stwo_qm31_mul(e278, e279);
    StwoCairoQm31 e281 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e282 = stwo_qm31_add(e281, e280);
    StwoCairoQm31 e283 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e284 = { b15, b74, b74, b74 };
    StwoCairoQm31 e285 = stwo_qm31_mul(e283, e284);
    StwoCairoQm31 e286 = stwo_qm31_add(e282, e285);
    StwoCairoQm31 e287 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e288 = { b16, b74, b74, b74 };
    StwoCairoQm31 e289 = stwo_qm31_mul(e287, e288);
    StwoCairoQm31 e290 = stwo_qm31_add(e286, e289);
    StwoCairoQm31 e291 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e292 = stwo_qm31_sub(e290, e291);
    StwoCairoQm31 e293 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e294 = { b3, b74, b74, b74 };
    StwoCairoQm31 e295 = stwo_qm31_mul(e293, e294);
    StwoCairoQm31 e296 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e297 = stwo_qm31_add(e296, e295);
    StwoCairoQm31 e298 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e299 = { b17, b74, b74, b74 };
    StwoCairoQm31 e300 = stwo_qm31_mul(e298, e299);
    StwoCairoQm31 e301 = stwo_qm31_add(e297, e300);
    StwoCairoQm31 e302 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e303 = { b18, b74, b74, b74 };
    StwoCairoQm31 e304 = stwo_qm31_mul(e302, e303);
    StwoCairoQm31 e305 = stwo_qm31_add(e301, e304);
    StwoCairoQm31 e306 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e307 = stwo_qm31_sub(e305, e306);
    StwoCairoQm31 e308 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e309 = { b4, b74, b74, b74 };
    StwoCairoQm31 e310 = stwo_qm31_mul(e308, e309);
    StwoCairoQm31 e311 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e312 = stwo_qm31_add(e311, e310);
    StwoCairoQm31 e313 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e314 = { b19, b74, b74, b74 };
    StwoCairoQm31 e315 = stwo_qm31_mul(e313, e314);
    StwoCairoQm31 e316 = stwo_qm31_add(e312, e315);
    StwoCairoQm31 e317 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e318 = { b20, b74, b74, b74 };
    StwoCairoQm31 e319 = stwo_qm31_mul(e317, e318);
    StwoCairoQm31 e320 = stwo_qm31_add(e316, e319);
    StwoCairoQm31 e321 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e322 = stwo_qm31_sub(e320, e321);
    StwoCairoQm31 e323 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e324 = { b5, b74, b74, b74 };
    StwoCairoQm31 e325 = stwo_qm31_mul(e323, e324);
    StwoCairoQm31 e326 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e327 = stwo_qm31_add(e326, e325);
    StwoCairoQm31 e328 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e329 = { b21, b74, b74, b74 };
    StwoCairoQm31 e330 = stwo_qm31_mul(e328, e329);
    StwoCairoQm31 e331 = stwo_qm31_add(e327, e330);
    StwoCairoQm31 e332 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e333 = { b22, b74, b74, b74 };
    StwoCairoQm31 e334 = stwo_qm31_mul(e332, e333);
    StwoCairoQm31 e335 = stwo_qm31_add(e331, e334);
    StwoCairoQm31 e336 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e337 = stwo_qm31_sub(e335, e336);
    StwoCairoQm31 e338 = { b7, b74, b74, b74 };
    StwoCairoQm31 e339 = stwo_qm31_neg(e338);
    StwoCairoQm31 e340 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e341 = { b6, b74, b74, b74 };
    StwoCairoQm31 e342 = stwo_qm31_mul(e340, e341);
    StwoCairoQm31 e343 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e344 = stwo_qm31_add(e343, e342);
    StwoCairoQm31 e345 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e346 = { b23, b74, b74, b74 };
    StwoCairoQm31 e347 = stwo_qm31_mul(e345, e346);
    StwoCairoQm31 e348 = stwo_qm31_add(e344, e347);
    StwoCairoQm31 e349 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e350 = { b24, b74, b74, b74 };
    StwoCairoQm31 e351 = stwo_qm31_mul(e349, e350);
    StwoCairoQm31 e352 = stwo_qm31_add(e348, e351);
    StwoCairoQm31 e353 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e354 = stwo_qm31_sub(e352, e353);
    StwoCairoQm31 e355 = { b7, b74, b74, b74 };
    StwoCairoQm31 e356 = stwo_qm31_neg(e355);
    StwoCairoQm31 e357 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e358 = { b8, b74, b74, b74 };
    StwoCairoQm31 e359 = stwo_qm31_mul(e357, e358);
    StwoCairoQm31 e360 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e361 = stwo_qm31_add(e360, e359);
    StwoCairoQm31 e362 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e363 = { b25, b74, b74, b74 };
    StwoCairoQm31 e364 = stwo_qm31_mul(e362, e363);
    StwoCairoQm31 e365 = stwo_qm31_add(e361, e364);
    StwoCairoQm31 e366 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e367 = { b26, b74, b74, b74 };
    StwoCairoQm31 e368 = stwo_qm31_mul(e366, e367);
    StwoCairoQm31 e369 = stwo_qm31_add(e365, e368);
    StwoCairoQm31 e370 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e371 = stwo_qm31_sub(e369, e370);
    StwoCairoQm31 e372 = { b7, b74, b74, b74 };
    StwoCairoQm31 e373 = stwo_qm31_neg(e372);
    StwoCairoQm31 e374 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e375 = { b9, b74, b74, b74 };
    StwoCairoQm31 e376 = stwo_qm31_mul(e374, e375);
    StwoCairoQm31 e377 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e378 = stwo_qm31_add(e377, e376);
    StwoCairoQm31 e379 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e380 = { b27, b74, b74, b74 };
    StwoCairoQm31 e381 = stwo_qm31_mul(e379, e380);
    StwoCairoQm31 e382 = stwo_qm31_add(e378, e381);
    StwoCairoQm31 e383 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e384 = { b28, b74, b74, b74 };
    StwoCairoQm31 e385 = stwo_qm31_mul(e383, e384);
    StwoCairoQm31 e386 = stwo_qm31_add(e382, e385);
    StwoCairoQm31 e387 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e388 = stwo_qm31_sub(e386, e387);
    StwoCairoQm31 e389 = { b7, b74, b74, b74 };
    StwoCairoQm31 e390 = stwo_qm31_neg(e389);
    StwoCairoQm31 e391 = stwo_load_qm31(arena, args->ext_params + 0u * 4u);
    StwoCairoQm31 e392 = { b10, b74, b74, b74 };
    StwoCairoQm31 e393 = stwo_qm31_mul(e391, e392);
    StwoCairoQm31 e394 = { 378353459u, 0u, 0u, 0u };
    StwoCairoQm31 e395 = stwo_qm31_add(e394, e393);
    StwoCairoQm31 e396 = stwo_load_qm31(arena, args->ext_params + 1u * 4u);
    StwoCairoQm31 e397 = { b29, b74, b74, b74 };
    StwoCairoQm31 e398 = stwo_qm31_mul(e396, e397);
    StwoCairoQm31 e399 = stwo_qm31_add(e395, e398);
    StwoCairoQm31 e400 = stwo_load_qm31(arena, args->ext_params + 2u * 4u);
    StwoCairoQm31 e401 = { b30, b74, b74, b74 };
    StwoCairoQm31 e402 = stwo_qm31_mul(e400, e401);
    StwoCairoQm31 e403 = stwo_qm31_add(e399, e402);
    StwoCairoQm31 e404 = stwo_load_qm31(arena, args->ext_params + 3u * 4u);
    StwoCairoQm31 e405 = stwo_qm31_sub(e403, e404);
    StwoCairoQm31 e406 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e407 = e31;
    StwoCairoQm31 e408 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e409 = e16;
    StwoCairoQm31 e410 = stwo_qm31_add(e407, e409);
    StwoCairoQm31 e411 = stwo_qm31_mul(e16, e31);
    StwoCairoQm31 e412 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e413 = e61;
    StwoCairoQm31 e414 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e415 = e46;
    StwoCairoQm31 e416 = stwo_qm31_add(e413, e415);
    StwoCairoQm31 e417 = stwo_qm31_mul(e46, e61);
    StwoCairoQm31 e418 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e419 = e93;
    StwoCairoQm31 e420 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e421 = e78;
    StwoCairoQm31 e422 = stwo_qm31_add(e419, e421);
    StwoCairoQm31 e423 = stwo_qm31_mul(e78, e93);
    StwoCairoQm31 e424 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e425 = e123;
    StwoCairoQm31 e426 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e427 = e108;
    StwoCairoQm31 e428 = stwo_qm31_add(e425, e427);
    StwoCairoQm31 e429 = stwo_qm31_mul(e108, e123);
    StwoCairoQm31 e430 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e431 = e155;
    StwoCairoQm31 e432 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e433 = e140;
    StwoCairoQm31 e434 = stwo_qm31_add(e431, e433);
    StwoCairoQm31 e435 = stwo_qm31_mul(e140, e155);
    StwoCairoQm31 e436 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e437 = e185;
    StwoCairoQm31 e438 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e439 = e170;
    StwoCairoQm31 e440 = stwo_qm31_add(e437, e439);
    StwoCairoQm31 e441 = stwo_qm31_mul(e170, e185);
    StwoCairoQm31 e442 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e443 = e217;
    StwoCairoQm31 e444 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e445 = e202;
    StwoCairoQm31 e446 = stwo_qm31_add(e443, e445);
    StwoCairoQm31 e447 = stwo_qm31_mul(e202, e217);
    StwoCairoQm31 e448 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e449 = e247;
    StwoCairoQm31 e450 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e451 = e232;
    StwoCairoQm31 e452 = stwo_qm31_add(e449, e451);
    StwoCairoQm31 e453 = stwo_qm31_mul(e232, e247);
    StwoCairoQm31 e454 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e455 = e277;
    StwoCairoQm31 e456 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e457 = e262;
    StwoCairoQm31 e458 = stwo_qm31_add(e455, e457);
    StwoCairoQm31 e459 = stwo_qm31_mul(e262, e277);
    StwoCairoQm31 e460 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e461 = e307;
    StwoCairoQm31 e462 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e463 = e292;
    StwoCairoQm31 e464 = stwo_qm31_add(e461, e463);
    StwoCairoQm31 e465 = stwo_qm31_mul(e292, e307);
    StwoCairoQm31 e466 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e467 = e337;
    StwoCairoQm31 e468 = { 1u, 0u, 0u, 0u };
    StwoCairoQm31 e469 = e322;
    StwoCairoQm31 e470 = stwo_qm31_add(e467, e469);
    StwoCairoQm31 e471 = stwo_qm31_mul(e322, e337);
    StwoCairoQm31 e472 = stwo_qm31_mul(e371, e339);
    StwoCairoQm31 e473 = stwo_qm31_mul(e354, e356);
    StwoCairoQm31 e474 = stwo_qm31_add(e472, e473);
    StwoCairoQm31 e475 = stwo_qm31_mul(e354, e371);
    StwoCairoQm31 e476 = stwo_qm31_mul(e405, e373);
    StwoCairoQm31 e477 = stwo_qm31_mul(e388, e390);
    StwoCairoQm31 e478 = stwo_qm31_add(e476, e477);
    StwoCairoQm31 e479 = stwo_qm31_mul(e388, e405);
    StwoCairoQm31 e480 = { b232, b233, b234, b235 };
    StwoCairoQm31 e481 = stwo_qm31_mul(e480, e411);
    StwoCairoQm31 e482 = stwo_qm31_sub(e481, e410);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e482, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 8u) * 4u)));
    StwoCairoQm31 e483 = { b236, b237, b238, b239 };
    StwoCairoQm31 e484 = stwo_qm31_sub(e483, e480);
    StwoCairoQm31 e485 = stwo_qm31_mul(e484, e417);
    StwoCairoQm31 e486 = stwo_qm31_sub(e485, e416);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e486, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 9u) * 4u)));
    StwoCairoQm31 e487 = { b240, b241, b242, b243 };
    StwoCairoQm31 e488 = stwo_qm31_sub(e487, e483);
    StwoCairoQm31 e489 = stwo_qm31_mul(e488, e423);
    StwoCairoQm31 e490 = stwo_qm31_sub(e489, e422);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e490, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 10u) * 4u)));
    StwoCairoQm31 e491 = { b244, b245, b246, b247 };
    StwoCairoQm31 e492 = stwo_qm31_sub(e491, e487);
    StwoCairoQm31 e493 = stwo_qm31_mul(e492, e429);
    StwoCairoQm31 e494 = stwo_qm31_sub(e493, e428);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e494, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 11u) * 4u)));
    StwoCairoQm31 e495 = { b248, b249, b250, b251 };
    StwoCairoQm31 e496 = stwo_qm31_sub(e495, e491);
    StwoCairoQm31 e497 = stwo_qm31_mul(e496, e435);
    StwoCairoQm31 e498 = stwo_qm31_sub(e497, e434);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e498, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 12u) * 4u)));
    StwoCairoQm31 e499 = { b252, b253, b254, b255 };
    StwoCairoQm31 e500 = stwo_qm31_sub(e499, e495);
    StwoCairoQm31 e501 = stwo_qm31_mul(e500, e441);
    StwoCairoQm31 e502 = stwo_qm31_sub(e501, e440);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e502, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 13u) * 4u)));
    StwoCairoQm31 e503 = { b256, b257, b258, b259 };
    StwoCairoQm31 e504 = stwo_qm31_sub(e503, e499);
    StwoCairoQm31 e505 = stwo_qm31_mul(e504, e447);
    StwoCairoQm31 e506 = stwo_qm31_sub(e505, e446);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e506, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 14u) * 4u)));
    StwoCairoQm31 e507 = { b260, b261, b262, b263 };
    StwoCairoQm31 e508 = stwo_qm31_sub(e507, e503);
    StwoCairoQm31 e509 = stwo_qm31_mul(e508, e453);
    StwoCairoQm31 e510 = stwo_qm31_sub(e509, e452);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e510, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 15u) * 4u)));
    StwoCairoQm31 e511 = { b264, b265, b266, b267 };
    StwoCairoQm31 e512 = stwo_qm31_sub(e511, e507);
    StwoCairoQm31 e513 = stwo_qm31_mul(e512, e459);
    StwoCairoQm31 e514 = stwo_qm31_sub(e513, e458);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e514, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 16u) * 4u)));
    StwoCairoQm31 e515 = { b268, b269, b270, b271 };
    StwoCairoQm31 e516 = stwo_qm31_sub(e515, e511);
    StwoCairoQm31 e517 = stwo_qm31_mul(e516, e465);
    StwoCairoQm31 e518 = stwo_qm31_sub(e517, e464);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e518, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 17u) * 4u)));
    StwoCairoQm31 e519 = { b272, b273, b274, b275 };
    StwoCairoQm31 e520 = stwo_qm31_sub(e519, e515);
    StwoCairoQm31 e521 = stwo_qm31_mul(e520, e471);
    StwoCairoQm31 e522 = stwo_qm31_sub(e521, e470);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e522, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 18u) * 4u)));
    StwoCairoQm31 e523 = { b276, b277, b278, b279 };
    StwoCairoQm31 e524 = stwo_qm31_sub(e523, e519);
    StwoCairoQm31 e525 = stwo_qm31_mul(e524, e475);
    StwoCairoQm31 e526 = stwo_qm31_sub(e525, e474);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e526, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 19u) * 4u)));
    StwoCairoQm31 e527 = { b280, b282, b284, b286 };
    StwoCairoQm31 e528 = { b281, b283, b285, b287 };
    StwoCairoQm31 e529 = stwo_qm31_sub(e528, e527);
    StwoCairoQm31 e530 = stwo_qm31_sub(e529, e523);
    StwoCairoQm31 e531 = stwo_load_qm31(arena, args->ext_params + 4u * 4u);
    StwoCairoQm31 e532 = stwo_qm31_add(e530, e531);
    StwoCairoQm31 e533 = stwo_qm31_mul(e532, e479);
    StwoCairoQm31 e534 = stwo_qm31_sub(e533, e478);
    part_acc = stwo_qm31_add(part_acc, stwo_qm31_mul(e534, stwo_load_qm31(arena, args->random_coeffs + (args->rc_base + 20u) * 4u)));
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
