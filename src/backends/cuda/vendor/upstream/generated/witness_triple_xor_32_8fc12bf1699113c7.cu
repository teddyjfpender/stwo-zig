typedef unsigned long long u64;

#define STWO_M31_P 2147483647u

#ifndef STWO_M31_FAST32_GLOBAL
#define STWO_M31_FAST32_GLOBAL 0
#endif
#if STWO_M31_FAST32_GLOBAL != 0 && STWO_M31_FAST32_GLOBAL != 1
#error "STWO_M31_FAST32_GLOBAL must be 0 or 1"
#endif

__device__ __forceinline__ unsigned stwo_m31_add(unsigned lhs, unsigned rhs) {
    unsigned sum = lhs + rhs;
    return sum >= STWO_M31_P ? sum - STWO_M31_P : sum;
}

__device__ __forceinline__ unsigned stwo_m31_sub(unsigned lhs, unsigned rhs) {
    return lhs >= rhs ? lhs - rhs : lhs + STWO_M31_P - rhs;
}

__device__ __forceinline__ unsigned stwo_m31_neg(unsigned value) {
    unsigned negated = STWO_M31_P - value;
    return negated == STWO_M31_P ? 0u : negated;
}

__device__ __forceinline__ unsigned stwo_m31_mul(unsigned lhs, unsigned rhs) {
#if STWO_M31_FAST32_GLOBAL
    unsigned lo = lhs * rhs;
    unsigned hi = __umulhi(lhs, rhs);
    unsigned quotient = (hi << 1) | (lo >> 31);
    unsigned reduced = (lo & STWO_M31_P) + quotient;
    reduced = (reduced & STWO_M31_P) + (reduced >> 31);
    return reduced == STWO_M31_P ? 0u : reduced;
#else
    u64 product = (u64)lhs * (u64)rhs;
    u64 reduced = (((((product >> 31) + product + 1u) >> 31) + product) & (u64)STWO_M31_P);
    return (unsigned)reduced;
#endif
}

static __device__ __forceinline__ unsigned stwo_m31_inverse(unsigned a) {
    unsigned result = a;                 // consumes exponent bit 30
    for (int bit = 29; bit >= 0; --bit) {
        result = stwo_m31_mul(result, result);
        if (bit != 1) { result = stwo_m31_mul(result, a); }
    }
    return result;
}

static __device__ __forceinline__ unsigned stwo_wit_deduce_limb(
    const unsigned *const *tb, const unsigned *ts, unsigned id, unsigned limb) {
    unsigned tag = id >> 30u;
    unsigned val = id & 0x3FFFFFFFu;
    if (tag == 1u) { return val < ts[1] ? tb[1u + limb][val] : 0u; }
    return (limb < 8u && val < ts[2]) ? tb[29u + limb][val] : 0u;
}

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_3d32279c16a57ca9(
    const unsigned *const *input_cols,   // [n_inputs][row]
    const unsigned *const *table_bases,  // deduce_output LUTs, per table
    const unsigned *table_strides,       // words per key, per table
    unsigned *const *out_cols,           // [n_cols][row]
    unsigned *const *mult_counts,        // atomic count tables, per mult table
    unsigned *lookup_words,              // [k * row_count + row] (word-major)
    unsigned *sub_words,                 // [k * row_count + row] (word-major)
    unsigned row_count
) {
    unsigned row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= row_count) { return; }

    unsigned r0 = 1u;
    lookup_words[41u * row_count + row] = r0;
    unsigned r1 = 256u;
    unsigned r2 = 112558620u;
    lookup_words[0u * row_count + row] = r2;
    lookup_words[4u * row_count + row] = r2;
    lookup_words[8u * row_count + row] = r2;
    lookup_words[12u * row_count + row] = r2;
    unsigned r3 = 521092554u;
    lookup_words[16u * row_count + row] = r3;
    lookup_words[20u * row_count + row] = r3;
    lookup_words[24u * row_count + row] = r3;
    lookup_words[28u * row_count + row] = r3;
    unsigned r4 = 990559919u;
    lookup_words[32u * row_count + row] = r4;
    unsigned r5 = input_cols[0u][row];
    unsigned r6 = (r5 & 65535u);
    unsigned r7 = (r6 % STWO_M31_P);
    unsigned r8 = input_cols[0u][row];
    unsigned r9 = (r8 >> 16u);
    unsigned r10 = (r9 % STWO_M31_P);
    unsigned r11 = input_cols[1u][row];
    unsigned r12 = (r11 & 65535u);
    unsigned r13 = (r12 % STWO_M31_P);
    unsigned r14 = input_cols[1u][row];
    unsigned r15 = (r14 >> 16u);
    unsigned r16 = (r15 % STWO_M31_P);
    unsigned r17 = input_cols[2u][row];
    unsigned r18 = (r17 & 65535u);
    unsigned r19 = (r18 % STWO_M31_P);
    unsigned r20 = input_cols[2u][row];
    unsigned r21 = (r20 >> 16u);
    unsigned r22 = (r21 % STWO_M31_P);
    unsigned r23 = input_cols[0u][row];
    unsigned r24 = (r23 & 65535u);
    unsigned r25 = ((r24 & 0xFFFFu) >> 8u);
    unsigned r26 = (r25 % STWO_M31_P);
    unsigned r27 = stwo_m31_mul(r26, r1);
    unsigned r28 = stwo_m31_sub(r7, r27);
    out_cols[0u][row] = r7;
    lookup_words[33u * row_count + row] = r7;
    unsigned r29 = input_cols[0u][row];
    unsigned r30 = (r29 >> 16u);
    unsigned r31 = ((r30 & 0xFFFFu) >> 8u);
    unsigned r32 = (r31 % STWO_M31_P);
    unsigned r33 = stwo_m31_mul(r32, r1);
    unsigned r34 = stwo_m31_sub(r10, r33);
    out_cols[1u][row] = r10;
    lookup_words[34u * row_count + row] = r10;
    unsigned r35 = input_cols[1u][row];
    unsigned r36 = (r35 & 65535u);
    unsigned r37 = ((r36 & 0xFFFFu) >> 8u);
    unsigned r38 = (r37 % STWO_M31_P);
    unsigned r39 = stwo_m31_mul(r38, r1);
    unsigned r40 = stwo_m31_sub(r13, r39);
    out_cols[2u][row] = r13;
    lookup_words[35u * row_count + row] = r13;
    unsigned r41 = input_cols[1u][row];
    unsigned r42 = (r41 >> 16u);
    unsigned r43 = ((r42 & 0xFFFFu) >> 8u);
    unsigned r44 = (r43 % STWO_M31_P);
    unsigned r45 = stwo_m31_mul(r44, r1);
    unsigned r46 = stwo_m31_sub(r16, r45);
    out_cols[3u][row] = r16;
    lookup_words[36u * row_count + row] = r16;
    unsigned r47 = input_cols[2u][row];
    unsigned r48 = (r47 & 65535u);
    unsigned r49 = ((r48 & 0xFFFFu) >> 8u);
    unsigned r50 = (r49 % STWO_M31_P);
    unsigned r51 = stwo_m31_mul(r50, r1);
    unsigned r52 = stwo_m31_sub(r19, r51);
    out_cols[4u][row] = r19;
    lookup_words[37u * row_count + row] = r19;
    unsigned r53 = input_cols[2u][row];
    unsigned r54 = (r53 >> 16u);
    unsigned r55 = ((r54 & 0xFFFFu) >> 8u);
    unsigned r56 = (r55 % STWO_M31_P);
    unsigned r57 = stwo_m31_mul(r56, r1);
    unsigned r58 = stwo_m31_sub(r22, r57);
    out_cols[5u][row] = r22;
    lookup_words[38u * row_count + row] = r22;
    unsigned r59 = (r28 & 0xFFFFu);
    sub_words[0u * row_count + row] = r28;
    lookup_words[1u * row_count + row] = r28;
    unsigned r60 = (r40 & 0xFFFFu);
    sub_words[1u * row_count + row] = r40;
    lookup_words[2u * row_count + row] = r40;
    unsigned r61 = (r59 ^ r60);
    unsigned r62 = (r61 % STWO_M31_P);
    unsigned r63 = (r62 & 0xFFFFu);
    out_cols[12u][row] = r62;
    sub_words[2u * row_count + row] = r62;
    lookup_words[3u * row_count + row] = r62;
    sub_words[3u * row_count + row] = r62;
    lookup_words[5u * row_count + row] = r62;
    unsigned r64 = (r52 & 0xFFFFu);
    sub_words[4u * row_count + row] = r52;
    lookup_words[6u * row_count + row] = r52;
    unsigned r65 = (r63 ^ r64);
    unsigned r66 = (r65 % STWO_M31_P);
    unsigned r67 = (r26 & 0xFFFFu);
    out_cols[6u][row] = r26;
    sub_words[6u * row_count + row] = r26;
    lookup_words[9u * row_count + row] = r26;
    unsigned r68 = (r38 & 0xFFFFu);
    out_cols[8u][row] = r38;
    sub_words[7u * row_count + row] = r38;
    lookup_words[10u * row_count + row] = r38;
    unsigned r69 = (r67 ^ r68);
    unsigned r70 = (r69 % STWO_M31_P);
    unsigned r71 = (r70 & 0xFFFFu);
    out_cols[14u][row] = r70;
    sub_words[8u * row_count + row] = r70;
    lookup_words[11u * row_count + row] = r70;
    sub_words[9u * row_count + row] = r70;
    lookup_words[13u * row_count + row] = r70;
    unsigned r72 = (r50 & 0xFFFFu);
    out_cols[10u][row] = r50;
    sub_words[10u * row_count + row] = r50;
    lookup_words[14u * row_count + row] = r50;
    unsigned r73 = (r71 ^ r72);
    unsigned r74 = (r73 % STWO_M31_P);
    unsigned r75 = (r34 & 0xFFFFu);
    sub_words[12u * row_count + row] = r34;
    lookup_words[17u * row_count + row] = r34;
    unsigned r76 = (r46 & 0xFFFFu);
    sub_words[13u * row_count + row] = r46;
    lookup_words[18u * row_count + row] = r46;
    unsigned r77 = (r75 ^ r76);
    unsigned r78 = (r77 % STWO_M31_P);
    unsigned r79 = (r78 & 0xFFFFu);
    out_cols[16u][row] = r78;
    sub_words[14u * row_count + row] = r78;
    lookup_words[19u * row_count + row] = r78;
    sub_words[15u * row_count + row] = r78;
    lookup_words[21u * row_count + row] = r78;
    unsigned r80 = (r58 & 0xFFFFu);
    sub_words[16u * row_count + row] = r58;
    lookup_words[22u * row_count + row] = r58;
    unsigned r81 = (r79 ^ r80);
    unsigned r82 = (r81 % STWO_M31_P);
    unsigned r83 = (r32 & 0xFFFFu);
    out_cols[7u][row] = r32;
    sub_words[18u * row_count + row] = r32;
    lookup_words[25u * row_count + row] = r32;
    unsigned r84 = (r44 & 0xFFFFu);
    out_cols[9u][row] = r44;
    sub_words[19u * row_count + row] = r44;
    lookup_words[26u * row_count + row] = r44;
    unsigned r85 = (r83 ^ r84);
    unsigned r86 = (r85 % STWO_M31_P);
    unsigned r87 = (r86 & 0xFFFFu);
    out_cols[18u][row] = r86;
    sub_words[20u * row_count + row] = r86;
    lookup_words[27u * row_count + row] = r86;
    sub_words[21u * row_count + row] = r86;
    lookup_words[29u * row_count + row] = r86;
    unsigned r88 = (r56 & 0xFFFFu);
    out_cols[11u][row] = r56;
    sub_words[22u * row_count + row] = r56;
    lookup_words[30u * row_count + row] = r56;
    unsigned r89 = (r87 ^ r88);
    unsigned r90 = (r89 % STWO_M31_P);
    unsigned r91 = stwo_m31_mul(r74, r1);
    out_cols[15u][row] = r74;
    sub_words[11u * row_count + row] = r74;
    lookup_words[15u * row_count + row] = r74;
    unsigned r92 = stwo_m31_add(r66, r91);
    out_cols[13u][row] = r66;
    sub_words[5u * row_count + row] = r66;
    lookup_words[7u * row_count + row] = r66;
    unsigned r93 = stwo_m31_mul(r90, r1);
    out_cols[19u][row] = r90;
    sub_words[23u * row_count + row] = r90;
    lookup_words[31u * row_count + row] = r90;
    unsigned r94 = stwo_m31_add(r82, r93);
    out_cols[17u][row] = r82;
    sub_words[17u * row_count + row] = r82;
    lookup_words[23u * row_count + row] = r82;
    unsigned r95 = (r94 << 16u);
    unsigned r96 = (r92 + r95);
    unsigned r97 = input_cols[3u][row];
    out_cols[20u][row] = r97;
    lookup_words[42u * row_count + row] = r97;
    unsigned r98 = (r96 & 65535u);
    unsigned r99 = (r98 % STWO_M31_P);
    lookup_words[39u * row_count + row] = r99;
    unsigned r100 = (r96 >> 16u);
    unsigned r101 = (r100 % STWO_M31_P);
    lookup_words[40u * row_count + row] = r101;
}
