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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_06f670fcbec124d8(
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

    unsigned r0 = 0u;
    sub_words[6u * row_count + row] = r0;
    lookup_words[7u * row_count + row] = r0;
    lookup_words[17u * row_count + row] = r0;
    lookup_words[18u * row_count + row] = r0;
    lookup_words[19u * row_count + row] = r0;
    lookup_words[20u * row_count + row] = r0;
    lookup_words[21u * row_count + row] = r0;
    lookup_words[22u * row_count + row] = r0;
    lookup_words[23u * row_count + row] = r0;
    lookup_words[24u * row_count + row] = r0;
    lookup_words[25u * row_count + row] = r0;
    lookup_words[26u * row_count + row] = r0;
    lookup_words[27u * row_count + row] = r0;
    lookup_words[28u * row_count + row] = r0;
    lookup_words[29u * row_count + row] = r0;
    lookup_words[30u * row_count + row] = r0;
    lookup_words[31u * row_count + row] = r0;
    lookup_words[32u * row_count + row] = r0;
    lookup_words[33u * row_count + row] = r0;
    lookup_words[34u * row_count + row] = r0;
    lookup_words[35u * row_count + row] = r0;
    lookup_words[36u * row_count + row] = r0;
    lookup_words[37u * row_count + row] = r0;
    lookup_words[38u * row_count + row] = r0;
    lookup_words[39u * row_count + row] = r0;
    lookup_words[40u * row_count + row] = r0;
    unsigned r1 = 1u;
    unsigned r2 = 8u;
    unsigned r3 = 16u;
    unsigned r4 = 32u;
    unsigned r5 = 256u;
    unsigned r6 = 512u;
    unsigned r7 = 32768u;
    unsigned r8 = 262144u;
    unsigned r9 = 134217728u;
    unsigned r10 = 428564188u;
    lookup_words[47u * row_count + row] = r10;
    lookup_words[51u * row_count + row] = r10;
    unsigned r11 = 1444891767u;
    lookup_words[8u * row_count + row] = r11;
    lookup_words[41u * row_count + row] = r11;
    lookup_words[44u * row_count + row] = r11;
    unsigned r12 = 1662111297u;
    lookup_words[11u * row_count + row] = r12;
    unsigned r13 = 1719106205u;
    lookup_words[0u * row_count + row] = r13;
    unsigned r14 = input_cols[0u][row];
    unsigned r15 = input_cols[1u][row];
    unsigned r16 = input_cols[2u][row];
    unsigned r17 = (r14 < table_strides[0u] ? table_bases[0u][r14] : 0u);
    unsigned r18 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 0u);
    unsigned r19 = (r18 & 0xFFFFu);
    unsigned r20 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 1u);
    unsigned r21 = (r20 & 0xFFFFu);
    unsigned r22 = (r21 & 127u);
    unsigned r23 = ((r22 << 9u) & 0xFFFFu);
    unsigned r24 = ((r19 + r23) & 0xFFFFu);
    unsigned r25 = (r24 % STWO_M31_P);
    unsigned r26 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 1u);
    unsigned r27 = (r26 & 0xFFFFu);
    unsigned r28 = ((r27 & 0xFFFFu) >> 7u);
    unsigned r29 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 2u);
    unsigned r30 = (r29 & 0xFFFFu);
    unsigned r31 = ((r30 << 2u) & 0xFFFFu);
    unsigned r32 = ((r28 + r31) & 0xFFFFu);
    unsigned r33 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 3u);
    unsigned r34 = (r33 & 0xFFFFu);
    unsigned r35 = (r34 & 31u);
    unsigned r36 = ((r35 << 11u) & 0xFFFFu);
    unsigned r37 = ((r32 + r36) & 0xFFFFu);
    unsigned r38 = (r37 % STWO_M31_P);
    unsigned r39 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 3u);
    unsigned r40 = (r39 & 0xFFFFu);
    unsigned r41 = ((r40 & 0xFFFFu) >> 5u);
    unsigned r42 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 4u);
    unsigned r43 = (r42 & 0xFFFFu);
    unsigned r44 = ((r43 << 4u) & 0xFFFFu);
    unsigned r45 = ((r41 + r44) & 0xFFFFu);
    unsigned r46 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 5u);
    unsigned r47 = (r46 & 0xFFFFu);
    unsigned r48 = (r47 & 7u);
    unsigned r49 = ((r48 << 13u) & 0xFFFFu);
    unsigned r50 = ((r45 + r49) & 0xFFFFu);
    unsigned r51 = (r50 % STWO_M31_P);
    unsigned r52 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 5u);
    unsigned r53 = (r52 & 0xFFFFu);
    unsigned r54 = ((r53 & 0xFFFFu) >> 3u);
    unsigned r55 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 6u);
    unsigned r56 = (r55 & 0xFFFFu);
    unsigned r57 = ((r56 << 6u) & 0xFFFFu);
    unsigned r58 = ((r54 + r57) & 0xFFFFu);
    unsigned r59 = ((r58 & 0xFFFFu) >> 0u);
    unsigned r60 = (r59 & 1u);
    unsigned r61 = (r60 % STWO_M31_P);
    unsigned r62 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 5u);
    unsigned r63 = (r62 & 0xFFFFu);
    unsigned r64 = ((r63 & 0xFFFFu) >> 3u);
    unsigned r65 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 6u);
    unsigned r66 = (r65 & 0xFFFFu);
    unsigned r67 = ((r66 << 6u) & 0xFFFFu);
    unsigned r68 = ((r64 + r67) & 0xFFFFu);
    unsigned r69 = ((r68 & 0xFFFFu) >> 1u);
    unsigned r70 = (r69 & 1u);
    unsigned r71 = (r70 % STWO_M31_P);
    unsigned r72 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 5u);
    unsigned r73 = (r72 & 0xFFFFu);
    unsigned r74 = ((r73 & 0xFFFFu) >> 3u);
    unsigned r75 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 6u);
    unsigned r76 = (r75 & 0xFFFFu);
    unsigned r77 = ((r76 << 6u) & 0xFFFFu);
    unsigned r78 = ((r74 + r77) & 0xFFFFu);
    unsigned r79 = ((r78 & 0xFFFFu) >> 11u);
    unsigned r80 = (r79 & 1u);
    unsigned r81 = (r80 % STWO_M31_P);
    unsigned r82 = stwo_m31_mul(r61, r2);
    unsigned r83 = stwo_m31_mul(r71, r3);
    unsigned r84 = stwo_m31_add(r82, r83);
    sub_words[4u * row_count + row] = r84;
    unsigned r85 = stwo_m31_mul(r81, r4);
    unsigned r86 = stwo_m31_add(r85, r5);
    sub_words[5u * row_count + row] = r86;
    unsigned r87 = stwo_m31_mul(r61, r2);
    unsigned r88 = stwo_m31_mul(r71, r3);
    unsigned r89 = stwo_m31_add(r87, r88);
    lookup_words[5u * row_count + row] = r89;
    unsigned r90 = stwo_m31_mul(r81, r4);
    unsigned r91 = stwo_m31_add(r90, r5);
    lookup_words[6u * row_count + row] = r91;
    unsigned r92 = stwo_m31_sub(r25, r7);
    out_cols[3u][row] = r25;
    sub_words[1u * row_count + row] = r25;
    lookup_words[2u * row_count + row] = r25;
    unsigned r93 = stwo_m31_sub(r38, r7);
    out_cols[4u][row] = r38;
    sub_words[2u * row_count + row] = r38;
    lookup_words[3u * row_count + row] = r38;
    unsigned r94 = stwo_m31_sub(r51, r7);
    out_cols[5u][row] = r51;
    sub_words[3u * row_count + row] = r51;
    lookup_words[4u * row_count + row] = r51;
    unsigned r95 = stwo_m31_mul(r61, r16);
    unsigned r96 = stwo_m31_sub(r1, r61);
    out_cols[6u][row] = r61;
    unsigned r97 = stwo_m31_mul(r96, r15);
    unsigned r98 = stwo_m31_add(r95, r97);
    unsigned r99 = stwo_m31_mul(r71, r16);
    out_cols[2u][row] = r16;
    lookup_words[50u * row_count + row] = r16;
    lookup_words[54u * row_count + row] = r16;
    unsigned r100 = stwo_m31_sub(r1, r71);
    out_cols[7u][row] = r71;
    unsigned r101 = stwo_m31_mul(r100, r15);
    unsigned r102 = stwo_m31_add(r99, r101);
    unsigned r103 = stwo_m31_add(r102, r93);
    unsigned r104 = (r103 < table_strides[0u] ? table_bases[0u][r103] : 0u);
    unsigned r105 = stwo_m31_add(r102, r93);
    sub_words[7u * row_count + row] = r105;
    unsigned r106 = stwo_m31_add(r102, r93);
    out_cols[10u][row] = r102;
    lookup_words[9u * row_count + row] = r106;
    unsigned r107 = stwo_wit_deduce_limb(table_bases, table_strides, r104, 0u);
    unsigned r108 = stwo_wit_deduce_limb(table_bases, table_strides, r104, 1u);
    unsigned r109 = stwo_wit_deduce_limb(table_bases, table_strides, r104, 2u);
    unsigned r110 = stwo_wit_deduce_limb(table_bases, table_strides, r104, 3u);
    out_cols[11u][row] = r104;
    lookup_words[10u * row_count + row] = r104;
    sub_words[10u * row_count + row] = r104;
    lookup_words[12u * row_count + row] = r104;
    unsigned r111 = (r110 & 0xFFFFu);
    unsigned r112 = (r111 & 2u);
    unsigned r113 = ((r112 & 0xFFFFu) >> 1u);
    unsigned r114 = (r113 % STWO_M31_P);
    out_cols[16u][row] = r114;
    unsigned r115 = stwo_m31_add(r98, r92);
    unsigned r116 = (r115 < table_strides[0u] ? table_bases[0u][r115] : 0u);
    out_cols[17u][row] = r116;
    lookup_words[43u * row_count + row] = r116;
    lookup_words[46u * row_count + row] = r116;
    unsigned r117 = stwo_m31_add(r98, r92);
    sub_words[8u * row_count + row] = r117;
    unsigned r118 = stwo_m31_add(r98, r92);
    out_cols[9u][row] = r98;
    lookup_words[42u * row_count + row] = r118;
    unsigned r119 = stwo_m31_mul(r108, r6);
    unsigned r120 = stwo_m31_add(r107, r119);
    unsigned r121 = stwo_m31_mul(r109, r8);
    unsigned r122 = stwo_m31_add(r120, r121);
    unsigned r123 = stwo_m31_mul(r110, r9);
    unsigned r124 = stwo_m31_add(r122, r123);
    unsigned r125 = stwo_m31_add(r124, r94);
    sub_words[9u * row_count + row] = r125;
    unsigned r126 = stwo_m31_mul(r108, r6);
    out_cols[13u][row] = r108;
    lookup_words[14u * row_count + row] = r108;
    unsigned r127 = stwo_m31_add(r107, r126);
    out_cols[12u][row] = r107;
    lookup_words[13u * row_count + row] = r107;
    unsigned r128 = stwo_m31_mul(r109, r8);
    out_cols[14u][row] = r109;
    lookup_words[15u * row_count + row] = r109;
    unsigned r129 = stwo_m31_add(r127, r128);
    unsigned r130 = stwo_m31_mul(r110, r9);
    out_cols[15u][row] = r110;
    lookup_words[16u * row_count + row] = r110;
    unsigned r131 = stwo_m31_add(r129, r130);
    unsigned r132 = stwo_m31_add(r131, r94);
    lookup_words[45u * row_count + row] = r132;
    unsigned r133 = input_cols[3u][row];
    out_cols[18u][row] = r133;
    lookup_words[56u * row_count + row] = r133;
    unsigned r134 = stwo_m31_add(r14, r1);
    out_cols[0u][row] = r14;
    sub_words[0u * row_count + row] = r14;
    lookup_words[1u * row_count + row] = r14;
    lookup_words[48u * row_count + row] = r14;
    lookup_words[52u * row_count + row] = r134;
    lookup_words[55u * row_count + row] = r1;
    unsigned r135 = stwo_m31_add(r15, r81);
    out_cols[1u][row] = r15;
    out_cols[8u][row] = r81;
    lookup_words[49u * row_count + row] = r15;
    lookup_words[53u * row_count + row] = r135;
}
