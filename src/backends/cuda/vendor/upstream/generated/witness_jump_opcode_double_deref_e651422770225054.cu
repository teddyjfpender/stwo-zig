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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_a2cb569f891013bf(
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
    lookup_words[50u * row_count + row] = r0;
    lookup_words[51u * row_count + row] = r0;
    lookup_words[52u * row_count + row] = r0;
    lookup_words[53u * row_count + row] = r0;
    lookup_words[54u * row_count + row] = r0;
    lookup_words[55u * row_count + row] = r0;
    lookup_words[56u * row_count + row] = r0;
    lookup_words[57u * row_count + row] = r0;
    lookup_words[58u * row_count + row] = r0;
    lookup_words[59u * row_count + row] = r0;
    lookup_words[60u * row_count + row] = r0;
    lookup_words[61u * row_count + row] = r0;
    lookup_words[62u * row_count + row] = r0;
    lookup_words[63u * row_count + row] = r0;
    lookup_words[64u * row_count + row] = r0;
    lookup_words[65u * row_count + row] = r0;
    lookup_words[66u * row_count + row] = r0;
    lookup_words[67u * row_count + row] = r0;
    lookup_words[68u * row_count + row] = r0;
    lookup_words[69u * row_count + row] = r0;
    lookup_words[70u * row_count + row] = r0;
    lookup_words[71u * row_count + row] = r0;
    lookup_words[72u * row_count + row] = r0;
    lookup_words[73u * row_count + row] = r0;
    unsigned r1 = 1u;
    unsigned r2 = 2u;
    unsigned r3 = 8u;
    unsigned r4 = 16u;
    unsigned r5 = 32u;
    unsigned r6 = 512u;
    unsigned r7 = 32767u;
    sub_words[1u * row_count + row] = r7;
    lookup_words[2u * row_count + row] = r7;
    unsigned r8 = 32768u;
    unsigned r9 = 262144u;
    unsigned r10 = 134217728u;
    unsigned r11 = 428564188u;
    lookup_words[74u * row_count + row] = r11;
    lookup_words[78u * row_count + row] = r11;
    unsigned r12 = 1444891767u;
    lookup_words[8u * row_count + row] = r12;
    lookup_words[41u * row_count + row] = r12;
    unsigned r13 = 1662111297u;
    lookup_words[11u * row_count + row] = r13;
    lookup_words[44u * row_count + row] = r13;
    unsigned r14 = 1719106205u;
    lookup_words[0u * row_count + row] = r14;
    unsigned r15 = 2147483646u;
    unsigned r16 = input_cols[0u][row];
    unsigned r17 = input_cols[1u][row];
    unsigned r18 = input_cols[2u][row];
    unsigned r19 = (r16 < table_strides[0u] ? table_bases[0u][r16] : 0u);
    out_cols[0u][row] = r16;
    sub_words[0u * row_count + row] = r16;
    lookup_words[1u * row_count + row] = r16;
    lookup_words[75u * row_count + row] = r16;
    unsigned r20 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 1u);
    unsigned r21 = (r20 & 0xFFFFu);
    unsigned r22 = ((r21 & 0xFFFFu) >> 7u);
    unsigned r23 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 2u);
    unsigned r24 = (r23 & 0xFFFFu);
    unsigned r25 = ((r24 << 2u) & 0xFFFFu);
    unsigned r26 = ((r22 + r25) & 0xFFFFu);
    unsigned r27 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 3u);
    unsigned r28 = (r27 & 0xFFFFu);
    unsigned r29 = (r28 & 31u);
    unsigned r30 = ((r29 << 11u) & 0xFFFFu);
    unsigned r31 = ((r26 + r30) & 0xFFFFu);
    unsigned r32 = (r31 % STWO_M31_P);
    unsigned r33 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 3u);
    unsigned r34 = (r33 & 0xFFFFu);
    unsigned r35 = ((r34 & 0xFFFFu) >> 5u);
    unsigned r36 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 4u);
    unsigned r37 = (r36 & 0xFFFFu);
    unsigned r38 = ((r37 << 4u) & 0xFFFFu);
    unsigned r39 = ((r35 + r38) & 0xFFFFu);
    unsigned r40 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 5u);
    unsigned r41 = (r40 & 0xFFFFu);
    unsigned r42 = (r41 & 7u);
    unsigned r43 = ((r42 << 13u) & 0xFFFFu);
    unsigned r44 = ((r39 + r43) & 0xFFFFu);
    unsigned r45 = (r44 % STWO_M31_P);
    unsigned r46 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 5u);
    unsigned r47 = (r46 & 0xFFFFu);
    unsigned r48 = ((r47 & 0xFFFFu) >> 3u);
    unsigned r49 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 6u);
    unsigned r50 = (r49 & 0xFFFFu);
    unsigned r51 = ((r50 << 6u) & 0xFFFFu);
    unsigned r52 = ((r48 + r51) & 0xFFFFu);
    unsigned r53 = ((r52 & 0xFFFFu) >> 1u);
    unsigned r54 = (r53 & 1u);
    unsigned r55 = (r54 % STWO_M31_P);
    unsigned r56 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 5u);
    unsigned r57 = (r56 & 0xFFFFu);
    unsigned r58 = ((r57 & 0xFFFFu) >> 3u);
    unsigned r59 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 6u);
    unsigned r60 = (r59 & 0xFFFFu);
    unsigned r61 = ((r60 << 6u) & 0xFFFFu);
    unsigned r62 = ((r58 + r61) & 0xFFFFu);
    unsigned r63 = ((r62 & 0xFFFFu) >> 11u);
    unsigned r64 = (r63 & 1u);
    unsigned r65 = (r64 % STWO_M31_P);
    unsigned r66 = stwo_m31_mul(r55, r4);
    unsigned r67 = stwo_m31_add(r3, r66);
    sub_words[4u * row_count + row] = r67;
    unsigned r68 = stwo_m31_mul(r65, r5);
    unsigned r69 = stwo_m31_add(r2, r68);
    sub_words[5u * row_count + row] = r69;
    unsigned r70 = stwo_m31_mul(r55, r4);
    unsigned r71 = stwo_m31_add(r3, r70);
    lookup_words[5u * row_count + row] = r71;
    unsigned r72 = stwo_m31_mul(r65, r5);
    unsigned r73 = stwo_m31_add(r2, r72);
    lookup_words[6u * row_count + row] = r73;
    unsigned r74 = stwo_m31_sub(r32, r8);
    out_cols[3u][row] = r32;
    sub_words[2u * row_count + row] = r32;
    lookup_words[3u * row_count + row] = r32;
    unsigned r75 = stwo_m31_sub(r45, r8);
    out_cols[4u][row] = r45;
    sub_words[3u * row_count + row] = r45;
    lookup_words[4u * row_count + row] = r45;
    unsigned r76 = stwo_m31_mul(r55, r18);
    out_cols[2u][row] = r18;
    lookup_words[77u * row_count + row] = r18;
    lookup_words[81u * row_count + row] = r18;
    unsigned r77 = stwo_m31_sub(r1, r55);
    out_cols[5u][row] = r55;
    lookup_words[82u * row_count + row] = r1;
    unsigned r78 = stwo_m31_mul(r77, r17);
    unsigned r79 = stwo_m31_add(r76, r78);
    unsigned r80 = stwo_m31_add(r79, r74);
    unsigned r81 = (r80 < table_strides[0u] ? table_bases[0u][r80] : 0u);
    unsigned r82 = stwo_m31_add(r79, r74);
    sub_words[7u * row_count + row] = r82;
    unsigned r83 = stwo_m31_add(r79, r74);
    out_cols[7u][row] = r79;
    lookup_words[9u * row_count + row] = r83;
    unsigned r84 = stwo_wit_deduce_limb(table_bases, table_strides, r81, 0u);
    unsigned r85 = stwo_wit_deduce_limb(table_bases, table_strides, r81, 1u);
    unsigned r86 = stwo_wit_deduce_limb(table_bases, table_strides, r81, 2u);
    unsigned r87 = stwo_wit_deduce_limb(table_bases, table_strides, r81, 3u);
    out_cols[8u][row] = r81;
    lookup_words[10u * row_count + row] = r81;
    sub_words[9u * row_count + row] = r81;
    lookup_words[12u * row_count + row] = r81;
    unsigned r88 = (r87 & 0xFFFFu);
    unsigned r89 = (r88 & 2u);
    unsigned r90 = ((r89 & 0xFFFFu) >> 1u);
    unsigned r91 = (r90 % STWO_M31_P);
    out_cols[13u][row] = r91;
    unsigned r92 = stwo_m31_mul(r85, r6);
    unsigned r93 = stwo_m31_add(r84, r92);
    unsigned r94 = stwo_m31_mul(r86, r9);
    unsigned r95 = stwo_m31_add(r93, r94);
    unsigned r96 = stwo_m31_mul(r87, r10);
    unsigned r97 = stwo_m31_add(r95, r96);
    unsigned r98 = stwo_m31_add(r97, r75);
    unsigned r99 = (r98 < table_strides[0u] ? table_bases[0u][r98] : 0u);
    unsigned r100 = stwo_m31_mul(r85, r6);
    unsigned r101 = stwo_m31_add(r84, r100);
    unsigned r102 = stwo_m31_mul(r86, r9);
    unsigned r103 = stwo_m31_add(r101, r102);
    unsigned r104 = stwo_m31_mul(r87, r10);
    unsigned r105 = stwo_m31_add(r103, r104);
    unsigned r106 = stwo_m31_add(r105, r75);
    sub_words[8u * row_count + row] = r106;
    unsigned r107 = stwo_m31_mul(r85, r6);
    out_cols[10u][row] = r85;
    lookup_words[14u * row_count + row] = r85;
    unsigned r108 = stwo_m31_add(r84, r107);
    out_cols[9u][row] = r84;
    lookup_words[13u * row_count + row] = r84;
    unsigned r109 = stwo_m31_mul(r86, r9);
    out_cols[11u][row] = r86;
    lookup_words[15u * row_count + row] = r86;
    unsigned r110 = stwo_m31_add(r108, r109);
    unsigned r111 = stwo_m31_mul(r87, r10);
    out_cols[12u][row] = r87;
    lookup_words[16u * row_count + row] = r87;
    unsigned r112 = stwo_m31_add(r110, r111);
    unsigned r113 = stwo_m31_add(r112, r75);
    lookup_words[42u * row_count + row] = r113;
    unsigned r114 = stwo_wit_deduce_limb(table_bases, table_strides, r99, 0u);
    unsigned r115 = stwo_wit_deduce_limb(table_bases, table_strides, r99, 1u);
    unsigned r116 = stwo_wit_deduce_limb(table_bases, table_strides, r99, 2u);
    unsigned r117 = stwo_wit_deduce_limb(table_bases, table_strides, r99, 3u);
    out_cols[14u][row] = r99;
    lookup_words[43u * row_count + row] = r99;
    sub_words[10u * row_count + row] = r99;
    lookup_words[45u * row_count + row] = r99;
    unsigned r118 = (r117 & 0xFFFFu);
    unsigned r119 = (r118 & 2u);
    unsigned r120 = ((r119 & 0xFFFFu) >> 1u);
    unsigned r121 = (r120 % STWO_M31_P);
    out_cols[19u][row] = r121;
    unsigned r122 = input_cols[3u][row];
    out_cols[20u][row] = r122;
    lookup_words[83u * row_count + row] = r122;
    unsigned r123 = stwo_m31_mul(r115, r6);
    out_cols[16u][row] = r115;
    lookup_words[47u * row_count + row] = r115;
    unsigned r124 = stwo_m31_add(r114, r123);
    out_cols[15u][row] = r114;
    lookup_words[46u * row_count + row] = r114;
    unsigned r125 = stwo_m31_mul(r116, r9);
    out_cols[17u][row] = r116;
    lookup_words[48u * row_count + row] = r116;
    unsigned r126 = stwo_m31_add(r124, r125);
    unsigned r127 = stwo_m31_mul(r117, r10);
    out_cols[18u][row] = r117;
    lookup_words[49u * row_count + row] = r117;
    unsigned r128 = stwo_m31_add(r126, r127);
    lookup_words[79u * row_count + row] = r128;
    unsigned r129 = stwo_m31_add(r17, r65);
    out_cols[1u][row] = r17;
    out_cols[6u][row] = r65;
    lookup_words[76u * row_count + row] = r17;
    lookup_words[80u * row_count + row] = r129;
}
