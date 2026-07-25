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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_d94540f2fd219001(
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
    lookup_words[35u * row_count + row] = r0;
    lookup_words[36u * row_count + row] = r0;
    lookup_words[37u * row_count + row] = r0;
    lookup_words[38u * row_count + row] = r0;
    lookup_words[39u * row_count + row] = r0;
    unsigned r1 = 1u;
    unsigned r2 = 16u;
    sub_words[5u * row_count + row] = r2;
    lookup_words[6u * row_count + row] = r2;
    unsigned r3 = 24u;
    unsigned r4 = 32u;
    unsigned r5 = 64u;
    unsigned r6 = 128u;
    unsigned r7 = 136u;
    unsigned r8 = 256u;
    unsigned r9 = 508u;
    unsigned r10 = 511u;
    unsigned r11 = 512u;
    unsigned r12 = 32767u;
    sub_words[1u * row_count + row] = r12;
    sub_words[2u * row_count + row] = r12;
    lookup_words[2u * row_count + row] = r12;
    lookup_words[3u * row_count + row] = r12;
    unsigned r13 = 32768u;
    unsigned r14 = 262144u;
    unsigned r15 = 1048576u;
    unsigned r16 = 134217728u;
    unsigned r17 = 428564188u;
    lookup_words[45u * row_count + row] = r17;
    lookup_words[49u * row_count + row] = r17;
    unsigned r18 = 536870912u;
    unsigned r19 = 991608089u;
    lookup_words[43u * row_count + row] = r19;
    unsigned r20 = 1109051422u;
    lookup_words[41u * row_count + row] = r20;
    unsigned r21 = 1444891767u;
    lookup_words[8u * row_count + row] = r21;
    unsigned r22 = 1662111297u;
    lookup_words[11u * row_count + row] = r22;
    unsigned r23 = 1719106205u;
    lookup_words[0u * row_count + row] = r23;
    unsigned r24 = 2147483646u;
    unsigned r25 = input_cols[0u][row];
    unsigned r26 = input_cols[1u][row];
    unsigned r27 = input_cols[2u][row];
    unsigned r28 = (r25 < table_strides[0u] ? table_bases[0u][r25] : 0u);
    unsigned r29 = stwo_wit_deduce_limb(table_bases, table_strides, r28, 3u);
    unsigned r30 = (r29 & 0xFFFFu);
    unsigned r31 = ((r30 & 0xFFFFu) >> 5u);
    unsigned r32 = stwo_wit_deduce_limb(table_bases, table_strides, r28, 4u);
    unsigned r33 = (r32 & 0xFFFFu);
    unsigned r34 = ((r33 << 4u) & 0xFFFFu);
    unsigned r35 = ((r31 + r34) & 0xFFFFu);
    unsigned r36 = stwo_wit_deduce_limb(table_bases, table_strides, r28, 5u);
    unsigned r37 = (r36 & 0xFFFFu);
    unsigned r38 = (r37 & 7u);
    unsigned r39 = ((r38 << 13u) & 0xFFFFu);
    unsigned r40 = ((r35 + r39) & 0xFFFFu);
    unsigned r41 = (r40 % STWO_M31_P);
    unsigned r42 = stwo_wit_deduce_limb(table_bases, table_strides, r28, 5u);
    unsigned r43 = (r42 & 0xFFFFu);
    unsigned r44 = ((r43 & 0xFFFFu) >> 3u);
    unsigned r45 = stwo_wit_deduce_limb(table_bases, table_strides, r28, 6u);
    unsigned r46 = (r45 & 0xFFFFu);
    unsigned r47 = ((r46 << 6u) & 0xFFFFu);
    unsigned r48 = ((r44 + r47) & 0xFFFFu);
    unsigned r49 = ((r48 & 0xFFFFu) >> 2u);
    unsigned r50 = (r49 & 1u);
    unsigned r51 = (r50 % STWO_M31_P);
    unsigned r52 = stwo_wit_deduce_limb(table_bases, table_strides, r28, 5u);
    unsigned r53 = (r52 & 0xFFFFu);
    unsigned r54 = ((r53 & 0xFFFFu) >> 3u);
    unsigned r55 = stwo_wit_deduce_limb(table_bases, table_strides, r28, 6u);
    unsigned r56 = (r55 & 0xFFFFu);
    unsigned r57 = ((r56 << 6u) & 0xFFFFu);
    unsigned r58 = ((r54 + r57) & 0xFFFFu);
    unsigned r59 = ((r58 & 0xFFFFu) >> 3u);
    unsigned r60 = (r59 & 1u);
    unsigned r61 = (r60 % STWO_M31_P);
    unsigned r62 = stwo_m31_sub(r1, r51);
    unsigned r63 = stwo_m31_sub(r62, r61);
    unsigned r64 = stwo_m31_mul(r51, r4);
    unsigned r65 = stwo_m31_add(r3, r64);
    unsigned r66 = stwo_m31_mul(r61, r5);
    unsigned r67 = stwo_m31_add(r65, r66);
    unsigned r68 = stwo_m31_mul(r63, r6);
    unsigned r69 = stwo_m31_add(r67, r68);
    sub_words[4u * row_count + row] = r69;
    unsigned r70 = stwo_m31_mul(r51, r4);
    unsigned r71 = stwo_m31_add(r3, r70);
    unsigned r72 = stwo_m31_mul(r61, r5);
    unsigned r73 = stwo_m31_add(r71, r72);
    unsigned r74 = stwo_m31_mul(r63, r6);
    unsigned r75 = stwo_m31_add(r73, r74);
    lookup_words[5u * row_count + row] = r75;
    unsigned r76 = stwo_m31_sub(r41, r13);
    out_cols[3u][row] = r41;
    sub_words[3u * row_count + row] = r41;
    lookup_words[4u * row_count + row] = r41;
    unsigned r77 = stwo_m31_mul(r51, r25);
    unsigned r78 = stwo_m31_mul(r61, r27);
    out_cols[2u][row] = r27;
    out_cols[5u][row] = r61;
    lookup_words[48u * row_count + row] = r27;
    lookup_words[52u * row_count + row] = r27;
    unsigned r79 = stwo_m31_add(r77, r78);
    unsigned r80 = stwo_m31_mul(r63, r26);
    unsigned r81 = stwo_m31_add(r79, r80);
    unsigned r82 = stwo_m31_add(r81, r76);
    unsigned r83 = (r82 < table_strides[0u] ? table_bases[0u][r82] : 0u);
    unsigned r84 = stwo_m31_add(r81, r76);
    sub_words[7u * row_count + row] = r84;
    unsigned r85 = stwo_m31_add(r81, r76);
    out_cols[6u][row] = r81;
    lookup_words[9u * row_count + row] = r85;
    unsigned r86 = stwo_wit_deduce_limb(table_bases, table_strides, r83, 27u);
    unsigned r87 = (r86 == r8 ? 1u : 0u);
    unsigned r88 = stwo_wit_deduce_limb(table_bases, table_strides, r83, 20u);
    unsigned r89 = (r88 == r10 ? 1u : 0u);
    unsigned r90 = stwo_m31_mul(r89, r87);
    unsigned r91 = stwo_m31_mul(r90, r9);
    unsigned r92 = stwo_m31_mul(r90, r10);
    lookup_words[17u * row_count + row] = r92;
    lookup_words[18u * row_count + row] = r92;
    lookup_words[19u * row_count + row] = r92;
    lookup_words[20u * row_count + row] = r92;
    lookup_words[21u * row_count + row] = r92;
    lookup_words[22u * row_count + row] = r92;
    lookup_words[23u * row_count + row] = r92;
    lookup_words[24u * row_count + row] = r92;
    lookup_words[25u * row_count + row] = r92;
    lookup_words[26u * row_count + row] = r92;
    lookup_words[27u * row_count + row] = r92;
    lookup_words[28u * row_count + row] = r92;
    lookup_words[29u * row_count + row] = r92;
    lookup_words[30u * row_count + row] = r92;
    lookup_words[31u * row_count + row] = r92;
    lookup_words[32u * row_count + row] = r92;
    lookup_words[33u * row_count + row] = r92;
    unsigned r93 = stwo_m31_mul(r87, r7);
    unsigned r94 = stwo_m31_sub(r93, r90);
    lookup_words[34u * row_count + row] = r94;
    unsigned r95 = stwo_m31_mul(r87, r8);
    lookup_words[40u * row_count + row] = r95;
    unsigned r96 = stwo_wit_deduce_limb(table_bases, table_strides, r83, 0u);
    unsigned r97 = stwo_wit_deduce_limb(table_bases, table_strides, r83, 1u);
    unsigned r98 = stwo_wit_deduce_limb(table_bases, table_strides, r83, 2u);
    unsigned r99 = stwo_wit_deduce_limb(table_bases, table_strides, r83, 3u);
    out_cols[7u][row] = r83;
    lookup_words[10u * row_count + row] = r83;
    sub_words[8u * row_count + row] = r83;
    lookup_words[12u * row_count + row] = r83;
    unsigned r100 = (r99 & 0xFFFFu);
    unsigned r101 = (r100 & 3u);
    unsigned r102 = (r101 % STWO_M31_P);
    unsigned r103 = (r102 & 0xFFFFu);
    unsigned r104 = (r103 & 2u);
    unsigned r105 = ((r104 & 0xFFFFu) >> 1u);
    unsigned r106 = (r105 % STWO_M31_P);
    out_cols[14u][row] = r106;
    unsigned r107 = stwo_m31_add(r102, r91);
    lookup_words[16u * row_count + row] = r107;
    unsigned r108 = stwo_m31_mul(r97, r11);
    out_cols[11u][row] = r97;
    lookup_words[14u * row_count + row] = r97;
    unsigned r109 = stwo_m31_add(r96, r108);
    out_cols[10u][row] = r96;
    lookup_words[13u * row_count + row] = r96;
    unsigned r110 = stwo_m31_mul(r98, r14);
    out_cols[12u][row] = r98;
    lookup_words[15u * row_count + row] = r98;
    unsigned r111 = stwo_m31_add(r109, r110);
    unsigned r112 = stwo_m31_mul(r102, r16);
    out_cols[13u][row] = r102;
    unsigned r113 = stwo_m31_add(r111, r112);
    unsigned r114 = stwo_m31_sub(r113, r87);
    out_cols[8u][row] = r87;
    unsigned r115 = stwo_m31_mul(r18, r90);
    out_cols[9u][row] = r90;
    unsigned r116 = stwo_m31_sub(r114, r115);
    unsigned r117 = stwo_m31_add(r26, r116);
    out_cols[1u][row] = r26;
    lookup_words[47u * row_count + row] = r26;
    unsigned r118 = (r117 & 2047u);
    unsigned r119 = (r118 & 65535u);
    unsigned r120 = (r119 % STWO_M31_P);
    unsigned r121 = stwo_m31_sub(r117, r120);
    unsigned r122 = stwo_m31_mul(r121, r15);
    sub_words[9u * row_count + row] = r122;
    unsigned r123 = stwo_m31_sub(r117, r120);
    out_cols[15u][row] = r120;
    sub_words[10u * row_count + row] = r120;
    lookup_words[44u * row_count + row] = r120;
    lookup_words[51u * row_count + row] = r117;
    unsigned r124 = stwo_m31_mul(r123, r15);
    lookup_words[42u * row_count + row] = r124;
    unsigned r125 = input_cols[3u][row];
    out_cols[16u][row] = r125;
    lookup_words[54u * row_count + row] = r125;
    unsigned r126 = stwo_m31_add(r1, r51);
    out_cols[4u][row] = r51;
    lookup_words[53u * row_count + row] = r1;
    unsigned r127 = stwo_m31_add(r25, r126);
    out_cols[0u][row] = r25;
    sub_words[0u * row_count + row] = r25;
    lookup_words[1u * row_count + row] = r25;
    lookup_words[46u * row_count + row] = r25;
    lookup_words[50u * row_count + row] = r127;
}
