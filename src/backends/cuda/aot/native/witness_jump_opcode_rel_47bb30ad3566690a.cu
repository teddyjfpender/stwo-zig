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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_c7457acb39874135(
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
    unsigned r2 = 4u;
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
    unsigned r15 = 134217728u;
    unsigned r16 = 428564188u;
    lookup_words[41u * row_count + row] = r16;
    lookup_words[45u * row_count + row] = r16;
    unsigned r17 = 536870912u;
    unsigned r18 = 1444891767u;
    lookup_words[8u * row_count + row] = r18;
    unsigned r19 = 1662111297u;
    lookup_words[11u * row_count + row] = r19;
    unsigned r20 = 1719106205u;
    lookup_words[0u * row_count + row] = r20;
    unsigned r21 = 2147483646u;
    unsigned r22 = input_cols[0u][row];
    unsigned r23 = input_cols[1u][row];
    unsigned r24 = input_cols[2u][row];
    unsigned r25 = (r22 < table_strides[0u] ? table_bases[0u][r22] : 0u);
    unsigned r26 = stwo_wit_deduce_limb(table_bases, table_strides, r25, 3u);
    unsigned r27 = (r26 & 0xFFFFu);
    unsigned r28 = ((r27 & 0xFFFFu) >> 5u);
    unsigned r29 = stwo_wit_deduce_limb(table_bases, table_strides, r25, 4u);
    unsigned r30 = (r29 & 0xFFFFu);
    unsigned r31 = ((r30 << 4u) & 0xFFFFu);
    unsigned r32 = ((r28 + r31) & 0xFFFFu);
    unsigned r33 = stwo_wit_deduce_limb(table_bases, table_strides, r25, 5u);
    unsigned r34 = (r33 & 0xFFFFu);
    unsigned r35 = (r34 & 7u);
    unsigned r36 = ((r35 << 13u) & 0xFFFFu);
    unsigned r37 = ((r32 + r36) & 0xFFFFu);
    unsigned r38 = (r37 % STWO_M31_P);
    unsigned r39 = stwo_wit_deduce_limb(table_bases, table_strides, r25, 5u);
    unsigned r40 = (r39 & 0xFFFFu);
    unsigned r41 = ((r40 & 0xFFFFu) >> 3u);
    unsigned r42 = stwo_wit_deduce_limb(table_bases, table_strides, r25, 6u);
    unsigned r43 = (r42 & 0xFFFFu);
    unsigned r44 = ((r43 << 6u) & 0xFFFFu);
    unsigned r45 = ((r41 + r44) & 0xFFFFu);
    unsigned r46 = ((r45 & 0xFFFFu) >> 3u);
    unsigned r47 = (r46 & 1u);
    unsigned r48 = (r47 % STWO_M31_P);
    unsigned r49 = stwo_wit_deduce_limb(table_bases, table_strides, r25, 5u);
    unsigned r50 = (r49 & 0xFFFFu);
    unsigned r51 = ((r50 & 0xFFFFu) >> 3u);
    unsigned r52 = stwo_wit_deduce_limb(table_bases, table_strides, r25, 6u);
    unsigned r53 = (r52 & 0xFFFFu);
    unsigned r54 = ((r53 << 6u) & 0xFFFFu);
    unsigned r55 = ((r51 + r54) & 0xFFFFu);
    unsigned r56 = ((r55 & 0xFFFFu) >> 11u);
    unsigned r57 = (r56 & 1u);
    unsigned r58 = (r57 % STWO_M31_P);
    unsigned r59 = stwo_m31_mul(r48, r5);
    unsigned r60 = stwo_m31_add(r3, r59);
    unsigned r61 = stwo_m31_sub(r1, r48);
    unsigned r62 = stwo_m31_mul(r61, r6);
    unsigned r63 = stwo_m31_add(r60, r62);
    sub_words[4u * row_count + row] = r63;
    unsigned r64 = stwo_m31_mul(r58, r4);
    unsigned r65 = stwo_m31_add(r2, r64);
    sub_words[5u * row_count + row] = r65;
    unsigned r66 = stwo_m31_mul(r48, r5);
    unsigned r67 = stwo_m31_add(r3, r66);
    unsigned r68 = stwo_m31_sub(r1, r48);
    unsigned r69 = stwo_m31_mul(r68, r6);
    unsigned r70 = stwo_m31_add(r67, r69);
    lookup_words[5u * row_count + row] = r70;
    unsigned r71 = stwo_m31_mul(r58, r4);
    unsigned r72 = stwo_m31_add(r2, r71);
    lookup_words[6u * row_count + row] = r72;
    unsigned r73 = stwo_m31_sub(r38, r13);
    out_cols[3u][row] = r38;
    sub_words[3u * row_count + row] = r38;
    lookup_words[4u * row_count + row] = r38;
    unsigned r74 = stwo_m31_sub(r1, r48);
    lookup_words[49u * row_count + row] = r1;
    unsigned r75 = stwo_m31_mul(r48, r24);
    out_cols[2u][row] = r24;
    out_cols[4u][row] = r48;
    lookup_words[44u * row_count + row] = r24;
    lookup_words[48u * row_count + row] = r24;
    unsigned r76 = stwo_m31_mul(r74, r23);
    unsigned r77 = stwo_m31_add(r75, r76);
    unsigned r78 = stwo_m31_add(r77, r73);
    unsigned r79 = (r78 < table_strides[0u] ? table_bases[0u][r78] : 0u);
    unsigned r80 = stwo_m31_add(r77, r73);
    sub_words[7u * row_count + row] = r80;
    unsigned r81 = stwo_m31_add(r77, r73);
    out_cols[6u][row] = r77;
    lookup_words[9u * row_count + row] = r81;
    unsigned r82 = stwo_wit_deduce_limb(table_bases, table_strides, r79, 27u);
    unsigned r83 = (r82 == r8 ? 1u : 0u);
    unsigned r84 = stwo_wit_deduce_limb(table_bases, table_strides, r79, 20u);
    unsigned r85 = (r84 == r10 ? 1u : 0u);
    unsigned r86 = stwo_m31_mul(r85, r83);
    unsigned r87 = stwo_m31_mul(r86, r9);
    unsigned r88 = stwo_m31_mul(r86, r10);
    lookup_words[17u * row_count + row] = r88;
    lookup_words[18u * row_count + row] = r88;
    lookup_words[19u * row_count + row] = r88;
    lookup_words[20u * row_count + row] = r88;
    lookup_words[21u * row_count + row] = r88;
    lookup_words[22u * row_count + row] = r88;
    lookup_words[23u * row_count + row] = r88;
    lookup_words[24u * row_count + row] = r88;
    lookup_words[25u * row_count + row] = r88;
    lookup_words[26u * row_count + row] = r88;
    lookup_words[27u * row_count + row] = r88;
    lookup_words[28u * row_count + row] = r88;
    lookup_words[29u * row_count + row] = r88;
    lookup_words[30u * row_count + row] = r88;
    lookup_words[31u * row_count + row] = r88;
    lookup_words[32u * row_count + row] = r88;
    lookup_words[33u * row_count + row] = r88;
    unsigned r89 = stwo_m31_mul(r83, r7);
    unsigned r90 = stwo_m31_sub(r89, r86);
    lookup_words[34u * row_count + row] = r90;
    unsigned r91 = stwo_m31_mul(r83, r8);
    lookup_words[40u * row_count + row] = r91;
    unsigned r92 = stwo_wit_deduce_limb(table_bases, table_strides, r79, 0u);
    unsigned r93 = stwo_wit_deduce_limb(table_bases, table_strides, r79, 1u);
    unsigned r94 = stwo_wit_deduce_limb(table_bases, table_strides, r79, 2u);
    unsigned r95 = stwo_wit_deduce_limb(table_bases, table_strides, r79, 3u);
    out_cols[7u][row] = r79;
    lookup_words[10u * row_count + row] = r79;
    sub_words[8u * row_count + row] = r79;
    lookup_words[12u * row_count + row] = r79;
    unsigned r96 = (r95 & 0xFFFFu);
    unsigned r97 = (r96 & 3u);
    unsigned r98 = (r97 % STWO_M31_P);
    unsigned r99 = (r98 & 0xFFFFu);
    unsigned r100 = (r99 & 2u);
    unsigned r101 = ((r100 & 0xFFFFu) >> 1u);
    unsigned r102 = (r101 % STWO_M31_P);
    out_cols[14u][row] = r102;
    unsigned r103 = stwo_m31_add(r98, r87);
    lookup_words[16u * row_count + row] = r103;
    unsigned r104 = stwo_m31_mul(r93, r11);
    out_cols[11u][row] = r93;
    lookup_words[14u * row_count + row] = r93;
    unsigned r105 = stwo_m31_add(r92, r104);
    out_cols[10u][row] = r92;
    lookup_words[13u * row_count + row] = r92;
    unsigned r106 = stwo_m31_mul(r94, r14);
    out_cols[12u][row] = r94;
    lookup_words[15u * row_count + row] = r94;
    unsigned r107 = stwo_m31_add(r105, r106);
    unsigned r108 = stwo_m31_mul(r98, r15);
    out_cols[13u][row] = r98;
    unsigned r109 = stwo_m31_add(r107, r108);
    unsigned r110 = stwo_m31_sub(r109, r83);
    out_cols[8u][row] = r83;
    unsigned r111 = stwo_m31_mul(r17, r86);
    out_cols[9u][row] = r86;
    unsigned r112 = stwo_m31_sub(r110, r111);
    unsigned r113 = input_cols[3u][row];
    out_cols[15u][row] = r113;
    lookup_words[50u * row_count + row] = r113;
    unsigned r114 = stwo_m31_add(r22, r112);
    out_cols[0u][row] = r22;
    sub_words[0u * row_count + row] = r22;
    lookup_words[1u * row_count + row] = r22;
    lookup_words[42u * row_count + row] = r22;
    lookup_words[46u * row_count + row] = r114;
    unsigned r115 = stwo_m31_add(r23, r58);
    out_cols[1u][row] = r23;
    out_cols[5u][row] = r58;
    lookup_words[43u * row_count + row] = r23;
    lookup_words[47u * row_count + row] = r115;
}
