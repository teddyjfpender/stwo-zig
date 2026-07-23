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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_c4b01b327c2ce2a3(
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
    unsigned r1 = 1u;
    unsigned r2 = 8u;
    unsigned r3 = 16u;
    unsigned r4 = 32u;
    unsigned r5 = 64u;
    unsigned r6 = 128u;
    unsigned r7 = 256u;
    unsigned r8 = 32767u;
    sub_words[2u * row_count + row] = r8;
    lookup_words[3u * row_count + row] = r8;
    unsigned r9 = 32768u;
    unsigned r10 = 428564188u;
    lookup_words[14u * row_count + row] = r10;
    lookup_words[18u * row_count + row] = r10;
    unsigned r11 = 1444891767u;
    lookup_words[8u * row_count + row] = r11;
    lookup_words[11u * row_count + row] = r11;
    unsigned r12 = 1719106205u;
    lookup_words[0u * row_count + row] = r12;
    unsigned r13 = 2147483646u;
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
    unsigned r26 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 3u);
    unsigned r27 = (r26 & 0xFFFFu);
    unsigned r28 = ((r27 & 0xFFFFu) >> 5u);
    unsigned r29 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 4u);
    unsigned r30 = (r29 & 0xFFFFu);
    unsigned r31 = ((r30 << 4u) & 0xFFFFu);
    unsigned r32 = ((r28 + r31) & 0xFFFFu);
    unsigned r33 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 5u);
    unsigned r34 = (r33 & 0xFFFFu);
    unsigned r35 = (r34 & 7u);
    unsigned r36 = ((r35 << 13u) & 0xFFFFu);
    unsigned r37 = ((r32 + r36) & 0xFFFFu);
    unsigned r38 = (r37 % STWO_M31_P);
    unsigned r39 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 5u);
    unsigned r40 = (r39 & 0xFFFFu);
    unsigned r41 = ((r40 & 0xFFFFu) >> 3u);
    unsigned r42 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 6u);
    unsigned r43 = (r42 & 0xFFFFu);
    unsigned r44 = ((r43 << 6u) & 0xFFFFu);
    unsigned r45 = ((r41 + r44) & 0xFFFFu);
    unsigned r46 = ((r45 & 0xFFFFu) >> 0u);
    unsigned r47 = (r46 & 1u);
    unsigned r48 = (r47 % STWO_M31_P);
    unsigned r49 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 5u);
    unsigned r50 = (r49 & 0xFFFFu);
    unsigned r51 = ((r50 & 0xFFFFu) >> 3u);
    unsigned r52 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 6u);
    unsigned r53 = (r52 & 0xFFFFu);
    unsigned r54 = ((r53 << 6u) & 0xFFFFu);
    unsigned r55 = ((r51 + r54) & 0xFFFFu);
    unsigned r56 = ((r55 & 0xFFFFu) >> 3u);
    unsigned r57 = (r56 & 1u);
    unsigned r58 = (r57 % STWO_M31_P);
    unsigned r59 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 5u);
    unsigned r60 = (r59 & 0xFFFFu);
    unsigned r61 = ((r60 & 0xFFFFu) >> 3u);
    unsigned r62 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 6u);
    unsigned r63 = (r62 & 0xFFFFu);
    unsigned r64 = ((r63 << 6u) & 0xFFFFu);
    unsigned r65 = ((r61 + r64) & 0xFFFFu);
    unsigned r66 = ((r65 & 0xFFFFu) >> 11u);
    unsigned r67 = (r66 & 1u);
    unsigned r68 = (r67 % STWO_M31_P);
    unsigned r69 = stwo_m31_mul(r48, r2);
    unsigned r70 = stwo_m31_add(r69, r3);
    unsigned r71 = stwo_m31_mul(r58, r5);
    unsigned r72 = stwo_m31_add(r70, r71);
    unsigned r73 = stwo_m31_sub(r1, r58);
    unsigned r74 = stwo_m31_mul(r73, r6);
    unsigned r75 = stwo_m31_add(r72, r74);
    sub_words[4u * row_count + row] = r75;
    unsigned r76 = stwo_m31_mul(r68, r4);
    unsigned r77 = stwo_m31_add(r76, r7);
    sub_words[5u * row_count + row] = r77;
    unsigned r78 = stwo_m31_mul(r48, r2);
    unsigned r79 = stwo_m31_add(r78, r3);
    unsigned r80 = stwo_m31_mul(r58, r5);
    unsigned r81 = stwo_m31_add(r79, r80);
    unsigned r82 = stwo_m31_sub(r1, r58);
    unsigned r83 = stwo_m31_mul(r82, r6);
    unsigned r84 = stwo_m31_add(r81, r83);
    lookup_words[5u * row_count + row] = r84;
    unsigned r85 = stwo_m31_mul(r68, r4);
    unsigned r86 = stwo_m31_add(r85, r7);
    lookup_words[6u * row_count + row] = r86;
    unsigned r87 = stwo_m31_sub(r25, r9);
    out_cols[3u][row] = r25;
    sub_words[1u * row_count + row] = r25;
    lookup_words[2u * row_count + row] = r25;
    unsigned r88 = stwo_m31_sub(r38, r9);
    out_cols[4u][row] = r38;
    sub_words[3u * row_count + row] = r38;
    lookup_words[4u * row_count + row] = r38;
    unsigned r89 = stwo_m31_sub(r1, r58);
    unsigned r90 = stwo_m31_mul(r48, r16);
    unsigned r91 = stwo_m31_sub(r1, r48);
    out_cols[5u][row] = r48;
    unsigned r92 = stwo_m31_mul(r91, r15);
    unsigned r93 = stwo_m31_add(r90, r92);
    unsigned r94 = stwo_m31_mul(r58, r16);
    out_cols[2u][row] = r16;
    out_cols[6u][row] = r58;
    lookup_words[17u * row_count + row] = r16;
    lookup_words[21u * row_count + row] = r16;
    unsigned r95 = stwo_m31_mul(r89, r15);
    unsigned r96 = stwo_m31_add(r94, r95);
    unsigned r97 = stwo_m31_add(r93, r87);
    unsigned r98 = (r97 < table_strides[0u] ? table_bases[0u][r97] : 0u);
    out_cols[10u][row] = r98;
    lookup_words[10u * row_count + row] = r98;
    lookup_words[13u * row_count + row] = r98;
    unsigned r99 = stwo_m31_add(r93, r87);
    sub_words[7u * row_count + row] = r99;
    unsigned r100 = stwo_m31_add(r93, r87);
    out_cols[8u][row] = r93;
    lookup_words[9u * row_count + row] = r100;
    unsigned r101 = stwo_m31_add(r96, r88);
    sub_words[8u * row_count + row] = r101;
    unsigned r102 = stwo_m31_add(r96, r88);
    out_cols[9u][row] = r96;
    lookup_words[12u * row_count + row] = r102;
    unsigned r103 = input_cols[3u][row];
    out_cols[11u][row] = r103;
    lookup_words[23u * row_count + row] = r103;
    unsigned r104 = stwo_m31_add(r14, r1);
    out_cols[0u][row] = r14;
    sub_words[0u * row_count + row] = r14;
    lookup_words[1u * row_count + row] = r14;
    lookup_words[15u * row_count + row] = r14;
    lookup_words[19u * row_count + row] = r104;
    lookup_words[22u * row_count + row] = r1;
    unsigned r105 = stwo_m31_add(r15, r68);
    out_cols[1u][row] = r15;
    out_cols[7u][row] = r68;
    lookup_words[16u * row_count + row] = r15;
    lookup_words[20u * row_count + row] = r105;
}
