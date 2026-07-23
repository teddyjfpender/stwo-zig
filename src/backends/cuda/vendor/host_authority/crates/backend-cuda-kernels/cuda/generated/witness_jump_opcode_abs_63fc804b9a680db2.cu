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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_5d42e07d1f98cef0(
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
    unsigned r2 = 2u;
    unsigned r3 = 24u;
    unsigned r4 = 32u;
    unsigned r5 = 64u;
    unsigned r6 = 128u;
    unsigned r7 = 512u;
    unsigned r8 = 32767u;
    sub_words[1u * row_count + row] = r8;
    sub_words[2u * row_count + row] = r8;
    lookup_words[2u * row_count + row] = r8;
    lookup_words[3u * row_count + row] = r8;
    unsigned r9 = 32768u;
    unsigned r10 = 262144u;
    unsigned r11 = 134217728u;
    unsigned r12 = 428564188u;
    lookup_words[41u * row_count + row] = r12;
    lookup_words[45u * row_count + row] = r12;
    unsigned r13 = 1444891767u;
    lookup_words[8u * row_count + row] = r13;
    unsigned r14 = 1662111297u;
    lookup_words[11u * row_count + row] = r14;
    unsigned r15 = 1719106205u;
    lookup_words[0u * row_count + row] = r15;
    unsigned r16 = 2147483646u;
    unsigned r17 = input_cols[0u][row];
    unsigned r18 = input_cols[1u][row];
    unsigned r19 = input_cols[2u][row];
    unsigned r20 = (r17 < table_strides[0u] ? table_bases[0u][r17] : 0u);
    out_cols[0u][row] = r17;
    sub_words[0u * row_count + row] = r17;
    lookup_words[1u * row_count + row] = r17;
    lookup_words[42u * row_count + row] = r17;
    unsigned r21 = stwo_wit_deduce_limb(table_bases, table_strides, r20, 3u);
    unsigned r22 = (r21 & 0xFFFFu);
    unsigned r23 = ((r22 & 0xFFFFu) >> 5u);
    unsigned r24 = stwo_wit_deduce_limb(table_bases, table_strides, r20, 4u);
    unsigned r25 = (r24 & 0xFFFFu);
    unsigned r26 = ((r25 << 4u) & 0xFFFFu);
    unsigned r27 = ((r23 + r26) & 0xFFFFu);
    unsigned r28 = stwo_wit_deduce_limb(table_bases, table_strides, r20, 5u);
    unsigned r29 = (r28 & 0xFFFFu);
    unsigned r30 = (r29 & 7u);
    unsigned r31 = ((r30 << 13u) & 0xFFFFu);
    unsigned r32 = ((r27 + r31) & 0xFFFFu);
    unsigned r33 = (r32 % STWO_M31_P);
    unsigned r34 = stwo_wit_deduce_limb(table_bases, table_strides, r20, 5u);
    unsigned r35 = (r34 & 0xFFFFu);
    unsigned r36 = ((r35 & 0xFFFFu) >> 3u);
    unsigned r37 = stwo_wit_deduce_limb(table_bases, table_strides, r20, 6u);
    unsigned r38 = (r37 & 0xFFFFu);
    unsigned r39 = ((r38 << 6u) & 0xFFFFu);
    unsigned r40 = ((r36 + r39) & 0xFFFFu);
    unsigned r41 = ((r40 & 0xFFFFu) >> 3u);
    unsigned r42 = (r41 & 1u);
    unsigned r43 = (r42 % STWO_M31_P);
    unsigned r44 = stwo_wit_deduce_limb(table_bases, table_strides, r20, 5u);
    unsigned r45 = (r44 & 0xFFFFu);
    unsigned r46 = ((r45 & 0xFFFFu) >> 3u);
    unsigned r47 = stwo_wit_deduce_limb(table_bases, table_strides, r20, 6u);
    unsigned r48 = (r47 & 0xFFFFu);
    unsigned r49 = ((r48 << 6u) & 0xFFFFu);
    unsigned r50 = ((r46 + r49) & 0xFFFFu);
    unsigned r51 = ((r50 & 0xFFFFu) >> 11u);
    unsigned r52 = (r51 & 1u);
    unsigned r53 = (r52 % STWO_M31_P);
    unsigned r54 = stwo_m31_mul(r43, r5);
    unsigned r55 = stwo_m31_add(r3, r54);
    unsigned r56 = stwo_m31_sub(r1, r43);
    unsigned r57 = stwo_m31_mul(r56, r6);
    unsigned r58 = stwo_m31_add(r55, r57);
    sub_words[4u * row_count + row] = r58;
    unsigned r59 = stwo_m31_mul(r53, r4);
    unsigned r60 = stwo_m31_add(r2, r59);
    sub_words[5u * row_count + row] = r60;
    unsigned r61 = stwo_m31_mul(r43, r5);
    unsigned r62 = stwo_m31_add(r3, r61);
    unsigned r63 = stwo_m31_sub(r1, r43);
    unsigned r64 = stwo_m31_mul(r63, r6);
    unsigned r65 = stwo_m31_add(r62, r64);
    lookup_words[5u * row_count + row] = r65;
    unsigned r66 = stwo_m31_mul(r53, r4);
    unsigned r67 = stwo_m31_add(r2, r66);
    lookup_words[6u * row_count + row] = r67;
    unsigned r68 = stwo_m31_sub(r33, r9);
    out_cols[3u][row] = r33;
    sub_words[3u * row_count + row] = r33;
    lookup_words[4u * row_count + row] = r33;
    unsigned r69 = stwo_m31_sub(r1, r43);
    lookup_words[49u * row_count + row] = r1;
    unsigned r70 = stwo_m31_mul(r43, r19);
    out_cols[2u][row] = r19;
    out_cols[4u][row] = r43;
    lookup_words[44u * row_count + row] = r19;
    lookup_words[48u * row_count + row] = r19;
    unsigned r71 = stwo_m31_mul(r69, r18);
    unsigned r72 = stwo_m31_add(r70, r71);
    unsigned r73 = stwo_m31_add(r72, r68);
    unsigned r74 = (r73 < table_strides[0u] ? table_bases[0u][r73] : 0u);
    unsigned r75 = stwo_m31_add(r72, r68);
    sub_words[7u * row_count + row] = r75;
    unsigned r76 = stwo_m31_add(r72, r68);
    out_cols[6u][row] = r72;
    lookup_words[9u * row_count + row] = r76;
    unsigned r77 = stwo_wit_deduce_limb(table_bases, table_strides, r74, 0u);
    unsigned r78 = stwo_wit_deduce_limb(table_bases, table_strides, r74, 1u);
    unsigned r79 = stwo_wit_deduce_limb(table_bases, table_strides, r74, 2u);
    unsigned r80 = stwo_wit_deduce_limb(table_bases, table_strides, r74, 3u);
    out_cols[7u][row] = r74;
    lookup_words[10u * row_count + row] = r74;
    sub_words[8u * row_count + row] = r74;
    lookup_words[12u * row_count + row] = r74;
    unsigned r81 = (r80 & 0xFFFFu);
    unsigned r82 = (r81 & 2u);
    unsigned r83 = ((r82 & 0xFFFFu) >> 1u);
    unsigned r84 = (r83 % STWO_M31_P);
    out_cols[12u][row] = r84;
    unsigned r85 = input_cols[3u][row];
    out_cols[13u][row] = r85;
    lookup_words[50u * row_count + row] = r85;
    unsigned r86 = stwo_m31_mul(r78, r7);
    out_cols[9u][row] = r78;
    lookup_words[14u * row_count + row] = r78;
    unsigned r87 = stwo_m31_add(r77, r86);
    out_cols[8u][row] = r77;
    lookup_words[13u * row_count + row] = r77;
    unsigned r88 = stwo_m31_mul(r79, r10);
    out_cols[10u][row] = r79;
    lookup_words[15u * row_count + row] = r79;
    unsigned r89 = stwo_m31_add(r87, r88);
    unsigned r90 = stwo_m31_mul(r80, r11);
    out_cols[11u][row] = r80;
    lookup_words[16u * row_count + row] = r80;
    unsigned r91 = stwo_m31_add(r89, r90);
    lookup_words[46u * row_count + row] = r91;
    unsigned r92 = stwo_m31_add(r18, r53);
    out_cols[1u][row] = r18;
    out_cols[5u][row] = r53;
    lookup_words[43u * row_count + row] = r18;
    lookup_words[47u * row_count + row] = r92;
}
