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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_3343f9826788070c(
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
    lookup_words[83u * row_count + row] = r0;
    lookup_words[84u * row_count + row] = r0;
    lookup_words[85u * row_count + row] = r0;
    lookup_words[86u * row_count + row] = r0;
    lookup_words[87u * row_count + row] = r0;
    lookup_words[88u * row_count + row] = r0;
    lookup_words[89u * row_count + row] = r0;
    lookup_words[90u * row_count + row] = r0;
    lookup_words[91u * row_count + row] = r0;
    lookup_words[92u * row_count + row] = r0;
    lookup_words[93u * row_count + row] = r0;
    lookup_words[94u * row_count + row] = r0;
    lookup_words[95u * row_count + row] = r0;
    lookup_words[96u * row_count + row] = r0;
    lookup_words[97u * row_count + row] = r0;
    lookup_words[98u * row_count + row] = r0;
    lookup_words[99u * row_count + row] = r0;
    lookup_words[100u * row_count + row] = r0;
    lookup_words[101u * row_count + row] = r0;
    lookup_words[102u * row_count + row] = r0;
    lookup_words[103u * row_count + row] = r0;
    lookup_words[104u * row_count + row] = r0;
    lookup_words[105u * row_count + row] = r0;
    lookup_words[106u * row_count + row] = r0;
    unsigned r1 = 1u;
    unsigned r2 = 2u;
    unsigned r3 = 64u;
    unsigned r4 = 66u;
    sub_words[5u * row_count + row] = r4;
    lookup_words[6u * row_count + row] = r4;
    unsigned r5 = 128u;
    unsigned r6 = 512u;
    unsigned r7 = 32768u;
    unsigned r8 = 32769u;
    sub_words[2u * row_count + row] = r8;
    lookup_words[3u * row_count + row] = r8;
    unsigned r9 = 262144u;
    unsigned r10 = 134217728u;
    unsigned r11 = 428564188u;
    lookup_words[107u * row_count + row] = r11;
    lookup_words[111u * row_count + row] = r11;
    unsigned r12 = 1444891767u;
    lookup_words[8u * row_count + row] = r12;
    lookup_words[41u * row_count + row] = r12;
    lookup_words[74u * row_count + row] = r12;
    unsigned r13 = 1662111297u;
    lookup_words[11u * row_count + row] = r13;
    lookup_words[44u * row_count + row] = r13;
    lookup_words[77u * row_count + row] = r13;
    unsigned r14 = 1719106205u;
    lookup_words[0u * row_count + row] = r14;
    unsigned r15 = input_cols[0u][row];
    unsigned r16 = input_cols[1u][row];
    unsigned r17 = input_cols[2u][row];
    unsigned r18 = (r15 < table_strides[0u] ? table_bases[0u][r15] : 0u);
    out_cols[0u][row] = r15;
    sub_words[0u * row_count + row] = r15;
    lookup_words[1u * row_count + row] = r15;
    lookup_words[108u * row_count + row] = r15;
    unsigned r19 = stwo_wit_deduce_limb(table_bases, table_strides, r18, 3u);
    unsigned r20 = (r19 & 0xFFFFu);
    unsigned r21 = ((r20 & 0xFFFFu) >> 5u);
    unsigned r22 = stwo_wit_deduce_limb(table_bases, table_strides, r18, 4u);
    unsigned r23 = (r22 & 0xFFFFu);
    unsigned r24 = ((r23 << 4u) & 0xFFFFu);
    unsigned r25 = ((r21 + r24) & 0xFFFFu);
    unsigned r26 = stwo_wit_deduce_limb(table_bases, table_strides, r18, 5u);
    unsigned r27 = (r26 & 0xFFFFu);
    unsigned r28 = (r27 & 7u);
    unsigned r29 = ((r28 << 13u) & 0xFFFFu);
    unsigned r30 = ((r25 + r29) & 0xFFFFu);
    unsigned r31 = (r30 % STWO_M31_P);
    unsigned r32 = stwo_wit_deduce_limb(table_bases, table_strides, r18, 5u);
    unsigned r33 = (r32 & 0xFFFFu);
    unsigned r34 = ((r33 & 0xFFFFu) >> 3u);
    unsigned r35 = stwo_wit_deduce_limb(table_bases, table_strides, r18, 6u);
    unsigned r36 = (r35 & 0xFFFFu);
    unsigned r37 = ((r36 << 6u) & 0xFFFFu);
    unsigned r38 = ((r34 + r37) & 0xFFFFu);
    unsigned r39 = ((r38 & 0xFFFFu) >> 3u);
    unsigned r40 = (r39 & 1u);
    unsigned r41 = (r40 % STWO_M31_P);
    unsigned r42 = stwo_m31_mul(r41, r3);
    unsigned r43 = stwo_m31_sub(r1, r41);
    unsigned r44 = stwo_m31_mul(r43, r5);
    unsigned r45 = stwo_m31_add(r42, r44);
    sub_words[4u * row_count + row] = r45;
    unsigned r46 = stwo_m31_mul(r41, r3);
    unsigned r47 = stwo_m31_sub(r1, r41);
    unsigned r48 = stwo_m31_mul(r47, r5);
    unsigned r49 = stwo_m31_add(r46, r48);
    lookup_words[5u * row_count + row] = r49;
    unsigned r50 = stwo_m31_sub(r31, r7);
    out_cols[3u][row] = r31;
    sub_words[1u * row_count + row] = r7;
    sub_words[3u * row_count + row] = r31;
    lookup_words[2u * row_count + row] = r7;
    lookup_words[4u * row_count + row] = r31;
    unsigned r51 = stwo_m31_sub(r1, r41);
    unsigned r52 = (r16 < table_strides[0u] ? table_bases[0u][r16] : 0u);
    unsigned r53 = stwo_wit_deduce_limb(table_bases, table_strides, r52, 0u);
    out_cols[6u][row] = r53;
    lookup_words[13u * row_count + row] = r53;
    unsigned r54 = stwo_wit_deduce_limb(table_bases, table_strides, r52, 1u);
    out_cols[7u][row] = r54;
    lookup_words[14u * row_count + row] = r54;
    unsigned r55 = stwo_wit_deduce_limb(table_bases, table_strides, r52, 2u);
    out_cols[8u][row] = r55;
    lookup_words[15u * row_count + row] = r55;
    unsigned r56 = stwo_wit_deduce_limb(table_bases, table_strides, r52, 3u);
    out_cols[5u][row] = r52;
    lookup_words[10u * row_count + row] = r52;
    sub_words[10u * row_count + row] = r52;
    lookup_words[12u * row_count + row] = r52;
    unsigned r57 = (r56 & 0xFFFFu);
    out_cols[9u][row] = r56;
    lookup_words[16u * row_count + row] = r56;
    unsigned r58 = (r57 & 2u);
    unsigned r59 = ((r58 & 0xFFFFu) >> 1u);
    unsigned r60 = (r59 % STWO_M31_P);
    out_cols[10u][row] = r60;
    unsigned r61 = stwo_m31_add(r16, r1);
    unsigned r62 = (r61 < table_strides[0u] ? table_bases[0u][r61] : 0u);
    unsigned r63 = stwo_m31_add(r16, r1);
    sub_words[8u * row_count + row] = r63;
    unsigned r64 = stwo_m31_add(r16, r1);
    lookup_words[42u * row_count + row] = r64;
    lookup_words[115u * row_count + row] = r1;
    unsigned r65 = stwo_wit_deduce_limb(table_bases, table_strides, r62, 0u);
    out_cols[12u][row] = r65;
    lookup_words[46u * row_count + row] = r65;
    unsigned r66 = stwo_wit_deduce_limb(table_bases, table_strides, r62, 1u);
    out_cols[13u][row] = r66;
    lookup_words[47u * row_count + row] = r66;
    unsigned r67 = stwo_wit_deduce_limb(table_bases, table_strides, r62, 2u);
    out_cols[14u][row] = r67;
    lookup_words[48u * row_count + row] = r67;
    unsigned r68 = stwo_wit_deduce_limb(table_bases, table_strides, r62, 3u);
    out_cols[11u][row] = r62;
    lookup_words[43u * row_count + row] = r62;
    sub_words[11u * row_count + row] = r62;
    lookup_words[45u * row_count + row] = r62;
    unsigned r69 = (r68 & 0xFFFFu);
    out_cols[15u][row] = r68;
    lookup_words[49u * row_count + row] = r68;
    unsigned r70 = (r69 & 2u);
    unsigned r71 = ((r70 & 0xFFFFu) >> 1u);
    unsigned r72 = (r71 % STWO_M31_P);
    out_cols[16u][row] = r72;
    unsigned r73 = stwo_m31_mul(r41, r17);
    out_cols[2u][row] = r17;
    out_cols[4u][row] = r41;
    lookup_words[110u * row_count + row] = r17;
    unsigned r74 = stwo_m31_mul(r51, r16);
    unsigned r75 = stwo_m31_add(r73, r74);
    unsigned r76 = stwo_m31_add(r75, r50);
    unsigned r77 = (r76 < table_strides[0u] ? table_bases[0u][r76] : 0u);
    unsigned r78 = stwo_m31_add(r75, r50);
    sub_words[9u * row_count + row] = r78;
    unsigned r79 = stwo_m31_add(r75, r50);
    out_cols[17u][row] = r75;
    lookup_words[75u * row_count + row] = r79;
    unsigned r80 = stwo_wit_deduce_limb(table_bases, table_strides, r77, 0u);
    unsigned r81 = stwo_wit_deduce_limb(table_bases, table_strides, r77, 1u);
    unsigned r82 = stwo_wit_deduce_limb(table_bases, table_strides, r77, 2u);
    unsigned r83 = stwo_wit_deduce_limb(table_bases, table_strides, r77, 3u);
    out_cols[18u][row] = r77;
    lookup_words[76u * row_count + row] = r77;
    sub_words[12u * row_count + row] = r77;
    lookup_words[78u * row_count + row] = r77;
    unsigned r84 = (r83 & 0xFFFFu);
    unsigned r85 = (r84 & 2u);
    unsigned r86 = ((r85 & 0xFFFFu) >> 1u);
    unsigned r87 = (r86 % STWO_M31_P);
    out_cols[23u][row] = r87;
    unsigned r88 = input_cols[3u][row];
    out_cols[24u][row] = r88;
    lookup_words[116u * row_count + row] = r88;
    unsigned r89 = stwo_m31_mul(r81, r6);
    out_cols[20u][row] = r81;
    lookup_words[80u * row_count + row] = r81;
    unsigned r90 = stwo_m31_add(r80, r89);
    out_cols[19u][row] = r80;
    lookup_words[79u * row_count + row] = r80;
    unsigned r91 = stwo_m31_mul(r82, r9);
    out_cols[21u][row] = r82;
    lookup_words[81u * row_count + row] = r82;
    unsigned r92 = stwo_m31_add(r90, r91);
    unsigned r93 = stwo_m31_mul(r83, r10);
    out_cols[22u][row] = r83;
    lookup_words[82u * row_count + row] = r83;
    unsigned r94 = stwo_m31_add(r92, r93);
    lookup_words[112u * row_count + row] = r94;
    unsigned r95 = stwo_m31_add(r16, r2);
    lookup_words[113u * row_count + row] = r95;
    unsigned r96 = stwo_m31_add(r16, r2);
    out_cols[1u][row] = r16;
    sub_words[7u * row_count + row] = r16;
    lookup_words[9u * row_count + row] = r16;
    lookup_words[109u * row_count + row] = r16;
    lookup_words[114u * row_count + row] = r96;
}
