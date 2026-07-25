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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_7db50b96e3fbaedb(
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
    unsigned r3 = 32u;
    unsigned r4 = 56u;
    sub_words[4u * row_count + row] = r4;
    lookup_words[5u * row_count + row] = r4;
    unsigned r5 = 136u;
    unsigned r6 = 256u;
    unsigned r7 = 508u;
    unsigned r8 = 511u;
    unsigned r9 = 512u;
    unsigned r10 = 32767u;
    sub_words[1u * row_count + row] = r10;
    sub_words[2u * row_count + row] = r10;
    lookup_words[2u * row_count + row] = r10;
    lookup_words[3u * row_count + row] = r10;
    unsigned r11 = 32769u;
    sub_words[3u * row_count + row] = r11;
    lookup_words[4u * row_count + row] = r11;
    unsigned r12 = 262144u;
    unsigned r13 = 134217728u;
    unsigned r14 = 428564188u;
    lookup_words[41u * row_count + row] = r14;
    lookup_words[45u * row_count + row] = r14;
    unsigned r15 = 536870912u;
    unsigned r16 = 1444891767u;
    lookup_words[8u * row_count + row] = r16;
    unsigned r17 = 1662111297u;
    lookup_words[11u * row_count + row] = r17;
    unsigned r18 = 1719106205u;
    lookup_words[0u * row_count + row] = r18;
    unsigned r19 = 2147483646u;
    unsigned r20 = input_cols[0u][row];
    unsigned r21 = input_cols[1u][row];
    unsigned r22 = input_cols[2u][row];
    out_cols[2u][row] = r22;
    lookup_words[44u * row_count + row] = r22;
    lookup_words[48u * row_count + row] = r22;
    unsigned r23 = (r20 < table_strides[0u] ? table_bases[0u][r20] : 0u);
    unsigned r24 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 5u);
    unsigned r25 = (r24 & 0xFFFFu);
    unsigned r26 = ((r25 & 0xFFFFu) >> 3u);
    unsigned r27 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 6u);
    unsigned r28 = (r27 & 0xFFFFu);
    unsigned r29 = ((r28 << 6u) & 0xFFFFu);
    unsigned r30 = ((r26 + r29) & 0xFFFFu);
    unsigned r31 = ((r30 & 0xFFFFu) >> 11u);
    unsigned r32 = (r31 & 1u);
    unsigned r33 = (r32 % STWO_M31_P);
    unsigned r34 = stwo_m31_mul(r33, r3);
    unsigned r35 = stwo_m31_add(r2, r34);
    sub_words[5u * row_count + row] = r35;
    unsigned r36 = stwo_m31_mul(r33, r3);
    unsigned r37 = stwo_m31_add(r2, r36);
    lookup_words[6u * row_count + row] = r37;
    unsigned r38 = stwo_m31_add(r20, r1);
    unsigned r39 = (r38 < table_strides[0u] ? table_bases[0u][r38] : 0u);
    unsigned r40 = stwo_m31_add(r20, r1);
    sub_words[7u * row_count + row] = r40;
    unsigned r41 = stwo_m31_add(r20, r1);
    lookup_words[9u * row_count + row] = r41;
    lookup_words[49u * row_count + row] = r1;
    unsigned r42 = stwo_wit_deduce_limb(table_bases, table_strides, r39, 27u);
    unsigned r43 = (r42 == r6 ? 1u : 0u);
    unsigned r44 = stwo_wit_deduce_limb(table_bases, table_strides, r39, 20u);
    unsigned r45 = (r44 == r8 ? 1u : 0u);
    unsigned r46 = stwo_m31_mul(r45, r43);
    unsigned r47 = stwo_m31_mul(r46, r7);
    unsigned r48 = stwo_m31_mul(r46, r8);
    lookup_words[17u * row_count + row] = r48;
    lookup_words[18u * row_count + row] = r48;
    lookup_words[19u * row_count + row] = r48;
    lookup_words[20u * row_count + row] = r48;
    lookup_words[21u * row_count + row] = r48;
    lookup_words[22u * row_count + row] = r48;
    lookup_words[23u * row_count + row] = r48;
    lookup_words[24u * row_count + row] = r48;
    lookup_words[25u * row_count + row] = r48;
    lookup_words[26u * row_count + row] = r48;
    lookup_words[27u * row_count + row] = r48;
    lookup_words[28u * row_count + row] = r48;
    lookup_words[29u * row_count + row] = r48;
    lookup_words[30u * row_count + row] = r48;
    lookup_words[31u * row_count + row] = r48;
    lookup_words[32u * row_count + row] = r48;
    lookup_words[33u * row_count + row] = r48;
    unsigned r49 = stwo_m31_mul(r43, r5);
    unsigned r50 = stwo_m31_sub(r49, r46);
    lookup_words[34u * row_count + row] = r50;
    unsigned r51 = stwo_m31_mul(r43, r6);
    lookup_words[40u * row_count + row] = r51;
    unsigned r52 = stwo_wit_deduce_limb(table_bases, table_strides, r39, 0u);
    unsigned r53 = stwo_wit_deduce_limb(table_bases, table_strides, r39, 1u);
    unsigned r54 = stwo_wit_deduce_limb(table_bases, table_strides, r39, 2u);
    unsigned r55 = stwo_wit_deduce_limb(table_bases, table_strides, r39, 3u);
    out_cols[4u][row] = r39;
    lookup_words[10u * row_count + row] = r39;
    sub_words[8u * row_count + row] = r39;
    lookup_words[12u * row_count + row] = r39;
    unsigned r56 = (r55 & 0xFFFFu);
    unsigned r57 = (r56 & 3u);
    unsigned r58 = (r57 % STWO_M31_P);
    unsigned r59 = (r58 & 0xFFFFu);
    unsigned r60 = (r59 & 2u);
    unsigned r61 = ((r60 & 0xFFFFu) >> 1u);
    unsigned r62 = (r61 % STWO_M31_P);
    out_cols[11u][row] = r62;
    unsigned r63 = stwo_m31_add(r58, r47);
    lookup_words[16u * row_count + row] = r63;
    unsigned r64 = stwo_m31_mul(r53, r9);
    out_cols[8u][row] = r53;
    lookup_words[14u * row_count + row] = r53;
    unsigned r65 = stwo_m31_add(r52, r64);
    out_cols[7u][row] = r52;
    lookup_words[13u * row_count + row] = r52;
    unsigned r66 = stwo_m31_mul(r54, r12);
    out_cols[9u][row] = r54;
    lookup_words[15u * row_count + row] = r54;
    unsigned r67 = stwo_m31_add(r65, r66);
    unsigned r68 = stwo_m31_mul(r58, r13);
    out_cols[10u][row] = r58;
    unsigned r69 = stwo_m31_add(r67, r68);
    unsigned r70 = stwo_m31_sub(r69, r43);
    out_cols[5u][row] = r43;
    unsigned r71 = stwo_m31_mul(r15, r46);
    out_cols[6u][row] = r46;
    unsigned r72 = stwo_m31_sub(r70, r71);
    unsigned r73 = input_cols[3u][row];
    out_cols[12u][row] = r73;
    lookup_words[50u * row_count + row] = r73;
    unsigned r74 = stwo_m31_add(r20, r72);
    out_cols[0u][row] = r20;
    sub_words[0u * row_count + row] = r20;
    lookup_words[1u * row_count + row] = r20;
    lookup_words[42u * row_count + row] = r20;
    lookup_words[46u * row_count + row] = r74;
    unsigned r75 = stwo_m31_add(r21, r33);
    out_cols[1u][row] = r21;
    out_cols[3u][row] = r33;
    lookup_words[43u * row_count + row] = r21;
    lookup_words[47u * row_count + row] = r75;
}
