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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_1ab1e90dff938797(
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
    lookup_words[13u * row_count + row] = r0;
    lookup_words[14u * row_count + row] = r0;
    lookup_words[15u * row_count + row] = r0;
    lookup_words[16u * row_count + row] = r0;
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
    unsigned r3 = 8u;
    unsigned r4 = 16u;
    unsigned r5 = 32u;
    unsigned r6 = 32767u;
    sub_words[2u * row_count + row] = r6;
    lookup_words[3u * row_count + row] = r6;
    unsigned r7 = 32768u;
    unsigned r8 = 32769u;
    sub_words[3u * row_count + row] = r8;
    lookup_words[4u * row_count + row] = r8;
    unsigned r9 = 428564188u;
    lookup_words[41u * row_count + row] = r9;
    lookup_words[45u * row_count + row] = r9;
    unsigned r10 = 1444891767u;
    lookup_words[8u * row_count + row] = r10;
    unsigned r11 = 1662111297u;
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
    unsigned r26 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 5u);
    unsigned r27 = (r26 & 0xFFFFu);
    unsigned r28 = ((r27 & 0xFFFFu) >> 3u);
    unsigned r29 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 6u);
    unsigned r30 = (r29 & 0xFFFFu);
    unsigned r31 = ((r30 << 6u) & 0xFFFFu);
    unsigned r32 = ((r28 + r31) & 0xFFFFu);
    unsigned r33 = ((r32 & 0xFFFFu) >> 0u);
    unsigned r34 = (r33 & 1u);
    unsigned r35 = (r34 % STWO_M31_P);
    unsigned r36 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 5u);
    unsigned r37 = (r36 & 0xFFFFu);
    unsigned r38 = ((r37 & 0xFFFFu) >> 3u);
    unsigned r39 = stwo_wit_deduce_limb(table_bases, table_strides, r17, 6u);
    unsigned r40 = (r39 & 0xFFFFu);
    unsigned r41 = ((r40 << 6u) & 0xFFFFu);
    unsigned r42 = ((r38 + r41) & 0xFFFFu);
    unsigned r43 = ((r42 & 0xFFFFu) >> 11u);
    unsigned r44 = (r43 & 1u);
    unsigned r45 = (r44 % STWO_M31_P);
    unsigned r46 = stwo_m31_mul(r35, r3);
    unsigned r47 = stwo_m31_add(r46, r4);
    unsigned r48 = stwo_m31_add(r47, r5);
    sub_words[4u * row_count + row] = r48;
    unsigned r49 = stwo_m31_mul(r45, r5);
    unsigned r50 = stwo_m31_add(r3, r49);
    sub_words[5u * row_count + row] = r50;
    unsigned r51 = stwo_m31_mul(r35, r3);
    unsigned r52 = stwo_m31_add(r51, r4);
    unsigned r53 = stwo_m31_add(r52, r5);
    lookup_words[5u * row_count + row] = r53;
    unsigned r54 = stwo_m31_mul(r45, r5);
    unsigned r55 = stwo_m31_add(r3, r54);
    lookup_words[6u * row_count + row] = r55;
    unsigned r56 = stwo_m31_sub(r25, r7);
    out_cols[3u][row] = r25;
    sub_words[1u * row_count + row] = r25;
    lookup_words[2u * row_count + row] = r25;
    unsigned r57 = stwo_m31_mul(r35, r16);
    out_cols[2u][row] = r16;
    lookup_words[44u * row_count + row] = r16;
    lookup_words[48u * row_count + row] = r16;
    unsigned r58 = stwo_m31_sub(r1, r35);
    out_cols[4u][row] = r35;
    lookup_words[49u * row_count + row] = r1;
    unsigned r59 = stwo_m31_mul(r58, r15);
    unsigned r60 = stwo_m31_add(r57, r59);
    unsigned r61 = stwo_m31_add(r60, r56);
    unsigned r62 = (r61 < table_strides[0u] ? table_bases[0u][r61] : 0u);
    out_cols[7u][row] = r62;
    lookup_words[10u * row_count + row] = r62;
    sub_words[8u * row_count + row] = r62;
    lookup_words[12u * row_count + row] = r62;
    unsigned r63 = stwo_m31_add(r60, r56);
    sub_words[7u * row_count + row] = r63;
    unsigned r64 = stwo_m31_add(r60, r56);
    out_cols[6u][row] = r60;
    lookup_words[9u * row_count + row] = r64;
    unsigned r65 = input_cols[3u][row];
    out_cols[8u][row] = r65;
    lookup_words[50u * row_count + row] = r65;
    unsigned r66 = stwo_m31_add(r14, r2);
    out_cols[0u][row] = r14;
    sub_words[0u * row_count + row] = r14;
    lookup_words[1u * row_count + row] = r14;
    lookup_words[42u * row_count + row] = r14;
    lookup_words[46u * row_count + row] = r66;
    unsigned r67 = stwo_m31_add(r15, r45);
    out_cols[1u][row] = r15;
    out_cols[5u][row] = r45;
    lookup_words[43u * row_count + row] = r15;
    lookup_words[47u * row_count + row] = r67;
}
