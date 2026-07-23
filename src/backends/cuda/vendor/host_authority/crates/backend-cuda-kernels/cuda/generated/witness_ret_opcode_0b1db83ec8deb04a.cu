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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_a290ddc144ee416a(
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
    unsigned r3 = 88u;
    sub_words[4u * row_count + row] = r3;
    lookup_words[5u * row_count + row] = r3;
    unsigned r4 = 130u;
    sub_words[5u * row_count + row] = r4;
    lookup_words[6u * row_count + row] = r4;
    unsigned r5 = 512u;
    unsigned r6 = 32766u;
    sub_words[1u * row_count + row] = r6;
    lookup_words[2u * row_count + row] = r6;
    unsigned r7 = 32767u;
    sub_words[2u * row_count + row] = r7;
    sub_words[3u * row_count + row] = r7;
    lookup_words[3u * row_count + row] = r7;
    lookup_words[4u * row_count + row] = r7;
    unsigned r8 = 262144u;
    unsigned r9 = 134217728u;
    unsigned r10 = 428564188u;
    lookup_words[74u * row_count + row] = r10;
    lookup_words[78u * row_count + row] = r10;
    unsigned r11 = 1444891767u;
    lookup_words[8u * row_count + row] = r11;
    lookup_words[41u * row_count + row] = r11;
    unsigned r12 = 1662111297u;
    lookup_words[11u * row_count + row] = r12;
    lookup_words[44u * row_count + row] = r12;
    unsigned r13 = 1719106205u;
    lookup_words[0u * row_count + row] = r13;
    unsigned r14 = 2147483645u;
    unsigned r15 = 2147483646u;
    unsigned r16 = input_cols[0u][row];
    unsigned r17 = input_cols[1u][row];
    out_cols[1u][row] = r17;
    lookup_words[76u * row_count + row] = r17;
    lookup_words[80u * row_count + row] = r17;
    unsigned r18 = input_cols[2u][row];
    unsigned r19 = (r16 < table_strides[0u] ? table_bases[0u][r16] : 0u);
    out_cols[0u][row] = r16;
    sub_words[0u * row_count + row] = r16;
    lookup_words[1u * row_count + row] = r16;
    lookup_words[75u * row_count + row] = r16;
    unsigned r20 = stwo_m31_sub(r18, r1);
    unsigned r21 = (r20 < table_strides[0u] ? table_bases[0u][r20] : 0u);
    unsigned r22 = stwo_m31_sub(r18, r1);
    sub_words[7u * row_count + row] = r22;
    unsigned r23 = stwo_m31_sub(r18, r1);
    lookup_words[9u * row_count + row] = r23;
    lookup_words[82u * row_count + row] = r1;
    unsigned r24 = stwo_wit_deduce_limb(table_bases, table_strides, r21, 0u);
    unsigned r25 = stwo_wit_deduce_limb(table_bases, table_strides, r21, 1u);
    unsigned r26 = stwo_wit_deduce_limb(table_bases, table_strides, r21, 2u);
    unsigned r27 = stwo_wit_deduce_limb(table_bases, table_strides, r21, 3u);
    out_cols[3u][row] = r21;
    lookup_words[10u * row_count + row] = r21;
    sub_words[9u * row_count + row] = r21;
    lookup_words[12u * row_count + row] = r21;
    unsigned r28 = (r27 & 0xFFFFu);
    unsigned r29 = (r28 & 2u);
    unsigned r30 = ((r29 & 0xFFFFu) >> 1u);
    unsigned r31 = (r30 % STWO_M31_P);
    out_cols[8u][row] = r31;
    unsigned r32 = stwo_m31_sub(r18, r2);
    unsigned r33 = (r32 < table_strides[0u] ? table_bases[0u][r32] : 0u);
    unsigned r34 = stwo_m31_sub(r18, r2);
    sub_words[8u * row_count + row] = r34;
    unsigned r35 = stwo_m31_sub(r18, r2);
    out_cols[2u][row] = r18;
    lookup_words[42u * row_count + row] = r35;
    lookup_words[77u * row_count + row] = r18;
    unsigned r36 = stwo_wit_deduce_limb(table_bases, table_strides, r33, 0u);
    unsigned r37 = stwo_wit_deduce_limb(table_bases, table_strides, r33, 1u);
    unsigned r38 = stwo_wit_deduce_limb(table_bases, table_strides, r33, 2u);
    unsigned r39 = stwo_wit_deduce_limb(table_bases, table_strides, r33, 3u);
    out_cols[9u][row] = r33;
    lookup_words[43u * row_count + row] = r33;
    sub_words[10u * row_count + row] = r33;
    lookup_words[45u * row_count + row] = r33;
    unsigned r40 = (r39 & 0xFFFFu);
    unsigned r41 = (r40 & 2u);
    unsigned r42 = ((r41 & 0xFFFFu) >> 1u);
    unsigned r43 = (r42 % STWO_M31_P);
    out_cols[14u][row] = r43;
    unsigned r44 = input_cols[3u][row];
    out_cols[15u][row] = r44;
    lookup_words[83u * row_count + row] = r44;
    unsigned r45 = stwo_m31_mul(r25, r5);
    out_cols[5u][row] = r25;
    lookup_words[14u * row_count + row] = r25;
    unsigned r46 = stwo_m31_add(r24, r45);
    out_cols[4u][row] = r24;
    lookup_words[13u * row_count + row] = r24;
    unsigned r47 = stwo_m31_mul(r26, r8);
    out_cols[6u][row] = r26;
    lookup_words[15u * row_count + row] = r26;
    unsigned r48 = stwo_m31_add(r46, r47);
    unsigned r49 = stwo_m31_mul(r27, r9);
    out_cols[7u][row] = r27;
    lookup_words[16u * row_count + row] = r27;
    unsigned r50 = stwo_m31_add(r48, r49);
    lookup_words[79u * row_count + row] = r50;
    unsigned r51 = stwo_m31_mul(r37, r5);
    out_cols[11u][row] = r37;
    lookup_words[47u * row_count + row] = r37;
    unsigned r52 = stwo_m31_add(r36, r51);
    out_cols[10u][row] = r36;
    lookup_words[46u * row_count + row] = r36;
    unsigned r53 = stwo_m31_mul(r38, r8);
    out_cols[12u][row] = r38;
    lookup_words[48u * row_count + row] = r38;
    unsigned r54 = stwo_m31_add(r52, r53);
    unsigned r55 = stwo_m31_mul(r39, r9);
    out_cols[13u][row] = r39;
    lookup_words[49u * row_count + row] = r39;
    unsigned r56 = stwo_m31_add(r54, r55);
    lookup_words[81u * row_count + row] = r56;
}
