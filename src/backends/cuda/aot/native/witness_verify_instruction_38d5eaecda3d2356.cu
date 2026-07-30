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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_17255b30022f129d(
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
    unsigned r1 = 1u;
    lookup_words[48u * row_count + row] = r1;
    unsigned r2 = 32u;
    unsigned r3 = 128u;
    unsigned r4 = 371240602u;
    lookup_words[0u * row_count + row] = r4;
    unsigned r5 = 1444891767u;
    lookup_words[7u * row_count + row] = r5;
    unsigned r6 = 1567323731u;
    lookup_words[4u * row_count + row] = r6;
    unsigned r7 = 1662111297u;
    lookup_words[10u * row_count + row] = r7;
    unsigned r8 = 1719106205u;
    lookup_words[40u * row_count + row] = r8;
    unsigned r9 = input_cols[0u][row];
    unsigned r10 = input_cols[1u][row];
    unsigned r11 = input_cols[2u][row];
    unsigned r12 = input_cols[3u][row];
    unsigned r13 = input_cols[4u][row];
    unsigned r14 = input_cols[5u][row];
    out_cols[5u][row] = r14;
    lookup_words[18u * row_count + row] = r14;
    lookup_words[46u * row_count + row] = r14;
    unsigned r15 = input_cols[6u][row];
    out_cols[6u][row] = r15;
    lookup_words[19u * row_count + row] = r15;
    lookup_words[47u * row_count + row] = r15;
    unsigned r16 = (r10 & 0xFFFFu);
    unsigned r17 = (r16 & 511u);
    unsigned r18 = (r17 % STWO_M31_P);
    out_cols[7u][row] = r18;
    lookup_words[12u * row_count + row] = r18;
    unsigned r19 = (r10 & 0xFFFFu);
    out_cols[1u][row] = r10;
    lookup_words[42u * row_count + row] = r10;
    unsigned r20 = ((r19 & 0xFFFFu) >> 9u);
    unsigned r21 = (r20 % STWO_M31_P);
    unsigned r22 = (r11 & 0xFFFFu);
    unsigned r23 = (r22 & 3u);
    unsigned r24 = (r23 % STWO_M31_P);
    unsigned r25 = (r11 & 0xFFFFu);
    unsigned r26 = ((r25 & 0xFFFFu) >> 2u);
    unsigned r27 = (r26 & 511u);
    unsigned r28 = (r27 % STWO_M31_P);
    out_cols[10u][row] = r28;
    lookup_words[14u * row_count + row] = r28;
    unsigned r29 = (r11 & 0xFFFFu);
    out_cols[2u][row] = r11;
    lookup_words[43u * row_count + row] = r11;
    unsigned r30 = ((r29 & 0xFFFFu) >> 11u);
    unsigned r31 = (r30 % STWO_M31_P);
    unsigned r32 = (r12 & 0xFFFFu);
    unsigned r33 = (r32 & 15u);
    unsigned r34 = (r33 % STWO_M31_P);
    unsigned r35 = (r12 & 0xFFFFu);
    unsigned r36 = ((r35 & 0xFFFFu) >> 4u);
    unsigned r37 = (r36 & 511u);
    unsigned r38 = (r37 % STWO_M31_P);
    out_cols[13u][row] = r38;
    lookup_words[16u * row_count + row] = r38;
    unsigned r39 = (r12 & 0xFFFFu);
    out_cols[3u][row] = r12;
    lookup_words[44u * row_count + row] = r12;
    unsigned r40 = ((r39 & 0xFFFFu) >> 13u);
    unsigned r41 = (r40 % STWO_M31_P);
    unsigned r42 = stwo_m31_mul(r24, r3);
    out_cols[9u][row] = r24;
    sub_words[1u * row_count + row] = r24;
    lookup_words[2u * row_count + row] = r24;
    unsigned r43 = stwo_m31_add(r21, r42);
    out_cols[8u][row] = r21;
    sub_words[0u * row_count + row] = r21;
    lookup_words[1u * row_count + row] = r21;
    lookup_words[13u * row_count + row] = r43;
    unsigned r44 = stwo_m31_mul(r34, r2);
    out_cols[12u][row] = r34;
    sub_words[3u * row_count + row] = r34;
    lookup_words[5u * row_count + row] = r34;
    unsigned r45 = stwo_m31_add(r31, r44);
    out_cols[11u][row] = r31;
    sub_words[2u * row_count + row] = r31;
    lookup_words[3u * row_count + row] = r31;
    lookup_words[15u * row_count + row] = r45;
    unsigned r46 = (r9 < table_strides[0u] ? table_bases[0u][r9] : 0u);
    out_cols[0u][row] = r9;
    out_cols[15u][row] = r46;
    sub_words[5u * row_count + row] = r9;
    lookup_words[8u * row_count + row] = r9;
    lookup_words[9u * row_count + row] = r46;
    sub_words[6u * row_count + row] = r46;
    lookup_words[11u * row_count + row] = r46;
    lookup_words[41u * row_count + row] = r9;
    unsigned r47 = stwo_m31_add(r41, r13);
    out_cols[4u][row] = r13;
    out_cols[14u][row] = r41;
    sub_words[4u * row_count + row] = r41;
    lookup_words[6u * row_count + row] = r41;
    lookup_words[17u * row_count + row] = r47;
    lookup_words[45u * row_count + row] = r13;
    unsigned r48 = input_cols[9u][row];
    out_cols[16u][row] = r48;
    lookup_words[49u * row_count + row] = r48;
}
