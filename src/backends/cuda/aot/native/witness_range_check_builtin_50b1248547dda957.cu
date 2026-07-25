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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_57e09935feaee102(
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
    unsigned r1 = 1u;
    lookup_words[33u * row_count + row] = r1;
    unsigned r2 = 1444891767u;
    lookup_words[0u * row_count + row] = r2;
    unsigned r3 = 1662111297u;
    lookup_words[3u * row_count + row] = r3;
    unsigned r4 = input_cols[2u][row];
    unsigned r5 = input_cols[0u][row];
    unsigned r6 = stwo_m31_add(r5, r4);
    unsigned r7 = (r6 < table_strides[0u] ? table_bases[0u][r6] : 0u);
    unsigned r8 = input_cols[0u][row];
    unsigned r9 = stwo_m31_add(r8, r4);
    sub_words[0u * row_count + row] = r9;
    unsigned r10 = input_cols[0u][row];
    unsigned r11 = stwo_m31_add(r10, r4);
    lookup_words[1u * row_count + row] = r11;
    unsigned r12 = stwo_wit_deduce_limb(table_bases, table_strides, r7, 0u);
    out_cols[1u][row] = r12;
    lookup_words[5u * row_count + row] = r12;
    unsigned r13 = stwo_wit_deduce_limb(table_bases, table_strides, r7, 1u);
    out_cols[2u][row] = r13;
    lookup_words[6u * row_count + row] = r13;
    unsigned r14 = stwo_wit_deduce_limb(table_bases, table_strides, r7, 2u);
    out_cols[3u][row] = r14;
    lookup_words[7u * row_count + row] = r14;
    unsigned r15 = stwo_wit_deduce_limb(table_bases, table_strides, r7, 3u);
    out_cols[4u][row] = r15;
    lookup_words[8u * row_count + row] = r15;
    unsigned r16 = stwo_wit_deduce_limb(table_bases, table_strides, r7, 4u);
    out_cols[5u][row] = r16;
    lookup_words[9u * row_count + row] = r16;
    unsigned r17 = stwo_wit_deduce_limb(table_bases, table_strides, r7, 5u);
    out_cols[6u][row] = r17;
    lookup_words[10u * row_count + row] = r17;
    unsigned r18 = stwo_wit_deduce_limb(table_bases, table_strides, r7, 6u);
    out_cols[7u][row] = r18;
    lookup_words[11u * row_count + row] = r18;
    unsigned r19 = stwo_wit_deduce_limb(table_bases, table_strides, r7, 7u);
    out_cols[8u][row] = r19;
    lookup_words[12u * row_count + row] = r19;
    unsigned r20 = stwo_wit_deduce_limb(table_bases, table_strides, r7, 8u);
    out_cols[9u][row] = r20;
    lookup_words[13u * row_count + row] = r20;
    unsigned r21 = stwo_wit_deduce_limb(table_bases, table_strides, r7, 9u);
    out_cols[10u][row] = r21;
    lookup_words[14u * row_count + row] = r21;
    unsigned r22 = stwo_wit_deduce_limb(table_bases, table_strides, r7, 10u);
    out_cols[11u][row] = r22;
    lookup_words[15u * row_count + row] = r22;
    unsigned r23 = stwo_wit_deduce_limb(table_bases, table_strides, r7, 11u);
    out_cols[12u][row] = r23;
    lookup_words[16u * row_count + row] = r23;
    unsigned r24 = stwo_wit_deduce_limb(table_bases, table_strides, r7, 12u);
    out_cols[13u][row] = r24;
    lookup_words[17u * row_count + row] = r24;
    unsigned r25 = stwo_wit_deduce_limb(table_bases, table_strides, r7, 13u);
    out_cols[14u][row] = r25;
    lookup_words[18u * row_count + row] = r25;
    unsigned r26 = stwo_wit_deduce_limb(table_bases, table_strides, r7, 14u);
    out_cols[0u][row] = r7;
    lookup_words[2u * row_count + row] = r7;
    sub_words[1u * row_count + row] = r7;
    lookup_words[4u * row_count + row] = r7;
    unsigned r27 = (r26 & 0xFFFFu);
    out_cols[15u][row] = r26;
    lookup_words[19u * row_count + row] = r26;
    unsigned r28 = (r27 & 2u);
    unsigned r29 = ((r28 & 0xFFFFu) >> 1u);
    unsigned r30 = (r29 % STWO_M31_P);
    out_cols[16u][row] = r30;
}
