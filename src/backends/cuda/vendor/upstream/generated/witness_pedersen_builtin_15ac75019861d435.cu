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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_da729390f0d884f9(
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

    unsigned r0 = 1u;
    unsigned r1 = 2u;
    unsigned r2 = 3u;
    unsigned r3 = 520578465u;
    lookup_words[9u * row_count + row] = r3;
    unsigned r4 = 1444891767u;
    lookup_words[0u * row_count + row] = r4;
    lookup_words[3u * row_count + row] = r4;
    lookup_words[6u * row_count + row] = r4;
    unsigned r5 = input_cols[2u][row];
    unsigned r6 = stwo_m31_mul(r5, r2);
    unsigned r7 = input_cols[0u][row];
    unsigned r8 = stwo_m31_add(r6, r7);
    unsigned r9 = (r8 < table_strides[0u] ? table_bases[0u][r8] : 0u);
    out_cols[0u][row] = r9;
    lookup_words[2u * row_count + row] = r9;
    sub_words[3u * row_count + row] = r9;
    lookup_words[10u * row_count + row] = r9;
    unsigned r10 = stwo_m31_add(r8, r0);
    unsigned r11 = (r10 < table_strides[0u] ? table_bases[0u][r10] : 0u);
    out_cols[1u][row] = r11;
    lookup_words[5u * row_count + row] = r11;
    sub_words[4u * row_count + row] = r11;
    lookup_words[11u * row_count + row] = r11;
    unsigned r12 = stwo_m31_add(r8, r0);
    sub_words[1u * row_count + row] = r12;
    unsigned r13 = stwo_m31_add(r8, r0);
    lookup_words[4u * row_count + row] = r13;
    lookup_words[13u * row_count + row] = r0;
    unsigned r14 = stwo_m31_add(r8, r1);
    unsigned r15 = (r14 < table_strides[0u] ? table_bases[0u][r14] : 0u);
    out_cols[2u][row] = r15;
    lookup_words[8u * row_count + row] = r15;
    sub_words[5u * row_count + row] = r15;
    lookup_words[12u * row_count + row] = r15;
    unsigned r16 = stwo_m31_add(r8, r1);
    sub_words[2u * row_count + row] = r16;
    unsigned r17 = stwo_m31_add(r8, r1);
    sub_words[0u * row_count + row] = r8;
    lookup_words[1u * row_count + row] = r8;
    lookup_words[7u * row_count + row] = r17;
}
