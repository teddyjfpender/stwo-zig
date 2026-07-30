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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_ad984cdbe607f973(
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
    lookup_words[44u * row_count + row] = r0;
    unsigned r1 = 262144u;
    unsigned r2 = 4194304u;
    unsigned r3 = 517791011u;
    lookup_words[0u * row_count + row] = r3;
    unsigned r4 = 1090315331u;
    lookup_words[33u * row_count + row] = r4;
    unsigned r5 = 1109051422u;
    lookup_words[3u * row_count + row] = r5;
    lookup_words[5u * row_count + row] = r5;
    lookup_words[12u * row_count + row] = r5;
    lookup_words[17u * row_count + row] = r5;
    lookup_words[19u * row_count + row] = r5;
    lookup_words[26u * row_count + row] = r5;
    lookup_words[31u * row_count + row] = r5;
    unsigned r6 = 1424798916u;
    lookup_words[10u * row_count + row] = r6;
    lookup_words[24u * row_count + row] = r6;
    unsigned r7 = 1847459238u;
    lookup_words[28u * row_count + row] = r7;
    unsigned r8 = 1864236857u;
    lookup_words[21u * row_count + row] = r8;
    unsigned r9 = 1881014476u;
    lookup_words[14u * row_count + row] = r9;
    unsigned r10 = 1897792095u;
    lookup_words[7u * row_count + row] = r10;
    unsigned r11 = input_cols[0u][row];
    unsigned r12 = input_cols[1u][row];
    unsigned r13 = input_cols[2u][row];
    unsigned r14 = input_cols[3u][row];
    unsigned r15 = input_cols[4u][row];
    unsigned r16 = input_cols[5u][row];
    unsigned r17 = input_cols[6u][row];
    unsigned r18 = input_cols[7u][row];
    unsigned r19 = input_cols[8u][row];
    unsigned r20 = input_cols[9u][row];
    unsigned r21 = input_cols[0u][row];
    unsigned r22 = input_cols[1u][row];
    unsigned r23 = input_cols[2u][row];
    unsigned r24 = input_cols[3u][row];
    unsigned r25 = input_cols[4u][row];
    unsigned r26 = input_cols[5u][row];
    unsigned r27 = input_cols[6u][row];
    unsigned r28 = input_cols[7u][row];
    unsigned r29 = input_cols[8u][row];
    unsigned r30 = input_cols[9u][row];
    unsigned r31 = input_cols[0u][row];
    unsigned r32 = input_cols[1u][row];
    unsigned r33 = input_cols[2u][row];
    unsigned r34 = input_cols[3u][row];
    unsigned r35 = input_cols[4u][row];
    unsigned r36 = input_cols[5u][row];
    unsigned r37 = input_cols[6u][row];
    unsigned r38 = input_cols[7u][row];
    unsigned r39 = input_cols[8u][row];
    unsigned r40 = input_cols[9u][row];
    unsigned r41 = input_cols[0u][row];
    unsigned r42 = input_cols[1u][row];
    unsigned r43 = input_cols[2u][row];
    unsigned r44 = input_cols[3u][row];
    unsigned r45 = input_cols[4u][row];
    unsigned r46 = input_cols[5u][row];
    unsigned r47 = input_cols[6u][row];
    unsigned r48 = input_cols[7u][row];
    unsigned r49 = input_cols[8u][row];
    unsigned r50 = input_cols[9u][row];
    unsigned r51 = input_cols[0u][row];
    unsigned r52 = input_cols[1u][row];
    unsigned r53 = input_cols[2u][row];
    unsigned r54 = input_cols[3u][row];
    unsigned r55 = input_cols[4u][row];
    unsigned r56 = input_cols[5u][row];
    unsigned r57 = input_cols[6u][row];
    unsigned r58 = input_cols[7u][row];
    unsigned r59 = input_cols[8u][row];
    unsigned r60 = input_cols[9u][row];
    unsigned r61 = input_cols[0u][row];
    unsigned r62 = input_cols[1u][row];
    unsigned r63 = input_cols[2u][row];
    unsigned r64 = input_cols[3u][row];
    unsigned r65 = input_cols[4u][row];
    unsigned r66 = input_cols[5u][row];
    unsigned r67 = input_cols[6u][row];
    unsigned r68 = input_cols[7u][row];
    unsigned r69 = input_cols[8u][row];
    unsigned r70 = input_cols[9u][row];
    unsigned r71 = input_cols[0u][row];
    unsigned r72 = input_cols[1u][row];
    unsigned r73 = input_cols[2u][row];
    unsigned r74 = input_cols[3u][row];
    unsigned r75 = input_cols[4u][row];
    unsigned r76 = input_cols[5u][row];
    unsigned r77 = input_cols[6u][row];
    unsigned r78 = input_cols[7u][row];
    unsigned r79 = input_cols[8u][row];
    unsigned r80 = input_cols[9u][row];
    unsigned r81 = input_cols[0u][row];
    unsigned r82 = input_cols[1u][row];
    unsigned r83 = input_cols[2u][row];
    unsigned r84 = input_cols[3u][row];
    unsigned r85 = input_cols[4u][row];
    unsigned r86 = input_cols[5u][row];
    unsigned r87 = input_cols[6u][row];
    unsigned r88 = input_cols[7u][row];
    unsigned r89 = input_cols[8u][row];
    unsigned r90 = input_cols[9u][row];
    unsigned r91 = input_cols[0u][row];
    unsigned r92 = input_cols[1u][row];
    unsigned r93 = input_cols[2u][row];
    unsigned r94 = input_cols[3u][row];
    unsigned r95 = input_cols[4u][row];
    unsigned r96 = input_cols[5u][row];
    unsigned r97 = input_cols[6u][row];
    unsigned r98 = input_cols[7u][row];
    unsigned r99 = input_cols[8u][row];
    unsigned r100 = input_cols[9u][row];
    unsigned r101 = input_cols[0u][row];
    unsigned r102 = input_cols[1u][row];
    unsigned r103 = input_cols[2u][row];
    unsigned r104 = input_cols[3u][row];
    unsigned r105 = input_cols[4u][row];
    unsigned r106 = input_cols[5u][row];
    unsigned r107 = input_cols[6u][row];
    unsigned r108 = input_cols[7u][row];
    unsigned r109 = input_cols[8u][row];
    unsigned r110 = input_cols[9u][row];
    out_cols[9u][row] = r110;
    sub_words[18u * row_count + row] = r110;
    lookup_words[30u * row_count + row] = r110;
    lookup_words[43u * row_count + row] = r110;
    unsigned r111 = input_cols[0u][row];
    unsigned r112 = input_cols[1u][row];
    unsigned r113 = input_cols[2u][row];
    unsigned r114 = input_cols[3u][row];
    unsigned r115 = input_cols[4u][row];
    unsigned r116 = input_cols[5u][row];
    unsigned r117 = input_cols[6u][row];
    unsigned r118 = input_cols[7u][row];
    unsigned r119 = input_cols[8u][row];
    unsigned r120 = input_cols[9u][row];
    unsigned r121 = (r111 & 511u);
    unsigned r122 = (r111 >> 9u);
    unsigned r123 = (r122 & 511u);
    unsigned r124 = (r111 >> 18u);
    unsigned r125 = (r124 & 511u);
    unsigned r126 = (r112 & 511u);
    unsigned r127 = (r112 >> 9u);
    unsigned r128 = (r127 & 511u);
    unsigned r129 = (r112 >> 18u);
    unsigned r130 = (r129 & 511u);
    unsigned r131 = (r113 & 511u);
    unsigned r132 = (r113 >> 9u);
    unsigned r133 = (r132 & 511u);
    unsigned r134 = (r113 >> 18u);
    unsigned r135 = (r134 & 511u);
    unsigned r136 = (r114 & 511u);
    unsigned r137 = (r114 >> 9u);
    unsigned r138 = (r137 & 511u);
    unsigned r139 = (r114 >> 18u);
    unsigned r140 = (r139 & 511u);
    unsigned r141 = (r115 & 511u);
    unsigned r142 = (r115 >> 9u);
    unsigned r143 = (r142 & 511u);
    unsigned r144 = (r115 >> 18u);
    unsigned r145 = (r144 & 511u);
    unsigned r146 = (r116 & 511u);
    unsigned r147 = (r116 >> 9u);
    unsigned r148 = (r147 & 511u);
    unsigned r149 = (r116 >> 18u);
    unsigned r150 = (r149 & 511u);
    unsigned r151 = (r117 & 511u);
    unsigned r152 = (r117 >> 9u);
    unsigned r153 = (r152 & 511u);
    unsigned r154 = (r117 >> 18u);
    unsigned r155 = (r154 & 511u);
    unsigned r156 = (r118 & 511u);
    unsigned r157 = (r118 >> 9u);
    unsigned r158 = (r157 & 511u);
    unsigned r159 = (r118 >> 18u);
    unsigned r160 = (r159 & 511u);
    unsigned r161 = (r119 & 511u);
    unsigned r162 = (r119 >> 9u);
    unsigned r163 = (r162 & 511u);
    unsigned r164 = (r119 >> 18u);
    unsigned r165 = (r164 & 511u);
    unsigned r166 = (r120 & 511u);
    unsigned r167 = stwo_m31_mul(r125, r1);
    unsigned r168 = stwo_m31_sub(r11, r167);
    sub_words[2u * row_count + row] = r168;
    unsigned r169 = stwo_m31_mul(r125, r1);
    out_cols[10u][row] = r125;
    sub_words[0u * row_count + row] = r125;
    lookup_words[1u * row_count + row] = r125;
    unsigned r170 = stwo_m31_sub(r11, r169);
    out_cols[0u][row] = r11;
    lookup_words[4u * row_count + row] = r170;
    lookup_words[34u * row_count + row] = r11;
    unsigned r171 = stwo_m31_sub(r22, r126);
    unsigned r172 = stwo_m31_mul(r171, r2);
    sub_words[3u * row_count + row] = r172;
    unsigned r173 = stwo_m31_sub(r22, r126);
    out_cols[1u][row] = r22;
    out_cols[11u][row] = r126;
    sub_words[1u * row_count + row] = r126;
    lookup_words[2u * row_count + row] = r126;
    lookup_words[35u * row_count + row] = r22;
    unsigned r174 = stwo_m31_mul(r173, r2);
    lookup_words[6u * row_count + row] = r174;
    unsigned r175 = stwo_m31_mul(r135, r1);
    unsigned r176 = stwo_m31_sub(r33, r175);
    sub_words[11u * row_count + row] = r176;
    unsigned r177 = stwo_m31_mul(r135, r1);
    out_cols[12u][row] = r135;
    sub_words[9u * row_count + row] = r135;
    lookup_words[8u * row_count + row] = r135;
    unsigned r178 = stwo_m31_sub(r33, r177);
    out_cols[2u][row] = r33;
    lookup_words[11u * row_count + row] = r178;
    lookup_words[36u * row_count + row] = r33;
    unsigned r179 = stwo_m31_sub(r44, r136);
    unsigned r180 = stwo_m31_mul(r179, r2);
    sub_words[4u * row_count + row] = r180;
    unsigned r181 = stwo_m31_sub(r44, r136);
    out_cols[3u][row] = r44;
    out_cols[13u][row] = r136;
    sub_words[10u * row_count + row] = r136;
    lookup_words[9u * row_count + row] = r136;
    lookup_words[37u * row_count + row] = r44;
    unsigned r182 = stwo_m31_mul(r181, r2);
    lookup_words[13u * row_count + row] = r182;
    unsigned r183 = stwo_m31_mul(r145, r1);
    unsigned r184 = stwo_m31_sub(r55, r183);
    sub_words[5u * row_count + row] = r184;
    unsigned r185 = stwo_m31_mul(r145, r1);
    out_cols[14u][row] = r145;
    sub_words[13u * row_count + row] = r145;
    lookup_words[15u * row_count + row] = r145;
    unsigned r186 = stwo_m31_sub(r55, r185);
    out_cols[4u][row] = r55;
    lookup_words[18u * row_count + row] = r186;
    lookup_words[38u * row_count + row] = r55;
    unsigned r187 = stwo_m31_sub(r66, r146);
    unsigned r188 = stwo_m31_mul(r187, r2);
    sub_words[6u * row_count + row] = r188;
    unsigned r189 = stwo_m31_sub(r66, r146);
    out_cols[5u][row] = r66;
    out_cols[15u][row] = r146;
    sub_words[14u * row_count + row] = r146;
    lookup_words[16u * row_count + row] = r146;
    lookup_words[39u * row_count + row] = r66;
    unsigned r190 = stwo_m31_mul(r189, r2);
    lookup_words[20u * row_count + row] = r190;
    unsigned r191 = stwo_m31_mul(r155, r1);
    unsigned r192 = stwo_m31_sub(r77, r191);
    sub_words[12u * row_count + row] = r192;
    unsigned r193 = stwo_m31_mul(r155, r1);
    out_cols[16u][row] = r155;
    sub_words[15u * row_count + row] = r155;
    lookup_words[22u * row_count + row] = r155;
    unsigned r194 = stwo_m31_sub(r77, r193);
    out_cols[6u][row] = r77;
    lookup_words[25u * row_count + row] = r194;
    lookup_words[40u * row_count + row] = r77;
    unsigned r195 = stwo_m31_sub(r88, r156);
    unsigned r196 = stwo_m31_mul(r195, r2);
    sub_words[7u * row_count + row] = r196;
    unsigned r197 = stwo_m31_sub(r88, r156);
    out_cols[7u][row] = r88;
    out_cols[17u][row] = r156;
    sub_words[16u * row_count + row] = r156;
    lookup_words[23u * row_count + row] = r156;
    lookup_words[41u * row_count + row] = r88;
    unsigned r198 = stwo_m31_mul(r197, r2);
    lookup_words[27u * row_count + row] = r198;
    unsigned r199 = stwo_m31_mul(r165, r1);
    unsigned r200 = stwo_m31_sub(r99, r199);
    sub_words[8u * row_count + row] = r200;
    unsigned r201 = stwo_m31_mul(r165, r1);
    out_cols[18u][row] = r165;
    sub_words[17u * row_count + row] = r165;
    lookup_words[29u * row_count + row] = r165;
    unsigned r202 = stwo_m31_sub(r99, r201);
    out_cols[8u][row] = r99;
    lookup_words[32u * row_count + row] = r202;
    lookup_words[42u * row_count + row] = r99;
    unsigned r203 = input_cols[10u][row];
    out_cols[19u][row] = r203;
    lookup_words[45u * row_count + row] = r203;
}
