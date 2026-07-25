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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_d467876d34b895c1(
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
    unsigned r2 = 8u;
    unsigned r3 = 16u;
    unsigned r4 = 32u;
    unsigned r5 = 64u;
    unsigned r6 = 128u;
    unsigned r7 = 256u;
    unsigned r8 = 512u;
    unsigned r9 = 8192u;
    unsigned r10 = 32768u;
    unsigned r11 = 428564188u;
    lookup_words[113u * row_count + row] = r11;
    lookup_words[117u * row_count + row] = r11;
    unsigned r12 = 991608089u;
    lookup_words[107u * row_count + row] = r12;
    lookup_words[109u * row_count + row] = r12;
    lookup_words[111u * row_count + row] = r12;
    unsigned r13 = 1444891767u;
    lookup_words[8u * row_count + row] = r13;
    lookup_words[41u * row_count + row] = r13;
    lookup_words[74u * row_count + row] = r13;
    unsigned r14 = 1662111297u;
    lookup_words[11u * row_count + row] = r14;
    lookup_words[44u * row_count + row] = r14;
    lookup_words[77u * row_count + row] = r14;
    unsigned r15 = 1719106205u;
    lookup_words[0u * row_count + row] = r15;
    unsigned r16 = input_cols[0u][row];
    unsigned r17 = input_cols[1u][row];
    unsigned r18 = input_cols[2u][row];
    unsigned r19 = (r16 < table_strides[0u] ? table_bases[0u][r16] : 0u);
    unsigned r20 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 0u);
    unsigned r21 = (r20 & 0xFFFFu);
    unsigned r22 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 1u);
    unsigned r23 = (r22 & 0xFFFFu);
    unsigned r24 = (r23 & 127u);
    unsigned r25 = ((r24 << 9u) & 0xFFFFu);
    unsigned r26 = ((r21 + r25) & 0xFFFFu);
    unsigned r27 = (r26 % STWO_M31_P);
    unsigned r28 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 1u);
    unsigned r29 = (r28 & 0xFFFFu);
    unsigned r30 = ((r29 & 0xFFFFu) >> 7u);
    unsigned r31 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 2u);
    unsigned r32 = (r31 & 0xFFFFu);
    unsigned r33 = ((r32 << 2u) & 0xFFFFu);
    unsigned r34 = ((r30 + r33) & 0xFFFFu);
    unsigned r35 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 3u);
    unsigned r36 = (r35 & 0xFFFFu);
    unsigned r37 = (r36 & 31u);
    unsigned r38 = ((r37 << 11u) & 0xFFFFu);
    unsigned r39 = ((r34 + r38) & 0xFFFFu);
    unsigned r40 = (r39 % STWO_M31_P);
    unsigned r41 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 3u);
    unsigned r42 = (r41 & 0xFFFFu);
    unsigned r43 = ((r42 & 0xFFFFu) >> 5u);
    unsigned r44 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 4u);
    unsigned r45 = (r44 & 0xFFFFu);
    unsigned r46 = ((r45 << 4u) & 0xFFFFu);
    unsigned r47 = ((r43 + r46) & 0xFFFFu);
    unsigned r48 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 5u);
    unsigned r49 = (r48 & 0xFFFFu);
    unsigned r50 = (r49 & 7u);
    unsigned r51 = ((r50 << 13u) & 0xFFFFu);
    unsigned r52 = ((r47 + r51) & 0xFFFFu);
    unsigned r53 = (r52 % STWO_M31_P);
    unsigned r54 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 5u);
    unsigned r55 = (r54 & 0xFFFFu);
    unsigned r56 = ((r55 & 0xFFFFu) >> 3u);
    unsigned r57 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 6u);
    unsigned r58 = (r57 & 0xFFFFu);
    unsigned r59 = ((r58 << 6u) & 0xFFFFu);
    unsigned r60 = ((r56 + r59) & 0xFFFFu);
    unsigned r61 = ((r60 & 0xFFFFu) >> 0u);
    unsigned r62 = (r61 & 1u);
    unsigned r63 = (r62 % STWO_M31_P);
    unsigned r64 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 5u);
    unsigned r65 = (r64 & 0xFFFFu);
    unsigned r66 = ((r65 & 0xFFFFu) >> 3u);
    unsigned r67 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 6u);
    unsigned r68 = (r67 & 0xFFFFu);
    unsigned r69 = ((r68 << 6u) & 0xFFFFu);
    unsigned r70 = ((r66 + r69) & 0xFFFFu);
    unsigned r71 = ((r70 & 0xFFFFu) >> 1u);
    unsigned r72 = (r71 & 1u);
    unsigned r73 = (r72 % STWO_M31_P);
    unsigned r74 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 5u);
    unsigned r75 = (r74 & 0xFFFFu);
    unsigned r76 = ((r75 & 0xFFFFu) >> 3u);
    unsigned r77 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 6u);
    unsigned r78 = (r77 & 0xFFFFu);
    unsigned r79 = ((r78 << 6u) & 0xFFFFu);
    unsigned r80 = ((r76 + r79) & 0xFFFFu);
    unsigned r81 = ((r80 & 0xFFFFu) >> 2u);
    unsigned r82 = (r81 & 1u);
    unsigned r83 = (r82 % STWO_M31_P);
    unsigned r84 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 5u);
    unsigned r85 = (r84 & 0xFFFFu);
    unsigned r86 = ((r85 & 0xFFFFu) >> 3u);
    unsigned r87 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 6u);
    unsigned r88 = (r87 & 0xFFFFu);
    unsigned r89 = ((r88 << 6u) & 0xFFFFu);
    unsigned r90 = ((r86 + r89) & 0xFFFFu);
    unsigned r91 = ((r90 & 0xFFFFu) >> 3u);
    unsigned r92 = (r91 & 1u);
    unsigned r93 = (r92 % STWO_M31_P);
    unsigned r94 = stwo_m31_sub(r1, r83);
    unsigned r95 = stwo_m31_sub(r94, r93);
    unsigned r96 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 5u);
    unsigned r97 = (r96 & 0xFFFFu);
    unsigned r98 = ((r97 & 0xFFFFu) >> 3u);
    unsigned r99 = stwo_wit_deduce_limb(table_bases, table_strides, r19, 6u);
    unsigned r100 = (r99 & 0xFFFFu);
    unsigned r101 = ((r100 << 6u) & 0xFFFFu);
    unsigned r102 = ((r98 + r101) & 0xFFFFu);
    unsigned r103 = ((r102 & 0xFFFFu) >> 11u);
    unsigned r104 = (r103 & 1u);
    unsigned r105 = (r104 % STWO_M31_P);
    unsigned r106 = stwo_m31_mul(r63, r2);
    unsigned r107 = stwo_m31_mul(r73, r3);
    unsigned r108 = stwo_m31_add(r106, r107);
    unsigned r109 = stwo_m31_mul(r83, r4);
    unsigned r110 = stwo_m31_add(r108, r109);
    unsigned r111 = stwo_m31_mul(r93, r5);
    unsigned r112 = stwo_m31_add(r110, r111);
    unsigned r113 = stwo_m31_mul(r95, r6);
    unsigned r114 = stwo_m31_add(r112, r113);
    sub_words[4u * row_count + row] = r114;
    unsigned r115 = stwo_m31_mul(r105, r4);
    unsigned r116 = stwo_m31_add(r1, r115);
    unsigned r117 = stwo_m31_add(r116, r7);
    sub_words[5u * row_count + row] = r117;
    unsigned r118 = stwo_m31_mul(r63, r2);
    unsigned r119 = stwo_m31_mul(r73, r3);
    unsigned r120 = stwo_m31_add(r118, r119);
    unsigned r121 = stwo_m31_mul(r83, r4);
    unsigned r122 = stwo_m31_add(r120, r121);
    unsigned r123 = stwo_m31_mul(r93, r5);
    unsigned r124 = stwo_m31_add(r122, r123);
    unsigned r125 = stwo_m31_mul(r95, r6);
    unsigned r126 = stwo_m31_add(r124, r125);
    lookup_words[5u * row_count + row] = r126;
    unsigned r127 = stwo_m31_mul(r105, r4);
    unsigned r128 = stwo_m31_add(r1, r127);
    unsigned r129 = stwo_m31_add(r128, r7);
    lookup_words[6u * row_count + row] = r129;
    unsigned r130 = stwo_m31_sub(r27, r10);
    out_cols[3u][row] = r27;
    sub_words[1u * row_count + row] = r27;
    lookup_words[2u * row_count + row] = r27;
    unsigned r131 = stwo_m31_sub(r40, r10);
    out_cols[4u][row] = r40;
    sub_words[2u * row_count + row] = r40;
    lookup_words[3u * row_count + row] = r40;
    unsigned r132 = stwo_m31_sub(r53, r10);
    out_cols[5u][row] = r53;
    sub_words[3u * row_count + row] = r53;
    lookup_words[4u * row_count + row] = r53;
    unsigned r133 = stwo_m31_mul(r63, r18);
    unsigned r134 = stwo_m31_sub(r1, r63);
    out_cols[6u][row] = r63;
    unsigned r135 = stwo_m31_mul(r134, r17);
    unsigned r136 = stwo_m31_add(r133, r135);
    unsigned r137 = stwo_m31_mul(r73, r18);
    unsigned r138 = stwo_m31_sub(r1, r73);
    out_cols[7u][row] = r73;
    unsigned r139 = stwo_m31_mul(r138, r17);
    unsigned r140 = stwo_m31_add(r137, r139);
    unsigned r141 = stwo_m31_mul(r83, r16);
    unsigned r142 = stwo_m31_mul(r93, r18);
    out_cols[2u][row] = r18;
    out_cols[9u][row] = r93;
    lookup_words[116u * row_count + row] = r18;
    lookup_words[120u * row_count + row] = r18;
    unsigned r143 = stwo_m31_add(r141, r142);
    unsigned r144 = stwo_m31_mul(r95, r17);
    unsigned r145 = stwo_m31_add(r143, r144);
    unsigned r146 = stwo_m31_add(r136, r130);
    unsigned r147 = (r146 < table_strides[0u] ? table_bases[0u][r146] : 0u);
    unsigned r148 = stwo_m31_add(r136, r130);
    sub_words[7u * row_count + row] = r148;
    unsigned r149 = stwo_m31_add(r136, r130);
    out_cols[11u][row] = r136;
    lookup_words[9u * row_count + row] = r149;
    unsigned r150 = stwo_wit_deduce_limb(table_bases, table_strides, r147, 0u);
    unsigned r151 = stwo_wit_deduce_limb(table_bases, table_strides, r147, 1u);
    unsigned r152 = stwo_wit_deduce_limb(table_bases, table_strides, r147, 2u);
    unsigned r153 = stwo_wit_deduce_limb(table_bases, table_strides, r147, 3u);
    unsigned r154 = stwo_wit_deduce_limb(table_bases, table_strides, r147, 4u);
    unsigned r155 = stwo_wit_deduce_limb(table_bases, table_strides, r147, 5u);
    unsigned r156 = stwo_wit_deduce_limb(table_bases, table_strides, r147, 6u);
    out_cols[21u][row] = r156;
    lookup_words[19u * row_count + row] = r156;
    unsigned r157 = stwo_wit_deduce_limb(table_bases, table_strides, r147, 7u);
    out_cols[14u][row] = r147;
    lookup_words[10u * row_count + row] = r147;
    out_cols[22u][row] = r157;
    sub_words[10u * row_count + row] = r147;
    lookup_words[12u * row_count + row] = r147;
    lookup_words[20u * row_count + row] = r157;
    unsigned r158 = stwo_m31_add(r140, r131);
    unsigned r159 = (r158 < table_strides[0u] ? table_bases[0u][r158] : 0u);
    unsigned r160 = stwo_m31_add(r140, r131);
    sub_words[8u * row_count + row] = r160;
    unsigned r161 = stwo_m31_add(r140, r131);
    out_cols[12u][row] = r140;
    lookup_words[42u * row_count + row] = r161;
    unsigned r162 = stwo_wit_deduce_limb(table_bases, table_strides, r159, 0u);
    unsigned r163 = stwo_wit_deduce_limb(table_bases, table_strides, r159, 1u);
    unsigned r164 = stwo_wit_deduce_limb(table_bases, table_strides, r159, 2u);
    unsigned r165 = stwo_wit_deduce_limb(table_bases, table_strides, r159, 3u);
    out_cols[23u][row] = r159;
    lookup_words[43u * row_count + row] = r159;
    sub_words[11u * row_count + row] = r159;
    lookup_words[45u * row_count + row] = r159;
    unsigned r166 = stwo_m31_add(r145, r132);
    unsigned r167 = (r166 < table_strides[0u] ? table_bases[0u][r166] : 0u);
    unsigned r168 = stwo_m31_add(r145, r132);
    sub_words[9u * row_count + row] = r168;
    unsigned r169 = stwo_m31_add(r145, r132);
    out_cols[13u][row] = r145;
    lookup_words[75u * row_count + row] = r169;
    unsigned r170 = stwo_wit_deduce_limb(table_bases, table_strides, r167, 0u);
    unsigned r171 = stwo_wit_deduce_limb(table_bases, table_strides, r167, 1u);
    unsigned r172 = stwo_wit_deduce_limb(table_bases, table_strides, r167, 2u);
    unsigned r173 = stwo_wit_deduce_limb(table_bases, table_strides, r167, 3u);
    out_cols[28u][row] = r167;
    lookup_words[76u * row_count + row] = r167;
    sub_words[12u * row_count + row] = r167;
    lookup_words[78u * row_count + row] = r167;
    unsigned r174 = stwo_m31_mul(r162, r170);
    unsigned r175 = stwo_m31_sub(r174, r150);
    out_cols[15u][row] = r150;
    lookup_words[13u * row_count + row] = r150;
    unsigned r176 = stwo_m31_mul(r162, r171);
    unsigned r177 = stwo_m31_mul(r163, r170);
    unsigned r178 = stwo_m31_add(r176, r177);
    unsigned r179 = stwo_m31_sub(r178, r151);
    out_cols[16u][row] = r151;
    lookup_words[14u * row_count + row] = r151;
    unsigned r180 = stwo_m31_mul(r179, r8);
    unsigned r181 = stwo_m31_add(r175, r180);
    unsigned r182 = stwo_m31_mul(r181, r9);
    unsigned r183 = stwo_m31_mul(r162, r172);
    unsigned r184 = stwo_m31_mul(r163, r171);
    unsigned r185 = stwo_m31_add(r183, r184);
    unsigned r186 = stwo_m31_mul(r164, r170);
    unsigned r187 = stwo_m31_add(r185, r186);
    unsigned r188 = stwo_m31_sub(r187, r152);
    out_cols[17u][row] = r152;
    lookup_words[15u * row_count + row] = r152;
    unsigned r189 = stwo_m31_add(r182, r188);
    out_cols[33u][row] = r182;
    sub_words[13u * row_count + row] = r182;
    lookup_words[108u * row_count + row] = r182;
    unsigned r190 = stwo_m31_mul(r162, r173);
    out_cols[24u][row] = r162;
    lookup_words[46u * row_count + row] = r162;
    unsigned r191 = stwo_m31_mul(r163, r172);
    unsigned r192 = stwo_m31_add(r190, r191);
    unsigned r193 = stwo_m31_mul(r164, r171);
    unsigned r194 = stwo_m31_add(r192, r193);
    unsigned r195 = stwo_m31_mul(r165, r170);
    out_cols[29u][row] = r170;
    lookup_words[79u * row_count + row] = r170;
    unsigned r196 = stwo_m31_add(r194, r195);
    unsigned r197 = stwo_m31_sub(r196, r153);
    out_cols[18u][row] = r153;
    lookup_words[16u * row_count + row] = r153;
    unsigned r198 = stwo_m31_mul(r197, r8);
    unsigned r199 = stwo_m31_add(r189, r198);
    unsigned r200 = stwo_m31_mul(r199, r9);
    unsigned r201 = stwo_m31_mul(r163, r173);
    out_cols[25u][row] = r163;
    lookup_words[47u * row_count + row] = r163;
    unsigned r202 = stwo_m31_mul(r164, r172);
    unsigned r203 = stwo_m31_add(r201, r202);
    unsigned r204 = stwo_m31_mul(r165, r171);
    out_cols[30u][row] = r171;
    lookup_words[80u * row_count + row] = r171;
    unsigned r205 = stwo_m31_add(r203, r204);
    unsigned r206 = stwo_m31_sub(r205, r154);
    out_cols[19u][row] = r154;
    lookup_words[17u * row_count + row] = r154;
    unsigned r207 = stwo_m31_add(r200, r206);
    out_cols[34u][row] = r200;
    sub_words[14u * row_count + row] = r200;
    lookup_words[110u * row_count + row] = r200;
    unsigned r208 = stwo_m31_mul(r164, r173);
    out_cols[26u][row] = r164;
    lookup_words[48u * row_count + row] = r164;
    out_cols[32u][row] = r173;
    lookup_words[82u * row_count + row] = r173;
    unsigned r209 = stwo_m31_mul(r165, r172);
    out_cols[27u][row] = r165;
    lookup_words[49u * row_count + row] = r165;
    out_cols[31u][row] = r172;
    lookup_words[81u * row_count + row] = r172;
    unsigned r210 = stwo_m31_add(r208, r209);
    unsigned r211 = stwo_m31_sub(r210, r155);
    out_cols[20u][row] = r155;
    lookup_words[18u * row_count + row] = r155;
    unsigned r212 = stwo_m31_mul(r211, r8);
    unsigned r213 = stwo_m31_add(r207, r212);
    unsigned r214 = stwo_m31_mul(r213, r9);
    out_cols[35u][row] = r214;
    sub_words[15u * row_count + row] = r214;
    lookup_words[112u * row_count + row] = r214;
    unsigned r215 = input_cols[3u][row];
    out_cols[36u][row] = r215;
    lookup_words[122u * row_count + row] = r215;
    unsigned r216 = stwo_m31_add(r16, r1);
    out_cols[0u][row] = r16;
    sub_words[0u * row_count + row] = r16;
    lookup_words[1u * row_count + row] = r16;
    lookup_words[114u * row_count + row] = r16;
    lookup_words[121u * row_count + row] = r1;
    unsigned r217 = stwo_m31_add(r216, r83);
    out_cols[8u][row] = r83;
    lookup_words[118u * row_count + row] = r217;
    unsigned r218 = stwo_m31_add(r17, r105);
    out_cols[1u][row] = r17;
    out_cols[10u][row] = r105;
    lookup_words[115u * row_count + row] = r17;
    lookup_words[119u * row_count + row] = r218;
}
