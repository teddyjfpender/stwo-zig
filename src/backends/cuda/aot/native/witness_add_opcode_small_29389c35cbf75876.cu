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

extern "C" __global__ void __launch_bounds__(256) stwo_jit_witness_643d6ea7402e00f9(
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
    lookup_words[68u * row_count + row] = r0;
    lookup_words[69u * row_count + row] = r0;
    lookup_words[70u * row_count + row] = r0;
    lookup_words[71u * row_count + row] = r0;
    lookup_words[72u * row_count + row] = r0;
    lookup_words[101u * row_count + row] = r0;
    lookup_words[102u * row_count + row] = r0;
    lookup_words[103u * row_count + row] = r0;
    lookup_words[104u * row_count + row] = r0;
    lookup_words[105u * row_count + row] = r0;
    unsigned r1 = 1u;
    unsigned r2 = 8u;
    unsigned r3 = 16u;
    unsigned r4 = 32u;
    unsigned r5 = 64u;
    unsigned r6 = 128u;
    unsigned r7 = 136u;
    unsigned r8 = 256u;
    unsigned r9 = 508u;
    unsigned r10 = 511u;
    unsigned r11 = 512u;
    unsigned r12 = 32768u;
    unsigned r13 = 262144u;
    unsigned r14 = 134217728u;
    unsigned r15 = 428564188u;
    lookup_words[107u * row_count + row] = r15;
    lookup_words[111u * row_count + row] = r15;
    unsigned r16 = 536870912u;
    unsigned r17 = 1444891767u;
    lookup_words[8u * row_count + row] = r17;
    lookup_words[41u * row_count + row] = r17;
    lookup_words[74u * row_count + row] = r17;
    unsigned r18 = 1662111297u;
    lookup_words[11u * row_count + row] = r18;
    lookup_words[44u * row_count + row] = r18;
    lookup_words[77u * row_count + row] = r18;
    unsigned r19 = 1719106205u;
    lookup_words[0u * row_count + row] = r19;
    unsigned r20 = input_cols[0u][row];
    unsigned r21 = input_cols[1u][row];
    unsigned r22 = input_cols[2u][row];
    unsigned r23 = (r20 < table_strides[0u] ? table_bases[0u][r20] : 0u);
    unsigned r24 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 0u);
    unsigned r25 = (r24 & 0xFFFFu);
    unsigned r26 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 1u);
    unsigned r27 = (r26 & 0xFFFFu);
    unsigned r28 = (r27 & 127u);
    unsigned r29 = ((r28 << 9u) & 0xFFFFu);
    unsigned r30 = ((r25 + r29) & 0xFFFFu);
    unsigned r31 = (r30 % STWO_M31_P);
    unsigned r32 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 1u);
    unsigned r33 = (r32 & 0xFFFFu);
    unsigned r34 = ((r33 & 0xFFFFu) >> 7u);
    unsigned r35 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 2u);
    unsigned r36 = (r35 & 0xFFFFu);
    unsigned r37 = ((r36 << 2u) & 0xFFFFu);
    unsigned r38 = ((r34 + r37) & 0xFFFFu);
    unsigned r39 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 3u);
    unsigned r40 = (r39 & 0xFFFFu);
    unsigned r41 = (r40 & 31u);
    unsigned r42 = ((r41 << 11u) & 0xFFFFu);
    unsigned r43 = ((r38 + r42) & 0xFFFFu);
    unsigned r44 = (r43 % STWO_M31_P);
    unsigned r45 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 3u);
    unsigned r46 = (r45 & 0xFFFFu);
    unsigned r47 = ((r46 & 0xFFFFu) >> 5u);
    unsigned r48 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 4u);
    unsigned r49 = (r48 & 0xFFFFu);
    unsigned r50 = ((r49 << 4u) & 0xFFFFu);
    unsigned r51 = ((r47 + r50) & 0xFFFFu);
    unsigned r52 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 5u);
    unsigned r53 = (r52 & 0xFFFFu);
    unsigned r54 = (r53 & 7u);
    unsigned r55 = ((r54 << 13u) & 0xFFFFu);
    unsigned r56 = ((r51 + r55) & 0xFFFFu);
    unsigned r57 = (r56 % STWO_M31_P);
    unsigned r58 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 5u);
    unsigned r59 = (r58 & 0xFFFFu);
    unsigned r60 = ((r59 & 0xFFFFu) >> 3u);
    unsigned r61 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 6u);
    unsigned r62 = (r61 & 0xFFFFu);
    unsigned r63 = ((r62 << 6u) & 0xFFFFu);
    unsigned r64 = ((r60 + r63) & 0xFFFFu);
    unsigned r65 = ((r64 & 0xFFFFu) >> 0u);
    unsigned r66 = (r65 & 1u);
    unsigned r67 = (r66 % STWO_M31_P);
    unsigned r68 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 5u);
    unsigned r69 = (r68 & 0xFFFFu);
    unsigned r70 = ((r69 & 0xFFFFu) >> 3u);
    unsigned r71 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 6u);
    unsigned r72 = (r71 & 0xFFFFu);
    unsigned r73 = ((r72 << 6u) & 0xFFFFu);
    unsigned r74 = ((r70 + r73) & 0xFFFFu);
    unsigned r75 = ((r74 & 0xFFFFu) >> 1u);
    unsigned r76 = (r75 & 1u);
    unsigned r77 = (r76 % STWO_M31_P);
    unsigned r78 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 5u);
    unsigned r79 = (r78 & 0xFFFFu);
    unsigned r80 = ((r79 & 0xFFFFu) >> 3u);
    unsigned r81 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 6u);
    unsigned r82 = (r81 & 0xFFFFu);
    unsigned r83 = ((r82 << 6u) & 0xFFFFu);
    unsigned r84 = ((r80 + r83) & 0xFFFFu);
    unsigned r85 = ((r84 & 0xFFFFu) >> 2u);
    unsigned r86 = (r85 & 1u);
    unsigned r87 = (r86 % STWO_M31_P);
    unsigned r88 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 5u);
    unsigned r89 = (r88 & 0xFFFFu);
    unsigned r90 = ((r89 & 0xFFFFu) >> 3u);
    unsigned r91 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 6u);
    unsigned r92 = (r91 & 0xFFFFu);
    unsigned r93 = ((r92 << 6u) & 0xFFFFu);
    unsigned r94 = ((r90 + r93) & 0xFFFFu);
    unsigned r95 = ((r94 & 0xFFFFu) >> 3u);
    unsigned r96 = (r95 & 1u);
    unsigned r97 = (r96 % STWO_M31_P);
    unsigned r98 = stwo_m31_sub(r1, r87);
    unsigned r99 = stwo_m31_sub(r98, r97);
    unsigned r100 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 5u);
    unsigned r101 = (r100 & 0xFFFFu);
    unsigned r102 = ((r101 & 0xFFFFu) >> 3u);
    unsigned r103 = stwo_wit_deduce_limb(table_bases, table_strides, r23, 6u);
    unsigned r104 = (r103 & 0xFFFFu);
    unsigned r105 = ((r104 << 6u) & 0xFFFFu);
    unsigned r106 = ((r102 + r105) & 0xFFFFu);
    unsigned r107 = ((r106 & 0xFFFFu) >> 11u);
    unsigned r108 = (r107 & 1u);
    unsigned r109 = (r108 % STWO_M31_P);
    unsigned r110 = stwo_m31_mul(r67, r2);
    unsigned r111 = stwo_m31_mul(r77, r3);
    unsigned r112 = stwo_m31_add(r110, r111);
    unsigned r113 = stwo_m31_mul(r87, r4);
    unsigned r114 = stwo_m31_add(r112, r113);
    unsigned r115 = stwo_m31_mul(r97, r5);
    unsigned r116 = stwo_m31_add(r114, r115);
    unsigned r117 = stwo_m31_mul(r99, r6);
    unsigned r118 = stwo_m31_add(r116, r117);
    unsigned r119 = stwo_m31_add(r118, r8);
    sub_words[4u * row_count + row] = r119;
    unsigned r120 = stwo_m31_mul(r109, r4);
    unsigned r121 = stwo_m31_add(r120, r8);
    sub_words[5u * row_count + row] = r121;
    unsigned r122 = stwo_m31_mul(r67, r2);
    unsigned r123 = stwo_m31_mul(r77, r3);
    unsigned r124 = stwo_m31_add(r122, r123);
    unsigned r125 = stwo_m31_mul(r87, r4);
    unsigned r126 = stwo_m31_add(r124, r125);
    unsigned r127 = stwo_m31_mul(r97, r5);
    unsigned r128 = stwo_m31_add(r126, r127);
    unsigned r129 = stwo_m31_mul(r99, r6);
    unsigned r130 = stwo_m31_add(r128, r129);
    unsigned r131 = stwo_m31_add(r130, r8);
    lookup_words[5u * row_count + row] = r131;
    unsigned r132 = stwo_m31_mul(r109, r4);
    unsigned r133 = stwo_m31_add(r132, r8);
    lookup_words[6u * row_count + row] = r133;
    unsigned r134 = stwo_m31_sub(r31, r12);
    out_cols[3u][row] = r31;
    sub_words[1u * row_count + row] = r31;
    lookup_words[2u * row_count + row] = r31;
    unsigned r135 = stwo_m31_sub(r44, r12);
    out_cols[4u][row] = r44;
    sub_words[2u * row_count + row] = r44;
    lookup_words[3u * row_count + row] = r44;
    unsigned r136 = stwo_m31_sub(r57, r12);
    out_cols[5u][row] = r57;
    sub_words[3u * row_count + row] = r57;
    lookup_words[4u * row_count + row] = r57;
    unsigned r137 = stwo_m31_mul(r67, r22);
    unsigned r138 = stwo_m31_sub(r1, r67);
    out_cols[6u][row] = r67;
    unsigned r139 = stwo_m31_mul(r138, r21);
    unsigned r140 = stwo_m31_add(r137, r139);
    unsigned r141 = stwo_m31_mul(r77, r22);
    unsigned r142 = stwo_m31_sub(r1, r77);
    out_cols[7u][row] = r77;
    unsigned r143 = stwo_m31_mul(r142, r21);
    unsigned r144 = stwo_m31_add(r141, r143);
    unsigned r145 = stwo_m31_mul(r87, r20);
    unsigned r146 = stwo_m31_mul(r97, r22);
    out_cols[2u][row] = r22;
    out_cols[9u][row] = r97;
    lookup_words[110u * row_count + row] = r22;
    lookup_words[114u * row_count + row] = r22;
    unsigned r147 = stwo_m31_add(r145, r146);
    unsigned r148 = stwo_m31_mul(r99, r21);
    unsigned r149 = stwo_m31_add(r147, r148);
    unsigned r150 = stwo_m31_add(r140, r134);
    unsigned r151 = (r150 < table_strides[0u] ? table_bases[0u][r150] : 0u);
    unsigned r152 = stwo_m31_add(r140, r134);
    sub_words[7u * row_count + row] = r152;
    unsigned r153 = stwo_m31_add(r140, r134);
    out_cols[11u][row] = r140;
    lookup_words[9u * row_count + row] = r153;
    unsigned r154 = stwo_wit_deduce_limb(table_bases, table_strides, r151, 27u);
    unsigned r155 = (r154 == r8 ? 1u : 0u);
    unsigned r156 = stwo_wit_deduce_limb(table_bases, table_strides, r151, 20u);
    unsigned r157 = (r156 == r10 ? 1u : 0u);
    unsigned r158 = stwo_m31_mul(r157, r155);
    unsigned r159 = stwo_m31_mul(r158, r9);
    unsigned r160 = stwo_m31_mul(r158, r10);
    lookup_words[17u * row_count + row] = r160;
    lookup_words[18u * row_count + row] = r160;
    lookup_words[19u * row_count + row] = r160;
    lookup_words[20u * row_count + row] = r160;
    lookup_words[21u * row_count + row] = r160;
    lookup_words[22u * row_count + row] = r160;
    lookup_words[23u * row_count + row] = r160;
    lookup_words[24u * row_count + row] = r160;
    lookup_words[25u * row_count + row] = r160;
    lookup_words[26u * row_count + row] = r160;
    lookup_words[27u * row_count + row] = r160;
    lookup_words[28u * row_count + row] = r160;
    lookup_words[29u * row_count + row] = r160;
    lookup_words[30u * row_count + row] = r160;
    lookup_words[31u * row_count + row] = r160;
    lookup_words[32u * row_count + row] = r160;
    lookup_words[33u * row_count + row] = r160;
    unsigned r161 = stwo_m31_mul(r155, r7);
    unsigned r162 = stwo_m31_sub(r161, r158);
    lookup_words[34u * row_count + row] = r162;
    unsigned r163 = stwo_m31_mul(r155, r8);
    lookup_words[40u * row_count + row] = r163;
    unsigned r164 = stwo_wit_deduce_limb(table_bases, table_strides, r151, 0u);
    unsigned r165 = stwo_wit_deduce_limb(table_bases, table_strides, r151, 1u);
    unsigned r166 = stwo_wit_deduce_limb(table_bases, table_strides, r151, 2u);
    unsigned r167 = stwo_wit_deduce_limb(table_bases, table_strides, r151, 3u);
    out_cols[14u][row] = r151;
    lookup_words[10u * row_count + row] = r151;
    sub_words[10u * row_count + row] = r151;
    lookup_words[12u * row_count + row] = r151;
    unsigned r168 = (r167 & 0xFFFFu);
    unsigned r169 = (r168 & 3u);
    unsigned r170 = (r169 % STWO_M31_P);
    unsigned r171 = (r170 & 0xFFFFu);
    unsigned r172 = (r171 & 2u);
    unsigned r173 = ((r172 & 0xFFFFu) >> 1u);
    unsigned r174 = (r173 % STWO_M31_P);
    out_cols[21u][row] = r174;
    unsigned r175 = stwo_m31_add(r170, r159);
    lookup_words[16u * row_count + row] = r175;
    unsigned r176 = stwo_m31_mul(r165, r11);
    out_cols[18u][row] = r165;
    lookup_words[14u * row_count + row] = r165;
    unsigned r177 = stwo_m31_add(r164, r176);
    out_cols[17u][row] = r164;
    lookup_words[13u * row_count + row] = r164;
    unsigned r178 = stwo_m31_mul(r166, r13);
    out_cols[19u][row] = r166;
    lookup_words[15u * row_count + row] = r166;
    unsigned r179 = stwo_m31_add(r177, r178);
    unsigned r180 = stwo_m31_mul(r170, r14);
    out_cols[20u][row] = r170;
    unsigned r181 = stwo_m31_add(r179, r180);
    unsigned r182 = stwo_m31_sub(r181, r155);
    out_cols[15u][row] = r155;
    unsigned r183 = stwo_m31_mul(r16, r158);
    out_cols[16u][row] = r158;
    unsigned r184 = stwo_m31_sub(r182, r183);
    unsigned r185 = stwo_m31_add(r144, r135);
    unsigned r186 = (r185 < table_strides[0u] ? table_bases[0u][r185] : 0u);
    unsigned r187 = stwo_m31_add(r144, r135);
    sub_words[8u * row_count + row] = r187;
    unsigned r188 = stwo_m31_add(r144, r135);
    out_cols[12u][row] = r144;
    lookup_words[42u * row_count + row] = r188;
    unsigned r189 = stwo_wit_deduce_limb(table_bases, table_strides, r186, 27u);
    unsigned r190 = (r189 == r8 ? 1u : 0u);
    unsigned r191 = stwo_wit_deduce_limb(table_bases, table_strides, r186, 20u);
    unsigned r192 = (r191 == r10 ? 1u : 0u);
    unsigned r193 = stwo_m31_mul(r192, r190);
    unsigned r194 = stwo_m31_mul(r193, r9);
    unsigned r195 = stwo_m31_mul(r193, r10);
    lookup_words[50u * row_count + row] = r195;
    lookup_words[51u * row_count + row] = r195;
    lookup_words[52u * row_count + row] = r195;
    lookup_words[53u * row_count + row] = r195;
    lookup_words[54u * row_count + row] = r195;
    lookup_words[55u * row_count + row] = r195;
    lookup_words[56u * row_count + row] = r195;
    lookup_words[57u * row_count + row] = r195;
    lookup_words[58u * row_count + row] = r195;
    lookup_words[59u * row_count + row] = r195;
    lookup_words[60u * row_count + row] = r195;
    lookup_words[61u * row_count + row] = r195;
    lookup_words[62u * row_count + row] = r195;
    lookup_words[63u * row_count + row] = r195;
    lookup_words[64u * row_count + row] = r195;
    lookup_words[65u * row_count + row] = r195;
    lookup_words[66u * row_count + row] = r195;
    unsigned r196 = stwo_m31_mul(r190, r7);
    unsigned r197 = stwo_m31_sub(r196, r193);
    lookup_words[67u * row_count + row] = r197;
    unsigned r198 = stwo_m31_mul(r190, r8);
    lookup_words[73u * row_count + row] = r198;
    unsigned r199 = stwo_wit_deduce_limb(table_bases, table_strides, r186, 0u);
    unsigned r200 = stwo_wit_deduce_limb(table_bases, table_strides, r186, 1u);
    unsigned r201 = stwo_wit_deduce_limb(table_bases, table_strides, r186, 2u);
    unsigned r202 = stwo_wit_deduce_limb(table_bases, table_strides, r186, 3u);
    out_cols[22u][row] = r186;
    lookup_words[43u * row_count + row] = r186;
    sub_words[11u * row_count + row] = r186;
    lookup_words[45u * row_count + row] = r186;
    unsigned r203 = (r202 & 0xFFFFu);
    unsigned r204 = (r203 & 3u);
    unsigned r205 = (r204 % STWO_M31_P);
    unsigned r206 = (r205 & 0xFFFFu);
    unsigned r207 = (r206 & 2u);
    unsigned r208 = ((r207 & 0xFFFFu) >> 1u);
    unsigned r209 = (r208 % STWO_M31_P);
    out_cols[29u][row] = r209;
    unsigned r210 = stwo_m31_add(r205, r194);
    lookup_words[49u * row_count + row] = r210;
    unsigned r211 = stwo_m31_mul(r200, r11);
    out_cols[26u][row] = r200;
    lookup_words[47u * row_count + row] = r200;
    unsigned r212 = stwo_m31_add(r199, r211);
    out_cols[25u][row] = r199;
    lookup_words[46u * row_count + row] = r199;
    unsigned r213 = stwo_m31_mul(r201, r13);
    out_cols[27u][row] = r201;
    lookup_words[48u * row_count + row] = r201;
    unsigned r214 = stwo_m31_add(r212, r213);
    unsigned r215 = stwo_m31_mul(r205, r14);
    out_cols[28u][row] = r205;
    unsigned r216 = stwo_m31_add(r214, r215);
    unsigned r217 = stwo_m31_sub(r216, r190);
    out_cols[23u][row] = r190;
    unsigned r218 = stwo_m31_mul(r16, r193);
    out_cols[24u][row] = r193;
    unsigned r219 = stwo_m31_sub(r217, r218);
    unsigned r220 = stwo_m31_add(r149, r136);
    unsigned r221 = (r220 < table_strides[0u] ? table_bases[0u][r220] : 0u);
    unsigned r222 = stwo_m31_add(r149, r136);
    sub_words[9u * row_count + row] = r222;
    unsigned r223 = stwo_m31_add(r149, r136);
    out_cols[13u][row] = r149;
    lookup_words[75u * row_count + row] = r223;
    unsigned r224 = stwo_wit_deduce_limb(table_bases, table_strides, r221, 27u);
    unsigned r225 = (r224 == r8 ? 1u : 0u);
    unsigned r226 = stwo_wit_deduce_limb(table_bases, table_strides, r221, 20u);
    unsigned r227 = (r226 == r10 ? 1u : 0u);
    unsigned r228 = stwo_m31_mul(r227, r225);
    unsigned r229 = stwo_m31_mul(r228, r9);
    unsigned r230 = stwo_m31_mul(r228, r10);
    lookup_words[83u * row_count + row] = r230;
    lookup_words[84u * row_count + row] = r230;
    lookup_words[85u * row_count + row] = r230;
    lookup_words[86u * row_count + row] = r230;
    lookup_words[87u * row_count + row] = r230;
    lookup_words[88u * row_count + row] = r230;
    lookup_words[89u * row_count + row] = r230;
    lookup_words[90u * row_count + row] = r230;
    lookup_words[91u * row_count + row] = r230;
    lookup_words[92u * row_count + row] = r230;
    lookup_words[93u * row_count + row] = r230;
    lookup_words[94u * row_count + row] = r230;
    lookup_words[95u * row_count + row] = r230;
    lookup_words[96u * row_count + row] = r230;
    lookup_words[97u * row_count + row] = r230;
    lookup_words[98u * row_count + row] = r230;
    lookup_words[99u * row_count + row] = r230;
    unsigned r231 = stwo_m31_mul(r225, r7);
    unsigned r232 = stwo_m31_sub(r231, r228);
    lookup_words[100u * row_count + row] = r232;
    unsigned r233 = stwo_m31_mul(r225, r8);
    lookup_words[106u * row_count + row] = r233;
    unsigned r234 = stwo_wit_deduce_limb(table_bases, table_strides, r221, 0u);
    unsigned r235 = stwo_wit_deduce_limb(table_bases, table_strides, r221, 1u);
    unsigned r236 = stwo_wit_deduce_limb(table_bases, table_strides, r221, 2u);
    unsigned r237 = stwo_wit_deduce_limb(table_bases, table_strides, r221, 3u);
    out_cols[30u][row] = r221;
    lookup_words[76u * row_count + row] = r221;
    sub_words[12u * row_count + row] = r221;
    lookup_words[78u * row_count + row] = r221;
    unsigned r238 = (r237 & 0xFFFFu);
    unsigned r239 = (r238 & 3u);
    unsigned r240 = (r239 % STWO_M31_P);
    unsigned r241 = (r240 & 0xFFFFu);
    unsigned r242 = (r241 & 2u);
    unsigned r243 = ((r242 & 0xFFFFu) >> 1u);
    unsigned r244 = (r243 % STWO_M31_P);
    out_cols[37u][row] = r244;
    unsigned r245 = stwo_m31_add(r240, r229);
    lookup_words[82u * row_count + row] = r245;
    unsigned r246 = stwo_m31_mul(r235, r11);
    out_cols[34u][row] = r235;
    lookup_words[80u * row_count + row] = r235;
    unsigned r247 = stwo_m31_add(r234, r246);
    out_cols[33u][row] = r234;
    lookup_words[79u * row_count + row] = r234;
    unsigned r248 = stwo_m31_mul(r236, r13);
    out_cols[35u][row] = r236;
    lookup_words[81u * row_count + row] = r236;
    unsigned r249 = stwo_m31_add(r247, r248);
    unsigned r250 = stwo_m31_mul(r240, r14);
    out_cols[36u][row] = r240;
    unsigned r251 = stwo_m31_add(r249, r250);
    unsigned r252 = stwo_m31_sub(r251, r225);
    out_cols[31u][row] = r225;
    unsigned r253 = stwo_m31_mul(r16, r228);
    out_cols[32u][row] = r228;
    unsigned r254 = stwo_m31_sub(r252, r253);
    unsigned r255 = input_cols[3u][row];
    out_cols[38u][row] = r255;
    lookup_words[116u * row_count + row] = r255;
    unsigned r256 = stwo_m31_add(r20, r1);
    out_cols[0u][row] = r20;
    sub_words[0u * row_count + row] = r20;
    lookup_words[1u * row_count + row] = r20;
    lookup_words[108u * row_count + row] = r20;
    lookup_words[115u * row_count + row] = r1;
    unsigned r257 = stwo_m31_add(r256, r87);
    out_cols[8u][row] = r87;
    lookup_words[112u * row_count + row] = r257;
    unsigned r258 = stwo_m31_add(r21, r109);
    out_cols[1u][row] = r21;
    out_cols[10u][row] = r109;
    lookup_words[109u * row_count + row] = r21;
    lookup_words[113u * row_count + row] = r258;
}
