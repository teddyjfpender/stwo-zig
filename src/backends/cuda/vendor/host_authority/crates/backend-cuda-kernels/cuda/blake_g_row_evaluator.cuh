// Shared phase-local Blake-G evaluator.
//
// The fused witness writer and the direct six-input relation kernel instantiate
// this exact arithmetic once with different sinks. Keep this header free of
// CUDA runtime state: values stay named and phase-local so ptxas can retire
// them instead of creating a 68-word thread-local array.

#ifndef BLAKE_G_ROW_EVALUATOR_CUH
#define BLAKE_G_ROW_EVALUATOR_CUH

__device__ __forceinline__ uint32_t blake_g_lo16(uint32_t value) {
  return value & 0xffffu;
}

__device__ __forceinline__ uint32_t blake_g_hi16(uint32_t value) {
  return value >> 16;
}

template <typename Sink>
__device__ __forceinline__ void blake_g_evaluate_row(
    uint32_t in0, uint32_t in1, uint32_t in2, uint32_t in3, uint32_t in4,
    uint32_t in5, uint32_t row, uint32_t n_rows, Sink &sink) {
    // Input limbs. Recompute these cheap projections for the final tuple so
    // twelve limb values do not remain live through the complete G function.
    sink.template trace<0>(blake_g_lo16(in0));
    sink.template trace<1>(blake_g_hi16(in0));
    sink.template trace<2>(blake_g_lo16(in1));
    sink.template trace<3>(blake_g_hi16(in1));
    sink.template trace<4>(blake_g_lo16(in2));
    sink.template trace<5>(blake_g_hi16(in2));
    sink.template trace<6>(blake_g_lo16(in3));
    sink.template trace<7>(blake_g_hi16(in3));
    sink.template trace<8>(blake_g_lo16(in4));
    sink.template trace<9>(blake_g_hi16(in4));
    sink.template trace<10>(blake_g_lo16(in5));
    sink.template trace<11>(blake_g_hi16(in5));

    // Triple Sum 32 and R16 xor. Emit the first four tuples and count edges
    // while their operands are live.
    const uint32_t ts0 = in0 + in1 + in4;
    const uint32_t ts0_lo = blake_g_lo16(ts0);
    const uint32_t ts0_hi = blake_g_hi16(ts0);
    sink.template trace<12>(ts0_lo);
    sink.template trace<13>(ts0_hi);

    const uint32_t ts0_lo_ms8 = ts0_lo >> 8;
    const uint32_t ts0_lo_ls8 = ts0_lo - ts0_lo_ms8 * 256u;
    const uint32_t ts0_hi_ms8 = ts0_hi >> 8;
    const uint32_t ts0_hi_ls8 = ts0_hi - ts0_hi_ms8 * 256u;
    const uint32_t in3_lo_ms8 = blake_g_lo16(in3) >> 8;
    const uint32_t in3_lo_ls8 = blake_g_lo16(in3) - in3_lo_ms8 * 256u;
    const uint32_t in3_hi_ms8 = blake_g_hi16(in3) >> 8;
    const uint32_t in3_hi_ls8 = blake_g_hi16(in3) - in3_hi_ms8 * 256u;
    const uint32_t xor16_0 = ts0_lo_ls8 ^ in3_lo_ls8;
    const uint32_t xor16_1 = ts0_lo_ms8 ^ in3_lo_ms8;
    const uint32_t xor16_2 = ts0_hi_ls8 ^ in3_hi_ls8;
    const uint32_t xor16_3 = ts0_hi_ms8 ^ in3_hi_ms8;
    sink.template auxiliary<0>(ts0_lo_ls8);
    sink.template auxiliary<1>(ts0_hi_ls8);
    sink.template auxiliary<2>(in3_lo_ls8);
    sink.template auxiliary<3>(in3_hi_ls8);
    sink.template trace<14>(ts0_lo_ms8);
    sink.template trace<15>(ts0_hi_ms8);
    sink.template trace<16>(in3_lo_ms8);
    sink.template trace<17>(in3_hi_ms8);
    sink.template trace<18>(xor16_0);
    sink.template trace<19>(xor16_1);
    sink.template trace<20>(xor16_2);
    sink.template trace<21>(xor16_3);
    sink.template tuple<0, 112558620>(ts0_lo_ls8,
                                  in3_lo_ls8, xor16_0);
    sink.template tuple<1, 112558620>(ts0_lo_ms8,
                                  in3_lo_ms8, xor16_1);
    sink.template tuple<2, 521092554>(ts0_hi_ls8,
                                  in3_hi_ls8, xor16_2);
    sink.template tuple<3, 521092554>(ts0_hi_ms8,
                                  in3_hi_ms8, xor16_3);
    sink.template count_lut<0, 0, 8, 0>(ts0_lo_ls8, in3_lo_ls8);
    sink.template count_lut<0, 0, 8, 0>(ts0_lo_ms8, in3_lo_ms8);
    sink.template count_lut<0, 0, 8, 1>(ts0_hi_ls8, in3_hi_ls8);
    sink.template count_lut<0, 0, 8, 1>(ts0_hi_ms8, in3_hi_ms8);
    const uint32_t xr16_lo = xor16_2 + xor16_3 * 256u;
    const uint32_t xr16_hi = xor16_0 + xor16_1 * 256u;
    const uint32_t xr16 = xr16_lo + (xr16_hi << 16);

    // Triple Sum 32 and R12 xor.
    const uint32_t ts22 = in2 + xr16;
    const uint32_t ts22_lo = blake_g_lo16(ts22);
    const uint32_t ts22_hi = blake_g_hi16(ts22);
    sink.template trace<22>(ts22_lo);
    sink.template trace<23>(ts22_hi);

    const uint32_t in1_lo_ms4 = blake_g_lo16(in1) >> 12;
    const uint32_t in1_lo_ls12 = blake_g_lo16(in1) - in1_lo_ms4 * 4096u;
    const uint32_t in1_hi_ms4 = blake_g_hi16(in1) >> 12;
    const uint32_t in1_hi_ls12 = blake_g_hi16(in1) - in1_hi_ms4 * 4096u;
    const uint32_t ts22_lo_ms4 = ts22_lo >> 12;
    const uint32_t ts22_lo_ls12 = ts22_lo - ts22_lo_ms4 * 4096u;
    const uint32_t ts22_hi_ms4 = ts22_hi >> 12;
    const uint32_t ts22_hi_ls12 = ts22_hi - ts22_hi_ms4 * 4096u;
    const uint32_t xor12_0 = in1_lo_ls12 ^ ts22_lo_ls12;
    const uint32_t xor12_1 = in1_lo_ms4 ^ ts22_lo_ms4;
    const uint32_t xor12_2 = in1_hi_ls12 ^ ts22_hi_ls12;
    const uint32_t xor12_3 = in1_hi_ms4 ^ ts22_hi_ms4;
    sink.template auxiliary<4>(in1_lo_ls12);
    sink.template auxiliary<5>(in1_hi_ls12);
    sink.template auxiliary<6>(ts22_lo_ls12);
    sink.template auxiliary<7>(ts22_hi_ls12);
    sink.template trace<24>(in1_lo_ms4);
    sink.template trace<25>(in1_hi_ms4);
    sink.template trace<26>(ts22_lo_ms4);
    sink.template trace<27>(ts22_hi_ms4);
    sink.template trace<28>(xor12_0);
    sink.template trace<29>(xor12_1);
    sink.template trace<30>(xor12_2);
    sink.template trace<31>(xor12_3);
    sink.template tuple<4, 648362599>(in1_lo_ls12,
                                  ts22_lo_ls12, xor12_0);
    sink.template tuple<5, 45448144>(in1_lo_ms4,
                                 ts22_lo_ms4, xor12_1);
    sink.template tuple<6, 648362599>(in1_hi_ls12,
                                  ts22_hi_ls12, xor12_2);
    sink.template tuple<7, 45448144>(in1_hi_ms4,
                                 ts22_hi_ms4, xor12_3);
    sink.count_xor12(in1_lo_ls12, ts22_lo_ls12);
    sink.count_xor12(in1_hi_ls12, ts22_hi_ls12);
    sink.template count_lut<1, 2, 4, 0>(in1_lo_ms4, ts22_lo_ms4);
    sink.template count_lut<1, 2, 4, 0>(in1_hi_ms4, ts22_hi_ms4);
    const uint32_t xr12_lo = xor12_1 + xor12_2 * 16u;
    const uint32_t xr12_hi = xor12_3 + xor12_0 * 16u;
    const uint32_t xr12 = xr12_lo + (xr12_hi << 16);

    // Triple Sum 32 and R8 xor.
    const uint32_t ts44 = ts0 + xr12 + in5;
    const uint32_t ts44_lo = blake_g_lo16(ts44);
    const uint32_t ts44_hi = blake_g_hi16(ts44);
    sink.template trace<32>(ts44_lo);
    sink.template trace<33>(ts44_hi);

    const uint32_t ts44_lo_ms8 = ts44_lo >> 8;
    const uint32_t ts44_lo_ls8 = ts44_lo - ts44_lo_ms8 * 256u;
    const uint32_t ts44_hi_ms8 = ts44_hi >> 8;
    const uint32_t ts44_hi_ls8 = ts44_hi - ts44_hi_ms8 * 256u;
    const uint32_t xr16_lo_ms8 = xr16_lo >> 8;
    const uint32_t xr16_lo_ls8 = xr16_lo - xr16_lo_ms8 * 256u;
    const uint32_t xr16_hi_ms8 = xr16_hi >> 8;
    const uint32_t xr16_hi_ls8 = xr16_hi - xr16_hi_ms8 * 256u;
    const uint32_t xor8_0 = ts44_lo_ls8 ^ xr16_lo_ls8;
    const uint32_t xor8_1 = ts44_lo_ms8 ^ xr16_lo_ms8;
    const uint32_t xor8_2 = ts44_hi_ls8 ^ xr16_hi_ls8;
    const uint32_t xor8_3 = ts44_hi_ms8 ^ xr16_hi_ms8;
    sink.template auxiliary<8>(ts44_lo_ls8);
    sink.template auxiliary<9>(ts44_hi_ls8);
    sink.template auxiliary<10>(xr16_lo_ls8);
    sink.template auxiliary<11>(xr16_hi_ls8);
    sink.template trace<34>(ts44_lo_ms8);
    sink.template trace<35>(ts44_hi_ms8);
    sink.template trace<36>(xr16_lo_ms8);
    sink.template trace<37>(xr16_hi_ms8);
    sink.template trace<38>(xor8_0);
    sink.template trace<39>(xor8_1);
    sink.template trace<40>(xor8_2);
    sink.template trace<41>(xor8_3);
    sink.template tuple<8, 112558620>(ts44_lo_ls8,
                                  xr16_lo_ls8, xor8_0);
    sink.template tuple<9, 112558620>(ts44_lo_ms8,
                                  xr16_lo_ms8, xor8_1);
    sink.template tuple<10, 521092554>(ts44_hi_ls8,
                                   xr16_hi_ls8, xor8_2);
    sink.template tuple<11, 521092554>(ts44_hi_ms8,
                                   xr16_hi_ms8, xor8_3);
    sink.template count_lut<0, 0, 8, 0>(ts44_lo_ls8, xr16_lo_ls8);
    sink.template count_lut<0, 0, 8, 0>(ts44_lo_ms8, xr16_lo_ms8);
    sink.template count_lut<0, 0, 8, 1>(ts44_hi_ls8, xr16_hi_ls8);
    sink.template count_lut<0, 0, 8, 1>(ts44_hi_ms8, xr16_hi_ms8);
    const uint32_t xr8_lo = xor8_1 + xor8_2 * 256u;
    const uint32_t xr8_hi = xor8_3 + xor8_0 * 256u;
    const uint32_t xr8 = xr8_lo + (xr8_hi << 16);

    // Triple Sum 32 and R7 xor.
    const uint32_t ts66 = ts22 + xr8;
    const uint32_t ts66_lo = blake_g_lo16(ts66);
    const uint32_t ts66_hi = blake_g_hi16(ts66);
    sink.template trace<42>(ts66_lo);
    sink.template trace<43>(ts66_hi);

    const uint32_t xr12_lo_ms9 = xr12_lo >> 7;
    const uint32_t xr12_lo_ls7 = xr12_lo - xr12_lo_ms9 * 128u;
    const uint32_t xr12_hi_ms9 = xr12_hi >> 7;
    const uint32_t xr12_hi_ls7 = xr12_hi - xr12_hi_ms9 * 128u;
    const uint32_t ts66_lo_ms9 = ts66_lo >> 7;
    const uint32_t ts66_lo_ls7 = ts66_lo - ts66_lo_ms9 * 128u;
    const uint32_t ts66_hi_ms9 = ts66_hi >> 7;
    const uint32_t ts66_hi_ls7 = ts66_hi - ts66_hi_ms9 * 128u;
    const uint32_t xor7_0 = xr12_lo_ls7 ^ ts66_lo_ls7;
    const uint32_t xor7_1 = xr12_lo_ms9 ^ ts66_lo_ms9;
    const uint32_t xor7_2 = xr12_hi_ls7 ^ ts66_hi_ls7;
    const uint32_t xor7_3 = xr12_hi_ms9 ^ ts66_hi_ms9;
    sink.template auxiliary<12>(xr12_lo_ls7);
    sink.template auxiliary<13>(xr12_hi_ls7);
    sink.template auxiliary<14>(ts66_lo_ls7);
    sink.template auxiliary<15>(ts66_hi_ls7);
    sink.template trace<44>(xr12_lo_ms9);
    sink.template trace<45>(xr12_hi_ms9);
    sink.template trace<46>(ts66_lo_ms9);
    sink.template trace<47>(ts66_hi_ms9);
    sink.template trace<48>(xor7_0);
    sink.template trace<49>(xor7_1);
    sink.template trace<50>(xor7_2);
    sink.template trace<51>(xor7_3);
    sink.template tuple<12, 62225763>(xr12_lo_ls7,
                                  ts66_lo_ls7, xor7_0);
    sink.template tuple<13, 95781001>(xr12_lo_ms9,
                                  ts66_lo_ms9, xor7_1);
    sink.template tuple<14, 62225763>(xr12_hi_ls7,
                                  ts66_hi_ls7, xor7_2);
    sink.template tuple<15, 95781001>(xr12_hi_ms9,
                                  ts66_hi_ms9, xor7_3);
    sink.template count_lut<2, 3, 7, 0>(xr12_lo_ls7, ts66_lo_ls7);
    sink.template count_lut<2, 3, 7, 0>(xr12_hi_ls7, ts66_hi_ls7);
    sink.template count_lut<3, 4, 9, 0>(xr12_lo_ms9, ts66_lo_ms9);
    sink.template count_lut<3, 4, 9, 0>(xr12_hi_ms9, ts66_hi_ms9);
    const uint32_t xr7_lo = xor7_1 + xor7_2 * 512u;
    const uint32_t xr7_hi = xor7_3 + xor7_0 * 512u;
    sink.template auxiliary<16>(xr7_lo);
    sink.template auxiliary<17>(xr7_hi);
    sink.template auxiliary<18>(xr8_lo);
    sink.template auxiliary<19>(xr8_hi);

    const uint32_t enabler = row < n_rows ? 1u : 0u;
    sink.template trace<52>(enabler);

    // Final blake_g relation tuple and multiplicities.
    sink.template lookup<64>(1139985212u);
    sink.template lookup<65>(blake_g_lo16(in0));
    sink.template lookup<66>(blake_g_hi16(in0));
    sink.template lookup<67>(blake_g_lo16(in1));
    sink.template lookup<68>(blake_g_hi16(in1));
    sink.template lookup<69>(blake_g_lo16(in2));
    sink.template lookup<70>(blake_g_hi16(in2));
    sink.template lookup<71>(blake_g_lo16(in3));
    sink.template lookup<72>(blake_g_hi16(in3));
    sink.template lookup<73>(blake_g_lo16(in4));
    sink.template lookup<74>(blake_g_hi16(in4));
    sink.template lookup<75>(blake_g_lo16(in5));
    sink.template lookup<76>(blake_g_hi16(in5));
    sink.template lookup<77>(ts44_lo);
    sink.template lookup<78>(ts44_hi);
    sink.template lookup<79>(xr7_lo);
    sink.template lookup<80>(xr7_hi);
    sink.template lookup<81>(ts66_lo);
    sink.template lookup<82>(ts66_hi);
    sink.template lookup<83>(xr8_lo);
    sink.template lookup<84>(xr8_hi);
    sink.template lookup<85>(1u);
    sink.template lookup<86>(enabler);
}

#endif  // BLAKE_G_ROW_EVALUATOR_CUH
