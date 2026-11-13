kernel void stwo_zig_framework_interaction_v1_3189e0f57241480608d508e3d36064f73c53ad19b6bea003e6b7dc0d14cc975b(
 device const uint *tree0 [[buffer(0)]], device const uint *tree1 [[buffer(1)]],
 device const ulong *column_offsets [[buffer(2)]], device const uint *profile_parameters [[buffer(3)]],
 device const uint *relation_parameters [[buffer(4)]], device uint *output [[buffer(5)]],
 device atomic_uint *status [[buffer(6)]], constant uint &row_count [[buffer(7)]],
 uint row [[thread_position_in_grid]]) {
 if (row >= row_count) return;
 if (tree1[column_offsets[0u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[1u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[2u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[3u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[4u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[5u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[6u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[7u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[8u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[9u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[10u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[11u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[12u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[13u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[14u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[15u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[16u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[17u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
    uint l0 = tree1[column_offsets[0u] + row];
    uint l1 = tree1[column_offsets[1u] + row];
    uint l2 = tree1[column_offsets[2u] + row];
    uint l3 = tree1[column_offsets[3u] + row];
    uint l4 = tree1[column_offsets[4u] + row];
    uint l5 = tree1[column_offsets[5u] + row];
    uint l6 = tree1[column_offsets[6u] + row];
    uint l7 = tree1[column_offsets[7u] + row];
    uint l8 = tree1[column_offsets[8u] + row];
    uint l9 = tree1[column_offsets[9u] + row];
    uint l10 = tree1[column_offsets[10u] + row];
    uint l11 = tree1[column_offsets[11u] + row];
    uint l12 = tree0[column_offsets[12u] + row];
    uint l13 = tree0[column_offsets[13u] + row];
    uint l14 = tree0[column_offsets[14u] + row];
    uint l15 = tree0[column_offsets[15u] + row];
    uint l16 = tree0[column_offsets[16u] + row];
    uint l17 = tree0[column_offsets[17u] + row];
    uint l18 = 2u;
    uint l19 = riscv_m31_neg(l12);
    uint l20 = riscv_m31_neg(l12);
    uint l21 = riscv_m31_neg(l12);
    uint l22 = riscv_m31_neg(l12);
    uint l23 = riscv_m31_neg(l12);
    uint l24 = riscv_m31_neg(l12);
    RiscvQm31 denominator0 = { 0u, 0u, 0u, 0u };
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 4u), l0));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 8u), l4));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 12u), l8));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 16u), l18));
    denominator0 = riscv_qm_sub(denominator0, riscv_load_qm31(relation_parameters, 0u));
    RiscvQm31 denominator1 = { 0u, 0u, 0u, 0u };
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 24u), l1));
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 28u), l5));
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 32u), l9));
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 36u), l18));
    denominator1 = riscv_qm_sub(denominator1, riscv_load_qm31(relation_parameters, 20u));
    RiscvQm31 denominator2 = { 0u, 0u, 0u, 0u };
    denominator2 = riscv_qm_add(denominator2, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 44u), l2));
    denominator2 = riscv_qm_add(denominator2, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 48u), l6));
    denominator2 = riscv_qm_add(denominator2, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 52u), l10));
    denominator2 = riscv_qm_add(denominator2, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 56u), l18));
    denominator2 = riscv_qm_sub(denominator2, riscv_load_qm31(relation_parameters, 40u));
    RiscvQm31 denominator3 = { 0u, 0u, 0u, 0u };
    denominator3 = riscv_qm_add(denominator3, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 64u), l3));
    denominator3 = riscv_qm_add(denominator3, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 68u), l7));
    denominator3 = riscv_qm_add(denominator3, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 72u), l11));
    denominator3 = riscv_qm_add(denominator3, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 76u), l18));
    denominator3 = riscv_qm_sub(denominator3, riscv_load_qm31(relation_parameters, 60u));
    RiscvQm31 denominator4 = { 0u, 0u, 0u, 0u };
    denominator4 = riscv_qm_add(denominator4, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 84u), l13));
    denominator4 = riscv_qm_add(denominator4, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 88u), l14));
    denominator4 = riscv_qm_add(denominator4, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 92u), l0));
    denominator4 = riscv_qm_add(denominator4, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 96u), l1));
    denominator4 = riscv_qm_add(denominator4, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 100u), l2));
    denominator4 = riscv_qm_add(denominator4, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 104u), l3));
    denominator4 = riscv_qm_sub(denominator4, riscv_load_qm31(relation_parameters, 80u));
    RiscvQm31 denominator5 = { 0u, 0u, 0u, 0u };
    denominator5 = riscv_qm_add(denominator5, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 112u), l13));
    denominator5 = riscv_qm_add(denominator5, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 116u), l15));
    denominator5 = riscv_qm_add(denominator5, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 120u), l4));
    denominator5 = riscv_qm_add(denominator5, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 124u), l5));
    denominator5 = riscv_qm_add(denominator5, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 128u), l6));
    denominator5 = riscv_qm_add(denominator5, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 132u), l7));
    denominator5 = riscv_qm_sub(denominator5, riscv_load_qm31(relation_parameters, 108u));
    RiscvQm31 denominator6 = { 0u, 0u, 0u, 0u };
    denominator6 = riscv_qm_add(denominator6, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 140u), l13));
    denominator6 = riscv_qm_add(denominator6, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 144u), l16));
    denominator6 = riscv_qm_add(denominator6, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 148u), l8));
    denominator6 = riscv_qm_add(denominator6, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 152u), l9));
    denominator6 = riscv_qm_add(denominator6, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 156u), l10));
    denominator6 = riscv_qm_add(denominator6, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 160u), l11));
    denominator6 = riscv_qm_sub(denominator6, riscv_load_qm31(relation_parameters, 136u));
 RiscvQm31 cumulative={0u,0u,0u,0u};
 RiscvQm31 n0 = riscv_qm_add(riscv_qm_mul_base(denominator1,l19),riscv_qm_mul_base(denominator0,l20)), d0 = riscv_qm_mul(denominator0,denominator1);
 if ((d0.a|d0.b|d0.c|d0.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
 RiscvQm31 f0 = riscv_qm_mul(n0,framework_interaction_inverse(d0));
 cumulative=riscv_qm_add(cumulative,f0);
 framework_interaction_store(output,row_count,0u,row,cumulative);
 RiscvQm31 n1 = riscv_qm_add(riscv_qm_mul_base(denominator3,l21),riscv_qm_mul_base(denominator2,l22)), d1 = riscv_qm_mul(denominator2,denominator3);
 if ((d1.a|d1.b|d1.c|d1.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
 RiscvQm31 f1 = riscv_qm_mul(n1,framework_interaction_inverse(d1));
 cumulative=riscv_qm_add(cumulative,f1);
 framework_interaction_store(output,row_count,1u,row,cumulative);
 RiscvQm31 n2 = riscv_qm_add(riscv_qm_mul_base(denominator5,l23),riscv_qm_mul_base(denominator4,l24)), d2 = riscv_qm_mul(denominator4,denominator5);
 if ((d2.a|d2.b|d2.c|d2.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
 RiscvQm31 f2 = riscv_qm_mul(n2,framework_interaction_inverse(d2));
 cumulative=riscv_qm_add(cumulative,f2);
 framework_interaction_store(output,row_count,2u,row,cumulative);
 RiscvQm31 n3 = {l17,0u,0u,0u}, d3 = denominator6;
 if ((d3.a|d3.b|d3.c|d3.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
 RiscvQm31 f3 = riscv_qm_mul(n3,framework_interaction_inverse(d3));
 cumulative=riscv_qm_add(cumulative,f3);
 framework_interaction_store(output,row_count,3u,row,cumulative);
}
kernel void stwo_zig_framework_interaction_v1_1da43de062b46ceaa5e04a77f429f3466050cfca52f6b1830a1133298130c20f(
 device const uint *tree0 [[buffer(0)]], device const uint *tree1 [[buffer(1)]],
 device const ulong *column_offsets [[buffer(2)]], device const uint *profile_parameters [[buffer(3)]],
 device const uint *relation_parameters [[buffer(4)]], device uint *output [[buffer(5)]],
 device atomic_uint *status [[buffer(6)]], constant uint &row_count [[buffer(7)]],
 uint row [[thread_position_in_grid]]) {
 if (row >= row_count) return;
 if (tree1[column_offsets[0u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[1u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[2u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[3u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[4u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[5u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[6u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[7u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[8u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[9u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[10u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[11u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
    uint l0 = tree1[column_offsets[0u] + row];
    uint l1 = tree1[column_offsets[1u] + row];
    uint l2 = tree1[column_offsets[2u] + row];
    uint l3 = tree1[column_offsets[3u] + row];
    uint l5 = tree0[column_offsets[5u] + row];
    uint l6 = tree0[column_offsets[6u] + row];
    uint l7 = tree0[column_offsets[7u] + row];
    RiscvQm31 denominator0 = { 0u, 0u, 0u, 0u };
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 4u), l5));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 8u), l6));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 12u), l0));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 16u), l1));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 20u), l2));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 24u), l3));
    denominator0 = riscv_qm_sub(denominator0, riscv_load_qm31(relation_parameters, 0u));
 RiscvQm31 cumulative={0u,0u,0u,0u};
 RiscvQm31 n0 = {l7,0u,0u,0u}, d0 = denominator0;
 if ((d0.a|d0.b|d0.c|d0.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
 RiscvQm31 f0 = riscv_qm_mul(n0,framework_interaction_inverse(d0));
 cumulative=riscv_qm_add(cumulative,f0);
 framework_interaction_store(output,row_count,0u,row,cumulative);
}
kernel void stwo_zig_framework_interaction_v1_ace96d9a45c208b9f233bb27ac73ce6147a91ad9df4301b9f1aff166fef6c9c4(
 device const uint *tree0 [[buffer(0)]], device const uint *tree1 [[buffer(1)]],
 device const ulong *column_offsets [[buffer(2)]], device const uint *profile_parameters [[buffer(3)]],
 device const uint *relation_parameters [[buffer(4)]], device uint *output [[buffer(5)]],
 device atomic_uint *status [[buffer(6)]], constant uint &row_count [[buffer(7)]],
 uint row [[thread_position_in_grid]]) {
 if (row >= row_count) return;
 if (tree1[column_offsets[0u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[1u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[2u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[3u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[4u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[5u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[6u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[7u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[8u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[9u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[10u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[11u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[12u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[13u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[14u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[15u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[16u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[17u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[18u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[19u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[20u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[21u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[22u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[23u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[24u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[25u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[26u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[27u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[28u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[29u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[30u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[31u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[32u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[33u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[34u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[35u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[36u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[37u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[38u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[39u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[40u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[41u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[42u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[43u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[44u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[45u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[46u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[47u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[48u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[49u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[50u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[51u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[52u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[53u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[54u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[55u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[56u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
    uint l0 = tree1[column_offsets[0u] + row];
    uint l1 = tree1[column_offsets[1u] + row];
    uint l2 = tree1[column_offsets[2u] + row];
    uint l3 = tree1[column_offsets[3u] + row];
    uint l4 = tree1[column_offsets[4u] + row];
    uint l5 = tree1[column_offsets[5u] + row];
    uint l6 = tree1[column_offsets[6u] + row];
    uint l7 = tree1[column_offsets[7u] + row];
    uint l8 = tree1[column_offsets[8u] + row];
    uint l9 = tree1[column_offsets[9u] + row];
    uint l10 = tree1[column_offsets[10u] + row];
    uint l11 = tree1[column_offsets[11u] + row];
    uint l12 = tree0[column_offsets[12u] + row];
    uint l13 = tree0[column_offsets[13u] + row];
    uint l14 = tree0[column_offsets[14u] + row];
    uint l15 = tree0[column_offsets[15u] + row];
    uint l16 = tree0[column_offsets[16u] + row];
    uint l17 = tree0[column_offsets[17u] + row];
    uint l18 = tree0[column_offsets[18u] + row];
    uint l19 = tree0[column_offsets[19u] + row];
    uint l20 = tree0[column_offsets[20u] + row];
    uint l57 = riscv_m31_neg(l12);
    uint l58 = riscv_m31_neg(l13);
    RiscvQm31 denominator0 = { 0u, 0u, 0u, 0u };
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 4u), l14));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 8u), l15));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 12u), l0));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 16u), l1));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 20u), l2));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 24u), l3));
    denominator0 = riscv_qm_sub(denominator0, riscv_load_qm31(relation_parameters, 0u));
    RiscvQm31 denominator1 = { 0u, 0u, 0u, 0u };
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 32u), l16));
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 36u), l17));
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 40u), l4));
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 44u), l5));
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 48u), l6));
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 52u), l7));
    denominator1 = riscv_qm_sub(denominator1, riscv_load_qm31(relation_parameters, 28u));
    RiscvQm31 denominator2 = { 0u, 0u, 0u, 0u };
    denominator2 = riscv_qm_add(denominator2, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 60u), l18));
    denominator2 = riscv_qm_add(denominator2, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 64u), l19));
    denominator2 = riscv_qm_add(denominator2, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 68u), l8));
    denominator2 = riscv_qm_add(denominator2, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 72u), l9));
    denominator2 = riscv_qm_add(denominator2, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 76u), l10));
    denominator2 = riscv_qm_add(denominator2, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 80u), l11));
    denominator2 = riscv_qm_sub(denominator2, riscv_load_qm31(relation_parameters, 56u));
 RiscvQm31 cumulative={0u,0u,0u,0u};
 RiscvQm31 n0 = riscv_qm_add(riscv_qm_mul_base(denominator1,l57),riscv_qm_mul_base(denominator0,l58)), d0 = riscv_qm_mul(denominator0,denominator1);
 if ((d0.a|d0.b|d0.c|d0.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
 RiscvQm31 f0 = riscv_qm_mul(n0,framework_interaction_inverse(d0));
 cumulative=riscv_qm_add(cumulative,f0);
 framework_interaction_store(output,row_count,0u,row,cumulative);
 RiscvQm31 n1 = {l20,0u,0u,0u}, d1 = denominator2;
 if ((d1.a|d1.b|d1.c|d1.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
 RiscvQm31 f1 = riscv_qm_mul(n1,framework_interaction_inverse(d1));
 cumulative=riscv_qm_add(cumulative,f1);
 framework_interaction_store(output,row_count,1u,row,cumulative);
}
kernel void stwo_zig_framework_interaction_v1_91d5fa87688b8c993ffca44fbb0679d02b25139fd1f538482c23d08bbfa7dec7(
 device const uint *tree0 [[buffer(0)]], device const uint *tree1 [[buffer(1)]],
 device const ulong *column_offsets [[buffer(2)]], device const uint *profile_parameters [[buffer(3)]],
 device const uint *relation_parameters [[buffer(4)]], device uint *output [[buffer(5)]],
 device atomic_uint *status [[buffer(6)]], constant uint &row_count [[buffer(7)]],
 uint row [[thread_position_in_grid]]) {
 if (row >= row_count) return;
 if (tree1[column_offsets[0u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[1u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[2u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[3u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[4u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[5u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[6u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[7u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
    uint l0 = tree1[column_offsets[0u] + row];
    uint l1 = tree1[column_offsets[1u] + row];
    uint l2 = tree1[column_offsets[2u] + row];
    uint l3 = tree1[column_offsets[3u] + row];
    uint l4 = tree0[column_offsets[4u] + row];
    uint l5 = tree0[column_offsets[5u] + row];
    uint l6 = tree0[column_offsets[6u] + row];
    uint l7 = tree0[column_offsets[7u] + row];
    uint l8 = riscv_m31_neg(l4);
    uint l9 = riscv_m31_neg(l4);
    RiscvQm31 denominator0 = { 0u, 0u, 0u, 0u };
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 4u), l5));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 8u), l6));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 12u), l0));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 16u), l1));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 20u), l2));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 24u), l3));
    denominator0 = riscv_qm_sub(denominator0, riscv_load_qm31(relation_parameters, 0u));
    RiscvQm31 denominator1 = { 0u, 0u, 0u, 0u };
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 32u), l0));
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 36u), l1));
    denominator1 = riscv_qm_sub(denominator1, riscv_load_qm31(relation_parameters, 28u));
    RiscvQm31 denominator2 = { 0u, 0u, 0u, 0u };
    denominator2 = riscv_qm_add(denominator2, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 44u), l2));
    denominator2 = riscv_qm_add(denominator2, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 48u), l3));
    denominator2 = riscv_qm_sub(denominator2, riscv_load_qm31(relation_parameters, 40u));
 RiscvQm31 cumulative={0u,0u,0u,0u};
 RiscvQm31 n0 = riscv_qm_add(riscv_qm_mul_base(denominator1,l7),riscv_qm_mul_base(denominator0,l8)), d0 = riscv_qm_mul(denominator0,denominator1);
 if ((d0.a|d0.b|d0.c|d0.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
 RiscvQm31 f0 = riscv_qm_mul(n0,framework_interaction_inverse(d0));
 cumulative=riscv_qm_add(cumulative,f0);
 framework_interaction_store(output,row_count,0u,row,cumulative);
 RiscvQm31 n1 = {l9,0u,0u,0u}, d1 = denominator2;
 if ((d1.a|d1.b|d1.c|d1.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
 RiscvQm31 f1 = riscv_qm_mul(n1,framework_interaction_inverse(d1));
 cumulative=riscv_qm_add(cumulative,f1);
 framework_interaction_store(output,row_count,1u,row,cumulative);
}
kernel void stwo_zig_framework_interaction_v1_a20d43085e9946c62dae85cfd655f90cfd044884b022408cc301aad58f77d860(
 device const uint *tree0 [[buffer(0)]], device const uint *tree1 [[buffer(1)]],
 device const ulong *column_offsets [[buffer(2)]], device const uint *profile_parameters [[buffer(3)]],
 device const uint *relation_parameters [[buffer(4)]], device uint *output [[buffer(5)]],
 device atomic_uint *status [[buffer(6)]], constant uint &row_count [[buffer(7)]],
 uint row [[thread_position_in_grid]]) {
 if (row >= row_count) return;
 if (tree1[column_offsets[0u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[1u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[2u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[3u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[4u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[5u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[6u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[7u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[8u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[9u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[10u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[11u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[12u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[13u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
    uint l0 = tree1[column_offsets[0u] + row];
    uint l1 = tree1[column_offsets[1u] + row];
    uint l2 = tree1[column_offsets[2u] + row];
    uint l3 = tree1[column_offsets[3u] + row];
    uint l4 = tree0[column_offsets[4u] + row];
    uint l5 = tree0[column_offsets[5u] + row];
    uint l6 = tree0[column_offsets[6u] + row];
    uint l7 = tree0[column_offsets[7u] + row];
    uint l8 = tree0[column_offsets[8u] + row];
    uint l9 = tree0[column_offsets[9u] + row];
    uint l14 = riscv_m31_neg(l4);
    RiscvQm31 denominator0 = { 0u, 0u, 0u, 0u };
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 4u), l5));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 8u), l6));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 12u), l0));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 16u), l1));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 20u), l2));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 24u), l3));
    denominator0 = riscv_qm_sub(denominator0, riscv_load_qm31(relation_parameters, 0u));
    RiscvQm31 denominator1 = { 0u, 0u, 0u, 0u };
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 32u), l7));
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 36u), l8));
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 40u), l0));
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 44u), l1));
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 48u), l2));
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 52u), l3));
    denominator1 = riscv_qm_sub(denominator1, riscv_load_qm31(relation_parameters, 28u));
 RiscvQm31 cumulative={0u,0u,0u,0u};
 RiscvQm31 n0 = riscv_qm_add(riscv_qm_mul_base(denominator1,l14),riscv_qm_mul_base(denominator0,l9)), d0 = riscv_qm_mul(denominator0,denominator1);
 if ((d0.a|d0.b|d0.c|d0.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
 RiscvQm31 f0 = riscv_qm_mul(n0,framework_interaction_inverse(d0));
 cumulative=riscv_qm_add(cumulative,f0);
 framework_interaction_store(output,row_count,0u,row,cumulative);
}
kernel void stwo_zig_framework_interaction_v1_f3062cacdbdc4475a2eb63fe1632cdea209bea7f6b52826d0373f4281b5e0f69(
 device const uint *tree0 [[buffer(0)]], device const uint *tree1 [[buffer(1)]],
 device const ulong *column_offsets [[buffer(2)]], device const uint *profile_parameters [[buffer(3)]],
 device const uint *relation_parameters [[buffer(4)]], device uint *output [[buffer(5)]],
 device atomic_uint *status [[buffer(6)]], constant uint &row_count [[buffer(7)]],
 uint row [[thread_position_in_grid]]) {
 if (row >= row_count) return;
 if (tree1[column_offsets[0u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[1u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[2u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree1[column_offsets[3u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[4u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[5u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[6u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[7u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[8u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[9u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[10u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
    uint l0 = tree1[column_offsets[0u] + row];
    uint l1 = tree1[column_offsets[1u] + row];
    uint l2 = tree1[column_offsets[2u] + row];
    uint l3 = tree1[column_offsets[3u] + row];
    uint l4 = tree0[column_offsets[4u] + row];
    uint l5 = tree0[column_offsets[5u] + row];
    uint l6 = tree0[column_offsets[6u] + row];
    uint l7 = tree0[column_offsets[7u] + row];
    uint l8 = tree0[column_offsets[8u] + row];
    uint l9 = tree0[column_offsets[9u] + row];
    uint l10 = tree0[column_offsets[10u] + row];
    uint l11 = 1u;
    uint l12 = riscv_m31_neg(l4);
    uint l13 = riscv_m31_neg(l4);
    RiscvQm31 denominator0 = { 0u, 0u, 0u, 0u };
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 4u), l11));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 8u), l5));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 12u), l6));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 16u), l0));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 20u), l1));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 24u), l2));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 28u), l3));
    denominator0 = riscv_qm_sub(denominator0, riscv_load_qm31(relation_parameters, 0u));
    RiscvQm31 denominator1 = { 0u, 0u, 0u, 0u };
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 36u), l0));
    denominator1 = riscv_qm_add(denominator1, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 40u), l1));
    denominator1 = riscv_qm_sub(denominator1, riscv_load_qm31(relation_parameters, 32u));
    RiscvQm31 denominator2 = { 0u, 0u, 0u, 0u };
    denominator2 = riscv_qm_add(denominator2, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 48u), l2));
    denominator2 = riscv_qm_add(denominator2, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 52u), l3));
    denominator2 = riscv_qm_sub(denominator2, riscv_load_qm31(relation_parameters, 44u));
    RiscvQm31 denominator3 = { 0u, 0u, 0u, 0u };
    denominator3 = riscv_qm_add(denominator3, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 60u), l8));
    denominator3 = riscv_qm_add(denominator3, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 64u), l9));
    denominator3 = riscv_qm_add(denominator3, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 68u), l0));
    denominator3 = riscv_qm_add(denominator3, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 72u), l1));
    denominator3 = riscv_qm_add(denominator3, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 76u), l2));
    denominator3 = riscv_qm_add(denominator3, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 80u), l3));
    denominator3 = riscv_qm_sub(denominator3, riscv_load_qm31(relation_parameters, 56u));
 RiscvQm31 cumulative={0u,0u,0u,0u};
 RiscvQm31 n0 = riscv_qm_add(riscv_qm_mul_base(denominator1,l7),riscv_qm_mul_base(denominator0,l12)), d0 = riscv_qm_mul(denominator0,denominator1);
 if ((d0.a|d0.b|d0.c|d0.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
 RiscvQm31 f0 = riscv_qm_mul(n0,framework_interaction_inverse(d0));
 cumulative=riscv_qm_add(cumulative,f0);
 framework_interaction_store(output,row_count,0u,row,cumulative);
 RiscvQm31 n1 = riscv_qm_add(riscv_qm_mul_base(denominator3,l13),riscv_qm_mul_base(denominator2,l10)), d1 = riscv_qm_mul(denominator2,denominator3);
 if ((d1.a|d1.b|d1.c|d1.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
 RiscvQm31 f1 = riscv_qm_mul(n1,framework_interaction_inverse(d1));
 cumulative=riscv_qm_add(cumulative,f1);
 framework_interaction_store(output,row_count,1u,row,cumulative);
}
kernel void stwo_zig_framework_interaction_v1_75a8d6628aa611590f73e1140e4d07eb773e0a4b856497959812210fd52bfdb1(
 device const uint *tree0 [[buffer(0)]], device const uint *tree1 [[buffer(1)]],
 device const ulong *column_offsets [[buffer(2)]], device const uint *profile_parameters [[buffer(3)]],
 device const uint *relation_parameters [[buffer(4)]], device uint *output [[buffer(5)]],
 device atomic_uint *status [[buffer(6)]], constant uint &row_count [[buffer(7)]],
 uint row [[thread_position_in_grid]]) {
 if (row >= row_count) return;
 if (tree0[column_offsets[0u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[1u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[2u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[3u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[4u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
 if (tree0[column_offsets[5u]+row] >= RISCV_M31_P) atomic_fetch_or_explicit(status, 4u, memory_order_relaxed);
    uint l0 = tree0[column_offsets[0u] + row];
    uint l1 = tree0[column_offsets[1u] + row];
    uint l2 = tree0[column_offsets[2u] + row];
    uint l3 = tree0[column_offsets[3u] + row];
    uint l4 = tree0[column_offsets[4u] + row];
    uint l5 = tree0[column_offsets[5u] + row];
    uint l6 = riscv_m31_neg(l5);
    RiscvQm31 denominator0 = { 0u, 0u, 0u, 0u };
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 4u), l4));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 8u), l0));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 12u), l1));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 16u), l2));
    denominator0 = riscv_qm_add(denominator0, riscv_qm_mul_base(riscv_load_qm31(relation_parameters, 20u), l3));
    denominator0 = riscv_qm_sub(denominator0, riscv_load_qm31(relation_parameters, 0u));
 RiscvQm31 cumulative={0u,0u,0u,0u};
 RiscvQm31 n0 = {l6,0u,0u,0u}, d0 = denominator0;
 if ((d0.a|d0.b|d0.c|d0.d)==0u) atomic_fetch_or_explicit(status,1u,memory_order_relaxed);
 RiscvQm31 f0 = riscv_qm_mul(n0,framework_interaction_inverse(d0));
 cumulative=riscv_qm_add(cumulative,f0);
 framework_interaction_store(output,row_count,0u,row,cumulative);
}
