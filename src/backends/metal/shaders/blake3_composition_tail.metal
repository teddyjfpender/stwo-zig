kernel void stwo_zig_framework_poly_v1_14fd127befc138e59e7bd018171534722c4e35f018f049ff3411bbb987bbd92f(
    device const uint *tree0 [[buffer(0)]],
    device const uint *tree1 [[buffer(1)]],
    device const uint *tree2 [[buffer(2)]],
    device const ulong *column_offsets [[buffer(3)]],
    device const uint *profile_parameters [[buffer(4)]],
    device const uint *relation_parameters [[buffer(5)]],
    device const uint *powers [[buffer(6)]],
    device uint *output [[buffer(7)]],
    constant uint &row_count [[buffer(8)]],
    constant uint *denominator_inverses [[buffer(9)]],
    constant uint &denominator_count [[buffer(10)]],
    uint row [[thread_position_in_grid]]) {
    if (row >= row_count) return;
    uint previous_row = riscv_previous_circle_row(row, row_count, denominator_count);
    RiscvQm31 folded = { 0u, 0u, 0u, 0u };
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
    RiscvQm31 current0 = { tree2[column_offsets[18u] + row], tree2[column_offsets[19u] + row], tree2[column_offsets[20u] + row], tree2[column_offsets[21u] + row] };
    RiscvQm31 delta0 = current0;
    RiscvQm31 constraint0 = riscv_qm_sub(riscv_qm_sub(riscv_qm_mul(riscv_qm_mul(delta0, denominator0), denominator1), riscv_qm_mul_base(denominator1, l19)), riscv_qm_mul_base(denominator0, l20));
    folded = riscv_qm_add(folded, riscv_qm_mul(riscv_load_qm31(powers, 12u), constraint0));
    RiscvQm31 current1 = { tree2[column_offsets[22u] + row], tree2[column_offsets[23u] + row], tree2[column_offsets[24u] + row], tree2[column_offsets[25u] + row] };
    RiscvQm31 delta1 = riscv_qm_sub(current1, current0);
    RiscvQm31 constraint1 = riscv_qm_sub(riscv_qm_sub(riscv_qm_mul(riscv_qm_mul(delta1, denominator2), denominator3), riscv_qm_mul_base(denominator3, l21)), riscv_qm_mul_base(denominator2, l22));
    folded = riscv_qm_add(folded, riscv_qm_mul(riscv_load_qm31(powers, 8u), constraint1));
    RiscvQm31 current2 = { tree2[column_offsets[26u] + row], tree2[column_offsets[27u] + row], tree2[column_offsets[28u] + row], tree2[column_offsets[29u] + row] };
    RiscvQm31 delta2 = riscv_qm_sub(current2, current1);
    RiscvQm31 constraint2 = riscv_qm_sub(riscv_qm_sub(riscv_qm_mul(riscv_qm_mul(delta2, denominator4), denominator5), riscv_qm_mul_base(denominator5, l23)), riscv_qm_mul_base(denominator4, l24));
    folded = riscv_qm_add(folded, riscv_qm_mul(riscv_load_qm31(powers, 4u), constraint2));
    RiscvQm31 current3 = { tree2[column_offsets[30u] + row], tree2[column_offsets[31u] + row], tree2[column_offsets[32u] + row], tree2[column_offsets[33u] + row] };
    RiscvQm31 delta3 = riscv_qm_sub(current3, current2);
    RiscvQm31 previous3 = { tree2[column_offsets[30u] + previous_row], tree2[column_offsets[31u] + previous_row], tree2[column_offsets[32u] + previous_row], tree2[column_offsets[33u] + previous_row] };
    delta3 = riscv_qm_add(riscv_qm_sub(delta3, previous3), riscv_load_qm31(relation_parameters, 164u));
    RiscvQm31 constraint3 = riscv_qm_sub(riscv_qm_mul(delta3, denominator6), RiscvQm31{ l17, 0u, 0u, 0u });
    folded = riscv_qm_add(folded, riscv_qm_mul(riscv_load_qm31(powers, 0u), constraint3));
    uint denominator_index = row / (row_count / denominator_count);
    RiscvQm31 result = riscv_qm_mul_base(folded, denominator_inverses[denominator_index]);
    output[riscv_column_offset(0u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(0u, row_count, row)], result.a);
    output[riscv_column_offset(1u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(1u, row_count, row)], result.b);
    output[riscv_column_offset(2u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(2u, row_count, row)], result.c);
    output[riscv_column_offset(3u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(3u, row_count, row)], result.d);
}
kernel void stwo_zig_framework_poly_v1_3cf90e2e9f42306556486b60b704dacd35b2ae0ca8e8dc82d094c24e878dec08(
    device const uint *tree0 [[buffer(0)]],
    device const uint *tree1 [[buffer(1)]],
    device const uint *tree2 [[buffer(2)]],
    device const ulong *column_offsets [[buffer(3)]],
    device const uint *profile_parameters [[buffer(4)]],
    device const uint *relation_parameters [[buffer(5)]],
    device const uint *powers [[buffer(6)]],
    device uint *output [[buffer(7)]],
    constant uint &row_count [[buffer(8)]],
    constant uint *denominator_inverses [[buffer(9)]],
    constant uint &denominator_count [[buffer(10)]],
    uint row [[thread_position_in_grid]]) {
    if (row >= row_count) return;
    uint previous_row = riscv_previous_circle_row(row, row_count, denominator_count);
    RiscvQm31 folded = { 0u, 0u, 0u, 0u };
    uint d0 = tree1[column_offsets[0u] + row];
    uint d1 = tree1[column_offsets[1u] + row];
    uint d2 = tree1[column_offsets[2u] + row];
    uint d3 = tree1[column_offsets[3u] + row];
    uint d4 = tree0[column_offsets[4u] + row];
    uint d8 = tree0[column_offsets[8u] + row];
    uint d9 = tree0[column_offsets[9u] + row];
    uint d10 = tree0[column_offsets[10u] + row];
    uint d11 = tree0[column_offsets[11u] + row];
    uint d12 = riscv_m31_sub(d0, d8);
    uint d13 = riscv_m31_mul(d4, d12);
    folded = riscv_qm_add(folded, riscv_qm_mul_base(riscv_load_qm31(powers, 16u), d13));
    uint d14 = riscv_m31_sub(d1, d9);
    uint d15 = riscv_m31_mul(d4, d14);
    folded = riscv_qm_add(folded, riscv_qm_mul_base(riscv_load_qm31(powers, 12u), d15));
    uint d16 = riscv_m31_sub(d2, d10);
    uint d17 = riscv_m31_mul(d4, d16);
    folded = riscv_qm_add(folded, riscv_qm_mul_base(riscv_load_qm31(powers, 8u), d17));
    uint d18 = riscv_m31_sub(d3, d11);
    uint d19 = riscv_m31_mul(d4, d18);
    folded = riscv_qm_add(folded, riscv_qm_mul_base(riscv_load_qm31(powers, 4u), d19));
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
    RiscvQm31 current0 = { tree2[column_offsets[12u] + row], tree2[column_offsets[13u] + row], tree2[column_offsets[14u] + row], tree2[column_offsets[15u] + row] };
    RiscvQm31 delta0 = current0;
    RiscvQm31 previous0 = { tree2[column_offsets[12u] + previous_row], tree2[column_offsets[13u] + previous_row], tree2[column_offsets[14u] + previous_row], tree2[column_offsets[15u] + previous_row] };
    delta0 = riscv_qm_add(riscv_qm_sub(delta0, previous0), riscv_load_qm31(relation_parameters, 28u));
    RiscvQm31 constraint0 = riscv_qm_sub(riscv_qm_mul(delta0, denominator0), RiscvQm31{ l7, 0u, 0u, 0u });
    folded = riscv_qm_add(folded, riscv_qm_mul(riscv_load_qm31(powers, 0u), constraint0));
    uint denominator_index = row / (row_count / denominator_count);
    RiscvQm31 result = riscv_qm_mul_base(folded, denominator_inverses[denominator_index]);
    output[riscv_column_offset(0u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(0u, row_count, row)], result.a);
    output[riscv_column_offset(1u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(1u, row_count, row)], result.b);
    output[riscv_column_offset(2u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(2u, row_count, row)], result.c);
    output[riscv_column_offset(3u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(3u, row_count, row)], result.d);
}
kernel void stwo_zig_framework_poly_v1_f75d65c0d545ba7c86fe825fd6bb72cc3206fd05d304b008bac279fa5364ded7(
    device const uint *tree0 [[buffer(0)]],
    device const uint *tree1 [[buffer(1)]],
    device const uint *tree2 [[buffer(2)]],
    device const ulong *column_offsets [[buffer(3)]],
    device const uint *profile_parameters [[buffer(4)]],
    device const uint *relation_parameters [[buffer(5)]],
    device const uint *powers [[buffer(6)]],
    device uint *output [[buffer(7)]],
    constant uint &row_count [[buffer(8)]],
    constant uint *denominator_inverses [[buffer(9)]],
    constant uint &denominator_count [[buffer(10)]],
    uint row [[thread_position_in_grid]]) {
    if (row >= row_count) return;
    uint previous_row = riscv_previous_circle_row(row, row_count, denominator_count);
    RiscvQm31 folded = { 0u, 0u, 0u, 0u };
    uint d0 = tree1[column_offsets[0u] + row];
    uint d1 = tree1[column_offsets[1u] + row];
    uint d2 = tree1[column_offsets[2u] + row];
    uint d3 = tree1[column_offsets[3u] + row];
    uint d4 = tree1[column_offsets[4u] + row];
    uint d5 = tree1[column_offsets[5u] + row];
    uint d6 = tree1[column_offsets[6u] + row];
    uint d7 = tree1[column_offsets[7u] + row];
    uint d8 = tree1[column_offsets[8u] + row];
    uint d9 = tree1[column_offsets[9u] + row];
    uint d10 = tree1[column_offsets[10u] + row];
    uint d11 = tree1[column_offsets[11u] + row];
    uint d21 = tree0[column_offsets[21u] + row];
    uint d22 = tree0[column_offsets[22u] + row];
    uint d23 = tree0[column_offsets[23u] + row];
    uint d24 = tree0[column_offsets[24u] + row];
    uint d25 = tree0[column_offsets[25u] + row];
    uint d26 = tree0[column_offsets[26u] + row];
    uint d27 = tree0[column_offsets[27u] + row];
    uint d28 = tree0[column_offsets[28u] + row];
    uint d29 = tree0[column_offsets[29u] + row];
    uint d30 = tree0[column_offsets[30u] + row];
    uint d31 = tree0[column_offsets[31u] + row];
    uint d32 = tree0[column_offsets[32u] + row];
    uint d33 = tree0[column_offsets[33u] + row];
    uint d34 = tree0[column_offsets[34u] + row];
    uint d35 = tree0[column_offsets[35u] + row];
    uint d36 = tree0[column_offsets[36u] + row];
    uint d37 = tree0[column_offsets[37u] + row];
    uint d38 = tree0[column_offsets[38u] + row];
    uint d39 = tree0[column_offsets[39u] + row];
    uint d40 = tree0[column_offsets[40u] + row];
    uint d41 = tree0[column_offsets[41u] + row];
    uint d42 = tree0[column_offsets[42u] + row];
    uint d43 = tree0[column_offsets[43u] + row];
    uint d44 = tree0[column_offsets[44u] + row];
    uint d45 = tree0[column_offsets[45u] + row];
    uint d46 = tree0[column_offsets[46u] + row];
    uint d47 = tree0[column_offsets[47u] + row];
    uint d48 = tree0[column_offsets[48u] + row];
    uint d49 = tree0[column_offsets[49u] + row];
    uint d50 = tree0[column_offsets[50u] + row];
    uint d51 = tree0[column_offsets[51u] + row];
    uint d52 = tree0[column_offsets[52u] + row];
    uint d53 = tree0[column_offsets[53u] + row];
    uint d54 = tree0[column_offsets[54u] + row];
    uint d55 = tree0[column_offsets[55u] + row];
    uint d56 = tree0[column_offsets[56u] + row];
    uint d57 = riscv_m31_mul(d0, d25);
    uint d58 = riscv_m31_add(d21, d57);
    uint d59 = riscv_m31_mul(d1, d26);
    uint d60 = riscv_m31_add(d58, d59);
    uint d61 = riscv_m31_mul(d2, d27);
    uint d62 = riscv_m31_add(d60, d61);
    uint d63 = riscv_m31_mul(d3, d28);
    uint d64 = riscv_m31_add(d62, d63);
    uint d65 = riscv_m31_mul(d4, d29);
    uint d66 = riscv_m31_add(d64, d65);
    uint d67 = riscv_m31_mul(d5, d30);
    uint d68 = riscv_m31_add(d66, d67);
    uint d69 = riscv_m31_mul(d6, d31);
    uint d70 = riscv_m31_add(d68, d69);
    uint d71 = riscv_m31_mul(d7, d32);
    uint d72 = riscv_m31_add(d70, d71);
    uint d73 = riscv_m31_sub(d8, d72);
    folded = riscv_qm_add(folded, riscv_qm_mul_base(riscv_load_qm31(powers, 20u), d73));
    uint d74 = riscv_m31_mul(d0, d33);
    uint d75 = riscv_m31_add(d22, d74);
    uint d76 = riscv_m31_mul(d1, d34);
    uint d77 = riscv_m31_add(d75, d76);
    uint d78 = riscv_m31_mul(d2, d35);
    uint d79 = riscv_m31_add(d77, d78);
    uint d80 = riscv_m31_mul(d3, d36);
    uint d81 = riscv_m31_add(d79, d80);
    uint d82 = riscv_m31_mul(d4, d37);
    uint d83 = riscv_m31_add(d81, d82);
    uint d84 = riscv_m31_mul(d5, d38);
    uint d85 = riscv_m31_add(d83, d84);
    uint d86 = riscv_m31_mul(d6, d39);
    uint d87 = riscv_m31_add(d85, d86);
    uint d88 = riscv_m31_mul(d7, d40);
    uint d89 = riscv_m31_add(d87, d88);
    uint d90 = riscv_m31_sub(d9, d89);
    folded = riscv_qm_add(folded, riscv_qm_mul_base(riscv_load_qm31(powers, 16u), d90));
    uint d91 = riscv_m31_mul(d0, d41);
    uint d92 = riscv_m31_add(d23, d91);
    uint d93 = riscv_m31_mul(d1, d42);
    uint d94 = riscv_m31_add(d92, d93);
    uint d95 = riscv_m31_mul(d2, d43);
    uint d96 = riscv_m31_add(d94, d95);
    uint d97 = riscv_m31_mul(d3, d44);
    uint d98 = riscv_m31_add(d96, d97);
    uint d99 = riscv_m31_mul(d4, d45);
    uint d100 = riscv_m31_add(d98, d99);
    uint d101 = riscv_m31_mul(d5, d46);
    uint d102 = riscv_m31_add(d100, d101);
    uint d103 = riscv_m31_mul(d6, d47);
    uint d104 = riscv_m31_add(d102, d103);
    uint d105 = riscv_m31_mul(d7, d48);
    uint d106 = riscv_m31_add(d104, d105);
    uint d107 = riscv_m31_sub(d10, d106);
    folded = riscv_qm_add(folded, riscv_qm_mul_base(riscv_load_qm31(powers, 12u), d107));
    uint d108 = riscv_m31_mul(d0, d49);
    uint d109 = riscv_m31_add(d24, d108);
    uint d110 = riscv_m31_mul(d1, d50);
    uint d111 = riscv_m31_add(d109, d110);
    uint d112 = riscv_m31_mul(d2, d51);
    uint d113 = riscv_m31_add(d111, d112);
    uint d114 = riscv_m31_mul(d3, d52);
    uint d115 = riscv_m31_add(d113, d114);
    uint d116 = riscv_m31_mul(d4, d53);
    uint d117 = riscv_m31_add(d115, d116);
    uint d118 = riscv_m31_mul(d5, d54);
    uint d119 = riscv_m31_add(d117, d118);
    uint d120 = riscv_m31_mul(d6, d55);
    uint d121 = riscv_m31_add(d119, d120);
    uint d122 = riscv_m31_mul(d7, d56);
    uint d123 = riscv_m31_add(d121, d122);
    uint d124 = riscv_m31_sub(d11, d123);
    folded = riscv_qm_add(folded, riscv_qm_mul_base(riscv_load_qm31(powers, 8u), d124));
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
    RiscvQm31 current0 = { tree2[column_offsets[57u] + row], tree2[column_offsets[58u] + row], tree2[column_offsets[59u] + row], tree2[column_offsets[60u] + row] };
    RiscvQm31 delta0 = current0;
    RiscvQm31 constraint0 = riscv_qm_sub(riscv_qm_sub(riscv_qm_mul(riscv_qm_mul(delta0, denominator0), denominator1), riscv_qm_mul_base(denominator1, l57)), riscv_qm_mul_base(denominator0, l58));
    folded = riscv_qm_add(folded, riscv_qm_mul(riscv_load_qm31(powers, 4u), constraint0));
    RiscvQm31 current1 = { tree2[column_offsets[61u] + row], tree2[column_offsets[62u] + row], tree2[column_offsets[63u] + row], tree2[column_offsets[64u] + row] };
    RiscvQm31 delta1 = riscv_qm_sub(current1, current0);
    RiscvQm31 previous1 = { tree2[column_offsets[61u] + previous_row], tree2[column_offsets[62u] + previous_row], tree2[column_offsets[63u] + previous_row], tree2[column_offsets[64u] + previous_row] };
    delta1 = riscv_qm_add(riscv_qm_sub(delta1, previous1), riscv_load_qm31(relation_parameters, 84u));
    RiscvQm31 constraint1 = riscv_qm_sub(riscv_qm_mul(delta1, denominator2), RiscvQm31{ l20, 0u, 0u, 0u });
    folded = riscv_qm_add(folded, riscv_qm_mul(riscv_load_qm31(powers, 0u), constraint1));
    uint denominator_index = row / (row_count / denominator_count);
    RiscvQm31 result = riscv_qm_mul_base(folded, denominator_inverses[denominator_index]);
    output[riscv_column_offset(0u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(0u, row_count, row)], result.a);
    output[riscv_column_offset(1u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(1u, row_count, row)], result.b);
    output[riscv_column_offset(2u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(2u, row_count, row)], result.c);
    output[riscv_column_offset(3u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(3u, row_count, row)], result.d);
}
kernel void stwo_zig_framework_poly_v1_72044ffd5100747bfbbb99fa4510e30bfabea6e957ad8af3fd7ecfcd24267fd3(
    device const uint *tree0 [[buffer(0)]],
    device const uint *tree1 [[buffer(1)]],
    device const uint *tree2 [[buffer(2)]],
    device const ulong *column_offsets [[buffer(3)]],
    device const uint *profile_parameters [[buffer(4)]],
    device const uint *relation_parameters [[buffer(5)]],
    device const uint *powers [[buffer(6)]],
    device uint *output [[buffer(7)]],
    constant uint &row_count [[buffer(8)]],
    constant uint *denominator_inverses [[buffer(9)]],
    constant uint &denominator_count [[buffer(10)]],
    uint row [[thread_position_in_grid]]) {
    if (row >= row_count) return;
    uint previous_row = riscv_previous_circle_row(row, row_count, denominator_count);
    RiscvQm31 folded = { 0u, 0u, 0u, 0u };
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
    RiscvQm31 current0 = { tree2[column_offsets[8u] + row], tree2[column_offsets[9u] + row], tree2[column_offsets[10u] + row], tree2[column_offsets[11u] + row] };
    RiscvQm31 delta0 = current0;
    RiscvQm31 constraint0 = riscv_qm_sub(riscv_qm_sub(riscv_qm_mul(riscv_qm_mul(delta0, denominator0), denominator1), riscv_qm_mul_base(denominator1, l7)), riscv_qm_mul_base(denominator0, l8));
    folded = riscv_qm_add(folded, riscv_qm_mul(riscv_load_qm31(powers, 4u), constraint0));
    RiscvQm31 current1 = { tree2[column_offsets[12u] + row], tree2[column_offsets[13u] + row], tree2[column_offsets[14u] + row], tree2[column_offsets[15u] + row] };
    RiscvQm31 delta1 = riscv_qm_sub(current1, current0);
    RiscvQm31 previous1 = { tree2[column_offsets[12u] + previous_row], tree2[column_offsets[13u] + previous_row], tree2[column_offsets[14u] + previous_row], tree2[column_offsets[15u] + previous_row] };
    delta1 = riscv_qm_add(riscv_qm_sub(delta1, previous1), riscv_load_qm31(relation_parameters, 52u));
    RiscvQm31 constraint1 = riscv_qm_sub(riscv_qm_mul(delta1, denominator2), RiscvQm31{ l9, 0u, 0u, 0u });
    folded = riscv_qm_add(folded, riscv_qm_mul(riscv_load_qm31(powers, 0u), constraint1));
    uint denominator_index = row / (row_count / denominator_count);
    RiscvQm31 result = riscv_qm_mul_base(folded, denominator_inverses[denominator_index]);
    output[riscv_column_offset(0u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(0u, row_count, row)], result.a);
    output[riscv_column_offset(1u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(1u, row_count, row)], result.b);
    output[riscv_column_offset(2u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(2u, row_count, row)], result.c);
    output[riscv_column_offset(3u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(3u, row_count, row)], result.d);
}
kernel void stwo_zig_framework_poly_v1_49cfc130b5919dcc71f5ede1ebc4670d768c75de281cbc2b61afdd57895f85d5(
    device const uint *tree0 [[buffer(0)]],
    device const uint *tree1 [[buffer(1)]],
    device const uint *tree2 [[buffer(2)]],
    device const ulong *column_offsets [[buffer(3)]],
    device const uint *profile_parameters [[buffer(4)]],
    device const uint *relation_parameters [[buffer(5)]],
    device const uint *powers [[buffer(6)]],
    device uint *output [[buffer(7)]],
    constant uint &row_count [[buffer(8)]],
    constant uint *denominator_inverses [[buffer(9)]],
    constant uint &denominator_count [[buffer(10)]],
    uint row [[thread_position_in_grid]]) {
    if (row >= row_count) return;
    uint previous_row = riscv_previous_circle_row(row, row_count, denominator_count);
    RiscvQm31 folded = { 0u, 0u, 0u, 0u };
    uint d0 = tree1[column_offsets[0u] + row];
    uint d1 = tree1[column_offsets[1u] + row];
    uint d2 = tree1[column_offsets[2u] + row];
    uint d3 = tree1[column_offsets[3u] + row];
    uint d10 = tree0[column_offsets[10u] + row];
    uint d11 = tree0[column_offsets[11u] + row];
    uint d12 = tree0[column_offsets[12u] + row];
    uint d13 = tree0[column_offsets[13u] + row];
    uint d14 = riscv_m31_mul(d0, d10);
    folded = riscv_qm_add(folded, riscv_qm_mul_base(riscv_load_qm31(powers, 16u), d14));
    uint d15 = riscv_m31_mul(d1, d11);
    folded = riscv_qm_add(folded, riscv_qm_mul_base(riscv_load_qm31(powers, 12u), d15));
    uint d16 = riscv_m31_mul(d2, d12);
    folded = riscv_qm_add(folded, riscv_qm_mul_base(riscv_load_qm31(powers, 8u), d16));
    uint d17 = riscv_m31_mul(d3, d13);
    folded = riscv_qm_add(folded, riscv_qm_mul_base(riscv_load_qm31(powers, 4u), d17));
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
    RiscvQm31 current0 = { tree2[column_offsets[14u] + row], tree2[column_offsets[15u] + row], tree2[column_offsets[16u] + row], tree2[column_offsets[17u] + row] };
    RiscvQm31 delta0 = current0;
    RiscvQm31 previous0 = { tree2[column_offsets[14u] + previous_row], tree2[column_offsets[15u] + previous_row], tree2[column_offsets[16u] + previous_row], tree2[column_offsets[17u] + previous_row] };
    delta0 = riscv_qm_add(riscv_qm_sub(delta0, previous0), riscv_load_qm31(relation_parameters, 56u));
    RiscvQm31 constraint0 = riscv_qm_sub(riscv_qm_sub(riscv_qm_mul(riscv_qm_mul(delta0, denominator0), denominator1), riscv_qm_mul_base(denominator1, l14)), riscv_qm_mul_base(denominator0, l9));
    folded = riscv_qm_add(folded, riscv_qm_mul(riscv_load_qm31(powers, 0u), constraint0));
    uint denominator_index = row / (row_count / denominator_count);
    RiscvQm31 result = riscv_qm_mul_base(folded, denominator_inverses[denominator_index]);
    output[riscv_column_offset(0u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(0u, row_count, row)], result.a);
    output[riscv_column_offset(1u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(1u, row_count, row)], result.b);
    output[riscv_column_offset(2u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(2u, row_count, row)], result.c);
    output[riscv_column_offset(3u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(3u, row_count, row)], result.d);
}
kernel void stwo_zig_framework_poly_v1_e0ee3bbc99efb45a130369bedeb3ed37a3c2b1a33ce09945ec5f47795a94726a(
    device const uint *tree0 [[buffer(0)]],
    device const uint *tree1 [[buffer(1)]],
    device const uint *tree2 [[buffer(2)]],
    device const ulong *column_offsets [[buffer(3)]],
    device const uint *profile_parameters [[buffer(4)]],
    device const uint *relation_parameters [[buffer(5)]],
    device const uint *powers [[buffer(6)]],
    device uint *output [[buffer(7)]],
    constant uint &row_count [[buffer(8)]],
    constant uint *denominator_inverses [[buffer(9)]],
    constant uint &denominator_count [[buffer(10)]],
    uint row [[thread_position_in_grid]]) {
    if (row >= row_count) return;
    uint previous_row = riscv_previous_circle_row(row, row_count, denominator_count);
    RiscvQm31 folded = { 0u, 0u, 0u, 0u };
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
    RiscvQm31 current0 = { tree2[column_offsets[11u] + row], tree2[column_offsets[12u] + row], tree2[column_offsets[13u] + row], tree2[column_offsets[14u] + row] };
    RiscvQm31 delta0 = current0;
    RiscvQm31 constraint0 = riscv_qm_sub(riscv_qm_sub(riscv_qm_mul(riscv_qm_mul(delta0, denominator0), denominator1), riscv_qm_mul_base(denominator1, l7)), riscv_qm_mul_base(denominator0, l12));
    folded = riscv_qm_add(folded, riscv_qm_mul(riscv_load_qm31(powers, 4u), constraint0));
    RiscvQm31 current1 = { tree2[column_offsets[15u] + row], tree2[column_offsets[16u] + row], tree2[column_offsets[17u] + row], tree2[column_offsets[18u] + row] };
    RiscvQm31 delta1 = riscv_qm_sub(current1, current0);
    RiscvQm31 previous1 = { tree2[column_offsets[15u] + previous_row], tree2[column_offsets[16u] + previous_row], tree2[column_offsets[17u] + previous_row], tree2[column_offsets[18u] + previous_row] };
    delta1 = riscv_qm_add(riscv_qm_sub(delta1, previous1), riscv_load_qm31(relation_parameters, 84u));
    RiscvQm31 constraint1 = riscv_qm_sub(riscv_qm_sub(riscv_qm_mul(riscv_qm_mul(delta1, denominator2), denominator3), riscv_qm_mul_base(denominator3, l13)), riscv_qm_mul_base(denominator2, l10));
    folded = riscv_qm_add(folded, riscv_qm_mul(riscv_load_qm31(powers, 0u), constraint1));
    uint denominator_index = row / (row_count / denominator_count);
    RiscvQm31 result = riscv_qm_mul_base(folded, denominator_inverses[denominator_index]);
    output[riscv_column_offset(0u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(0u, row_count, row)], result.a);
    output[riscv_column_offset(1u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(1u, row_count, row)], result.b);
    output[riscv_column_offset(2u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(2u, row_count, row)], result.c);
    output[riscv_column_offset(3u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(3u, row_count, row)], result.d);
}
kernel void stwo_zig_framework_poly_v1_64c7692789702f479217419ea05af67c8163b99191c8278fc8fca40eb12e30e0(
    device const uint *tree0 [[buffer(0)]],
    device const uint *tree1 [[buffer(1)]],
    device const uint *tree2 [[buffer(2)]],
    device const ulong *column_offsets [[buffer(3)]],
    device const uint *profile_parameters [[buffer(4)]],
    device const uint *relation_parameters [[buffer(5)]],
    device const uint *powers [[buffer(6)]],
    device uint *output [[buffer(7)]],
    constant uint &row_count [[buffer(8)]],
    constant uint *denominator_inverses [[buffer(9)]],
    constant uint &denominator_count [[buffer(10)]],
    uint row [[thread_position_in_grid]]) {
    if (row >= row_count) return;
    uint previous_row = riscv_previous_circle_row(row, row_count, denominator_count);
    RiscvQm31 folded = { 0u, 0u, 0u, 0u };
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
    RiscvQm31 current0 = { tree2[column_offsets[6u] + row], tree2[column_offsets[7u] + row], tree2[column_offsets[8u] + row], tree2[column_offsets[9u] + row] };
    RiscvQm31 delta0 = current0;
    RiscvQm31 previous0 = { tree2[column_offsets[6u] + previous_row], tree2[column_offsets[7u] + previous_row], tree2[column_offsets[8u] + previous_row], tree2[column_offsets[9u] + previous_row] };
    delta0 = riscv_qm_add(riscv_qm_sub(delta0, previous0), riscv_load_qm31(relation_parameters, 24u));
    RiscvQm31 constraint0 = riscv_qm_sub(riscv_qm_mul(delta0, denominator0), RiscvQm31{ l6, 0u, 0u, 0u });
    folded = riscv_qm_add(folded, riscv_qm_mul(riscv_load_qm31(powers, 0u), constraint0));
    uint denominator_index = row / (row_count / denominator_count);
    RiscvQm31 result = riscv_qm_mul_base(folded, denominator_inverses[denominator_index]);
    output[riscv_column_offset(0u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(0u, row_count, row)], result.a);
    output[riscv_column_offset(1u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(1u, row_count, row)], result.b);
    output[riscv_column_offset(2u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(2u, row_count, row)], result.c);
    output[riscv_column_offset(3u, row_count, row)] = riscv_m31_add(output[riscv_column_offset(3u, row_count, row)], result.d);
}
