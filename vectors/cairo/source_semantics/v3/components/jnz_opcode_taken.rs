// This file was created by the AIR team.

#![allow(unused_parens)]
use cairo_air::components::jnz_opcode_taken::{Claim, InteractionClaim, N_TRACE_COLUMNS};
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{RawLogupTrace, RawLogupTraceGenerator};

use crate::witness::components::{memory_address_to_id, memory_id_to_big, verify_instruction};
use crate::witness::prelude::*;

pub type InputType = CasmState;
pub type PackedInputType = PackedCasmState;

#[derive(Default)]
pub struct ClaimGenerator {
    pub inputs: Vec<InputType>,
}

impl ClaimGenerator {
    pub fn new(inputs: Vec<InputType>) -> Self {
        Self { inputs }
    }

    pub fn write_trace(
        mut self,
        memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
        memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
        verify_instruction_state: &verify_instruction::ClaimGenerator,
    ) -> (
        ComponentTrace<N_TRACE_COLUMNS>,
        Claim,
        InteractionClaimGenerator,
    ) {
        let n_rows = self.inputs.len();
        assert_ne!(n_rows, 0);
        let size = std::cmp::max(n_rows.next_power_of_two(), N_LANES);
        let log_size = size.ilog2();
        self.inputs.resize(size, *self.inputs.first().unwrap());
        let packed_inputs = pack_values(&self.inputs);

        let (trace, lookup_data, sub_component_inputs) = write_trace_simd(
            packed_inputs,
            n_rows,
            memory_address_to_id_state,
            memory_id_to_big_state,
            verify_instruction_state,
        );
        for inputs in sub_component_inputs.verify_instruction {
            add_inputs(verify_instruction_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.memory_address_to_id {
            add_inputs(
                memory_address_to_id_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.memory_id_to_big {
            add_inputs(memory_id_to_big_state, &inputs, inputs.len() * N_LANES, 0);
        }

        (
            trace,
            Claim { log_size },
            InteractionClaimGenerator {
                log_size,
                lookup_data,
            },
        )
    }
}

#[derive(Uninitialized, IterMut, ParIterMut)]
struct SubComponentInputs {
    verify_instruction: [Vec<verify_instruction::PackedInputType>; 1],
    memory_address_to_id: [Vec<memory_address_to_id::PackedInputType>; 2],
    memory_id_to_big: [Vec<memory_id_to_big::PackedInputType>; 2],
}

#[allow(clippy::useless_conversion)]
#[allow(unused_variables)]
#[allow(clippy::double_parens)]
#[allow(non_snake_case)]
fn write_trace_simd(
    inputs: Vec<PackedInputType>,
    n_rows: usize,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
    verify_instruction_state: &verify_instruction::ClaimGenerator,
) -> (
    ComponentTrace<N_TRACE_COLUMNS>,
    LookupData,
    SubComponentInputs,
) {
    let log_n_packed_rows = inputs.len().ilog2();
    let log_size = log_n_packed_rows + LOG_N_LANES;
    let (mut trace, mut lookup_data, mut sub_component_inputs) = unsafe {
        (
            ComponentTrace::<N_TRACE_COLUMNS>::uninitialized(log_size),
            LookupData::uninitialized(log_n_packed_rows),
            SubComponentInputs::uninitialized(log_n_packed_rows),
        )
    };

    let M31_0 = PackedM31::broadcast(M31::from(0));
    let M31_1 = PackedM31::broadcast(M31::from(1));
    let M31_134217728 = PackedM31::broadcast(M31::from(134217728));
    let M31_136 = PackedM31::broadcast(M31::from(136));
    let M31_1444891767 = PackedM31::broadcast(M31::from(1444891767));
    let M31_16 = PackedM31::broadcast(M31::from(16));
    let M31_1662111297 = PackedM31::broadcast(M31::from(1662111297));
    let M31_1719106205 = PackedM31::broadcast(M31::from(1719106205));
    let M31_2147483646 = PackedM31::broadcast(M31::from(2147483646));
    let M31_256 = PackedM31::broadcast(M31::from(256));
    let M31_262144 = PackedM31::broadcast(M31::from(262144));
    let M31_32 = PackedM31::broadcast(M31::from(32));
    let M31_32767 = PackedM31::broadcast(M31::from(32767));
    let M31_32768 = PackedM31::broadcast(M31::from(32768));
    let M31_32769 = PackedM31::broadcast(M31::from(32769));
    let M31_428564188 = PackedM31::broadcast(M31::from(428564188));
    let M31_508 = PackedM31::broadcast(M31::from(508));
    let M31_511 = PackedM31::broadcast(M31::from(511));
    let M31_512 = PackedM31::broadcast(M31::from(512));
    let M31_536870912 = PackedM31::broadcast(M31::from(536870912));
    let M31_8 = PackedM31::broadcast(M31::from(8));
    let UInt16_0 = PackedUInt16::broadcast(UInt16::from(0));
    let UInt16_1 = PackedUInt16::broadcast(UInt16::from(1));
    let UInt16_11 = PackedUInt16::broadcast(UInt16::from(11));
    let UInt16_127 = PackedUInt16::broadcast(UInt16::from(127));
    let UInt16_2 = PackedUInt16::broadcast(UInt16::from(2));
    let UInt16_3 = PackedUInt16::broadcast(UInt16::from(3));
    let UInt16_6 = PackedUInt16::broadcast(UInt16::from(6));
    let UInt16_9 = PackedUInt16::broadcast(UInt16::from(9));
    let enabler_col = Enabler::new(n_rows);

    (
        trace.par_iter_mut(),
        lookup_data.par_iter_mut(),
        sub_component_inputs.par_iter_mut(),
        inputs.into_par_iter(),
    )
        .into_par_iter()
        .enumerate()
        .for_each(
            |(row_index, (row, lookup_data, sub_component_inputs, jnz_opcode_taken_input))| {
                let input_pc_col0 = jnz_opcode_taken_input.pc;
                *row[0] = input_pc_col0;
                let input_ap_col1 = jnz_opcode_taken_input.ap;
                *row[1] = input_ap_col1;
                let input_fp_col2 = jnz_opcode_taken_input.fp;
                *row[2] = input_fp_col2;

                // Decode Instruction.

                let memory_address_to_id_value_tmp_7f087_0 =
                    memory_address_to_id_state.deduce_output(input_pc_col0);
                let memory_id_to_big_value_tmp_7f087_1 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_7f087_0);
                let offset0_tmp_7f087_2 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_7f087_1.get_m31(0)))
                        + (((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_7f087_1.get_m31(1),
                        )) & (UInt16_127))
                            << (UInt16_9)));
                let offset0_col3 = offset0_tmp_7f087_2.as_m31();
                *row[3] = offset0_col3;
                let dst_base_fp_tmp_7f087_3 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_7f087_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_7f087_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_0))
                        & (UInt16_1));
                let dst_base_fp_col4 = dst_base_fp_tmp_7f087_3.as_m31();
                *row[4] = dst_base_fp_col4;
                let ap_update_add_1_tmp_7f087_4 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_7f087_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_7f087_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_11))
                        & (UInt16_1));
                let ap_update_add_1_col5 = ap_update_add_1_tmp_7f087_4.as_m31();
                *row[5] = ap_update_add_1_col5;
                *sub_component_inputs.verify_instruction[0] = (
                    input_pc_col0,
                    [offset0_col3, M31_32767, M31_32769],
                    [
                        ((((dst_base_fp_col4) * (M31_8)) + (M31_16)) + (M31_32)),
                        ((M31_8) + ((ap_update_add_1_col5) * (M31_32))),
                    ],
                    M31_0,
                );
                *lookup_data.verify_instruction_0 = [
                    M31_1719106205,
                    input_pc_col0,
                    offset0_col3,
                    M31_32767,
                    M31_32769,
                    ((((dst_base_fp_col4) * (M31_8)) + (M31_16)) + (M31_32)),
                    ((M31_8) + ((ap_update_add_1_col5) * (M31_32))),
                    M31_0,
                ];
                let decode_instruction_ad440_output_tmp_7f087_5 = (
                    [((offset0_col3) - (M31_32768)), M31_2147483646, M31_1],
                    [
                        dst_base_fp_col4,
                        M31_1,
                        M31_1,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_1,
                        M31_0,
                        ap_update_add_1_col5,
                        M31_0,
                        M31_0,
                        M31_0,
                    ],
                    M31_0,
                );

                let mem_dst_base_col6 = (((dst_base_fp_col4) * (input_fp_col2))
                    + (((M31_1) - (dst_base_fp_col4)) * (input_ap_col1)));
                *row[6] = mem_dst_base_col6;

                // Read Positive Num Bits 252.

                // Read Id.

                let memory_address_to_id_value_tmp_7f087_6 = memory_address_to_id_state
                    .deduce_output(
                        ((mem_dst_base_col6) + (decode_instruction_ad440_output_tmp_7f087_5.0[0])),
                    );
                let dst_id_col7 = memory_address_to_id_value_tmp_7f087_6;
                *row[7] = dst_id_col7;
                *sub_component_inputs.memory_address_to_id[0] =
                    ((mem_dst_base_col6) + (decode_instruction_ad440_output_tmp_7f087_5.0[0]));
                *lookup_data.memory_address_to_id_1 = [
                    M31_1444891767,
                    ((mem_dst_base_col6) + (decode_instruction_ad440_output_tmp_7f087_5.0[0])),
                    dst_id_col7,
                ];

                // Read Positive Known Id Num Bits 252.

                let memory_id_to_big_value_tmp_7f087_8 =
                    memory_id_to_big_state.deduce_output(dst_id_col7);
                let dst_limb_0_col8 = memory_id_to_big_value_tmp_7f087_8.get_m31(0);
                *row[8] = dst_limb_0_col8;
                let dst_limb_1_col9 = memory_id_to_big_value_tmp_7f087_8.get_m31(1);
                *row[9] = dst_limb_1_col9;
                let dst_limb_2_col10 = memory_id_to_big_value_tmp_7f087_8.get_m31(2);
                *row[10] = dst_limb_2_col10;
                let dst_limb_3_col11 = memory_id_to_big_value_tmp_7f087_8.get_m31(3);
                *row[11] = dst_limb_3_col11;
                let dst_limb_4_col12 = memory_id_to_big_value_tmp_7f087_8.get_m31(4);
                *row[12] = dst_limb_4_col12;
                let dst_limb_5_col13 = memory_id_to_big_value_tmp_7f087_8.get_m31(5);
                *row[13] = dst_limb_5_col13;
                let dst_limb_6_col14 = memory_id_to_big_value_tmp_7f087_8.get_m31(6);
                *row[14] = dst_limb_6_col14;
                let dst_limb_7_col15 = memory_id_to_big_value_tmp_7f087_8.get_m31(7);
                *row[15] = dst_limb_7_col15;
                let dst_limb_8_col16 = memory_id_to_big_value_tmp_7f087_8.get_m31(8);
                *row[16] = dst_limb_8_col16;
                let dst_limb_9_col17 = memory_id_to_big_value_tmp_7f087_8.get_m31(9);
                *row[17] = dst_limb_9_col17;
                let dst_limb_10_col18 = memory_id_to_big_value_tmp_7f087_8.get_m31(10);
                *row[18] = dst_limb_10_col18;
                let dst_limb_11_col19 = memory_id_to_big_value_tmp_7f087_8.get_m31(11);
                *row[19] = dst_limb_11_col19;
                let dst_limb_12_col20 = memory_id_to_big_value_tmp_7f087_8.get_m31(12);
                *row[20] = dst_limb_12_col20;
                let dst_limb_13_col21 = memory_id_to_big_value_tmp_7f087_8.get_m31(13);
                *row[21] = dst_limb_13_col21;
                let dst_limb_14_col22 = memory_id_to_big_value_tmp_7f087_8.get_m31(14);
                *row[22] = dst_limb_14_col22;
                let dst_limb_15_col23 = memory_id_to_big_value_tmp_7f087_8.get_m31(15);
                *row[23] = dst_limb_15_col23;
                let dst_limb_16_col24 = memory_id_to_big_value_tmp_7f087_8.get_m31(16);
                *row[24] = dst_limb_16_col24;
                let dst_limb_17_col25 = memory_id_to_big_value_tmp_7f087_8.get_m31(17);
                *row[25] = dst_limb_17_col25;
                let dst_limb_18_col26 = memory_id_to_big_value_tmp_7f087_8.get_m31(18);
                *row[26] = dst_limb_18_col26;
                let dst_limb_19_col27 = memory_id_to_big_value_tmp_7f087_8.get_m31(19);
                *row[27] = dst_limb_19_col27;
                let dst_limb_20_col28 = memory_id_to_big_value_tmp_7f087_8.get_m31(20);
                *row[28] = dst_limb_20_col28;
                let dst_limb_21_col29 = memory_id_to_big_value_tmp_7f087_8.get_m31(21);
                *row[29] = dst_limb_21_col29;
                let dst_limb_22_col30 = memory_id_to_big_value_tmp_7f087_8.get_m31(22);
                *row[30] = dst_limb_22_col30;
                let dst_limb_23_col31 = memory_id_to_big_value_tmp_7f087_8.get_m31(23);
                *row[31] = dst_limb_23_col31;
                let dst_limb_24_col32 = memory_id_to_big_value_tmp_7f087_8.get_m31(24);
                *row[32] = dst_limb_24_col32;
                let dst_limb_25_col33 = memory_id_to_big_value_tmp_7f087_8.get_m31(25);
                *row[33] = dst_limb_25_col33;
                let dst_limb_26_col34 = memory_id_to_big_value_tmp_7f087_8.get_m31(26);
                *row[34] = dst_limb_26_col34;
                let dst_limb_27_col35 = memory_id_to_big_value_tmp_7f087_8.get_m31(27);
                *row[35] = dst_limb_27_col35;
                *sub_component_inputs.memory_id_to_big[0] = dst_id_col7;
                *lookup_data.memory_id_to_big_2 = [
                    M31_1662111297,
                    dst_id_col7,
                    dst_limb_0_col8,
                    dst_limb_1_col9,
                    dst_limb_2_col10,
                    dst_limb_3_col11,
                    dst_limb_4_col12,
                    dst_limb_5_col13,
                    dst_limb_6_col14,
                    dst_limb_7_col15,
                    dst_limb_8_col16,
                    dst_limb_9_col17,
                    dst_limb_10_col18,
                    dst_limb_11_col19,
                    dst_limb_12_col20,
                    dst_limb_13_col21,
                    dst_limb_14_col22,
                    dst_limb_15_col23,
                    dst_limb_16_col24,
                    dst_limb_17_col25,
                    dst_limb_18_col26,
                    dst_limb_19_col27,
                    dst_limb_20_col28,
                    dst_limb_21_col29,
                    dst_limb_22_col30,
                    dst_limb_23_col31,
                    dst_limb_24_col32,
                    dst_limb_25_col33,
                    dst_limb_26_col34,
                    dst_limb_27_col35,
                ];
                let read_positive_known_id_num_bits_252_output_tmp_7f087_9 =
                    PackedFelt252::from_limbs([
                        dst_limb_0_col8,
                        dst_limb_1_col9,
                        dst_limb_2_col10,
                        dst_limb_3_col11,
                        dst_limb_4_col12,
                        dst_limb_5_col13,
                        dst_limb_6_col14,
                        dst_limb_7_col15,
                        dst_limb_8_col16,
                        dst_limb_9_col17,
                        dst_limb_10_col18,
                        dst_limb_11_col19,
                        dst_limb_12_col20,
                        dst_limb_13_col21,
                        dst_limb_14_col22,
                        dst_limb_15_col23,
                        dst_limb_16_col24,
                        dst_limb_17_col25,
                        dst_limb_18_col26,
                        dst_limb_19_col27,
                        dst_limb_20_col28,
                        dst_limb_21_col29,
                        dst_limb_22_col30,
                        dst_limb_23_col31,
                        dst_limb_24_col32,
                        dst_limb_25_col33,
                        dst_limb_26_col34,
                        dst_limb_27_col35,
                    ]);

                let read_positive_num_bits_252_output_tmp_7f087_10 = (
                    read_positive_known_id_num_bits_252_output_tmp_7f087_9,
                    dst_id_col7,
                );

                let dst_sum_p_zero_tmp_7f087_11 = (((((((((((((((((((((((((dst_limb_1_col9)
                    + (dst_limb_2_col10))
                    + (dst_limb_3_col11))
                    + (dst_limb_4_col12))
                    + (dst_limb_5_col13))
                    + (dst_limb_6_col14))
                    + (dst_limb_7_col15))
                    + (dst_limb_8_col16))
                    + (dst_limb_9_col17))
                    + (dst_limb_10_col18))
                    + (dst_limb_11_col19))
                    + (dst_limb_12_col20))
                    + (dst_limb_13_col21))
                    + (dst_limb_14_col22))
                    + (dst_limb_15_col23))
                    + (dst_limb_16_col24))
                    + (dst_limb_17_col25))
                    + (dst_limb_18_col26))
                    + (dst_limb_19_col27))
                    + (dst_limb_20_col28))
                    + (dst_limb_22_col30))
                    + (dst_limb_23_col31))
                    + (dst_limb_24_col32))
                    + (dst_limb_25_col33))
                    + (dst_limb_26_col34));
                let dst_sum_inv_col36 = ((dst_sum_p_zero_tmp_7f087_11)
                    + (((dst_limb_0_col8) + (dst_limb_21_col29)) + (dst_limb_27_col35)))
                    .inverse();
                *row[36] = dst_sum_inv_col36;
                let diff_from_p_tmp_7f087_12 = ((dst_limb_0_col8) - (M31_1));
                let diff_from_p_tmp_7f087_13 = ((dst_limb_21_col29) - (M31_136));
                let diff_from_p_tmp_7f087_14 = ((dst_limb_27_col35) - (M31_256));
                let dst_sum_squares_inv_col37 = ((dst_sum_p_zero_tmp_7f087_11)
                    + ((((diff_from_p_tmp_7f087_12) * (diff_from_p_tmp_7f087_12))
                        + ((diff_from_p_tmp_7f087_13) * (diff_from_p_tmp_7f087_13)))
                        + ((diff_from_p_tmp_7f087_14) * (diff_from_p_tmp_7f087_14))))
                    .inverse();
                *row[37] = dst_sum_squares_inv_col37;

                // Read Small.

                // Read Id.

                let memory_address_to_id_value_tmp_7f087_15 =
                    memory_address_to_id_state.deduce_output(((input_pc_col0) + (M31_1)));
                let next_pc_id_col38 = memory_address_to_id_value_tmp_7f087_15;
                *row[38] = next_pc_id_col38;
                *sub_component_inputs.memory_address_to_id[1] = ((input_pc_col0) + (M31_1));
                *lookup_data.memory_address_to_id_3 = [
                    M31_1444891767,
                    ((input_pc_col0) + (M31_1)),
                    next_pc_id_col38,
                ];

                let memory_id_to_big_value_tmp_7f087_17 =
                    memory_id_to_big_state.deduce_output(next_pc_id_col38);

                // Decode Small Sign.

                let msb_tmp_7f087_18 = memory_id_to_big_value_tmp_7f087_17.get_m31(27).eq(M31_256);
                let msb_col39 = msb_tmp_7f087_18.as_m31();
                *row[39] = msb_col39;
                let mid_limbs_set_tmp_7f087_19 =
                    ((memory_id_to_big_value_tmp_7f087_17.get_m31(20).eq(M31_511))
                        & (msb_tmp_7f087_18));
                let mid_limbs_set_col40 = mid_limbs_set_tmp_7f087_19.as_m31();
                *row[40] = mid_limbs_set_col40;
                let decode_small_sign_output_tmp_7f087_20 = [
                    msb_col39,
                    mid_limbs_set_col40,
                    ((mid_limbs_set_col40) * (M31_508)),
                    ((mid_limbs_set_col40) * (M31_511)),
                    (((msb_col39) * (M31_136)) - (mid_limbs_set_col40)),
                    ((msb_col39) * (M31_256)),
                ];

                let next_pc_limb_0_col41 = memory_id_to_big_value_tmp_7f087_17.get_m31(0);
                *row[41] = next_pc_limb_0_col41;
                let next_pc_limb_1_col42 = memory_id_to_big_value_tmp_7f087_17.get_m31(1);
                *row[42] = next_pc_limb_1_col42;
                let next_pc_limb_2_col43 = memory_id_to_big_value_tmp_7f087_17.get_m31(2);
                *row[43] = next_pc_limb_2_col43;
                let remainder_bits_tmp_7f087_21 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_7f087_17.get_m31(3)))
                        & (UInt16_3));
                let remainder_bits_col44 = remainder_bits_tmp_7f087_21.as_m31();
                *row[44] = remainder_bits_col44;

                // Cond Range Check 2.

                let partial_limb_msb_tmp_7f087_22 =
                    (((PackedUInt16::from_m31(remainder_bits_col44)) & (UInt16_2)) >> (UInt16_1));
                let partial_limb_msb_col45 = partial_limb_msb_tmp_7f087_22.as_m31();
                *row[45] = partial_limb_msb_col45;

                *sub_component_inputs.memory_id_to_big[1] = next_pc_id_col38;
                *lookup_data.memory_id_to_big_4 = [
                    M31_1662111297,
                    next_pc_id_col38,
                    next_pc_limb_0_col41,
                    next_pc_limb_1_col42,
                    next_pc_limb_2_col43,
                    ((remainder_bits_col44) + (decode_small_sign_output_tmp_7f087_20[2])),
                    decode_small_sign_output_tmp_7f087_20[3],
                    decode_small_sign_output_tmp_7f087_20[3],
                    decode_small_sign_output_tmp_7f087_20[3],
                    decode_small_sign_output_tmp_7f087_20[3],
                    decode_small_sign_output_tmp_7f087_20[3],
                    decode_small_sign_output_tmp_7f087_20[3],
                    decode_small_sign_output_tmp_7f087_20[3],
                    decode_small_sign_output_tmp_7f087_20[3],
                    decode_small_sign_output_tmp_7f087_20[3],
                    decode_small_sign_output_tmp_7f087_20[3],
                    decode_small_sign_output_tmp_7f087_20[3],
                    decode_small_sign_output_tmp_7f087_20[3],
                    decode_small_sign_output_tmp_7f087_20[3],
                    decode_small_sign_output_tmp_7f087_20[3],
                    decode_small_sign_output_tmp_7f087_20[3],
                    decode_small_sign_output_tmp_7f087_20[3],
                    decode_small_sign_output_tmp_7f087_20[3],
                    decode_small_sign_output_tmp_7f087_20[4],
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    decode_small_sign_output_tmp_7f087_20[5],
                ];
                let read_small_output_tmp_7f087_24 = (
                    ((((((next_pc_limb_0_col41) + ((next_pc_limb_1_col42) * (M31_512)))
                        + ((next_pc_limb_2_col43) * (M31_262144)))
                        + ((remainder_bits_col44) * (M31_134217728)))
                        - (msb_col39))
                        - ((M31_536870912) * (mid_limbs_set_col40))),
                    next_pc_id_col38,
                );

                let enabler_col46 = enabler_col.packed_at(row_index);
                *row[46] = enabler_col46;
                *lookup_data.opcodes_5 =
                    [M31_428564188, input_pc_col0, input_ap_col1, input_fp_col2];
                *lookup_data.opcodes_6 = [
                    M31_428564188,
                    ((input_pc_col0) + (read_small_output_tmp_7f087_24.0)),
                    ((input_ap_col1) + (ap_update_add_1_col5)),
                    input_fp_col2,
                ];
                *lookup_data.mults_0 = M31_1;
                *lookup_data.mults_1 = enabler_col46;
            },
        );

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `jnz_opcode_taken` — mechanical rewrite of
// `write_trace_simd`'s per-row closure into a generic body over `WitnessEval`. Do not
// edit by hand: re-run the tool after upstream regeneration (this block is stripped and
// re-emitted idempotently). The original `write_trace_simd` above is the untouched
// byte-equality baseline (see `witness_eval::differential_test`).
//
// Flat layouts (derived, DECLARATION order):
//   LOOKUP words:
//     verify_instruction_0[8] 0..7
//     memory_address_to_id_1[3] 8..10
//     memory_id_to_big_2[30] 11..40
//     memory_address_to_id_3[3] 41..43
//     memory_id_to_big_4[30] 44..73
//     opcodes_5[4] 74..77
//     opcodes_6[4] 78..81
//     mults_0 82
//     mults_1 83
//     (84 words)
//   SUB-INPUT words:
//     verify_instruction[0] 0..6
//     memory_address_to_id[0] 7
//     memory_address_to_id[1] 8
//     memory_id_to_big[0] 9
//     memory_id_to_big[1] 10
//     (11 words)
use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};
use crate::witness::witness_eval::simd::SimdWitnessEval;
use crate::witness::witness_eval::{WitnessEval, SLOT_AP, SLOT_FP, SLOT_PC};

pub(crate) const N_LOOKUP_WORDS: usize = 84;
pub(crate) const N_SUB_INPUT_WORDS: usize = 11;

/// The per-row `jnz_opcode_taken` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn jnz_opcode_taken_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_0 = eval.m31_const(0);
    let m31_1 = eval.m31_const(1);
    let m31_8 = eval.m31_const(8);
    let m31_16 = eval.m31_const(16);
    let m31_32 = eval.m31_const(32);
    let m31_136 = eval.m31_const(136);
    let m31_256 = eval.m31_const(256);
    let m31_508 = eval.m31_const(508);
    let m31_511 = eval.m31_const(511);
    let m31_512 = eval.m31_const(512);
    let m31_32767 = eval.m31_const(32767);
    let m31_32768 = eval.m31_const(32768);
    let m31_32769 = eval.m31_const(32769);
    let m31_262144 = eval.m31_const(262144);
    let m31_134217728 = eval.m31_const(134217728);
    let m31_428564188 = eval.m31_const(428564188);
    let m31_536870912 = eval.m31_const(536870912);
    let m31_1444891767 = eval.m31_const(1444891767);
    let m31_1662111297 = eval.m31_const(1662111297);
    let m31_1719106205 = eval.m31_const(1719106205);
    let m31_2147483646 = eval.m31_const(2147483646);
    let input_pc_col0 = eval.input(SLOT_PC);
    eval.set_col(0, input_pc_col0);
    let input_ap_col1 = eval.input(SLOT_AP);
    eval.set_col(1, input_ap_col1);
    let input_fp_col2 = eval.input(SLOT_FP);
    eval.set_col(2, input_fp_col2);
    let memory_address_to_id_value_tmp_7f087_0 = eval.mem_addr_to_id(input_pc_col0);
    let memory_id_to_big_value_tmp_7f087_1 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_7f087_0);
    let wg_v0 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_1.clone(), 0);
    let wg_v1 = eval.u16_from_m31(wg_v0);
    let wg_v2 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_1.clone(), 1);
    let wg_v3 = eval.u16_from_m31(wg_v2);
    let wg_v4 = eval.u16_and(wg_v3, 127);
    let wg_v5 = eval.u16_shl(wg_v4, 9);
    let offset0_tmp_7f087_2 = eval.u16_add(wg_v1, wg_v5);
    let offset0_col3 = eval.u16_as_m31(offset0_tmp_7f087_2);
    eval.set_col(3, offset0_col3);
    let wg_v6 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_1.clone(), 5);
    let wg_v7 = eval.u16_from_m31(wg_v6);
    let wg_v8 = eval.u16_shr(wg_v7, 3);
    let wg_v9 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_1.clone(), 6);
    let wg_v10 = eval.u16_from_m31(wg_v9);
    let wg_v11 = eval.u16_shl(wg_v10, 6);
    let wg_v12 = eval.u16_add(wg_v8, wg_v11);
    let wg_v13 = eval.u16_shr(wg_v12, 0);
    let dst_base_fp_tmp_7f087_3 = eval.u16_and(wg_v13, 1);
    let dst_base_fp_col4 = eval.u16_as_m31(dst_base_fp_tmp_7f087_3);
    eval.set_col(4, dst_base_fp_col4);
    let wg_v14 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_1.clone(), 5);
    let wg_v15 = eval.u16_from_m31(wg_v14);
    let wg_v16 = eval.u16_shr(wg_v15, 3);
    let wg_v17 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_1.clone(), 6);
    let wg_v18 = eval.u16_from_m31(wg_v17);
    let wg_v19 = eval.u16_shl(wg_v18, 6);
    let wg_v20 = eval.u16_add(wg_v16, wg_v19);
    let wg_v21 = eval.u16_shr(wg_v20, 11);
    let ap_update_add_1_tmp_7f087_4 = eval.u16_and(wg_v21, 1);
    let ap_update_add_1_col5 = eval.u16_as_m31(ap_update_add_1_tmp_7f087_4);
    eval.set_col(5, ap_update_add_1_col5);
    let wg_v22 = eval.m31_mul(dst_base_fp_col4, m31_8);
    let wg_v23 = eval.m31_add(wg_v22, m31_16);
    let wg_v24 = eval.m31_add(wg_v23, m31_32);
    let wg_v25 = eval.m31_mul(ap_update_add_1_col5, m31_32);
    let wg_v26 = eval.m31_add(m31_8, wg_v25);
    eval.set_sub_input_word(0, input_pc_col0);
    eval.set_sub_input_word(1, offset0_col3);
    eval.set_sub_input_word(2, m31_32767);
    eval.set_sub_input_word(3, m31_32769);
    eval.set_sub_input_word(4, wg_v24);
    eval.set_sub_input_word(5, wg_v26);
    eval.set_sub_input_word(6, m31_0);
    eval.set_lookup_word(0, m31_1719106205);
    eval.set_lookup_word(1, input_pc_col0);
    eval.set_lookup_word(2, offset0_col3);
    eval.set_lookup_word(3, m31_32767);
    eval.set_lookup_word(4, m31_32769);
    let wg_v27 = eval.m31_mul(dst_base_fp_col4, m31_8);
    let wg_v28 = eval.m31_add(wg_v27, m31_16);
    let wg_v29 = eval.m31_add(wg_v28, m31_32);
    eval.set_lookup_word(5, wg_v29);
    let wg_v30 = eval.m31_mul(ap_update_add_1_col5, m31_32);
    let wg_v31 = eval.m31_add(m31_8, wg_v30);
    eval.set_lookup_word(6, wg_v31);
    eval.set_lookup_word(7, m31_0);
    let wg_v32 = eval.m31_sub(offset0_col3, m31_32768);
    let decode_instruction_ad440_output_tmp_7f087_5 = (
        [wg_v32, m31_2147483646, m31_1],
        [
            dst_base_fp_col4,
            m31_1,
            m31_1,
            m31_0,
            m31_0,
            m31_0,
            m31_0,
            m31_0,
            m31_0,
            m31_1,
            m31_0,
            ap_update_add_1_col5,
            m31_0,
            m31_0,
            m31_0,
        ],
        m31_0,
    );
    let wg_v33 = eval.m31_mul(dst_base_fp_col4, input_fp_col2);
    let wg_v34 = eval.m31_sub(m31_1, dst_base_fp_col4);
    let wg_v35 = eval.m31_mul(wg_v34, input_ap_col1);
    let mem_dst_base_col6 = eval.m31_add(wg_v33, wg_v35);
    eval.set_col(6, mem_dst_base_col6);
    let wg_v36 = eval.m31_add(
        mem_dst_base_col6,
        decode_instruction_ad440_output_tmp_7f087_5.0[0],
    );
    let memory_address_to_id_value_tmp_7f087_6 = eval.mem_addr_to_id(wg_v36);
    let dst_id_col7 = memory_address_to_id_value_tmp_7f087_6;
    eval.set_col(7, dst_id_col7);
    let wg_v37 = eval.m31_add(
        mem_dst_base_col6,
        decode_instruction_ad440_output_tmp_7f087_5.0[0],
    );
    eval.set_sub_input_word(7, wg_v37);
    eval.set_lookup_word(8, m31_1444891767);
    let wg_v38 = eval.m31_add(
        mem_dst_base_col6,
        decode_instruction_ad440_output_tmp_7f087_5.0[0],
    );
    eval.set_lookup_word(9, wg_v38);
    eval.set_lookup_word(10, dst_id_col7);
    let memory_id_to_big_value_tmp_7f087_8 = eval.mem_id_to_value(dst_id_col7);
    let dst_limb_0_col8 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 0);
    eval.set_col(8, dst_limb_0_col8);
    let dst_limb_1_col9 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 1);
    eval.set_col(9, dst_limb_1_col9);
    let dst_limb_2_col10 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 2);
    eval.set_col(10, dst_limb_2_col10);
    let dst_limb_3_col11 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 3);
    eval.set_col(11, dst_limb_3_col11);
    let dst_limb_4_col12 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 4);
    eval.set_col(12, dst_limb_4_col12);
    let dst_limb_5_col13 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 5);
    eval.set_col(13, dst_limb_5_col13);
    let dst_limb_6_col14 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 6);
    eval.set_col(14, dst_limb_6_col14);
    let dst_limb_7_col15 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 7);
    eval.set_col(15, dst_limb_7_col15);
    let dst_limb_8_col16 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 8);
    eval.set_col(16, dst_limb_8_col16);
    let dst_limb_9_col17 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 9);
    eval.set_col(17, dst_limb_9_col17);
    let dst_limb_10_col18 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 10);
    eval.set_col(18, dst_limb_10_col18);
    let dst_limb_11_col19 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 11);
    eval.set_col(19, dst_limb_11_col19);
    let dst_limb_12_col20 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 12);
    eval.set_col(20, dst_limb_12_col20);
    let dst_limb_13_col21 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 13);
    eval.set_col(21, dst_limb_13_col21);
    let dst_limb_14_col22 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 14);
    eval.set_col(22, dst_limb_14_col22);
    let dst_limb_15_col23 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 15);
    eval.set_col(23, dst_limb_15_col23);
    let dst_limb_16_col24 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 16);
    eval.set_col(24, dst_limb_16_col24);
    let dst_limb_17_col25 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 17);
    eval.set_col(25, dst_limb_17_col25);
    let dst_limb_18_col26 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 18);
    eval.set_col(26, dst_limb_18_col26);
    let dst_limb_19_col27 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 19);
    eval.set_col(27, dst_limb_19_col27);
    let dst_limb_20_col28 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 20);
    eval.set_col(28, dst_limb_20_col28);
    let dst_limb_21_col29 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 21);
    eval.set_col(29, dst_limb_21_col29);
    let dst_limb_22_col30 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 22);
    eval.set_col(30, dst_limb_22_col30);
    let dst_limb_23_col31 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 23);
    eval.set_col(31, dst_limb_23_col31);
    let dst_limb_24_col32 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 24);
    eval.set_col(32, dst_limb_24_col32);
    let dst_limb_25_col33 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 25);
    eval.set_col(33, dst_limb_25_col33);
    let dst_limb_26_col34 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 26);
    eval.set_col(34, dst_limb_26_col34);
    let dst_limb_27_col35 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_8.clone(), 27);
    eval.set_col(35, dst_limb_27_col35);
    eval.set_sub_input_word(9, dst_id_col7);
    eval.set_lookup_word(11, m31_1662111297);
    eval.set_lookup_word(12, dst_id_col7);
    eval.set_lookup_word(13, dst_limb_0_col8);
    eval.set_lookup_word(14, dst_limb_1_col9);
    eval.set_lookup_word(15, dst_limb_2_col10);
    eval.set_lookup_word(16, dst_limb_3_col11);
    eval.set_lookup_word(17, dst_limb_4_col12);
    eval.set_lookup_word(18, dst_limb_5_col13);
    eval.set_lookup_word(19, dst_limb_6_col14);
    eval.set_lookup_word(20, dst_limb_7_col15);
    eval.set_lookup_word(21, dst_limb_8_col16);
    eval.set_lookup_word(22, dst_limb_9_col17);
    eval.set_lookup_word(23, dst_limb_10_col18);
    eval.set_lookup_word(24, dst_limb_11_col19);
    eval.set_lookup_word(25, dst_limb_12_col20);
    eval.set_lookup_word(26, dst_limb_13_col21);
    eval.set_lookup_word(27, dst_limb_14_col22);
    eval.set_lookup_word(28, dst_limb_15_col23);
    eval.set_lookup_word(29, dst_limb_16_col24);
    eval.set_lookup_word(30, dst_limb_17_col25);
    eval.set_lookup_word(31, dst_limb_18_col26);
    eval.set_lookup_word(32, dst_limb_19_col27);
    eval.set_lookup_word(33, dst_limb_20_col28);
    eval.set_lookup_word(34, dst_limb_21_col29);
    eval.set_lookup_word(35, dst_limb_22_col30);
    eval.set_lookup_word(36, dst_limb_23_col31);
    eval.set_lookup_word(37, dst_limb_24_col32);
    eval.set_lookup_word(38, dst_limb_25_col33);
    eval.set_lookup_word(39, dst_limb_26_col34);
    eval.set_lookup_word(40, dst_limb_27_col35);
    let read_positive_known_id_num_bits_252_output_tmp_7f087_9 = eval.felt_from_limbs([
        dst_limb_0_col8,
        dst_limb_1_col9,
        dst_limb_2_col10,
        dst_limb_3_col11,
        dst_limb_4_col12,
        dst_limb_5_col13,
        dst_limb_6_col14,
        dst_limb_7_col15,
        dst_limb_8_col16,
        dst_limb_9_col17,
        dst_limb_10_col18,
        dst_limb_11_col19,
        dst_limb_12_col20,
        dst_limb_13_col21,
        dst_limb_14_col22,
        dst_limb_15_col23,
        dst_limb_16_col24,
        dst_limb_17_col25,
        dst_limb_18_col26,
        dst_limb_19_col27,
        dst_limb_20_col28,
        dst_limb_21_col29,
        dst_limb_22_col30,
        dst_limb_23_col31,
        dst_limb_24_col32,
        dst_limb_25_col33,
        dst_limb_26_col34,
        dst_limb_27_col35,
    ]);
    let read_positive_num_bits_252_output_tmp_7f087_10 = (
        read_positive_known_id_num_bits_252_output_tmp_7f087_9.clone(),
        dst_id_col7,
    );
    let wg_v39 = eval.m31_add(dst_limb_1_col9, dst_limb_2_col10);
    let wg_v40 = eval.m31_add(wg_v39, dst_limb_3_col11);
    let wg_v41 = eval.m31_add(wg_v40, dst_limb_4_col12);
    let wg_v42 = eval.m31_add(wg_v41, dst_limb_5_col13);
    let wg_v43 = eval.m31_add(wg_v42, dst_limb_6_col14);
    let wg_v44 = eval.m31_add(wg_v43, dst_limb_7_col15);
    let wg_v45 = eval.m31_add(wg_v44, dst_limb_8_col16);
    let wg_v46 = eval.m31_add(wg_v45, dst_limb_9_col17);
    let wg_v47 = eval.m31_add(wg_v46, dst_limb_10_col18);
    let wg_v48 = eval.m31_add(wg_v47, dst_limb_11_col19);
    let wg_v49 = eval.m31_add(wg_v48, dst_limb_12_col20);
    let wg_v50 = eval.m31_add(wg_v49, dst_limb_13_col21);
    let wg_v51 = eval.m31_add(wg_v50, dst_limb_14_col22);
    let wg_v52 = eval.m31_add(wg_v51, dst_limb_15_col23);
    let wg_v53 = eval.m31_add(wg_v52, dst_limb_16_col24);
    let wg_v54 = eval.m31_add(wg_v53, dst_limb_17_col25);
    let wg_v55 = eval.m31_add(wg_v54, dst_limb_18_col26);
    let wg_v56 = eval.m31_add(wg_v55, dst_limb_19_col27);
    let wg_v57 = eval.m31_add(wg_v56, dst_limb_20_col28);
    let wg_v58 = eval.m31_add(wg_v57, dst_limb_22_col30);
    let wg_v59 = eval.m31_add(wg_v58, dst_limb_23_col31);
    let wg_v60 = eval.m31_add(wg_v59, dst_limb_24_col32);
    let wg_v61 = eval.m31_add(wg_v60, dst_limb_25_col33);
    let dst_sum_p_zero_tmp_7f087_11 = eval.m31_add(wg_v61, dst_limb_26_col34);
    let wg_v62 = eval.m31_add(dst_limb_0_col8, dst_limb_21_col29);
    let wg_v63 = eval.m31_add(wg_v62, dst_limb_27_col35);
    let wg_v64 = eval.m31_add(dst_sum_p_zero_tmp_7f087_11, wg_v63);
    let dst_sum_inv_col36 = eval.m31_inverse(wg_v64);
    eval.set_col(36, dst_sum_inv_col36);
    let diff_from_p_tmp_7f087_12 = eval.m31_sub(dst_limb_0_col8, m31_1);
    let diff_from_p_tmp_7f087_13 = eval.m31_sub(dst_limb_21_col29, m31_136);
    let diff_from_p_tmp_7f087_14 = eval.m31_sub(dst_limb_27_col35, m31_256);
    let wg_v65 = eval.m31_mul(diff_from_p_tmp_7f087_12, diff_from_p_tmp_7f087_12);
    let wg_v66 = eval.m31_mul(diff_from_p_tmp_7f087_13, diff_from_p_tmp_7f087_13);
    let wg_v67 = eval.m31_add(wg_v65, wg_v66);
    let wg_v68 = eval.m31_mul(diff_from_p_tmp_7f087_14, diff_from_p_tmp_7f087_14);
    let wg_v69 = eval.m31_add(wg_v67, wg_v68);
    let wg_v70 = eval.m31_add(dst_sum_p_zero_tmp_7f087_11, wg_v69);
    let dst_sum_squares_inv_col37 = eval.m31_inverse(wg_v70);
    eval.set_col(37, dst_sum_squares_inv_col37);
    let wg_v71 = eval.m31_add(input_pc_col0, m31_1);
    let memory_address_to_id_value_tmp_7f087_15 = eval.mem_addr_to_id(wg_v71);
    let next_pc_id_col38 = memory_address_to_id_value_tmp_7f087_15;
    eval.set_col(38, next_pc_id_col38);
    let wg_v72 = eval.m31_add(input_pc_col0, m31_1);
    eval.set_sub_input_word(8, wg_v72);
    eval.set_lookup_word(41, m31_1444891767);
    let wg_v73 = eval.m31_add(input_pc_col0, m31_1);
    eval.set_lookup_word(42, wg_v73);
    eval.set_lookup_word(43, next_pc_id_col38);
    let memory_id_to_big_value_tmp_7f087_17 = eval.mem_id_to_value(next_pc_id_col38);
    let wg_v74 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_17.clone(), 27);
    let msb_tmp_7f087_18 = eval.m31_eq(wg_v74, m31_256);
    let msb_col39 = eval.mask_as_m31(msb_tmp_7f087_18);
    eval.set_col(39, msb_col39);
    let wg_v75 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_17.clone(), 20);
    let wg_v76 = eval.m31_eq(wg_v75, m31_511);
    let mid_limbs_set_tmp_7f087_19 = eval.mask_and(wg_v76, msb_tmp_7f087_18);
    let mid_limbs_set_col40 = eval.mask_as_m31(mid_limbs_set_tmp_7f087_19);
    eval.set_col(40, mid_limbs_set_col40);
    let wg_v77 = eval.m31_mul(mid_limbs_set_col40, m31_508);
    let wg_v78 = eval.m31_mul(mid_limbs_set_col40, m31_511);
    let wg_v79 = eval.m31_mul(msb_col39, m31_136);
    let wg_v80 = eval.m31_sub(wg_v79, mid_limbs_set_col40);
    let wg_v81 = eval.m31_mul(msb_col39, m31_256);
    let decode_small_sign_output_tmp_7f087_20 = [
        msb_col39,
        mid_limbs_set_col40,
        wg_v77,
        wg_v78,
        wg_v80,
        wg_v81,
    ];
    let next_pc_limb_0_col41 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_17.clone(), 0);
    eval.set_col(41, next_pc_limb_0_col41);
    let next_pc_limb_1_col42 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_17.clone(), 1);
    eval.set_col(42, next_pc_limb_1_col42);
    let next_pc_limb_2_col43 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_17.clone(), 2);
    eval.set_col(43, next_pc_limb_2_col43);
    let wg_v82 = eval.felt_get_m31(&memory_id_to_big_value_tmp_7f087_17.clone(), 3);
    let wg_v83 = eval.u16_from_m31(wg_v82);
    let remainder_bits_tmp_7f087_21 = eval.u16_and(wg_v83, 3);
    let remainder_bits_col44 = eval.u16_as_m31(remainder_bits_tmp_7f087_21);
    eval.set_col(44, remainder_bits_col44);
    let wg_v84 = eval.u16_from_m31(remainder_bits_col44);
    let wg_v85 = eval.u16_and(wg_v84, 2);
    let partial_limb_msb_tmp_7f087_22 = eval.u16_shr(wg_v85, 1);
    let partial_limb_msb_col45 = eval.u16_as_m31(partial_limb_msb_tmp_7f087_22);
    eval.set_col(45, partial_limb_msb_col45);
    eval.set_sub_input_word(10, next_pc_id_col38);
    eval.set_lookup_word(44, m31_1662111297);
    eval.set_lookup_word(45, next_pc_id_col38);
    eval.set_lookup_word(46, next_pc_limb_0_col41);
    eval.set_lookup_word(47, next_pc_limb_1_col42);
    eval.set_lookup_word(48, next_pc_limb_2_col43);
    let wg_v86 = eval.m31_add(
        remainder_bits_col44,
        decode_small_sign_output_tmp_7f087_20[2],
    );
    eval.set_lookup_word(49, wg_v86);
    eval.set_lookup_word(50, decode_small_sign_output_tmp_7f087_20[3]);
    eval.set_lookup_word(51, decode_small_sign_output_tmp_7f087_20[3]);
    eval.set_lookup_word(52, decode_small_sign_output_tmp_7f087_20[3]);
    eval.set_lookup_word(53, decode_small_sign_output_tmp_7f087_20[3]);
    eval.set_lookup_word(54, decode_small_sign_output_tmp_7f087_20[3]);
    eval.set_lookup_word(55, decode_small_sign_output_tmp_7f087_20[3]);
    eval.set_lookup_word(56, decode_small_sign_output_tmp_7f087_20[3]);
    eval.set_lookup_word(57, decode_small_sign_output_tmp_7f087_20[3]);
    eval.set_lookup_word(58, decode_small_sign_output_tmp_7f087_20[3]);
    eval.set_lookup_word(59, decode_small_sign_output_tmp_7f087_20[3]);
    eval.set_lookup_word(60, decode_small_sign_output_tmp_7f087_20[3]);
    eval.set_lookup_word(61, decode_small_sign_output_tmp_7f087_20[3]);
    eval.set_lookup_word(62, decode_small_sign_output_tmp_7f087_20[3]);
    eval.set_lookup_word(63, decode_small_sign_output_tmp_7f087_20[3]);
    eval.set_lookup_word(64, decode_small_sign_output_tmp_7f087_20[3]);
    eval.set_lookup_word(65, decode_small_sign_output_tmp_7f087_20[3]);
    eval.set_lookup_word(66, decode_small_sign_output_tmp_7f087_20[3]);
    eval.set_lookup_word(67, decode_small_sign_output_tmp_7f087_20[4]);
    eval.set_lookup_word(68, m31_0);
    eval.set_lookup_word(69, m31_0);
    eval.set_lookup_word(70, m31_0);
    eval.set_lookup_word(71, m31_0);
    eval.set_lookup_word(72, m31_0);
    eval.set_lookup_word(73, decode_small_sign_output_tmp_7f087_20[5]);
    let wg_v87 = eval.m31_mul(next_pc_limb_1_col42, m31_512);
    let wg_v88 = eval.m31_add(next_pc_limb_0_col41, wg_v87);
    let wg_v89 = eval.m31_mul(next_pc_limb_2_col43, m31_262144);
    let wg_v90 = eval.m31_add(wg_v88, wg_v89);
    let wg_v91 = eval.m31_mul(remainder_bits_col44, m31_134217728);
    let wg_v92 = eval.m31_add(wg_v90, wg_v91);
    let wg_v93 = eval.m31_sub(wg_v92, msb_col39);
    let wg_v94 = eval.m31_mul(m31_536870912, mid_limbs_set_col40);
    let wg_v95 = eval.m31_sub(wg_v93, wg_v94);
    let read_small_output_tmp_7f087_24 = (wg_v95, next_pc_id_col38);
    let enabler_col46 = eval.enabler();
    eval.set_col(46, enabler_col46);
    eval.set_lookup_word(74, m31_428564188);
    eval.set_lookup_word(75, input_pc_col0);
    eval.set_lookup_word(76, input_ap_col1);
    eval.set_lookup_word(77, input_fp_col2);
    eval.set_lookup_word(78, m31_428564188);
    let wg_v96 = eval.m31_add(input_pc_col0, read_small_output_tmp_7f087_24.0);
    eval.set_lookup_word(79, wg_v96);
    let wg_v97 = eval.m31_add(input_ap_col1, ap_update_add_1_col5);
    eval.set_lookup_word(80, wg_v97);
    eval.set_lookup_word(81, input_fp_col2);
    eval.set_lookup_word(82, m31_1);
    eval.set_lookup_word(83, enabler_col46);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `jnz_opcode_taken_row_body` on a per-row `SimdWitnessEval`, then reconstructs the concrete
/// `LookupData` / `SubComponentInputs` from the eval's flat scratch. Module-private (it
/// returns the module-private `LookupData` / `SubComponentInputs`; wider visibility would
/// be E0446 and force a change OUTSIDE this block). External callers use the `pub(crate)`
/// `write_trace_generic` method or the `#[cfg(test)]` `generic_simd_diff` harness.
#[allow(clippy::type_complexity)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn write_trace_generic_simd(
    inputs: Vec<PackedInputType>,
    n_rows: usize,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
    verify_instruction_state: &verify_instruction::ClaimGenerator,
) -> (
    ComponentTrace<N_TRACE_COLUMNS>,
    LookupData,
    SubComponentInputs,
) {
    let log_n_packed_rows = inputs.len().ilog2();
    let log_size = log_n_packed_rows + LOG_N_LANES;
    let (mut trace, mut lookup_data, mut sub_component_inputs) = unsafe {
        (
            ComponentTrace::<N_TRACE_COLUMNS>::uninitialized(log_size),
            LookupData::uninitialized(log_n_packed_rows),
            SubComponentInputs::uninitialized(log_n_packed_rows),
        )
    };
    let enabler_col = Enabler::new(n_rows);
    (
        trace.par_iter_mut(),
        lookup_data.par_iter_mut(),
        sub_component_inputs.par_iter_mut(),
        inputs.into_par_iter(),
    )
        .into_par_iter()
        .enumerate()
        .for_each(
            |(row_index, (row, lookup_data, sub_component_inputs, jnz_opcode_taken_input))| {
                let mut eval = SimdWitnessEval::new(
                    row,
                    memory_address_to_id_state,
                    memory_id_to_big_state,
                    jnz_opcode_taken_input,
                    row_index,
                    &enabler_col,
                    N_LOOKUP_WORDS,
                    N_SUB_INPUT_WORDS,
                );
                jnz_opcode_taken_row_body(&mut eval);
                let lw = eval.lookup_scratch();
                *lookup_data.verify_instruction_0 =
                    [lw[0], lw[1], lw[2], lw[3], lw[4], lw[5], lw[6], lw[7]];
                *lookup_data.memory_address_to_id_1 = [lw[8], lw[9], lw[10]];
                *lookup_data.memory_id_to_big_2 = [
                    lw[11], lw[12], lw[13], lw[14], lw[15], lw[16], lw[17], lw[18], lw[19], lw[20],
                    lw[21], lw[22], lw[23], lw[24], lw[25], lw[26], lw[27], lw[28], lw[29], lw[30],
                    lw[31], lw[32], lw[33], lw[34], lw[35], lw[36], lw[37], lw[38], lw[39], lw[40],
                ];
                *lookup_data.memory_address_to_id_3 = [lw[41], lw[42], lw[43]];
                *lookup_data.memory_id_to_big_4 = [
                    lw[44], lw[45], lw[46], lw[47], lw[48], lw[49], lw[50], lw[51], lw[52], lw[53],
                    lw[54], lw[55], lw[56], lw[57], lw[58], lw[59], lw[60], lw[61], lw[62], lw[63],
                    lw[64], lw[65], lw[66], lw[67], lw[68], lw[69], lw[70], lw[71], lw[72], lw[73],
                ];
                *lookup_data.opcodes_5 = [lw[74], lw[75], lw[76], lw[77]];
                *lookup_data.opcodes_6 = [lw[78], lw[79], lw[80], lw[81]];
                *lookup_data.mults_0 = lw[82];
                *lookup_data.mults_1 = lw[83];
                let sw = eval.sub_scratch();
                *sub_component_inputs.verify_instruction[0] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[0]) },
                    [
                        unsafe { PackedM31::from_simd_unchecked(sw[1]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[2]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[3]) },
                    ],
                    [unsafe { PackedM31::from_simd_unchecked(sw[4]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[5])
                    }],
                    unsafe { PackedM31::from_simd_unchecked(sw[6]) },
                );
                *sub_component_inputs.memory_address_to_id[0] =
                    unsafe { PackedM31::from_simd_unchecked(sw[7]) };
                *sub_component_inputs.memory_address_to_id[1] =
                    unsafe { PackedM31::from_simd_unchecked(sw[8]) };
                *sub_component_inputs.memory_id_to_big[0] =
                    unsafe { PackedM31::from_simd_unchecked(sw[9]) };
                *sub_component_inputs.memory_id_to_big[1] =
                    unsafe { PackedM31::from_simd_unchecked(sw[10]) };
            },
        );
    (trace, lookup_data, sub_component_inputs)
}

impl ClaimGenerator {
    /// Generic-path counterpart of [`ClaimGenerator::write_trace`]: identical shape, but
    /// the base trace is produced by `write_trace_generic_simd`.
    #[allow(dead_code)]
    pub(crate) fn write_trace_generic(
        mut self,
        memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
        memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
        verify_instruction_state: &verify_instruction::ClaimGenerator,
    ) -> (
        ComponentTrace<N_TRACE_COLUMNS>,
        Claim,
        InteractionClaimGenerator,
    ) {
        let n_rows = self.inputs.len();
        assert_ne!(n_rows, 0);
        let size = std::cmp::max(n_rows.next_power_of_two(), N_LANES);
        let log_size = size.ilog2();
        self.inputs.resize(size, *self.inputs.first().unwrap());
        let packed_inputs = pack_values(&self.inputs);
        let (trace, lookup_data, sub_component_inputs) = write_trace_generic_simd(
            packed_inputs,
            n_rows,
            memory_address_to_id_state,
            memory_id_to_big_state,
            verify_instruction_state,
        );
        for inputs in sub_component_inputs.verify_instruction {
            add_inputs(verify_instruction_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.memory_address_to_id {
            add_inputs(
                memory_address_to_id_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.memory_id_to_big {
            add_inputs(memory_id_to_big_state, &inputs, inputs.len() * N_LANES, 0);
        }
        (
            trace,
            Claim { log_size },
            InteractionClaimGenerator {
                log_size,
                lookup_data,
            },
        )
    }
}

/// Record the `jnz_opcode_taken` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_jnz_opcode_taken() -> RecordingOutput {
    let mut eval = RecordingWitnessEval::new("jnz_opcode_taken");
    jnz_opcode_taken_row_body(&mut eval);
    eval.finish()
}

crate::jit_lookup_accessor! {
    84;
    verify_instruction_0: 8,
    memory_address_to_id_1: 3,
    memory_id_to_big_2: 30,
    memory_address_to_id_3: 3,
    memory_id_to_big_4: 30,
    opcodes_5: 4,
    opcodes_6: 4,
    mults_0: scalar,
    mults_1: scalar,
}

/// Device-DAG feed layout (facts, DECLARATION order): one entry per
/// `SubComponentInputs` instance — (field, instance, downstream state
/// param, relation_index, flat word base, words per instance).
#[allow(dead_code)]
pub(crate) const SUB_FEED_LAYOUT: &[(&str, usize, &str, u32, usize, usize)] = &[
    ("verify_instruction", 0, "verify_instruction_state", 0, 0, 7),
    (
        "memory_address_to_id",
        0,
        "memory_address_to_id_state",
        0,
        7,
        1,
    ),
    (
        "memory_address_to_id",
        1,
        "memory_address_to_id_state",
        0,
        8,
        1,
    ),
    ("memory_id_to_big", 0, "memory_id_to_big_state", 0, 9, 1),
    ("memory_id_to_big", 1, "memory_id_to_big_state", 0, 10, 1),
];

/// §6a device-interaction descriptors (facts, COLUMN order): one entry
/// per logup column — (a_field, a_mult, a_neg, b_field, b_mult, b_neg);
/// b_field == "" for a trailing solo column. mult encoding: "1" = one,
/// "enabler" = the real-row enabler, else a scalar lookup-data field.
#[allow(dead_code)]
pub(crate) const JIT_LOGUP_DESCS: &[(&str, &str, bool, &str, &str, bool)] = &[
    (
        "verify_instruction_0",
        "mults_0",
        false,
        "memory_address_to_id_1",
        "mults_0",
        false,
    ),
    (
        "memory_id_to_big_2",
        "mults_0",
        false,
        "memory_address_to_id_3",
        "mults_0",
        false,
    ),
    (
        "memory_id_to_big_4",
        "mults_0",
        false,
        "opcodes_5",
        "mults_1",
        false,
    ),
    ("opcodes_6", "mults_1", true, "", "", false),
];

// ---- Test-only surface for the byte-equality gate ---------------------------------

fn lookup_data_flat(ld: &LookupData) -> Vec<Vec<PackedM31>> {
    vec![
        ld.verify_instruction_0.iter().flatten().copied().collect(),
        ld.memory_address_to_id_1
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_2.iter().flatten().copied().collect(),
        ld.memory_address_to_id_3
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_4.iter().flatten().copied().collect(),
        ld.opcodes_5.iter().flatten().copied().collect(),
        ld.opcodes_6.iter().flatten().copied().collect(),
        ld.mults_0.clone(),
        ld.mults_1.clone(),
    ]
}

#[cfg(test)]
pub(crate) fn test_lookup_data_flat(ig: &InteractionClaimGenerator) -> Vec<Vec<PackedM31>> {
    lookup_data_flat(&ig.lookup_data)
}

fn sub_inputs_flat(sci: &SubComponentInputs) -> Vec<Vec<Simd<u32, N_LANES>>> {
    vec![
        sci.verify_instruction[0]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1[0].into_simd(),
                    t.1[1].into_simd(),
                    t.1[2].into_simd(),
                    t.2[0].into_simd(),
                    t.2[1].into_simd(),
                    t.3.into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[0]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[1]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[0]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[1]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
    ]
}

/// Byte-comparison bundle (only public types cross the module boundary).
#[cfg(test)]
pub(crate) struct GenericSimdDiff {
    pub log_size: u32,
    pub orig_rows: Vec<[M31; N_TRACE_COLUMNS]>,
    pub gen_rows: Vec<[M31; N_TRACE_COLUMNS]>,
    pub orig_lookup: Vec<Vec<PackedM31>>,
    pub gen_lookup: Vec<Vec<PackedM31>>,
    pub orig_sub: Vec<Vec<Simd<u32, N_LANES>>>,
    pub gen_sub: Vec<Vec<Simd<u32, N_LANES>>>,
    pub orig_interaction_cols: Vec<Vec<M31>>,
    pub gen_interaction_cols: Vec<Vec<M31>>,
    pub orig_claimed_sum: SecureField,
    pub gen_claimed_sum: SecureField,
}

/// Run BOTH SIMD writers on the same (pure-read) states and return public compare data.
#[cfg(test)]
pub(crate) fn generic_simd_diff(
    inputs: Vec<PackedInputType>,
    n_rows: usize,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
    verify_instruction_state: &verify_instruction::ClaimGenerator,
) -> GenericSimdDiff {
    let (trace_o, ld_o, sci_o) = write_trace_simd(
        inputs.clone(),
        n_rows.clone(),
        memory_address_to_id_state,
        memory_id_to_big_state,
        verify_instruction_state,
    );
    let (trace_g, ld_g, sci_g) = write_trace_generic_simd(
        inputs,
        n_rows,
        memory_address_to_id_state,
        memory_id_to_big_state,
        verify_instruction_state,
    );
    let log_size = trace_o.log_size();
    let orig_rows = (0..(1usize << log_size))
        .map(|r| trace_o.row_at(r))
        .collect();
    let gen_rows = (0..(1usize << log_size))
        .map(|r| trace_g.row_at(r))
        .collect();
    let orig_lookup = lookup_data_flat(&ld_o);
    let gen_lookup = lookup_data_flat(&ld_g);
    let orig_sub = sub_inputs_flat(&sci_o);
    let gen_sub = sub_inputs_flat(&sci_g);
    let common = relations::CommonLookupElements::dummy();
    let (raw_o, _) = InteractionClaimGenerator {
        log_size,
        lookup_data: ld_o,
    }
    .write_interaction_trace(&common);
    let (raw_g, _) = InteractionClaimGenerator {
        log_size,
        lookup_data: ld_g,
    }
    .write_interaction_trace(&common);
    let (cols_o, orig_claimed_sum) = raw_o.finalize_on_simd();
    let (cols_g, gen_claimed_sum) = raw_g.finalize_on_simd();
    let orig_interaction_cols = cols_o.iter().map(|c| c.values.to_cpu()).collect();
    let gen_interaction_cols = cols_g.iter().map(|c| c.values.to_cpu()).collect();
    GenericSimdDiff {
        log_size,
        orig_rows,
        gen_rows,
        orig_lookup,
        gen_lookup,
        orig_sub,
        gen_sub,
        orig_interaction_cols,
        gen_interaction_cols,
        orig_claimed_sum,
        gen_claimed_sum,
    }
}
// === END witness_genericize ===

#[derive(Uninitialized, IterMut, ParIterMut)]
struct LookupData {
    verify_instruction_0: Vec<[PackedM31; 8]>,
    memory_address_to_id_1: Vec<[PackedM31; 3]>,
    memory_id_to_big_2: Vec<[PackedM31; 30]>,
    memory_address_to_id_3: Vec<[PackedM31; 3]>,
    memory_id_to_big_4: Vec<[PackedM31; 30]>,
    opcodes_5: Vec<[PackedM31; 4]>,
    opcodes_6: Vec<[PackedM31; 4]>,
    mults_0: Vec<PackedM31>,
    mults_1: Vec<PackedM31>,
}

pub struct InteractionClaimGenerator {
    log_size: u32,
    lookup_data: LookupData,
}
// === BEGIN relation_lookup_source_codegen ===
crate::relation_lookup_source! {
    verify_instruction_0: 8,
    memory_address_to_id_1: 3,
    memory_id_to_big_2: 30,
    memory_address_to_id_3: 3,
    memory_id_to_big_4: 30,
    opcodes_5: 4,
    opcodes_6: 4,
    mults_0: scalar,
    mults_1: scalar,
}
// === END relation_lookup_source_codegen ===
impl InteractionClaimGenerator {
    pub fn write_interaction_trace(
        self,
        common_lookup_elements: &relations::CommonLookupElements,
    ) -> (RawLogupTrace, impl FnOnce(SecureField) -> InteractionClaim) {
        let mut logup_gen = unsafe { RawLogupTraceGenerator::uninitialized(self.log_size) };

        // Sum logup terms in pairs.
        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.verify_instruction_0,
            &self.lookup_data.memory_address_to_id_1,
            &self.lookup_data.mults_0,
            &self.lookup_data.mults_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 * *mult1 + denom1 * *mult0, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.memory_id_to_big_2,
            &self.lookup_data.memory_address_to_id_3,
            &self.lookup_data.mults_0,
            &self.lookup_data.mults_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 * *mult1 + denom1 * *mult0, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.memory_id_to_big_4,
            &self.lookup_data.opcodes_5,
            &self.lookup_data.mults_0,
            &self.lookup_data.mults_1,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 * *mult1 + denom1 * *mult0, denom0 * denom1);
            });
        col_gen.finalize_col();

        // Sum last logup term.
        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.opcodes_6,
            self.lookup_data.mults_1,
        )
            .into_par_iter()
            .for_each(|(writer, values, mult)| {
                let denom = common_lookup_elements.combine(values);
                writer.write_frac((-mult).into(), denom);
            });
        col_gen.finalize_col();

        (logup_gen.into_raw(), |claimed_sum| InteractionClaim {
            claimed_sum,
        })
    }
}

// --- witness-JIT prove-lane accessors (marked additive; layout mirrors LookupData /
// the emitted sub-word order; fenced by the prove-accessor parity gate) ---------------

crate::jit_sub_accessors!(N_SUB_INPUT_WORDS, n_addr = 2, n_id = 2);
